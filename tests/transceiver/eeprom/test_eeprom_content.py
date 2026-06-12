import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers
from tests.transceiver.eeprom._constants import DEFAULT_EEPROM_DUMP_TIMEOUT_SEC

logger = logging.getLogger(__name__)

# Mapping of CLI keys to attribute keys (expected naming from CLI parser)
EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING = {
    "Vendor Date Code(YYYY-MM-DD Lot)": "vendor_date",
    "Vendor OUI":                       "vendor_oui",
    "Vendor Rev":                       "vendor_rev",
    "Vendor SN":                        "vendor_sn",
    "Vendor PN":                        "vendor_pn",
    "Active Firmware":                  "gold_firmware_version",
    "Inactive Firmware":                "inactive_firmware_version",
    "CMIS Rev":                         "cmis_revision",
    "Vendor Name":                      "vendor_name",
    # Module hardware revision. The CLI key is "Module Hardware Rev" (verified
    # against `show interfaces transceiver info` on an OSFP module), distinct
    # from "Vendor Rev" above. Emitted only for QSFP-DD/OSFP (CMIS) modules;
    # gating is automatic — non-CMIS ports don't define hardware_rev in the
    # inventory, so _resolve_expected returns _MISSING and the check is skipped
    # (same inventory-presence gating as cmis_revision).
    "Module Hardware Rev":              "hardware_rev",
}

# CLI keys validated exclusively by the dedicated firmware-version test case.
# Both EEPROM-content tests (sfputil and show-cli variants) skip these to avoid
# duplicate / misleading failures when firmware drift is detected elsewhere.
FIRMWARE_CLI_KEYS = frozenset({"Active Firmware", "Inactive Firmware"})

# Sentinel distinguishing "attribute genuinely absent from inventory" from
# "attribute present with an explicit None value".  An inventory entry that is
# explicitly set to None means "must be unset on hardware" and should be
# checked, not silently skipped.
_MISSING = object()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _resolve_expected(base_attrs, eeprom_attrs, attr_key):
    """Look up ``attr_key`` in BASE_ATTRIBUTES first, then EEPROM_ATTRIBUTES.

    Returns ``_MISSING`` when the key is absent from both blocks so the caller
    can skip the check.  When the key is present (in either block) and its
    value is ``None``, returns ``None`` so the comparison loop will flag a
    mismatch against any non-None actual value.
    """
    if attr_key in base_attrs:
        return base_attrs[attr_key]
    if attr_key in eeprom_attrs:
        return eeprom_attrs[attr_key]
    return _MISSING


def _validate_port_eeprom_dump(
    duthost, port, port_attrs, parse_wrapper, source_label, exclude_keys=None,
):
    """Per-port EEPROM dump + timeout enforcement + field validation.

    Implements Generic full contract for a single port:
      1. Call ``parse_wrapper(duthost, port=port)`` once, timed with
         ``time.monotonic()``.  The wrapper is a ``cli_helpers`` parsed
         accessor (e.g. ``cli_helpers.sfputil_show_eeprom``) that runs the
         command and centralizes the rc / empty-output / parse handling via
         ``_run_and_parse``, returning ``(parsed_by_port, err)``.
      2. Fail the port when the call's elapsed time exceeds
         ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec``
         (default ``DEFAULT_EEPROM_DUMP_TIMEOUT_SEC``).  Field validation
         still runs so a slow-but-correct dump surfaces both signals.
      3. Compare every field in
         ``EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING`` against
         the value resolved by ``_resolve_expected`` (BASE then EEPROM
         attributes).  ``exclude_keys`` skips a subset (e.g. firmware
         fields owned by another test case).

    Args:
        duthost: DUT host fixture.
        port:    logical interface name (e.g. ``"Ethernet0"``).
        port_attrs: the port's entry from ``port_attributes_dict``.
        parse_wrapper: callable ``(duthost, port=...) -> (parsed_by_port, err)``
            from ``cli_helpers`` (e.g. ``cli_helpers.sfputil_show_eeprom``).
            Timing the wrapper rather than a bare command keeps the
            rc / empty / parse handling centralized in ``_run_and_parse``.
        source_label: human-readable label for failure messages.
        exclude_keys: optional iterable of CLI keys to skip in field comparison.

    Returns:
        list[str]: zero or more per-port failure strings.  Empty list means
        every check (command success, elapsed-time budget, field matches)
        passed for this port.
    """
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
    timeout_sec = eeprom_attrs.get(
        "eeprom_dump_timeout_sec", DEFAULT_EEPROM_DUMP_TIMEOUT_SEC
    )

    start = time.monotonic()
    parsed_by_port, err = parse_wrapper(duthost, port=port)
    elapsed = time.monotonic() - start

    failures = []
    if err:
        failures.append(err)
        return failures

    # Timeout enforcement (Generic expected result, per eeprom_test_plan.md).
    if elapsed > timeout_sec:
        failures.append(
            f"{source_label} took {elapsed:.2f}s, exceeding "
            f"eeprom_dump_timeout_sec={timeout_sec}s"
        )

    port_fields = parsed_by_port.get(port, {})
    if not port_fields:
        failures.append(f"transceiver not detected (no {source_label} output)")
        return failures

    excluded = frozenset(exclude_keys or ())
    for cli_key, attr_key in EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING.items():
        if cli_key in excluded:
            continue
        expected_value = _resolve_expected(base_attrs, eeprom_attrs, attr_key)
        if expected_value is _MISSING:
            continue
        actual_value = port_fields.get(cli_key)
        if actual_value is None:
            failures.append(f"'{cli_key}' field missing in {source_label}")
        elif actual_value != expected_value:
            failures.append(
                f"'{cli_key}': expected '{expected_value}', got '{actual_value}'"
            )

    return failures


def _run_per_port_eeprom_check(
    duthost, port_attributes_dict, parse_wrapper, source_label, exclude_keys=None,
):
    """Iterate every port with attributes, validate via
    ``_validate_port_eeprom_dump``, and aggregate per-port failure blocks
    for one consolidated ``pytest.fail`` at the test level.
    """
    all_failures = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        port_failures = _validate_port_eeprom_dump(
            duthost, port, port_attrs, parse_wrapper, source_label, exclude_keys,
        )
        if port_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(port_failures))
    return all_failures


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_eeprom_content_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify EEPROM content via ``sfputil show eeprom -p <port>`` per port.

    Implements Generic test case from
    ``docs/testplan/transceiver/eeprom_test_plan.md``.  For every port with
    inventory attributes the test:

      * Runs ``sfputil show eeprom -p <port>`` once, timed.
      * Fails the port when elapsed time exceeds
        ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` (default 5s per the
        plan).  This is the test case expected result "EEPROM dump completes
        within eeprom_dump_timeout_sec".
      * Compares the parsed EEPROM fields against expected values from
        ``port_attributes_dict``.

    Firmware fields (``Active Firmware``, ``Inactive Firmware``) are
    validated exclusively by the dedicated firmware-version test case, so
    this test skips them via the ``exclude_keys`` argument.

    Aggregates per-port failure blocks into one ``pytest.fail``.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM verification on virtual switch testbed")

    all_failures = _run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=cli_helpers.sfputil_show_eeprom,
        source_label="sfputil show eeprom -p <port>",
        exclude_keys=FIRMWARE_CLI_KEYS,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))


def test_eeprom_content_verification_via_show_cli(duthost, port_attributes_dict):
    """Verify EEPROM content via ``show interfaces transceiver info <port>`` per port.

    Mirror of :func:`test_eeprom_content_verification_via_sfputil` for the
    SONiC ``show`` CLI variant.  Same per-port timeout enforcement against
    ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` applies here too, so a
    sluggish ``show interfaces`` path is caught independently of the
    sfputil variant.

    Firmware fields (``Active Firmware``, ``Inactive Firmware``) are
    validated exclusively by the dedicated firmware-version test case, so
    this test skips them via the ``exclude_keys`` argument (matching the
    sfputil variant).
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM verification on virtual switch testbed")

    all_failures = _run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=cli_helpers.show_interfaces_transceiver_info,
        source_label="show interfaces transceiver info <port>",
        exclude_keys=FIRMWARE_CLI_KEYS,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
