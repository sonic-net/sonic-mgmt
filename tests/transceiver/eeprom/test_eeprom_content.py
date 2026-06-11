import logging
import time

import pytest

from tests.transceiver.common import cli_helpers
from tests.transceiver.utils.cli_parser_helper import parse_eeprom, RC_FAILURE

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

# Plan-documented default for ``eeprom_dump_timeout_sec`` when the per-port
# inventory does not define it (see eeprom_test_plan.md, attributes table).
_DEFAULT_EEPROM_DUMP_TIMEOUT_SEC = 5


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
    duthost, port, port_attrs, command_builder, source_label, exclude_keys=None,
):
    """Per-port EEPROM dump + timeout enforcement + field validation.

    Implements Generic TC 3's full contract for a single port:
      1. Run ``command_builder(port=port)`` once, timed with
         ``time.monotonic()``.  The command builder comes from
         ``cli_helpers`` so command spelling stays single-sourced.
      2. Fail the port when the command's elapsed time exceeds
         ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec``
         (default ``_DEFAULT_EEPROM_DUMP_TIMEOUT_SEC``).  Field validation
         still runs so a slow-but-correct dump surfaces both signals.
      3. Parse the output via ``parse_eeprom`` and compare every field in
         ``EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING`` against
         the value resolved by ``_resolve_expected`` (BASE then EEPROM
         attributes).  ``exclude_keys`` skips a subset (e.g. firmware
         fields owned by another test case).

    Args:
        duthost: DUT host fixture.
        port:    logical interface name (e.g. ``"Ethernet0"``).
        port_attrs: the port's entry from ``port_attributes_dict``.
        command_builder: callable ``port -> str`` from ``cli_helpers``
            (e.g. ``cli_helpers.sfputil_show_eeprom_cmd``).  Inlined here
            rather than calling the parsed wrapper because we need to
            measure elapsed time around the bare command invocation.
        source_label: human-readable label for failure messages.
        exclude_keys: optional iterable of CLI keys to skip in field comparison.

    Returns:
        list[str]: zero or more per-port failure strings.  Empty list means
        every check (command rc, output non-empty, elapsed-time budget,
        field matches) passed for this port.
    """
    eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})
    base_attrs = port_attrs.get("BASE_ATTRIBUTES", {})
    timeout_sec = eeprom_attrs.get(
        "eeprom_dump_timeout_sec", _DEFAULT_EEPROM_DUMP_TIMEOUT_SEC
    )
    cmd = command_builder(port=port)

    start = time.monotonic()
    result = duthost.command(cmd, module_ignore_errors=True)
    elapsed = time.monotonic() - start

    failures = []
    if result.get('rc', RC_FAILURE) != 0:
        failures.append(
            f"{source_label} failed (rc={result.get('rc')}, "
            f"stderr: {result.get('stderr', '')})"
        )
        return failures

    stdout_lines = result.get('stdout_lines', [])
    if not stdout_lines:
        failures.append(f"{source_label} returned empty output (elapsed={elapsed:.2f}s)")
        return failures

    # Timeout enforcement (Generic TC 3 expected result, per eeprom_test_plan.md).
    if elapsed > timeout_sec:
        failures.append(
            f"{source_label} took {elapsed:.2f}s, exceeding "
            f"eeprom_dump_timeout_sec={timeout_sec}s"
        )

    eeprom_by_port = parse_eeprom(stdout_lines)
    port_fields = eeprom_by_port.get(port, {})
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
    duthost, port_attributes_dict, command_builder, source_label, exclude_keys=None,
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
            duthost, port, port_attrs, command_builder, source_label, exclude_keys,
        )
        if port_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(port_failures))
    return all_failures


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_eeprom_content_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify EEPROM content via ``sfputil show eeprom -p <port>`` per port.

    Implements Generic TC 3 from
    ``docs/testplan/transceiver/eeprom_test_plan.md``.  For every port with
    inventory attributes the test:

      * Runs ``sfputil show eeprom -p <port>`` once, timed.
      * Fails the port when elapsed time exceeds
        ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` (default 5s per the
        plan).  This is the TC 3 expected result "EEPROM dump completes
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
        command_builder=cli_helpers.sfputil_show_eeprom_cmd,
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
        command_builder=cli_helpers.show_interfaces_transceiver_info_cmd,
        source_label="show interfaces transceiver info <port>",
        exclude_keys=FIRMWARE_CLI_KEYS,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
