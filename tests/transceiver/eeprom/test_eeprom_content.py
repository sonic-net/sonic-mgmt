import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.eeprom_decode import is_stem_port
from tests.transceiver.eeprom._constants import DEFAULT_EEPROM_DUMP_TIMEOUT_SEC

logger = logging.getLogger(__name__)

# CLI-key → inventory-attribute mapping for fields whose CLI key is IDENTICAL
# in both ``sfputil show eeprom`` and ``show interfaces transceiver info``.
_COMMON_CLI_KEY_TO_INV_KEY = {
    "Vendor Date Code(YYYY-MM-DD Lot)": "vendor_date",
    "Vendor OUI":                       "vendor_oui",
    "Vendor Rev":                       "vendor_rev",
    "Vendor SN":                        "vendor_sn",
    "Vendor PN":                        "vendor_pn",
    "Vendor Name":                      "vendor_name",
}

# Some fields are spelled differently by the two CLIs, or exposed by only one,
# so each test uses its own command-specific mapping (verified on an OSFP
# module):
#   hardware revision: sfputil "Hardware Revision" / show CLI "Module Hardware Rev"
#   CMIS revision:     sfputil "CMIS Revision"     / show CLI "CMIS Rev"
#   firmware versions: reported ONLY by 'show interfaces transceiver info'
#                      ('sfputil show eeprom' does not show firmware), so they
#                      are verified by the show-CLI test only.
# Gating is automatic: a port that doesn't define the attribute in inventory is
# skipped (_resolve_expected returns _MISSING), so these never false-fail.
SFPUTIL_CLI_KEY_TO_INV_KEY = {
    **_COMMON_CLI_KEY_TO_INV_KEY,
    "Hardware Revision": "hardware_rev",
    "CMIS Revision":     "cmis_revision",
}
SHOW_CLI_KEY_TO_INV_KEY = {
    **_COMMON_CLI_KEY_TO_INV_KEY,
    "Module Hardware Rev": "hardware_rev",
    "CMIS Rev":            "cmis_revision",
    "Active Firmware":     "gold_firmware_version",
    "Inactive Firmware":   "inactive_firmware_version",
}

# Sentinel distinguishing "attribute genuinely absent from inventory" from
# "attribute present with an explicit None value".  An inventory entry that is
# explicitly set to None means "must be unset on hardware" and should be
# checked, not silently skipped.
_MISSING = object()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _resolve_expected(base_attrs, eeprom_attrs, cdb_fw_attrs, attr_key):
    """Look up ``attr_key`` in BASE, then EEPROM, then CDB_FIRMWARE_UPGRADE attrs.

    The firmware-version fields (``gold_firmware_version`` /
    ``inactive_firmware_version``) live under CDB_FIRMWARE_UPGRADE_ATTRIBUTES,
    so that block is consulted too — otherwise those keys would silently
    resolve to ``_MISSING`` and never be verified.

    Returns ``_MISSING`` when the key is absent from all three blocks so the
    caller can skip the check.  When the key is present (in any block) and its
    value is ``None``, returns ``None`` so the comparison loop will flag a
    mismatch against any non-None actual value.
    """
    if attr_key in base_attrs:
        return base_attrs[attr_key]
    if attr_key in eeprom_attrs:
        return eeprom_attrs[attr_key]
    if attr_key in cdb_fw_attrs:
        return cdb_fw_attrs[attr_key]
    return _MISSING


def _validate_port_eeprom_dump(
    duthost, port, port_attrs, parse_wrapper, source_label, key_mapping,
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
      3. Compare every field in ``key_mapping`` (the command-specific
         CLI-key → inventory-attribute map) against the value resolved by
         ``_resolve_expected`` (BASE, EEPROM, then CDB_FIRMWARE_UPGRADE attrs).

    Args:
        duthost: DUT host fixture.
        port:    logical interface name (e.g. ``"Ethernet0"``).
        port_attrs: the port's entry from ``port_attributes_dict``.
        parse_wrapper: callable ``(duthost, port=...) -> (parsed_by_port, err)``
            from ``cli_helpers`` (e.g. ``cli_helpers.sfputil_show_eeprom``).
            Timing the wrapper rather than a bare command keeps the
            rc / empty / parse handling centralized in ``_run_and_parse``.
        source_label: human-readable label for failure messages.
        key_mapping: CLI-key → inventory-attribute dict for the command this
            test drives (e.g. ``SFPUTIL_CLI_KEY_TO_INV_KEY``).  The two CLIs
            spell some fields differently (e.g. hardware revision), so each
            test passes its own.

    Returns:
        list[str]: zero or more per-port failure strings.  Empty list means
        every check (command success, elapsed-time budget, field matches)
        passed for this port.
    """
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
    cdb_fw_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
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

    for cli_key, attr_key in key_mapping.items():
        expected_value = _resolve_expected(base_attrs, eeprom_attrs, cdb_fw_attrs, attr_key)
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
    duthost, port_attributes_dict, parse_wrapper, source_label, key_mapping, stem_map,
):
    """Iterate stem ports with attributes, validate via
    ``_validate_port_eeprom_dump``, and aggregate per-port failure blocks
    for one consolidated ``pytest.fail`` at the test level.

    Filters to stem ports: EEPROM bytes are per-physical-port, so a breakout
    sub-port returns the same data as its stem and adds no coverage here.  The
    per-subport ``sfputil`` CLI-resolution path has its own dedicated test.
    """
    all_failures = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        if not is_stem_port(port, stem_map):
            logger.debug("Port %s is a breakout sub-port, skipping", port)
            continue
        port_failures = _validate_port_eeprom_dump(
            duthost, port, port_attrs, parse_wrapper, source_label, key_mapping,
        )
        if port_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(port_failures))
    return all_failures


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_eeprom_content_verification_via_sfputil(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
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
        ``port_attributes_dict``.  Firmware versions are NOT checked here:
        ``sfputil show eeprom`` does not report them, so they are verified by
        the show-CLI variant instead.

    Aggregates per-port failure blocks into one ``pytest.fail``.
    """
    all_failures = _run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=cli_helpers.sfputil_show_eeprom,
        source_label="sfputil show eeprom -p <port>",
        key_mapping=SFPUTIL_CLI_KEY_TO_INV_KEY,
        stem_map=lport_to_first_subport_mapping,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))


def test_eeprom_content_verification_via_show_cli(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Verify EEPROM content via ``show interfaces transceiver info <port>`` per port.

    Mirror of :func:`test_eeprom_content_verification_via_sfputil` for the
    SONiC ``show`` CLI variant.  Same per-port timeout enforcement against
    ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` applies here too, so a
    sluggish ``show interfaces`` path is caught independently of the
    sfputil variant.  This variant additionally verifies firmware versions
    (``Active Firmware`` / ``Inactive Firmware``), which only this CLI reports.
    """
    all_failures = _run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=cli_helpers.show_interfaces_transceiver_info,
        source_label="show interfaces transceiver info <port>",
        key_mapping=SHOW_CLI_KEY_TO_INV_KEY,
        stem_map=lport_to_first_subport_mapping,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
