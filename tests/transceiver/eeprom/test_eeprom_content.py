import logging
import pytest

from tests.transceiver.utils.cli_parser_helper import parse_eeprom, RC_FAILURE

logger = logging.getLogger(__name__)

CMD_SFP_EEPROM_SFPUTIL = "sudo sfputil show eeprom"
CMD_SFP_EEPROM_CLI = "show interfaces transceiver info"

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


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _collect_eeprom_field_failures(eeprom_by_port, port_attributes_dict, source_label):
    """Validate per-port EEPROM fields against expected values in port_attributes_dict.

    Iterates every port that has non-empty attributes, looks up its parsed EEPROM
    fields from ``eeprom_by_port``, and compares each field listed in
    EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING against BASE_ATTRIBUTES
    (checked first) or EEPROM_ATTRIBUTES.

    Args:
        eeprom_by_port:       {port: {cli_key: value}} dict returned by parse_eeprom().
        port_attributes_dict: {port: attrs} fixture dict.
        source_label:         Human-readable label for error messages, e.g.
                              "sfputil show eeprom" or "show interfaces transceiver info".

    Returns:
        List of aggregated failure strings (empty list means all ports passed).
    """
    all_failures = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        port_fields = eeprom_by_port.get(port, {})
        if not port_fields:
            all_failures.append(
                f"{port}: transceiver not detected (no {source_label} output)"
            )
            continue

        base_attrs = port_attrs.get("BASE_ATTRIBUTES", {})
        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})

        field_failures = []
        for cli_key, attr_key in EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING.items():
            expected_value = (
                base_attrs.get(attr_key)
                if attr_key in base_attrs
                else eeprom_attrs.get(attr_key)
            )
            if expected_value is None:
                continue
            actual_value = port_fields.get(cli_key)
            if actual_value is None:
                field_failures.append(f"'{cli_key}' field missing in {source_label}")
            elif actual_value != expected_value:
                field_failures.append(
                    f"'{cli_key}': expected '{expected_value}', got '{actual_value}'"
                )

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    return all_failures


def test_eeprom_content_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify EEPROM content via 'sudo sfputil show eeprom' sfputil.

    Runs one sfputil command, parses output per port, and validates expected EEPROM fields
    against attributes from port_attributes_dict. Aggregates all failures for reporting.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM verification on virtual switch testbed")

    result = duthost.command(CMD_SFP_EEPROM_SFPUTIL, module_ignore_errors=True)
    if result.get('rc', RC_FAILURE) != 0:
        pytest.fail(f"sfputil failed with rc={result.get('rc')}, stderr: {result.get('stderr', '')}")

    stdout_lines = result.get('stdout_lines', [])
    if not stdout_lines:
        pytest.fail("sfputil returned empty output")

    sfputil_eeprom_by_port = parse_eeprom(stdout_lines)
    all_failures = _collect_eeprom_field_failures(
        sfputil_eeprom_by_port, port_attributes_dict, "sfputil show eeprom"
    )

    # TC3 compares key identity fields only (vendor name, part number, serial number,
    # CMIS revision, module hardware revision, etc.).  Firmware versions
    # (gold_firmware_version → 'Active Firmware', inactive_firmware_version →
    # 'Inactive Firmware') are validated exclusively in test_tc5_firmware_version_verification,
    # so we strip those lines here to avoid duplicate / misleading failures.
    _FIRMWARE_CLI_KEYS = {"'Active Firmware'", "'Inactive Firmware'"}
    filtered_failures = []
    for entry in all_failures:
        lines = entry.split("\n")
        kept = [ln for ln in lines if not any(fw_key in ln for fw_key in _FIRMWARE_CLI_KEYS)]
        # Each entry starts with a port-header line (e.g. "Ethernet0:"); if nothing
        # is left after stripping firmware lines, discard the whole entry.
        if len(kept) > 1:
            filtered_failures.append("\n".join(kept))
    all_failures = filtered_failures

    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))


def test_eeprom_content_verification_via_show_cli(duthost, port_attributes_dict):
    """Verify EEPROM content via 'show interfaces transceiver info' CLI.

    Runs one CLI command, parses output per port, and validates expected EEPROM fields
    against attributes from port_attributes_dict. Aggregates all failures for reporting.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM verification on virtual switch testbed")

    result = duthost.command(CMD_SFP_EEPROM_CLI, module_ignore_errors=True)
    if result.get('rc', RC_FAILURE) != 0:
        pytest.fail(f"CLI failed with rc={result.get('rc')}, stderr: {result.get('stderr', '')}")

    stdout_lines = result.get('stdout_lines', [])
    if not stdout_lines:
        pytest.fail("CLI returned empty output")

    cli_eeprom_by_port = parse_eeprom(stdout_lines)
    all_failures = _collect_eeprom_field_failures(
        cli_eeprom_by_port, port_attributes_dict, "show interfaces transceiver info"
    )

    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
