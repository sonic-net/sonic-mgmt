import pytest
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

pytestmark = [
    pytest.mark.topology('ptp-256')
]

CMD_SFP_EEPROM = "show interfaces transceiver info"

# Mapping of CLI keys to attribute keys (expected naming from CLI parser)
EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING = {
    "Vendor Date Code(YYYY-MM-DD Lot)": "vendor_date",
    "Vendor OUI": "vendor_oui",
    "Vendor Rev": "vendor_rev",
    "Vendor SN": "vendor_sn",
    "Vendor PN": "vendor_pn",
    "Active Firmware": "gold_firmware_version",
    "Inactive Firmware": "inactive_firmware_version",
    "CMIS Rev": "cmis_revision",
    "Vendor Name": "vendor_name",
}


def test_eeprom_content_verification_via_show_cli(duthost, port_attributes_dict):
    """Verify EEPROM content via 'show interfaces transceiver info' CLI.

    Runs one CLI command, parses output per port, and validates expected EEPROM fields
    against attributes from port_attributes_dict. Aggregates all failures for reporting.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM verification on virtual switch testbed")

    all_failures = []

    result = duthost.command(CMD_SFP_EEPROM, module_ignore_errors=True)
    if result.get('rc', 1) != 0:
        pytest.fail(f"CLI failed with rc={result.get('rc')}, stderr: {result.get('stderr', '')}")

    stdout_lines = result.get('stdout_lines', [])
    if not stdout_lines:
        pytest.fail("CLI returned empty output")

    cli_eeprom_by_port = parse_eeprom(stdout_lines)

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            continue

        cli_port_fields = cli_eeprom_by_port.get(port, {})
        if not cli_port_fields:
            all_failures.append(f"{port}: transceiver not detected (no CLI output)")
            continue

        base_attrs = port_attrs.get("BASE_ATTRIBUTES", {})
        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})

        field_failures = []
        for cli_key, attr_key in EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING.items():
            if attr_key in base_attrs:
                expected_value = base_attrs.get(attr_key)
            else:
                expected_value = eeprom_attrs.get(attr_key)
            if expected_value is None:
                continue

            actual_value = cli_port_fields.get(cli_key)
            if actual_value is None:
                field_failures.append(f"'{cli_key}' field missing in CLI output")
            elif actual_value != expected_value:
                field_failures.append(f"'{cli_key}': expected '{expected_value}', got '{actual_value}'")

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
