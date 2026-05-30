import logging
import pytest

import re

from tests.transceiver.utils.cli_parser_helper import (
    parse_hexdump,
    parse_read_eeprom,
    RC_FAILURE,
    _extract_ascii_field,
    _check_dp_state_activated,
    CMIS_VENDOR_NAME_START,
    CMIS_VENDOR_NAME_LEN,
    CMIS_VENDOR_PN_START,
    CMIS_VENDOR_PN_LEN,
)

logger = logging.getLogger(__name__)

CMD_SFP_HEXDUMP_SFPUTIL = "sudo sfputil show eeprom-hexdump"
CMD_SFP_READ_EEPROM_SFPUTIL = "sudo sfputil read-eeprom"


def test_eeprom_hexdump_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify EEPROM hexdump content via 'sfputil show eeprom-hexdump'.

    For every connected port:
    - Runs 'sfputil show eeprom-hexdump -p <port> -n 0' and verifies vendor name
      and part number decoded from the CMIS upper page 0h byte map against
      port_attributes_dict (BASE_ATTRIBUTES: vendor_name, vendor_pn).
    - For non-DAC CMIS transceivers (is_non_dac_and_cmis = True), additionally runs
      'sfputil show eeprom-hexdump -p <port> -n 0x11' and verifies all 8 lanes report
      DPActivated (0x4) in the upper page 11h DataPath state registers (offsets 0x80-0x83).
    Aggregates all failures for reporting.

    CMIS upper page 0h field map (referenced from the hexdump address range):
        Vendor Name : bytes 0x81-0x90 (16 bytes, ASCII, space-padded)
        Vendor PN   : bytes 0x94-0xA3 (16 bytes, ASCII, space-padded)

    CMIS upper page 11h DataPath state (2 lanes per byte, nibble-encoded):
        Bytes 0x80-0x83 cover lanes 1-8; each nibble == 0x4 means DPActivated.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM hexdump verification on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Skip sub-port breakout interfaces — EEPROM hexdump commands must
        # target the physical (stem) port that actually hosts the transceiver.
        # Sub-ports (e.g. Ethernet1, Ethernet2, …) share the same EEPROM and
        # return redundant or misleading results on some platforms.
        # Only stem ports (port-number divisible by 8) are tested; this matches
        # the filtering used in test_cmis.py.
        port_match = re.match(r"^Ethernet(\d+)$", port)
        if not port_match:
            logger.debug("Port %s is not a physical Ethernet port name, skipping", port)
            continue
        if (int(port_match.group(1)) % 8) != 0:
            logger.debug("Port %s is a breakout sub-port, skipping hexdump check", port)
            continue

        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        base_attrs = port_attrs.get("BASE_ATTRIBUTES", {})
        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})
        field_failures = []

        # ------------------------------------------------------------------ #
        # Step 1 – page 0: vendor name and part number from upper page 0h     #
        # ------------------------------------------------------------------ #
        cmd_page0 = f"{CMD_SFP_HEXDUMP_SFPUTIL} -p {port} -n 0"
        result = duthost.command(cmd_page0, module_ignore_errors=True)
        if result.get('rc', RC_FAILURE) != 0:
            all_failures.append(
                f"{port}: sfputil page 0 hexdump failed with rc={result.get('rc')}, "
                f"stderr: {result.get('stderr', '')}"
            )
            continue

        stdout_lines = result.get('stdout_lines', [])
        if not stdout_lines:
            all_failures.append(f"{port}: sfputil page 0 hexdump returned empty output")
            continue

        hexdump_page0 = parse_hexdump(stdout_lines)
        upper_page_0 = hexdump_page0.get("upper_page_0", {})
        if not upper_page_0:
            all_failures.append(f"{port}: upper page 0h section not found in hexdump output")
            continue

        expected_vendor_name = base_attrs.get("vendor_name")
        if expected_vendor_name is not None:
            actual_vendor_name = _extract_ascii_field(
                upper_page_0, CMIS_VENDOR_NAME_START, CMIS_VENDOR_NAME_LEN
            )
            if actual_vendor_name is None:
                field_failures.append(
                    f"Vendor name bytes incomplete at page 0h offset 0x{CMIS_VENDOR_NAME_START:02X}"
                )
            elif actual_vendor_name != expected_vendor_name:
                field_failures.append(
                    f"Vendor name: expected '{expected_vendor_name}', got '{actual_vendor_name}'"
                )

        expected_vendor_pn = base_attrs.get("vendor_pn")
        if expected_vendor_pn is not None:
            actual_vendor_pn = _extract_ascii_field(
                upper_page_0, CMIS_VENDOR_PN_START, CMIS_VENDOR_PN_LEN
            )
            if actual_vendor_pn is None:
                field_failures.append(
                    f"Vendor PN bytes incomplete at page 0h offset 0x{CMIS_VENDOR_PN_START:02X}"
                )
            elif actual_vendor_pn != expected_vendor_pn:
                field_failures.append(
                    f"Vendor PN: expected '{expected_vendor_pn}', got '{actual_vendor_pn}'"
                )

        # ------------------------------------------------------------------ #
        # Step 2 – page 11h: DPActivated state (non-DAC CMIS ports only)     #
        # ------------------------------------------------------------------ #
        if eeprom_attrs.get("is_non_dac_and_cmis"):
            cmd_page11 = f"{CMD_SFP_HEXDUMP_SFPUTIL} -p {port} -n 0x11"
            result_11 = duthost.command(cmd_page11, module_ignore_errors=True)
            if result_11.get('rc', RC_FAILURE) != 0:
                field_failures.append(
                    f"sfputil page 11h hexdump failed with rc={result_11.get('rc')}, "
                    f"stderr: {result_11.get('stderr', '')}"
                )
            else:
                stdout_lines_11 = result_11.get('stdout_lines', [])
                if not stdout_lines_11:
                    field_failures.append("sfputil page 11h hexdump returned empty output")
                else:
                    hexdump_page11 = parse_hexdump(stdout_lines_11)
                    upper_page_11 = hexdump_page11.get("upper_page_11", {})
                    if not upper_page_11:
                        field_failures.append("Upper page 11h section not found in hexdump output")
                    else:
                        field_failures.extend(_check_dp_state_activated(upper_page_11))

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("EEPROM hexdump verification failures:\n" + "\n".join(all_failures))


def test_identifier_byte_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify the SFF-8024 identifier byte via 'sfputil read-eeprom'.

    For every connected port, reads exactly one byte from lower page 0, offset 0
    using 'sfputil read-eeprom -p <port> -n 0 -o 0 -s 1' and validates it against
    the 'sff8024_identifier' value from EEPROM_ATTRIBUTES in port_attributes_dict.
    Aggregates all failures for reporting.

    Lower page 0, byte 0 — SFF-8024 identifier values (decimal):
        25 (0x19) = QSFP-DD / OSFP (CMIS)
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping identifier byte verification on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})
        expected_identifier = eeprom_attrs.get("sff8024_identifier")
        if expected_identifier is None:
            logger.debug("Port %s has no sff8024_identifier defined, skipping", port)
            continue

        cmd = f"{CMD_SFP_READ_EEPROM_SFPUTIL} -p {port} -n 0 -o 0 -s 1"
        result = duthost.command(cmd, module_ignore_errors=True)
        if result.get('rc', RC_FAILURE) != 0:
            all_failures.append(
                f"{port}: sfputil read-eeprom failed with rc={result.get('rc')}, "
                f"stderr: {result.get('stderr', '')}"
            )
            continue

        stdout_lines = result.get('stdout_lines', [])
        if not stdout_lines:
            all_failures.append(f"{port}: sfputil read-eeprom returned empty output")
            continue

        byte_map = parse_read_eeprom(stdout_lines)
        actual_identifier = byte_map.get(0)
        if actual_identifier is None:
            all_failures.append(f"{port}: identifier byte at offset 0 not found in sfputil output")
        elif actual_identifier != expected_identifier:
            all_failures.append(
                f"{port}: identifier byte mismatch: "
                f"expected 0x{expected_identifier:02X} ({expected_identifier}), "
                f"got 0x{actual_identifier:02X} ({actual_identifier})"
            )

    if all_failures:
        pytest.fail("Identifier byte verification failures:\n" + "\n".join(all_failures))
