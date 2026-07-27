import logging

import pytest

from tests.common.platform.interface_utils import is_first_subport
from tests.transceiver.attribute_parser.attribute_keys import EEPROM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.cmis_helper import (
    CMIS_PAGE_01_CDB_CAP_PAGE,
    CMIS_PAGE_01_CDB_CAP_OFFSET,
    CMIS_PAGE_01_CDB_BG_MODE_BIT,
)

logger = logging.getLogger(__name__)


def test_cdb_background_mode_support_test(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Verify CMIS CDB background mode hardware capability against inventory configuration.

    Prerequisites per port (both must be satisfied or the port is silently skipped):
    - EEPROM_ATTRIBUTES: cmis_active_optical = True  (non-DAC CMIS module)
    - EEPROM_ATTRIBUTES: cdb_background_mode_supported is defined (True or False)

    First-sub-port detection (used to skip the other breakout sub-ports that
    share an EEPROM with the first one) comes from
    ``tests.common.platform.interface_utils.get_lport_to_first_subport_mapping``
    — a port is the first sub-port iff it maps to itself, so no per-platform
    port-number modulus is needed.

    For qualifying first sub-ports, reads CMIS Page 01h at sfputil offset 0xA3
    (= CMIS global byte 163 decimal, absolute address 0xA3 in the 256-byte
    page view) using:
        sfputil read-eeprom -p <port> -n 0x01 -o 0xA3 -s 1

    Extracts bit 5 of the returned byte and validates against expected configuration:
        cdb_background_mode_supported = True  → bit 5 must be 1 (hardware supports it)
        cdb_background_mode_supported = False → bit 5 must be 0 (hardware does not)

    Aggregates all failures for reporting.

    CMIS reference:
        Page 01h (Capabilities Advertising), CMIS global byte 163 (decimal) = 0xA3, bit 5:
        CDB background mode support advertisement.
        sfputil: -n 0x01 -o 0xA3  (upper page, 0xA3 - 0x80 = 0x23 = 35 bytes from page start)
    """
    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Only test the first sub-port of each breakout group.  In a breakout
        # deployment a single physical transceiver is represented by several
        # logical sub-ports that share the same EEPROM; running CDB reads against
        # the non-first sub-ports is redundant and can cause false failures on
        # some ASIC drivers.
        if not is_first_subport(port, lport_to_first_subport_mapping):
            logger.debug("Port %s is not the first breakout sub-port, skipping CDB check", port)
            continue
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

        # Prerequisite 1: port must be a non-DAC CMIS module
        if not eeprom_attrs.get("cmis_active_optical"):
            logger.debug("Port %s: cmis_active_optical is not True, skipping CDB check", port)
            continue

        # Prerequisite 2: expected CDB background mode support must be defined
        expected_cdb_bg_mode = eeprom_attrs.get("cdb_background_mode_supported")
        if expected_cdb_bg_mode is None:
            logger.debug("Port %s: cdb_background_mode_supported not defined, skipping", port)
            continue

        # Read CMIS Page 01h, CMIS global byte 163 (decimal) = 0xA3 (sfputil offset 0xA3)
        byte_map, err = cli_helpers.sfputil_read_eeprom(
            duthost, port,
            page=f"0x{format(CMIS_PAGE_01_CDB_CAP_PAGE, '02X')}",
            offset=CMIS_PAGE_01_CDB_CAP_OFFSET,
            size=1,
        )
        if err:
            all_failures.append(f"{port}: {err}")
            continue

        if not byte_map:
            all_failures.append(
                f"{port}: no parseable byte found in sfputil read-eeprom output "
                f"(page 0x{format(CMIS_PAGE_01_CDB_CAP_PAGE, '02X')}, "
                f"offset 0x{format(CMIS_PAGE_01_CDB_CAP_OFFSET, '02X')})"
            )
            continue

        # Extract bit 5 from the single returned byte
        raw_byte = byte_map.get(CMIS_PAGE_01_CDB_CAP_OFFSET)
        if raw_byte is None:
            all_failures.append(
                f"{port}: expected byte missing at offset 0x{format(CMIS_PAGE_01_CDB_CAP_OFFSET, '02X')} "
                f"in parsed sfputil output (keys: {sorted(byte_map.keys())})"
            )
            continue
        actual_bit = (raw_byte >> CMIS_PAGE_01_CDB_BG_MODE_BIT) & 0x01
        expected_bit = 1 if expected_cdb_bg_mode else 0

        if actual_bit != expected_bit:
            all_failures.append(
                f"{port}: CDB background mode mismatch: "
                f"expected bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {expected_bit} "
                f"(cdb_background_mode_supported={expected_cdb_bg_mode}), "
                f"got bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {actual_bit} "
                f"(raw byte: 0x{format(raw_byte, '02X')}, "
                f"page 0x{format(CMIS_PAGE_01_CDB_CAP_PAGE, '02X')} "
                f"offset 0x{format(CMIS_PAGE_01_CDB_CAP_OFFSET, '02X')})"
            )
        else:
            logger.debug(
                "Port %s CDB background mode verified: bit %d = %d "
                "(cdb_background_mode_supported=%s, raw byte: 0x%02X)",
                port, CMIS_PAGE_01_CDB_BG_MODE_BIT, actual_bit, expected_cdb_bg_mode, raw_byte,
            )

    if all_failures:
        pytest.fail("CDB background mode verification failures:\n" + "\n".join(all_failures))
