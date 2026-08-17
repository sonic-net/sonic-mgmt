"""TC3: CDB firmware download validation.

Downloads the next firmware in ``firmware_versions`` to the target bank and
verifies the firmware-downloaded state.
"""
import logging
import pytest

from tests.transceiver.cdb_firmware_upgrade import firmware_operations

logger = logging.getLogger(__name__)


def test_firmware_download(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Download firmware to the target bank and verify every qualifying module."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers, firmware_operations.perform_firmware_download,
    )
    logger.info("Firmware download exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware download failures:\n" + "\n".join(all_failures))
