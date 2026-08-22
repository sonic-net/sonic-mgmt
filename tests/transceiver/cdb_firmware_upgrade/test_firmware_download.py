"""CDB firmware download validation."""

import logging
import pytest

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
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
        verify_post_operation=True,
    )
    logger.info("Firmware download exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware download failures:\n" + "\n".join(all_failures))


def test_firmware_download_post_reset(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Verify a downloaded firmware image survives a transceiver reset."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers,
        firmware_operations.download_post_reset_op,
        verify_post_operation=True,
    )
    logger.info("Firmware download post reset exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware download post reset failures:\n" + "\n".join(all_failures))


def test_firmware_download_low_power(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Verify firmware downloads succeed while the module is in low-power mode."""
    low_power_ports = [
        port for port in cdb_firmware_qualifying_ports
        if port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get("low_power_mode_supported", False)
    ]
    if not low_power_ports:
        pytest.skip("No qualifying ports have low_power_mode_supported set")

    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, low_power_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers,
        firmware_operations.download_low_power_op,
        verify_post_operation=True,
    )
    logger.info("Firmware download in low-power mode exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware download in low-power mode failures:\n" + "\n".join(all_failures))


def test_firmware_download_admin_down(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Verify firmware downloads succeed while the port is admin-down."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers,
        firmware_operations.download_admin_down_op,
        verify_post_operation=True,
    )
    logger.info("Firmware download with admin-down port exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware download with admin-down port failures:\n" + "\n".join(all_failures))
