"""CDB firmware upgrade validation."""

import logging
import pytest

from tests.transceiver.cdb_firmware_upgrade import firmware_operations

logger = logging.getLogger(__name__)


def test_firmware_upgrade_distinct_version(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Upgrade every qualifying module to the fully distinct firmware version."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers,
        firmware_operations.distinct_version_upgrade_op,
        verify_post_operation=True,
    )
    logger.info("Firmware upgrade to distinct version exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware upgrade to distinct version failures:\n" + "\n".join(all_failures))


def test_firmware_upgrade_stress(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Verify repeated full firmware upgrades succeed without drift."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers,
        firmware_operations.upgrade_stress_op,
        verify_post_operation=True,
    )
    logger.info("Firmware upgrade stress exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware upgrade stress failures:\n" + "\n".join(all_failures))
