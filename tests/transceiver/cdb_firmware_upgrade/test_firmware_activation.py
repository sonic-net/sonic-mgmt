"""CDB firmware activation validation."""

import logging
import pytest

from tests.transceiver.cdb_firmware_upgrade import firmware_operations

logger = logging.getLogger(__name__)


def test_firmware_activation(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers, lport_to_first_subport_mapping,
    port_peers,
):
    """Activate selected firmware and verify every qualifying module recovers."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers, firmware_operations.activation_op,
        lport_to_first_subport_mapping,
        verify_post_operation=True,
        port_peers=port_peers,
    )
    logger.info("Firmware activation exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware activation failures:\n" + "\n".join(all_failures))
