"""TC4: CDB firmware activation validation.

Activates firmware and verifies the final firmware state and recovery.
"""
import logging
import pytest

from tests.transceiver.cdb_firmware_upgrade import firmware_operations

logger = logging.getLogger(__name__)


def test_firmware_activation(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    required_firmware_metadata_for_all_transceivers,
    dom_polling_disabled,
):
    """Activate selected firmware and verify every qualifying module recovers."""
    all_failures, num_ports = firmware_operations.execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping,
        required_firmware_metadata_for_all_transceivers, firmware_operations.activation_op,
    )
    logger.info("Firmware activation exercised %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware activation failures:\n" + "\n".join(all_failures))
