import logging

import pytest
import ptf.testutils as testutils

from constants import *  # noqa: F403
import packets

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('appliance'),
    pytest.mark.disable_loganalyzer
]


def test_outbound_vnet(ptfadapter, apply_vnet_configs, dash_config_info):
    """
    Send VXLAN packets from the VM VNI
    """
    _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info)
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])


def test_inbound_vnet_pa_validate(ptfadapter, apply_vnet_configs, dash_config_info):
    """
    Send VXLAN packets from the remote VNI with PA validation enabled

    1. Send one packet where the source PA (outer source IP) matches the VNET mapping table
        - Expect DPU to forward packet normally
    2. Send one packet where the source PA does not match the mapping table
        - Expect DPU to drop packet
    """
    _,  pa_match_packet, pa_mismatch_packet, expected_packet = packets.inbound_vnet_packets(dash_config_info)
    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_match_packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[LOCAL_PTF_INTF])

    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_mismatch_packet, 1)
    testutils.verify_no_packet(ptfadapter, expected_packet, dash_config_info[LOCAL_PTF_INTF])
