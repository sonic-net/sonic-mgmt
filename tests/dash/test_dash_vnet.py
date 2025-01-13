import logging
import pytest
import ptf.testutils as testutils
import packets

from constants import LOCAL_PTF_INTF, REMOTE_PTF_INTF

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('dpu'),
    pytest.mark.disable_loganalyzer
]


def test_outbound_vnet(
        ptfadapter,
        apply_vnet_configs,
        dash_config_info,
        skip_dataplane_checking,
        asic_db_checker,
        inner_packet_type,
        acl_default_rule,
        vxlan_udp_dport):
    """
    Send VXLAN packets from the VM VNI
    """
    asic_db_checker(["SAI_OBJECT_TYPE_VNET", "SAI_OBJECT_TYPE_ENI"])
    if skip_dataplane_checking:
        return
    _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info,
                                                                     vxlan_udp_dport=vxlan_udp_dport,
                                                                     inner_packet_type=inner_packet_type)
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])


def test_outbound_vnet_direct(
        ptfadapter,
        apply_vnet_direct_configs,
        dash_config_info,
        skip_dataplane_checking,
        asic_db_checker,
        inner_packet_type,
        acl_default_rule,
        vxlan_udp_dport):
    asic_db_checker(["SAI_OBJECT_TYPE_VNET", "SAI_OBJECT_TYPE_ENI"])
    if skip_dataplane_checking:
        return
    _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info,
                                                                     vxlan_udp_dport=vxlan_udp_dport,
                                                                     inner_packet_type=inner_packet_type)
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])


def test_outbound_direct(
        ptfadapter,
        apply_direct_configs,
        dash_config_info,
        skip_dataplane_checking,
        asic_db_checker,
        inner_packet_type,
        acl_default_rule,
        vxlan_udp_dport):
    asic_db_checker(["SAI_OBJECT_TYPE_VNET", "SAI_OBJECT_TYPE_ENI"])
    if skip_dataplane_checking:
        return
    expected_inner_packet, vxlan_packet, _ = packets.outbound_vnet_packets(dash_config_info,
                                                                           vxlan_udp_dport=vxlan_udp_dport,
                                                                           inner_packet_type=inner_packet_type)
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_inner_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_inner_packet, dash_config_info[REMOTE_PTF_INTF])


def test_inbound_vnet_pa_validate(
        ptfadapter,
        apply_inbound_configs,
        dash_config_info,
        skip_dataplane_checking,
        asic_db_checker,
        inner_packet_type,
        acl_default_rule,
        vxlan_udp_dport):
    """
    Send VXLAN packets from the remote VNI with PA validation enabled

    1. Send one packet where the source PA (outer source IP) matches the VNET mapping table
        - Expect DPU to forward packet normally
    2. Send one packet where the source PA does not match the mapping table
        - Expect DPU to drop packet
    """
    asic_db_checker(["SAI_OBJECT_TYPE_VNET", "SAI_OBJECT_TYPE_ENI"])
    if skip_dataplane_checking:
        return
    _,  pa_match_packet, pa_mismatch_packet, expected_packet = packets.inbound_vnet_packets(
        dash_config_info, vxlan_udp_dport=vxlan_udp_dport, inner_packet_type=inner_packet_type)
    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_match_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[LOCAL_PTF_INTF])
    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_mismatch_packet, 1)
