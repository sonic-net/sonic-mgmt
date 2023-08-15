import logging
from ipaddress import ip_address

import pytest
import ptf.packet as scapy
from ptf.mask import Mask
import ptf.testutils as testutils

from constants import VM_VNI, VNET2_VNI, REMOTE_CA_IP, LOCAL_CA_IP, REMOTE_ENI_MAC,\
    LOCAL_ENI_MAC, LOOPBACK_IP, DUT_MAC, LOCAL_PA_IP, LOCAL_PTF_INTF, LOCAL_PTF_MAC,\
    REMOTE_PA_IP, REMOTE_PTF_INTF, REMOTE_PTF_MAC

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('appliance'),
    pytest.mark.disable_loganalyzer
]


@pytest.fixture
def inbound_vnet_packets(dash_config_info):
    inner_packet = testutils.simple_udp_packet(
        eth_src=dash_config_info[REMOTE_ENI_MAC],
        eth_dst=dash_config_info[LOCAL_ENI_MAC],
        ip_src=dash_config_info[REMOTE_CA_IP],
        ip_dst=dash_config_info[LOCAL_CA_IP],
    )
    pa_match_vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[REMOTE_PTF_MAC],
        eth_dst=dash_config_info[DUT_MAC],
        ip_src=dash_config_info[REMOTE_PA_IP],
        ip_dst=dash_config_info[LOOPBACK_IP],
        vxlan_vni=dash_config_info[VNET2_VNI],
        ip_ttl=64,
        inner_frame=inner_packet
    )
    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[LOCAL_PTF_MAC],
        ip_src=dash_config_info[LOOPBACK_IP],
        ip_dst=dash_config_info[LOCAL_PA_IP],
        vxlan_vni=dash_config_info[VM_VNI],
        ip_ttl=255,
        ip_id=0,
        inner_frame=inner_packet
    )

    pa_mismatch_vxlan_packet = pa_match_vxlan_packet.copy()
    remote_pa_ip = ip_address(dash_config_info[REMOTE_PA_IP])
    pa_mismatch_vxlan_packet["IP"].src = str(remote_pa_ip + 1)

    masked_exp_packet = Mask(expected_packet)
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")

    return inner_packet, pa_match_vxlan_packet, pa_mismatch_vxlan_packet, masked_exp_packet


@pytest.fixture
def outbound_vnet_packets(dash_config_info):
    inner_packet = testutils.simple_udp_packet(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_dst=dash_config_info[REMOTE_CA_IP],
    )
    vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[LOCAL_PTF_MAC],
        eth_dst=dash_config_info[DUT_MAC],
        ip_src=dash_config_info[LOCAL_PA_IP],
        ip_dst=dash_config_info[LOOPBACK_IP],
        with_udp_chksum=False,
        vxlan_vni=dash_config_info[VM_VNI],
        ip_ttl=64,
        inner_frame=inner_packet
    )
    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[REMOTE_PTF_MAC],
        ip_src=dash_config_info[LOOPBACK_IP],
        ip_dst=dash_config_info[REMOTE_PA_IP],
        vxlan_vni=dash_config_info[VNET2_VNI],
        ip_ttl=255,
        ip_id=0,
        inner_frame=inner_packet
    )

    masked_exp_packet = Mask(expected_packet)
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
    return inner_packet, vxlan_packet, masked_exp_packet


def test_outbound_vnet(ptfadapter, apply_vnet_configs, outbound_vnet_packets, dash_config_info):
    """
    Send VXLAN packets from the VM VNI
    """
    _, vxlan_packet, expected_packet = outbound_vnet_packets
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])


def test_outbound_vnet_direct(ptfadapter, apply_vnet_direct_configs, outbound_vnet_packets, dash_config_info):
    _, vxlan_packet, expected_packet = outbound_vnet_packets
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_packet, dash_config_info[REMOTE_PTF_INTF])


def test_outbound_direct(ptfadapter, apply_direct_configs, outbound_vnet_packets, dash_config_info):
    expected_inner_packet, vxlan_packet, _ = outbound_vnet_packets
    testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_inner_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    # testutils.verify_packet(ptfadapter, expected_inner_packet, dash_config_info[REMOTE_PTF_INTF])


def test_inbound_vnet_pa_validate(ptfadapter, apply_inbound_configs, inbound_vnet_packets, dash_config_info):
    """
    Send VXLAN packets from the remote VNI with PA validation enabled

    1. Send one packet where the source PA (outer source IP) matches the VNET mapping table
        - Expect DPU to forward packet normally
    2. Send one packet where the source PA does not match the mapping table
        - Expect DPU to drop packet
    """
    _,  pa_match_packet, pa_mismatch_packet, expected_packet = inbound_vnet_packets
    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_match_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[LOCAL_PTF_INTF])

    testutils.send(ptfadapter, dash_config_info[REMOTE_PTF_INTF], pa_mismatch_packet, 1)
    testutils.verify_no_packet_any(ptfadapter, expected_packet, ports=dash_config_info[LOCAL_PTF_INTF])
