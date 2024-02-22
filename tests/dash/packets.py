from ipaddress import ip_address

import ptf.packet as scapy
from ptf.mask import Mask
import ptf.testutils as testutils

from constants import *  # noqa: F403


def generate_inner_packet(packet_type):
    if packet_type == 'udp':
        return testutils.simple_udp_packet
    elif packet_type == 'tcp':
        return testutils.simple_tcp_packet
    elif packet_type == 'echo_request' or packet_type == 'echo_reply':
        return testutils.simple_icmp_packet

    return None


def set_icmp_sub_type(packet, packet_type):
    if packet_type == 'echo_request':
        packet[scapy.ICMP].type = 8
    elif packet_type == 'echo_reply':
        packet[scapy.ICMP].type = 0


def inbound_vnet_packets(dash_config_info, inner_packet_type='udp'):
    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[REMOTE_ENI_MAC],
        eth_dst=dash_config_info[LOCAL_ENI_MAC],
        ip_src=dash_config_info[REMOTE_CA_IP],
        ip_dst=dash_config_info[LOCAL_CA_IP],
    )
    set_icmp_sub_type(inner_packet, inner_packet_type)
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


def outbound_vnet_packets(dash_config_info, inner_extra_conf={}, inner_packet_type='udp'):
    proto = None
    if "proto" in inner_extra_conf:
        proto = int(inner_extra_conf["proto"])
        del inner_extra_conf["proto"]

    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_dst=dash_config_info[REMOTE_CA_IP],
        **inner_extra_conf
    )
    set_icmp_sub_type(inner_packet, inner_packet_type)

    if proto:
        inner_packet[scapy.IP].proto = proto

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
        # TODO: Change TTL to 63 after SAI bug is fixed
        ip_ttl=0xff,
        ip_id=0,
        inner_frame=inner_packet
    )

    masked_exp_packet = Mask(expected_packet)
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
    return inner_packet, vxlan_packet, masked_exp_packet
