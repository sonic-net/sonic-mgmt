from ipaddress import ip_address

import ptf.packet as scapy
import scapy.utils as scapy_utils
from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.dataplane import match_exp_pkt
from constants import *  # noqa: F403
import logging
import sys
import time
from tests.common.helpers.assertions import pytest_assert
from six import StringIO


logger = logging.getLogger(__name__)


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


def inbound_vnet_packets(dash_config_info, inner_extra_conf={}, inner_packet_type='udp', vxlan_udp_dport=4789):
    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[REMOTE_ENI_MAC],
        eth_dst=dash_config_info[LOCAL_ENI_MAC],
        ip_src=dash_config_info[REMOTE_CA_IP],
        ip_dst=dash_config_info[LOCAL_CA_IP],
        **inner_extra_conf
    )
    set_icmp_sub_type(inner_packet, inner_packet_type)
    pa_match_vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[REMOTE_PTF_MAC],
        eth_dst=dash_config_info[DUT_MAC],
        ip_src=dash_config_info[REMOTE_PA_IP],
        ip_dst=dash_config_info[LOOPBACK_IP],
        udp_dport=vxlan_udp_dport,
        vxlan_vni=dash_config_info[VNET2_VNI],
        ip_ttl=64,
        inner_frame=inner_packet
    )
    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[LOCAL_PTF_MAC],
        ip_src=dash_config_info[LOOPBACK_IP],
        ip_dst=dash_config_info[LOCAL_PA_IP],
        udp_dport=vxlan_udp_dport,
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


def outbound_vnet_packets(dash_config_info, inner_extra_conf={}, inner_packet_type='udp', vxlan_udp_dport=4789):
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
        udp_dport=vxlan_udp_dport,
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
        udp_dport=vxlan_udp_dport,
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


def get_packets_on_specified_ports(ptfadapter, ports, filter_pkt_lens, device_number=0, duration=3, timeout=0.2):
    """
    Get the packets on the specified ports and device for the specified duration
    """
    logging.info("Get pkts on device %d, port %r", device_number, ports)

    received_pkts_res = {}
    start_time = time.time()
    while (time.time() - start_time) < duration:
        result = testutils.dp_poll(ptfadapter, device_number=device_number, timeout=timeout)
        logger.info(result)
        if isinstance(result, ptfadapter.dataplane.PollSuccess) and result.port in ports:
            if len(result.packet) in filter_pkt_lens:
                if result.port in received_pkts_res:
                    received_pkts_res[result.port].append(result)
                else:
                    received_pkts_res[result.port] = [result]
    return received_pkts_res


def verify_each_packet_on_each_port(exp_pkts, received_pkts_res, ports):
    """
    Verify each packet can be received on the corresponding port
    """
    logger.info(f"Checking pkts on ports :{ports}")
    for port, exp_pkt in zip(ports, exp_pkts):
        if port in received_pkts_res:
            find_matched_ptk = False
            for pkt_res in received_pkts_res[port]:
                if match_exp_pkt(exp_pkt, pkt_res.packet):
                    find_matched_ptk = True
                    logger.info(f"find the matched packet on port {port}")
                    break
            if not find_matched_ptk:
                logger.error(
                    print_expect_packet_and_received_packet_hex_information([exp_pkt], received_pkts_res[port]))
                pytest_assert(False, f"Not find the matched pkt on port {port}")
        else:
            pytest_assert(False, f"port {port} doesn't receive any packet")
    return True


def verify_packets_not_received(unexp_pkts, received_pkts_res):
    """
    Verify packets are not received
    """
    for unexp_pkt in unexp_pkts:
        for _, received_pkts in received_pkts_res.items():
            for pkt_res in received_pkts:
                if match_exp_pkt(unexp_pkt, pkt_res.packet):
                    logger.error(print_expect_packet_and_received_packet_hex_information([unexp_pkt], received_pkts))
                    pytest_assert(False, f" unexpected packet are received on port {pkt_res.port}")
    return True


def print_expect_packet_and_received_packet_hex_information(exp_pkts, received_pkts_res):
    try:
        stdout_save = sys.stdout
        # The scapy packet dissection methods print directly to stdout,
        # so we have to redirect stdout to a string.
        sys.stdout = StringIO()

        for exp_pkt in exp_pkts:
            print("Expected pkt:")
            scapy_utils.hexdump(exp_pkt.exp_pkt)
            print("Expected pkt mask:")
            scapy_utils.hexdump(exp_pkt.mask)

        print("==============================")
        for pkt_res in received_pkts_res:
            print("Receive pkt:")
            scapy_utils.hexdump(pkt_res.packet)

        return sys.stdout.getvalue()
    finally:
        sys.stdout.close()
        sys.stdout = stdout_save  # Restore the original stdout.


def verify_tcp_packet_drop_rst_packet_sent(ptfadapter,
                                           exp_rst_pkts,
                                           drop_tcp_pkts, ports,
                                           filter_pkt_lens, device_number=0, duration=10, timeout=0.2):
    received_pkts_res = get_packets_on_specified_ports(
        ptfadapter, ports, filter_pkt_lens, device_number, duration, timeout)
    verify_packets_not_received(drop_tcp_pkts, received_pkts_res)
    verify_each_packet_on_each_port(exp_rst_pkts, received_pkts_res, ports)
