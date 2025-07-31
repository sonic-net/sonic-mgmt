import logging
import sys
import time
from ipaddress import ip_address

import ptf.packet as scapy
import ptf.testutils as testutils
import scapy.utils as scapy_utils
from configs import privatelink_config as pl
from constants import *  # noqa: F403
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
from six import StringIO

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def generate_inner_packet(packet_type, ipv6=False):
    if packet_type == 'udp':
        if ipv6:
            return testutils.simple_udpv6_packet
        else:
            return testutils.simple_udp_packet
    elif packet_type == 'tcp':
        if ipv6:
            return testutils.simple_tcpv6_packet
        else:
            return testutils.simple_tcp_packet
    elif packet_type == 'echo_request' or packet_type == 'echo_reply':
        if ipv6:
            return testutils.simple_icmpv6_packet
        else:
            return testutils.simple_icmp_packet

    return None


def set_icmp_sub_type(packet, packet_type):
    if packet_type == 'echo_request':
        packet[scapy.ICMP].type = 8
    elif packet_type == 'echo_reply':
        packet[scapy.ICMP].type = 0


def get_bits(ip):
    addr = ip_address(ip)
    return int(addr)


def get_pl_overlay_sip(orig_sip, ol_sip, ol_mask, pl_sip_encoding, pl_sip_mask):
    pkt_sip = get_bits(orig_sip)
    ol_sip_ip = get_bits(ol_sip)
    ol_sip_mask = get_bits(ol_mask)
    pl_encoding_ip = get_bits(pl_sip_encoding)
    pl_encoding_mask = get_bits(pl_sip_mask)

    overlay_sip = (
        ((pkt_sip & ~ol_sip_mask) | ol_sip_ip) & ~pl_encoding_mask
    ) | pl_encoding_ip
    return str(ip_address(overlay_sip))


def get_pl_overlay_dip(orig_dip, ol_dip, ol_mask):
    pkt_dip = get_bits(orig_dip)
    ol_dip_ip = get_bits(ol_dip)
    ol_dip_mask = get_bits(ol_mask)

    overlay_dip = (pkt_dip & ~ol_dip_mask) | ol_dip_ip
    return str(ip_address(overlay_dip))


def inbound_pl_packets(config, floating_nic=False, inner_packet_type='udp', vxlan_udp_dport=4789):
    inner_sip = get_pl_overlay_dip(  # not a typo, inner DIP/SIP are reversed for inbound direction
        pl.PE_CA,
        pl.PL_OVERLAY_DIP,
        pl.PL_OVERLAY_DIP_MASK
    )

    inner_dip = get_pl_overlay_sip(
        pl.VM1_CA,
        pl.PL_OVERLAY_SIP,
        pl.PL_OVERLAY_SIP_MASK,
        pl.PL_ENCODING_IP,
        pl.PL_ENCODING_MASK
    )

    inner_packet = generate_inner_packet(inner_packet_type, ipv6=True)(
        eth_src=pl.REMOTE_MAC,
        eth_dst=pl.ENI_MAC, 
        ipv6_src=inner_sip,
        ipv6_dst=inner_dip,
    )

    l4_protocol_key = get_scapy_l4_protocol_key(inner_packet_type)

    sport = inner_packet[l4_protocol_key].sport
    dport = inner_packet[l4_protocol_key].dport
    inner_packet[l4_protocol_key].sport = dport
    inner_packet[l4_protocol_key].dport = sport

    gre_packet = testutils.simple_gre_packet(
        eth_dst=config[DUT_MAC],
        ip_src=pl.PE_PA,
        ip_dst=pl.APPLIANCE_VIP,
        gre_key_present=True,
        gre_key=int(pl.ENCAP_VNI) << 8,
        inner_frame=inner_packet,
    )

    exp_inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=pl.ENI_MAC if floating_nic else pl.REMOTE_MAC,
        eth_dst=pl.VM_MAC if floating_nic else pl.ENI_MAC,
        ip_src=pl.PE1_CA,
        ip_dst=pl.VM1_CA,
        ip_id=0,
    )

    exp_inner_packet[l4_protocol_key].sport = dport
    exp_inner_packet[l4_protocol_key].dport = sport
    exp_inner_packet[l4_protocol_key].load = inner_packet[l4_protocol_key].load

    exp_vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=config[DUT_MAC],
        eth_dst=config[LOCAL_PTF_MAC],
        ip_src=pl.APPLIANCE_VIP,
        ip_dst=pl.VM1_PA,
        ip_ttl=254,
        ip_id=0,
        udp_dport=vxlan_udp_dport,
        udp_sport=VXLAN_UDP_BASE_SRC_PORT,
        vxlan_vni=202 if floating_nic else int(pl.VM_VNI),
        inner_frame=exp_inner_packet
    )

    masked_exp_packet = Mask(exp_vxlan_packet)
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_packet(scapy.UDP, "chksum")
    if floating_nic:
        masked_exp_packet.set_do_not_care_packet(scapy.IP, "dst")
    # 34 is the sport offset, 2 is the length of UDP sport field
    masked_exp_packet.set_do_not_care(8 * (34 + 2) - VXLAN_UDP_SRC_PORT_MASK, VXLAN_UDP_SRC_PORT_MASK)
    # mask the UDP payload TODO: need further triage on why the payload is being modified
    # Not a platform specific issue, but a problem with the PTF
    masked_exp_packet.set_do_not_care(8 * (90), 8 * (40))

    return gre_packet, masked_exp_packet


def outbound_pl_packets(config, outer_encap, floating_nic=False, inner_packet_type='udp',
                        vxlan_udp_dport=4789, inner_extra_conf={}, vxlan_udp_sport=1234, nsg_packet=False):
    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=pl.VM_MAC if floating_nic else pl.ENI_MAC,
        eth_dst=pl.ENI_MAC if floating_nic else pl.REMOTE_MAC,
        ip_src=pl.VM1_CA,
        ip_dst=pl.PE_CA,
    )
    l4_protocol_key = get_scapy_l4_protocol_key(inner_packet_type)

    if outer_encap == 'vxlan':
        outer_packet = testutils.simple_vxlan_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=pl.VM1_PA,
            ip_dst=pl.APPLIANCE_VIP,
            udp_dport=vxlan_udp_dport,
            udp_sport=vxlan_udp_sport,
            with_udp_chksum=False,
            vxlan_vni=int(pl.VM_VNI),
            inner_frame=inner_packet
        )
    elif outer_encap == 'gre':
        outer_packet = testutils.simple_gre_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=pl.VM1_PA,
            ip_dst=pl.APPLIANCE_VIP,
            gre_key_present=True,
            gre_key=int(pl.VM_VNI) << 8,
            inner_frame=inner_packet
        )
    else:
        logger.error(f"Unsupported encap type: {outer_encap}")
        return None

    exp_overlay_sip = get_pl_overlay_sip(
        inner_packet[scapy.IP].src,
        pl.PL_OVERLAY_SIP,
        pl.PL_OVERLAY_SIP_MASK,
        pl.PL_ENCODING_IP,
        pl.PL_ENCODING_MASK
    )

    exp_overlay_dip = get_pl_overlay_dip(
        inner_packet[scapy.IP].dst,
        pl.PL_OVERLAY_DIP,
        pl.PL_OVERLAY_DIP_MASK
    )

    logger.info(f"Expecting overlay SIP: {exp_overlay_sip}")
    logger.info(f"Expecting overlay DIP: {exp_overlay_dip}")

    if inner_packet_type == 'tcp':
        exp_inner_packet = scapy.Ether() / scapy.IPv6() / scapy.TCP()
    else:
        exp_inner_packet = scapy.Ether() / scapy.IPv6() / scapy.UDP()
    exp_inner_packet[scapy.Ether].src = pl.ENI_MAC
    exp_inner_packet[scapy.Ether].dst = pl.REMOTE_MAC
    exp_inner_packet[scapy.IPv6].src = exp_overlay_sip
    exp_inner_packet[scapy.IPv6].dst = exp_overlay_dip

    exp_inner_packet[l4_protocol_key] = inner_packet[l4_protocol_key]
    if nsg_packet:
        ip_ttl = 255
    else:
        ip_ttl = 254

    exp_inner_packet[l4_protocol_key] = inner_packet[l4_protocol_key]

    exp_encap_packet = testutils.simple_gre_packet(
        eth_dst=config[REMOTE_PTF_MAC],
        eth_src=config[DUT_MAC],
        ip_src=pl.APPLIANCE_VIP,
        ip_dst=pl.PE_PA,
        gre_key_present=True,
        gre_key=pl.ENCAP_VNI << 8,
        inner_frame=exp_inner_packet,
        ip_id=0,
        ip_ttl=63 if use_pkt_alt_attrs else 254,
    )

    masked_exp_packet = Mask(exp_encap_packet)
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care(336, 48)  # Inner Ether dst

    return outer_packet, masked_exp_packet


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

def build_outer_encap_packet(config, encap_type, inner_packet, ip_src, ip_dst,
                             encap_key, vxlan_udp_dport):
    if encap_type == 'vxlan':
        outer_packet = testutils.simple_vxlan_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=ip_src,
            ip_dst=ip_dst,
            udp_dport=vxlan_udp_dport,
            udp_sport=VXLAN_UDP_BASE_SRC_PORT,
            with_udp_chksum=False,
            ip_id=0,
            ip_ttl=254,
            vxlan_vni=int(encap_key),
            inner_frame=inner_packet
        )
    elif encap_type == 'gre':
        outer_packet = testutils.simple_gre_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=ip_src,
            ip_dst=ip_dst,
            gre_key_present=True,
            gre_key=int(encap_key) << 8,
            inner_frame=inner_packet
        )
    else:
        logger.error(f"Unsupported encap type: {encap_type}")
        return None

    return outer_packet


def generate_plnsg_packets(config, floating_nic, inner_encap, outer_encap, inner_packet_type='udp', num_packets=1000):
    plnsg_pkts = []
    for i in range(num_packets):
        sport = random.randint(49152, 65535)
        outbound_pkt, outbound_exp_pkt = outbound_plnsg_packets(
            config=config, floating_nic=floating_nic, inner_encap=inner_encap, outer_encap=outer_encap, inner_sport=sport
        )
        inbound_pkt, inbound_exp_pkt = inbound_pl_packets(
            config, floating_nic, inner_packet_type=inner_packet_type, vxlan_udp_dport=4789
        )
        plnsg_pkts.append((
            outbound_pkt,
            outbound_exp_pkt,
            inbound_pkt,
            inbound_exp_pkt
        ))

    return plnsg_pkts


def outbound_plnsg_packets(config, floating_nic, inner_encap, outer_encap, inner_sport, inner_packet_type='udp',
                           vxlan_udp_dport=4789, vxlan_udp_sport=1234):
    pl_outer_packet, pl_exp_packet = outbound_pl_packets(
        config, inner_encap, floating_nic, inner_packet_type=inner_packet_type, vxlan_udp_sport=inner_sport, nsg_packet=True
    )

    nsg_exp_packet = build_outer_encap_packet(
        config, "vxlan", pl_exp_packet.exp_pkt, pl.APPLIANCE_VIP, pl.TUNNEL1_ENDPOINT_IP,
        pl.ENCAP_VNI, vxlan_udp_dport
    )

    masked_exp_packet = Mask(nsg_exp_packet)
    # Set masks for outer encapsulation
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "dst")
    masked_exp_packet.set_do_not_care(8 * (34 + 2) - VXLAN_UDP_SRC_PORT_MASK, VXLAN_UDP_SRC_PORT_MASK)
    masked_exp_packet.set_do_not_care_packet(scapy.UDP, "chksum")

    # Set masks for inner packet (offset by outer encapsulation size)
    inner_offset = 50  # Ethernet(14) + IP(20) + UDP(8) + VXLAN(8) + Inner Ethernet(14)
    masked_exp_packet.mask[inner_offset:inner_offset + len(pl_exp_packet.mask)] = pl_exp_packet.mask

    return pl_outer_packet, masked_exp_packet


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


def outbound_smartswitch_vnet_packets(dash_config_info, inner_extra_conf={},
                                      inner_packet_type='udp', vxlan_udp_dport=4789):

    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_dst=dash_config_info[REMOTE_CA_IP]
    )
    set_icmp_sub_type(inner_packet, inner_packet_type)

    vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[LOCAL_PTF_MAC],
        eth_dst=dash_config_info[DUT_MAC],
        ip_src=dash_config_info[LOCAL_PA_IP],
        ip_dst=dash_config_info[LOOPBACK_IP],
        udp_dport=vxlan_udp_dport,
        with_udp_chksum=False,
        vxlan_vni=dash_config_info[VNET1_VNI],
        ip_ttl=64,
        inner_frame=inner_packet
    )
    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[REMOTE_PTF_MAC],
        ip_src=dash_config_info[LOOPBACK_IP],
        ip_dst=dash_config_info[REMOTE_PA_IP],
        udp_dport=vxlan_udp_dport,
        vxlan_vni=dash_config_info[VNET1_VNI],
        ip_ttl=63,
        ip_id=0,
        inner_frame=inner_packet
    )

    masked_exp_packet = Mask(expected_packet)
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "sport")
    masked_exp_packet.set_do_not_care_scapy(scapy.UDP, "chksum")
    return inner_packet, vxlan_packet, masked_exp_packet


def get_scapy_l4_protocol_key(inner_packet_type):
    scapy_tcp = scapy.TCP
    scapy_udp = scapy.UDP
    l4_protocol_key = scapy_udp if inner_packet_type == 'udp' else scapy_tcp
    return l4_protocol_key
