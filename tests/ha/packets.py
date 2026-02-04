import logging
import random
from ipaddress import ip_address

import ptf.packet as scapy
import ptf.testutils as testutils
from configs import privatelink_config as pl
from constants import VXLAN_UDP_BASE_SRC_PORT, VXLAN_UDP_SRC_PORT_MASK, \
        DUT_MAC, LOCAL_PTF_MAC, REMOTE_PTF_MAC
from ptf.mask import Mask

logger = logging.getLogger(__name__)


def generate_inner_packet(packet_type, ipv6=False):
    if packet_type == "udp":
        if ipv6:
            return testutils.simple_udpv6_packet
        else:
            return testutils.simple_udp_packet
    elif packet_type == "tcp":
        if ipv6:
            return testutils.simple_tcpv6_packet
        else:
            return testutils.simple_tcp_packet
    elif packet_type == "echo_request" or packet_type == "echo_reply":
        if ipv6:
            return testutils.simple_icmpv6_packet
        else:
            return testutils.simple_icmp_packet

    return None


def get_bits(ip):
    addr = ip_address(ip)
    return int(addr)


def get_pl_overlay_sip(orig_sip, ol_sip, ol_mask, pl_sip_encoding, pl_sip_mask):
    pkt_sip = get_bits(orig_sip)
    ol_sip_ip = get_bits(ol_sip)
    ol_sip_mask = get_bits(ol_mask)
    pl_encoding_ip = get_bits(pl_sip_encoding)
    pl_encoding_mask = get_bits(pl_sip_mask)

    overlay_sip = (((pkt_sip & ~ol_sip_mask) | ol_sip_ip) & ~pl_encoding_mask) | pl_encoding_ip
    return str(ip_address(overlay_sip))


def get_pl_overlay_dip(orig_dip, ol_dip, ol_mask):
    pkt_dip = get_bits(orig_dip)
    ol_dip_ip = get_bits(ol_dip)
    ol_dip_mask = get_bits(ol_mask)

    overlay_dip = (pkt_dip & ~ol_dip_mask) | ol_dip_ip
    return str(ip_address(overlay_dip))


def inbound_pl_packets(
    config, floating_nic=False, inner_packet_type="udp", vxlan_udp_dport=4789, inner_sport=4567, inner_dport=6789,
    vxlan_udp_base_src_port=VXLAN_UDP_BASE_SRC_PORT, vxlan_udp_src_port_mask=VXLAN_UDP_SRC_PORT_MASK
):
    inner_sip = get_pl_overlay_dip(  # not a typo, inner DIP/SIP are reversed for inbound direction
        pl.PE_CA, pl.PL_OVERLAY_DIP, pl.PL_OVERLAY_DIP_MASK
    )

    inner_dip = get_pl_overlay_sip(
        pl.VM1_CA, pl.PL_OVERLAY_SIP, pl.PL_OVERLAY_SIP_MASK, pl.PL_ENCODING_IP, pl.PL_ENCODING_MASK
    )

    l4_protocol_key = get_scapy_l4_protocol_key(inner_packet_type)

    inner_packet = generate_inner_packet(inner_packet_type, ipv6=True)(
        eth_src=pl.REMOTE_MAC,
        eth_dst=pl.ENI_MAC,
        ipv6_src=inner_sip,
        ipv6_dst=inner_dip,
    )
    inner_packet[l4_protocol_key].sport = inner_sport
    inner_packet[l4_protocol_key].dport = inner_dport

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
        ip_src=pl.PE_CA,
        ip_dst=pl.VM1_CA,
        ip_id=0,
    )

    l4_protocol_key = get_scapy_l4_protocol_key(inner_packet_type)
    exp_inner_packet[l4_protocol_key] = inner_packet[l4_protocol_key]

    exp_vxlan_packet = testutils.simple_vxlan_packet(
        eth_src=config[DUT_MAC],
        eth_dst=config[LOCAL_PTF_MAC],
        ip_src=pl.APPLIANCE_VIP,
        ip_dst=pl.VM1_PA,
        ip_ttl=254,
        ip_id=0,
        udp_dport=vxlan_udp_dport,
        udp_sport=vxlan_udp_base_src_port,
        vxlan_vni=pl.ENCAP_VNI if floating_nic else int(pl.VNET1_VNI),
        inner_frame=exp_inner_packet,
    )

    masked_exp_packet = Mask(exp_vxlan_packet)
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")
    masked_exp_packet.set_do_not_care_packet(scapy.UDP, "chksum")
    masked_exp_packet.set_do_not_care(8 * (34 + 2) - vxlan_udp_src_port_mask, vxlan_udp_src_port_mask)
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "ttl")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
    if floating_nic:
        # As destination IP is not fixed in case of return path ECMP,
        # we need to mask the checksum and destination IP
        masked_exp_packet.set_do_not_care_packet(scapy.IP, "dst")
        masked_exp_packet.set_do_not_care(400, 48)  # Inner dst MAC

    return gre_packet, masked_exp_packet


def outbound_pl_packets(
    config,
    outer_encap,
    floating_nic=False,
    inner_packet_type="udp",
    vxlan_udp_dport=4789,
    vxlan_udp_sport=random.randint(
        VXLAN_UDP_BASE_SRC_PORT,
        VXLAN_UDP_BASE_SRC_PORT + 2**VXLAN_UDP_SRC_PORT_MASK - 1),
    inner_sport=6789,
    inner_dport=4567,
    vni=None
):
    outer_vni = int(vni if vni else pl.VM_VNI)

    l4_protocol_key = get_scapy_l4_protocol_key(inner_packet_type)

    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=pl.VM_MAC if floating_nic else pl.ENI_MAC,
        eth_dst=pl.ENI_MAC if floating_nic else pl.REMOTE_MAC,
        ip_src=pl.VM1_CA,
        ip_dst=pl.PE_CA,
    )
    inner_packet[l4_protocol_key].sport = inner_sport
    inner_packet[l4_protocol_key].dport = inner_dport

    if outer_encap == "vxlan":
        outer_packet = testutils.simple_vxlan_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=pl.VM1_PA,
            ip_dst=pl.APPLIANCE_VIP,
            udp_dport=vxlan_udp_dport,
            udp_sport=vxlan_udp_sport,
            with_udp_chksum=False,
            vxlan_vni=outer_vni if floating_nic else int(pl.VNET1_VNI),
            inner_frame=inner_packet,
        )
    elif outer_encap == "gre":
        outer_packet = testutils.simple_gre_packet(
            eth_src=config[LOCAL_PTF_MAC],
            eth_dst=config[DUT_MAC],
            ip_src=pl.VM1_PA,
            ip_dst=pl.APPLIANCE_VIP,
            gre_key_present=True,
            gre_key=(outer_vni << 8) if floating_nic else (int(pl.VNET1_VNI) << 8),
            inner_frame=inner_packet,
        )
    else:
        logger.error(f"Unsupported encap type: {outer_encap}")
        return None

    exp_overlay_sip = get_pl_overlay_sip(
        inner_packet[scapy.IP].src, pl.PL_OVERLAY_SIP, pl.PL_OVERLAY_SIP_MASK, pl.PL_ENCODING_IP, pl.PL_ENCODING_MASK
    )

    exp_overlay_dip = get_pl_overlay_dip(inner_packet[scapy.IP].dst, pl.PL_OVERLAY_DIP, pl.PL_OVERLAY_DIP_MASK)

    logger.debug(f"Expecting overlay SIP: {exp_overlay_sip}")
    logger.debug(f"Expecting overlay DIP: {exp_overlay_dip}")

    if inner_packet_type == 'tcp':
        exp_inner_packet = scapy.Ether() / scapy.IPv6() / scapy.TCP()
    else:
        exp_inner_packet = scapy.Ether() / scapy.IPv6() / scapy.UDP()
    exp_inner_packet[scapy.Ether].src = pl.ENI_MAC
    exp_inner_packet[scapy.Ether].dst = pl.REMOTE_MAC
    exp_inner_packet[scapy.IPv6].src = exp_overlay_sip
    exp_inner_packet[scapy.IPv6].dst = exp_overlay_dip

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
    )

    masked_exp_packet = Mask(exp_encap_packet)
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
    masked_exp_packet.set_do_not_care_packet(scapy.IP, "ttl")  # behavior differs between Cisco and Nvidia platforms
    masked_exp_packet.set_do_not_care(336, 48)  # Inner Ether dst

    return outer_packet, masked_exp_packet


def get_scapy_l4_protocol_key(inner_packet_type):
    scapy_tcp = scapy.TCP
    scapy_udp = scapy.UDP
    l4_protocol_key = scapy_udp if inner_packet_type == 'udp' else scapy_tcp
    return l4_protocol_key
