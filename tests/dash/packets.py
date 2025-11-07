import logging
import random
import sys
import time
from ipaddress import ip_address

import ptf.packet as scapy
import ptf.testutils as testutils
import scapy.utils as scapy_utils
from configs import privatelink_config as pl
from constants import *  # noqa: F403
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask, MaskException
from six import StringIO

from tests.common.helpers.assertions import pytest_assert

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


def set_icmp_sub_type(packet, packet_type):
    if packet_type == "echo_request":
        packet[scapy.ICMP].type = 8
    elif packet_type == "echo_reply":
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

    overlay_sip = (((pkt_sip & ~ol_sip_mask) | ol_sip_ip) & ~pl_encoding_mask) | pl_encoding_ip
    return str(ip_address(overlay_sip))


def get_pl_overlay_dip(orig_dip, ol_dip, ol_mask):
    pkt_dip = get_bits(orig_dip)
    ol_dip_ip = get_bits(ol_dip)
    ol_dip_mask = get_bits(ol_mask)

    overlay_dip = (pkt_dip & ~ol_dip_mask) | ol_dip_ip
    return str(ip_address(overlay_dip))


def rand_udp_port_packets(config, floating_nic=True, outbound_vni=None):
    """
    Randomly generate the inner (overlay) UDP source and destination ports.
    Useful to ensure an even distribution of packets across multiple ECMP endpoints.
    """
    sport = random.randint(49152, 65535)
    dport = random.randint(49152, 65535)
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(
        config, "vxlan", floating_nic, inner_sport=sport, inner_dport=dport, vni=outbound_vni
    )
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(config, floating_nic, inner_sport=dport, inner_dport=sport)
    return vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt


def set_do_not_care_layer(mask, layer, field_name, n=1):
    """
    Zeroes out the mask for 'field' in the nth occurrence of the specified layer.
    """
    header_offset = mask.size - len(mask.exp_pkt.getlayer(layer, n))

    try:
        fields_desc = [
            field
            for field in layer.fields_desc
            if field.name in mask.exp_pkt[layer].__class__(bytes(mask.exp_pkt[layer])).fields.keys()
        ]  # build & parse packet to be sure all fields are correctly filled
    except Exception:  # noqa
        raise MaskException("Can not build or decode Packet")

    if field_name not in [x.name for x in fields_desc]:
        raise MaskException("Field %s does not exist in frame" % field_name)

    field_offset = 0
    bitwidth = 0
    for f in fields_desc:
        try:
            bits = f.size
        except Exception:  # noqa
            bits = 8 * f.sz
        if f.name == field_name:
            bitwidth = bits
            break
        else:
            field_offset += bits

    mask.set_do_not_care(header_offset * 8 + field_offset, bitwidth)


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


def plnsg_packets(config):
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(config, "vxlan")
    inner_pkt = exp_dpu_to_pe_pkt.exp_pkt
    inner_pkt[scapy.Ether].src = config[DPU_DATAPLANE_MAC]
    inner_pkt[scapy.Ether].dst = config[NPU_DATAPLANE_MAC]
    exp_outer_pkt = testutils.simple_vxlan_packet(
        eth_src=config[DUT_MAC],
        eth_dst=config[REMOTE_PTF_MAC],
        ip_src=pl.APPLIANCE_VIP,
        ip_id=0,
        udp_dport=4789,
        udp_sport=1234,
        with_udp_chksum=False,
        vxlan_vni=pl.NSG_OUTBOUND_VNI,
        inner_frame=inner_pkt,
    )
    masked_outer_pkt = Mask(exp_outer_pkt)
    masked_outer_pkt.set_do_not_care_packet(scapy.UDP, "sport")
    masked_outer_pkt.set_do_not_care_packet(scapy.IP, "chksum")
    masked_outer_pkt.set_do_not_care_packet(scapy.IP, "dst")
    masked_outer_pkt.set_do_not_care_packet(scapy.IP, "ttl")
    set_do_not_care_layer(masked_outer_pkt, scapy.IP, "ttl", 2)
    set_do_not_care_layer(masked_outer_pkt, scapy.IP, "chksum", 2)
    return vm_to_dpu_pkt, masked_outer_pkt


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


def inbound_vnet_packets(dash_config_info, inner_extra_conf={}, inner_packet_type="udp", vxlan_udp_dport=4789):
    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[REMOTE_ENI_MAC],
        eth_dst=dash_config_info[LOCAL_ENI_MAC],
        ip_src=dash_config_info[REMOTE_CA_IP],
        ip_dst=dash_config_info[LOCAL_CA_IP],
        **inner_extra_conf,
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
        inner_frame=inner_packet,
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
        inner_frame=inner_packet,
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


def outbound_vnet_packets(dash_config_info, inner_extra_conf={}, inner_packet_type="udp", vxlan_udp_dport=4789):
    proto = None
    if "proto" in inner_extra_conf:
        proto = int(inner_extra_conf["proto"])
        del inner_extra_conf["proto"]

    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_dst=dash_config_info[REMOTE_CA_IP],
        **inner_extra_conf,
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
        inner_frame=inner_packet,
    )
    expected_packet = testutils.simple_vxlan_packet(
        eth_src=dash_config_info[DUT_MAC],
        eth_dst=dash_config_info[REMOTE_PTF_MAC],
        ip_src=dash_config_info[LOOPBACK_IP],
        ip_dst=dash_config_info[REMOTE_PA_IP],
        udp_dport=vxlan_udp_dport,
        vxlan_vni=dash_config_info[VNET2_VNI],
        # TODO: Change TTL to 63 after SAI bug is fixed
        ip_ttl=0xFF,
        ip_id=0,
        inner_frame=inner_packet,
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
                    print_expect_packet_and_received_packet_hex_information([exp_pkt], received_pkts_res[port])
                )
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


def verify_tcp_packet_drop_rst_packet_sent(
    ptfadapter, exp_rst_pkts, drop_tcp_pkts, ports, filter_pkt_lens, device_number=0, duration=10, timeout=0.2
):
    received_pkts_res = get_packets_on_specified_ports(
        ptfadapter, ports, filter_pkt_lens, device_number, duration, timeout
    )
    verify_packets_not_received(drop_tcp_pkts, received_pkts_res)
    verify_each_packet_on_each_port(exp_rst_pkts, received_pkts_res, ports)


def outbound_smartswitch_vnet_packets(
    dash_config_info, inner_extra_conf={}, inner_packet_type="udp", vxlan_udp_dport=4789
):

    inner_packet = generate_inner_packet(inner_packet_type)(
        eth_src=dash_config_info[LOCAL_ENI_MAC],
        eth_dst=dash_config_info[REMOTE_ENI_MAC],
        ip_src=dash_config_info[LOCAL_CA_IP],
        ip_dst=dash_config_info[REMOTE_CA_IP],
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
        inner_frame=inner_packet,
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
        inner_frame=inner_packet,
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
