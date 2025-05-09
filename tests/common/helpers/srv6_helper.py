import logging
import sys
from io import StringIO
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

logger = logging.getLogger(__name__)


class SRv6():
    uN = 'uN'
    prefix_len = '48'
    pipe_mode = 'pipe'
    uniform_mode = 'uniform'


class SRv6Packets():
    '''
    Define the ipv6 packets used in srv6 test
    Each item was defined with actions and packet type as well as segment left and segment list, destination ip
    '''
    srv6_packets = [
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': None,
            'outer_dscp': None,
            'dst_ipv6': '2001:1000:0100:0200::',
            'exp_dst_ipv6': '2001:1000:0200::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward',
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': None,
            'outer_dscp': None,
            'dst_ipv6': '2001:1001:0200:0300::',
            'exp_dst_ipv6': '2001:1001:0300::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': ['2001:2000:0300:0400:0500:0600::'],
            'dst_ipv6': '2001:2000:0300::',
            'exp_dst_ipv6': '2001:2000:0300:0400:0500:0600::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 0,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': ['2001:2001:0400:0500:0600::'],
            'dst_ipv6': '2001:2001:0400:0500::',
            'exp_dst_ipv6': '2001:2001:0500::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 1,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 1,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': [
                '2001:3000:0500:0600::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:3000:0500::',
            'exp_dst_ipv6': '2001:3000:0500:0600::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 0,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 2,
            'inner_dscp': None,
            'outer_dscp': None,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:3001:0600::',
            'exp_dst_ipv6': '2001:3000:0600:0700:0800:0900:0a00::',
            'exp_inner_dscp_pipe': None,
            'exp_outer_dscp_uniform': None,
            'exp_srh_seg_left': 1,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': 20,
            'outer_dscp': 40,
            'dst_ipv6': '2001:4000:0700::',
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'exp_inner_dscp_pipe': 20,
            'exp_outer_dscp_uniform': 40,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'one_u_sid',
            'srh_seg_left': 0,
            'inner_dscp': 32,
            'outer_dscp': 31,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:4001:0800::',
            'exp_inner_dscp_pipe': 32,
            'exp_outer_dscp_uniform': 31,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '4',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'two_u_sid',
            'srh_seg_left': 0,
            'inner_dscp': 2,
            'outer_dscp': 62,
            'srh_seg_list': [
                '2001:3001:0500::',
                '2001:3000:0600:0700:0800:0900:0a00::'
            ],
            'dst_ipv6': '2001:5000:0900::',
            'exp_inner_dscp_pipe': 2,
            'exp_outer_dscp_uniform': 62,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        },
        {
            'action': SRv6.uN,
            'packet_type': 'reduced_srh',
            'srh_seg_left': None,
            'srh_seg_list': None,
            'inner_dscp': 63,
            'outer_dscp': 1,
            'dst_ipv6': '2001:5001:0a00::',
            'exp_inner_dscp_pipe': 63,
            'exp_outer_dscp_uniform': 1,
            'exp_dst_ipv6': None,
            'exp_srh_seg_left': None,
            'inner_pkt_ver': '6',
            'exp_process_result': 'forward'
        }
    ]
    srv6_next_header = {
        scapy.IP: 4,
        scapy.IPv6: 41
    }


def dump_packet_detail(pkt):
    _stdout, sys.stdout = sys.stdout, StringIO()
    try:
        pkt.show()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = _stdout


def create_srv6_packet(
        outer_src_mac,
        outer_dst_mac,
        outer_src_pkt_ip,
        outer_dst_pkt_ip,
        srv6_action,
        inner_dscp,
        outer_dscp,
        exp_outer_dst_pkt_ip,
        exp_seg_left,
        exp_dscp_pipe,
        exp_dscp_uniform,
        seg_left,
        sef_list,
        inner_pkt_ver,
        dscp_mode,
        router_mac,
        inner_src_ip,
        inner_dst_ip,
        inner_src_ipv6,
        inner_dst_ipv6):
    """
    Create SRv6 packets for testing

    Args:
        outer_src_mac (str): Outer source MAC address
        outer_dst_mac (str): Outer destination MAC address
        outer_src_pkt_ip (str): Outer source IP address
        outer_dst_pkt_ip (str): Outer destination IP address
        srv6_action (str): SRv6 action type
        inner_dscp (int): Inner DSCP value
        outer_dscp (int): Outer DSCP value
        exp_outer_dst_pkt_ip (str): Expected outer destination IP address
        exp_seg_left (int): Expected segment left value
        exp_dscp_pipe (int): Expected DSCP value in pipe mode
        exp_dscp_uniform (int): Expected DSCP value in uniform mode
        seg_left (int): Segment left value
        sef_list (list): Segment list
        inner_pkt_ver (str): Inner packet version ('4' for IPv4, '6' for IPv6)
        dscp_mode (str): DSCP mode ('pipe' or 'uniform')
        router_mac (str): Router MAC address
        inner_src_ip (str): Inner source IPv4 address
        inner_dst_ip (str): Inner destination IPv4 address
        inner_src_ipv6 (str): Inner source IPv6 address
        inner_dst_ipv6 (str): Inner destination IPv6 address

    Returns:
        tuple: (srv6_pkt, exp_pkt) - Created SRv6 packet and expected packet
    """
    srv6_next_header = SRv6Packets.srv6_next_header

    if dscp_mode == SRv6.uniform_mode:
        exp_dscp = exp_dscp_uniform
    else:
        exp_dscp = exp_dscp_pipe

    if inner_pkt_ver == '4':
        inner_pkt = testutils.simple_tcp_packet(
            eth_src=router_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_dscp=inner_dscp if inner_dscp else 0
        )

        exp_inner_pkt = testutils.simple_tcp_packet(
            eth_src=router_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_dscp=exp_dscp if exp_dscp else 0
        )
        scapy_ver = scapy.IP
    else:
        inner_pkt = testutils.simple_tcpv6_packet(
            eth_src=router_mac,
            ipv6_src=inner_src_ipv6,
            ipv6_dst=inner_dst_ipv6,
            ipv6_dscp=inner_dscp if inner_dscp else 0
        )

        exp_inner_pkt = testutils.simple_tcpv6_packet(
            eth_src=router_mac,
            ipv6_src=inner_src_ipv6,
            ipv6_dst=inner_dst_ipv6,
            ipv6_dscp=exp_dscp if exp_dscp else 0
        )
        scapy_ver = scapy.IPv6

    if srv6_action == SRv6.uN:
        if exp_outer_dst_pkt_ip:
            if seg_left or sef_list:
                logger.info('Create SRv6 packets with SRH')
                srv6_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    srh_seg_left=seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=inner_pkt[scapy_ver],
                )
                exp_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=exp_outer_dst_pkt_ip,
                    srh_seg_left=exp_seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=exp_dscp * 4 if exp_dscp else 0,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=exp_inner_pkt[scapy_ver],
                )
            else:
                logger.info('Create SRv6 packet with reduced SRH(no SRH header)')
                srv6_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    inner_frame=inner_pkt[scapy_ver],
                )
                exp_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=exp_outer_dst_pkt_ip,
                    ipv6_tc=exp_dscp * 4 if exp_dscp else 0,
                    inner_frame=exp_inner_pkt[scapy_ver],
                )

            exp_pkt['IPv6'].hlim -= 1
            exp_pkt = Mask(exp_pkt)

            logger.info('Do not care packet ethernet destination address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')
            logger.info('Do not care packet ethernet source address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'src')

        else:
            if seg_left or sef_list:
                logger.info('Create SRv6 packets with SRH for USD flavor validation')
                srv6_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    srh_seg_left=seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=inner_pkt[scapy_ver],
                )
            else:
                logger.info('Create SRv6 packets without SRH for USD flavor validation')
                srv6_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    inner_frame=inner_pkt[scapy_ver],
                )

            if inner_pkt_ver == '4':
                exp_inner_pkt['IP'].ttl -= 1
                exp_pkt = Mask(exp_inner_pkt)
                logger.info('Do not care packet checksum')
                exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
            else:
                exp_inner_pkt['IPv6'].hlim -= 1
                exp_pkt = Mask(exp_inner_pkt)
            logger.info('Do not care packet ethernet destination address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')

    return srv6_pkt, exp_pkt


def send_verify_srv6_packet(
        ptfadapter,
        pkt,
        exp_pkt,
        exp_pro,
        ptf_src_port_id,
        ptf_dst_port_ids,
        packet_num=10):
    """
    Send and verify SRv6 packets

    Args:
        ptfadapter: PTF adapter object
        pkt: Packet to send
        exp_pkt: Expected packet
        exp_pro (str): Expected process result ('forward' or 'drop')
        ptf_src_port_id (int): Source PTF port ID
        ptf_dst_port_ids (list): List of destination PTF port IDs
        packet_num (int): Number of packets to send (default: 10)
    """
    ptfadapter.dataplane.flush()
    logger.info(f'Send SRv6 packet(s) from PTF port {ptf_src_port_id} to upstream')
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=packet_num)
    logger.info('SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
    logger.info('Expect receive SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

    try:
        if exp_pro == 'forward':
            port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
            logger.info(f'Received packet(s) on port {ptf_dst_port_ids[port_index]}\n')
        elif exp_pro == 'drop':
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
            logger.info(f'No packet received on {ptf_dst_port_ids}')
        else:
            logger.error(f'Wrong expected process result: {exp_pro}')
    except AssertionError as detail:
        raise detail


def create_srv6_locator(duthost,
                        locator_name,
                        prefix,
                        block_len=32,
                        node_len=16,
                        func_len=0,
                        arg_len=0):
    logger.info(f'Configure locator: SRV6_MY_LOCATORS|{locator_name}')
    duthost.shell(
        f'sonic-db-cli CONFIG_DB HSET "SRV6_MY_LOCATORS|{locator_name}" '
        f'"prefix" "{prefix}" '
        f'"block_len" "{block_len}" '
        f'"node_len" "{node_len}" '
        f'"func_len" "{func_len}" '
        f'"arg_len" "{arg_len}"')


def del_srv6_locator(duthost, locator_name):
    logger.info(f'Delete locator: SRV6_MY_LOCATORS|{locator_name}')
    duthost.shell(f'sonic-db-cli CONFIG_DB DEL "SRV6_MY_LOCATORS|{locator_name}"')


def create_srv6_sid(duthost,
                    locator_name,
                    ip_addr,
                    action=SRv6.uN,
                    decap_vrf='default',
                    decap_dscp_mode=SRv6.uniform_mode):
    logger.info(f'Configure sid: SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}')
    duthost.shell(
        f'sonic-db-cli CONFIG_DB HSET "SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}" '
        f'"action" "{action}" '
        f'"decap_vrf" "{decap_vrf}" '
        f'"decap_dscp_mode" "{decap_dscp_mode}"')


def del_srv6_sid(duthost, locator_name, ip_addr):
    logger.info(f'Delete sid: SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}')
    duthost.shell(f'sonic-db-cli CONFIG_DB DEL "SRV6_MY_SIDS|{locator_name}|{ip_addr}/{SRv6.prefix_len}"')
