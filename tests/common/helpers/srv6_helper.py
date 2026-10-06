import logging
import sys
import json
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
    srv6_next_header = {
        scapy.IP: 4,
        scapy.IPv6: 41
    }

    @classmethod
    def generate_srv6_packets(cls, my_locator_list, srv6_packet_type):
        """
        Generate SRv6 test packets based on the provided locator list.
        Each packet will have different configurations for comprehensive testing.

        Args:
            my_locator_list (list): List of locator entries
            srv6_packet_type (str): Type of SRv6 packet to generate

        Returns:
            list: List of SRv6 packet configurations
        """
        srv6_packets = []

        # Define base packet types with different configurations
        base_packets = [
            {  # 1
                'action': 'uN',
                'srv6_packet_type': 'no_srh',
                'validate_dip_shift': True,
                'validate_usd_flavor': False,
                'srh_seg_list': None,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 0,
                'inner_dscp': 0,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 0,
                'exp_outer_dscp_uniform': 0,
                'exp_process_result': 'forward'
            },
            {  # 2
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': True,
                'validate_usd_flavor': False,
                'srh_seg_list': 1,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 0,
                'inner_dscp': 0,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 0,
                'exp_outer_dscp_uniform': 0,
                'exp_process_result': 'forward'
            },
            {  # 3
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': True,
                'validate_usd_flavor': False,
                'srh_seg_list': 2,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 0,
                'inner_dscp': 0,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 0,
                'exp_outer_dscp_uniform': 0,
                'exp_process_result': 'forward'
            },
            {  # 4
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': False,
                'validate_usd_flavor': False,
                'srh_seg_list': 1,
                'srh_seg_left': 1,
                'inner_pkt_ver': '6',
                'outer_dscp': 32,
                'inner_dscp': 48,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 48,
                'exp_outer_dscp_uniform': 32,
                'exp_process_result': 'forward'
            },
            {  # 5
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': False,
                'validate_usd_flavor': False,
                'srh_seg_list': 2,
                'srh_seg_left': 2,
                'inner_pkt_ver': '6',
                'outer_dscp': 16,
                'inner_dscp': 24,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 1,
                'exp_inner_dscp_pipe': 24,
                'exp_outer_dscp_uniform': 16,
                'exp_process_result': 'forward'
            },
            {  # 6
                'action': 'uN',
                'srv6_packet_type': 'no_srh',
                'validate_dip_shift': False,
                'validate_usd_flavor': True,
                'srh_seg_list': None,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 48,
                'inner_dscp': 56,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 56,
                'exp_outer_dscp_uniform': 48,
                'exp_process_result': 'forward'
            },
            {  # 7
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': False,
                'validate_usd_flavor': True,
                'srh_seg_list': 1,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 48,
                'inner_dscp': 56,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 56,
                'exp_outer_dscp_uniform': 48,
                'exp_process_result': 'forward'
            },
            {  # 8
                'action': 'uN',
                'srv6_packet_type': 'srh',
                'validate_dip_shift': False,
                'validate_usd_flavor': True,
                'srh_seg_list': 2,
                'srh_seg_left': 0,
                'inner_pkt_ver': '6',
                'outer_dscp': 48,
                'inner_dscp': 56,
                'exp_dst_ipv6': None,
                'exp_srh_seg_left': 0,
                'exp_inner_dscp_pipe': 56,
                'exp_outer_dscp_uniform': 48,
                'exp_process_result': 'forward'
            }
        ]

        # Use dictionary mapping for packet type filtering
        packet_type_map = {
            'srh': 'srh',
            'no_srh': 'no_srh'
        }
        filtered_base_packets = [
            packet for packet in base_packets
            if packet['srv6_packet_type'] == packet_type_map.get(srv6_packet_type, 'no_srh')
        ]
        # Generate packets for each SID
        for i, sid_entry in enumerate(my_locator_list):
            # Select base packet type based on index
            base_type = filtered_base_packets[i % len(filtered_base_packets)]
            current_sid_container = sid_entry[1]
            usid = sid_entry[2]

            # Create packet configuration
            packet = base_type.copy()
            packet['inner_src_ip'] = '1.1.1.1'
            packet['inner_dst_ip'] = '2.2.2.2'
            packet['inner_src_ipv6'] = '2000::1'
            packet['inner_dst_ipv6'] = '3000::2'
            packet['outer_src_ipv6'] = '1000:1000::1'
            packet['dst_ipv6'] = current_sid_container
            next_sid_index = (i + 1) % len(my_locator_list)
            next_usid = 1000 + int(my_locator_list[next_sid_index][2])

            if base_type['validate_dip_shift']:
                # Prepare the expected destination IPv6 address for DIP shift validation
                packet['dst_ipv6'] = current_sid_container.replace(f'{usid}::', f'{usid}:{next_usid}::')
                packet['exp_dst_ipv6'] = current_sid_container.replace(f'{usid}::', f'{next_usid}::')

            temp_sid_container = current_sid_container.replace(f'{usid}::', f'{next_usid}::')
            # Set segment list based on base type
            if base_type['srh_seg_list'] == 1:
                packet['srh_seg_list'] = [temp_sid_container]
            elif base_type['srh_seg_list'] == 2:
                packet['srh_seg_list'] = [current_sid_container, temp_sid_container]

            # Set expected destination IPv6 if not validating USD flavor
            if not base_type['validate_usd_flavor']:
                packet['exp_dst_ipv6'] = temp_sid_container

            packet['exp_inner_dscp_pipe'] = packet['inner_dscp'] = packet['exp_outer_dscp_uniform'] = \
                packet['outer_dscp'] = i % 64

            if packet['validate_usd_flavor']:
                packet['exp_outer_dscp_uniform'] = packet['outer_dscp'] = i % 64
                packet['exp_inner_dscp_pipe'] = packet['inner_dscp'] = (packet['outer_dscp'] + 8) % 64

            srv6_packets.append(packet)

        return srv6_packets


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
    ptfadapter.dataplane.set_qlen(1000000)
    logger.info(f'Send SRv6 packet(s) from PTF port {ptf_src_port_id} to upstream')
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=packet_num)
    logger.info('SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
    logger.info('Expect receive SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

    try:
        if exp_pro == 'forward':
            # set timeout to 60 to override the affection of huge BGP update exchange after config reload or bgp restart
            port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, timeout=60, ports=ptf_dst_port_ids)
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


def validate_srv6_in_appl_db(duthost,
                             mysid_list,
                             block_len=32,
                             node_len=16,
                             func_len=0,
                             arg_len=0):
    """
    Validate all SRv6 MySIDs in Application DB using a single query.

    Args:
        duthost (SonicHost): DUT host object
        mysid_list (list): MySID list
        block_len (int): Block length for SRv6 SID
        node_len (int): Node length for SRv6 SID
        func_len (int): Function length for SRv6 SID
        arg_len (int): Argument length for SRv6 SID

    Returns:
        bool: True if all MySIDs are valid, False otherwise
    """
    try:
        # Get all SRv6 MySID entries from APPL_DB
        appl_db_keys = duthost.shell('sonic-db-cli APPL_DB KEYS "SRV6_MY_SID_TABLE*"')["stdout"]
        if not appl_db_keys:
            logger.error("No SRv6 MySID entries found in APPL_DB")
            return False

        # Convert keys to a set for faster lookup
        appl_db_keys_set = set(appl_db_keys.split())

        # Validate each MySID
        for entry in mysid_list:
            prefix = entry[1]
            expected_key = f"SRV6_MY_SID_TABLE:{block_len}:{node_len}:{func_len}:{arg_len}:{prefix}"

            # Check if the key exists
            if expected_key not in appl_db_keys_set:
                logger.error(f"MySID entry not found in APPL_DB: {expected_key}")
                return False

        return True

    except Exception as err:
        raise Exception(f"Failed to validate SRv6 MySIDs in Application DB: {str(err)}")


def validate_srv6_in_asic_db(duthost, mysid_list):
    """
    Validate all SRv6 MySIDs in ASIC DB using a single query.

    Args:
        duthost (SonicHost): DUT host object
        mysid_list (list): MySID list

    Returns:
        bool: True if all MySIDs are valid, False otherwise
    """
    try:
        asic_db_keys = duthost.shell('sonic-db-cli ASIC_DB keys "*ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*"')["stdout"]
        if not asic_db_keys:
            logger.error("No SRv6 MySID entries found in ASIC_DB")
            return False

        # Validate each MySID
        for entry in mysid_list:
            prefix = entry[1]

            # Check if the key exists
            if prefix not in asic_db_keys:
                logger.error(f"MySID entry not found in ASIC_DB: {prefix}")
                return False

        return True

    except Exception as err:
        raise Exception(f"Failed to validate SRv6 MySIDs in ASIC DB: {str(err)}")


def validate_srv6_route(duthost, route_prefix):
    """
    Validate the SRv6 route in ASIC DB
    Args:
        duthost (SonicHost): DUT host object
        route_prefix (str): Route prefix
    """
    try:
        asic_route = duthost.shell(
            f'sonic-db-cli ASIC_DB keys "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*{route_prefix}::/16*"')["stdout"]

        if not asic_route:
            logger.error(f"No SRv6 route {route_prefix}::/16 found")
            return False

        logger.info(f"SRv6 route {route_prefix}::/16 installed")
        return True

    except Exception as err:
        raise Exception(f"Failed to validate SRv6 route {route_prefix}::/16: {str(err)}")


def is_bgp_route_synced(duthost):
    cmd = 'vtysh -c "show ip bgp neighbors json"'
    output = duthost.command(cmd)['stdout']
    bgp_info = json.loads(output)
    for neighbor, info in bgp_info.items():
        if 'gracefulRestartInfo' in info:
            if "ipv4Unicast" in info['gracefulRestartInfo']:
                if not info['gracefulRestartInfo']["ipv4Unicast"]['endOfRibStatus']['endOfRibSend']:
                    logger.info(f"BGP neighbor {neighbor} is sending updates")
                    return False
                if not info['gracefulRestartInfo']["ipv4Unicast"]['endOfRibStatus']['endOfRibRecv']:
                    logger.info(
                        f"BGP neighbor {neighbor} is receiving updates")
                    return False

            if "ipv6Unicast" in info['gracefulRestartInfo']:
                if not info['gracefulRestartInfo']["ipv6Unicast"]['endOfRibStatus']['endOfRibSend']:
                    logger.info(f"BGP neighbor {neighbor} is sending updates")
                    return False
                if not info['gracefulRestartInfo']["ipv6Unicast"]['endOfRibStatus']['endOfRibRecv']:
                    logger.info(
                        f"BGP neighbor {neighbor} is receiving updates")
                    return False
    logger.info("BGP routes are synced")
    return True
