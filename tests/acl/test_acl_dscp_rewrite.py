#! /usr/bin/env python3
'''
    These tests verify egress ACL DSCP rewrite on VXLAN-encapsulated overlay traffic.
    ACL rules match overlay destination (and optional qualifiers) and set underlay DSCP
    on the outer header. Tests cover v4/v6 overlay and underlay combinations on T1 topologies.
'''
import os
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until

from tests.common.vxlan_ecmp_utils import Ecmp_Utils     # noqa F401
import ptf.testutils as testutils
from ptf import mask
from scapy.all import Ether, IP, VXLAN, IPv6, UDP

Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


# This is the list of encapsulations that will be tested in this script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v6_in_v4', 'v4_in_v6', 'v6_in_v6']
DESTINATION_PREFIX = 150
NEXTHOP_PREFIX = 100
pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    # This script supports any T1 topology: t1, t1-64-lag, t1-56-lag, t1-lag.
    pytest.mark.topology("t1"),

]

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

TMP_DIR = '/tmp'
ACL_TABLE_FILE = 'acl_tbl_config.json'

ACL_RULES_FILE = 'acl_rule_config.json'
ACL_TEMPLATE_TABLE_FILE = "acltb_dscp_rewrite_table.j2"
ACL_TEMPLATE_RULE_FILE = "acltb_dscp_rewrite_rule.j2"

TABLE_V4 = "OVERLAY_MARK_META_TEST"
TABLE_V6 = "OVERLAY_MARK_META_TESTV6"


@pytest.fixture(
    name="encap_type",
    scope="module",
    params=SUPPORTED_ENCAP_TYPES)
def fixture_encap_type(request):
    '''
        This fixture forces the script to perform one encap_type at a time.
        So this script doesn't support multiple encap types at the same.
    '''
    return request.param


@pytest.fixture(scope='module')
def prepare_test_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    portchannels = list(mg_facts['minigraph_portchannels'].keys())
    if not portchannels:
        pytest.skip('No portchannels found')

    dut_port = portchannels[0]
    dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    # Get the list of upstream ports
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if "T2" in neighbor["name"]:
            upstream_port_ids.append(port_id)

    return ptf_src_port, upstream_port_ids, dut_port


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp_vxlan_vnet_routes(duthosts,
                                    rand_one_dut_hostname,
                                    tbinfo,
                                    ptfadapter,
                                    prepare_test_port,
                                    encap_type):
    '''
        Setup for the entire script.
        The basic steps in VxLAN configs are:
            1. Configure VxLAN tunnel.
            2. Configure Vnet and its VNI.

            The testcases are focused on the "configure routes" step. They add,
            delete, modify, the routes.
    '''
    data = {}

    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port
    data['ptfadapter'] = ptfadapter
    data['ptf_src_port'] = ptf_src_port
    data['ptf_dst_ports'] = ptf_dst_ports
    data['dut_port'] = dut_port

    duthost = duthosts[rand_one_dut_hostname]
    minigraph_data = duthost.get_extended_minigraph_facts(tbinfo)
    data['minigraph_facts'] = minigraph_data
    data['tbinfo'] = tbinfo
    data['duthost'] = duthost

    # Determine IPv4 and IPv6 loopback addresses by checking address format
    for lo_interface in data['minigraph_facts']['minigraph_lo_interfaces']:
        addr = lo_interface['addr']
        if ':' in addr:
            data['loopback_v6'] = addr
        else:
            data['loopback_v4'] = addr

    asic_type = duthost.facts["asic_type"]
    # enable for CISCO when support is confirmed.
    if asic_type not in ["cisco-8000"]:
        pytest.skip(f"Test not supported on {asic_type} platform. Please update this script for your platform.")

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = False
    ecmp_utils.Constants['DEBUG'] = False

    Logger.info("Constants to be used in the script:%s", ecmp_utils.Constants)

    data['vxlan_port'] = 4789
    data['dut_mac'] = data['duthost'].facts['router_mac']

    time.sleep(1)
    # setting up vxlan tunnel.
    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=data['vxlan_port'],
        dutmac=data['dut_mac'])

    encap_type_data = {}

    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    if outer_layer_version not in tunnel_names:
        tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(
            data['duthost'],
            minigraph_data,
            af=outer_layer_version)

    payload_version = ecmp_utils.get_payload_version(encap_type)
    encap_type = "{}_in_{}".format(payload_version, outer_layer_version)

    if outer_layer_version not in vnet_af_map:
        vnet_af_map[outer_layer_version] = ecmp_utils.create_vnets(
            data['duthost'],
            tunnel_name=tunnel_names[outer_layer_version],
            vnet_count=1,     # default scope can take only one vnet.
            vnet_name_prefix="Vnet_" + encap_type,
            scope="default",
            vni_base=10000)
    encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]

    data[encap_type] = encap_type_data

    data["t0_interfaces"] = ecmp_utils.get_all_interfaces_running_bgp(
            duthost,
            minigraph_data,
            "T0")
    data["t2_interfaces"] = ecmp_utils.get_all_interfaces_running_bgp(
            duthost,
            minigraph_data,
            "T2")

    intf_list = set()
    for key in data["t0_interfaces"].keys():
        for intfname in data["t0_interfaces"][key]:
            intf_list.add(intfname)
    for key in data["t2_interfaces"].keys():
        for intfname in data["t2_interfaces"][key]:
            intf_list.add(intfname)
    data["connected_interfaces"] = intf_list

    # This data doesn't change per testcase, so we copy
    # it as a seperate file. The test-specific config
    # data will be copied on testase basis.
    vnet = list(encap_type_data['vnet_vni_map'].keys())[0]
    Logger.info("Create a new list of endpoint(s).")
    tc_end_point_list = []
    for _ in range(4):
        tc_end_point_list.append(ecmp_utils.get_ip_address(
            af=ecmp_utils.get_outer_layer_version(encap_type),
            netid=NEXTHOP_PREFIX))

    Logger.info("Create a new destination")
    tc_new_dest = ecmp_utils.get_ip_address(
        af=ecmp_utils.get_payload_version(encap_type),
        netid=DESTINATION_PREFIX)
    ax = {vnet: {tc_new_dest: tc_end_point_list}}
    data[encap_type]['dest_to_nh_map'] = ax
    ecmp_utils.create_and_apply_config(data['duthost'],
                                       vnet,
                                       tc_new_dest,
                                       ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                       tc_end_point_list,
                                       "SET")

    yield data

    # Cleanup code.
    del_acl_tables(duthost)
    ecmp_utils.create_and_apply_config(data['duthost'],
                                       vnet,
                                       tc_new_dest,
                                       ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                       tc_end_point_list,
                                       "DEL")
    # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
    # There will be same vnet in multiple encap types.
    # So remove vnets *after* removing the routes first.
    for vnet in list(data[encap_type]['vnet_vni_map'].keys()):
        data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    time.sleep(5)
    for tunnel in list(tunnel_names.values()):
        data['duthost'].shell(
            "redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))


def setup_acl_tables(duthost, setUp_vnet):
    intfs = str()
    for intf in setUp_vnet["connected_interfaces"]:
        intfs += ('"' + intf + '", ')
    extra_vars = {
        'acl_interfaces': intfs[:-2],
        'acl_interfacesv6': intfs[:-2],
       }
    dest_path = os.path.join(TMP_DIR, ACL_TABLE_FILE)
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.file(path=dest_path, state='absent')
    duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_TEMPLATE_TABLE_FILE), dest=dest_path)
    Logger.info("Creating ACL table")

    duthost.shell("config load -y {}".format(dest_path))

    def table_is_active(table_name):
        status = duthost.shell(
            "redis-cli -n 6 hget 'ACL_TABLE_TABLE|{}' 'status'".format(table_name))['stdout']
        return status == 'Active'

    for table_name in (TABLE_V4, TABLE_V6):
        if not wait_until(60, 2, 0, lambda t=table_name: table_is_active(t)):
            Logger.error("Generated ACL table JSON:\n%s", duthost.shell("cat {}".format(dest_path))['stdout'])
            Logger.error("STATE_DB %s:\n%s", table_name,
                         duthost.shell("redis-cli -n 6 hgetall 'ACL_TABLE_TABLE|{}'".format(table_name))['stdout'])
            py_assert(False, "ACL table {} is not active".format(table_name))


def create_acl_rule(duthost, tableName, ruleNumber, priority, dscpAction, dstIp, qualifer=None):
    # {   "ACL_RULE": {
    #         "{{ tableName }}|RULE{{ruleNumber}}": {
    #             "PRIORITY": {{priority}},
    #             "DSCP_ACTION": {{dscpAction}},
    #             {{qualifer}}
    #             "DST_IP": {{dstIp}}

    #         }
    #     }
    # }
    if tableName == TABLE_V4:
        qualifer = '"DST_IP":"{}"'.format(dstIp) + (',' + qualifer if qualifer is not None else "")
    else:
        qualifer = '"DST_IPV6":"{}"'.format(dstIp) + (',' + qualifer if qualifer is not None else "")
    extra_vars = {
        'tableName': tableName,
        'ruleNumber': ruleNumber,
        'priority': priority,
        'dscpAction': dscpAction,
        'qualifer': qualifer,
       }

    dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.file(path=dest_path, state='absent')
    duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_TEMPLATE_RULE_FILE), dest=dest_path)
    Logger.info("Creating ACL rule for %s with id %s, priority %s, dscp action %s, DST IP %s and qualifers %s",
                tableName, ruleNumber, priority, dscpAction, dstIp, qualifer)

    duthost.shell("config load -y {}".format(dest_path))

    rule_key = f'ACL_RULE_TABLE|{tableName}|RULE{ruleNumber}'

    def rule_is_active():
        status = duthost.shell(f"redis-cli -n 6 hget '{rule_key}' 'status'")['stdout']
        return status == 'Active'

    if not wait_until(30, 2, 0, rule_is_active):
        Logger.error("Generated ACL rule JSON:\n%s", duthost.shell("cat {}".format(dest_path))['stdout'])
        Logger.error("STATE_DB rule:\n%s", duthost.shell(f"redis-cli -n 6 hgetall '{rule_key}'")['stdout'])
        py_assert(False, f"ACL rule {tableName}|RULE{ruleNumber} is not active")


def del_acl_rule(duthost, table, ruleId):
    config_key = f'ACL_RULE|{table}|RULE{ruleId}'
    state_key = f'ACL_RULE_TABLE|{table}|RULE{ruleId}'
    duthost.shell(f"redis-cli -n 4 del '{config_key}'")

    def rule_is_removed():
        exists = duthost.shell(f"redis-cli -n 6 exists '{state_key}'")['stdout'].strip()
        if exists == '0':
            return True
        status = duthost.shell(f"redis-cli -n 6 hget '{state_key}' 'status'")['stdout'].strip()
        return status != 'Active'

    if not wait_until(30, 2, 0, rule_is_removed):
        Logger.error("STATE_DB rule after delete:\n%s",
                     duthost.shell(f"redis-cli -n 6 hgetall '{state_key}'")['stdout'])
        py_assert(False, f"ACL rule {table}|RULE{ruleId} not removed from STATE_DB")


def del_all_acl_rules(duthost):
    """Remove all ACL rules for both overlay DSCP tables."""
    for table in (TABLE_V4, TABLE_V6):
        out = duthost.shell("redis-cli -n 4 KEYS 'ACL_RULE|{}|*'".format(table))['stdout'].strip()
        if not out:
            continue
        for key in out.splitlines():
            key = key.strip()
            if key:
                duthost.shell("redis-cli -n 4 del '{}'".format(key))

    def all_rules_removed():
        for table in (TABLE_V4, TABLE_V6):
            remaining = duthost.shell(
                "redis-cli -n 6 KEYS 'ACL_RULE_TABLE|{}|*'".format(table))['stdout'].strip()
            if remaining:
                return False
        return True

    if not wait_until(30, 2, 0, all_rules_removed):
        py_assert(False, "ACL rules not removed from STATE_DB")


def del_acl_tables(duthost):
    Logger.info("Cleaning up ACL rules and tables")
    del_all_acl_rules(duthost)
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TEST' ")
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TESTV6' ")

    def table_is_removed(table_name):
        exists = duthost.shell(
            "redis-cli -n 6 exists 'ACL_TABLE_TABLE|{}'".format(table_name))['stdout'].strip()
        if exists == '0':
            return True
        status = duthost.shell(
            "redis-cli -n 6 hget 'ACL_TABLE_TABLE|{}' 'status'".format(table_name))['stdout'].strip()
        return status != 'Active'

    for table_name in (TABLE_V4, TABLE_V6):
        if not wait_until(30, 2, 0, lambda t=table_name: table_is_removed(t)):
            Logger.error("STATE_DB table after delete:\n%s",
                         duthost.shell("redis-cli -n 6 hgetall 'ACL_TABLE_TABLE|{}'".format(table_name))['stdout'])
            py_assert(False, "ACL table {} not removed from STATE_DB".format(table_name))


@pytest.fixture(scope='function')
def acl_table_setup_and_cleanup(setUp, duthost, encap_type):
    """
    Fixture to setup ACL tables and ensure cleanup always happens.
    Yields the table name (TABLE_V4 or TABLE_V6) based on encap_type.
    """
    setUp_vnet = setUp
    # Save current ACL counterpoll interval for teardown restore
    original_interval = duthost.get_counter_poll_status()['ACL']['interval']

    # Enable acl counter and reduce interval to 1s
    duthost.shell('counterpoll acl interval 1000')
    setup_acl_tables(duthost, setUp_vnet)

    if 'v4_in' in encap_type:
        table = TABLE_V4
    else:
        table = TABLE_V6

    yield table

    # Restore ACL counterpoll interval to pre-test value
    duthost.set_counter_poll_interval(
        'ACL', original_interval, wait_for_new_interval=False)

    Logger.info("Cleaning up ACL tables")
    del_acl_tables(duthost)


def parse_matchfields(match_fields=None, separator=':'):
    ipSrc = None
    l4SrcPort = None
    l4DstPort = None
    ipTos = 0x84

    if match_fields is not None:
        qualifiers = match_fields.split(',')
        for qual in qualifiers:
            field, value = qual.split(separator)
            if separator == ':"':
                value = value.split('"')[0]
            else:
                value = value.split('"')[1]
            if field == '"SRC_IP"':
                ipSrc = value
            elif field == '"L4_SRC_PORT"':
                l4SrcPort = int(value)
            elif field == '"L4_DST_PORT"':
                l4DstPort = int(value)
            elif field == '"DSCP"':
                ipTos = int(value) * 4
            elif field == '"SRC_IPV6"':
                ipSrc = value
    return ipSrc, l4SrcPort, l4DstPort, ipTos


def create_expected_packet(setUp_vnet, duthost, encap_type, expectedDscp, inner_packet):
    outer_ip_src = setUp_vnet['loopback_v4'] if 'in_v4' in encap_type else setUp_vnet['loopback_v6']
    vxlan_vni = list(setUp_vnet[encap_type]['vnet_vni_map'].values())[0]

    if 'v4_in_v4' == encap_type:
        exp_pkt = testutils.simple_vxlan_packet(
            eth_src=duthost.facts['router_mac'],
            ip_src=outer_ip_src,
            ip_dst="0.0.0.0",  # We don't care about the outer dest IP
            ip_tos=expectedDscp * 4,
            udp_dport=setUp_vnet['vxlan_port'],
            vxlan_vni=vxlan_vni,
            inner_frame=inner_packet.copy()
        )
    elif 'v4_in_v6' == encap_type:
        exp_pkt = testutils.simple_vxlanv6_packet(
            eth_src=duthost.facts['router_mac'],
            ipv6_src=outer_ip_src,
            ipv6_dst="::",  # We don't care about the outer dest IP
            ipv6_tc=expectedDscp * 4,
            udp_dport=setUp_vnet['vxlan_port'],
            vxlan_vni=vxlan_vni,
            inner_frame=inner_packet.copy()
        )
    elif 'v6_in_v4' == encap_type:
        exp_pkt = testutils.simple_vxlan_packet(
            eth_src=duthost.facts['router_mac'],
            ip_src=outer_ip_src,
            ip_dst="0.0.0.0",  # We don't care about the outer dest IP
            ip_tos=expectedDscp * 4,
            udp_dport=setUp_vnet['vxlan_port'],
            vxlan_vni=vxlan_vni,
            inner_frame=inner_packet.copy()
        )
    elif 'v6_in_v6' == encap_type:
        exp_pkt = testutils.simple_vxlanv6_packet(
            eth_src=duthost.facts['router_mac'],
            ipv6_src=outer_ip_src,
            ipv6_dst="::",  # We don't care about the outer dest IP
            ipv6_tc=expectedDscp * 4,
            udp_dport=setUp_vnet['vxlan_port'],
            vxlan_vni=vxlan_vni,
            inner_frame=inner_packet.copy()
        )
    else:
        raise ValueError(f"Unsupported encap_type: {encap_type}")

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")

    if 'in_v4' in encap_type:
        exp_pkt.set_do_not_care_scapy(IP, "ihl")
        exp_pkt.set_do_not_care_scapy(IP, "len")
        exp_pkt.set_do_not_care_scapy(IP, "id")
        exp_pkt.set_do_not_care_scapy(IP, "flags")
        exp_pkt.set_do_not_care_scapy(IP, "frag")
        exp_pkt.set_do_not_care_scapy(IP, "ttl")
        exp_pkt.set_do_not_care_scapy(IP, "proto")
        exp_pkt.set_do_not_care_scapy(IP, "chksum")
        exp_pkt.set_do_not_care_scapy(IP, "ttl")
        exp_pkt.set_do_not_care_scapy(IP, "dst")
        exp_pkt.set_do_not_care_scapy(UDP, 'sport')
        exp_pkt.set_do_not_care_scapy(UDP, 'len')
        exp_pkt.set_do_not_care_scapy(UDP, 'chksum')
    elif 'in_v6' in encap_type:
        exp_pkt.set_do_not_care_scapy(IPv6, "plen")
        exp_pkt.set_do_not_care_scapy(IPv6, "hlim")
        exp_pkt.set_do_not_care_scapy(IPv6, "nh")
        exp_pkt.set_do_not_care_scapy(IPv6, "dst")
        exp_pkt.set_do_not_care_scapy(UDP, 'sport')
        exp_pkt.set_do_not_care_scapy(UDP, 'len')
        exp_pkt.set_do_not_care_scapy(UDP, 'chksum')

    exp_pkt.set_do_not_care_scapy(VXLAN, 'flags')
    exp_pkt.set_do_not_care_scapy(VXLAN, 'reserved1')
    exp_pkt.set_do_not_care_scapy(VXLAN, 'reserved2')

    total_size = exp_pkt.size
    # We also dont care about the inner IP header checksum and TTL fields for both IPv4 and IPv6

    if 'v4_in' in encap_type:
        inner_ether_hdr_start = total_size - len(exp_pkt.exp_pkt[VXLAN][Ether])
        inner_ether_hdr_end = total_size - len(exp_pkt.exp_pkt[VXLAN][IP])
        for iter in range(inner_ether_hdr_start, inner_ether_hdr_end):
            exp_pkt.mask[iter] = 0x00

        exp_pkt.mask[inner_ether_hdr_end + 8] = 0x00  # TTL is changed
        exp_pkt.mask[inner_ether_hdr_end + 10] = 0x00  # checksum is changed
        exp_pkt.mask[inner_ether_hdr_end + 11] = 0x00  # checksum is changed
    elif 'v6_in' in encap_type:
        inner_ether_hdr_start = total_size - len(exp_pkt.exp_pkt[VXLAN][Ether])
        inner_ether_hdr_end = total_size - len(exp_pkt.exp_pkt[VXLAN][IPv6])
        for iter in range(inner_ether_hdr_start, inner_ether_hdr_end):
            exp_pkt.mask[iter] = 0x00

        exp_pkt.mask[inner_ether_hdr_end + 7] = 0x00  # Hop Limit (TTL) is changed
        exp_pkt.mask[inner_ether_hdr_end + 8] = 0x00  # checksum is changed
        exp_pkt.mask[inner_ether_hdr_end + 9] = 0x00  # checksum is changed
        exp_pkt.mask[inner_ether_hdr_end + 10] = 0x00  # checksum is changed
        exp_pkt.mask[inner_ether_hdr_end + 11] = 0x00  # checksum is changed

    if inner_packet is None:
        exp_pkt.set_ignore_extra_bytes()
    return exp_pkt


def create_inner_packet(setUp_vnet, duthost, encap_type, match_fields=None):
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    ipSrc, l4SrcPort, l4DstPort, ipTos = parse_matchfields(match_fields,
                                                           separator=":" if 'v4_in' in encap_type else ':"')

    if ipSrc is None:
        if 'v4_in' in encap_type:
            ipSrc = "170.170.170.170/32"
        else:
            ipSrc = "9999:AAAA:BBBB:CCCC:DDDD:EEEE:EEEE:7777/128"

    if 'v4_in' in encap_type:
        pkt = testutils.simple_udp_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=setUp_vnet['ptfadapter'].dataplane.get_mac(0, setUp_vnet['ptf_src_port']),
            ip_src=ipSrc,
            ip_dst=dstip,
            ip_tos=ipTos,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=121,
            udp_sport=l4SrcPort if l4SrcPort is not None else None,
            udp_dport=l4DstPort if l4DstPort is not None else None
        )
    else:
        pkt = testutils.simple_udpv6_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=setUp_vnet['ptfadapter'].dataplane.get_mac(0, setUp_vnet['ptf_src_port']),
            ipv6_src=ipSrc,
            ipv6_dst=dstip,
            ipv6_tc=ipTos,
            ipv6_hlim=121,
            udp_sport=l4SrcPort if l4SrcPort is not None else None,
            udp_dport=l4DstPort if l4DstPort is not None else None
        )
    return pkt


def verify_acl_rules(setup_vnet, duthost, encap_type, expectedDscp, match_fields=None):
    pkt = create_inner_packet(setup_vnet, duthost, encap_type, match_fields)
    exp_pkt = create_expected_packet(setup_vnet, duthost, encap_type, expectedDscp, pkt)
    setup_vnet['ptfadapter'].dataplane.flush()
    # Clear ACL Counter
    Logger.info("Clear ACL counters (aclshow -c):\n%s", duthost.shell('aclshow -c')['stdout'])
    testutils.send(test=setup_vnet['ptfadapter'], port_id=setup_vnet['ptf_src_port'], pkt=pkt)
    # Check ACL Counter
    time.sleep(3)
    Logger.info("ACL counters (aclshow -a):\n%s", duthost.shell('aclshow -a')['stdout'])
    testutils.verify_packet_any_port(test=setup_vnet['ptfadapter'], pkt=exp_pkt, ports=setup_vnet['ptf_dst_ports'])


def test_acl_create_delete_tables(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)
    create_acl_rule(duthost, TABLE, '1', '9999', str(40), dstPrefix)
    verify_acl_rules(setUp_vnet, duthost, encap_type, 40)


def test_acl_rules_with_different_dscp(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)

    # Create multiple rules with different priorities, rule IDs, and SRC_IP/SRC_IPV6 fields
    if TABLE == TABLE_V4:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '10', 'match': '"SRC_IP":"170.170.170.1/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20', 'match': '"SRC_IP":"170.170.170.2/32"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30', 'match': '"SRC_IP":"170.170.170.3/32"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40', 'match': '"SRC_IP":"170.170.170.4/32"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '50', 'match': '"SRC_IP":"170.170.170.5/32"'}
        ]
    else:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '10',
             'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:1/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20',
             'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:2/128"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30',
             'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:3/128"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40',
             'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:4/128"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '50',
             'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:5/128"'}
        ]

    for rule in rules:
        create_acl_rule(duthost,
                        TABLE,
                        rule['rule_id'],
                        rule['priority'],
                        rule['dscp_action'],
                        dstPrefix, rule['match'])
    for rule in rules:
        verify_acl_rules(setUp_vnet,
                         duthost,
                         encap_type,
                         int(rule['dscp_action']),
                         rule['match'])


def test_acl_rule_with_different_match_fields(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)
    # Test different match fields
    if TABLE == TABLE_V4:
        match_fields_list = [
            '"SRC_IP":"170.170.170.9/32"',
            '"L4_SRC_PORT":"1234"',
            '"L4_DST_PORT":"80"',
            '"DSCP":"10"'
        ]
    else:
        match_fields_list = [
            '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0006/128"',
            '"L4_SRC_PORT":"1234"',
            '"L4_DST_PORT":"80"',
            '"DSCP":"10"'
        ]

    for idx, match_fields in enumerate(match_fields_list, start=6):
        rule_id = str(idx)
        priority = str(100 * idx)
        dscp_action = str(5 * idx)
        create_acl_rule(duthost, TABLE, rule_id, priority, dscp_action, dstPrefix, match_fields)
        verify_acl_rules(setUp_vnet, duthost, encap_type, int(dscp_action), match_fields)


def test_acl_rules_with_same_dscp(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)
    # Create multiple rules with different priorities, rule IDs, and SRC_IP/SRC_IPV6 fields
    if TABLE == TABLE_V4:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.1/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.2/32"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.3/32"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.4/32"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.5/32"'}
        ]
    else:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::1/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::2/128"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::3/128"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::4/128"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::5/128"'}
        ]

    for rule in rules:
        create_acl_rule(duthost,
                        TABLE,
                        rule['rule_id'],
                        rule['priority'],
                        rule['dscp_action'],
                        dstPrefix,
                        rule['match'])
    for rule in rules:
        verify_acl_rules(setUp_vnet,
                         duthost,
                         encap_type,
                         int(rule['dscp_action']),
                         rule['match'])


def test_acl_rule_deletion(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)

    # Create 4 rules with different priorities, rule IDs, and SRC_IP/SRC_IPV6 fields
    if TABLE == TABLE_V4:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '15', 'match': '"SRC_IP":"192.168.1.1/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '25', 'match': '"SRC_IP":"192.168.1.2/32"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '35', 'match': '"SRC_IP":"192.168.1.3/32"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '45', 'match': '"SRC_IP":"192.168.1.4/32"'}
        ]
    else:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '15',
             'match': '"SRC_IPV6":"2001:db8:1::1/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '25',
             'match': '"SRC_IPV6":"2001:db8:1::2/128"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '35',
             'match': '"SRC_IPV6":"2001:db8:1::3/128"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '45',
             'match': '"SRC_IPV6":"2001:db8:1::4/128"'}
        ]

    # Configure all 4 rules
    Logger.info("Configuring 4 ACL rules")
    for rule in rules:
        create_acl_rule(duthost,
                        TABLE,
                        rule['rule_id'],
                        rule['priority'],
                        rule['dscp_action'],
                        dstPrefix,
                        rule['match'])

    # Verify all 4 rules work (DSCP rewrite happens)
    Logger.info("Verifying all 4 rules apply DSCP rewrite correctly")
    for rule in rules:
        verify_acl_rules(setUp_vnet,
                         duthost,
                         encap_type,
                         int(rule['dscp_action']),
                         rule['match'])

    # Delete rule 2
    Logger.info("Deleting rule 2 (DSCP action 25)")
    del_acl_rule(duthost, TABLE, '2')

    # Verify rule 2 no longer applies DSCP rewrite (should have default DSCP 33)
    Logger.info("Verifying deleted rule 2 no longer applies DSCP rewrite (expecting default DSCP 33)")
    deleted_rule = rules[1]
    rules.pop(1)
    verify_acl_rules(setUp_vnet,
                     duthost,
                     encap_type,
                     33,
                     deleted_rule['match'])

    # Verify remaining 3 rules still work
    for rule in rules:
        verify_acl_rules(setUp_vnet,
                         duthost,
                         encap_type,
                         int(rule['dscp_action']),
                         rule['match'])

    # Re-add rule 2 and verify DSCP rewrite applies again
    Logger.info("Re-adding deleted rule 2 (DSCP action 25)")
    create_acl_rule(duthost,
                    TABLE,
                    deleted_rule['rule_id'],
                    deleted_rule['priority'],
                    deleted_rule['dscp_action'],
                    dstPrefix,
                    deleted_rule['match'])
    Logger.info("Verifying re-added rule 2 applies DSCP rewrite correctly")
    verify_acl_rules(setUp_vnet,
                     duthost,
                     encap_type,
                     int(deleted_rule['dscp_action']),
                     deleted_rule['match'])


def test_acl_rule_no_match_default_dscp(setUp, duthost, encap_type, acl_table_setup_and_cleanup):
    setUp_vnet = setUp
    TABLE = acl_table_setup_and_cleanup
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)

    # Create rules with specific match criteria that won't match default test traffic
    if TABLE == TABLE_V4:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '20', 'match': '"SRC_IP":"100.64.0.1/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '30', 'match': '"SRC_IP":"100.64.0.2/32"'}
        ]
    else:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '20', 'match': '"SRC_IPV6":"2001:db8:999::1/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '30', 'match': '"SRC_IPV6":"2001:db8:999::2/128"'}
        ]

    Logger.info("Creating ACL rules")
    for rule in rules:
        create_acl_rule(duthost, TABLE, rule['rule_id'], rule['priority'],
                        rule['dscp_action'], dstPrefix, rule['match'])

    # Verify traffic that doesn't match any rule gets default DSCP 33
    Logger.info("Verifying non-matching traffic uses default DSCP 33")
    verify_acl_rules(setUp_vnet, duthost, encap_type, 33)
