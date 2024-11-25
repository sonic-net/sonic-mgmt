#! /usr/bin/env python3
'''
    These tests check the Vxlam ecmp nexthop group switch over functionality. Further details are
    provided with each test.
'''
import os
import time
import logging
from collections import defaultdict
import pytest
from tests.common.helpers.assertions import pytest_assert as py_assert

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
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

TMP_DIR = '/tmp'
ACL_TABLE_FILE = 'acl_tbl_config.json'
ACL_TABLE_REMOVE_FILE = "acl_tbl_del.json"

ACL_RULES_FILE = 'acl_rule_config.json'
ACL_RULES_REMOVE_FILE = "acl_rules_del.json"
ACL_TEMPLATE_TABLE_FILE = "dscp_acl_tablev4_v6.j2"
ACL_TEMPLATE_RULE_FILE = "dscp_acl_rulev4_v6.j2"

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
    if tbinfo["topo"]["type"] == "mx":
        dut_port = rand_selected_dut.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"][0]
    else:
        dut_port = list(mg_facts['minigraph_portchannels'].keys())[0]
    if not dut_port:
        pytest.skip('No portchannels found')
    if "Ethernet" in dut_port:
        dut_eth_port = dut_port
    elif "PortChannel" in dut_port:
        dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    topo = tbinfo["topo"]["type"]
    # Get the list of upstream ports
    upstream_ports = defaultdict(list)
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]) or \
                (topo == "m0" and "M1" in neighbor["name"]) or (topo == "mx" and "M0" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
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
    if data['minigraph_facts']['minigraph_lo_interfaces'][0]['prefixlen'] == 32:
        data['loopback_v4'] = data['minigraph_facts']['minigraph_lo_interfaces'][0]['addr']
        data['loopback_v6'] = data['minigraph_facts']['minigraph_lo_interfaces'][1]['addr']
    else:
        data['loopback_v4'] = data['minigraph_facts']['minigraph_lo_interfaces'][1]['addr']
        data['loopback_v6'] = data['minigraph_facts']['minigraph_lo_interfaces'][0]['addr']

    asic_type = duthost.facts["asic_type"]
    if asic_type in ["cisco-8000", "mellanox"]:
        data['tolerance'] = 0.03
    else:
        raise RuntimeError("Pls update this script for your platform.")

    platform = duthost.facts['platform']
    if platform == 'x86_64-mlnx_msn2700-r0' and encap_type in ['v4_in_v6', 'v6_in_v6']:
        pytest.skip("Skipping test. v6 underlay is not supported on Mlnx 2700")

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = False
    ecmp_utils.Constants['DEBUG'] = False

    Logger.info("Constants to be used in the script:%s", ecmp_utils.Constants)

    data['vxlan_port'] = 4789
    data['dut_mac'] = data['duthost'].facts['router_mac']
    time.sleep(1)
    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=data['vxlan_port'],
        dutmac=data['dut_mac'])

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    encap_type_data = {}

    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    try:
        tunnel_names[outer_layer_version]
    except KeyError:
        tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(
            data['duthost'],
            minigraph_data,
            af=outer_layer_version)

    payload_version = ecmp_utils.get_payload_version(encap_type)
    encap_type = "{}_in_{}".format(payload_version, outer_layer_version)

    try:
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
    except KeyError:
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
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TEST' ")
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TESTV6' ")
    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    payload_version = ecmp_utils.get_payload_version(encap_type)
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
    time.sleep(5)
    py_assert(
        duthost.shell("redis-cli -n 6 hgetall 'ACL_TABLE_TABLE|OVERLAY_MARK_META_TEST'")['stdout'] == 'status\nActive')
    py_assert(duthost.shell(
        "redis-cli -n 6 hgetall 'ACL_TABLE_TABLE|OVERLAY_MARK_META_TESTV6'")['stdout'] == 'status\nActive')


def del_acl_tables(duthost):
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TEST' ")
    duthost.shell("redis-cli -n 4 del 'ACL_TABLE|OVERLAY_MARK_META_TESTV6' ")


def create_acl_Rule(duthost, tableName, ruleNumber, priority, dscpAction, dstIp, qualifer=None):
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


def del_acl_rule(duthost, table, ruleId):
    key = f'ACL_RULE|{table}|RULE{ruleId}'
    duthost.shell(f"redis-cli -n 4 del '{key}'")


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
    testutils.send(test=setup_vnet['ptfadapter'], port_id=setup_vnet['ptf_src_port'], pkt=pkt)
    testutils.verify_packet_any_port(test=setup_vnet['ptfadapter'], pkt=exp_pkt, ports=setup_vnet['ptf_dst_ports'])


def test_acl_create_delete_tables(setUp, duthost, encap_type):
    setUp_vnet = setUp
    setup_acl_tables(duthost, setUp_vnet)
    if 'v4_in' in encap_type:
        TABLE = TABLE_V4
    else:
        TABLE = TABLE_V6
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)
    create_acl_Rule(duthost, TABLE, '1', '9999', str(40), dstPrefix)
    verify_acl_rules(setUp_vnet, duthost, encap_type, 40)
    del_acl_rule(duthost, TABLE, '1')
    del_acl_tables(duthost)


def test_acl_rules_with_different_dscp(setUp, duthost, encap_type):
    setUp_vnet = setUp
    setup_acl_tables(duthost, setUp_vnet)
    if 'v4_in' in encap_type:
        TABLE = TABLE_V4
    else:
        TABLE = TABLE_V6
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
        create_acl_Rule(duthost,
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

    # Delete all rules
    for rule in rules:
        del_acl_rule(duthost, TABLE, rule['rule_id'])
    del_acl_tables(duthost)


def test_acl_rule_with_different_match_fields(setUp, duthost, encap_type):
    setUp_vnet = setUp
    setup_acl_tables(duthost, setUp_vnet)
    if 'v4_in' in encap_type:
        TABLE = TABLE_V4
    else:
        TABLE = TABLE_V6
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
        create_acl_Rule(duthost, TABLE, rule_id, priority, dscp_action, dstPrefix, match_fields)
        verify_acl_rules(setUp_vnet, duthost, encap_type, int(dscp_action), match_fields)

    # Delete all rules
    for idx in range(6, 6 + len(match_fields_list)):
        del_acl_rule(duthost, TABLE, str(idx))

    del_acl_tables(duthost)


def test_acl_rules_with_same_dscp(setUp, duthost, encap_type):
    setUp_vnet = setUp
    setup_acl_tables(duthost, setUp_vnet)
    if 'v4_in' in encap_type:
        TABLE = TABLE_V4
    else:
        TABLE = TABLE_V6
    vnet = list(setUp_vnet[encap_type]['vnet_vni_map'].keys())[0]
    dstip = list(setUp_vnet[encap_type]['dest_to_nh_map'][vnet].keys())[0]
    mask = ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]
    dstPrefix = dstip + '/' + str(mask)
    # Create multiple rules with different priorities, rule IDs, and SRC_IP/SRC_IPV6 fields
    if TABLE == TABLE_V4:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.1"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.2"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.3"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.4"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.5"'}
        ]
    else:
        rules = [
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::1"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::2"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::3"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::4"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::5"'}
        ]

    for rule in rules:
        create_acl_Rule(duthost,
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

    # Delete all rules
    for rule in rules:
        del_acl_rule(duthost, TABLE, rule['rule_id'])
    del_acl_tables(duthost)
