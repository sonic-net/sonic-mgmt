"""
This module contains tests for Segment Routing over IPv6 feature (SRv6)
Tests are based on the following feature docs:
- SONiC feature HLD https://github.com/Azure/SONiC/blob/e2d9fef2526244d3b734f3bb695cd5d22453749d/doc/srv6/srv6_hld.md
- RFC 8200 - IPv6
- RFC 8402 - Segment Routing Architecture
- RFC 8754 - IPv6 Segment Routing Header (SRH)
- RFC 8986 - Segment Routing over IPv6 (SRv6) Network Programming
"""

import pytest
import ptf.testutils as testutils
import ipaddr
from scapy.all import Ether, IP, IPv6, IPv6ExtHdrRouting
import ptf.mask as mask

pytestmark = [
    pytest.mark.topology('t1')
]

SR_POLICY_ENCAP = {
    'segments': ['aaaa::11', 'aaaa::22', 'aaaa::33'],
    'source': '1000::1',
    'name': 'seg1'
}

INNER_PACKET_DEST_IP = {
    'ipv4': '222.0.0.1',
    'ipv6': '222::1'
}


@pytest.fixture(scope="module")
def setup_info(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Collect T0, T2 neighbor interface names, addresses and corresponding PTF indexes
    """
    duthost = duthosts[rand_one_dut_hostname]

    tor_ports = []
    spine_ports = []

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        if "T0" in neigh["name"]:
            tor_ports.append(dut_port)
        elif "T2" in neigh["name"]:
            spine_ports.append(dut_port)

    neigh_if_map = {
        v['name']: iface
        for iface, v in mg_facts["minigraph_neighbors"].items()
    }
    setup_information = {
        "router_mac": duthost.facts["router_mac"],
        "tor_ports": tor_ports,
        "spine_ports": spine_ports,
        "port_index_map": {
            k: v
            for k, v in mg_facts["minigraph_ptf_indices"].items()
            if k in mg_facts["minigraph_ports"]
        },
        "ipv6": {
            neigh_if_map[v["name"]]: v["addr"]
            for v in mg_facts["minigraph_bgp"]
            if ipaddr.IPAddress(v["addr"]).version == 6
        },
        "ipv4": {
            neigh_if_map[v["name"]]: v["addr"]
            for v in mg_facts["minigraph_bgp"]
            if ipaddr.IPAddress(v["addr"]).version == 4
        },
    }

    yield setup_information


def _redis(duthost, db, commands):
    for cmd in commands:
        duthost.shell('redis-cli -n {} {}'.format(db, cmd))


def add_seg_list(duthost, seg_name, seg_list):
    cmds = [
        'SADD SRV6_SID_LIST_TABLE_KEY_SET {}'.format(seg_name),
        'HSET _SRV6_SID_LIST_TABLE:seg1 path {}'.format(','.join(seg_list)),
        'PUBLISH SRV6_SID_LIST_TABLE_CHANNEL G'
    ]
    _redis(duthost, 0, cmds)


def del_seg_list(duthost, seg_name):
    cmds = [
        'SADD SRV6_SID_LIST_TABLE_KEY_SET {}'.format(seg_name),
        'SADD SRV6_SID_LIST_TABLE_DEL_SET {}'.format(seg_name),
        'DEL _SRV6_SID_LIST_TABLE:{}'.format(seg_name),
        'PUBLISH SRV6_SID_LIST_TABLE_CHANNEL G'
    ]
    _redis(duthost, 0, cmds)


def add_encap_route(duthost, netmask, src_addr, policy_name):
    cmds = [
        "SADD ROUTE_TABLE_KEY_SET '{}'".format(netmask),
        "HSET _ROUTE_TABLE:'{}' seg_src '{}' segment '{}'".format(netmask, src_addr, policy_name),
        "PUBLISH ROUTE_TABLE_CHANNEL G"
    ]
    _redis(duthost, 0, cmds)


def del_encap_route(duthost, netmask):
    cmds = [
        "SADD ROUTE_TABLE_KEY_SET '{}'".format(netmask),
        "SADD ROUTE_TABLE_DEL_SET '{}'".format(netmask),
        "DEL _ROUTE_TABLE:'{}'".format(netmask),
        "SREM ROUTE_TABLE_DEL_SET '{}'".format(netmask),
        "DEL ROUTE_TABLE:'{}'".format(netmask),
    ]
    _redis(duthost, 0, cmds)


@pytest.fixture(scope="module")
def setup_h_encaps_red(setup_info, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    nexthop_iface = setup_info['spine_ports'][0]
    rx_iface = setup_info['tor_ports'][0]
    nexthop_addr = setup_info['ipv6'][nexthop_iface]

    # setup T2 neighbor as a nexthop for the 1st segment
    first_seg_netmask = SR_POLICY_ENCAP['segments'][0] + '/128'
    duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"ipv6 route {} {}\"".format(first_seg_netmask, nexthop_addr), ''))

    add_seg_list(duthost, SR_POLICY_ENCAP['name'], SR_POLICY_ENCAP['segments'])
    ip4_dst_netmask = INNER_PACKET_DEST_IP['ipv4']+'/32'
    ip6_dst_netmask = INNER_PACKET_DEST_IP['ipv6']+'/128'
    add_encap_route(duthost, ip4_dst_netmask, SR_POLICY_ENCAP['source'], SR_POLICY_ENCAP['name'])
    add_encap_route(duthost, ip6_dst_netmask, SR_POLICY_ENCAP['source'], SR_POLICY_ENCAP['name'])

    yield {
        'nexthop_iface': nexthop_iface,
        'rx_iface': rx_iface
    }
    del_encap_route(duthost, ip4_dst_netmask)
    del_encap_route(duthost, ip6_dst_netmask)
    del_seg_list(duthost, SR_POLICY_ENCAP['name'])

    duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ipv6 route {} {}\"".format(SR_POLICY_ENCAP['segments'][0] + '/128', nexthop_addr), ''))


@pytest.fixture(params=['ipv4', 'ipv6'])
def packet_to_encap(request, duthosts, rand_one_dut_hostname, ptfadapter):
    duthost = duthosts[rand_one_dut_hostname]

    if request.param == 'ipv4':
        pkt = testutils.simple_tcp_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=INNER_PACKET_DEST_IP['ipv4'],
            ip_src='111.0.0.1',
            ip_ttl=64,
            tcp_sport=4444,
            tcp_dport=6666,
        )
    else:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_dst=INNER_PACKET_DEST_IP['ipv6'],
            ipv6_src='1::1',
            ipv6_hlim=64,
            tcp_sport=4444,
            tcp_dport=6666,
        )

    return pkt


def test_h_encaps_red(setup_h_encaps_red, setup_info, packet_to_encap, ptfadapter):
    """
    Test H.Encaps.Red function. RFC 8986, section 5.2 
    """
    nexthop_iface = setup_h_encaps_red['nexthop_iface']
    rx_iface = setup_h_encaps_red['rx_iface']
    nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]
    ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

    # make a segment list conforn to SRH segments order - reversed
    exp_segments = SR_POLICY_ENCAP['segments'][::-1]
    first_seg = exp_segments[-1]

    # as per Encap.Red SRH does not carry the 1st segment
    exp_segments = exp_segments[:-1]

    # take packet with a stripped Ether header
    exp_inner_packet = packet_to_encap.copy()[1:]

    if IP in packet_to_encap:
        exp_inner_packet[IP].ttl -= 1
        srh_next_header_proto = 4
    else:
        exp_inner_packet[IPv6].hlim -= 1
        srh_next_header_proto = 41

    exp_pkt = testutils.simple_ipv6_sr_packet(
        eth_src=packet_to_encap.dst,
        ipv6_src=SR_POLICY_ENCAP['source'],
        ipv6_dst=first_seg,
        srh_seg_list=exp_segments,
        srh_seg_left=len(exp_segments),
        inner_frame=exp_inner_packet,
        srh_nh=srh_next_header_proto,
    )

    exp_pkt = mask.Mask(exp_pkt.copy())
    exp_pkt.set_do_not_care_scapy(Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(IPv6, 'chksum')
    exp_pkt.set_do_not_care_scapy(IPv6, 'hlim')
    exp_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

    testutils.send(ptfadapter, ptf_tx_port_idx, packet_to_encap)
    testutils.verify_packet(ptfadapter, exp_pkt, nexthop_ptf_port_idx, timeout=5)
