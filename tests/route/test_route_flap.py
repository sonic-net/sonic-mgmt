import math
import os
import yaml
import requests
import time

import json
import logging
import re
import ipaddress
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy

from ptf.mask import Mask
from natsort import natsorted

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 3,
    'confident': 10,
    'thorough': 20,
    'diagnose': 50
}

WAIT_EXPECTED_PACKET_TIMEOUT = 5
EXABGP_BASE_PORT = 5000


def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def get_ptf_recv_ports(duthost, tbinfo):
    """The collector IP is a destination reachable by default. 
    So we need to collect the uplink ports to do a packet capture
    """
    recv_ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for ptf_idx in mg_facts["minigraph_ptf_indices"].values():
        recv_ports.append(ptf_idx)
    return recv_ports


def get_ptf_send_ports(duthost, tbinfo, dev_port):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    member_port = mg_facts['minigraph_portchannels'][dev_port]['members']
    send_port = mg_facts['minigraph_ptf_indices'][member_port[0]]
    return send_port


def send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dst_mac, src_ip, dst_ip):
    pkt = testutils.simple_icmp_packet(eth_dst = dst_mac, ip_src = src_ip, ip_dst = dst_ip, icmp_type=8, icmp_data="")

    ext_pkt = pkt.copy()
    ext_pkt['Ether'].src = dst_mac

    masked_exp_pkt = Mask(ext_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"flags")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"frag")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"ttl")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "code")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "seq")

    logger.info('send ping request packet send port {}, recv port {}, dmac: {}, dip: {}'.format(ptf_send_port, ptf_recv_ports, dst_mac, dst_ip))
    testutils.send(ptfadapter, ptf_send_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, ptf_recv_ports, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def get_ip_route_info(duthost):
    output = json.loads(duthost.shell('vtysh -c "show ip route json"', verbose=False)['stdout'])
    return output


def get_exabgp_port(tbinfo, nbrhosts):
    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys()])
    tor1 = tor_neighbors[0]
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    return tor1_exabgp_port


def test_route_flap(duthost, tbinfo, nbrhosts, ptfhost, ptfadapter, get_function_conpleteness_level):
    ptf_ip = tbinfo['ptf_ip']
    #dst mac = router mac
    dut_mac = duthost.facts['router_mac']

    #get neighbor
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    neighbor = mg_facts['minigraph_lo_interfaces'][0]['addr']

    #get dst_prefix_list and nexthop
    iproute_info = get_ip_route_info(duthost)
    dst_prefix_list = []
    for route_prefix, route_info in iproute_info.items():
        if "/25" in route_prefix:
            dst_prefix_list.append(route_prefix.strip('/25'))
        for nexthops, nexthops_info in route_info[0].items():
            if nexthops == 'nexthops':
                for key, value in nexthops_info[0].items():
                    if key == 'ip':
                        nexthop = value
                    if key == 'interfaceName':
                        dev_port = value

    route_nums = len(dst_prefix_list)
    logger.info("route_nums = %d" % route_nums)

    #choose one ptf port to send msg
    ptf_send_port = get_ptf_send_ports(duthost, tbinfo, dev_port)
    ptf_recv_ports = get_ptf_recv_ports(duthost, tbinfo)

    exabgp_port = get_exabgp_port(tbinfo, nbrhosts)
    logger.info("exabgp_port = %d" % exabgp_port)

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'basic'

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        logger.info("Round %s" % loop_times)
        route_index = 1
        while route_index < route_nums/10:
            dst_prefix = dst_prefix_list[route_index]
            ping_ip = dst_prefix_list[0]

            #test link status
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)

            withdraw_route(ptf_ip, neighbor, dst_prefix, nexthop, exabgp_port)
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)
            
            announce_route(ptf_ip, neighbor, dst_prefix, nexthop, exabgp_port)
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)

            route_index += 1
            
        loop_times -= 1
    
    logger.info("End")
