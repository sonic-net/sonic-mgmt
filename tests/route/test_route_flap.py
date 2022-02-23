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

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 5,
    'confident': 25,
    'thorough': 50,
    'diagnose': 100
}

logger = logging.getLogger(__name__)

def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200

def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def get_send_port(duthost, tbinfo, port_info):
	dev_port = port_info[0][1]
	mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
	logger.info("mg_facts: %s" % mg_facts)
	member_port = mg_facts['minigraph_portchannels'][dev_port]['members']
	logger.info("member_port: %s" % member_port)
	send_port = mg_facts['minigraph_ptf_indices'][member_port[0]]
	logger.info("src_port: %d" % send_port)
	return send_port


def send_recv_ping_packet(ptfadapter, src_port, dst_mac, dst_ip):
	pkt = testutils.simple_icmp_packet(
									eth_dst = dst_mac, 
									ip_dst = dst_ip, 
									icmp_type=8)

	ext_pkt = pkt.copy()
	ext_pkt['Ether'].src = dst_mac

	masked_exp_pkt = Mask(ext_pkt)
	masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
	masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"ttl")
	masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")
	masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
	masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
	masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
	masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")

	logger.info('send ping request packet source port id {} dmac: {} dip: {}'.format(src_port, dst_mac, dst_ip))
	testutils.send(ptfadapter, src_port, pkt)
	testutils.verify_packet(ptfadapter, masked_exp_pkt, src_port, timeout=None)


def get_ip_route_info(duthost):
	output = duthost.command("ip route")['stdout']
	output.replace('\n', ' ').replace('\r', ' ')
	return output


def get_url_port(duthost, ptfhost, nexthop):
	bgp_output = duthost.shell("show ip bgp summary | grep %s" % nexthop)['stdout']
	bgp_info = re.findall(r"ARISTA(\S+)", bgp_output)
	logger.info("bgp_info = %s" % bgp_info)

	path = "ARISTA" + bgp_info[0] + ".conf"

	#get url port from /etc/exabgp/
	res = ptfhost.shell('cat /etc/exabgp/{}'.format(path))['stdout']
	logger.info("res = %s" % res)

	res.replace('\n', ' ').replace('\r', ' ')
	port_info = re.findall(r"run /usr/bin/python /usr/share/exabgp/http_api.py ((\d+))", res)

	port = int(port_info[0][0].encode("utf-8"))
	logger.info("port = %d" % port)
	return port


def test_route_flap(duthost, tbinfo, ptfhost, ptfadapter, get_function_conpleteness_level):
	ptf_ip = tbinfo['ptf_ip']

	#dst mac = router mac
	dst_mac = duthost.facts['router_mac']

	#stdout of ip route
	iproute_info = get_ip_route_info(duthost)

	#example: nexthop via 10.0.0.57 dev PortChannel101 weight 1
	port_info = re.findall(r"nexthop via (\S+) dev (\S+) weight (\d+)", iproute_info)
	#example: 192.168.8.0/25 (nhid 84669) proto bgp src 10.1.0.32 metric 20
	route_nhid_info = re.findall(r"(\S+) proto bgp src (\S+)", iproute_info)
	route_list = [x[0] for x in route_nhid_info]
	route_str = " ".join(route_list)
	#get route ip address without nhid(if have)
	route_info = re.findall(r"(\S+)/25", route_str)
	logger.info("route_info %s" % route_info)
	
	nexthop = port_info[0][0]

	#choose one ptf port to send msg
	src_port = get_send_port(duthost, tbinfo, port_info)
	
	route_nums = len(route_info)

	#ptf url port
	url_port = get_url_port(duthost, ptfhost, nexthop)

	normalized_level = get_function_conpleteness_level
	if normalized_level is None:
		normalized_level = 'basic'

	loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

	while loop_times > 0:
		logger.info("Round %s" % loop_times)
		route_index = route_nums - route_nums / 2
		while route_index < route_nums:
			#neighbor = lo address
			neighbor = route_info[route_index][len(route_nhid_info[0])]
			#example: dst_prefix = 192.168.8.0
			dst_prefix = route_info[route_index][0]
			ping_ip = route_info[2][0]

			#test link status
			send_recv_ping_packet(ptfadapter, src_port, dst_mac, ping_ip)

			withdraw_route(ptf_ip, neighbor, dst_prefix, nexthop, url_port)
			send_recv_ping_packet(ptfadapter, src_port, dst_mac, ping_ip)
			
			announce_route(ptf_ip, neighbor, dst_prefix, nexthop, url_port)
			send_recv_ping_packet(ptfadapter, src_port, dst_mac, ping_ip)

			route_index += 1
			
		loop_times -= 1
	
	logger.info("End")
	