import ipaddress
import logging
import random
import socket
import sys
import struct
import ipaddress
import re

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *


class PfcWdTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.queue_index = int(self.test_params['queue_index'])
        self.pkt_count = int(self.test_params['pkt_count'])
        self.port_src = int(self.test_params['port_src'])
        self.port_dst = self.test_params['port_dst']
        self.ip_dst = self.test_params['ip_dst']
        self.port_type = self.test_params['port_type']
        self.wd_action = self.test_params.get('wd_action', 'drop')
        self.port_src_vlan_id = self.test_params.get('port_src_vlan_id')
        self.port_dst_vlan_id = self.test_params.get('port_dst_vlan_id')

    def runTest(self):
        ecn = 1
        dscp = self.queue_index
        tos = dscp << 2
        tos |= ecn

        matches = re.findall('\[([\d\s]+)\]', self.port_dst)

        dst_port_list = []
        for match in matches:
            for port in match.split():
                dst_port_list.append(int(port))
        src_mac = self.dataplane.get_mac(*random.choice(self.dataplane.ports.keys()))

        if self.port_type == "portchannel":
            for x in range(0, self.pkt_count):
                sport = random.randint(0, 65535)
                dport = random.randint(0, 65535)
                ip_src = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                ip_src =ipaddress.IPv4Address(unicode(ip_src,'utf-8'))
                if not isinstance(self.ip_dst, unicode):
                    self.ip_dst = unicode(self.ip_dst, 'utf-8')
                ip_dst = ipaddress.IPv4Address(self.ip_dst)
                while ip_src == ip_dst or ip_src.is_multicast or ip_src.is_private or ip_src.is_global or ip_src.is_reserved:
                    ip_src = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                    ip_src =ipaddress.IPv4Address(unicode(ip_src,'utf-8'))

                ip_src = str(ip_src)
                pkt_args = {
                    'eth_dst': self.router_mac,
                    'eth_src': src_mac,
                    'ip_src': ip_src,
                    'ip_dst': self.ip_dst,
                    'ip_tos': tos,
                    'tcp_sport': sport,
                    'tcp_dport': dport,
                    'ip_ttl': 64
                }
                if self.port_src_vlan_id is not None:
                    pkt_args['dl_vlan_enable'] = True
                    pkt_args['vlan_vid'] = int(self.port_src_vlan_id)
                    pkt_args['vlan_pcp'] = self.queue_index
                pkt = simple_tcp_packet(**pkt_args)
                exp_pkt_args = {
                    'eth_src': self.router_mac,
                    'ip_src': ip_src,
                    'ip_dst': self.ip_dst,
                    'ip_tos': tos,
                    'tcp_sport': sport,
                    'tcp_dport': dport,
                    'ip_ttl': 63
                }
                if self.port_dst_vlan_id is not None:
                    exp_pkt_args['dl_vlan_enable'] = True
                    exp_pkt_args['vlan_vid'] = int(self.port_dst_vlan_id)
                    exp_pkt_args['vlan_pcp'] = self.queue_index
                exp_pkt = simple_tcp_packet(**exp_pkt_args)
                masked_exp_pkt = Mask(exp_pkt)
                masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
                masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

                send_packet(self, self.port_src, pkt, 1)
        else:
            sport = random.randint(0, 65535)
            dport = random.randint(0, 65535)
            ip_src = "1.1.1.1"

            pkt_args = {
                'eth_dst': self.router_mac,
                'eth_src': src_mac,
                'ip_src': ip_src,
                'ip_dst': self.ip_dst,
                'ip_tos': tos,
                'tcp_sport': sport,
                'tcp_dport': dport,
                'ip_ttl': 64
            }
            if self.port_src_vlan_id is not None:
                pkt_args['dl_vlan_enable'] = True
                pkt_args['vlan_vid'] = int(self.port_src_vlan_id)
                pkt_args['vlan_pcp'] = self.queue_index
            pkt = simple_tcp_packet(**pkt_args)
            exp_pkt_args = {
                'eth_src': self.router_mac,
                'ip_src': ip_src,
                'ip_dst': self.ip_dst,
                'ip_tos': tos,
                'tcp_sport': sport,
                'tcp_dport': dport,
                'ip_ttl': 63
            }
            if self.port_dst_vlan_id is not None:
                exp_pkt_args['dl_vlan_enable'] = True
                exp_pkt_args['vlan_vid'] = int(self.port_dst_vlan_id)
                exp_pkt_args['vlan_pcp'] = self.queue_index
            exp_pkt = simple_tcp_packet(**exp_pkt_args)
            masked_exp_pkt = Mask(exp_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

            send_packet(self, self.port_src, pkt, self.pkt_count)
        if self.wd_action == 'drop':
            return verify_no_packet_any(self, masked_exp_pkt, dst_port_list)
        elif self.wd_action == 'forward':
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
