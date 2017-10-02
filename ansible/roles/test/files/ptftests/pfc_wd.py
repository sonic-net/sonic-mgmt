import ipaddress
import logging
import random
import socket
import sys

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
        self.ip_src = self.test_params['ip_src']
        self.ip_dst = self.test_params['ip_dst']
        self.wd_action = self.test_params.get('wd_action', 'drop')

    def runTest(self):
        ecn = 1
        dscp = self.queue_index
        tos = dscp << 2
        tos |= ecn
        dst_port_list = range(0,32)
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=self.ip_src,
                            ip_dst=self.ip_dst,
                            ip_tos = tos,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_src=self.router_mac,
                            ip_src=self.ip_src,
                            ip_dst=self.ip_dst,
                            ip_tos = tos,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, self.port_src, pkt, self.pkt_count)

        if self.wd_action == 'drop':
            return verify_no_packet_any(self, masked_exp_pkt, dst_port_list)
        else:
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
