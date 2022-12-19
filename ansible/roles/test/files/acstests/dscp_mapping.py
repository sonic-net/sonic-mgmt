"""
ACS Dataplane Qos tests
"""

import time
import logging
import ptf.packet as scapy

import ptf.dataplane as dataplane
import acs_base_test

from ptf.testutils import *
from ptf.mask import Mask

class ArpPopulate(acs_base_test.ACSDataplaneTest):
    def runTest(self):

        router_mac = self.test_params['router_mac']

        index = 0
        for port in ptf_ports():
            arpreq_pkt = simple_arp_packet(
                          eth_dst='ff:ff:ff:ff:ff:ff',
                          eth_src=self.dataplane.get_mac(port[0], port[1]),
                          arp_op=1,
                          ip_snd='10.0.0.%d' % (index * 2 + 1),
                          ip_tgt='10.0.0.%d' % (index * 2),
                          hw_snd=self.dataplane.get_mac(port[0], port[1]),
                          hw_tgt='ff:ff:ff:ff:ff:ff')
            send_packet(self, port[1], arpreq_pkt)
            index += 1

class DscpMappingTest(acs_base_test.ACSDataplaneTest):
    def runTest(self):

        router_mac = self.test_params['router_mac']

        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        src_mac[1] = self.dataplane.get_mac(0, 1)

        for dscp in range(0, 64):
            print "Sending L3 packet port 0 -> port 1, dscp %d" % dscp
            tos = dscp << 2
            pkt = simple_tcp_packet(eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src='10.0.0.1',
                            ip_dst='10.0.0.3',
                            ip_tos=tos,
                            ip_id=101,
                            ip_ttl=64)

            exp_pkt = simple_tcp_packet(eth_dst=src_mac[1],
                            eth_src=router_mac,
                            ip_src='10.0.0.1',
                            ip_dst='10.0.0.3',
                            ip_tos=tos,
                            ip_id=101,
                            ip_ttl=63)

            send_packet(self, 0, pkt)
            verify_packets(self, exp_pkt, ports=[1])
