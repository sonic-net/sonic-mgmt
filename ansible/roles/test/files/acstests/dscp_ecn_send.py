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

class DscpEcnSend(acs_base_test.ACSDataplaneTest):
    def runTest(self):

        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)

        router_mac = self.test_params['router_mac']
        dscp = self.test_params['dscp']
        tos = dscp << 2
        tos |= self.test_params['ecn']
        ip_src = '10.0.0.1' if 'ip_src' not in self.test_params else self.test_params['ip_src']
        ip_dst = '10.0.0.3' if 'ip_dst' not in self.test_params else self.test_params['ip_dst']
        for i in range(0, self.test_params['packet_num']):
            pkt = simple_tcp_packet(eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
            send_packet(self, 0, pkt)

        leaking_pkt_number = 0
        for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
            leaking_pkt_number += 1

        print "leaking packet %d" % leaking_pkt_number
