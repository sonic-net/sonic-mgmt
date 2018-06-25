"""
SONiC drop tests
"""

import logging
import os
import random
import sys
import time
import unittest
import threading

import ptf.dataplane as dataplane
from scapy.all import *
from ptf.testutils import *
from ptf.thriftutils import *
from switch_ptf_config import *

mac_all_ospf_routers = '01:00:5e:00:00:05'
ipaddr_all_ospf_routers = '224.0.0.5'

min_sleeptime = 3

################################################################################
@group('drop')
@group('postcard')
@group('int_ep')
@group('int_transit')
class IngressDropTest(BaseTest):
    def runTest(self):
        print 'Ingress Drop test with malformed packet'
        bind_drop_pkt()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        # Value of dtel_monitoring_type is irrelevant since neither postcard
        # or INT will be enabled, and no 'flow' watchlist will be configured
        switch = sonic_switch.SONiCSwitch(dtel_monitoring_type='postcard',
                                          dtel_switch_id=switch_id,
                                          management_ip=switch_ip)

        switch.dtel_int_l4_dscp = {'value': get_int_l45_dscp_value(),
                                   'mask': get_int_l45_dscp_mask()}

        try:
            rs = switch.create_dtel_report_session(dst_ip_list=report_dst)

            pkt_in = simple_tcp_packet(
                eth_dst=mac_self,
                eth_src=mac_nbr[0],
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                ip_id=105,
                ip_ttl=64,
                tcp_flags=None,
                pktlen=128)

            exp_pkt_out = simple_tcp_packet(
                eth_dst=mac_nbr[1],
                eth_src=mac_self,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                ip_id=105,
                ip_ttl=63,
                tcp_flags=None,
                pktlen=128)

            pkt_in_malformed = simple_tcp_packet(
                eth_dst=mac_self,
                eth_src=mac_all_zeros,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                ip_id=105,
                ip_ttl=64,
                tcp_flags=None,
                pktlen=128)

            exp_drop_inner = drop_report(
                packet=pkt_in_malformed,
                switch_id=switch_id,
                ingress_port=swports[0],
                egress_port=INVALID_PORT_ID,
                queue_id=0,
                drop_reason=10)  # outer source mac all zeros

            exp_drop_pkt = ipv4_dtel_pkt(
                eth_dst=mac_nbr[report_ports[0]],
                eth_src=mac_self,
                ip_src=report_src,
                ip_dst=report_dst[0],
                ip_id=0,
                ip_ttl=64,
                next_proto=DTEL_REPORT_NEXT_PROTO_DROP,
                dropped=1,
                congested_queue=0,
                path_tracking_flow=0,
                inner_frame=exp_drop_inner)

            time.sleep(min_sleeptime)

            print "Start sending packets"

            # send a test packet
            send_packet(self, swports[0], str(pkt_in))
            # verify packet out
            verify_packet(self, exp_pkt_out, swports[1])
            #verify_no_other_packets(self)
            print "Normal packet passed"

            # send malformed packet
            send_packet(self, swports[0], str(pkt_in_malformed))
            # verify no packets out
            #verify_no_other_packets(self)
            print "No report for malformed packet before adding watchlist"

            # Create drop watchlist
            drop_watchlist = switch.create_dtel_watchlist(watchlist_type='drop')
            drop_watchlist_entry = drop_watchlist.create_entry(
                priority=10,
                ether_type=0x800,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1])

            switch.dtel_drop_report_enable = True

            time.sleep(min_sleeptime)

            # send a test packet
            send_packet(self, swports[0], str(pkt_in))
            # verify packet out
            verify_packet(self, exp_pkt_out, swports[1])
            #verify_no_other_packets(self)
            print "Normal packet passed after adding drop watchlist"

            # send malformed packet
            send_packet(self, swports[0], str(pkt_in_malformed))
            # verify drop packet
            verify_dtel_packet(
                self, exp_drop_pkt, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "Received drop report for malformed packet"

            # send the same malformed packet again
            send_packet(self, swports[0], str(pkt_in_malformed))
            # verify drop packet
            verify_dtel_packet(
                self, exp_drop_pkt, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "Passed for identical malformed pkt from the same port"

            drop_watchlist_entry.delete()
            print "delete watchlist entry"
            time.sleep(min_sleeptime)

            # send a malformed packet
            send_packet(self, swports[0], str(pkt_in_malformed))
            #verify_no_other_packets(self)
            print "No report after deleting watchlist"

        finally:
            switch.cleanup(purge=True)

