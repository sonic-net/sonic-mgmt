"""
Postcard SONiC test
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

reset_cycle = 1
min_sleeptime = 3

################################################################################
@group('postcard')
@group('postcard_no_suppression')
class PostcardTest(BaseTest):
    def runTest(self):
        print 'postcard test'
        bind_postcard_pkt()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        switch = sonic_switch.SONiCSwitch(dtel_monitoring_type='postcard',
                                          dtel_switch_id=switch_id,
                                          management_ip=switch_ip)

        try:
            rs = switch.create_dtel_report_session(dst_ip_list=report_dst)

            flow_watchlist = switch.create_dtel_watchlist(watchlist_type='flow')

            # Temporary entry to test delete after creating another entry
            flow_watchlist_entry_temp = flow_watchlist.create_entry(
                priority=10,
                ether_type=0x9000,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1],
                l4_src_port_range='900-1100',
                dtel_sample_percent=100,
                dtel_report_all=True)

            flow_watchlist_entry = flow_watchlist.create_entry(
                priority=10,
                ether_type=0x800,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1],
                l4_src_port_range='900-1100',
                dtel_sample_percent=100,
                dtel_report_all=True)

            flow_watchlist_entry_temp.delete()

            switch.dtel_postcard_enable = True
            switch.dtel_latency_sensitivity = MAX_QUANTIZATION

            time.sleep(min_sleeptime)

            pkt_in_1 = simple_tcp_packet(
                eth_dst=mac_self,
                eth_src=mac_nbr[0],
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                tcp_sport=1001,
                ip_id=105,
                ip_ttl=64,
                tcp_flags=None,
                pktlen=128)

            exp_pkt_out_1 = simple_tcp_packet(
                eth_dst=mac_nbr[1],
                eth_src=mac_self,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                tcp_sport=1001,
                ip_id=105,
                tcp_flags=None,
                ip_ttl=63,
                pktlen=128)

            exp_postcard_inner_1 = postcard_report(
                packet=exp_pkt_out_1,
                switch_id=switch_id,
                ingress_port=swports[0],
                egress_port=swports[1],
                queue_id=0,
                queue_depth=0,
                egress_tstamp=0)

            exp_postcard_pkt_1 = ipv4_dtel_pkt(
                eth_dst=mac_nbr[report_ports[0]],
                eth_src=mac_self,
                ip_src=report_src,
                ip_dst=report_dst[0],
                ip_id=0,
                ip_ttl=64,
                next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL,
                dropped=0,
                congested_queue=0,
                path_tracking_flow=1,
                inner_frame=exp_postcard_inner_1)

            # send a test packet
            send_packet(self, swports[0], str(pkt_in_1))

            # verify packet out
            verify_packet(self, exp_pkt_out_1, swports[1])
            # verify postcard packet
            verify_postcard_packet(
                self, exp_postcard_pkt_1, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "Passed for the 1st pkt with sport 1001."

            pkt_in_2 = simple_tcp_packet(
                eth_dst=mac_self,
                eth_src=mac_nbr[0],
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                tcp_sport=5005,
                ip_id=105,
                ip_ttl=64,
                tcp_flags=None,
                pktlen=128)

            exp_pkt_out_2 = simple_tcp_packet(
                eth_dst=mac_nbr[1],
                eth_src=mac_self,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                tcp_sport=5005,
                ip_id=105,
                tcp_flags=None,
                ip_ttl=63,
                pktlen=128)

            exp_postcard_inner_2 = postcard_report(
                packet=exp_pkt_out_2,
                switch_id=switch_id,
                ingress_port=swports[0],
                egress_port=swports[1],
                queue_id=0,
                queue_depth=0,
                egress_tstamp=0)

            exp_postcard_pkt_2 = ipv4_dtel_pkt(
                eth_dst=mac_nbr[report_ports[0]],
                eth_src=mac_self,
                ip_src=report_src,
                ip_dst=report_dst[0],
                ip_id=0,
                ip_ttl=64,
                next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL,
                dropped=0,
                congested_queue=0,
                path_tracking_flow=1,
                inner_frame=exp_postcard_inner_2)

            # send a test packet
            send_packet(self, swports[0], str(pkt_in_2))
            # verify packet out
            verify_packet(self, exp_pkt_out_2, swports[1])
            #verify_no_other_packets(self)
            print "Passed for the 2nd pkt with sport 5005."

            flow_watchlist_entry.delete()
            time.sleep(min_sleeptime)
            # send a test packet
            send_packet(self, swports[0], str(pkt_in_1))
            # verify packet out
            verify_packet(self, exp_pkt_out_1, swports[1])
            #verify_no_other_packets(self)
            print "Passed for watchlist_delete api"

            flow_watchlist_entry = flow_watchlist.create_entry(
                priority=10,
                ether_type=0x800,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1],
                l4_src_port=5005,
                dtel_sample_percent=100,
                dtel_report_all=True)

            time.sleep(min_sleeptime)

            # send a test packet
            send_packet(self, swports[0], str(pkt_in_2))
            # verify packet out
            verify_packet(self, exp_pkt_out_2, swports[1])
            # verify potcard packet
            verify_postcard_packet(
                self, exp_postcard_pkt_2, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "Passed for the 3rd pkt with sport 5005."

        finally:
            switch.cleanup(purge=True)

