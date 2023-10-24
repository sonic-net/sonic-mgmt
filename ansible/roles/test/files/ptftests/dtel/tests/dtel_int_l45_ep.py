"""
INT endpoint SONiC test
"""

import logging
import os
import random
import sys
import time
import unittest
import threading
from copy import deepcopy

import ptf.dataplane as dataplane
from scapy.all import *
from ptf.testutils import *
from ptf.thriftutils import *
from switch_ptf_config import *

import pdb

reset_cycle = 1
min_sleeptime = 3

################################################################################
@group('int_ep')
@group('int_ep_no_suppression')
@group('int_ep_udp_src')
class INT_UDP_SourceTest(BaseTest):
    def runTest(self):
        print 'INT Endpoint Source test'
        prepare_int_l45_bindings()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        switch = sonic_switch.SONiCSwitch(dtel_monitoring_type='int_endpoint',
                                          dtel_switch_id=switch_id,
                                          management_ip=switch_ip)

        try:
            rs = switch.create_dtel_report_session(dst_ip_list=report_dst)

            switch.dtel_int_sink_port_list = []
            switch.dtel_int_l4_dscp = {'value': get_int_l45_dscp_value(),
                                       'mask': get_int_l45_dscp_mask()}
            int_session = switch.create_dtel_int_session(
                max_hop_count=8,
                collect_switch_id=True,
                collect_switch_ports=False,
                collect_ig_timestamp=False,
                collect_eg_timestamp=False,
                collect_queue_info=False)

            time.sleep(min_sleeptime)

            flow_watchlist = switch.create_dtel_watchlist(watchlist_type='flow')

            flow_watchlist_entry = flow_watchlist.create_entry(
                priority=10,
                ether_type=0x800,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1],
                dtel_int_session=int_session,
                dtel_sample_percent=100,
                dtel_report_all=True)

            switch.dtel_int_endpoint_enable = True
            switch.dtel_latency_sensitivity = MAX_QUANTIZATION
            time.sleep(min_sleeptime)

            payload = 'int_l45'
            pkt = simple_udp_packet(
                eth_dst=mac_self,
                eth_src=mac_nbr[0],
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                ip_id=108,
                ip_ttl=64,
                with_udp_chksum=False,
                udp_payload=payload)

            exp_pkt_ = simple_udp_packet(
                eth_dst=mac_nbr[1],
                eth_src=mac_self,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                with_udp_chksum=False,
                ip_id=108,
                ip_ttl=63,
                udp_payload=payload)

            exp_pkt = int_l45_src_packet(
                test=self,
                int_inst_mask=0x8000,
                int_inst_cnt=1,
                max_hop_cnt=8,
                pkt=exp_pkt_)

            exp_pkt = int_l45_packet_add_hop_info(
                Packet=exp_pkt, val=switch_id, incr_cnt=1)

            send_packet(self, swports[0], str(pkt))
            verify_packet(self, exp_pkt, swports[1])
            #verify_no_other_packets(self)
            print "pass 1st packet w/ INT enabled"

            switch.dtel_int_endpoint_enable = False
            time.sleep(min_sleeptime)
            send_packet(self, swports[0], str(pkt))
            verify_packet(self, exp_pkt_, swports[1])
            #verify_no_other_packets(self)
            print "pass 2nd packet w/ INT disabled"

            switch.dtel_int_endpoint_enable = True
            time.sleep(min_sleeptime)
            send_packet(self, swports[0], str(pkt))
            verify_packet(self, exp_pkt, swports[1])
            #verify_no_other_packets(self)
            print "pass 3rd packet w/ INT enabled"

        finally:
            switch.cleanup(purge=True)


@group('int_ep')
@group('int_ep_no_suppression')
@group('int_ep_udp_sink')
class INT_UDP_SinkTest(BaseTest):
    def runTest(self):
        print 'INT Endpoint Sink test'
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        prepare_int_l45_bindings()

        switch = sonic_switch.SONiCSwitch(dtel_monitoring_type='int_endpoint',
                                          dtel_switch_id=switch_id,
                                          management_ip=switch_ip)

        try:
            rs = switch.create_dtel_report_session(dst_ip_list=report_dst)

            switch.dtel_int_sink_port_list = [fpports[1]]
            switch.dtel_int_l4_dscp = {'value': get_int_l45_dscp_value(),
                                       'mask': get_int_l45_dscp_mask()}

            int_session = switch.create_dtel_int_session(
                max_hop_count=8,
                collect_switch_id=True,
                collect_switch_ports=False,
                collect_ig_timestamp=False,
                collect_eg_timestamp=False,
                collect_queue_info=False)

            time.sleep(min_sleeptime)

            flow_watchlist = switch.create_dtel_watchlist(watchlist_type='flow')

            flow_watchlist_entry = flow_watchlist.create_entry(
                priority=10,
                ether_type=0x800,
                src_ip=ipaddr_nbr[0],
                dst_ip=ipaddr_nbr[1],
                dtel_int_session=int_session,
                dtel_sample_percent=100,
                dtel_report_all=True)

            switch.dtel_int_endpoint_enable = True
            switch.dtel_latency_sensitivity = MAX_QUANTIZATION
            time.sleep(min_sleeptime)

            payload = 'int l45'
            # make input frame to inject to sink
            pkt = simple_udp_packet(
                eth_dst=mac_self,
                eth_src=mac_nbr[0],
                ip_id=108,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                ip_ttl=64,
                with_udp_chksum=False,
                udp_sport=101,
                udp_payload=payload)

            int_pkt_orig = int_l45_src_packet(
                test=self,
                int_inst_mask=0x8000,  # swid
                int_inst_cnt=1,
                max_hop_cnt=8,
                dscp=get_int_l45_dscp_value(),
                dscp_mask=get_int_l45_dscp_mask(),
                pkt=pkt)

            # add 2 hop info to the packet
            int_pkt = int_l45_packet_add_hop_info(
                Packet=int_pkt_orig, val=0x66666666, incr_cnt=1)
            int_pkt = int_l45_packet_add_hop_info(
                Packet=int_pkt, val=0x22222222, incr_cnt=1)

            routed_int_pkt = deepcopy(int_pkt)
            routed_int_pkt.getlayer(Ether, 1).src=mac_self
            routed_int_pkt.getlayer(Ether, 1).dst=mac_nbr[1]
            routed_int_pkt.getlayer(IP, 1).ttl=63

            # upstream report packet
            exp_i2e_pkt = ipv4_dtel_pkt(
                eth_dst=mac_nbr[report_ports[0]],
                eth_src=mac_self,
                ip_src=report_src,
                ip_dst=report_dst[0],
                ip_id=0,
                ip_ttl=64,
                next_proto=DTEL_REPORT_NEXT_PROTO_ETHERNET,
                dropped=0,
                congested_queue=0,
                path_tracking_flow=1,
                inner_frame=int_pkt)

            exp_pkt = simple_udp_packet(
                eth_dst=mac_nbr[1],
                eth_src=mac_self,
                ip_dst=ipaddr_nbr[1],
                ip_src=ipaddr_nbr[0],
                with_udp_chksum=False,
                ip_id=108,
                ip_ttl=63,
                udp_sport=101,
                udp_payload=payload)

            exp_inte2e_inner_1 = postcard_report(
                packet=exp_pkt,
                switch_id=switch_id,
                ingress_port=swports[0],
                egress_port=swports[1],
                queue_id=0,
                queue_depth=0,
                egress_tstamp=0)

            exp_e2e_pkt = ipv4_dtel_pkt(
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
                inner_frame=exp_inte2e_inner_1)


            send_packet(self, swports[0], str(int_pkt))
            verify_packet(self, exp_pkt, swports[1])
            # verify i2e mirrored packet
            verify_int_l45_dtel_packet(
                self, exp_i2e_pkt, swports[report_ports[0]])
            # e2e mirror will have qdepth value. Ignore qdepth and compare.
            verify_int_lasthop_dtel_report_packet(
                self, exp_e2e_pkt, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "pass 1st packet w/ INT enabled"

            switch.dtel_int_endpoint_enable = False
            time.sleep(min_sleeptime)
            send_packet(self, swports[0], str(int_pkt))
            verify_packet(self, routed_int_pkt, swports[1])
            #verify_no_other_packets(self)
            print "pass 2nd packet w/ INT disabled"

            switch.dtel_int_endpoint_enable = True
            time.sleep(min_sleeptime)
            send_packet(self, swports[0], str(int_pkt))
            verify_packet(self, exp_pkt, swports[1])
            # verify i2e mirrored packet
            verify_int_l45_dtel_packet(
                self, exp_i2e_pkt, swports[report_ports[0]])
            # e2e mirror will have qdepth value. Ignore qdepth and compare.
            verify_int_lasthop_dtel_report_packet(
                self, exp_e2e_pkt, swports[report_ports[0]])
            #verify_no_other_packets(self)
            print "pass 3rd packet w/ INT enabled"

        finally:
            switch.cleanup(purge=True)

