#-----------------------------------
# A set of traffic-tests for checking LAGs functionality.
#-----------------------------------

import random
import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane

from ptf.testutils import *
from ptf.mask import Mask
import ipaddress

import os
import logging
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from router_utils import *
import pprint
from scapy.all import rdpcap

class LagMembersTrafficTest(BaseTest,RouterUtility):
    '''
    @ summary: run traffic from <src_iface> to <dst_addr>. All packets should arrive to <check_pkts_iface>.

    @ param: dst_addr   -   destination address of the traffic (usually LAG interface IP)
    @ param: src_iface  -   interface, where traffic is sent from
    @ param: check_pkts_iface   -   where packets should arrive (because usually one of LAG members is being DOWN in test purposes).
    @ param: num_of_pkts        -   amount of traffic to send
    @ param: dut_mac        -   DUT MAC address
    '''
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance

    def runTest(self):
        self.dst_addr = self.test_params['dst_addr']
        self.src_iface = int(self.test_params['src_iface'])
        self.check_pkts_iface = int(self.test_params['check_pkts_iface'])
        self.num_of_pkts = int(self.test_params['num_of_pkts'])
        self.dut_mac = self.test_params['dut_mac']

        slash_index = self.dst_addr.find("/")
        if slash_index != -1:
            self.dst_addr = self.dst_addr[:slash_index]

        # Generate packet (use DUT MAC address as next-hop-mac).
        pkt = simple_icmp_packet(eth_dst=self.dut_mac,
                                 ip_dst=self.dst_addr)

        # Generate expected packet (ignore MAC addresses).
        exp_pkt = simple_icmp_packet(ip_ttl=63,
                                     ip_dst=self.dst_addr)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        # Send packets and verify it on dst port.
        i = 0
        while i < int(self.num_of_pkts):
            send_packet(self, self.src_iface, pkt)
            verify_packet(self, masked_exp_pkt, self.check_pkts_iface)
            i += 1

class LacpTimingTest(BaseTest,RouterUtility):
    '''
    @ summary: Verify LACP packets arrive with proper packet timing.

    @ param: exp_iface      -   where to expect LACP packets.
    @ param: timeout        -   time to expect the LACP packet.
    @ param: packet_timing         -   time between two packets.
    @ param: ether_type     -   Ethernet type of expected packet.
    @ param: interval_count -   Number of intervals to collect.
    '''

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance

    def getMedianInterval(self, masked_exp_pkt):
        intervals = []
        # Verify two LACP packets.
        (rcv_device, rcv_port, rcv_pkt, last_pkt_time) = self.dataplane.poll(port_number=self.exp_iface, timeout=self.timeout, exp_pkt=masked_exp_pkt)
        last_pkt_time = round(float(last_pkt_time), 2)

        for i in range(0, self.interval_count):
            (rcv_device, rcv_port, rcv_pkt, curr_pkt_time) = self.dataplane.poll(port_number=self.exp_iface, timeout=self.timeout, exp_pkt=masked_exp_pkt)

            # Check the packet received.
            self.assertTrue(rcv_pkt != None, "Failed to receive LACP packet\n")

            # Get current packet timing
            curr_pkt_time = round(float(curr_pkt_time), 2)

            interval   = curr_pkt_time - last_pkt_time
            intervals += [ interval ]

            last_pkt_time = curr_pkt_time

        # Get the median
        intervals.sort()
        current_pkt_timing = intervals[self.interval_count / 2]
        return current_pkt_timing


    def runTest(self):

        # Get test parameters
        self.exp_iface = self.test_params['exp_iface']
        self.timeout = self.test_params['timeout']
        self.packet_timing = self.test_params['packet_timing']
        self.ether_type = self.test_params['ether_type']
        self.interval_count = int(self.test_params['interval_count'])
        if self.interval_count < 1:
            self.interval_count = 3

        # Make sure the interval count is odd, so that we only look at one median interval
        if self.interval_count % 2 == 0:
            self.interval_count += 1

        # Generate a packet.
        exp_pkt = simple_eth_packet(eth_type=self.ether_type)
        exp_pkt = exp_pkt/("0" * 64)

        # Ignore fields with value unknown
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"src")
        masked_exp_pkt.set_do_not_care(14 * 8, 110 * 8)

        # Flush packets in dataplane
        self.dataplane.flush()

        # Check that packet timing matches the expected value.
        current_pkt_timing = self.getMedianInterval(masked_exp_pkt)
        self.assertTrue(abs(current_pkt_timing - float(self.packet_timing)) < 0.1, "Bad packet timing: %.2f seconds while expected timing is %d seconds from port %s out of %d intervals" % (current_pkt_timing, self.packet_timing, self.exp_iface, self.interval_count))
