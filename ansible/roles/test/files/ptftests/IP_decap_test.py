'''
Description:    This file contains the Decapasulation test for SONIC, to test Decapsulation of IPv4 with double and triple encapsulated packets                
                      
                Design is available in https://github.com/Azure/SONiC/wiki/IPv4-Decapsulation-test
                
Precondition:   Before the test start, all routes need to be defined as in the fib_info.txt file, in addition to the decap rule that need to be set as the dspc_mode
topology:       SUpports t1, t1-lag, t0-116 and t0 topology
                      
Usage:          Examples of how to start the test 
                ptf  --test-dir /root/dor/ ip_decap_test_red --platform remote -t "verbose=True;fib_info='/root/fib_info.txt';lo_ip='10.1.0.32';router_mac='00:02:03:04:05:00';dscp_mode='pipe'; testbed_type='t1'"  --log-dir /tmp/logs --verbose 
Parameters:     fib_info - The fib_info file location 
                lo_ip -  The loop_back IP that is configured in the decap rule
                lo_ipv6 -  The loop_back IP v6that is configured in the decap rule
                router_mac - The mac of the router_mac
                testbed_type - The type of testbed topology
                dscp_mode - The rule for the dscp parameter in the decap packet that is configured in the JSON file ('pipe' for inner and 'uniform' for outer)
                inner_ipv4 - Test IPv4 encap packets
                inner_ipv6 - Test IPv6 encap packets
                outer_ipv4 - Test packets encapsulated in IPv4
                outer_ipv6 - Test packets encapsulated in IPv6
                
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import sys
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
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils

import pprint


import fib

class DecapPacketTest(BaseTest):
    """ IP in IP decapsulation test """

    # Default source IP to use for inner packet
    DEFAULT_INNER_V4_PKT_SRC_IP = '1.1.1.1'
    DEFAULT_INNER_V6_PKT_SRC_IP = '1::1'

    # Default source and destination IPs to use
    # for triple encapsulated packets
    DEFAULT_INNER2_V4_PKT_SRC_IP = '4.4.4.4'
    DEFAULT_INNER2_V6_PKT_SRC_IP = '4::4'
    DEFAULT_INNER2_V4_PKT_DST_IP = '3.3.3.3'
    DEFAULT_INNER2_V6_PKT_DST_IP = '3::3'

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
        #-----------------------------------------------------------------
    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.fib = fib.Fib(self.test_params['fib_info'])
        if self.test_params['testbed_type'] == 't1' or self.test_params['testbed_type'] == 't1-lag':
            self.src_ports = range(0, 32)
        if self.test_params['testbed_type'] == 't1-64-lag':
            self.src_ports = [0, 1, 4, 5, 16, 17, 20, 21, 34, 36, 37, 38, 39, 42, 44, 45, 46, 47, 50, 52, 53, 54, 55, 58, 60, 61, 62, 63]
        if self.test_params['testbed_type'] == 't0':
            self.src_ports = range(1, 25) + range(28, 32)
        if self.test_params['testbed_type'] == 't0-64':
            self.src_ports = [0,  1,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 36, 37, 38, 39, 40, 41, 42, 48, 52, 53, 54, 55, 56, 57, 58]
        if self.test_params['testbed_type'] == 't0-116':
            self.src_ports = range(0, 24) + range(32, 120)

        # which type of tunneled trafic to test (IPv4 in IPv4, IPv6 in IPv4, IPv6 in IPv4, IPv6 in IPv6)
        self.test_outer_ipv4 = self.test_params.get('outer_ipv4', True)
        self.test_outer_ipv6 = self.test_params.get('outer_ipv6', True)
        self.test_inner_ipv4 = self.test_params.get('inner_ipv4', True)
        self.test_inner_ipv6 = self.test_params.get('inner_ipv6', True)

        self.summary = {}

    #-----------------------------------------------------------------

    def print_summary(self):
        """
        Print summary
        """

        print '\nSummary:'
        print '\n'.join(['{}: {}'.format(encap_comb, status)
            for encap_comb, status in self.summary.items()])

        sys.stdout.flush()

    def create_ipv4_inner_pkt_only(self, src_ip, dst_ip, tos, encap=False):
        """Creates an IP only packet for the test
        @param src_ip: source ip
        @param dst_ip: destination ip
        @param tos: type of service field
        @param encap: build encapsulated packet.
                      If @encap is True the return packet would be:
                      IP(@src_ip, @dst_ip, @tos) / IP(dst_ip=4.4.4.4, src_ip=3.3.3.3) / TCP()
        """

        inner_pkt = simple_ip_only_packet(ip_dst=dst_ip, ip_src=src_ip, ip_ttl=64, ip_tos=tos)
        if encap:
            inner_pkt2 = self.create_ipv4_inner_pkt_only(self.DEFAULT_INNER2_V4_PKT_SRC_IP,
                                                         self.DEFAULT_INNER2_V4_PKT_DST_IP,
                                                         0)
            inner_pkt = simple_ipv4ip_packet(ip_src=src_ip,
                                             ip_dst=dst_ip,
                                             ip_tos=tos,
                                             ip_ttl=64,
                                             inner_frame=inner_pkt2).getlayer(scapy.IP) # get only the IP layer

        return inner_pkt

    #-----------------------------------------------------------------

    def create_ipv6_inner_pkt_only(self, src_ip, dst_ip, tc, encap=False):
        """Creates an IPv6 only packet for the test
        @param src_ip: source ip
        @param dst_ip: destination ip
        @param tc: traffic class
        @param encap: build encapsulated packet.
                      If @encap is True the return packet would be:
                      IP(@src_ip, @dst_ip, @tc) / IP(dst_ip=4::4, src_ip=3::3) / TCP()
        """

        # no ptf function to build simple ipv6 only packet
        # so use simple_tcpv6_packet function which builds the same packet
        # with TCP header as simple_ip_only_packet but extract away Ethernet
        inner_pkt = simple_tcpv6_packet(ipv6_dst=dst_ip, ipv6_src=src_ip, ipv6_hlim=64, ipv6_tc=tc).getlayer(scapy.IPv6)
        if encap:
            inner_pkt2 = self.create_ipv6_inner_pkt_only(self.DEFAULT_INNER2_V6_PKT_SRC_IP,
                                                         self.DEFAULT_INNER2_V6_PKT_DST_IP,
                                                         0)
            inner_pkt = simple_ipv6ip_packet(ipv6_src=src_ip,
                                             ipv6_dst=dst_ip,
                                             ipv6_tc=tc,
                                             ipv6_hlim=64,
                                             inner_frame=inner_pkt2).getlayer(scapy.IPv6) # get only the IP layer

        return inner_pkt

    #-----------------------------------------------------------------

    def create_encap_packet(self, dst_ip, outer_pkt='ipv4', triple_encap=False):
        """Creates an IPv4/IPv6 encapsulated packet in @outer_pkt packet
        @param dst_ip: Destination IP for inner packet. Depending @dst_ip IPv4 or IPv6 packet will be created
        @param outer_pkt: Outer packet type to encapsulate inner packet in (ipv4/ipv6)
        @param triple_encap: Whether to build triple encapsulated packet
        @return: built packet and expected packet to match after decapsulation"""

        src_mac =  self.dataplane.get_mac(0, 0)
        dst_mac = '00:11:22:33:44:55'
        router_mac = self.test_params['router_mac']
        dscp_in = random.randint(0, 32)
        # TC for IPv6, ToS for IPv4
        tc_in = tos_in = dscp_in << 2
        dscp_out = random.randint(0, 32)
        tc_out = tos_out = dscp_out << 2
        if ("pipe" == self.test_params['dscp_mode']):
            exp_tc = exp_tos = tc_in
        elif("uniform" == self.test_params['dscp_mode']):
            exp_tc = exp_tos = tc_out
        else:
            print("ERROR: no dscp is configured")
            exit()

        if ipaddress.ip_address(unicode(dst_ip)).version == 6:
            inner_src_ip = self.DEFAULT_INNER_V6_PKT_SRC_IP
            # build inner packet, if triple_encap is True inner_pkt would be double encapsulated
            inner_pkt = self.create_ipv6_inner_pkt_only(inner_src_ip, dst_ip, tos_in, triple_encap)

            # build expected packet based on inner packet
            # set the correct L2 fields
            exp_pkt = scapy.Ether(dst=dst_mac, src=router_mac) / inner_pkt

            # set expected TC value
            exp_pkt['IPv6'].tc = exp_tc
            # decrement TTL
            exp_pkt['IPv6'].hlim -= 1
        else:
            inner_src_ip = self.DEFAULT_INNER_V4_PKT_SRC_IP
            # build inner packet, if triple_encap is True inner_pkt would be double encapsulated
            inner_pkt = self.create_ipv4_inner_pkt_only(inner_src_ip, dst_ip, tos_in, triple_encap)

            # build expected packet based on inner packet
            # set the correct L2 fields
            exp_pkt = scapy.Ether(dst=dst_mac, src=router_mac) / inner_pkt

            # set expected ToS value
            exp_pkt['IP'].tos = exp_tos
            # decrement TTL
            exp_pkt['IP'].ttl -= 1


        if outer_pkt == 'ipv4':
            pkt = simple_ipv4ip_packet(
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                ip_src='1.1.1.1',
                                ip_dst=self.test_params['lo_ip'],
                                ip_tos=tos_out,
                                ip_ttl=random.randint(2, 63),
                                inner_frame=inner_pkt)
        elif outer_pkt == 'ipv6':
            pkt = simple_ipv6ip_packet(
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                ipv6_src='1::1',
                                ipv6_dst=self.test_params['lo_ipv6'],
                                ipv6_tc=tc_out,
                                ipv6_hlim=random.randint(2, 63),
                                inner_frame=inner_pkt)
        else:
            raise Exception("ERROR: invalid outer packet type ", outer_pkt)


        return pkt, exp_pkt

    #-----------------------------------------------------------------

    def send_and_verify(self, dst_ip, expected_ports, src_port, outer_pkt='ipv4', triple_encap=False):
        '''
        @summary: This function builds encap packet, send and verify their arrival.
        @dst_ip: the destination ip for the inner IP header
        @expected_ports: list of ports that a packet can arrived from
        @src_port: the physical port that the packet will be sent from
        @triple_encap: True to send triple encapsulated packet
        '''

        pkt, exp_pkt = self.create_encap_packet(dst_ip, outer_pkt, triple_encap)
        
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        #send and verify the return packets
        send_packet(self, src_port, pkt)
        logging.info(".....Sending packet from port" + str(src_port) + " to " +
                     dst_ip + ", Triple_encap: " + str(triple_encap))
        matched, received = verify_packet_any_port(self, masked_exp_pkt, expected_ports)
        assert received
        return matched, received

    #-----------------------------------------------------------------

    def run_encap_combination_test(self, outer_pkt_type, inner_pkt_type):
        """
        @summary: Send double and triple encapsulated packets for each IP range and
        expect the packet to be received from one of the expected ports
        """

        if inner_pkt_type == 'ipv4':
            ip_ranges = self.fib.ipv4_ranges()
        elif inner_pkt_type == 'ipv6':
            ip_ranges = self.fib.ipv6_ranges()
        else:
            raise Exception('ERROR: Invalid inner packet type passed: ', inner_pkt_type)

        for ip_range in ip_ranges:
            # Get the expected list of ports that would receive the packets
            exp_port_list = self.fib[ip_range.get_first_ip()].get_next_hop_list()
            # Choose random one source port from all ports excluding the expected ones
            src_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

            if not len(exp_port_list):
                continue

            logging.info("Check " + outer_pkt_type.replace('ip', 'IP') + " tunneled traffic on IP range:" +
                         str(ip_range) + " on " + str(exp_port_list) + "...")
            # Send a packet with the first IP in the range
            self.send_and_verify(ip_range.get_first_ip(), exp_port_list, src_port, outer_pkt_type)
            self.send_and_verify(ip_range.get_first_ip(), exp_port_list, src_port, outer_pkt_type, True)
            # Send a packet with the last IP in the range
            if ip_range.length() > 1:
                self.send_and_verify(ip_range.get_last_ip(), exp_port_list, src_port, outer_pkt_type)
                self.send_and_verify(ip_range.get_last_ip(), exp_port_list, src_port, outer_pkt_type, True)
            # Send a packet with a random IP in the range
            if ip_range.length() > 2:
                self.send_and_verify(ip_range.get_random_ip(), exp_port_list, src_port, outer_pkt_type)
                self.send_and_verify(ip_range.get_random_ip(), exp_port_list, src_port, outer_pkt_type, True)

    def runTest(self):
        """
        @summary: run test cases
        """

        inner_pkt_types = []
        if self.test_inner_ipv4:
            inner_pkt_types.append('ipv4')
        if self.test_inner_ipv6:
            inner_pkt_types.append('ipv6')

        outer_pkt_types = []
        if self.test_outer_ipv4:
            outer_pkt_types.append('ipv4')
        if self.test_outer_ipv6:
            outer_pkt_types.append('ipv6')

        for outer_pkt_type in outer_pkt_types:
            for inner_pkt_type in inner_pkt_types:

                encap_combination = "{}in{}".format(outer_pkt_type.replace('ip', 'IP'),
                                                    inner_pkt_type.replace('ip', 'IP'))

                logging.info('----------------------------------------------------------------------')
                logging.info("{} test started".format(encap_combination))
                logging.info('----------------------------------------------------------------------')

                status = 'Failed'
                error = None

                try:
                    self.run_encap_combination_test(outer_pkt_type, inner_pkt_type)
                except AssertionError, e:
                    error = e
                    # print error, but continue to test others encap traffic combinations
                    print "\n{}:\n{}".format(encap_combination, error)
                    sys.stdout.flush()
                else:
                    status = 'Passed'

                self.summary[encap_combination] = status

                logging.info('----------------------------------------------------------------------')
                logging.info("{} test finished, status: {}".format(encap_combination, status))
                logging.info('----------------------------------------------------------------------')

        self.print_summary()

        total = len(outer_pkt_types)*len(inner_pkt_types)
        passed = len(filter(lambda status: status == 'Passed', self.summary.values()))

        # assert all passed
        assert total == passed, "total tests {}, passed: {}".format(total, passed)

#---------------------------------------------------------------------

