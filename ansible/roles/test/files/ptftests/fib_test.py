'''
Description:    This file contains the FIB test for SONIC

                Design is available in https://github.com/Azure/SONiC/wiki/FIB-Scale-Test-Plan

Usage:          Examples of how to use log analyzer
                ptf --test-dir fib fib_test.FibTest  --platform remote -t 'router_mac="00:02:03:04:05:00";route_info="fib/route_info.txt";testbed_type=t1'
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
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

import fib

class FibTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test routes advertised by BGP peers of SONIC are working properly.
    The setup of peers is described in 'VM set' section in
    https://github.com/Azure/sonic-mgmt/blob/master/ansible/README.testbed.md

    Routes advertized by the peers have ECMP groups. The purpose of the test is to make sure
    that packets are forwarded through one of the ports specified in route's ECMP group.

    This class receives a text file describing the bgp routes added to the switch.
    File contains informaiton about each bgp route which was added to the switch.

    #-----------------------------------------------------------------------

    The file is loaded on startup and is used to
        - construct packet with correct destination IP
        - validate that packet arrived from switch from a port which
        is member of ECMP group for given route.

    For each route test
        - builds a packet with destination IP matching to the IP in the route
        - sends packet to the switch
        - verifies that packet came back from the switch on one of
        the ports specified in the ECMP group of the route.

    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 10000
    DEFAULT_BALANCING_TEST_RATIO = 0.0001

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------

    def setUp(self):
        '''
        @summary: Setup for the test
        Two test parameters are used:
         - fib_info: the FIB information generated according to the testbed
         - router_mac: the MAC address of the DUT used to create the eth_dst
           of the packet
         - testbed_type: the type of the testbed used to determine the source
           port
         - src_port: this list should include all enabled ports, both up links
                     and down links.
        TODO: Have a separate line in fib_info/file to indicate all UP ports
        '''
        self.dataplane = ptf.dataplane_instance
        self.fib = fib.Fib(self.test_params['fib_info'])
        self.router_mac = self.test_params['router_mac']
        self.pktlen = self.test_params['testbed_mtu']

        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)

        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_ratio = self.test_params.get('balancing_test_ratio', self.DEFAULT_BALANCING_TEST_RATIO)

        # Provide the list of all UP interfaces with index in sequence order starting from 0
        if self.test_params['testbed_type'] == 't1' or self.test_params['testbed_type'] == 't1-lag':
            self.src_ports = range(0, 32)
        if self.test_params['testbed_type'] == 't1-64-lag':
            self.src_ports = [0, 1, 4, 5, 16, 17, 20, 21, 34, 36, 37, 38, 39, 42, 44, 45, 46, 47, 50, 52, 53, 54, 55, 58, 60, 61, 62, 63]
        if self.test_params['testbed_type'] == 't0':
            self.src_ports = range(1, 25) + range(28, 32)
        if self.test_params['testbed_type'] == 't0-52':
            self.src_ports = range(0, 52)
        if self.test_params['testbed_type'] == 't0-56':
            self.src_ports = [0, 1, 4, 5, 8, 9] + range(12, 18) + [20, 21, 24, 25, 28, 29, 32, 33, 36, 37] + range(40, 46) + [48, 49, 52, 53]
        if self.test_params['testbed_type'] == 't0-64':
            self.src_ports = range(0, 2) + range(4, 18) + range(20, 33) + range(36, 43) + range(48, 49) + range(52, 59)
        if self.test_params['testbed_type'] == 't0-116':
            self.src_ports = range(0, 120)
    #---------------------------------------------------------------------

    def check_ip_range(self, ipv4=True):
        if ipv4:
            ip_ranges = self.fib.ipv4_ranges()
        else:
            ip_ranges = self.fib.ipv6_ranges()

        for ip_range in ip_ranges:

            # Get the expected list of ports that would receive the packets
            exp_port_list = self.fib[ip_range.get_first_ip()].get_next_hop_list()
            # Choose random one source port from all ports excluding the expected ones
            src_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

            if not exp_port_list:
                continue

            logging.info("Check IP range:" + str(ip_range) + " on " + str(exp_port_list) + "...")

            # Send a packet with the first IP in the range
            self.check_ip_route(src_port, ip_range.get_first_ip(), exp_port_list, ipv4)
            # Send a packet with the last IP in the range
            if ip_range.length() > 1:
                self.check_ip_route(src_port, ip_range.get_last_ip(), exp_port_list, ipv4)
            # Send a packet with a random IP in the range
            if ip_range.length() > 2:
                self.check_ip_route(src_port, ip_range.get_random_ip(), exp_port_list, ipv4)

            # Test traffic balancing across ECMP/LAG members
            if len(exp_port_list) > 1 and random.random() < self.balancing_test_ratio:
                logging.info("Check IP range balancing...")
                dst_ip = ip_range.get_random_ip()
                hit_count_map = {}
                for i in range(0, self.BALANCING_TEST_TIMES):
                    (matched_index, received) = self.check_ip_route(src_port, dst_ip, exp_port_list, ipv4)
                    hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
                self.check_balancing(self.fib[dst_ip].get_next_hop(), hit_count_map)

    def check_ip_route(self, src_port, dst_ip_addr, dst_port_list, ipv4=True):
        if ipv4:
            (matched_index, received) = self.check_ipv4_route(src_port, dst_ip_addr, dst_port_list)
        else:
            (matched_index, received) = self.check_ipv6_route(src_port, dst_ip_addr, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_ipv4_route(self, src_port, dst_ip_addr, dst_port_list):
        '''
        @summary: Check IPv4 route works.
        @param src_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = "10.0.0.1"
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcp_packet(
                            pktlen=self.pktlen,
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            self.pktlen,
                            eth_src=self.router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
    #---------------------------------------------------------------------

    def check_ipv6_route(self, src_port, dst_ip_addr, dst_port_list):
        '''
        @summary: Check IPv6 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = '2000::1'
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcpv6_packet(
                                pktlen=self.pktlen,
                                eth_dst=self.router_mac,
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                pktlen=self.pktlen,
                                eth_src=self.router_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
    #---------------------------------------------------------------------
    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)

    #---------------------------------------------------------------------
    def check_balancing(self, dest_port_list, port_hit_cnt):
        '''
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @return bool
        '''

        logging.info("%-10s \t %-10s \t %10s \t %10s \t %10s" % ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
        result = True

        total_hit_cnt = sum(port_hit_cnt.values())
        for ecmp_entry in dest_port_list:
            total_entry_hit_cnt = 0
            for member in ecmp_entry:
                total_entry_hit_cnt += port_hit_cnt.get(member, 0)
            (p, r) = self.check_within_expected_range(total_entry_hit_cnt, float(total_hit_cnt)/len(dest_port_list))
            logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                         % ("ECMP", str(ecmp_entry), total_hit_cnt/len(dest_port_list), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
            result &= r
            if len(ecmp_entry) == 1 or total_entry_hit_cnt == 0:
                continue
            for member in ecmp_entry:
                (p, r) = self.check_within_expected_range(port_hit_cnt.get(member, 0), float(total_entry_hit_cnt)/len(ecmp_entry))
                logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                              % ("LAG", str(member), total_entry_hit_cnt/len(ecmp_entry), port_hit_cnt.get(member, 0), str(round(p, 4)*100) + '%'))
                result &= r

        assert result

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        # IPv4 Test
        if (self.test_ipv4):
            self.check_ip_range()
        # IPv6 Test
        if (self.test_ipv6):
            self.check_ip_range(ipv4=False)
