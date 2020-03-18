'''
Description:    This file contains the hash test for SONiC
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import ipaddress
import logging
import random
import socket
import sys

from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *

import fib
import lpm

class HashTest(BaseTest):

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 1000

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
        '''
        self.dataplane = ptf.dataplane_instance
        self.fib = fib.Fib(self.test_params['fib_info'])
        self.router_mac = self.test_params['router_mac']

        self.src_ip_range = [unicode(x) for x in self.test_params['src_ip_range'].split(',')]
        self.dst_ip_range = [unicode(x) for x in self.test_params['dst_ip_range'].split(',')]
        self.test_hash_srcip = self.test_params.get('hash_srcip', True)
        self.test_hash_dstip = self.test_params.get('hash_dstip', True)
        self.test_hash_srcport = self.test_params.get('hash_srcport', True)
        self.test_hash_dstport = self.test_params.get('hash_dstport', True)
        self.test_hash_inport = self.test_params.get('hash_inport', False)
        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)

        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)

        # Provide the list of all UP interfaces with index in sequence order starting from 0
        if self.test_params['testbed_type'] == 't1' or self.test_params['testbed_type'] == 't1-lag':
            self.src_ports = range(0, 32)
        if self.test_params['testbed_type'] == 't1-64-lag' or self.test_params['testbed_type'] == 't1-64-lag-clet':
            self.src_ports = [0, 1, 4, 5, 16, 17, 20, 21, 34, 36, 37, 38, 39, 42, 44, 45, 46, 47, 50, 52, 53, 54, 55, 58, 60, 61, 62, 63]
        if self.test_params['testbed_type'] == 't0':
            self.src_ports = range(1, 25) + range(28, 32)
        if self.test_params['testbed_type'] == 't0-56':
            self.src_ports = [0, 1, 4, 5, 8, 9] + range(12, 18) + [20, 21, 24, 25, 28, 29, 32, 33, 36, 37] + range(40, 46) + [48, 49, 52, 53]
        if self.test_params['testbed_type'] == 't0-64':
            self.src_ports = range(0, 2) + range(4, 18) + range(20, 33) + range(36, 43) + range(48, 49) + range(52, 59)
        if self.test_params['testbed_type'] == 't0-116':
            self.src_ports = range(0, 120)
    #---------------------------------------------------------------------

    def check_hash(self, src_ip_range, dst_ip_range, ipv4=True):

        src_ip_interval = lpm.LpmDict.IpInterval(ip_address(src_ip_range[0]), ip_address(src_ip_range[1]))
        dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(dst_ip_range[0]), ip_address(dst_ip_range[1]))

        # hash field for regular packets:
        #   src_ip, dst_ip, protocol, l4_src_port, l4_dst_port (if applicable)

        # initialize all parameters
        src_ip = src_ip_interval.get_random_ip()
        dst_ip = dst_ip_interval.get_random_ip()
        src_port = random.randint(0, 65535)
        dst_port = random.randint(0, 65535)
        next_hop = self.fib[dst_ip]
        exp_port_list = self.fib[dst_ip].get_next_hop_list()
        logging.info("exp_port_list: {}".format(exp_port_list))
        if exp_port_list <= 1:
            logging.warning("{} has only {} nexthop".format(dst_ip, exp_port_list))
            assert False
        in_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

        ### check hash fields ###

        hit_count_map = {}
        # step 1: check randomizing source ip
        if self.test_hash_srcip:
            for i in range(0, self.BALANCING_TEST_TIMES):
                src_ip = src_ip_interval.get_random_ip()
                (matched_index, _) = self.check_ip_route(
                        in_port, src_port, dst_port, src_ip, dst_ip, exp_port_list, ipv4)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            self.check_balancing(next_hop.get_next_hop(), hit_count_map)

        # step 2: check randomizing destination ip
        if self.test_hash_dstip:
            hit_count_map.clear()
            for i in range(0, self.BALANCING_TEST_TIMES):
                dst_ip = dst_ip_interval.get_random_ip()
                (matched_index, _) = self.check_ip_route(
                        in_port, src_port, dst_port, src_ip, dst_ip, exp_port_list, ipv4)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            self.check_balancing(next_hop.get_next_hop(), hit_count_map)

        # step 3: check randomizing l3 source port
        if self.test_hash_srcport:
            hit_count_map.clear()
            for i in range(0, self.BALANCING_TEST_TIMES):
                src_port = random.randint(0, 65535)
                (matched_index, _) = self.check_ip_route(
                        in_port, src_port, dst_port, src_ip, dst_ip, exp_port_list, ipv4)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            self.check_balancing(next_hop.get_next_hop(), hit_count_map)

        # step 4: check randomizing l4 destination port
        if self.test_hash_dstport:
            hit_count_map.clear()
            for i in range(0, self.BALANCING_TEST_TIMES):
                dst_port = random.randint(0, 65535)
                (matched_index, _) = self.check_ip_route(
                        in_port, src_port, dst_port, src_ip, dst_ip, exp_port_list, ipv4)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            self.check_balancing(exp_port_list, hit_count_map)

        # step 5: check randomizing in port
        # TODO

    def check_ip_route(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list, ipv4=True):
        if ipv4:
            (matched_index, received) = self.check_ipv4_route(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list)
        else:
            (matched_index, received) = self.check_ipv6_route(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_ipv4_route(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list):
        '''
        @summary: Check IPv4 route works.
        @param in_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_src=self.router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, in_port, pkt)
        logging.info("Sending packet from port " + str(in_port) + " to " + ip_dst)

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
    #---------------------------------------------------------------------

    def check_ipv6_route(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list):
        '''
        @summary: Check IPv6 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcpv6_packet(
                                eth_dst=self.router_mac,
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_src=self.router_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

        send_packet(self, in_port, pkt)
        logging.info("Sending packet from port " + str(in_port) + " to " + ip_dst)

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
            self.check_hash(self.src_ip_range, self.dst_ip_range)
        if (self.test_ipv6):
            self.check_hash(self.src_ip_range, self.dst_ip_range, ipv4=False)
