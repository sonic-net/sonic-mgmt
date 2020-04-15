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
    BALANCING_TEST_TIMES = 10000

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
        self.in_ports = self.test_params['in_ports']

        self.src_ip_range = [unicode(x) for x in self.test_params['src_ip_range'].split(',')]
        self.dst_ip_range = [unicode(x) for x in self.test_params['dst_ip_range'].split(',')]
        self.src_ip_interval = lpm.LpmDict.IpInterval(ip_address(self.src_ip_range[0]), ip_address(self.src_ip_range[1]))
        self.dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(self.dst_ip_range[0]), ip_address(self.dst_ip_range[1]))
        self.hash_keys = self.test_params.get('hash_keys', ['src-ip', 'dst-ip', 'src-port', 'dst-port'])

        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)

    #---------------------------------------------------------------------

    def check_hash(self, hash_key):
        dst_ip = self.dst_ip_interval.get_random_ip()
        next_hop = self.fib[dst_ip]
        exp_port_list = self.fib[dst_ip].get_next_hop_list()
        logging.info("exp_port_list: {}".format(exp_port_list))
        if exp_port_list <= 1:
            logging.warning("{} has only {} nexthop".format(dst_ip, exp_port_list))
            assert False
        in_port = random.choice([port for port in self.in_ports if port not in exp_port_list])

        hit_count_map = {}
        if hash_key == 'ingress-port': # The sample is too little for hash_key ingress-port, check it loose(just verify if the asic actually used the hash field as a load-balancing factor)
            for in_port in [port for port in self.in_ports if port not in exp_port_list]:
                logging.info("in_port: {}".format(in_port))
                (matched_index, _) = self.check_ip_route(hash_key, in_port, dst_ip, exp_port_list)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            assert True if len(hit_count_map.keys()) > 1 else False
        else:
            for _ in range(0, self.BALANCING_TEST_TIMES):
                logging.info("in_port: {}".format(in_port))
                (matched_index, _) = self.check_ip_route(hash_key, in_port, dst_ip, exp_port_list)
                hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))

            self.check_balancing(next_hop.get_next_hop(), hit_count_map)

    def check_ip_route(self, hash_key, in_port, dst_ip, dst_port_list):
        if ip_network(unicode(dst_ip)).version == 4:
            (matched_index, received) = self.check_ipv4_route(hash_key, in_port, dst_port_list)
        else:
            (matched_index, received) = self.check_ipv6_route(hash_key, in_port, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_ipv4_route(self, hash_key, in_port, dst_port_list):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, 0)
        ip_src = self.src_ip_interval.get_random_ip() if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip() if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

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

    def check_ipv6_route(self, hash_key, in_port, dst_port_list):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        src_mac = self.dataplane.get_mac(0, 0)
        ip_src = self.src_ip_interval.get_random_ip() if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip() if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

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

        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)
