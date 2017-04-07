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
    EXPECTED_RANGE = 0.25 # TODO: need to get the percentage from param

    '''
    Information about routes to test.
    '''
    source_port_list = [] # a list of source port indices
    dest_port_list = []  # a list of lists describing ecmp/lag relationships
    route_list = [] # a list of route to be tested
    hit_dict = {}   # a dict of hit count recording the number of hits per port

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
        self.testbed = self.test_params['testbed_type']
        self.router_mac = self.test_params['router_mac']
        self.load_route_info(self.test_params["route_info"])

        if self.testbed == 't0':
            self.source_port_list = range(1,25) + range(28,32)
            self.dest_port_list = [[i] for i in range(28,32)]
        elif self.testbed == 't1':
            self.source_port_list = range(0,32)
            self.dest_port_list = [[i] for i in range(0,16)]
        elif self.testbed == 't1-lag':
            self.source_port_list = range(0,32)
            self.dest_port_list = [[i, i+1] for i in range(0,16,2)]
    #---------------------------------------------------------------------

    def load_route_info(self, route_info_path):
        '''
        @summary: Load route_info file
        @param route_info_path : Path to the file
        '''
        with open(route_info_path, 'r') as route_info_file:
            content = route_info_file.readlines()
            for line in content:
                self.route_list.append(line.strip())
        return
    #---------------------------------------------------------------------

    def verify_packet_any_port(self, pkt, ports=[], device_number=0):
        """
        @summary: Check that the packet is received on _any_ of the specified ports belonging to
        the given device (default device_number is 0).

        The function returns when either the expected packet is received or timeout (1 second).

        Also verifies that the packet is or received on any other ports for this
        device, and that no other packets are received on the device (unless --relax
        is in effect).
        @param pkt : packet to verify
        @param ports : list of ports

        @return: index of the port on which the packet is received and the packet.
        """
        received = False
        match_index = -1
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
         self,
         device_number=device_number,
         exp_pkt=pkt,
         timeout=1
        )

        if rcv_port in ports:
            match_index = ports.index(rcv_port)
            received = True

        return (match_index, received)
    #---------------------------------------------------------------------

    def is_ipv4_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv4 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        try:
            # building ipaddress fails for some of addresses unless unicode(ipaddr) is specified for both ipv4/ipv6
            # Example - 192.168.156.129, it is valid IPV4 address, send_packet works with it.
            ipaddress.IPv4Address(unicode(ipaddr))
            return True
        except Exception, e:
            return False
    #---------------------------------------------------------------------

    def is_ipv6_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv6 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        try:
            ipaddress.IPv6Address(unicode(ipaddr))
            return True
        except Exception, e:
            return False
    #---------------------------------------------------------------------

    def check_ipv4_route(self, source_port_index, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv4 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = "10.0.0.1"
        ip_dst = dest_ip_addr

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
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

        send_packet(self, source_port_index, pkt)

        (received_port_index, received) = self.verify_packet_any_port(masked_exp_pkt,destination_port_list)

        if not received:
            logging.error("Packet sent from %d to %s...Failed" % (source_port_index, dest_ip_addr))
            assert(False) # Fail the test immediately
        else:
            logging.debug("Packet sent from %d to %s...OK received at %d" %
                          (source_port_index, dest_ip_addr, received_port_index))

        return (received_port_index, received)
    #---------------------------------------------------------------------

    def check_ipv6_route(self, source_port_index, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv6 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = '2000::1'
        ip_dst = dest_ip_addr

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

        send_packet(self, source_port_index, pkt)

        return self.verify_packet_any_port(masked_exp_pkt,destination_port_list)
    #---------------------------------------------------------------------
    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        '''
        print "%10s" % str(round(percentage, 4)*100) + '%'
        '''
        return (percentage, abs(percentage) <= self.EXPECTED_RANGE)

    #---------------------------------------------------------------------
    def check_balancing(self, dest_port_list, port_hit_cnt):
        '''
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @return bool
        '''

        logging.info("%-10s \t %10s \t %10s \t %10s" % ("port(s)", "exp_cnt", "act_cnt", "diff(%)"))
        result = True

        total_hit_cnt = float(sum(port_hit_cnt.values()))
        for ecmp_entry in dest_port_list:
            total_entry_hit_cnt = 0.0
            for member in ecmp_entry:
                total_entry_hit_cnt += port_hit_cnt[member]
            (p, r) = self.check_within_expected_range(total_entry_hit_cnt, total_hit_cnt/len(dest_port_list))
            logging.info("%-10s \t %10d \t %10d \t %10s"
                         % (str(ecmp_entry), total_hit_cnt/len(dest_port_list), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
            result &= r
            if len(ecmp_entry) == 1:
                continue
            for member in ecmp_entry:
                (p, r) = self.check_within_expected_range(port_hit_cnt[member], total_entry_hit_cnt/len(ecmp_entry))
                logging.info("%-10s \t %10d \t %10d \t %10s"
                              % (str(member), total_entry_hit_cnt/len(ecmp_entry), port_hit_cnt[member], str(round(p, 4)*100) + '%'))
                result &= r

        return result

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send packet for each route and validate it arrives
        on one of expected ECMP ports
        """
        exp_port_list = []
        for ecmp_entry in self.dest_port_list:
            for port in ecmp_entry:
                exp_port_list.append(port)

        ip4_route_cnt = 0
        ip6_route_cnt = 0
        ip4_hit_cnt = 0
        ip6_hit_cnt = 0
        port_cnt_dict = {}

        for i in self.source_port_list:
            port_cnt_dict[i] = 0

        for dest_ip in self.route_list:
            for src_port in self.source_port_list:
                if self.is_ipv4_address(dest_ip):
                    ip4_route_cnt += 1
                    (matched_index, received) = self.check_ipv4_route(src_port, dest_ip, exp_port_list)
                    if received:
                        ip4_hit_cnt += 1
                        port_cnt_dict[exp_port_list[matched_index]] = port_cnt_dict.setdefault(exp_port_list[matched_index], 0) + 1
                elif self.is_ipv6_address(dest_ip):
                    continue
                    ip6_route_cnt += 1
                    (matched_index, received) = self.check_ipv6_route(src_port, dest_ip, exp_port_list)
                    if received:
                        ip6_hit_cnt += 1
                        port_cnt_dict[exp_port_list[matched_index]] = port_cnt_dict.setdefault(exp_port_list[matched_index], 0) + 1
                else:
                    print 'Invalid IP  address:%s' % dest_ip_addr
                    assert(False)

        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        ch.terminator = ""
        logging.getLogger().addHandler(ch)

        # Check if sent/received counts are matched
        logging.info("\n")
        logging.info("--------------------------- TEST RESULT ------------------------------")
        logging.info("Sent %d IPv4 packets; recieved %d IPv4 packets" % (ip4_route_cnt, ip4_hit_cnt))
        logging.info("Sent %d IPv6 packets; recieved %d IPv6 packets" % (ip6_route_cnt, ip6_hit_cnt))
        logging.info("----------------------------------------------------------------------")
        balancing_result = self.check_balancing(self.dest_port_list, port_cnt_dict)
        assert (ip4_route_cnt == ip4_hit_cnt) and (ip6_route_cnt == ip6_hit_cnt) and balancing_result
    #---------------------------------------------------------------------
