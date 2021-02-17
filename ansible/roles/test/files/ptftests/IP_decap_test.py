'''
Description:    This file contains the decapasulation test for SONIC, to test decapsulation of IPv4 with double and
                triple encapsulated packets

                Design is available in https://github.com/Azure/SONiC/wiki/IPv4-Decapsulation-test

Precondition:   Before the test start, all routes need to be defined as in the fib_info.txt file, in addition to the
                decap rule that need to be set as the dspc_mode

topology:       Supports all the variations of t0 and t1 topologies.

Usage:          Examples of how to start the test
                ptf --test-dir /root/ptftest/ IP_decap_test.DecapPacketTest --platform-dir ptftests --platform remote \
                    --qlen=1000 -t "verbose=True;fib_info='/root/fib_info.txt';lo_ip='10.1.0.32';\
                    router_mac='00:02:03:04:05:00';dscp_mode='pipe';ttl_mode='pipe';testbed_type='t1';\
                    vlan_ip='192.168.0.1';src_ports='1,2,3,4,5,6'" --log-file /tmp/logs --verbose

Parameters:     fib_info - The fib_info file location
                lo_ip -  The loop_back IP that is configured in the decap rule
                lo_ipv6 -  The loop_back IP v6that is configured in the decap rule
                router_mac - The mac of the router_mac
                testbed_type - The type of testbed topology
                dscp_mode - The rule for the dscp parameter in the decap packet that is configured in the JSON file
                            ('pipe' for inner and 'uniform' for outer)
                ttl_mode - The rule for the ttl parameter in the decap packet that is configured in the JSON file
                           ('pipe' for inner and 'uniform' for outer)
                inner_ipv4 - Test IPv4 encap packets
                inner_ipv6 - Test IPv6 encap packets
                outer_ipv4 - Test packets encapsulated in IPv4
                outer_ipv6 - Test packets encapsulated in IPv6
                src_ports - The list of ports for injecting encapsulated packets. Separated by comma, for example:
                            "1,2,3,4,5,6"
                vlan_ip - IPv4 address of the vlan interface. Required for t0 testbed type.
                vlan_ipv6 - IPv6 address of the vlan interface. Optional.

'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import sys
import random
import time
import logging
import socket
import os
import unittest

import ipaddress
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.testutils import simple_ip_only_packet, simple_tcpv6_packet, simple_ipv4ip_packet, simple_ipv6ip_packet
from ptf.testutils import send_packet, verify_packet_any_port
from ptf.mask import Mask
from ptf.base_tests import BaseTest
from ptf import config

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

    # Allowed DSCP and TTL values
    DSCP_RANGE = list(range(0, 33))
    TTL_RANGE = list(range(2, 65))

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
        self.src_ports = [int(port) for port in self.test_params['src_ports'].split(',')]

        # which type of tunneled trafic to test (IPv4 in IPv4, IPv6 in IPv4, IPv6 in IPv4, IPv6 in IPv6)
        self.test_outer_ipv4 = self.test_params.get('outer_ipv4', True)
        self.test_outer_ipv6 = self.test_params.get('outer_ipv6', True)
        self.test_inner_ipv4 = self.test_params.get('inner_ipv4', True)
        self.test_inner_ipv6 = self.test_params.get('inner_ipv6', True)

        self.vlan_ip = self.test_params.get('vlan_ip')
        self.vlan_ipv6 = self.test_params.get('vlan_ipv6')

        # Index of current DSCP and TTL value in allowed DSCP_RANGE and TTL_RANGE
        self.dscp_in_idx = 0  # DSCP of inner layer.
        self.dscp_out_idx = len(self.DSCP_RANGE) / 2  # DSCP of outer layer. Set different initial dscp_in and dscp_out
        self.ttl_in_idx = 0  # TTL of inner layer.
        self.ttl_out_idx = len(self.TTL_RANGE) / 2  # TTL of outer layer. Set different initial ttl_in and ttl_out

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

    def create_ipv4_inner_pkt_only(self, src_ip, dst_ip, tos, encap=False, ttl=64):
        """Creates an IP only packet for the test
        @param src_ip: source ip
        @param dst_ip: destination ip
        @param tos: type of service field
        @param encap: build encapsulated packet.
                      If @encap is True the return packet would be:
                      IP(@src_ip, @dst_ip, @tos) / IP(dst_ip=4.4.4.4, src_ip=3.3.3.3) / TCP()
        @param ttl: ttl field
        """

        inner_pkt = simple_ip_only_packet(ip_dst=dst_ip, ip_src=src_ip, ip_ttl=ttl, ip_tos=tos)
        if encap:
            inner_pkt2 = self.create_ipv4_inner_pkt_only(self.DEFAULT_INNER2_V4_PKT_SRC_IP,
                                                         self.DEFAULT_INNER2_V4_PKT_DST_IP,
                                                         0)
            inner_pkt = simple_ipv4ip_packet(ip_src=src_ip,
                                             ip_dst=dst_ip,
                                             ip_tos=tos,
                                             ip_ttl=ttl,
                                             inner_frame=inner_pkt2).getlayer(scapy.IP) # get only the IP layer

        return inner_pkt

    #-----------------------------------------------------------------

    def create_ipv6_inner_pkt_only(self, src_ip, dst_ip, tc, encap=False, hlim=64):
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

        inner_pkt = simple_tcpv6_packet(ipv6_dst=dst_ip, ipv6_src=src_ip, ipv6_hlim=hlim, ipv6_tc=tc).getlayer(scapy.IPv6)
        if encap:
            inner_pkt2 = self.create_ipv6_inner_pkt_only(self.DEFAULT_INNER2_V6_PKT_SRC_IP,
                                                         self.DEFAULT_INNER2_V6_PKT_DST_IP,
                                                         0)
            inner_pkt = simple_ipv6ip_packet(ipv6_src=src_ip,
                                             ipv6_dst=dst_ip,
                                             ipv6_tc=tc,
                                             ipv6_hlim=hlim,
                                             inner_frame=inner_pkt2).getlayer(scapy.IPv6) # get only the IP layer

        return inner_pkt

    #-----------------------------------------------------------------

    def create_encap_packet(self, dst_ip, outer_pkt='ipv4', triple_encap=False, outer_ttl=None, inner_ttl=None):
        """Creates an IPv4/IPv6 encapsulated packet in @outer_pkt packet
        @param dst_ip: Destination IP for inner packet. Depending @dst_ip IPv4 or IPv6 packet will be created
        @param outer_pkt: Outer packet type to encapsulate inner packet in (ipv4/ipv6)
        @param triple_encap: Whether to build triple encapsulated packet
        @outer_ttl: TTL for the outer layer
        @inner_ttl: TTL for the inner layer
        @return: built packet and expected packet to match after decapsulation
        """

        src_mac =  self.dataplane.get_mac(0, 0)
        dst_mac = '00:11:22:33:44:55'
        router_mac = self.test_params['router_mac']

        # Set DSCP value for the inner layer
        dscp_in = self.DSCP_RANGE[self.dscp_in_idx]
        self.dscp_in_idx = (self.dscp_in_idx + 1) % len(self.DSCP_RANGE)  # Next packet will use a different DSCP

        # TC for IPv6, ToS for IPv4
        tc_in = tos_in = dscp_in << 2

        # Set DSCP value for the outer layer
        dscp_out = self.DSCP_RANGE[self.dscp_out_idx]
        self.dscp_out_idx = (self.dscp_out_idx + 1) % len(self.DSCP_RANGE)  # Next packet will use a different DSCP

        # TC for IPv6, ToS for IPv4
        tc_out = tos_out = dscp_out << 2

        if "pipe" == self.test_params['dscp_mode']:
            exp_tc = exp_tos = tc_in
        elif "uniform" == self.test_params['dscp_mode']:
            exp_tc = exp_tos = tc_out
        else:
            print("ERROR: no dscp is configured")
            exit()

        # Set TTL value for the outer layer
        if outer_ttl is None:
            outer_ttl = self.TTL_RANGE[self.ttl_out_idx]
            self.ttl_out_idx = (self.ttl_out_idx + 1) % len(self.TTL_RANGE)  # Next packet will use a different TTL

        # Set TTL value for the inner layer
        if inner_ttl is None:
            inner_ttl = self.TTL_RANGE[self.ttl_in_idx]
            self.ttl_in_idx = (self.ttl_in_idx + 1) % len(self.TTL_RANGE)  # Next packet will use a different TTL

        if "pipe" == self.test_params['ttl_mode']:
            exp_ttl = inner_ttl - 1
        elif "uniform" == self.test_params["ttl_mode"]:
            exp_ttl = outer_ttl - 1
        else:
            print("ERROR: unexpected ttl_mode is configured")
            exit()

        if ipaddress.ip_address(unicode(dst_ip)).version == 6:
            inner_src_ip = self.DEFAULT_INNER_V6_PKT_SRC_IP
            # build inner packet, if triple_encap is True inner_pkt would be double encapsulated
            inner_pkt = self.create_ipv6_inner_pkt_only(inner_src_ip, dst_ip, tos_in, triple_encap, hlim=inner_ttl)

            # build expected packet based on inner packet
            # set the correct L2 fields
            exp_pkt = scapy.Ether(dst=dst_mac, src=router_mac) / inner_pkt

            # set expected TC value
            exp_pkt['IPv6'].tc = exp_tc
            # decrement TTL
            exp_pkt['IPv6'].hlim = exp_ttl
        else:
            inner_src_ip = self.DEFAULT_INNER_V4_PKT_SRC_IP
            # build inner packet, if triple_encap is True inner_pkt would be double encapsulated
            inner_pkt = self.create_ipv4_inner_pkt_only(inner_src_ip, dst_ip, tos_in, triple_encap, ttl=inner_ttl)

            # build expected packet based on inner packet
            # set the correct L2 fields
            exp_pkt = scapy.Ether(dst=dst_mac, src=router_mac) / inner_pkt

            # set expected ToS value
            exp_pkt['IP'].tos = exp_tos
            # decrement TTL
            exp_pkt['IP'].ttl = exp_ttl

        if outer_pkt == 'ipv4':
            pkt = simple_ipv4ip_packet(
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                ip_src='1.1.1.1',
                                ip_dst=self.test_params['lo_ip'],
                                ip_tos=tos_out,
                                ip_ttl=outer_ttl,
                                inner_frame=inner_pkt)
        elif outer_pkt == 'ipv6':
            pkt = simple_ipv6ip_packet(
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                ipv6_src='1::1',
                                ipv6_dst=self.test_params['lo_ipv6'],
                                ipv6_tc=tc_out,
                                ipv6_hlim=outer_ttl,
                                inner_frame=inner_pkt)
        else:
            raise Exception("ERROR: invalid outer packet type ", outer_pkt)

        return pkt, exp_pkt

    #-----------------------------------------------------------------

    def send_and_verify(self, dst_ip, expected_ports, src_port, outer_pkt='ipv4', triple_encap=False,
                        outer_ttl=None, inner_ttl=None):
        '''
        @summary: This function builds encap packet, send and verify their arrival.
        @dst_ip: the destination ip for the inner IP header
        @expected_ports: list of ports that a packet can arrived from
        @src_port: the physical port that the packet will be sent from
        @triple_encap: True to send triple encapsulated packet
        @outer_ttl: TTL for the outer layer
        @inner_ttl: TTL for the inner layer
        '''

        pkt, exp_pkt = self.create_encap_packet(dst_ip, outer_pkt, triple_encap, outer_ttl, inner_ttl)
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

    def send_and_verify_all(self, dst_ip, expected_ports, src_port, outer_pkt_type):
        """
        @summary: This method builds different encap packets, send and verify their arrival
        @dest_ip: The destination ip for the inner IP header
        @expected_ports: List of ports that a packet can arrive from
        @src_port: The physical port that the packet will be sent from
        @outer_pkt_type: Indicates whether the outer packet is ipv4 or ipv6
        """

        self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type)
        self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, outer_ttl=64, inner_ttl=2)
        if self.test_params["ttl_mode"] == "pipe":
            self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, outer_ttl=1, inner_ttl=64)
        elif self.test_params["ttl_mode"] == "uniform":
            self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, outer_ttl=2, inner_ttl=64)

        self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, True)
        self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, True, outer_ttl=64, inner_ttl=2)
        if self.test_params["ttl_mode"] == "pipe":
            self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, True, outer_ttl=1, inner_ttl=64)
        elif self.test_params["ttl_mode"] == "uniform":
            self.send_and_verify(dst_ip, expected_ports, src_port, outer_pkt_type, True, outer_ttl=2, inner_ttl=64)

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

        ip_ranges_length = len(ip_ranges)
        if ip_ranges_length > 150:
            # This is to limit the test execution time. Because the IP ranges in the head and tail of the list are
            # kind of special. We need to always cover them. The IP ranges in the middle are not fundamentally
            # different. We can just sample some IP ranges in the middle. Using this method, test coverage is not
            # compromized. Test execution time can be reduced from over 5000 seconds to around 300 seconds.
            last_ten_index = ip_ranges_length - 10
            covered_ip_ranges = ip_ranges[:100] + \
                                random.sample(ip_ranges[100:last_ten_index], 40) + \
                                ip_ranges[last_ten_index:]
        else:
            covered_ip_ranges = ip_ranges[:]

        for ip_range in covered_ip_ranges:

            # Skip the IP range on VLAN interface, t0 topology
            if inner_pkt_type == 'ipv4' and self.vlan_ip and \
                ip_range.contains(ipaddress.ip_address(unicode(self.vlan_ip))):
                continue
            elif inner_pkt_type == 'ipv6' and self.vlan_ipv6 and \
                ip_range.contains(ipaddress.ip_address(unicode(self.vlan_ipv6))):
                continue

            # Get the expected list of ports that would receive the packets
            exp_port_list = self.fib[ip_range.get_first_ip()].get_next_hop_list()
            # Choose random one source port from all ports excluding the expected ones
            src_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

            if not len(exp_port_list):
                continue

            logging.info("Check " + outer_pkt_type.replace('ip', 'IP') + " tunneled traffic on IP range:" +
                         str(ip_range) + " on " + str(exp_port_list) + "...")
            # Send a packet with the first IP in the range
            self.send_and_verify_all(ip_range.get_first_ip(), exp_port_list, src_port, outer_pkt_type)

            # Send a packet with the last IP in the range
            if ip_range.length() > 1:
                self.send_and_verify_all(ip_range.get_last_ip(), exp_port_list, src_port, outer_pkt_type)

            # Send a packet with a random IP in the range
            if ip_range.length() > 2:
                self.send_and_verify_all(ip_range.get_random_ip(), exp_port_list, src_port, outer_pkt_type)

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

                encap_combination = "{}in{}".format(inner_pkt_type.replace('ip', 'IP'),
                                                    outer_pkt_type.replace('ip', 'IP'))

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
