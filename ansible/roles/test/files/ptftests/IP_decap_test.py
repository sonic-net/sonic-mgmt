'''
Description:    This file contains the decapasulation test for SONIC, to test decapsulation of IPv4 with double and
                triple encapsulated packets

                Design is available in https://github.com/Azure/SONiC/wiki/IPv4-Decapsulation-test

Precondition:   Before the test start, all routes need to be defined as in the fib_info.txt file, in addition to the
                decap rule that need to be set as the dspc_mode

topology:       Supports all the variations of t0 and t1 topologies.

Usage:          Examples of how to start the test
                ptf --test-dir /root/ptftests IP_decap_test.DecapPacketTest --platform-dir ptftests --qlen=1000 \
                    --platform remote -t 'lo_ipv6s=["fc00:1::32", "fc00:1::33"];ttl_mode="pipe";dscp_mode="uniform";\
                    lo_ips=["10.1.0.32", "10.1.0.33"];ignore_ttl=False;router_macs=["d4:af:f7:4d:a5:4c", \
                    "d4:af:f7:4d:a8:64"];max_internal_hops=0;outer_ipv6=True;outer_ipv4=True;inner_ipv4=True;\
                    inner_ipv6=True;fib_info_files=["/root/fib_info_dut0.txt", "/root/fib_info_dut1.txt"];\
                    ptf_test_port_map="/root/ptf_test_port_map.json"' --relax --debug info \
                    --log-file /tmp/decap.debug.log

Parameters:     fib_info_files - The fib_info files location
                lo_ips -  The loop_back IPs that are configured in the decap rule
                lo_ipv6s -  The loop_back IPv6 IPs that are configured in the decap rule
                router_macs - The mac addresses of the DUTs.
                dscp_mode - The rule for the dscp parameter in the decap packet that is configured in the JSON file
                            ('pipe' for inner and 'uniform' for outer)
                ttl_mode - The rule for the ttl parameter in the decap packet that is configured in the JSON file
                           ('pipe' for inner and 'uniform' for outer)
                inner_ipv4 - Test IPv4 encap packets
                inner_ipv6 - Test IPv6 encap packets
                outer_ipv4 - Test packets encapsulated in IPv4
                outer_ipv6 - Test packets encapsulated in IPv6
                max_internal_hops: Internal hops for multi asic platforms
                ignore_ttl: Ignore checking the ttl value

'''
from __future__ import print_function

import sys
import random
import logging
import json

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

    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance

        # which type of tunneled trafic to test (IPv4 in IPv4, IPv6 in IPv4, IPv6 in IPv4, IPv6 in IPv6)
        self.test_outer_ipv4 = self.test_params.get('outer_ipv4', True)
        self.test_outer_ipv6 = self.test_params.get('outer_ipv6', True)
        self.test_inner_ipv4 = self.test_params.get('inner_ipv4', True)
        self.test_inner_ipv6 = self.test_params.get('inner_ipv6', True)

        self.lo_ips = self.test_params.get('lo_ips')
        self.lo_ipv6s = self.test_params.get('lo_ipv6s')
        self.router_macs = self.test_params.get('router_macs')
        self.dscp_mode = self.test_params.get('dscp_mode')
        self.ttl_mode = self.test_params.get('ttl_mode')
        self.ignore_ttl = self.test_params.get('ignore_ttl', False)

        # multi asic platforms have internal routing hops
        # this param will be used to set the correct ttl values for inner packet
        # this value is zero for single asic platform
        self.max_internal_hops = self.test_params.get('max_internal_hops', 0)
        if self.max_internal_hops:
            self.TTL_RANGE = list(range(self.max_internal_hops + 1, 63))

        self.fibs = []
        for fib_info_file in self.test_params.get('fib_info_files'):
            self.fibs.append(fib.Fib(fib_info_file))

        ptf_test_port_map = self.test_params.get('ptf_test_port_map')
        with open(ptf_test_port_map) as f:
            self.ptf_test_port_map = json.load(f)

        self.src_ports = [int(port) for port in self.ptf_test_port_map.keys()]

        # Index of current DSCP and TTL value in allowed DSCP_RANGE and TTL_RANGE
        self.dscp_in_idx = 0  # DSCP of inner layer.
        self.dscp_out_idx = len(self.DSCP_RANGE) / 2  # DSCP of outer layer. Set different initial dscp_in and dscp_out
        self.ttl_in_idx = 0  # TTL of inner layer.
        self.ttl_out_idx = len(self.TTL_RANGE) / 2  # TTL of outer layer. Set different initial ttl_in and ttl_out

        self.summary = {}

    def print_summary(self):
        """
        Print summary
        """

        print('\nSummary:')
        print('\n'.join(['{}: {}'.format(encap_comb, status)
            for encap_comb, status in self.summary.items()]))

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

    def create_encap_packet(self, dst_ip, src_port, dut_index, outer_pkt='ipv4', triple_encap=False, outer_ttl=None, inner_ttl=None):
        """Creates an IPv4/IPv6 encapsulated packet in @outer_pkt packet
        @param dst_ip: Destination IP for inner packet. Depending @dst_ip IPv4 or IPv6 packet will be created
        @src_port: the physical port that the packet will be sent from
        @dut_index: Index of the DUT that the test packet is targeted for
        @param outer_pkt: Outer packet type to encapsulate inner packet in (ipv4/ipv6)
        @param triple_encap: Whether to build triple encapsulated packet
        @outer_ttl: TTL for the outer layer
        @inner_ttl: TTL for the inner layer
        @return: built packet and expected packet to match after decapsulation
        """

        src_mac =  self.dataplane.get_mac(0, src_port)
        dst_mac = '00:11:22:33:44:55'
        router_mac = self.router_macs[dut_index]
        target_mac = self.ptf_test_port_map[str(src_port)]['target_mac']  # Outer dest mac

        active_dut_index = int(self.ptf_test_port_map[str(src_port)]['target_dut'])
        lo_ip = self.lo_ips[active_dut_index]
        lo_ipv6 = self.lo_ipv6s[active_dut_index]

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

        if "pipe" == self.dscp_mode:
            exp_tc = exp_tos = tc_in
        elif "uniform" == self.dscp_mode:
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

        if "pipe" == self.ttl_mode:
            exp_ttl = inner_ttl - 1
        elif "uniform" == self.ttl_mode:
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
                                eth_dst=target_mac,
                                eth_src=src_mac,
                                ip_src='1.1.1.1',
                                ip_dst=lo_ip,
                                ip_tos=tos_out,
                                ip_ttl=outer_ttl,
                                inner_frame=inner_pkt)
        elif outer_pkt == 'ipv6':
            pkt = simple_ipv6ip_packet(
                                eth_dst=target_mac,
                                eth_src=src_mac,
                                ipv6_src='1::1',
                                ipv6_dst=lo_ipv6,
                                ipv6_tc=tc_out,
                                ipv6_hlim=outer_ttl,
                                inner_frame=inner_pkt)
        else:
            raise Exception("ERROR: invalid outer packet type ", outer_pkt)

        return pkt, exp_pkt

    def send_and_verify(self, dst_ip, expected_ports, src_port, dut_index, outer_pkt_type='ipv4', triple_encap=False,
                        outer_ttl=None, inner_ttl=None):
        '''
        @summary: This function builds encap packet, send and verify their arrival.
        @dst_ip: the destination ip for the inner IP header
        @expected_ports: list of ports that a packet can arrived from
        @src_port: the physical port that the packet will be sent from
        @dut_index: Index of the DUT that the test packet is targeted for
        @outer_pkt_type: Outer layter packet type, either 'ipv4' or 'ipv6'
        @triple_encap: True to send triple encapsulated packet
        @outer_ttl: TTL for the outer layer
        @inner_ttl: TTL for the inner layer
        '''

        pkt, exp_pkt = self.create_encap_packet(dst_ip, src_port, dut_index, outer_pkt_type, triple_encap, outer_ttl, inner_ttl)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        if self.ignore_ttl:
            if ipaddress.ip_address(unicode(dst_ip)).version == 4:
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            else:
                masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")

        inner_pkt_type = 'ipv4' if ipaddress.ip_address(unicode(dst_ip)).version == 4 else 'ipv6'

        if outer_pkt_type == 'ipv4':
            outer_src_ip = pkt['IP'].src
            outer_dst_ip = pkt['IP'].dst
            outer_ttl_info = pkt['IP'].ttl
            outer_tos = pkt['IP'].tos

            inner_src_ip = pkt['IP'].payload.src

            if inner_pkt_type == 'ipv4':
                inner_ttl_info = pkt['IP'].payload.ttl
                inner_tos = pkt['IP'].payload.tos
            else:
                inner_ttl_info = pkt['IP'].payload.hlim
                inner_tos = pkt['IP'].payload.tc

        else:
            outer_src_ip = pkt['IPv6'].src
            outer_dst_ip = pkt['IPv6'].dst
            outer_ttl_info = pkt['IPv6'].hlim
            outer_tos = pkt['IPv6'].tc

            inner_src_ip = pkt['IPv6'].payload.src

            if inner_pkt_type == 'ipv4':
                inner_ttl_info = pkt['IPv6'].payload.ttl
                inner_tos = pkt['IPv6'].payload.tos
            else:
                inner_ttl_info = pkt['IPv6'].payload.hlim
                inner_tos = pkt['IPv6'].payload.tc

        if inner_pkt_type == 'ipv4':
            exp_tos = exp_pkt.tos
        else:
            exp_tos = exp_pkt.tc

        #send and verify the return packets
        send_packet(self, src_port, pkt)

        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={}, (tos|tc)={}, ttl={})/IP(src={}, dst={}, (tos|tc)={}, ttl={}) from interface {}'\
            .format(pkt.src,
                    pkt.dst,
                    outer_src_ip,
                    outer_dst_ip,
                    outer_tos,
                    outer_ttl_info,
                    inner_src_ip,
                    dst_ip,
                    inner_tos,
                    inner_ttl_info,
                    src_port))
        logging.info('Expect Ether(src={}, dst={})/IP(src={}, dst={}, (tos|tc)={}, ttl={}) on interfaces {}'\
            .format('any',
                    'any',
                    inner_src_ip,
                    dst_ip,
                    exp_tos,
                    'any',
                    str(expected_ports)))

        matched, received = verify_packet_any_port(self, masked_exp_pkt, expected_ports)
        logging.info('Received expected packet on interface {}'.format(str(expected_ports[matched])))
        return matched, received

    def send_and_verify_all(self, dst_ip, expected_ports, src_port, dut_index, outer_pkt_type):
        """
        @summary: This method builds different encap packets, send and verify their arrival
        @dest_ip: The destination ip for the inner IP header
        @expected_ports: List of ports that a packet can arrive from
        @src_port: The physical port that the packet will be sent from
        @dut_index: Index of the DUT that the test packet is targeted for
        @outer_pkt_type: Indicates whether the outer packet is ipv4 or ipv6
        """

        self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type)
        self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, outer_ttl=64, inner_ttl=self.max_internal_hops +2)
        if self.ttl_mode == "pipe":
            self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, outer_ttl=self.max_internal_hops +1, inner_ttl=64)
        elif self.ttl_mode == "uniform":
            self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, outer_ttl=self.max_internal_hops +2, inner_ttl=64)

        # Triple encapsulation
        self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, triple_encap=True)
        self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, triple_encap=True, outer_ttl=64, inner_ttl=self.max_internal_hops +2)
        if self.ttl_mode == "pipe":
            self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, triple_encap=True, outer_ttl=self.max_internal_hops +1, inner_ttl=64)
        elif self.ttl_mode == "uniform":
            self.send_and_verify(dst_ip, expected_ports, src_port, dut_index, outer_pkt_type, triple_encap=True, outer_ttl=self.max_internal_hops +2, inner_ttl=64)

    def get_src_and_exp_ports(self, dst_ip):
        while True:
            src_port = int(random.choice(self.src_ports))
            active_dut_index = int(self.ptf_test_port_map[str(src_port)]['target_dut'])
            next_hop = self.fibs[active_dut_index][dst_ip]
            exp_port_list = next_hop.get_next_hop_list()
            if src_port in exp_port_list:
                continue
            logging.info('src_port={}, exp_port_list={}, active_dut_index={}'.format(src_port, exp_port_list, active_dut_index))
            break
        return src_port, exp_port_list, next_hop

    def run_encap_combination_test(self, outer_pkt_type, inner_pkt_type):
        """
        @summary: Send double and triple encapsulated packets for each IP range and
        expect the packet to be received from one of the expected ports
        """

        for dut_index, fib in enumerate(self.fibs):
            if inner_pkt_type == 'ipv4':
                ip_ranges = fib.ipv4_ranges()
            elif inner_pkt_type == 'ipv6':
                ip_ranges = fib.ipv6_ranges()
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
                self.check_range(ip_range, outer_pkt_type, inner_pkt_type, dut_index)

    def check_range(self, ip_range, outer_pkt_type, inner_pkt_type, dut_index):
        dst_ips = []
        dst_ips.append(ip_range.get_first_ip())
        if ip_range.length > 1:
            dst_ips.append(ip_range.get_last_ip())
        if ip_range.length > 2:
            dst_ips.append(ip_range.get_random_ip())

        logging.info('Checking dst_ips={}'.format(dst_ips))
        for dst_ip in dst_ips:
            src_port, exp_port_list, _ = self.get_src_and_exp_ports(dst_ip)

            if not exp_port_list:
                logging.info('Skip checking ip_range {} with exp_ports {}, outer_pkt_type={}, inner_pkt_type={}'\
                    .format(ip_range, exp_port_list, outer_pkt_type, inner_pkt_type))
                return

            logging.info('Checking ip range {}, outer_pkt_type={}, inner_pkt_type={}, src_port={}, exp_port_list={}, dst_ip={}, dut_index={}'\
                .format(ip_range, outer_pkt_type, inner_pkt_type, src_port, exp_port_list, dst_ip, dut_index))
            self.send_and_verify_all(dst_ip, exp_port_list, src_port, dut_index, outer_pkt_type)

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

                try:
                    self.run_encap_combination_test(outer_pkt_type, inner_pkt_type)
                except AssertionError as error:
                    # print error, but continue to test others encap traffic combinations
                    print("\n{}:\n{}".format(encap_combination, error))
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
