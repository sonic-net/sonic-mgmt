'''
Description:    This file contains the FIB test for SONIC

                Design is available in https://github.com/Azure/SONiC/wiki/FIB-Scale-Test-Plan

Usage:          Examples of how to use log analyzer
                ptf --test-dir ptftests fib_test.FibTest --platform-dir ptftests --qlen=2000 --platform remote -t 'setup_info="/root/test_fib_setup_info.json";testbed_mtu=1514;ipv4=True;test_balancing=True;ipv6=True' --relax --debug info --log-file /tmp/fib_test.FibTest.ipv4.True.ipv6.True.2020-12-22-08:17:05.log --socket-recv-size 16384
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import random
import time
import json

import ptf
import ptf.packet as scapy

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_tcpv6_packet
from ptf.testutils import send_packet
from ptf.testutils import verify_packet_any_port
from ptf.testutils import verify_no_packet_any

import fib

class FibTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test routes advertised by BGP peers of SONIC are working properly.
    The setup of peers is described in 'VM set' section in
    https://github.com/Azure/sonic-mgmt/blob/master/docs/ansible/README.testbed.md

    Routes advertized by the peers have ECMP groups. The purpose of the test is to make sure
    that packets are forwarded through one of the ports specified in route's ECMP group.

    This class receives a text file describing the bgp routes added to the switch.
    File contains information about each bgp route which was added to the switch.

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
    BALANCING_TEST_TIMES = 625
    DEFAULT_BALANCING_TEST_NUMBER = 1
    ACTION_FWD = 'fwd'
    ACTION_DROP = 'drop'

    _required_params = [
        'fib_info_files',
        'ptf_test_port_map',
        'router_macs'
    ]

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()
        self.check_required_params()

    def check_required_params(self):
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception("Missing required parameter {}".format(param))

    def setUp(self):
        '''
        @summary: Setup for the test
        Some test parameters are used:
         - setup_info: various configuration required by the FIB ptf test
         - src_ports: this list should include all enabled ports, both up links
                     and down links.
         - pkt_action: expect to receive test traffic or not. Default: fwd
         - ipv4/ipv6: enable ipv4/ipv6 tests

        Other test parameters:
         - ttl:             ttl of test pkts. Auto decrease 1 for expected pkts.
         - ip_options       enable ip option header in ipv4 pkts. Default: False(disable)
         - src_vid          vlan tag id of src pkts. Default: None(untag)
         - dst_vid          vlan tag id of dst pkts. Default: None(untag)
         - ignore_ttl:      mask the ttl field in the expected packet
        '''
        self.dataplane = ptf.dataplane_instance

        self.fibs = []
        for fib_info_file in self.test_params.get('fib_info_files'):
            self.fibs.append(fib.Fib(fib_info_file))

        ptf_test_port_map = self.test_params.get('ptf_test_port_map')
        with open(ptf_test_port_map) as f:
            self.ptf_test_port_map = json.load(f)

        self.router_macs = self.test_params.get('router_macs')
        self.pktlen = self.test_params.get('testbed_mtu', 1500)
        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)
        self.test_balancing = self.test_params.get('test_balancing', True)
        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get('balancing_test_times', self.BALANCING_TEST_TIMES)
        self.balancing_test_number = self.test_params.get('balancing_test_number', self.DEFAULT_BALANCING_TEST_NUMBER)
        self.balancing_test_count = 0

        self.pkt_action = self.test_params.get('pkt_action', self.ACTION_FWD)
        self.ttl = self.test_params.get('ttl', 64)
        self.ip_options = self.test_params.get('ip_options', False)
        self.src_vid = self.test_params.get('src_vid', None)
        self.dst_vid = self.test_params.get('dst_vid', None)

        self.src_ports = self.test_params.get('src_ports', None)
        if not self.src_ports:
            self.src_ports = [int(port) for port in self.ptf_test_port_map.keys()]
        
        self.ignore_ttl = self.test_params.get('ignore_ttl', False)

    def check_ip_ranges(self, ipv4=True):
        for dut_index, fib in enumerate(self.fibs):
            if ipv4:
                ip_ranges = fib.ipv4_ranges()
            else:
                ip_ranges = fib.ipv6_ranges()

            if len(ip_ranges) > 150:
                covered_ip_ranges = ip_ranges[:100] + random.sample(ip_ranges[100:], 50)  # Limit test execution time
            else:
                covered_ip_ranges = ip_ranges[:]

            for ip_range in covered_ip_ranges:
                if ip_range.get_first_ip() in fib:
                    self.check_ip_range(ip_range, dut_index, ipv4)

            random.shuffle(covered_ip_ranges)
            self.check_balancing(covered_ip_ranges, dut_index, ipv4)

    def get_src_and_exp_ports(self, dst_ip):
        while True:
            src_port = int(random.choice(self.src_ports))
            active_dut_index = self.ptf_test_port_map[str(src_port)]['target_dut']
            next_hop = self.fibs[active_dut_index][dst_ip]
            exp_port_list = next_hop.get_next_hop_list()
            if src_port in exp_port_list:
                continue
            break
        return src_port, exp_port_list, next_hop

    def check_ip_range(self, ip_range, dut_index, ipv4=True):

        dst_ips = []
        dst_ips.append(ip_range.get_first_ip())
        if ip_range.length > 1:
            dst_ips.append(ip_range.get_last_ip())
        if ip_range.length > 2:
            dst_ips.append(ip_range.get_random_ip())

        for dst_ip in dst_ips:
            src_port, exp_ports, _ = self.get_src_and_exp_ports(dst_ip)
            if not exp_ports:
                logging.info('Skip checking ip range {} with exp_ports {}'.format(ip_range, exp_ports))
                return
            logging.info('Checking ip range {}, src_port={}, exp_ports={}, dst_ip={}, dut_index={}'\
                .format(ip_range, src_port, exp_ports, dst_ip, dut_index))
            self.check_ip_route(src_port, dst_ip, exp_ports, ipv4)

    def check_balancing(self, ip_ranges, dut_index, ipv4=True):
        # Test traffic balancing across ECMP/LAG members
        if self.test_balancing and self.pkt_action == self.ACTION_FWD:
            for ip_range in ip_ranges:
                dst_ip = ip_range.get_random_ip()
                src_port, exp_port_list, next_hop = self.get_src_and_exp_ports(dst_ip)
                if len(exp_port_list) <= 1:
                    # Only 1 expected output port is not enough for balancing test.
                    continue
                hit_count_map = {}
                # Change balancing_test_times according to number of next hop groups
                logging.info('Checking ip range balancing {}, src_port={}, exp_ports={}, dst_ip={}, dut_index={}'\
                    .format(ip_range, src_port, exp_port_list, dst_ip, dut_index))
                for i in range(0, self.balancing_test_times*len(exp_port_list)):
                    (matched_index, received) = self.check_ip_route(src_port, dst_ip, exp_port_list, ipv4)
                    hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
                self.check_hit_count_map(next_hop.get_next_hop(), hit_count_map)
                self.balancing_test_count += 1
                if self.balancing_test_count >= self.balancing_test_number:
                    break

    def check_ip_route(self, src_port, dst_ip_addr, dst_port_list, ipv4=True):
        if ipv4:
            res = self.check_ipv4_route(src_port, dst_ip_addr, dst_port_list)
        else:
            res = self.check_ipv6_route(src_port, dst_ip_addr, dst_port_list)

        if self.pkt_action == self.ACTION_DROP:
            return res

        (matched_index, received) = res

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

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
        ip_src = "30.0.0.1"
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, src_port)

        router_mac = self.ptf_test_port_map[str(src_port)]['target_mac']
        exp_router_mac = self.router_macs[self.ptf_test_port_map[str(src_port)]['target_dut']]

        pkt = simple_tcp_packet(
                            pktlen=self.pktlen,
                            eth_dst=router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=self.ttl,
                            ip_options=self.ip_options,
                            dl_vlan_enable=self.src_vid is not None,
                            vlan_vid=self.src_vid or 0)
        exp_pkt = simple_tcp_packet(
                            self.pktlen,
                            eth_src=exp_router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=max(self.ttl-1, 0),
                            ip_options=self.ip_options,
                            dl_vlan_enable=self.dst_vid is not None,
                            vlan_vid=self.dst_vid or 0)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={}) on port {}'\
            .format(pkt.src,
                    pkt.dst,
                    pkt['IP'].src,
                    pkt['IP'].dst,
                    sport,
                    dport,
                    src_port))
        logging.info('Expect Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(exp_router_mac,
                    'any',
                    ip_src,
                    ip_dst,
                    sport,
                    dport))

        if self.pkt_action == self.ACTION_FWD:
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
        elif self.pkt_action == self.ACTION_DROP:
            return verify_no_packet_any(self, masked_exp_pkt, dst_port_list)
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
        ip_src = '2000:0030::1'
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, src_port)

        router_mac = self.ptf_test_port_map[str(src_port)]['target_mac']
        exp_router_mac = self.router_macs[self.ptf_test_port_map[str(src_port)]['target_dut']]

        pkt = simple_tcpv6_packet(
                                pktlen=self.pktlen,
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=self.ttl,
                                dl_vlan_enable=self.src_vid is not None,
                                vlan_vid=self.src_vid or 0)
        exp_pkt = simple_tcpv6_packet(
                                pktlen=self.pktlen,
                                eth_src=exp_router_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=max(self.ttl-1, 0),
                                dl_vlan_enable=self.dst_vid is not None,
                                vlan_vid=self.dst_vid or 0)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(pkt.src,
                    pkt.dst,
                    pkt['IPv6'].src,
                    pkt['IPv6'].dst,
                    sport,
                    dport))
        logging.info('Expect Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(exp_router_mac,
                    'any',
                    ip_src,
                    ip_dst,
                    sport,
                    dport))

        if self.pkt_action == self.ACTION_FWD:
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
        elif self.pkt_action == self.ACTION_DROP:
            return verify_no_packet_any(self, masked_exp_pkt, dst_port_list)

    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)

    def check_hit_count_map(self, dest_port_list, port_hit_cnt):
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
                         % ("ECMP", str(ecmp_entry), total_hit_cnt//len(dest_port_list), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
            result &= r
            if len(ecmp_entry) == 1 or total_entry_hit_cnt == 0:
                continue
            for member in ecmp_entry:
                (p, r) = self.check_within_expected_range(port_hit_cnt.get(member, 0), float(total_entry_hit_cnt)/len(ecmp_entry))
                logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                              % ("LAG", str(member), total_entry_hit_cnt//len(ecmp_entry), port_hit_cnt.get(member, 0), str(round(p, 4)*100) + '%'))
                result &= r

        assert result

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        # IPv4 Test
        if (self.test_ipv4):
            self.check_ip_ranges()
        # IPv6 Test
        if (self.test_ipv6):
            self.check_ip_ranges(ipv4=False)
