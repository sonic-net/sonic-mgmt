'''
Description:    This file contains the VRF test for SONIC

Usage:          Examples of how to use VRF test
                ptf --test-dir ptftests vrf_test.FwdTest \
                    --platform-dir ptftests \
                    --platform remote \
                    --relax\
                    --debug info \
                    --log-file /tmp/vrf_Capacity_test.FwdTest.log \
                    -t 'testbed_type="t0";router_mac="3c:2c:99:c4:81:2a";dst_ports="[[14]]";dst_vid="3001";dst_ips="[\"200.200.200.1\"]";src_vid="2001";src_ports="[2]"'
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import ipaddress
import logging
import random
import sys
import re
import ast

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *

import fib

#---------------------------------------------------------------------
def generate_ipv4_packet(test, dst_ip_addr):
    '''
    @summary: Generate IPv4 tcp packet.
    @param dest_ip_addr: destination IP to build packet with.
    '''
    sport = random.randint(0, 65535)
    dport = random.randint(0, 65535)
    ip_src = "10.0.0.1"
    ip_dst = dst_ip_addr
    src_mac = test.dataplane.get_mac(0, 0)

    pkt_args = {
                'eth_dst':   test.router_mac,
                'eth_src':   src_mac,
                'ip_src':    ip_src,
                'ip_dst':    ip_dst,
                'tcp_sport': sport,
                'tcp_dport': dport,
                'ip_ttl':    test.ttl
                }

    if test.ip_option:
        pkt_args['ip_options'] = test.ip_option

    if test.src_vid != None:
        pkt_args['dl_vlan_enable'] = True
        pkt_args['vlan_vid'] = int(test.src_vid)

    pkt = simple_tcp_packet(**pkt_args)

    exp_pkt_args = {
                    'eth_src':   test.router_mac,
                    'ip_src':    ip_src,
                    'ip_dst':    ip_dst,
                    'tcp_sport': sport,
                    'tcp_dport': dport,
                    'ip_ttl':    test.ttl-1 if test.ttl > 1 else 0
                    }

    if test.dst_vid != None:
        exp_pkt_args['dl_vlan_enable'] = True
        exp_pkt_args['vlan_vid'] = int(test.dst_vid)

    exp_pkt = simple_tcp_packet(**exp_pkt_args)
    masked_exp_pkt = Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "options")

    return (pkt, masked_exp_pkt)

#---------------------------------------------------------------------
def generate_ipv6_packet(test, dst_ip_addr):
    '''
    @summary: Generate IPv6 tcp packet.
    @param dest_ip_addr: destination IP to build packet with.
    '''
    sport = random.randint(0, 65535)
    dport = random.randint(0, 65535)
    ip_src = '2000::1'
    ip_dst = dst_ip_addr
    src_mac = test.dataplane.get_mac(0, 0)

    pkt_args = {
                'eth_dst':   test.router_mac,
                'eth_src':   src_mac,
                'ipv6_src':  ip_src,
                'ipv6_dst':  ip_dst,
                'tcp_sport': sport,
                'tcp_dport': dport,
                'ipv6_hlim': test.ttl
                }

    if test.src_vid != None:
        pkt_args['dl_vlan_enable'] = True
        pkt_args['vlan_vid'] = int(test.src_vid)

    pkt = simple_tcpv6_packet(**pkt_args)

    exp_pkt_args = {
                'eth_src':   test.router_mac,
                'ipv6_src':  ip_src,
                'ipv6_dst':  ip_dst,
                'tcp_sport': sport,
                'tcp_dport': dport,
                'ipv6_hlim': test.ttl-1 if test.ttl > 1 else 0
                }

    if test.dst_vid != None:
        exp_pkt_args['dl_vlan_enable'] = True
        exp_pkt_args['vlan_vid'] = int(test.dst_vid)

    exp_pkt = simple_tcpv6_packet(**exp_pkt_args)

    masked_exp_pkt = Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

    return (pkt, masked_exp_pkt)

#---------------------------------------------------------------------
def check_within_expected_range(test, actual, expected):
    '''
    @summary: Check if the actual number is within the accepted range of the expected number
    @param actual : acutal number of recieved packets
    @param expected : expected number of recieved packets
    @return (percentage, bool)
    '''
    percentage = (actual - expected) / float(expected)
    return (percentage, abs(percentage) <= test.balancing_range)

#---------------------------------------------------------------------
def check_balancing(test, dest_port_list, port_hit_cnt):
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

        (p, r) = check_within_expected_range(test, total_entry_hit_cnt, float(total_hit_cnt)/len(dest_port_list))

        logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                        % ("ECMP", str(ecmp_entry), total_hit_cnt/len(dest_port_list), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))

        result &= r

        if len(ecmp_entry) == 1 or total_entry_hit_cnt == 0:
            continue

        for member in ecmp_entry:
            (p, r) = check_within_expected_range(test, port_hit_cnt.get(member, 0), float(total_entry_hit_cnt)/len(ecmp_entry))
            logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                            % ("LAG", str(member), total_entry_hit_cnt/len(ecmp_entry), port_hit_cnt.get(member, 0), str(round(p, 4)*100) + '%'))
            result &= r

    assert result


def check_traffic(test, src_port, dst_ip_addr, dst_port_list, balance_port_list, ipv4=True):
    if ipv4:
        (pkt, masked_exp_pkt) = generate_ipv4_packet(test, dst_ip_addr)
    else:
        (pkt, masked_exp_pkt) = generate_ipv6_packet(test, dst_ip_addr)

    send_packet(test, src_port, pkt)
    logging.info("Sending packet from port " + str(src_port) + " to " + dst_ip_addr + ', packet_action is: ' + test.pkt_action)

    if test.pkt_action == 'fwd':

        logging.info("expect receive packets in " + str(dst_port_list))

        (matched_index, received) = verify_packet_any_port(test, masked_exp_pkt, dst_port_list)
        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        # Test traffic balancing across ECMP/LAG members
        if len(dst_port_list) > 1 and test.balance and random.random() < test.balancing_test_ratio :

            logging.info("Check IP range balancing...")

            hit_count_map = {}

            for i in range(0, test.balancing_test_times):
                if ipv4:
                    (pkt, masked_exp_pkt) = generate_ipv4_packet(test, dst_ip_addr)
                else:
                    (pkt, masked_exp_pkt) = generate_ipv6_packet(test, dst_ip_addr)

                send_packet(test, src_port, pkt)
                logging.info("Sending packet from port " + str(src_port) + " to " + dst_ip_addr)

                (matched_index, received) = verify_packet_any_port(test, masked_exp_pkt, dst_port_list)
                matched_port = dst_port_list[matched_index]
                hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1

            check_balancing(test, balance_port_list, hit_count_map)
    else:
        logging.info("expect not receive packet in " + str(dst_port_list))
        verify_no_packet_any(test, masked_exp_pkt, dst_port_list)


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
    BALANCING_TEST_TIMES = 1000
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
        Some test parameters are used:
         - fib_info:        the FIB information generated according to the testbed
         - router_mac:      the MAC address of the DUT used to create the eth_dst
                            of the packet
         - testbed_type:    the type of the testbed used to determine the source
                            port
         - src_ports:       this list should include ports those send test traffic.
         - ipv4/ipv6:       enable ipv4/ipv6 tests
         - balance:         enable check balancing. Default: True(enabled)
         - pkt_action:      expect to receive test traffic or not. Default: fwd
        
        Other test parameters:
         - ttl:             ttl of test pkts.
         - ip_option        enable ip option header in test pkts. Default: False(disable)
         - src_vid          vlan tag id of src pkts. Default: None(untag)
         - dst_vid          vlan tag id of dst pkts. Default: None(untag)
        '''

        self.dataplane = ptf.dataplane_instance

        self.fib = fib.Fib(self.test_params['fib_info'])
        self.router_mac = self.test_params['router_mac']

        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)

        self.balance = self.test_params.get('balance', True)
        self.balancing_range = ast.literal_eval(self.test_params.get('balancing_range', 'None')) or self.DEFAULT_BALANCING_RANGE
        self.balancing_test_times = ast.literal_eval(self.test_params.get('balancing_test_times', 'None')) or self.BALANCING_TEST_TIMES
        self.balancing_test_ratio = ast.literal_eval(self.test_params.get('balancing_test_ratio', 'None')) or self.DEFAULT_BALANCING_TEST_RATIO

        self.src_ports = ast.literal_eval(self.test_params.get('src_ports', 'None')) or range(1, 13) + range(28, 30)

        self.pkt_action = self.test_params.get('pkt_action', 'fwd')
        self.ttl = self.test_params.get('ttl', 64)
        self.ip_option = self.test_params.get('ip_option', False)
        self.src_vid = self.test_params.get('src_vid', None)
        self.dst_vid = self.test_params.get('dst_vid', None)

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

            balance_port_list = self.fib[ip_range.get_random_ip()].get_next_hop()
            # Send a packet with the first IP in the range
            check_traffic(self, src_port, ip_range.get_first_ip(), exp_port_list, balance_port_list, ipv4)
            # Send a packet with the last IP in the range
            if ip_range.length() > 1:
                check_traffic(self, src_port, ip_range.get_last_ip(), exp_port_list, balance_port_list, ipv4)
            # Send a packet with a random IP in the range
            if ip_range.length() > 2:
                check_traffic(self, src_port, ip_range.get_random_ip(), exp_port_list, balance_port_list, ipv4)

    # ---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports 
        or NOT(acrroding to 'pkt_action' configuration)
        """
        # IPv4 Test
        if (self.test_ipv4):
            self.check_ip_range()
        # IPv6 Test
        if (self.test_ipv6):
            self.check_ip_range(ipv4=False)


class FwdTest(BaseTest):
    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 1000
    DEFAULT_BALANCING_TEST_RATIO = 1


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
        Some test parameters are used:
         - fwd_info:        the IP Ranges to be tested. Same syntax as fib.txt in FibTest
         - router_mac:      the MAC address of the DUT used to create the eth_dst
                            of the packet
         - testbed_type:    the type of the testbed used to determine the source
                            port
         - src_ports:       this list should include ports those send test traffic
         - dst_ports:       this list should include ports those receive test traffic,
                            the syntax is same as dst_ports of fib.txt in FibTest.
                            this parameter should be used combine with 'dst_ips'
                            If both fwd_info and dst_ports are specifed, fwd_info is prefered.
         - dst_ips:         this list include dst IP addresses to be tested.
                            this parameter should be used combine with 'dst_ports'
                            If both fwd_info and dst_ips are specifed, fwd_info is prefered.
         - ipv4/ipv6:       enable ipv4/ipv6 tests
         - balance:         enable check balancing. Default: False(disabled)
         - pkt_action:      expect to receive test traffic or not. Default: fwd
        
        Other test parameters:
         - ttl:             ttl of test pkts.
         - ip_option        enable ip option header in test pkts. Default: False(disable)
         - src_vid          vlan tag id of src pkts. Default: None(untag)
         - dst_vid          vlan tag id of dst pkts. Default: None(untag)
        '''
        self.dataplane = ptf.dataplane_instance
        self.fwd_info = self.test_params.get('fwd_info', None)
        self.router_mac = self.test_params['router_mac']

        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)

        self.src_ports = ast.literal_eval(self.test_params.get('src_ports', 'None')) or range(1, 13) + range(28, 30)
        # dst_ports syntax example: [[0, 1], [2, 3, 4]]
        self.dst_ports = ast.literal_eval(self.test_params.get('dst_ports', 'None'))
        self.dst_ips = ast.literal_eval(self.test_params.get('dst_ips', 'None'))

        self.pkt_action = self.test_params.get('pkt_action', 'fwd')

        self.balance = self.test_params.get('balance', False)
        self.balancing_range = ast.literal_eval(self.test_params.get('balancing_range', 'None')) or self.DEFAULT_BALANCING_RANGE
        self.balancing_test_times = ast.literal_eval(self.test_params.get('balancing_test_times', 'None')) or self.BALANCING_TEST_TIMES
        self.balancing_test_ratio = ast.literal_eval(self.test_params.get('balancing_test_ratio', 'None')) or self.DEFAULT_BALANCING_TEST_RATIO

        self.ttl = self.test_params.get('ttl', 64)
        self.ip_option = self.test_params.get('ip_option', False)
        self.src_vid = self.test_params.get('src_vid', None)
        self.dst_vid = self.test_params.get('dst_vid', None)

    def check_ip_range(self, ipv4=True):
        fwd_entry = {'ipv4': {}, 'ipv6': {}}

        if self.fwd_info:
            # filter out empty lines and lines starting with '#'
            pattern = re.compile("^#.*$|^[ \t]*$")

            with open(self.fwd_info, 'r') as f:
                for line in f.readlines():
                    if pattern.match(line): continue
                    entry = line.split(' ', 1)
                    prefix = entry[0]
                    next_hop = []
                    matches = re.findall(r'\[([\s\d]+)\]', entry[1])
                    for match in matches:
                        next_hop.append([int(s) for s in match.split()])
                    port_list = [p for intf in next_hop for p in intf]
                    if ipaddress.ip_network(unicode(prefix)).version == 6:
                        fwd_entry['ipv6'].update({prefix: {'next_hop': next_hop, 'next_hop_list': port_list}})
                    else:
                        fwd_entry['ipv4'].update({prefix: {'next_hop': next_hop, 'next_hop_list': port_list}})
        else:
            port_list = [p for intf in self.dst_ports for p in intf]
            for ip in self.dst_ips:
                if ipaddress.ip_network(unicode(ip)).version == 6:
                    fwd_entry['ipv6'].update({ip: {'next_hop': self.dst_ports, 'next_hop_list': port_list}})
                else:
                    fwd_entry['ipv4'].update({ip: {'next_hop': self.dst_ports, 'next_hop_list': port_list}})

        if ipv4:
            ip_fwd_info = fwd_entry['ipv4']
        else:
            ip_fwd_info = fwd_entry['ipv6']

        for ip, ports in ip_fwd_info.iteritems():

            # Get the expected list of ports that would receive the packets
            exp_port_list = ports['next_hop_list']
            # Choose random source port from all ports excluding the expected ones
            src_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

            if not exp_port_list:
                continue

            logging.info("Check IP :" + str(ip) + " on " + str(exp_port_list) + "...")

            balance_port_list = ports['next_hop']

            check_traffic(self, src_port, ip, exp_port_list, balance_port_list, ipv4)

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


class CapTest(FwdTest):
    def setUp(self):
        super(CapTest, self).setUp()

        self.random_vrf_list = ast.literal_eval(self.test_params.get('random_vrf_list', '[]'))
        self.base_vid = int(self.test_params.get('base_vid', 2000))

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        for vrf_idx in self.random_vrf_list:
            self.src_vid = self.base_vid + vrf_idx
            self.dst_vid = self.src_vid + 1000

            logging.info("test vrf {} from Vlan{} to Vlan{}".format(vrf_idx, self.src_vid, self.dst_vid))

            # IPv4 Test
            if (self.test_ipv4):
                self.check_ip_range()
            # IPv6 Test
            if (self.test_ipv6):
                self.check_ip_range(ipv4=False)