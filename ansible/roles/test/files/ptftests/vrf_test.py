'''
Description:    This file contains the VRF test for SONIC

Usage:          Examples of how to use VRF test
                ptf --test-dir ptftests vrf_test.FwdTest \
                    --platform-dir ptftests \
                    --platform remote \
                    --relax\
                    --debug info \
                    --log-file /tmp/vrf_Capacity_test.FwdTest.log \
                    -t 'testbed_type="t0";router_mac="3c:2c:99:c4:81:2a";dst_ports=[[14]];dst_vid=3001;dst_ips=["200.200.200.1"];src_vid=2001;src_ports=[2]'
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import re

from ipaddress import ip_network
from fib_test import FibTest
import lpm
import fib

class FwdTest(FibTest):
    _required_params = [
        'router_macs',
    ]
    class FwdDict(object):
        def __init__(self):
            self.ipv4 = {}
            self.ipv6 = {}

        def parse_fwd_info(self, file_path):
            # filter out empty lines and lines starting with '#'
            pattern = re.compile("^#.*$|^[ \t]*$")
            file_path = file_path[0]

            with open(file_path, 'r') as f:
                for line in f.readlines():
                    if pattern.match(line):
                        continue
                    prefix, dst_ports = line.split(' ', 1)
                    self.add_entry(prefix, dst_ports)

        def add_entry(self, prefix, dst_ports):
            prefix = ip_network(unicode(prefix))
            ip_range = lpm.LpmDict.IpInterval(prefix[0], prefix[-1])
            next_hop = fib.Fib.NextHop(dst_ports)
            if prefix.version == 4:
                self.ipv4[ip_range] = next_hop
            else:
                self.ipv6[ip_range] = next_hop

    #---------------------------------------------------------------------

    def setUp(self):
        """
        @summary: Setup for the test
        Some test parameters are used:
         - fwd_info:        the IP Ranges to be tested. Same syntax as fib.txt in FibTest
         - dst_ports:       this list should include ports those receive test traffic,
                            the syntax is same as dst_ports of fib.txt in FibTest.
                            this parameter should be used combine with 'dst_ips'
                            If both fwd_info and dst_ports are specifed, fwd_info is prefered.
         - dst_ips:         this list include dst IP addresses to be tested.
                            this parameter should be used combine with 'dst_ports'
                            If both fwd_info and dst_ips are specifed, fwd_info is prefered.
        """
        super(FwdTest, self).setUp()
        self.test_balancing = self.test_params.get('test_balancing', False)  # default not to test balancing
        self.fib_info_files = self.test_params.get('fib_info_files', None)
        self.dst_ports = self.test_params.get('dst_ports', None)  # dst_ports syntax example: [[0, 1], [2, 3, 4]]
        self.dst_ips = self.test_params.get('dst_ips', None)

        self.fwd_dict = FwdTest.FwdDict()
        if self.fib_info_files is not None:
            self.fwd_dict.parse_fwd_info(self.fib_info_files)
        else:
            for ip in self.dst_ips:
                self.fwd_dict.add_entry(ip, str(self.dst_ports))

    def check_fwd_entries(self, ipv4=True):
        if ipv4:
            entries = self.fwd_dict.ipv4
        else:
            entries = self.fwd_dict.ipv6

        for ip_range, next_hop in entries.iteritems():
            self.check_ip_range(ip_range, next_hop, ipv4)

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send packet for each route/host of both IPv4 and IPv6 and
        expect the packet to be received from one of the expected ports
        """
        # IPv4 Test
        if (self.test_ipv4):
            self.check_fwd_entries()
        # IPv6 Test
        if (self.test_ipv6):
            self.check_fwd_entries(ipv4=False)


class CapTest(FwdTest):
    _required_params=[
        'router_macs',
        'random_vrf_list',
        'src_base_vid',
        'dst_base_vid'
    ]

    def setUp(self):
        """
        @summary: Setup for the test
         - random_vrf_list: vrf indexes those to be verified.
         - src_base_vid:
         - dst_base_vid:
        """
        super(CapTest, self).setUp()

        self.random_vrf_list = self.test_params.get('random_vrf_list', '[]')
        self.src_base_vid = self.test_params.get('src_base_vid')
        self.dst_base_vid = self.test_params.get('dst_base_vid')

    def runTest(self):
        """
        @summary: Send packet for each vrf of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        for vrf_idx in self.random_vrf_list:
            self.src_vid = self.src_base_vid + vrf_idx
            self.dst_vid = self.dst_base_vid + vrf_idx

            logging.info("test vrf {} from Vlan{} to Vlan{}".format(vrf_idx, self.src_vid, self.dst_vid))

            # IPv4 Test
            if (self.test_ipv4):
                self.check_fwd_entries()
            # IPv6 Test
            if (self.test_ipv6):
                self.check_fwd_entries(ipv4=False)