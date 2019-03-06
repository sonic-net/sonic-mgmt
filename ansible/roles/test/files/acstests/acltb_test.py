'''
Description:    This file contains the ACL test for SONiC testbed

                Implemented according to the https://github.com/Azure/SONiC/wiki/ACL-test-plan

Usage:          Examples of how to use:
                ptf --test-dir acstests acltb_test.AclTest  --platform remote -t 'router_mac="00:02:03:04:05:00";verbose=True;route_info="/tmp/route_info.txt"'
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
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
import logging
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils

import pprint

class AclTest(BaseTest):
    '''
    @summary: ACL tests on testbed topo: t1
    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    PORT_COUNT = 31 # temporary exclude the last port

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
    #---------------------------------------------------------------------

    def setUp(self):
        '''
        @summary: Setup for the test
        '''

        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.testbed_type = self.test_params['testbed_type']

    #---------------------------------------------------------------------

    '''
    For diagnostic purposes only
    '''
    def print_route_info(self):
        pprint.pprint(self.route_info)
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
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=device_number, exp_pkt=pkt, timeout=1)

        if rcv_port in ports:
            match_index = ports.index(rcv_port)
            received = True

        return (match_index, rcv_pkt, received)
    #---------------------------------------------------------------------

    def runSendReceiveTest(self, i, pkt2send, src_port , pkt2recv, dst_ports, expect):
        """
        @summary Send packet and verify it is received/not received on the expected ports
        """

        masked2recv = Mask(pkt2recv)
        masked2recv.set_do_not_care_scapy(scapy.Ether, "dst")
        masked2recv.set_do_not_care_scapy(scapy.Ether, "src")
        send_packet(self, src_port, pkt2send)
        (index, rcv_pkt, received) = self.verify_packet_any_port(masked2recv, dst_ports)

        self.tests_total += 1

        passed = received == expect
        print "Test #" + str(i) + " %s" % ("PASSED" if passed else "FAILED")
        self.tests_passed += 1 if passed else 0

        return passed

    #---------------------------------------------------------------------
    def runAclTests(self, dst_ip, dst_ip_blocked, src_port, dst_ports):
        """
        @summary: Crete and send packet to verify each ACL rule
        @return: Number of tests passed
        """

        self.tests_passed = 0
        self.tests_total = 0

        print "\nPort to sent packets to: %d" % src_port
        print "Destination IP: %s" % dst_ip
        print "Ports to expect packet from: ",
        pprint.pprint(dst_ports)
        print "Dst IP expected to be blocked: %s " % dst_ip_blocked

        pkt0 = simple_tcp_packet(
                                eth_dst = self.router_mac,
                                eth_src = self.dataplane.get_mac(0, 0),
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                tcp_sport = 0x4321,
                                tcp_dport = 0x51,
                                ip_ttl = 64
                                )

        exp_pkt0 = simple_tcp_packet(
                                eth_dst = self.dataplane.get_mac(0, 0),
                                eth_src = self.router_mac,
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                tcp_sport = 0x4321,
                                tcp_dport = 0x51,
                                ip_ttl = 63
                            )

        print ""
        # Test #0 - unmatched packet - dropped
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        self.runSendReceiveTest(0, pkt, src_port, exp_pkt, dst_ports, 0)

        # Test #1 - source IP match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].src = "10.0.0.2"
        exp_pkt['IP'].src = "10.0.0.2"
        self.runSendReceiveTest(1, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #2 - destination IP match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].dst = dst_ip_blocked
        exp_pkt['IP'].dst = dst_ip_blocked
        self.runSendReceiveTest(2, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #3 - L4 source port match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['TCP'].sport = 0x1235
        exp_pkt['TCP'].sport = 0x1235
        self.runSendReceiveTest(3, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #4 - L4 destination port match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['TCP'].dport = 0x1235
        exp_pkt['TCP'].dport = 0x1235
        self.runSendReceiveTest(4, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #5 - IP protocol match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].proto = 0x7E
        exp_pkt['IP'].proto = 0x7E
        self.runSendReceiveTest(5, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #6 - TCP flags match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['TCP'].flags = 0x12
        exp_pkt['TCP'].flags = 0x12
        self.runSendReceiveTest(6, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #7 - source port range match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['TCP'].sport = 0x123A
        exp_pkt['TCP'].sport = 0x123A
        self.runSendReceiveTest(7, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #8 - destination port range match - forwarded
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['TCP'].dport = 0x123A
        exp_pkt['TCP'].dport = 0x123A
        self.runSendReceiveTest(8, pkt, src_port, exp_pkt, dst_ports, 1)

        # Test #9 - rules priority - dropped
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].src = "10.0.0.3"
        exp_pkt['IP'].src = "10.0.0.3"
        self.runSendReceiveTest(9, pkt, src_port, exp_pkt, dst_ports, 0)

	# Create a ICMP packet
	pkt0 = simple_icmp_packet(
                                eth_dst = self.router_mac,
                                eth_src = self.dataplane.get_mac(0, 0),
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                icmp_type=8,
                                icmp_code=0,
                                ip_ttl = 64
                            )

        exp_pkt0 = simple_icmp_packet(
                                eth_dst = self.dataplane.get_mac(0, 0),
                                eth_src = self.router_mac,
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                icmp_type=8,
                                icmp_code=0,
                                ip_ttl = 63
                            )
							
        # Test #10 - ICMP source IP match - forwarded
        # IP_PROTOCOL = 0x1
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].src = "10.0.0.2"
        exp_pkt['IP'].src = "10.0.0.2"
        self.runSendReceiveTest(10, pkt, src_port, exp_pkt, dst_ports, 1)

        # Create a UDP packet
        pkt0 = simple_udp_packet(
                                eth_dst = self.router_mac,
                                eth_src = self.dataplane.get_mac(0, 0),
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                udp_sport = 1234,
                                udp_dport = 80,
                                ip_ttl = 64
                                )

        exp_pkt0 = simple_udp_packet(
                                eth_dst = self.dataplane.get_mac(0, 0),
                                eth_src = self.router_mac,
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                udp_sport = 1234,
                                udp_dport = 80,
                                ip_ttl = 63
                                )

        # Test #11 - UDP source IP match - forwarded
        # IP_PROTOCOL = 0x11
        pkt = pkt0.copy()
        exp_pkt = exp_pkt0.copy()
        pkt['IP'].src = "10.0.0.2"
        exp_pkt['IP'].src = "10.0.0.2"
        self.runSendReceiveTest(11, pkt, src_port, exp_pkt, dst_ports, 1)

        return self.tests_passed, self.tests_total

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Crete and send packet to verify each ACL rule
        """

        test_result = False

        self.switch_info = open(self.test_params["switch_info"], 'r').readlines()
        if self.testbed_type in [ 't1', 't1-lag', 't1-64-lag' ]:
            self.tor_ports = map(int, self.switch_info[0].rstrip(",\n").split(","))
            self.spine_ports = map(int, self.switch_info[1].rstrip(",\n").split(","))
            self.dest_ip_addr_spine = self.switch_info[2].strip()
            self.dest_ip_addr_spine_blocked = self.switch_info[3].strip()
            self.dest_ip_addr_tor = self.switch_info[4].strip()
            self.dest_ip_addr_tor_blocked = self.switch_info[5].strip()

            # Verify ACLs on tor port
            (tests_passed, tests_total) = self.runAclTests(self.dest_ip_addr_spine, self.dest_ip_addr_spine_blocked, self.tor_ports[0], self.spine_ports)
            assert(tests_passed == tests_total)

            # Verify ACLs on spine port
            (tests_passed, tests_total) = self.runAclTests(self.dest_ip_addr_tor, self.dest_ip_addr_tor_blocked, self.spine_ports[0], self.tor_ports)
            assert(tests_passed == tests_total)
        elif self.testbed_type == 't0':
            src_port = map(int, self.switch_info[0].rstrip(",\n").split(","))
            dst_ports =  map(int, self.switch_info[1].rstrip(",\n").split(","))
            dst_ip = self.switch_info[2].strip()
            dst_ip_blocked = self.switch_info[3].strip()

            (tests_passed, tests_total) = self.runAclTests(dst_ip, dst_ip_blocked, src_port[0], dst_ports)
            assert(tests_passed == tests_total)


