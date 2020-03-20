'''
Description:

    This file contains the ACL test for SONiC testbed
    Implemented according to the https://github.com/Azure/SONiC/wiki/ACL-test-plan

Usage:
    Examples of how to use:

    ptf --test-dir acstests acltb_test.AclTest   --platform-dir ptftests  --platform remote
        -t "router_mac='e4:1d:2d:f7:d5:40';testbed_type='t1-lag';
        tor_ports='27,22,29,25,20,28,26,21,24,31,23,30,19,16,18,17';
        spine_ports='7,2,11,0,1,6,13,12,14,10,15,8,5,4,9,3';
        dst_ip_tor='172.16.1.0';dst_ip_tor_forwarded='172.16.2.0';dst_ip_tor_blocked='172.16.3.0';
        dst_ip_spine='192.168.0.0';dst_ip_spine_forwarded='192.168.0.16';dst_ip_spine_blocked='192.168.0.17'"
'''
from __future__ import print_function

import logging
import json

import ptf
import ptf.packet as scapy
import ptf.testutils as testutils

from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_udp_packet
from ptf.testutils import simple_icmp_packet
from ptf.testutils import dp_poll
from ptf.testutils import send_packet
from ptf.mask import Mask
from ptf.base_tests import BaseTest


class AclTest(BaseTest):
    '''
    @summary: ACL tests on testbed topo: t1
    '''

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
        self.router_mac = self.test_params['router_mac']
        self.testbed_type = self.test_params['testbed_type']
        self.tor_ports = [int(p) for p in self.test_params['tor_ports'].split(',')]
        self.tor_ports.sort()
        self.spine_ports = [int(p) for p in self.test_params['spine_ports'].split(',')]
        self.spine_ports.sort()
        self.dst_ip_tor = self.test_params['dst_ip_tor']
        self.dst_ip_tor_forwarded = self.test_params['dst_ip_tor_forwarded']
        self.dst_ip_tor_blocked = self.test_params['dst_ip_tor_blocked']
        self.dst_ip_spine = self.test_params['dst_ip_spine']
        self.dst_ip_spine_forwarded = self.test_params['dst_ip_spine_forwarded']
        self.dst_ip_spine_blocked = self.test_params['dst_ip_spine_blocked']
        self.current_src_port_idx = 0  # An index for choosing a port for injecting packet
        self.test_results = []

    def _select_src_port(self, src_ports):
        """
        @summary: Choose a source port from list source ports in a round robin way
        @return: Source port number picked from list of source ports
        """
        if len(src_ports) == 0:
            return None

        self.current_src_port_idx = self.current_src_port_idx % len(src_ports)  # In case the index is out of range

        port = src_ports[self.current_src_port_idx]
        self.current_src_port_idx = (self.current_src_port_idx + 1) % len(src_ports)
        return port

    def verify_packet_any_port(self, pkt, ports, device_number=0):
        """
        @summary: Check that the packet is received on _any_ of the specified ports belonging to
        the given device (default device_number is 0).

        The function returns when either the expected packet is received or timeout (1 second).

        Also verifies that the packet is or received on any other ports for this
        device, and that no other packets are received on the device (unless --relax
        is in effect).

        @param pkt : packet to verify
        @param ports : list of ports
        @param device_number: device number, default is 0

        @return: index of the port on which the packet is received and the packet.
        """
        received = False
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=device_number, exp_pkt=pkt, timeout=1)

        if rcv_port in ports:
            match_index = ports.index(rcv_port)
            received = True

        return match_index, rcv_pkt, received

    def runSendReceiveTest(self, pkt2send, src_ports, pkt2recv, dst_ports, pkt_expected):
        """
        @summary Send packet and verify it is received/not received on the expected ports
        @param pkt2send: The packet that will be injected into src_port
        @param src_ports: The port into which the pkt2send will be injected
        @param pkt2recv: The packet that will be received on one of the dst_ports
        @param dst_ports: The ports on which the pkt2recv may be received
        @param pkt_expected: Indicated whether it is expected to receive the pkt2recv on one of the dst_ports
        """

        masked2recv = Mask(pkt2recv)
        masked2recv.set_do_not_care_scapy(scapy.Ether, "dst")
        masked2recv.set_do_not_care_scapy(scapy.Ether, "src")

        # Choose a source port from list of source ports
        src_port = self._select_src_port(src_ports)

        # Send the packet and poll on destination ports
        send_packet(self, src_port, pkt2send)
        logging.debug("Sent packet: " + pkt2send.summary())
        (index, rcv_pkt, received) = self.verify_packet_any_port(masked2recv, dst_ports)

        logging.debug('index=%s, received=%s' % (str(index), str(received)))
        if received:
            logging.debug("Received packet: " + scapy.Ether(rcv_pkt).summary())

        if pkt_expected:
            logging.debug('Expected packet on dst_ports')
            passed = True if received else False
            logging.debug('Received: ' + str(received))
        else:
            logging.debug('No packet expected on dst_ports')
            passed = False if received else True
            logging.debug('Received: ' + str(received))
        logging.debug('Passed: ' + str(passed))
        return passed

    def runAclTestCase(self, test_name, *args, **kwargs):
        """
        @summary: Wrapper for running ACL test cases
        @param test_name: Friendly name of the test case
        """
        logging.info('Run test case: ' + test_name)
        res = self.runSendReceiveTest(*args, **kwargs)
        logging.info('Result of "%s": %s' % (test_name, "PASSED" if res else "FAILED"))
        self.test_results.append({"result": res, "test_name": test_name})

    def runAclTests(self, dst_ip, dst_ip_forwarded, dst_ip_blocked, src_ports, dst_ports, direction):
        """
        @summary: Crete and send packet to verify each ACL rule
        """

        direction = ", " + direction

        print("\nPort to sent packets to:")
        print(src_ports)
        print("Destination IP: %s" % dst_ip)
        print("Ports to expect packet from: ")
        print(dst_ports)
        print("Dst IP expected to be blocked: %s " % dst_ip_blocked)

        tcp_pkt0 = simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=64
        )

        tcp_exp_pkt0 = simple_tcp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=63
        )

        test_name = 'Test #0 - unmatched packet - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = 'Test #1 - source IP match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.2"
        exp_pkt['IP'].src = "20.0.0.2"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #2 - destination IP match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].dst = dst_ip_forwarded
        exp_pkt['IP'].dst = dst_ip_forwarded
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #3 - L4 source port match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].sport = 0x120D
        exp_pkt['TCP'].sport = 0x120D
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #4 - L4 destination port match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].dport = 0x1217
        exp_pkt['TCP'].dport = 0x1217
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #5 - IP protocol match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].proto = 0x7E
        exp_pkt['IP'].proto = 0x7E
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #6 - TCP flags match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].flags = 0x1B
        exp_pkt['TCP'].flags = 0x1B
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #7 - source port range match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].sport = 0x123A
        exp_pkt['TCP'].sport = 0x123A
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #8 - destination port range match - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].dport = 0x123B
        exp_pkt['TCP'].dport = 0x123B
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = '# Test #9 - rules priority - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.3"
        exp_pkt['IP'].src = "20.0.0.3"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        # Create a ICMP packet
        icmp_pkt0 = simple_icmp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64
        )

        icmp_exp_pkt0 = simple_icmp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            icmp_type=8,
            icmp_code=0,
            ip_ttl=63
        )

        test_name = 'Test #10 - ICMP source IP match, IP_PROTOCOL=0x1 - forwarded' + direction
        pkt = icmp_pkt0.copy()
        exp_pkt = icmp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.4"
        exp_pkt['IP'].src = "20.0.0.4"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        # Create a UDP packet
        udp_pkt0 = simple_udp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=64
        )

        udp_exp_pkt0 = simple_udp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src="20.0.0.1",
            ip_dst=dst_ip,
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=63
        )

        test_name = 'Test #11 - UDP source IP match, IP_PROTOCOL=0x11 - forwarded' + direction
        pkt = udp_pkt0.copy()
        exp_pkt = udp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.4"
        exp_pkt['IP'].src = "20.0.0.4"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        ###########################################################################

        test_name = 'Test #12 - source IP match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.6"
        exp_pkt['IP'].src = "20.0.0.6"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #13 - destination IP match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].dst = dst_ip_blocked
        exp_pkt['IP'].dst = dst_ip_blocked
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #14 - L4 source port match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].sport = 0x1271
        exp_pkt['TCP'].sport = 0x1271
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #15 - L4 destination port match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].dport = 0x127B
        exp_pkt['TCP'].dport = 0x127B
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #16 - IP protocol match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].proto = 0x7F
        exp_pkt['IP'].proto = 0x7F
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #17 - TCP flags match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].flags = 0x24
        exp_pkt['TCP'].flags = 0x24
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #18 - source port range match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].sport = 0x129E
        exp_pkt['TCP'].sport = 0x129E
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #19 - destination port range match - dropped' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['TCP'].dport = 0x129F
        exp_pkt['TCP'].dport = 0x129F
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = '# Test #20 - rules priority - forwarded' + direction
        pkt = tcp_pkt0.copy()
        exp_pkt = tcp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.7"
        exp_pkt['IP'].src = "20.0.0.7"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, True)

        test_name = 'Test #21 - ICMP source IP match, IP_PROTOCOL=0x1 - dropped' + direction
        pkt = icmp_pkt0.copy()
        exp_pkt = icmp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.8"
        exp_pkt['IP'].src = "20.0.0.8"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

        test_name = 'Test #22 - UDP source IP match, IP_PROTOCOL=0x11 - dropped' + direction
        pkt = udp_pkt0.copy()
        exp_pkt = udp_exp_pkt0.copy()
        pkt['IP'].src = "20.0.0.8"
        exp_pkt['IP'].src = "20.0.0.8"
        self.runAclTestCase(test_name, pkt, src_ports, exp_pkt, dst_ports, False)

    def runTest(self):
        """
        @summary: Crete and send packet to verify each ACL rule
        """

        # Inject packets into TOR ports, check on SPINE ports
        self.runAclTests(self.dst_ip_spine,
                         self.dst_ip_spine_forwarded,
                         self.dst_ip_spine_blocked,
                         self.tor_ports,
                         self.spine_ports,
                         "tor->spine")

        # Inject packets into SPINE ports, check on TOR ports
        self.runAclTests(self.dst_ip_tor,
                         self.dst_ip_tor_forwarded,
                         self.dst_ip_tor_blocked,
                         self.spine_ports,
                         self.tor_ports,
                         "spine->tor")

        failed_cases = filter(lambda r: not r['result'], self.test_results)
        if len(failed_cases) == 0:
            print('!!!! All test cases passed! !!!!')
        assert (len(failed_cases) == 0), "TEST FAILED. Failed test cases: " + str(failed_cases)
