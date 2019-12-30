'''
Description:    This file contains the fiaball test for SONiC testbed

                Implemented according to the <SONiC_FIB_TestPlan.md>

Usage:          Examples of how to use:
                ptf --test-dir ptftests fib_update_test.FibUpdateTest -t 'router_mac="00:02:03:04:05:00";src_port=0;dst_port=1;dst_ip_addr_list=["1.1.1.1","2.2.2.2"]'
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import ast
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import ptf.testutils as testutils
import ipaddress
import pprint
import time

def count_matched_packets_all_ports_ext(test, exp_packet, ports=[], device_number=0, timeout=1):
    """
    Receive all packets on all specified ports and count how many expected packets were received.
    This function will return the cumulative count of matched packets received once it stops
    receiving matched packets for the specified timeout duration. Therefore, this function
    requires a positive timeout value.
    """
    if timeout <= 0:
        raise Exception("%s() requires positive timeout value." % sys._getframe().f_code.co_name)

    last_matched_packet_time = time.time()
    rcv_pkt_cnt = {}
    for p in ports:
        rcv_pkt_cnt[p]=0

    while True:
        if (time.time() - last_matched_packet_time) > timeout:
            break

        result = testutils.dp_poll(test, device_number=device_number, timeout=timeout)
        if isinstance(result, test.dataplane.PollSuccess):
            if (result.port in ports and
                ptf.dataplane.match_exp_pkt(exp_packet, result.packet)):
                rcv_pkt_cnt[result.port] = rcv_pkt_cnt.get(result.port, 0) + 1
                last_matched_packet_time = time.time()
        else:
            break

    return rcv_pkt_cnt

class FibUpdateTest(BaseTest):
    '''
    @summary: Fiball tests on testbed topo: t0
    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------

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
        ptf.open_logfile(str(self))
        logging.info("### Start Fiball test ###")
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.src_port = self.test_params['src_port']
        self.dst_mac = self.test_params.get('dst_mac', None)
        self.dst_port_list = self.test_params['dst_port_list']
        self.dst_ip_addr_list = self.test_params['dst_ip_addr_list']
        self.unexpected_ip_addr_list = self.test_params.get('unexpected_ip_addr_list', '[]')
    #---------------------------------------------------------------------

    def checkPacketSendReceive(self, src_port, dst_mac, dst_port_list, dst_ip_addr, expect_passed=True, count=1):
        src_port_mac = self.dataplane.get_mac(0, src_port)
        dst_port_mac = dst_mac
        if ipaddress.ip_address(unicode(dst_ip_addr)).version == 4: # is ipv4
            pkt,exp_pkt = self.create_pkt(src_port_mac, dst_port_mac, dst_ip_addr)
        else:
            pkt,exp_pkt = self.create_pkt6(src_port_mac, dst_port_mac, dst_ip_addr)
        testutils.send_packet(self, src_port, pkt, count=count)
        logging.info("Sent {} pkts from port {}: DIP-{}".format(count, src_port, dst_ip_addr))
        rcv_pkt_cnt = count_matched_packets_all_ports_ext(self, exp_pkt, dst_port_list, timeout=1)
        logging.info("Received expected pkts from ports: {}".format(pprint.pformat(rcv_pkt_cnt)))
        test_result = True
        rcv_cnt = sum(rcv_pkt_cnt.values())
        if rcv_cnt != count:
            test_result = False
        return test_result if expect_passed else not test_result

    #---------------------------------------------------------------------

    def create_pkt(self, src_port_mac, dst_port_mac, dst_ip):
        pkt = testutils.simple_icmp_packet(
                                eth_dst = self.router_mac,
                                eth_src = src_port_mac,
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                icmp_type=8,
                                icmp_code=0,
                                ip_ttl = 64
                            )
        exp_pkt = testutils.simple_icmp_packet(
                                eth_src = self.router_mac,
                                eth_dst = dst_port_mac or "00:11:22:33:44:55",
                                ip_src = "10.0.0.1",
                                ip_dst = dst_ip,
                                icmp_type=8,
                                icmp_code=0,
                                ip_ttl = 63
                            )
        if not dst_port_mac:
            exp_pkt = Mask(exp_pkt)
            exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        return (pkt,exp_pkt)

    def create_pkt6(self, src_port_mac, dst_port_mac, dst_ip):
        pkt = testutils.simple_tcpv6_packet(
                                eth_dst = self.router_mac,
                                eth_src = src_port_mac,
                                ipv6_src = "3ffe:1::1",
                                ipv6_dst = dst_ip,
                                ipv6_hlim = 64
                            )
        exp_pkt = testutils.simple_tcpv6_packet(
                                eth_src = self.router_mac,
                                eth_dst = dst_port_mac or "00:11:22:33:44:55",
                                ipv6_src = "3ffe:1::1",
                                ipv6_dst = dst_ip,
                                ipv6_hlim = 63
                            )
        if not dst_port_mac:
            exp_pkt = Mask(exp_pkt)
            exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        return (pkt,exp_pkt)

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Create and send packet to verify each IP address
        """

        tests_passed = 0
        tests_total = len(self.dst_ip_addr_list)

        for dst_ip_addr in self.dst_ip_addr_list:
            expect_passed = True if dst_ip_addr not in self.unexpected_ip_addr_list else False
            logging.info("Expect received %s? %s" % (dst_ip_addr, str(expect_passed)))
            res = self.checkPacketSendReceive(self.src_port, self.dst_mac, self.dst_port_list, dst_ip_addr, expect_passed)
            if res:
                tests_passed +=1
        logging.info("Total tests: {}, Faild: {}".format(tests_total, tests_total - tests_passed))
        assert(tests_passed == tests_total)
