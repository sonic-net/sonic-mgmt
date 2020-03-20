'''
Description:
    This file contains the DIP=SIP test for SONiC

    This test uses UDP packets to validate that HW supports routing of L3 packets with DIP=SIP

Topologies:
    Supports t0, t0-16, t0-56, t0-64, t0-64-32, t0-116, t1, t1-lag t1-64-lag and t1-64-lag-clet topology

Parameters:
    testbed_type    - testbed type
    dst_host_mac    - destination host MAC address
    src_host_mac    - source host MAC address
    dst_router_mac  - destination router MAC address
    src_router_mac  - source router MAC address
    dst_router_ipv4 - destination router IPv4 address
    src_router_ipv4 - source router IPv4 address
    dst_router_ipv6 - destination router IPv6 address
    src_router_ipv6 - source router IPv6 address
    dst_port_ids    - destination port array of indices (when router has a members)
    src_port_ids    - source port array of indices (when router has a members)

Usage:
    Example of how to start this script:
        ptf --test-dir ptftests dip_sip.DipSipTest --platform-dir ptftests --platform remote \
        -t "testbed_type='<testbed_type>'; \
            dst_host_mac='<dst_host_mac>'; \
            src_host_mac='<src_host_mac>'; \
            dst_router_mac='<dst_router_mac>'; \
            src_router_mac='<src_router_mac>'; \
            dst_router_ipv4='<dst_router_ipv4>'; \
            src_router_ipv4='<src_router_ipv4>'; \
            dst_router_ipv6='<dst_router_ipv6>'; \
            src_router_ipv6='<src_router_ipv6>'; \
            dst_port_ids='<dst_port_ids>'; \
            src_port_ids='<src_port_ids>'" \
        --relax --debug info --log-file /tmp/dip_sip.DipSipTest.log \
        --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre

Notes:
    Please check the dip_sip.yml file to see the details of how this test works
'''

#-------------------------------------------------------------------------------
# Global imports
#-------------------------------------------------------------------------------

import logging
import ptf

from ipaddress import ip_address
from ptf.base_tests import BaseTest

from ptf.testutils import test_params_get
from ptf.testutils import simple_udp_packet
from ptf.testutils import simple_udpv6_packet
from ptf.testutils import send
from ptf.testutils import verify_packet_any_port

#-------------------------------------------------------------------------------
# Testcase
#-------------------------------------------------------------------------------

class PortLagRouterBasedTest:
    def __init__(self, dipSipTest):
        self.test = dipSipTest
        self.testParams = dipSipTest.test_params
    #--------------------------------------------------------------------------

    def logParams(self):
        self.test.log("Destination router mac is:  " + self.dstRouterMac)
        self.test.log("Destination router ipv4 is: " + self.dstRouterIpv4)
        self.test.log("Destination router ipv6 is: " + self.dstRouterIpv6)

        self.test.log("Destination host mac is:    " + self.dstHostMac)
        self.test.log("Destination host ipv4 is:   " + self.dstHostIpv4)
        self.test.log("Destination host ipv6 is:   " + self.dstHostIpv6)

        self.test.log("Source router mac is:       " + self.srcRouterMac)
        self.test.log("Source router ipv4 is:      " + self.srcRouterIpv4)
        self.test.log("Source router ipv6 is:      " + self.srcRouterIpv6)

        self.test.log("Source host mac is:         " + self.srcHostMac)
        self.test.log("Source host ipv4 is:        " + self.srcHostIpv4)
        self.test.log("Source host ipv6 is:        " + self.srcHostIpv6)

        self.test.log("Destination port ids is:    " + str([int(portId) for portId in self.dstPortIds]))
        self.test.log("Source port ids is:         " + str([int(portId) for portId in self.srcPortIds]))

        self.test.log("Packet TTL/HL is:           " + str(self.pktTtlHlim))
    #--------------------------------------------------------------------------

    def setUpParams(self):
        self.dstRouterMac = self.testParams['dst_router_mac']
        self.dstRouterIpv4 = self.testParams['dst_router_ipv4']
        self.dstRouterIpv6 = self.testParams['dst_router_ipv6']

        self.dstHostMac = self.testParams['dst_host_mac']
        self.dstHostIpv4 = str(ip_address(unicode(self.testParams['dst_router_ipv4'])) + 1)
        self.dstHostIpv6 = str(ip_address(unicode(self.testParams['dst_router_ipv6'])) + 1)

        self.srcRouterMac = self.testParams['src_router_mac']
        self.srcRouterIpv4 = self.testParams['src_router_ipv4']
        self.srcRouterIpv6 = self.testParams['src_router_ipv6']

        self.srcHostMac = self.testParams['src_host_mac']
        self.srcHostIpv4 = str(ip_address(unicode(self.testParams['src_router_ipv4'])) + 1)
        self.srcHostIpv6 = str(ip_address(unicode(self.testParams['src_router_ipv6'])) + 1)

        self.dstPortIds = self.testParams['dst_port_ids']
        self.srcPortIds = self.testParams['src_port_ids']

        self.pktTtlHlim = 64 # Default packet TTL/HL value
    #--------------------------------------------------------------------------

    def runTestIpv6(self):
        self.test.log("Run IPv6 based test")

        pkt = simple_udpv6_packet(eth_dst=self.srcRouterMac,
                                  eth_src=self.srcHostMac,
                                  ipv6_src=self.dstHostIpv6,
                                  ipv6_dst=self.dstHostIpv6,
                                  ipv6_hlim=self.pktTtlHlim)
        send(self.test, int(self.srcPortIds[0]), pkt)

        pkt = simple_udpv6_packet(eth_dst=self.dstHostMac,
                                  eth_src=self.dstRouterMac,
                                  ipv6_src=self.dstHostIpv6,
                                  ipv6_dst=self.dstHostIpv6,
                                  ipv6_hlim=self.pktTtlHlim-1)

        verify_packet_any_port(self.test, pkt, [int(port) for port in self.dstPortIds])

        self.test.log("IPv6 based test: done")
    #--------------------------------------------------------------------------

    def runTestIpv4(self):
        self.test.log("Run IPv4 based test")

        pkt = simple_udp_packet(eth_dst=self.srcRouterMac,
                                eth_src=self.srcHostMac,
                                ip_src=self.dstHostIpv4,
                                ip_dst=self.dstHostIpv4,
                                ip_ttl=self.pktTtlHlim)
        send(self.test, int(self.srcPortIds[0]), pkt)

        pkt = simple_udp_packet(eth_dst=self.dstHostMac,
                                eth_src=self.dstRouterMac,
                                ip_src=self.dstHostIpv4,
                                ip_dst=self.dstHostIpv4,
                                ip_ttl=self.pktTtlHlim-1)

        verify_packet_any_port(self.test, pkt, [int(port) for port in self.dstPortIds])

        self.test.log("IPv4 based test: done")
    #--------------------------------------------------------------------------

    def runTest(self):
        self.setUpParams()
        self.logParams()

        self.runTestIpv4()
        self.runTestIpv6()
    #--------------------------------------------------------------------------

class DipSipTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
    #--------------------------------------------------------------------------

    def log(self, message):
        logging.info(message)
    #--------------------------------------------------------------------------

    def setUp(self):
        self.log("SetUp testbed")

        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.testbed_type = self.test_params['testbed_type']
    #--------------------------------------------------------------------------

    def tearDown(self):
        self.log("TearDown testbed")
    #--------------------------------------------------------------------------

    def runTest(self):
        if self.testbed_type in ['t0', 't0-16', 't0-56', 't0-64', 't0-64-32', 't0-116', 't1', 't1-lag', 't1-64-lag', 't1-64-lag-clet']:
            self.log("Run PORT/LAG-router based test")

            test = PortLagRouterBasedTest(self)
            test.runTest()

            self.log("PORT/LAG-router based test: done")

            return

        self.fail("Unexpected testbed type %s!" % (self.testbed_type))
    #--------------------------------------------------------------------------
