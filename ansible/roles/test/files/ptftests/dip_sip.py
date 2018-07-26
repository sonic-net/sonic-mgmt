'''
Description:
    This file contains the DIP=SIP test for SONiC

    This test uses UDP packets to validate that HW supports routing of L3 packets with DIP=SIP

Topologies:
    Supports t0, t1 and t1-lag topology

Parameters:
    testbed_type   - testbed type
    dst_host_mac   - destination host MAC address
    src_host_mac   - source host MAC address
    dst_router_mac - destination router MAC address
    src_router_mac - source router MAC address
    dst_router_ip  - destination router IPv4 address
    src_router_ip  - source router IPv4 address
    dst_port_ids   - destination port array of indices (when router has a members)
    src_port_ids   - source port array of indices (when router has a members)

Usage:
    Example of how to start this script:
        ptf --test-dir ptftests dip_sip.DipSipTest --platform-dir ptftests --platform remote \
        -t "testbed_type='<testbed_type>'; \
            dst_host_mac='<dst_host_mac>'; \
            src_host_mac='<src_host_mac>'; \
            dst_router_mac='<dst_router_mac>'; \
            src_router_mac='<src_router_mac>'; \
            dst_router_ip='<dst_router_ip>'; \
            src_router_ip='<src_router_ip>'; \
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

import json
import time
import logging

from collections import defaultdict
from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.testutils import *

#-------------------------------------------------------------------------------
# Testcase
#-------------------------------------------------------------------------------

class PortLagRouterBasedTest:
    def __init__(self, dipSipTest):
        self.test = dipSipTest
        self.testParams = dipSipTest.test_params
    #--------------------------------------------------------------------------

    def logParams(self):
        self.test.log("Destination router mac is: " + self.dstRouterMac)
        self.test.log("Destination router ip is:  " + self.dstRouterIp)

        self.test.log("Destination host mac is:   " + self.dstHostMac)
        self.test.log("Destination host ip is:    " + self.dstHostIp)

        self.test.log("Source router mac is:      " + self.srcRouterMac)
        self.test.log("Source router ip is:       " + self.srcRouterIp)

        self.test.log("Source host mac is:        " + self.srcHostMac)
        self.test.log("Source host ip is:         " + self.srcHostIp)

        self.test.log("Destination port ids is:   " + str([int(portId) for portId in self.dstPortIds]))
        self.test.log("Source port ids is:        " + str([int(portId) for portId in self.srcPortIds]))

        self.test.log("Packet TTL is:             " + str(self.pktTtl))
    #--------------------------------------------------------------------------

    def setUpParams(self):
        self.dstRouterMac = self.testParams['dst_router_mac']
        self.dstRouterIp = self.testParams['dst_router_ip']

        self.dstHostMac = self.testParams['dst_host_mac']
        self.dstHostIp = str(ip_address(unicode(self.testParams['dst_router_ip'])) + 1)

        self.srcRouterMac = self.testParams['src_router_mac']
        self.srcRouterIp = self.testParams['src_router_ip']

        self.srcHostMac = self.testParams['src_host_mac']
        self.srcHostIp = str(ip_address(unicode(self.testParams['src_router_ip'])) + 1)

        self.dstPortIds = self.testParams['dst_port_ids']
        self.srcPortIds = self.testParams['src_port_ids']

        self.pktTtl = 64 # Default packet TTL value
    #--------------------------------------------------------------------------

    def runTest(self):
        self.setUpParams()
        self.logParams()

        pkt = simple_udp_packet(eth_dst=self.srcRouterMac,
                                eth_src=self.srcHostMac,
                                ip_src=self.dstHostIp,
                                ip_dst=self.dstHostIp,
                                ip_ttl=self.pktTtl)
        send(self.test, int(self.srcPortIds[0]), pkt)

        pkt = simple_udp_packet(eth_dst=self.dstHostMac,
                                eth_src=self.dstRouterMac,
                                ip_src=self.dstHostIp,
                                ip_dst=self.dstHostIp,
                                ip_ttl=self.pktTtl-1)

        verify_packet_any_port(self.test, pkt, [int(port) for port in self.dstPortIds])
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
        if self.testbed_type in ['t0', 't1', 't1-lag']:
            self.log("Run PORT/LAG-router based test")

            test = PortLagRouterBasedTest(self)
            test.runTest()

            return

        self.fail("Unexpected testbed type %s!" % (self.testbed_type))
    #--------------------------------------------------------------------------
