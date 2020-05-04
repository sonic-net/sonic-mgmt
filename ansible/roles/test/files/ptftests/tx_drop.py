#-------------------------------------------------------------------------------
# Global imports
#-------------------------------------------------------------------------------

import logging
import ptf

from ipaddress import ip_address
from ptf.base_tests import BaseTest

from ptf.testutils import test_params_get
from ptf.testutils import simple_udp_packet
from ptf.testutils import send
from ptf.testutils import verify_packet_any_port

from scapy.all import *

#-------------------------------------------------------------------------------
# Testcase
#-------------------------------------------------------------------------------

class SendPacketTest:
    def __init__(self, TxDropTest):
        self.test = TxDropTest
        self.testParams = TxDropTest.test_params
    #--------------------------------------------------------------------------

    def logParams(self):
        self.test.log("Source mac is:       " + self.srcMac)
        self.test.log("Source ipv is:      "  + self.srcIp)

        self.test.log("Destination mac is:  " + self.dstMac)
        self.test.log("Destination ip is: "   + self.dstIp)

        self.test.log("Type of Service (ToS): "   + self.ToS)
        self.test.log("Source interface: "        + self.srcIntf)
        self.test.log("Packet count: "   + self.pktCount)

    #--------------------------------------------------------------------------

    def setUpParams(self):
        self.srcMac = self.testParams['src_mac']
        self.srcIp = self.testParams['src_ip']

        self.dstMac = self.testParams['dst_mac']
        self.dstIp = self.testParams['dst_ip']

        self.ToS = self.testParams['tos']
        self.srcIntf = self.testParams['src_intf']
        self.pktCount = self.testParams['pkt_count']

    #--------------------------------------------------------------------------

    def runTestIpv4(self):
        self.test.log("Run IPv4 based test")

        eth_h = Ether(src=self.srcMac, dst=self.dstMac)
        ip_h =  IP(src=self.srcIp, dst=self.dstIp, tos=int(self.ToS))
        udp_h = UDP(dport=123)
        payload = Raw(load="abc")

        pkt = eth_h/ip_h/udp_h/payload
        sendp(pkt, iface=self.srcIntf, count=int(self.pktCount))

        self.test.log("IPv4 based test: done")
    #--------------------------------------------------------------------------

    def runTest(self):
        self.setUpParams()
        self.logParams()

        self.runTestIpv4()
    #--------------------------------------------------------------------------

class TxDropTest(BaseTest):
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

    def runTest(self):
        if self.testbed_type in ['ptf32']:
            self.log("Run TX_DROP test")

            test = SendPacketTest(self)
            test.runTest()

            self.log("TX_DROP test: done")

            return

        self.fail("Unexpected testbed type %s!" % (self.testbed_type))
    #--------------------------------------------------------------------------