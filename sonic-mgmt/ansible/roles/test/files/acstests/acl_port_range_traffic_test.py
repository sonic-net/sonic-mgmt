import sys
import ptf.packet as scapy
import ptf.dataplane as dataplane
import acs_base_test
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
from ptf.testutils import *
import scapy.all as scapy2

class SendTCP(acs_base_test.ACSDataplaneTest):
    def runTest(self):
        pkt = scapy2.Ether(src="e4:1d:2d:a5:f3:ac", dst="00:02:03:04:05:00")
        pkt /= scapy2.IP(src="10.0.0.1", dst="10.0.0.0")

        # get L4 port number
        port_number = testutils.test_params_get("port_number")
        port = port_number["port_number"]
        pkt /= scapy2.TCP(sport = int(port))
        pkt /= ("badabadaboom")

        # get packets number
        count = testutils.test_params_get("count")
        pack_number = count["count"]

        # send packets
        send(self, 0, pkt, int(pack_number))
