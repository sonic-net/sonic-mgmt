"""
PTF test script to be used by dualtor dataplane utilities.
This ptf test, uses Scapy to sniff packets based on the filter and timeout provided.
Captured packets are dumped into a pcap file which later can be extracted from ptf.
"""

import ptf
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
import scapy.all as scapyall
import socket
import logging

from ptf import config # lgtm[py/unused-import]

SOCKET_RECV_BUFFER_SIZE = 10 * 1024 * 1024


class Sniff(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.sniff_timeout = testutils.test_params_get().get("sniff_timeout")
        self.sniff_filter = testutils.test_params_get().get("sniff_filter")
        self.capture_pcap = testutils.test_params_get().get("capture_pcap")
        self.sniffer_log = testutils.test_params_get().get("sniffer_logs")
        self.port_filter_expression = testutils.test_params_get().get("port_filter_expression")


    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        logging.info("Setting socket configuration and filters")
        for p in self.dataplane.ports.values():
            port = p.get_packet_source()
            port.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RECV_BUFFER_SIZE)
            #scapyall.attach_filter(port.socket, self.port_filter_expression)
        logging.info("Socket configuration and filters complete")


    def runTest(self):
        """
        @summary: Sniff packets based on given filters and timeout
        """
        logging.info("Scappy sniffer started with wait {} and filter: {}".format(self.sniff_timeout, self.sniff_filter))
        self.packets = scapyall.sniff(timeout=self.sniff_timeout, filter=self.sniff_filter)
        logging.info("Scappy sniffer ended")
        self.save_sniffed_packets()


    def save_sniffed_packets(self):
        """
        @summary: Dump all the captured packets into a pcap file
        """
        if self.packets:
            scapyall.wrpcap(self.capture_pcap, self.packets)
            logging.info("Pcap file dumped to {}".format(self.capture_pcap))
        else:
            logging.info("Pcap file is empty")
