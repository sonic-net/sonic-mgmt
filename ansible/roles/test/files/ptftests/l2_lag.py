import logging
import random

import ptf
import ptf.dataplane as dataplane

from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf.mask import Mask


class LagTest(BaseTest):
    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 1000

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
        Two test parameters are used:
         - dst_mac: the MAC address to create the eth_dst of the packet
         - src_port: src_port will send packets
         - dst_ports: dst_port list will receive packets
         - hash_key:
            src_mac: will send packets with src_mac changes
            dst_mac: will send packets with dst_mac changes
            src_ip: will send packets with src_ip changes
            dst_ip: will send packets with dst_ip changes
         - pkt_action: expect to "receive" or "not receive" the packets. "fwd" is expect to "receive"
        '''
        self.dataplane            = ptf.dataplane_instance
        self.src_mac              = self.test_params["src_mac"]
        self.dst_mac              = self.test_params["dst_mac"]
        self.src_port             = self.test_params["src_port"]
        self.dst_ports            = self.test_params["dst_ports"]
        self.pkt_action           = self.test_params.get("pkt_action", "fwd")
        self.pkt_type             = self.test_params.get("packet_type", "ipv4")
        self.hash_key             = self.test_params.get("hash_key", None)
        self.balancing_range      = self.test_params.get("balancing_range", self.DEFAULT_BALANCING_RANGE)

    #---------------------------------------------------------------------

    def check_traffic(self):

        (pkt, masked_exp_pkt) = self.generate_packet()

        send_packet(self, self.src_port, pkt)
        logging.info("Sending packet from port {} to {}".format(self.src_port, self.dst_ports))
        logging.info("packet_action : {}".format(self.pkt_action))
        logging.info("pkt_type: {}".format(self.pkt_type))

        if self.pkt_action == "fwd":
            (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, self.dst_ports)
            logging.info("Receive packet at port {}".format(self.dst_ports[matched_index]))
            assert received
            # check lag load balance
            if self.hash_key:
                logging.info("Check PortChannel member balancing...")
                hit_count_map = {}
                for _ in range(0, self.BALANCING_TEST_TIMES):
                    (pkt, masked_exp_pkt) = self.generate_packet()
                    send_packet(self, self.src_port, pkt)
                    (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, self.dst_ports)
                    matched_port = self.dst_ports[matched_index]
                    hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1
                    logging.info("Receive packet at port {}".format(matched_port))
                self.check_balancing(hit_count_map)
        else:
            verify_no_packet_any(self, masked_exp_pkt, self.dst_ports)

    #---------------------------------------------------------------------

    def generate_packet(self):
        src_mac = "00:10:94:00:00:{:x}".format(random.randint(0, 255)) if self.hash_key == "src_mac" else self.src_mac
        dst_mac = "00:10:94:00:01:{:x}".format(random.randint(0, 255)) if self.hash_key == "dst_mac" else self.dst_mac
        if self.pkt_type == "ipv4":
            src_ip  = "10.0.0.{}".format(random.randint(0, 255)) if self.hash_key == "src_ip" else "10.0.0.1"
            dst_ip  = "192.168.0.{}".format(random.randint(0, 255)) if self.hash_key == "dst_ip" else "192.168.0.1"
            pkt = simple_ip_packet( eth_dst=dst_mac,
                                    eth_src=src_mac,
                                    ip_src=src_ip,
                                    ip_dst=dst_ip
                                )
        else:
            src_ip  = "2000::{:x}".format(random.randint(0, 65535)) if self.hash_key == "src_ip" else "2000::1"
            dst_ip  = "2001::{:x}".format(random.randint(0, 65535)) if self.hash_key == "dst_ip" else "2001::1"
            pkt = simple_tcpv6_packet( eth_dst=dst_mac,
                                    eth_src=src_mac,
                                    ipv6_src=src_ip,
                                    ipv6_dst=dst_ip
                                )

        masked_exp_pkt = Mask(pkt)
        return (pkt, masked_exp_pkt)

    #---------------------------------------------------------------------

    def check_within_expected_range(self, actual, expected):
        """
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        """
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)

    #---------------------------------------------------------------------

    def check_balancing(self, port_hit_cnt):
            """
            @summary: Check if the traffic is balanced across the LAG members
            @param port_hit_cnt : a dict that records the number of packets each port received
            @return bool
            """

            logging.info("%-10s \t %-10s \t %10s \t %10s \t %10s" % ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
            result = True

            total_hit_cnt = sum(port_hit_cnt.values())

            for port in self.dst_ports:
                (p, r) = self.check_within_expected_range(port_hit_cnt.get(port, 0), float(total_hit_cnt)/len(self.dst_ports))
                logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                    % ("LAG", str(port), total_hit_cnt/len(self.dst_ports), port_hit_cnt.get(port, 0), str(round(p, 4)*100) + "%"))
                result &= r

            assert result

    # ---------------------------------------------------------------------

    def runTest(self):
        self.dataplane.flush()
        self.check_traffic()