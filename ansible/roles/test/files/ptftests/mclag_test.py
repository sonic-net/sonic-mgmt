"""
Description:    This file contains the MCLAG test for SONiC testbed

                Implemented according to the https://github.com/Azure/SONiC/wiki/

Usage:          Examples of how to use:
                ptf --test-dir ptftests mclag_test.MclagTest  --platform remote -t 'router_mac="00:02:03:04:05:00";switch_info="/tmp/mclag_switch_info.txt"'
"""

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------
import random
from ptf.testutils import *
from ptf.mask import Mask
import logging
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
import ptf.packet as scapy
import ptf
import time


SCALE_MAC_TEMPLATE = '00:03:00:{}:00:{}'
NUM = 10


class MclagTest(BaseTest):
    """
    @summary: MCLAG tests on testbed topo: t0-mclag
    """

    def __init__(self):
        """
        @summary: constructor
        """
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
    # ---------------------------------------------------------------------

    def setUp(self):
        """
        @summary: Setup for the test
        """

        self.dataplane = ptf.dataplane_instance
        self.basic_mac = self.dataplane.get_mac(0, 0)
        self.router_mac = self.test_params['router_mac']
        self.router_mac_dut2 = self.test_params.get('router_mac_dut2', self.router_mac)
        self.testbed_type = self.test_params['testbed_type']
        self.test_scenario = self.test_params.get('test_scenario')
        self.ignore_ports = self.test_params.get('ignore_ports', [])
        self.strict = self.test_params.get('strict', False)
        self.scale = self.test_params.get('scale', False)
        self.learning_flag = self.test_params.get('learning_flag', True)

        if self.testbed_type == 't0-mclag':
            self.port_count = 32
            self.ports = range(0, 26) + range(32, 58)
            self.ports_vlan1 = range(0, 13) + range(32, 45)
            self.ports_vlan2 = range(13, 26) + range(45, 58)
            self.server_count = (len(self.ports_vlan1) - 4)/2 + 4
        else:
            self.port_count = 16
            self.ports = range(0, 10) + range(16, 26)
            self.ports_vlan1 = range(0, 5) + range(16, 21)
            self.ports_vlan2 = range(5, 10) + range(21, 26)
            self.vlan_server_count = (len(self.ports_vlan1) - 4)/2 + 4

    # ---------------------------------------------------------------------

    def mac_arp_learn(self, src_port, ip_addr):
        """
        @summary: Check mclag forwarding packet.
        @param src_port: index of port to use for sending packet to switch.
        @param ip_addr: destination IP to build packet with.
        The MAC address will learn from this packet, and the device will send an arp packet requesting the IP address
        """
        ip_src = ip_addr
        ip_dst = ip_addr
        if self.scale:
            src_mac = SCALE_MAC_TEMPLATE.format(hex(int(ip_addr.split(".")[2])-1)[2:].zfill(2), hex(int(ip_addr.split(".")[3])-3)[2:].zfill(2))
        else:
            if self.test_scenario == "l2":
                if 0 <= (src_port % self.port_count) < (len(self.ports_vlan1)/2 - 2) or len(self.ports_vlan1)/2 <= (src_port % self.port_count) < (len(self.ports_vlan1) - 2):
                    src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
                else:
                    src_mac = self.basic_mac[:-2] + "%02x" % src_port
            else:
                if (src_port % self.port_count) < (len(self.ports_vlan1) - 2):
                    src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
                else:
                    src_mac = self.basic_mac[:-2] + "%02x" % src_port

        dst_mac = self.router_mac_dut2 if self.test_scenario == "l3" and src_port in self.ports[-2:] else self.router_mac
        pkt = simple_ip_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst)
        logging.info("eth_src: " + str(src_mac))
        logging.info("eth_dst: " + str(dst_mac))
        send_packet(self, src_port, pkt)
        logging.info("Sending learning packet from port " + str(src_port) + " to " + ip_addr)

    # ---------------------------------------------------------------------

    def check_mclag(self, dst_ip_addr, dst_port_list):

        src_ports = [p for p in self.ports if p not in dst_port_list and p not in self.ignore_ports]

        if self.strict:
            for src_port in src_ports:
                self.traffic_check(src_port, dst_ip_addr, dst_port_list)
        else:
            # Verify packet receive on expect ports
            # Choose only one port to verify, because of test on all ports takes too long times
            src_port = src_ports[random.randint(0, len(src_ports) - 1)]
            self.traffic_check(src_port, dst_ip_addr, dst_port_list)

    # ---------------------------------------------------------------------

    def traffic_check(self, src_port, dst_ip_addr, dst_port_list):
        if self.test_scenario == "l3":
            (matched_index, received) = self.check_mclag_l3(src_port, dst_ip_addr, dst_port_list)
            assert received
            matched_port = dst_port_list[matched_index]
            logging.info("Received packet at " + str(matched_port))
            # Verify only one packet receive on the expected ports, do not receive double packets
            if not self.scale:
                self.check_mclag_l3(src_port, dst_ip_addr, dst_port_list, count=True)
        elif self.test_scenario == "vxlan":
            (matched_index, received) = self.check_mclag_l2(src_port, dst_ip_addr, dst_port_list)
            assert received
            matched_port = dst_port_list[matched_index]
            logging.info("Received packet at " + str(matched_port))
            if not self.scale:
                self.check_mclag_l2(src_port, dst_ip_addr, dst_port_list, count=True)
        elif self.test_scenario == "l2":
            if (src_port in self.ports_vlan1 and set(dst_port_list) < set(self.ports_vlan1)) or (src_port in self.ports_vlan2 and set(dst_port_list) < set(self.ports_vlan2)):
                # verify received pkt in valid ports
                (matched_index, received) = self.check_mclag_l2(src_port, dst_ip_addr, dst_port_list)
                assert received
                matched_port = dst_port_list[matched_index]
                logging.info("Received packet at " + str(matched_port))
                if not self.scale:
                    # verify received pkt count is valid
                    self.check_mclag_l2(src_port, dst_ip_addr, dst_port_list, count=True)
            else:
                (matched_index, received) = self.check_mclag_l3(src_port, dst_ip_addr, dst_port_list)
                assert received
                matched_port = dst_port_list[matched_index]
                logging.info("Received packet at " + str(matched_port))
                if not self.scale:
                    self.check_mclag_l3(src_port, dst_ip_addr, dst_port_list, count=True)

    # ---------------------------------------------------------------------

    def check_mclag_l3(self, src_port, dst_ip_addr, dst_port_list, count=False):
        """
        @summary: Check mclag forwarding packet.
        @param src_port: index of port to use for sending packet to switch
        @param dst_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @param count: verify packet received count on list of ports
        """
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = "10.0.0.1"
        ip_dst = dst_ip_addr

        if self.test_scenario == "l2":
            if 0 <= (src_port % self.port_count) < (len(self.ports_vlan1)/2 - 2) or len(self.ports_vlan1)/2 <= (src_port % self.port_count) < (len(self.ports_vlan1) - 2):
                src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
            else:
                src_mac = self.basic_mac[:-2] + "%02x" % src_port
        else:
            if (src_port % self.port_count) < (len(self.ports_vlan1) - 2):
                src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
            else:
                src_mac = self.basic_mac[:-2] + "%02x" % src_port

        dst_mac = self.router_mac_dut2 if self.test_scenario == "l3" and src_port in self.ports[-2:] else self.router_mac
        if self.scale:
            exp_dst_mac = SCALE_MAC_TEMPLATE.format(hex(int(dst_ip_addr.split(".")[2])-1)[2:].zfill(2), hex(int(dst_ip_addr.split(".")[3])-3)[2:].zfill(2))
        else:
            exp_dst_mac = self.basic_mac[:-2] + "%02x" % (int(dst_ip_addr.split(".")[2]) - 1)

        print("Check src_port:{} to dst_ip:{} dst_port_list:{}".format(src_port, dst_ip_addr, dst_port_list))

        pkt = simple_tcp_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_dst=exp_dst_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        if "192.168" in dst_ip_addr:
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt_str = ''.join(['{:02x}'.format(ord(str(masked_exp_pkt.exp_pkt)[i]) & masked_exp_pkt.mask[i]) for i in xrange(masked_exp_pkt.size)])
        logging.info("exp_pkt: " + masked_exp_pkt_str)

        send_packet(self, src_port, pkt, count=NUM)

        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)
        logging.info("*************\n")
        logging.info("eth_src: " + str(src_mac))
        logging.info("eth_dst: " + str(dst_mac))
        logging.info("ip_src: " + str(ip_src))
        logging.info("ip_dst: " + str(ip_dst))
        logging.info("tcp_sport: " + str(sport))
        logging.info("tcp_dport: " + str(dport))
        logging.info("dst_port_list: " + str(dst_port_list) + "\n*************\n")

        if count:
            pkt_count = count_matched_packets_all_ports(self, masked_exp_pkt, dst_port_list)
            logging.info("Received " + str(pkt_count) + " expect packets, expecting {}".format(NUM))
            assert (pkt_count == NUM), "Receive pkt_count not equal send in l2 forwarding"
        else:
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
    # ---------------------------------------------------------------------

    def check_mclag_l2(self, src_port, dst_ip_addr, dst_port_list, count=False):
        """
        @summary: Check mclag forwarding packet.
        @param src_port: index of port to use for sending packet to switch
        @param dst_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @param count: verify packet received count on list of ports
        """
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = "10.0.0.1"
        ip_dst = dst_ip_addr
        if self.test_scenario == "l2":
            if 0 <= (src_port % self.port_count) < (len(self.ports_vlan1)/2 - 2) or len(self.ports_vlan1)/2 <= (src_port % self.port_count) < (len(self.ports_vlan1) - 2):
                src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
            else:
                src_mac = self.basic_mac[:-2] + "%02x" % src_port
        else:
            if src_port < (len(self.ports_vlan1) - 2):
                src_mac = self.basic_mac[:-2] + ("%02x" % (src_port % self.port_count))
            else:
                src_mac = self.basic_mac[:-2] + "%02x" % src_port
        if self.scale:
            dst_mac = SCALE_MAC_TEMPLATE.format(hex(int(dst_ip_addr.split(".")[2]) - 1)[2:].zfill(2),
                                                hex(int(dst_ip_addr.split(".")[3]) - 3)[2:].zfill(2))
        else:
            dst_mac = self.basic_mac[:-2] + "%02x" % (int(dst_ip_addr.split(".")[2]) - 1)

        print("Check src_port:{} to dst_ip:{} dst_port_list:{}".format(src_port, dst_ip_addr, dst_port_list))

        pkt = simple_tcp_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport)
        exp_pkt = simple_tcp_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport)
        logging.info("exp_pkt: " + str(repr(exp_pkt)))

        send_packet(self, src_port, pkt, count=NUM)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)
        logging.info("*************\n")
        logging.info("eth_src: " + str(src_mac))
        logging.info("eth_dst: " + str(dst_mac))
        logging.info("ip_src: " + str(ip_src))
        logging.info("ip_dst: " + str(ip_dst))
        logging.info("tcp_sport: " + str(sport))
        logging.info("tcp_dport: " + str(dport))
        logging.info("dst_port_list: " + str(dst_port_list) + "\n*************\n")

        if count:
            pkt_count = count_matched_packets_all_ports(self, exp_pkt, dst_port_list)
            logging.info("Received " + str(pkt_count) + " expect packets, expecting {}".format(NUM))
            assert (pkt_count == NUM)
        else:
            return verify_packet_any_port(self, exp_pkt, dst_port_list)

    # ---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Crete and send packet to verify the reachbility
        """
        if self.learning_flag:
            with open(self.test_params["switch_info"], 'r') as f:
                for line in f.read().splitlines():
                    dst_ports = map(int, line.split(" ", 1)[1].split(","))
                    dst_ports_list = [p for p in dst_ports if p not in self.ignore_ports]
                    dst_ip_addr = line.split(" ", 1)[0]

                    if not dst_ports_list:
                        continue

                    # Learn all mac and arp
                    logging.info("*" * 20)
                    logging.info("mac and arp learning")
                    for port in dst_ports_list:
                        for _ in range(0, 3):
                            self.mac_arp_learn(port, dst_ip_addr)
                            time.sleep(0.01)
                    logging.info("*" * 20)
                    time.sleep(0.01)

            if self.test_scenario == "l2":
                print("wait 70s for mac and arp sync!")
                time.sleep(70)
            logging.info("mac and arp learning finished! Start check traffic!")

        # Drop any queued packets before test
        self.dataplane.flush()

        with open(self.test_params["switch_info"], 'r') as f:
            for line in f.read().splitlines():
                dst_ports = map(int, line.split(" ", 1)[1].split(","))
                dst_ports_list = [p for p in dst_ports if p not in self.ignore_ports]
                dst_ip_addr = line.split(" ", 1)[0]

                if not dst_ports_list:
                    continue

                # Verify packet forwarding from all mclag member ports
                logging.info("#" * 20)
                logging.info("Verify neighbor: " + str(dst_ip_addr) + " on " + str(dst_ports_list))
                self.check_mclag(dst_ip_addr, dst_ports_list)
                logging.info("neighbor: " + str(dst_ip_addr) + " on " + str(dst_ports_list) + " check forwarding ok!")
