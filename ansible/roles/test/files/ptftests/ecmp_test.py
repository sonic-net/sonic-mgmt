"""
SONiC Dataplane ECMP tests
"""
import random
import time
import logging
import ptf.packet as scapy
import socket
import datetime
import ptf.dataplane as dataplane
import ptf.testutils as testutils
import ptf
from ptf import config
from ptf.testutils import *
from ptf.mask import Mask
from ptf.base_tests import BaseTest

# For SONiC
# testing ECMP uniformn distribution over 16 RIFs from 16 differnt ports
# ---- Test require 32 connected ports and SONiC up and running ----
# ---- MUST RUN WITH "--relax" option on the ptf running line   ----
# Preliminary steps
# 1. Configure IPs of all of the connected ports
# (SONiC will configure neighbors)
# 2. configure all routes (run add_routes.sh on SONiC)

# Test structure
# Sending Packets sequance
# 1. Main loop running on 16 sources ports
# 2. IP_LAST_WORD_RANGE loop running from 0-254
# 3. IP_2ND_LAST_WORD_RANGE loop running 0-15
# 4. Inside loop, to increase the number of packets, with differnt ports
# 5. Sending and reciving packets, and counting destanation ports
# - Final counters checking for uniform distribution

# Final steps
# For cleaning configuration run remove_routes.sh from SONiC


# Constants
IP_LAST_WORD_RANGE = 254
IP_2ND_LAST_WORD_RANGE = 16
NUMBER_OF_SRC_PORTS = 16
NUMBER_OF_DST_PORTS = 16


class ECMPtest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
        self.verbose = self.test_params['verbose']
        self.log_fp = open('/tmp/ecmp.log', 'a')

    def log(self, message, debug=False):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if (debug and self.verbose) or (not debug):
            print "%s : %s" % (current_time, message)
        self.log_fp.write("%s : %s\n" % (current_time, message))

    def runTest(self):
        self.pkt_counter = [0]*NUMBER_OF_DST_PORTS
        self.send_packets()
        self.check_distribution()

    def send_packets(self):
        random.seed(time.time())
        sport = 0x1234
        dport = 0x50
        router_mac = self.test_params['router_mac']
        destanation_ports = range(NUMBER_OF_SRC_PORTS,NUMBER_OF_DST_PORTS+NUMBER_OF_SRC_PORTS)
        self.log("the router mac is %s" % router_mac)
        self.log("the rif macs are:")
        for i in range(16):
            self.log("    %s" % self.dataplane.get_mac(0, i+16))

        #send packets
        for port in xrange(NUMBER_OF_SRC_PORTS):
            for i in xrange(IP_LAST_WORD_RANGE):
                for j in xrange(IP_2ND_LAST_WORD_RANGE):
                    ip_src = '10.0.0.' + str(port * 2 + 32)
                    src_mac = self.dataplane.get_mac(0, 0)
                    ip_dst = '172.16.' + str(j) + '.' + str(i + 1)

                    pkt = simple_tcp_packet(
                                        eth_dst=router_mac,
                                        eth_src=src_mac,
                                        ip_src=ip_src,
                                        ip_dst=ip_dst,
                                        ip_id=i*j*port,
                                        tcp_sport=sport,
                                        tcp_dport=dport,
                                        ip_ttl=64)
                    exp_pkt = simple_tcp_packet(
                                        eth_dst=self.dataplane.get_mac(0, 16),
                                        eth_src=router_mac,
                                        ip_src=ip_src,
                                        ip_dst=ip_dst,
                                        ip_id=i*j*port,
                                        tcp_sport=sport,
                                        tcp_dport=dport,
                                        ip_ttl=63)
                    masked_exp_pkt = Mask(exp_pkt)
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

                    sleep_time = 1
                    repeat = 5 # Repeat the send action until we receive a packet
                    while True:
                        send_packet(self, port, pkt)
                        self.log("Sent packet src=%s dst=%s port=%s" % (ip_src, ip_dst, port), True)
                        port_index = self.verify_packet_any_port(masked_exp_pkt, destanation_ports)
                        if port_index is None:
                            self.log("Expected packet isn't received. Repeating", True)
                            time.sleep(sleep_time)
                            sleep_time *= 2
                            repeat -= 1
                            if repeat == 0:
                                self.fail("Can't receive packet: src=%s dst=%s port=%s" % (ip_src, ip_dst, port))
                        else:
                            break
                    self.log("Received expected packet from port %d" % destanation_ports[port_index], True)

                    self.pkt_counter[port_index] += 1
                    sport = random.randint(0,0xffff)
                    dport = random.randint(0,0xffff)
        return

    def check_distribution(self):
        #final uniform distribution check

        self.log("")
        for i, counter in enumerate(self.pkt_counter):
            self.log("Port %02d counter: %d" % (i, counter))

        for stat_port in xrange(NUMBER_OF_DST_PORTS):
            self.assertTrue((self.pkt_counter[stat_port] >= ((IP_LAST_WORD_RANGE * IP_2ND_LAST_WORD_RANGE) * 0.9)),
                    "Not all paths are equally balanced, %s" % self.pkt_counter[stat_port])
            self.assertTrue((self.pkt_counter[stat_port] <= ((IP_LAST_WORD_RANGE * IP_2ND_LAST_WORD_RANGE) * 1.1)),
                    "Not all paths are equally balanced, %s" % self.pkt_counter[stat_port])

        return

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        self.log_fp.close()
        BaseTest.tearDown(self)

    def verify_packet_any_port(self, pkt, ports=[], device_number=0):
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=device_number, exp_pkt=pkt, timeout=1)

        if rcv_port in ports:
            return ports.index(rcv_port)
        else:
            return None
