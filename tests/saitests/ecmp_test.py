"""
SONiC Dataplane ECMP tests
"""
import random
import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane
import sai_base_test
from ptf.testutils import *
from ptf.mask import Mask
from switch import *

# Constants
IP_LAST_WORD_RANGE = 254
IP_2ND_LAST_WORD_RANGE = 16
NUMBER_OF_SRC_PORTS = 16
NUMBER_OF_DST_PORTS = 16

class ECMPtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        """
        For SONiC
        testing ECMP uniformn distribution over 16 RIFs from 16 differnt ports
        ---- Test require 32 connected ports and SONiC up and running ----
        ---- MUST RUN WITH "--relax" option on the ptf running line   ----
        Preliminary steps
        1. Configure IPs of all of the connected ports
        (SONiC will configure neighbors)
        2. configure all routes (run add_routes.sh on SONiC)

        Test structure
        Sending Packets sequance
        1. Main loop running on 16 sources ports
        2. IP_LAST_WORD_RANGE loop running from 0-254
        3. IP_2ND_LAST_WORD_RANGE loop running 0-15
        4. Inside loop, to increase the number of packets, with differnt ports
        5. Sending and reciving packets, and counting destanation ports
        - Final counters checking for uniform distribution

        Final steps
        For cleaning configuration run remove_routes.sh from SONiC
        """
        switch_init(self.client)
        random.seed(1)
        #init vars
        sport = 0x1234
        dport = 0x50
        router_mac = self.test_params['router_mac']
        destanation_ports = range(NUMBER_OF_SRC_PORTS,NUMBER_OF_DST_PORTS+NUMBER_OF_SRC_PORTS)
        pkt_counter = [0]*32
        logging.debug("the router mac is ")
        logging.debug( router_mac)
        logging.debug("the rif macs are")
        for i in range(16): logging.debug( self.dataplane.get_mac(0, i+16))
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
                                        ip_id=i,
                                        tcp_sport=sport,
                                        tcp_dport=dport,
                                        ip_ttl=64)
                    exp_pkt = simple_tcp_packet(
                                        eth_dst=self.dataplane.get_mac(0, 16),
                                        eth_src=router_mac,
                                        ip_src=ip_src,
                                        ip_dst=ip_dst,
                                        ip_id=i,
                                        tcp_sport=sport,
                                        tcp_dport=dport,
                                        ip_ttl=63)
                    masked_exp_pkt = Mask(exp_pkt)
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

                    send_packet(self, port, pkt)
                    (match_index,rcv_pkt) = verify_packet_any_port(self,masked_exp_pkt,destanation_ports)
                    logging.debug("found expected packet from port %d" % destanation_ports[match_index])
                    pkt_counter[match_index] += 1
                    sport = random.randint(0,0xffff)
                    dport = random.randint(0,0xffff)

        #final uniform distribution check
        for stat_port in xrange(NUMBER_OF_DST_PORTS):
            logging.debug( "PORT #"+str(hex(port_list[stat_port+NUMBER_OF_SRC_PORTS]))+":")
            logging.debug(str(pkt_counter[stat_port]))
            self.assertTrue((pkt_counter[stat_port ] >= ((IP_LAST_WORD_RANGE * IP_2ND_LAST_WORD_RANGE) * 0.9)),
                    "Not all paths are equally balanced, %s" % pkt_counter[stat_port+NUMBER_OF_SRC_PORTS])
            self.assertTrue((pkt_counter[stat_port ] <= ((IP_LAST_WORD_RANGE * IP_2ND_LAST_WORD_RANGE) * 1.1)),
                    "Not all paths are equally balanced, %s" % pkt_counter[stat_port+NUMBER_OF_SRC_PORTS])
        print "END OF TEST"

