'''
Description:    This file contains the MTU test for SONIC

Usage:          Examples of how to use log analyzer
                ptf --test-dir ptftests mtu_test.MtuTest  --platform remote  -t "testbed_type='t1-lag';" --relax --debug info --log-file /tmp/mtu_test.log  --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre --socket-recv-size 16384

'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *


class MtuTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test sends a jumbo ICMP echo frame with MAX MTU size and expects the reply
    back. It also sends a jumbo frame to a route destination for verifying the 
    forwarding functionality
    
    For the device configured with IP-MTU=9100, PHY-MTU=9114,
     - ICMP/IP frame, the packet-len is 9114 (This includes the 14 bytes Layer 2 Ethernet header)
    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_PACKET_LEN = 9114
    ICMP_HDR_LEN = 8

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
    
    #---------------------------------------------------------------------

    def check_icmp_mtu(self):
        '''
        @summary: Check ICMP/Ping to DUT works for MAX MTU.
        '''
        ip_src = "10.0.0.1"
        ip_dst = "10.0.0.0"
        src_mac = self.dataplane.get_mac(0, 0)

        pktlen = self.DEFAULT_PACKET_LEN

        pkt = simple_icmp_packet(pktlen=pktlen,
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_ttl=64)

        exp_pkt = simple_icmp_packet(pktlen=pktlen,
                            eth_src=self.router_mac,
                            ip_src=ip_dst,
                            ip_dst=ip_src,
                            icmp_type=0)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
         
        src_port = 0
        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)
        dst_port_list = [0,1]

        (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
        
        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return

    #---------------------------------------------------------------------

    def check_ip_mtu(self):
        '''
        @summary: Check unicast IP forwarding in DUT works for MAX MTU.
        '''
        ip_src = "10.0.0.1"
        ip_dst = "10.0.0.63"
        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_ip_packet(pktlen=self.DEFAULT_PACKET_LEN,
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_ttl=64)

        exp_pkt = simple_ip_packet(pktlen=self.DEFAULT_PACKET_LEN,
                            eth_src=self.router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_ttl=63)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        src_port = 0
        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)
        dst_port_list = [31]

        (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))
    
        return

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send packet(Max MTU) to test on Ping request/response and unicast IP destination.
        Expect the packet to be received from one of the expected ports
        """
        self.check_icmp_mtu()
        self.check_ip_mtu()
