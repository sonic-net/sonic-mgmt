'''
Description:    This file contains the Decapasulation test for SONIC, to test Decapsulation of IPv4 with double and triple encapsulated packets                
                      
                Design is available in https://github.com/Azure/SONiC/wiki/IPv4-Decapsulation-test
                
Precondition:   Before the test start, all routes need to be defined as in the fib_info.txt file, in addition to the decap rule that need to be set as the dspc_mode
topology:       SUpports t1, t1-lag, t0-116 and t0 topology
                      
Usage:          Examples of how to start the test 
                ptf  --test-dir /root/dor/ ip_decap_test_red --platform remote -t "verbose=True;fib_info='/root/fib_info.txt';lo_ip='10.1.0.32';router_mac='00:02:03:04:05:00';dscp_mode='pipe'; testbed_type='t1'"  --log-dir /tmp/logs --verbose 
Parameters:     fib_info - The fib_info file location 
                lo_ip -  The loop_back IP that is configured in the decap rule
                router_mac - The mac of the router_mac
                testbed_type - The type of testbed topology
                dscp_mode - The rule for the dscp parameter in the decap packet that is configured in the JSON file ('pipe' for inner and 'uniform' for outer)
                
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import random
import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane

from ptf.testutils import *
from ptf.mask import Mask
import ipaddress

import os
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils

import pprint

import fib

class DecapPacketTest(BaseTest):
    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
        #-----------------------------------------------------------------
    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.fib = fib.Fib(self.test_params['fib_info'])
        if self.test_params['testbed_type'] == 't1' or self.test_params['testbed_type'] == 't1-lag':
            self.src_ports = range(0, 32)
        if self.test_params['testbed_type'] == 't1-64-lag':
            self.src_ports = [0, 1, 4, 5, 16, 17, 20, 21, 34, 36, 37, 38, 39, 42, 44, 45, 46, 47, 50, 52, 53, 54, 55, 58, 60, 61, 62, 63]
        if self.test_params['testbed_type'] == 't0':
            self.src_ports = range(1, 25) + range(28, 32)
        if self.test_params['testbed_type'] == 't0-64':
            self.src_ports = [0,  1,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 36, 37, 38, 39, 40, 41, 42, 48, 52, 53, 54, 55, 56, 57, 58]
        if self.test_params['testbed_type'] == 't0-116':
            self.src_ports = range(0, 24) + range(32, 120)
    #-----------------------------------------------------------------
    
    def send_and_verify(self, dst_ip, expected_ports, src_port, triple_encap = False):
        '''
        @summary: This function builds encap packet, send and verify their arrival.
        @dst_ip: the destination ip for the inner IP header
        @expected_ports: list of ports that a packet can arrived from 
        @src_port: the physical port that the packet will be sent from 
        @triple_encap: True to send triple encapsulated packet
        '''
        #setting parameters
        src_mac =  self.dataplane.get_mac(0, 0)
        dst_mac = '00:11:22:33:44:55'
        inner_src_ip = '2.2.2.2'
        router_mac = self.test_params['router_mac']
        dscp_in = random.randint(0, 32)
        tos_in = dscp_in << 2
        dscp_out = random.randint(0, 32)
        tos_out = dscp_out << 2
        if ("pipe" == self.test_params['dscp_mode']):
            exp_tos = tos_in
        elif("uniform" == self.test_params['dscp_mode']):
            exp_tos = tos_out
        else:
            print("ERROR: no dscp is configured")
            exit()

        default_packet_len = 100
        default_packet_add_header_len = 114

        #building the packets  and the expected packets
        if (not triple_encap):
            #for the double encap packet we will use IP header with TCP header without mac    
            inner_pkt = simple_ip_only_packet(ip_dst=dst_ip, ip_src=inner_src_ip, ip_ttl=64, ip_tos=tos_in)
            #after the decap process the retuning packet will be normal tcp packet, The TTL is taked from the inner layer and redused by one
            exp_pkt = simple_tcp_packet(pktlen=default_packet_add_header_len,
                                        eth_dst=dst_mac,
                                        eth_src=router_mac,
                                        ip_dst=dst_ip,
                                        ip_src=inner_src_ip,
                                        ip_tos=exp_tos,
                                        ip_ttl=63)
        else:
            #Building triple encap packet with SCAPY, because there is no PTF function for it, I use the defualt values for the TCP header
            tcp_hdr    = scapy.TCP(sport=1234, dport=80, flags="S", chksum=0)
            inner_pkt2 = scapy.IP(src='4.4.4.4', dst='3.3.3.3', tos=0, ttl=64, id=1, ihl=None) / tcp_hdr
            inner_pkt  = scapy.IP(src=inner_src_ip, dst=dst_ip, tos=tos_in, ttl=64, id=1, ihl=None,proto=4) / inner_pkt2
            inner_pkt  = inner_pkt/("".join([chr(x) for x in xrange(default_packet_len - len(inner_pkt))]))
            #The expected packet is also built by scapy, and the TTL is taked from the inner layer and redused by one
            exp_pkt    = scapy.Ether(dst=dst_mac, src=router_mac)/inner_pkt   
            exp_pkt['IP'].tos = exp_tos #this parameter is taken by the decap rule configuration 
            exp_pkt['IP'].ttl = 63

        pkt = simple_ipv4ip_packet(
                            eth_dst=router_mac,
                            eth_src=src_mac,
                            ip_src='1.1.1.1',
                            ip_dst=self.test_params['lo_ip'],
                            ip_tos=tos_out,
                            ip_ttl=random.randint(2, 63), 
                            inner_frame=inner_pkt)
        
        #send and verify the return packets
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        send_packet(self, src_port, pkt)
        logging.info(".....Sending packet from port" + str(src_port) + " to " + dst_ip + ", Triple_encap: " + str(triple_encap))
        (matched, received) = verify_packet_any_port(self, masked_exp_pkt, expected_ports)
        assert received
        return (matched, received)
    #-----------------------------------------------------------------
    
    def runTest(self):
        """
        @summary: Send double and triple encapsulated packets for each range of IPv4 and
        expect the packet to be received from one of the expected ports
        """
        # IPv4 Test
        for ip_range in self.fib.ipv4_ranges():
            # Get the expected list of ports that would receive the packets
            exp_port_list = self.fib[ip_range.get_first_ip()].get_next_hop_list()
            # Choose random one source port from all ports excluding the expected ones
            src_port = random.choice([port for port in self.src_ports if port not in exp_port_list])

            if not len(exp_port_list):
                continue

            logging.info("Check IP range:" + str(ip_range) + " on " + str(exp_port_list) + "...")
            # Send a packet with the first IP in the range
            self.send_and_verify(ip_range.get_first_ip(), exp_port_list, src_port)
            self.send_and_verify(ip_range.get_first_ip(), exp_port_list, src_port, True)
            # Send a packet with the last IP in the range
            if ip_range.length() > 1:
                self.send_and_verify(ip_range.get_last_ip(), exp_port_list, src_port)
                self.send_and_verify(ip_range.get_last_ip(), exp_port_list, src_port, True)
            # Send a packet with a random IP in the range
            if ip_range.length() > 2:
                self.send_and_verify(ip_range.get_random_ip(), exp_port_list, src_port)
                self.send_and_verify(ip_range.get_random_ip(), exp_port_list, src_port, True)
#---------------------------------------------------------------------

    
