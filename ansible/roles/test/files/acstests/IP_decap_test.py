'''
Owner:          Dor Marcus <Dorm@mellanox.com> 
Created on:     12/09/2017
Description:    This file contains the Decapasulation test for SONIC, to test Decapsulation of IPv4 with double and triple encapsulated packets                
                      
                Design is available in https://github.com/Azure/SONiC/wiki/IPv4-Decapsulation-test
                
Precondition:   Before the test start, all routes need to be defined as in the route_info.txt file, in addition to the decap rule that need to be set as the dspc_mode
topology:         The test need to run on non-lag systems with at least 31 active ports
                      
Usage:          Examples of how to start the test 
                ptf  --test-dir /root/dor/ ip_decap_test_red --platform remote -t "verbose=True;route_info='/tmp/route_info.txt';lo_ip='10.1.0.32';router_mac='00:02:03:04:05:00';dscp_mode='pipe'"  --log-dir /tmp/logs --verbose 
Parameters:    route_info - The route_info file location 
                       lo_ip -  The loop_back IP that is configured in the decap rule
                       router_mac - The mac of the router_mac
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
from router_utils import *


#---------------------------------------------------------------------
# Global variables
#---------------------------------------------------------------------
PREFIX_AND_PORT_SPLITTER=" "
PORT_LIST_SPLITTER=","
PORT_COUNT = 31

class DecapPacketTest(BaseTest, RouterUtility):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
	#-----------------------------------------------------------------
    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
    #-----------------------------------------------------------------
    
    def send_and_verify(self, dst_ip, expected_ports, src_port, triple_encap = False):
        '''
        @summary: This function builds encap packet, send and verify their arrival, When a packet will not arrived as expected an exeption will be throwen 
        @dst_ip: the destination ip for the inner IP header
        @expected_ports: list of ports that a packet can arrived from 
        @src_port: the physical port that the packet will be sent from 
        @triple_encap: Bool if to send triple encapsulated packet
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
        
        #building the packets  and the expected packets
        if (not triple_encap):
            #for the double encap packet we will use IP header with TCP header without mac    
            inner_pkt = simple_ip_only_packet(ip_dst=dst_ip, ip_src=inner_src_ip, ip_ttl=64)
            #after the decap process the retuning packet will be normal tcp packet, The TTL is taked from the inner layer and redused by one
            exp_pkt = simple_tcp_packet(pktlen=114, 
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
            inner_pkt  = scapy.IP(src=inner_src_ip, dst=dst_ip, tos=tos_in, ttl=64, id=1, ihl=None,proto =4) / inner_pkt2
            inner_pkt  = inner_pkt/("".join([chr(x) for x in xrange(100 - len(inner_pkt))]))
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
        (match_index, rcv_pkt) = verify_packet_any_port(self, masked_exp_pkt, expected_ports)
    #-----------------------------------------------------------------
    
    def runTest(self):
        test_result = True
        random.seed(1)
        self.load_route_info(self.test_params["route_info"])
        default_route_ports =[]
        unicast_ip = 'none'
        unicast_dst_port = []
        print self.route_info.iteritems()
        #running on the routes_info file and extractin ECMP route and unicast route
        for prefix, port_index_list in self.route_info.iteritems():
            dest_ip_addr = prefix.split("/")[0]
			
            if (self.is_ipv6_address(dest_ip_addr)): 
				continue
				
            if (len(port_index_list) > 1):
                for port_index in port_index_list:
                    if (len(port_index)> 0): 
						default_route_ports.append(int(port_index))
                default_route_dst_ip = dest_ip_addr
            elif (len(port_index_list) == 1): 
                unicast_ip = dest_ip_addr
                unicast_dst_port = [int(port_index_list[0])]
            #when found unicast and ECMP routes stop    
            if ((unicast_ip != 'none') and (len(default_route_ports) != 0)): 
				break
        
        #Sending double and triple encapsulated packets from all ports with unicast and ECMP IP routes
        for src_port in range(PORT_COUNT):
            
            try:
                self.send_and_verify(default_route_dst_ip, default_route_ports, src_port)
            except:
                print("ERROR: failed to send encap packet with default route from port: " + str(src_port)) 
                test_result = False
           
            try:   
                self.send_and_verify(default_route_dst_ip, default_route_ports, src_port, True)
            except:
                print("ERROR: failed to send triple encap packet with default route from port: " + str(src_port)) 
                test_result = False
            
            try:   
                self.send_and_verify(unicast_ip, unicast_dst_port, src_port)
            except:
                print("ERROR: failed to send encap packet with unicast route from port: " + str(src_port))
                test_result = False
            
            try:   
                self.send_and_verify(unicast_ip, unicast_dst_port, src_port, True)
            except:
                print("ERROR: faield to send triple encap packet with unicast route from port: " + str(src_port))
                test_result = False
                
        assert(test_result)
#---------------------------------------------------------------------

    
