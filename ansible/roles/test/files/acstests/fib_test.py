'''
Owner:          Hrachya Mughnetsyan <Hrachya@mellanox.com> 

Created on:     11/14/2016

Description:    This file contains the FIB test for SONIC                
                      
                Design is available in https://github.com/Azure/SONiC/wiki/FIB-Scale-Test-Plan
                      
Usage:          Examples of how to use log analyzer
                ptf --test-dir fib fib_test.FibTest  --platform remote -t 'router_mac="00:02:03:04:05:00";verbose=True;route_info="fib/route_info.txt"'
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
import logging
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils

import pprint

class FibTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test routes advertised by BGP peers of SONIC are working properly.
    The setup of peers is described in 'VM set' section in 
    https://github.com/Azure/sonic-mgmt/blob/master/ansible/README.testbed.md
    
    Routes advertized by the peers have ECMP groups. The purpose of the test is to make sure
    that packets are forwarded through one of the ports specified in route's ECMP group.
    
    
    This class receives a text file describing the bgp routes added to the switch.

    File contains informaiton about each bgp route which was added to the switch.
    
    #-----------------------------------------------------------------------
    Format of the route_info file
    #-----------------------------------------------------------------------
    Example:
        192.168.0.65/32 02,00,01,13,14,08,04,09,03,07,06,12,11,10,15,05,
        20C0:A800:0:41::/64 02,00,01,13,14,08,04,09,03,07,06,12,11,10,15,05,
    
    Meaning:
    Each entry describes IP prefix, and indexes of ports-members of ecmp group for the route.
    The packet should be received from one of those ports.
    #-----------------------------------------------------------------------
    
    The file is loaded on startup and is used to 
        - construct packet with correct destination IP
        - validate that packet arrived from switch from a port which 
        is member of ECMP group for given route.

    For each route test 
        - builds a packet with destination IP matching to the IP in the route 
        - sends packet to the switch
        - verifies that packet came back from the switch on one of 
        the ports specified in the ECMP group of the route.
    
    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    PREFIX_AND_PORT_SPLITTER=" "
    PORT_LIST_SPLITTER=","
    PORT_COUNT = 32

    '''
    Information about routes to test.
    '''
    route_info={}
    

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
    #---------------------------------------------------------------------

    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
    #---------------------------------------------------------------------
        
    def load_route_info(self, route_info_path):
        '''
        @summary: Load route_info file into self.route_info. For details see section 'Format of the route_info file' in the summary of the class.        
        @param route_info_path : Path to the file        
        '''
        with open(route_info_path, 'r') as route_info_file:
            for line in route_info_file:
                line = line.strip()
                if (0==len(line)): 
                    continue
                prefix_ports_pair = line.split(self.PREFIX_AND_PORT_SPLITTER)
                port_list = prefix_ports_pair[1].split(self.PORT_LIST_SPLITTER)
                self.route_info[prefix_ports_pair[0]]=port_list
        return
    #---------------------------------------------------------------------
    
    '''
    For diagnostic purposes only
    '''
    def print_route_info(self):
        pprint.pprint(self.route_info)
        return
    #---------------------------------------------------------------------

    def verify_packet_any_port(self, pkt, ports=[], device_number=0):
        """
        @summary: Check that the packet is received on _any_ of the specified ports belonging to
        the given device (default device_number is 0).

        The function returns when either the expected packet is received or timeout (1 second).

        Also verifies that the packet is or received on any other ports for this
        device, and that no other packets are received on the device (unless --relax
        is in effect).
        @param pkt : packet to verify
        @param ports : list of ports

        @return: index of the port on which the packet is received and the packet.
        """
        received = False
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
         self,
         device_number=device_number,
         exp_pkt=pkt,
         timeout=1
        )

        if rcv_port in ports:
         match_index = ports.index(rcv_port)
         received = True

        return (match_index, rcv_pkt, received)
    #---------------------------------------------------------------------
     
    def is_ipv4_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv4 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        is_valid_ipv4 = True
        try :
            # building ipaddress fails for some of addresses unless unicode(ipaddr) is specified for both ipv4/ipv6
            # Example - 192.168.156.129, it is valid IPV4 address, send_packet works with it.
            ip = ipaddress.IPv4Address(unicode(ipaddr))
        except Exception, e :
            is_valid_ipv4 = False

        return is_valid_ipv4
    #---------------------------------------------------------------------
        
    def is_ipv6_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv6 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        is_valid_ipv6 = True
        try :
            ip = ipaddress.IPv6Address(unicode(ipaddr))
        except Exception, e:
            is_valid_ipv6 = False

        return is_valid_ipv6
    #---------------------------------------------------------------------

    def check_ipv4_route(self, source_port_index, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv4 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch        
        @return Boolean
        '''
        sport = 0x1234
        dport = 0x50
        ip_src = "10.0.0.1"
        ip_dst = dest_ip_addr

        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_dst=self.dataplane.get_mac(0, 0),
                            eth_src=self.router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"src")

        result = False
        send_packet(self, source_port_index, pkt)

        (match_index,rcv_pkt, received) = self.verify_packet_any_port(masked_exp_pkt,destination_port_list)
        if received:
            result = True            
        else:
            print 'FAIL for ip:%s' % dest_ip_addr ,
            pprint.pprint(destination_port_list)
        return result
    #---------------------------------------------------------------------
    
    def check_ipv6_route(self, source_port_index, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv6 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch        
        @return Boolean
        '''
        sport = 0x2233
        dport = 0x60
        ip_src = '2000::1'
        ip_dst = dest_ip_addr

        src_mac = self.dataplane.get_mac(0, 0)
        
        pkt = simple_tcpv6_packet(
                                eth_dst=self.router_mac,
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst=self.dataplane.get_mac(0, 0),
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"src")

        result = False
        send_packet(self, source_port_index, pkt)

        (match_index,rcv_pkt, received) = self.verify_packet_any_port(masked_exp_pkt,destination_port_list)
        
        if received:
            result = True            
        else:
            print 'src_port:%d' % source_port_index,
            print 'FAIL for ip:%s' % dest_ip_addr ,
            pprint.pprint(destination_port_list)
        return result
    #---------------------------------------------------------------------
    
    def runTest(self):
        """
        @summary: Send packet for each route and validate it arrives 
        on one of expected ECMP ports
        """
        self.load_route_info(self.test_params["route_info"])
        pass_count = 0
        test_result = True
        result = True
        ip4_route_cnt = 0
        ip6_route_cnt = 0
        
        for prefix, port_index_list in self.route_info.iteritems() :
            dest_ip_addr = prefix.split("/")[0]
            destination_port_list = []
            for port_index in port_index_list :
                if len(port_index) > 0 :
                    destination_port_list.append(int(port_index))
            
            for src_port in xrange(0, self.PORT_COUNT):
                
                if src_port in destination_port_list: continue
                
                if self.is_ipv4_address(dest_ip_addr):
                    ip4_route_cnt += 1
                    result = self.check_ipv4_route(src_port, dest_ip_addr, destination_port_list)
                elif self.is_ipv6_address(dest_ip_addr):
                    ip6_route_cnt += 1
                    result = self.check_ipv6_route(src_port, dest_ip_addr, destination_port_list)
                else:
                    print 'Invalid ip address:%s' % dest_ip_addr
                    assert(False)

                test_result = test_result and result
                if(result):
                    pass_count = pass_count + 1
                    
        print 'pass_count:%d' % pass_count
        print 'ip4_route_cnt:%d' % ip4_route_cnt
        print 'ip6_route_cnt:%d' % ip6_route_cnt
        assert(test_result)
    #---------------------------------------------------------------------
