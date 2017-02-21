'''
Owner:          Hrachya Mughnetsyan <Hrachya@mellanox.com> 

Created on:     01/09/2017

Description:    This file contains the LAG test for SONIC                
                Design is available in https://github.com/Azure/SONiC/wiki/LAG-test-plan
                      
Usage:          Examples of how to use log analyzer
                time ptf --test-dir /root/sonic-mgmt/ansible/roles/test/files/acstests lag_test.LagAllRoutes --platform remote -t "verbose=True;router_mac='00:02:03:04:05:00';lag_info='/tmp/lag.txt'"
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
from router_utils import *
import pprint

class LagAllRoutes(BaseTest,RouterUtility):
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
    Format of the lag_info file
    #-----------------------------------------------------------------------
    Example:
        192.168.0.0/32 [0,1];[2,3];[4,5];[6,7];[8,9];[10,11];[12,13];[14,15]
        20C0:A800:0:00::/64 [0,1];[2,3];[4,5];[6,7];[8,9];[10,11];[12,13];[14,15]
        
        172.16.7.4/32 [22]
        20AC:1007:0:04::/64 [22]
    
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
    VERBOSE_OUT = True
    
    '''
        Number of copies of the packet to send.
        Currently set to 1. We may decide to increase this in next stages of the test.
    '''
    IPV4_SEND_PACKET_COPY_CNT = 1
    IPV6_SEND_PACKET_COPY_CNT = 1

    '''
    Information about LAG to test.
    '''
    lag_info={}
    

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
    
    def print_verbose(self, msg):
        if(not self.VERBOSE_OUT):
            return
        print msg
    #---------------------------------------------------------------------
    
    def load_lag_info(self, lag_info_path):
        '''
        @summary: Load lag_info file into self.lag_info. For details see section 'Format of the lag_info file' in the summary of the class.        
        @param lag_info_path : Path to the file        
        '''
        with open(lag_info_path, 'r') as lag_info_file:
            for line in lag_info_file:
                line = line.strip()
                if (0==len(line)): 
                    continue
                prefix_ports_pair = line.split(PREFIX_AND_PORT_SPLITTER)
                port_group_list = prefix_ports_pair[1].split(PORT_GROUP_SPLITTER)
                self.lag_info[prefix_ports_pair[0]]=[]
                for port_group in port_group_list:
                    lag_members = port_group[1:-1].split(PORT_LIST_SPLITTER)
                    self.lag_info[prefix_ports_pair[0]].append(lag_members)

        return
    #---------------------------------------------------------------------
    
    '''
    For diagnostic purposes only
    '''
    def print_lag_info(self):
        pprint.pprint(self.lag_info)
        return
    #---------------------------------------------------------------------
    
    def get_spine_ecmp_group(self):
        '''
        @summary: return ecmp group for spine routes
        '''
        for prefix, port_group_list in self.lag_info.iteritems() :
            if len(port_group_list) <= 1 :
                continue
            return port_group_list
            
        return None
    #---------------------------------------------------------------------
    
    def get_lag_total_cnt(self, lag_port_group, port_cnt_map):
        '''
        @summary: Return total number of packets received by given lag.
        @param: lag_port_group - index of lag
        @param: port_cnt_map - map<port_index, packet_counter>
        '''
        # total packet count for current LAG
        lag_total_cnt = 0
        for port_ind in lag_port_group:
            if int(port_ind) in port_cnt_map:
                lag_total_cnt += port_cnt_map[int(port_ind)]
        return lag_total_cnt        
    #---------------------------------------------------------------------
    
    def check_packet_count_ratio(self, actaul_counts, expected_counts, expected_ratio):
        '''
        @summary: Check actual packets are in +/- expected ratio of expected packet count
        '''
        ratio = abs(actaul_counts - expected_counts) / expected_counts
        self.print_verbose('ratio:%f' % ratio)
        
        if (ratio > expected_ratio):            
            return False
        return True
    #---------------------------------------------------------------------
    
    def check_lag_member_counts(self, port_cnt_map, ecmp_group_list, expected_ratio = 0.25, inactive_lag_info = None):
        '''
        @summary: Check traffic distributed between lag memeber ports inside each lag.
        @param port_cnt_map: map with collected port counters during runtime
        @ecmp_group_list: list of lags, each containing list of member ports.
        @expected_ratio: Amount of packets received on a lag member shuold be in 
        'expected_ratio' with expected amount of packets on a lag member.
        The expected amount of packets == total packets on lag / number of members.
        @return Boolean
        '''
        self.print_verbose('\ncheck_lag_member_counts --------------\n')
        self.print_verbose('expected_ratio:%f'%expected_ratio)
        if self.VERBOSE_OUT:
            pprint.pprint(port_cnt_map)
        
        if (expected_ratio < 0) or (expected_ratio > 1):
            print 'ERROR: expected_ratio:%d must be in [0,1] value range' % expected_ratio
            return False
        
        result = True        

        # process each LAG
        for group_idx, port_group in enumerate(ecmp_group_list) :
            
            self.print_verbose('\ncheck lag[%d] members ----------------' % group_idx)
            
            # total packet count for current LAG
            lag_total_cnt = self.get_lag_total_cnt(port_group, port_cnt_map)
            
            if inactive_lag_info is not None:
                if group_idx == inactive_lag_info[0]:
                    self.print_verbose('lag[%d] member marked as inactive' % group_idx)
                    if lag_total_cnt != 0:
                        self.print_verbose('ERROR: lag[%d] member:%d is marked as inactive, but total lag count is not 0, count:%d' % (group_idx, inactive_lag_info[0], lag_total_cnt))
                    result = result and (lag_total_cnt == 0)
                    continue
            
            if lag_total_cnt == 0:            
                self.print_verbose('lag received 0 packets')
                continue
            
            # expected count on each lag member
            expected_cnt_per_member = float(lag_total_cnt) / len(port_group)
            
            self.print_verbose('lag_total_cnt:%d' % lag_total_cnt)
            self.print_verbose('expected_cnt_per_member:%f' % expected_cnt_per_member)
            
            curr_port_member_actual_count = 0
            for arr_ind, port_ind in enumerate(port_group):
                curr_port_member_actual_count = 0
                if int(port_ind) in port_cnt_map:
                    curr_port_member_actual_count = port_cnt_map[int(port_ind)]
                self.print_verbose('lag[%d].port[%d](port:%d) cnt:%d' % (group_idx, arr_ind, int(port_ind), curr_port_member_actual_count))

                self.print_verbose('curr_port_member_actual_count:%d' % curr_port_member_actual_count)
                
                lag_member_result = self.check_packet_count_ratio(curr_port_member_actual_count, expected_cnt_per_member, expected_ratio)
                if not lag_member_result:
                    print 'ERROR: counters for lag group:%d not correct' % group_idx
                result = result and lag_member_result
                
        return result
            
    #---------------------------------------------------------------------
    def check_lag_counts(self, port_cnt_map, ecmp_group_list, expected_ratio = 0.25, inactive_lag_info = None):
        '''
        @summary: Check traffic distributed between lags
        @param port_cnt_map: map with collected port counters during runtime
        @param inactive_lag_info: tuple <lag_index, inactive_member_index>
        @return Boolean
        '''
        self.print_verbose('\ncheck_lag_counts ------------\n')
        self.print_verbose('expected_ratio%f'%expected_ratio)
        if self.VERBOSE_OUT:
            pprint.pprint(port_cnt_map)

        if (expected_ratio < 0) or (expected_ratio > 1):
            print 'ERROR: expected_ratio:%d must be in [0,1] value range' % expected_ratio
            return False

        result = True       
        
        lag_counter = {}
        lag_total_cnt = 0
        # get counters for each LAG, and total across all LAGs.
        for group_idx, port_group in enumerate(ecmp_group_list) :
            # total packet count for current LAG
            lag_cnt = self.get_lag_total_cnt(port_group, port_cnt_map)
            self.print_verbose('lag[%d] counter:%d' % (group_idx, lag_cnt))
            
            if (inactive_lag_info is not None) and (group_idx == inactive_lag_info[0]):
                    self.print_verbose('lag[%d] member:%d marked as inactive.'%(group_idx,inactive_lag_info[1]))
                    if lag_cnt != 0:
                        self.print_verbose('ERROR: counter of inactive lag[%d] is not 0. counter:%d' % (group_idx, lag_cnt))
                        result = False
            else:
                lag_counter[group_idx] = lag_cnt
            lag_total_cnt += lag_cnt
            
        self.print_verbose('lag_total_cnt:%d' % lag_total_cnt)
        if self.VERBOSE_OUT:
            print 'lag counters:', 
            pprint.pprint(lag_counter)
            
        if lag_total_cnt == 0:
            self.print_verbose('No traffic passed through any of lags')
            return False

        # expected count on each lag member
        expected_cnt_per_lag = float(lag_total_cnt) / len(lag_counter)
        self.print_verbose('expected_cnt_per_lag:%f' % expected_cnt_per_lag)

        # check counter on each LAG
        for lag_ind, actual_lag_cnt in lag_counter.iteritems():
            self.print_verbose('\ncheck lag[%d] ----------------' % lag_ind)
            self.print_verbose('actual_lag_cnt:%d' % actual_lag_cnt)
            lag_result = self.check_packet_count_ratio(actual_lag_cnt, expected_cnt_per_lag, expected_ratio)
            if not lag_result:
                print 'ERROR: counters for lag:%d not correct' % lag_ind
            result = result and lag_result

        return result
    #---------------------------------------------------------------------
    
    def update_port_counter(self, port_counter, rcv_port_ind, count):
        '''
        @summary: update(increment) packet counter for given phisical port
        @param port_counter: map<port_index, integer> holding counters for each port
        @param rcv_port_ind: port for which to update the counter
        @param count: amount by which to update the counter
        '''
        if rcv_port_ind in port_counter:
            port_counter[rcv_port_ind] += count
        else:
            port_counter[rcv_port_ind] = count

    #---------------------------------------------------------------------
    def generate_ipv4_list(self, outer_range = 254, inner_range = 16):
        '''
        @summary: Generate list of ipv4 addresses to be used for packet generation
        @param outer_range: range of values for -.-.X.- component of IP address
        @param inner_range: range of values for -.-.-.X component of IP address
        '''
        # Generate SRC IP list for packets.
        src_ipv4_list = []
        IP_LAST_WORD_RANGE = outer_range#max 254
        IP_2ND_LAST_WORD_RANGE = inner_range#max 16
        for i in xrange(IP_LAST_WORD_RANGE):
                for j in xrange(IP_2ND_LAST_WORD_RANGE):
                    src_ipv4_addr = '10.0.' + str(j) + '.' + str(i+1)
                    src_ipv4_list.append(src_ipv4_addr)        
        return src_ipv4_list

    #---------------------------------------------------------------------
    def generate_ipv6_list(self, outer_range = 5, inner_range = 10):
        '''
        @summary: Generate list of ipv6 addresses to be used for packet generation
        @param outer_range: range of values for ---X::- component of IP address
        @param inner_range: range of values for ----::X component of IP address
        '''
        # Generate SRC IP list for packets.
        src_ipv6_list = []
        for i in xrange(outer_range):
                for j in xrange(inner_range):
                    src_ipv6_addr = '200' + str(i) + '::' + str(j)
                    src_ipv6_list.append(src_ipv6_addr)
        return src_ipv6_list
    #---------------------------------------------------------------------
    
    def get_inactive_lag_info(self):
        '''
        @summary:   parse test_params for information about inactive lag.
                    lag_index specifies index of the lag which is inactive.
                    member_index specifies index of the lag member port which is inactive.
        '''
        inactive_lag_info = None
        lag_index = None
        member_index = None
        if 'lag_index' in self.test_params:
            lag_index = self.test_params["lag_index"]
        
        if 'member_index' in self.test_params:
            member_index = self.test_params["member_index"]
        
        if (lag_index is None) and (member_index is None):
            inactive_lag_info = None
        elif (lag_index is not None) and (member_index is not None):
            inactive_lag_info = (lag_index, member_index)
        else:
            print 'Invalid input parameters for inactive lag state'
            assert(False)
            
        return inactive_lag_info
    
    #---------------------------------------------------------------------
    
    def runTest(self):
        """
        @summary: Send packet for each route and validate it arrives 
        on one of expected ECMP ports
        """

        self.load_lag_info(self.test_params["lag_info"])
        inactive_lag_info = self.get_inactive_lag_info()
        pprint.pprint(inactive_lag_info)
        passed_prefic_count = 0
        test_result = True
        result = True
        total_ipv4_packet_cnt = 0
        total_ipv6_packet_cnt = 0
        port_counter = {}
        src_ipv4_list = []
        src_ipv6_list = []
        
        
        for prefix, port_group_list in self.lag_info.iteritems() :
            dest_ip_addr = prefix.split("/")[0]
            destination_port_list = []
            
            # Generate list of destination ports to receive packet from for current route
            for port_group in port_group_list :
                for port_index in port_group:
                    destination_port_list.append(int(port_index))
                    
            # send packet through each port which is NOT in the list of destination ports,
            # otherwise there will be a loop-back and switch will drop packets
            # Pick random port to send through
            src_port = random.randint(0, PORT_COUNT-1)
            while src_port in destination_port_list:
                src_port = random.randint(0, PORT_COUNT-1)
            
            
            # Generate ipv4 and ipv6 packets to be sent.
            # Format: map<src_ip_string, pair(packet_to_send, expected_packet)>
            ipv4_packets = {}
            ipv6_packets = {}            
            
            if self.is_ipv4_address(dest_ip_addr):
                if 'skip_ipv4' in self.test_params:
                    continue
                #Generate list of src_ip addresses. Currently we generate only 1 src_ip, but
                #in next stages of test we'll generate N amount(tbd).
                src_ipv4_list = self.generate_ipv4_list(1,1)
                
                for ipv4_src in src_ipv4_list :
                    sport = random.randint(0,0xffff)
                    dport = random.randint(0,0xffff)
                    src_mac = self.create_random_mac()
                    ipv4_packets[ipv4_src] = self.create_ipv4_packets(ipv4_src, sport, dport, dest_ip_addr, destination_port_list, src_mac)

                for src_ip in ipv4_packets:
                    total_ipv4_packet_cnt += self.IPV4_SEND_PACKET_COPY_CNT
                    ret_val, rcv_port_ind = self.check_route(ipv4_packets[src_ip][0], ipv4_packets[src_ip][1], src_port, dest_ip_addr, destination_port_list, self.IPV4_SEND_PACKET_COPY_CNT)
                    result = result and ret_val
                    self.update_port_counter(port_counter, destination_port_list[rcv_port_ind], self.IPV4_SEND_PACKET_COPY_CNT)

            elif self.is_ipv6_address(dest_ip_addr):
                if 'skip_ipv6' in self.test_params:
                    continue
                #Generate list of src_ip addresses. Currently we generate only 1 src_ip, but
                #in next stages of test we'll generate N amount(tbd).
                src_ipv6_list = self.generate_ipv6_list(1,1)
                
                for ipv6_src in src_ipv6_list :
                    sport = random.randint(0,0xffff)
                    dport = random.randint(0,0xffff)
                    src_mac = self.create_random_mac()
                    ipv6_packets[ipv6_src] = self.create_ipv6_packets(ipv6_src,  sport, dport, dest_ip_addr, destination_port_list, src_mac)
                
                for src_ip in ipv6_packets:
                    total_ipv6_packet_cnt += self.IPV6_SEND_PACKET_COPY_CNT
                    ret_val, rcv_port_ind = self.check_route(ipv6_packets[src_ip][0], ipv6_packets[src_ip][1], src_port, dest_ip_addr, destination_port_list, self.IPV6_SEND_PACKET_COPY_CNT)
                    result = result and ret_val
                    self.update_port_counter(port_counter, destination_port_list[rcv_port_ind], self.IPV6_SEND_PACKET_COPY_CNT)
            else:
                print 'Invalid ip address:%s\n' % dest_ip_addr
                assert(False)

            test_result = test_result and result
            if(result):
                passed_prefic_count = passed_prefic_count + 1
            
        
        spine_ecmp_group = self.get_spine_ecmp_group()
        lag_member_counter_check = self.check_lag_member_counts(port_counter, spine_ecmp_group, 0.25, inactive_lag_info)
        lag_counter_check = self.check_lag_counts(port_counter, spine_ecmp_group, 0.25, inactive_lag_info)
        
        print 'passed routes count:%d' % passed_prefic_count
        print 'total_ipv4_packet_cnt:%d' % total_ipv4_packet_cnt
        print 'total_ipv6_packet_cnt:%d' % total_ipv6_packet_cnt

        assert(lag_member_counter_check)
        assert(lag_counter_check)
                    
        assert(test_result)
    #---------------------------------------------------------------------
