# PTF test contains the test cases for fine grained ecmp, the scenarios of test are as follows:
# create_flows: Sends NUM_FLOWS flows with varying src_Ip and creates a tuple to port map
# initial_hash_check: Checks the the flows from create_flows still end up at the same port
# withdraw_nh: Withdraw next-hop in one fg nhg bank, and make sure flow redistributes to ports in the fg nhg bank
# add_nh: Add next-hop in one fg nhg bank, and make sure flow redistributes to from ports in same fg nhg bank to added port
# withdraw_bank: Withdraw all next-hops which constitue a bank, and make sure that flows migrate to using the other bank
# add_first_nh: Add 1st next-hop from previously withdrawn bank, and make sure that some flow migrate back to using the next-hop in old bank


import ipaddress
import logging
import random
import time
import os
import json
import ipaddress

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.testutils import *

PERSIST_MAP = '/tmp/fg_ecmp_persist_map.json'

class FgEcmpTest(BaseTest):

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------
    def log(self, message):
        logging.info(message)


    def trigger_mac_learning(self, ip_to_port):
      	for src_ip, src_port in ip_to_port.items():
            pkt = simple_eth_packet(
                eth_dst=self.router_mac,
                eth_src=self.dataplane.get_mac(0, src_port),
                eth_type=0x1234)

            send_packet(self, src_port, pkt) 


    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.test_params = testutils.test_params_get()
        self.max_deviation = 0.25
        if 'test_case' in self.test_params:
            self.test_case = self.test_params['test_case']
        else:
            raise Exception("Need a test case param")

        if self.test_case == 'withdraw_nh':
            self.withdraw_nh_port = self.test_params['withdraw_nh_port']
        elif self.test_case == 'add_nh':
            self.add_nh_port = self.test_params['add_nh_port']
        elif self.test_case == 'withdraw_bank':
            self.withdraw_nh_bank = self.test_params['withdraw_nh_bank']
        elif self.test_case == 'add_first_nh':
            self.first_nh = self.test_params['first_nh'] 

        if 'config_file' not in self.test_params:
            raise Exception("required parameter 'config_file' is not present")
        config = self.test_params['config_file']

        if 'exp_flow_count' not in self.test_params:
            raise Exception("required parameter 'exp_flow_count' is not present")
        self.exp_flow_count = self.test_params['exp_flow_count']

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.net_ports = graph['net_ports']
        self.exp_ports = graph['port_list']
        self.exp_port_set_one = graph['bank_0_port']
        self.exp_port_set_two = graph['bank_1_port']
        self.dst_ip = graph['dst_ip']
        self.router_mac = graph['dut_mac']
        self.ip_to_port = graph['ip_to_port']
        self.num_flows = graph['num_flows']
        self.inner_hashing = graph['inner_hashing']

        self.log(self.net_ports)
        self.log(self.exp_ports)
        self.log(self.exp_port_set_one)
        self.log(self.exp_port_set_two)
        self.log(self.dst_ip)
        self.log(self.router_mac)
        self.log(self.test_case)
        self.log(self.ip_to_port)
        self.log(self.num_flows)
        self.log(self.inner_hashing)
        self.log(self.exp_flow_count)

        self.trigger_mac_learning(self.ip_to_port)
        time.sleep(3)


    #---------------------------------------------------------------------
    def test_balancing(self, hit_count_map):
        for port, exp_flows in self.exp_flow_count.items():
            assert port in hit_count_map
            num_flows = hit_count_map[port]
            deviation = float(num_flows)/float(exp_flows)
            deviation = abs(1-deviation)
            self.log("port "+ str(port) + " exp_flows " + str(exp_flows) + 
                    " num_flows " + str(num_flows) + " deviation " + str(deviation))
            assert deviation <= self.max_deviation


    def fg_ecmp(self):
        ipv4 = isinstance(ipaddress.ip_address(self.dst_ip.decode('utf8')),
                ipaddress.IPv4Address)

        if self.inner_hashing:
            base_ip = ipaddress.ip_address(u'8.0.0.0')
        else:
            if isinstance(ipaddress.ip_address(self.dst_ip.decode('utf8')), ipaddress.IPv4Address):
                base_ip = ipaddress.ip_address(u'8.0.0.0')
            else:
                base_ip = ipaddress.ip_address(u'20D0:A800:0:00::')

        # initialize all parameters
        if self.inner_hashing:
            dst_ip = '5.5.5.5'
        else:
            dst_ip = self.dst_ip
        src_port = 20000
        dst_port = 30000

        tuple_to_port_map ={}
        hit_count_map = {}

        if self.test_case == 'create_flows':
            # Send packets with varying src_ips to create NUM_FLOWS unique flows
            # and generate a flow to port map
            self.log("Creating flow to port map ...")
            for i in range(0, self.num_flows):
                src_ip = str(base_ip + i)
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                tuple_to_port_map[src_ip] = port_idx
            self.test_balancing(hit_count_map)

            json.dump(tuple_to_port_map, open(PERSIST_MAP,"w"))
            return

        elif self.test_case == 'initial_hash_check':
            with open(PERSIST_MAP) as fp:
                tuple_to_port_map = json.load(fp)
            assert tuple_to_port_map
            # step 2: Send the same flows once again and verify that they end up on the same port
            self.log("Ensure that flow to port map is maintained when the same flow is re-sent...")
            for src_ip, port in tuple_to_port_map.iteritems():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                assert port_idx == port
            return

        elif self.test_case == 'withdraw_nh':
            self.log("Withdraw next-hop " + str(self.withdraw_nh_port) + " and ensure hash redistribution within correct bank")
            with open(PERSIST_MAP) as fp:
                tuple_to_port_map = json.load(fp)
            assert tuple_to_port_map
            if self.withdraw_nh_port in self.exp_port_set_one:
                withdraw_port_grp = self.exp_port_set_one
            else:
                withdraw_port_grp = self.exp_port_set_two
            hit_count_map = {}
            for src_ip, port in tuple_to_port_map.iteritems():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                assert port_idx != self.withdraw_nh_port
                if port == self.withdraw_nh_port:
                    assert port_idx != self.withdraw_nh_port
                    assert (port_idx in withdraw_port_grp)
                    tuple_to_port_map[src_ip] = port_idx
                else:
                    assert port_idx == port

            self.test_balancing(hit_count_map)

            json.dump(tuple_to_port_map, open(PERSIST_MAP,"w"))
            return

        elif self.test_case == 'add_nh':
            self.log("Add next-hop " + str(self.add_nh_port) + " and ensure hash redistribution within correct bank")
            with open(PERSIST_MAP) as fp:
                tuple_to_port_map = json.load(fp)
            assert tuple_to_port_map
            if self.add_nh_port in self.exp_port_set_one:
                add_port_grp = self.exp_port_set_one
            else:
                add_port_grp = self.exp_port_set_two
            hit_count_map = {}
            for src_ip, port in tuple_to_port_map.iteritems():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                if port_idx == self.add_nh_port:
                    assert (port in add_port_grp)
                else:
                    assert port_idx == port

            self.test_balancing(hit_count_map)

            json.dump(tuple_to_port_map, open(PERSIST_MAP,"w"))
            return

        elif self.test_case == 'withdraw_bank':
            self.log("Withdraw bank " + str(self.withdraw_nh_bank) + " and ensure hash redistribution is as expected")
            with open(PERSIST_MAP) as fp:
                tuple_to_port_map = json.load(fp)
            assert tuple_to_port_map
            if self.withdraw_nh_bank[0] in self.exp_port_set_one:
                active_port_grp = self.exp_port_set_two
            else:
                active_port_grp = self.exp_port_set_one
            hit_count_map = {}
            for src_ip, port in tuple_to_port_map.iteritems():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                if port in self.withdraw_nh_bank:
                    assert (port_idx in active_port_grp)
                    tuple_to_port_map[src_ip] = port_idx
                else:
                    assert port_idx == port

            self.test_balancing(hit_count_map)

            json.dump(tuple_to_port_map, open(PERSIST_MAP,"w"))
            return

        elif self.test_case == 'add_first_nh':
            self.log("Add 1st next-hop " + str(self.first_nh) + " and ensure hash redistribution is as expected")
            with open(PERSIST_MAP) as fp:
                tuple_to_port_map = json.load(fp)
            if self.first_nh in self.exp_port_set_one:
                active_port_grp = self.exp_port_set_two
            else:
                active_port_grp = self.exp_port_set_one

            assert tuple_to_port_map
            hit_count_map = {}
            for src_ip, port in tuple_to_port_map.iteritems():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.exp_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                flow_redistribution_in_correct_grp = False
                if port_idx in active_port_grp:
                    assert port_idx == port
                    flow_redistribution_in_correct_grp = True
                elif port_idx == self.first_nh:
                    flow_redistribution_in_correct_grp = True
                    tuple_to_port_map[src_ip] = port_idx
                assert flow_redistribution_in_correct_grp == True

            self.test_balancing(hit_count_map)
            return

        else:
            self.log("Unsupported testcase " + self.test_case)
            return


    def send_rcv_ip_pkt(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list, ipv4=True):
        if ipv4:
            (matched_index, received) = self.send_rcv_ipv4_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list)
        else:
            (matched_index, received) = self.send_rcv_ipv6_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)


    def send_rcv_ipv4_pkt(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list):
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        if self.inner_hashing:
            pkt = simple_vxlan_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src='2.2.2.' + str(rand_int),
                    ip_dst=self.dst_ip,
                    ip_ttl=64,
                    udp_sport=rand_int,
                    udp_dport=4789,
                    vxlan_vni=rand_int,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        send_packet(self, in_port, pkt)

        masked_exp_pkt = Mask(pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)


    def send_rcv_ipv6_pkt(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list):
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        if self.inner_hashing:
            pkt = simple_tcp_packet(
                        eth_dst=self.router_mac,
                        eth_src=src_mac,
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ip_ttl=64)
            pkt = simple_vxlanv6_packet(
                        eth_dst=self.router_mac,
                        eth_src=src_mac,
                        ipv6_src='2:2:2::' + str(rand_int),
                        ipv6_dst=self.dst_ip,
                        udp_sport=rand_int,
                        udp_dport=4789,
                        vxlan_vni=rand_int,
                        with_udp_chksum=False,
                        inner_frame=pkt)
        else:
            pkt = simple_tcpv6_packet(
                        eth_dst=self.router_mac,
                        eth_src=src_mac,
                        ipv6_dst=ip_dst,
                        ipv6_src=ip_src,
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=64)

        send_packet(self, in_port, pkt)

        masked_exp_pkt = Mask(pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)


    #---------------------------------------------------------------------
    def runTest(self):
        # Main function which triggers all the tests
        self.fg_ecmp()
