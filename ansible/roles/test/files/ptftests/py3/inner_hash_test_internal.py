'''
Description:    This file contains the inner hash test for SONiC.
                This is a Microsoft internal ONLY test since it contains
                the proprietary service tunnel packet format hashing test.
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import ipaddress
import logging
import random
import socket
import sys
import time
import json
import os

from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *
import ptf.testutils as testutils

import lpm

class InnerHashTestInternal(BaseTest):

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()
        self.check_required_params()

    #---------------------------------------------------------------------
    def log(self, message):
        logging.info(message)

    _required_params = [
        'config_file',
        'vxlan_port',
        'exp_flow_count',
        'outer_dst_ipv4',
        'outer_dst_ipv6'
    ]

    def check_required_params(self):
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception("Missing required parameter {}".format(param))

    def trigger_mac_learning(self, exp_ports):
        for src_port in exp_ports:
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
        self.max_deviation = 0.35

        config = self.test_params['config_file']

        self.exp_flow_count = self.test_params['exp_flow_count']
        self.outer_dst_ipv4 = self.test_params['outer_dst_ipv4']
        self.outer_dst_ipv6 = self.test_params['outer_dst_ipv6']
        self.vxlan_port = self.test_params['vxlan_port']

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.net_ports = graph['net_ports']
        self.exp_ports = graph['port_list']
        self.exp_port_set_one = graph['bank_0_port']
        self.exp_port_set_two = graph['bank_1_port']
        self.router_mac = graph['dut_mac']
        self.num_flows = graph['num_flows']

        self.log(self.net_ports)
        self.log(self.exp_ports)
        self.log(self.exp_port_set_one)
        self.log(self.exp_port_set_two)
        self.log(self.router_mac)
        self.log(self.exp_flow_count)
        self.log(self.num_flows)
        self.log(self.outer_dst_ipv4)
        self.log(self.outer_dst_ipv6)
        self.log(self.vxlan_port)

        self.trigger_mac_learning(self.exp_ports)
        time.sleep(3)

    def test_balancing(self, hit_count_map):
        for port, exp_flows in list(self.exp_flow_count.items()):
            assert port in hit_count_map
            num_flows = hit_count_map[port]
            deviation = float(num_flows)/float(exp_flows)
            deviation = abs(1-deviation)
            self.log("port "+ str(port) + " exp_flows " + str(exp_flows) +
                    " num_flows " + str(num_flows) + " deviation " + str(deviation))
            assert deviation <= self.max_deviation

    def simple_nvgrev6_packet(self, pktlen=300,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='00:06:07:08:09:0a',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ipv6_src='1::2',
                        ipv6_dst='3::4',
                        ipv6_fl=0,
                        ipv6_tc=0,
                        ipv6_ecn=None,
                        ipv6_dscp=None,
                        ipv6_hlim=64,
                        nvgre_version=0,
                        nvgre_tni=None,
                        nvgre_flowid=0,
                        inner_frame=None
                        ):
            if scapy.NVGRE is None:
                logging.error("A NVGRE packet was requested but NVGRE is not supported by your Scapy. See README for more information")
                return None

            if MINSIZE > pktlen:
                pktlen = MINSIZE

            nvgre_hdr = scapy.NVGRE(vsid=nvgre_tni, flowid=nvgre_flowid)

            #ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

            if (dl_vlan_enable):
                pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                    scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
                    scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim, nh=47)/ \
                    nvgre_hdr
            else:
                pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                    scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim, nh=47)/ \
                    nvgre_hdr

            if inner_frame:
                pkt = pkt / inner_frame
            else:
                pkt = pkt / scapy.IP()
                pkt = pkt/("D" * (pktlen - len(pkt)))

            return pkt

    #---------------------------------------------------------------------

    def check_hash(self, inner_l3_proto):
        if inner_l3_proto == "IPv4":
            src_ip_interval = lpm.LpmDict.IpInterval(ip_address('8.0.0.0'), ip_address('8.255.255.255'))
            dst_ip_interval = lpm.LpmDict.IpInterval(ip_address('9.0.0.0'), ip_address('9.255.255.255'))
        else:
            print("Unsupport inner L3 proto " + inner_l3_proto)

        # hash field for regular packets:
        #   src_ip, dst_ip, protocol, l4_src_port, l4_dst_port (if applicable)


        inner_protos = ['tcp', 'udp', 'icmp']

        for inner_l4_proto in inner_protos:
            # Keep mac learning active
            self.trigger_mac_learning(self.exp_ports)

            hit_count_map_v4 = {}
            hit_count_map_v6 = {}
            for i in range(0, self.num_flows):
                src_ip = src_ip_interval.get_random_ip()
                dst_ip = dst_ip_interval.get_random_ip()
                src_port = random.randint(2, 65000)
                dst_port = random.randint(2, 65000)
                (port_idx_vxlan, _) = self.check_ip_route_nvgre(
                        random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports, inner_l4_proto, True)
                (port_idx_nvgre, _) = self.check_ip_route_vxlan(
                        random.choice(self.net_ports), dst_port, src_port, dst_ip, src_ip, self.exp_ports, inner_l4_proto, True)
                (port_idx_vxlan_v6, _) = self.check_ip_route_nvgre(
                        random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports, inner_l4_proto, False)
                (port_idx_nvgre_v6, _) = self.check_ip_route_vxlan(
                        random.choice(self.net_ports), dst_port, src_port, dst_ip, src_ip, self.exp_ports, inner_l4_proto, False)
                if inner_l4_proto == 'tcp':
                    (port_idx_st, _) = self.check_ip_route_service_tunnel(
                        random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports)

                hit_count_map_v4[port_idx_vxlan] = hit_count_map_v4.get(port_idx_vxlan, 0) + 1
                hit_count_map_v6[port_idx_vxlan_v6] = hit_count_map_v6.get(port_idx_vxlan_v6, 0) + 1
                assert port_idx_vxlan == port_idx_nvgre
                if inner_l4_proto == 'tcp':
                    assert port_idx_vxlan == port_idx_st

                port_grp = self.exp_port_set_one
                if port_idx_vxlan in self.exp_port_set_two:
                    port_grp = self.exp_port_set_two
                assert port_idx_nvgre_v6 in port_grp
                assert port_idx_vxlan_v6 in port_grp
                assert port_idx_vxlan_v6 == port_idx_vxlan_v6
            self.log(inner_l4_proto + " outer_v4 hash distribution " + str(hit_count_map_v4))
            self.log(inner_l4_proto + " outer_v6 hash distribution " + str(hit_count_map_v6))
            self.test_balancing(hit_count_map_v4)
            self.test_balancing(hit_count_map_v6)
    
    def check_tuples(self, inner_l3_proto):
        # Tests if each Tuple in inner 5-tuple participates in the
        # hash algorithm such that change in single tuple leads to 
        # a change in picked port per ECMP.
        if inner_l3_proto == "IPv4":
            base_src_ip = ipaddress.ip_address('8.0.0.0')
            base_dst_ip = ipaddress.ip_address('10.0.0.0')
        else:
            print("Unsupport inner L3 proto " + inner_l3_proto)

        # hash field for regular packets:
        #   src_ip, dst_ip, protocol, l4_src_port, l4_dst_port (if applicable)
        SRC_IP = 'src_ip'
        DST_IP = 'dst_ip'
        SRC_PORT = 'src_port'
        DST_PORT = 'dst_port'
        default_src_ip = base_src_ip
        default_dst_ip = base_dst_ip
        default_src_port = random.randint(2, 30000)
        default_dst_port = random.randint(2, 30000)

        inner_tuples = [SRC_IP, DST_IP, SRC_PORT, DST_PORT]
        inner_protos = ['tcp', 'udp', 'icmp']
        for inner_l4_proto in inner_protos:
            for tuple in inner_tuples:
                if inner_l4_proto == 'icmp' and (tuple == SRC_PORT or tuple == DST_PORT):
                    continue
                # Keep mac learning active
                self.trigger_mac_learning(self.exp_ports)

                inner = {}
                inner[SRC_IP] = default_src_ip
                inner[DST_IP] = default_dst_ip
                inner[SRC_PORT] = default_src_port
                inner[DST_PORT] = default_dst_port
                hit_count_map_v4 = {}
                hit_count_map_v6 = {}
                for i in range(0, self.num_flows):
                    inner[tuple] = inner[tuple] + 1
                    src_ip = str(inner[SRC_IP])
                    dst_ip = str(inner[DST_IP])
                    src_port = inner[SRC_PORT]
                    dst_port = inner[DST_PORT]
                    (port_idx_vxlan, _) = self.check_ip_route_nvgre(
                            random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports, inner_l4_proto, True)
                    (port_idx_nvgre, _) = self.check_ip_route_vxlan(
                            random.choice(self.net_ports), dst_port, src_port, dst_ip, src_ip, self.exp_ports, inner_l4_proto, True)
                    (port_idx_vxlan_v6, _) = self.check_ip_route_nvgre(
                            random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports, inner_l4_proto, False)
                    (port_idx_nvgre_v6, _) = self.check_ip_route_vxlan(
                            random.choice(self.net_ports), dst_port, src_port, dst_ip, src_ip, self.exp_ports, inner_l4_proto, False)
                    if inner_l4_proto == 'tcp':
                        (port_idx_st, _) = self.check_ip_route_service_tunnel(
                            random.choice(self.net_ports), src_port, dst_port, src_ip, dst_ip, self.exp_ports)

                    hit_count_map_v4[port_idx_vxlan] = hit_count_map_v4.get(port_idx_vxlan, 0) + 1
                    hit_count_map_v6[port_idx_vxlan_v6] = hit_count_map_v6.get(port_idx_vxlan_v6, 0) + 1
                    assert port_idx_vxlan == port_idx_nvgre
                    if inner_l4_proto == 'tcp':
                        assert port_idx_vxlan == port_idx_st

                    port_grp = self.exp_port_set_one
                    if port_idx_vxlan in self.exp_port_set_two:
                        port_grp = self.exp_port_set_two
                    assert port_idx_nvgre_v6 in port_grp
                    assert port_idx_vxlan_v6 in port_grp
                    assert port_idx_vxlan_v6 == port_idx_vxlan_v6
                self.log(inner_l4_proto + " outer_v4 hash distribution on inner tuple " + tuple + " " + str(hit_count_map_v4))
                self.log(inner_l4_proto + " outer_v6 hash distribution on inner tuple " + tuple + " " + str(hit_count_map_v6))
                self.test_balancing(hit_count_map_v4)
                self.test_balancing(hit_count_map_v6)

    def check_ip_route_vxlan(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list, inner_l4_proto, ipv4=True):
        if ipv4:
            (matched_index, received) = self.check_ipv4_route_vxlan(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, inner_l4_proto)
        else:
            (matched_index, received) = self.check_ipv6_route_vxlan(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, inner_l4_proto)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_ip_route_nvgre(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list, inner_l4_proto, ipv4=True):
        if ipv4:
            (matched_index, received) = self.check_ipv4_route_nvgre(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, inner_l4_proto)
        else:
            (matched_index, received) = self.check_ipv6_route_nvgre(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, inner_l4_proto)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_ip_route_service_tunnel(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list):
        (matched_index, received) = self.check_service_tunnel(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)

    def check_service_tunnel(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list):
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)
        inner_src_ip = str(ipaddress.IPv6Address((random.getrandbits(64) << 64) + int(ipaddress.IPv4Address(ip_src))))
        inner_dst_ip = str(ipaddress.IPv6Address((random.getrandbits(64) << 64) + int(ipaddress.IPv4Address(ip_dst))))

        pkt = simple_tcpv6_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ipv6_src=inner_src_ip,
                            ipv6_dst=inner_dst_ip,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ipv6_hlim=64)
        nvgre_pkt = simple_nvgre_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src='2.2.2.' + str(rand_int),
                    ip_dst=self.outer_dst_ipv4,
                    ip_ttl=64,
                    nvgre_tni=100,
                    inner_frame=pkt)

        send_packet(self, in_port, nvgre_pkt)
        
        masked_exp_pkt = Mask(nvgre_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
      
        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)


    def generate_inner_pkt(self, sport, dport, ip_src, ip_dst, inner_l4_proto):

        rand_int = random.randint(1, 99)
        src_mac = '00:12:ab:34:cd:' + str(rand_int)
        dst_mac = str(rand_int) + ':12:ab:34:cd:00'
        if inner_l4_proto == 'tcp':
            pkt = simple_tcp_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        elif inner_l4_proto == 'udp':
            pkt = simple_udp_packet(
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            udp_sport=sport,
                            udp_dport=dport,
                            ip_ttl=64)
        elif inner_l4_proto == 'icmp':
            pkt = simple_icmp_packet(pktlen=100,
			     eth_dst=dst_mac,
			     eth_src=src_mac,
			     dl_vlan_enable=False,
			     ip_src=ip_src,
			     ip_dst=ip_dst,
			     ip_ttl=64) 
        return pkt
        


    def check_ipv4_route_vxlan(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, inner_l4_proto):
        '''
        @summary: Check IPv4 route works.
        @param in_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, inner_l4_proto)
        vxlan_pkt = simple_vxlan_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src='2.2.2.' + str(rand_int),
                    ip_dst=self.outer_dst_ipv4,
                    ip_ttl=64,
                    udp_sport=rand_int,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=rand_int+20000,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        send_packet(self, in_port, vxlan_pkt)
        
        masked_exp_pkt = Mask(vxlan_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
      
        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)
    #---------------------------------------------------------------------

    def check_ipv4_route_nvgre(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, inner_l4_proto):
        '''
        @summary: Check IPv4 route works.
        @param in_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, inner_l4_proto)
        nvgre_pkt = simple_nvgre_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src='2.2.2.' + str(rand_int),
                    ip_dst=self.outer_dst_ipv4,
                    ip_ttl=64,
                    nvgre_tni=rand_int+20000,
                    inner_frame=pkt)

        send_packet(self, in_port, nvgre_pkt)
        
        masked_exp_pkt = Mask(nvgre_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
      
        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

    #---------------------------------------------------------------------

    def check_ipv6_route_vxlan(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, inner_l4_proto):
        '''
        @summary: Check IPv4 route works.
        @param in_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, inner_l4_proto)
        vxlan_pkt = simple_vxlanv6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src='2:2:2::' + str(rand_int),
                    ipv6_dst=self.outer_dst_ipv6,
                    udp_sport=rand_int,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=rand_int+20000,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        send_packet(self, in_port, vxlan_pkt)
        
        masked_exp_pkt = Mask(vxlan_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
      
        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

    #---------------------------------------------------------------------

    def check_ipv6_route_nvgre(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, inner_l4_proto):
        '''
        @summary: Check IPv4 route works.
        @param in_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, inner_l4_proto)
        nvgre_pkt = self.simple_nvgrev6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src='2:2:2::' + str(rand_int),
                    ipv6_dst=self.outer_dst_ipv6,
                    nvgre_tni=rand_int+20000,
                    inner_frame=pkt)


        send_packet(self, in_port, nvgre_pkt)
        
        masked_exp_pkt = Mask(nvgre_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
      
        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)


    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """

        self.log("Starting test check_hash...")
        self.check_hash(inner_l3_proto="IPv4")
        self.log("Completed test check_hash...")

        self.log("Starting test check_tuples...")
        self.check_tuples(inner_l3_proto="IPv4")
        self.log("Completed test check_tuples...")
