'''
Description:    This file contains the inner hash test for SONiC
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import random
import time

from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *

import fib
import lpm

class InnerHashTest(BaseTest):

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 625

    _required_params = [
        'fib_info',
        'vxlan_port',
        'src_ports',
        'inner_src_ip_range',
        'inner_dst_ip_range',
        'outer_src_ip_range',
        'outer_dst_ip_range'
    ]


    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()
        self.check_required_params()


    def check_required_params(self):
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception("Missing required parameter {}".format(param))


    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance

        self.fib = fib.Fib(self.test_params['fib_info'])
        self.router_mac = self.test_params['router_mac']

        inner_src_ip_range = [str(x) for x in self.test_params['inner_src_ip_range'].split(',')]
        inner_dst_ip_range = [str(x) for x in self.test_params['inner_dst_ip_range'].split(',')]
        self.inner_src_ip_interval = lpm.LpmDict.IpInterval(ip_address(inner_src_ip_range[0]), ip_address(inner_src_ip_range[1]))
        self.inner_dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(inner_dst_ip_range[0]), ip_address(inner_dst_ip_range[1]))

        outer_src_ip_range = [str(x) for x in self.test_params['outer_src_ip_range'].split(',')]
        outer_dst_ip_range = [str(x) for x in self.test_params['outer_dst_ip_range'].split(',')]
        self.outer_src_ip_interval = lpm.LpmDict.IpInterval(ip_address(outer_src_ip_range[0]), ip_address(outer_src_ip_range[1]))
        self.outer_dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(outer_dst_ip_range[0]), ip_address(outer_dst_ip_range[1]))

        self.hash_keys = self.test_params.get('hash_keys', ['src-ip', 'dst-ip', 'src-port', 'dst-port'])
        self.src_ports = self.test_params['src_ports']
        self.exp_port_groups = self.test_params['exp_port_groups']
        self.vxlan_port = self.test_params['vxlan_port']
        self.outer_encap_formats = self.test_params['outer_encap_formats']
        self.symmetric_hashing = self.test_params.get('symmetric_hashing', False)
        self.nvgre_tni = self.test_params.get('nvgre_tni', '')
        self.outer_dst_ip = self.outer_dst_ip_interval.get_first_ip()

        self.next_hop = self.fib[self.outer_dst_ip]
        self.exp_port_list = self.next_hop.get_next_hop_list()
        assert (len(self.exp_port_list) > 1)
        for exp_port in self.exp_port_list:
            assert exp_port not in self.src_ports

        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get('balancing_test_times', self.BALANCING_TEST_TIMES)

        logging.info("balancing_range:  {}".format(self.balancing_range))
        logging.info("balancing_test_times:  {}".format(self.balancing_test_times))
        logging.info("outer_encap_formats:  {}".format(self.outer_encap_formats))
        logging.info("hash_keys:  {}".format(self.hash_keys))
        logging.info("symmetric_hashing:  {}".format(self.symmetric_hashing))
        logging.info("exp_port_groups:  {}".format(self.exp_port_groups))


    def check_hash(self, hash_key):
        src_port = int(random.choice(self.src_ports))
        logging.info("outer_dst_ip={}, src_port={}, exp_port_list={}".format(self.outer_dst_ip, src_port, self.exp_port_list))

        for outer_encap_format in self.outer_encap_formats:
            hit_count_map = {}
            for _ in range(0, self.balancing_test_times*len(self.exp_port_list)):
                src_port = int(random.choice(self.src_ports))
                logging.info('Checking {} hash key {}, src_port={}, exp_ports={}, dst_ip={}'\
                    .format(outer_encap_format, hash_key, src_port, self.exp_port_list, self.outer_dst_ip))

                ip_src = self.inner_src_ip_interval.get_random_ip() if hash_key == 'src-ip' else self.inner_src_ip_interval.get_first_ip()
                ip_dst = self.inner_dst_ip_interval.get_random_ip() if hash_key == 'dst-ip' else self.inner_dst_ip_interval.get_first_ip()
                sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
                dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80
                ip_proto = self._get_ip_proto() if hash_key == 'ip-proto' else 6

                (matched_port, _) = self.check_ip_route(hash_key, outer_encap_format, src_port, ip_src, ip_dst, sport, dport, ip_proto)
                if self.symmetric_hashing and hash_key != 'ip-proto':
                    # Send the same packet with reversed tuples and validate that it lands on the same port
                    rand_src_port = int(random.choice(self.src_ports))
                    (rMatched_port, _) = self.check_ip_route(hash_key, outer_encap_format, rand_src_port, ip_dst, ip_src, dport, sport, ip_proto)
                    self.check_matched_ports(matched_port, rMatched_port)
                    hit_count_map[rMatched_port] = hit_count_map.get(rMatched_port, 0) + 1

                hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1
            logging.info("outer_encap_fmts={}, hash_key={}, hit count map: {}".format(outer_encap_format, hash_key, hit_count_map))
            if hash_key == 'outer-tuples':
                self.check_all_packets_hash_to_same_nh(self.next_hop.get_next_hop(), hit_count_map)
            else:
                self.check_balancing(self.next_hop.get_next_hop(), hit_count_map, hash_key)


    def check_ip_route(self, hash_key, outer_encap_format, src_port, ip_src, ip_dst, sport, dport, ip_proto):
        if (outer_encap_format == 'vxlan'):
            (matched_index, received) = self.check_ip_route_vxlan(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)
        elif (outer_encap_format == 'nvgre'):
            (matched_index, received) = self.check_ip_route_nvgre(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)
        else:
            raise Exception("Logic issue, unexpected outer encap format {}".format(outer_encap_format))

        matched_port = self.exp_port_list[matched_index]
        return (matched_port, received)


    def check_matched_ports(self, matched_port, rMatched_port):
        logging.info("matched_port:  {}, rMatched_port: {}".format(matched_port, rMatched_port))
        matched_port_in_any_group = False
        for ports_group in self.exp_port_groups:
            if matched_port in ports_group:
                assert rMatched_port in ports_group, 'The matched_port {} and rMatched_port {} not in the same group {}'.\
                    format(matched_port, rMatched_port, ports_group)
                matched_port_in_any_group = True
                break
        assert matched_port_in_any_group, "The matched port {} not in expected ports list {}".\
            format(matched_port, self.exp_port_groups)


    def _get_ip_proto(self, ipv6=False):
        # ip_proto 2 is IGMP, should not be forwarded by router
        # ip_proto 254 is experimental
        # MLNX ASIC can't forward ip_proto 254, BRCM is OK, skip for all for simplicity
        skip_protos = [2, 253, 254]
        if ipv6:
            # Skip ip_proto 0 for IPv6
            skip_protos.append(0)

        while True:
            ip_proto = random.randint(0, 255)
            if ip_proto not in skip_protos:
                return ip_proto


    def generate_inner_pkt(self, sport, dport, ip_src, ip_dst, ip_proto):
        rand_int = random.randint(1, 99)
        src_mac = '00:12:ab:34:cd:' + str(rand_int)
        dst_mac = str(rand_int) + ':12:ab:34:cd:00'
        if ip_network(str(ip_src)).version == 4:
            pkt = simple_tcp_packet(
                eth_dst=dst_mac,
                eth_src=src_mac,
                ip_dst=ip_dst,
                ip_src=ip_src,
                tcp_sport=sport,
                tcp_dport=dport,
                ip_ttl=64
            )

            pkt["IP"].proto = ip_proto
        else:
            pkt = simple_tcpv6_packet(
                eth_dst=dst_mac,
                eth_src=src_mac,
                ipv6_dst=ip_dst,
                ipv6_src=ip_src,
                tcp_sport=sport,
                tcp_dport=dport,
                ipv6_hlim=64
            )

            pkt["IPv6"].nh = ip_proto
        return pkt


    def check_ip_route_nvgre(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check nvgre based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        if ip_network(str(self.outer_dst_ip)).version == 4:
            (matched_index, received) = self.check_ipv4_route_nvgre(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)
        else:
            (matched_index, received) = self.check_ipv6_route_nvgre(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)

        assert received

        logging.info("Received packet at index " + str(matched_index))
        time.sleep(0.02)

        return (matched_index, received)


    def check_ipv4_route_nvgre(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check IPv4 nvgre based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        src_mac = self.dataplane.get_mac(0, src_port)

        outer_ip_src = self.outer_src_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_src_ip_interval.get_first_ip()
        outer_ip_dst = self.outer_dst_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_dst_ip_interval.get_first_ip()
        nvgre_tni = self.nvgre_tni if self.nvgre_tni else random.randint(1, 254) + 20000

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, ip_proto)
        nvgre_pkt = simple_nvgre_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src=outer_ip_src,
                    ip_dst=outer_ip_dst,
                    ip_ttl=64,
                    inner_frame=pkt,
                    nvgre_tni=nvgre_tni,
                    nvgre_flowid=0)

        logging.info("Sending packet from port {} outer_ip_src {} outer_ip_dst {} inner_src_ip {} inner_dst_ip {} inner_sport {} inner_dport {} inner_ipproto {}"\
                .format(src_port, outer_ip_src, outer_ip_dst, ip_src, ip_dst, sport, dport, ip_proto))
        send_packet(self, src_port, nvgre_pkt)

        masked_exp_pkt = Mask(nvgre_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        return verify_packet_any_port(self, masked_exp_pkt, self.exp_port_list)


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
        '''
        @summary: Helper function to construct an IPv6 NVGRE packet
        '''
        if scapy.NVGRE is None:
            logging.error("A NVGRE packet was requested but NVGRE is not supported by your Scapy. See README for more information")
            return None

        if MINSIZE > pktlen:
            pktlen = MINSIZE

        nvgre_hdr = scapy.NVGRE(vsid=nvgre_tni, flowid=nvgre_flowid)

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


    def check_ipv6_route_nvgre(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check IPv6 nvgre based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        src_mac = self.dataplane.get_mac(0, src_port)

        outer_ip_src = self.outer_src_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_src_ip_interval.get_first_ip()
        outer_ip_dst = self.outer_dst_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_dst_ip_interval.get_first_ip()
        nvgre_tni = self.nvgre_tni if self.nvgre_tni else random.randint(1, 254) + 20000

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, ip_proto)
        nvgre_pkt = self.simple_nvgrev6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src=outer_ip_src,
                    ipv6_dst=outer_ip_dst,
                    inner_frame=pkt,
                    nvgre_tni=nvgre_tni,
                    nvgre_flowid=0)

        logging.info("Sending packet from port {} outer_ip_src {} outer_ip_dst {} inner_src_ip {} inner_dst_ip {} inner_sport {} inner_dport {} inner_ipproto {}"\
                .format(src_port, outer_ip_src, outer_ip_dst, ip_src, ip_dst, sport, dport, ip_proto))
        send_packet(self, src_port, nvgre_pkt)

        masked_exp_pkt = Mask(nvgre_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        return verify_packet_any_port(self, masked_exp_pkt, self.exp_port_list)


    def check_ip_route_vxlan(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check IP vxlan based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        if ip_network(str(self.outer_dst_ip)).version == 4:
            (matched_index, received) = self.check_ipv4_route_vxlan(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)
        else:
            (matched_index, received) = self.check_ipv6_route_vxlan(hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto)

        assert received

        logging.info("Received packet at index" + str(matched_index))
        time.sleep(0.02)

        return (matched_index, received)


    def check_ipv4_route_vxlan(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check IPv4 vxlan based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        src_mac = self.dataplane.get_mac(0, src_port)

        outer_ip_src = self.outer_src_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_src_ip_interval.get_first_ip()
        outer_ip_dst = self.outer_dst_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_dst_ip_interval.get_first_ip()
        outer_sport = random.randint(0, 65535) if hash_key == 'outer-tuples' else 1234

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, ip_proto)
        vxlan_pkt = simple_vxlan_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src=outer_ip_src,
                    ip_dst=outer_ip_dst,
                    ip_ttl=64,
                    udp_sport=outer_sport,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=random.randint(1, 254)+20000,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        logging.info("Sending packet from port {} outer_ip_src {} outer_ip_dst {} inner_src_ip {} inner_dst_ip {} inner_sport {} inner_dport {} inner_ipproto {}"\
                .format(src_port, outer_ip_src, outer_ip_dst, ip_src, ip_dst, sport, dport, ip_proto))
        send_packet(self, src_port, vxlan_pkt)

        masked_exp_pkt = Mask(vxlan_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        return verify_packet_any_port(self, masked_exp_pkt, self.exp_port_list)


    def check_ipv6_route_vxlan(self, hash_key, src_port, ip_dst, ip_src, dport, sport, ip_proto):
        '''
        @summary: Check IPv6 vxlan based inner packet hashing works
        @param hash_key: hash_key we are varying in this iteration
        @param src_port: index of port to use for sending packet to switch
        @param ip_dst: Inner packet Destination IP address
        @param ip_src: Inner packet Source IP address
        @param dport: Inner packet dst port
        @param sport: Inner packet src port
        @param ip_proto: Inner packet ip protocol
        '''
        src_mac = self.dataplane.get_mac(0, src_port)

        outer_ip_src = self.outer_src_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_src_ip_interval.get_first_ip()
        outer_ip_dst = self.outer_dst_ip_interval.get_random_ip() if hash_key == 'outer-tuples' else self.outer_dst_ip_interval.get_first_ip()
        outer_sport = random.randint(0, 65535) if hash_key == 'outer-tuples' else 1234

        pkt = self.generate_inner_pkt(sport, dport, ip_src, ip_dst, ip_proto)
        vxlan_pkt = simple_vxlanv6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src=outer_ip_src,
                    ipv6_dst=outer_ip_dst,
                    udp_sport=outer_sport,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=random.randint(1, 254)+20000,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        logging.info("Sending packet from port {} outer_ip_src {} outer_ip_dst {} inner_src_ip {} inner_dst_ip {} inner_sport {} inner_dport {} inner_ipproto {}"\
                .format(src_port, outer_ip_src, outer_ip_dst, ip_src, ip_dst, sport, dport, ip_proto))
        send_packet(self, src_port, vxlan_pkt)

        masked_exp_pkt = Mask(vxlan_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        return verify_packet_any_port(self, masked_exp_pkt, self.exp_port_list)


    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)


    def check_balancing(self, dest_port_list, port_hit_cnt, hash_key):
        '''
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @param hash_key : hash key
        @return bool
        '''

        logging.info("%-10s \t %-10s \t %10s \t %10s \t %10s" % ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
        result = True

        total_hit_cnt = self.balancing_test_times*len(self.exp_port_list)
        for ecmp_entry in dest_port_list:
            total_entry_hit_cnt = 0
            for member in ecmp_entry:
                total_entry_hit_cnt += port_hit_cnt.get(member, 0)

            total_expected = float(total_hit_cnt) / len(dest_port_list)
            if self.symmetric_hashing and hash_key != 'ip-proto':
                total_expected = total_expected * 2

            (p, r) = self.check_within_expected_range(total_entry_hit_cnt, total_expected)
            logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                        % ("ECMP", str(ecmp_entry), (total_hit_cnt//len(dest_port_list)*len(ecmp_entry)), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
            result &= r

        assert result


    def check_all_packets_hash_to_same_nh(self, dest_port_list, port_hit_cnt):
        '''
        @summary: Check if all the traffic is sent to a single ECMP next-hop out of all available next-hops
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @return bool
        '''

        logging.info("%-10s \t %10s" % ("port(s)", "cnt"))

        total_hit_cnt = self.balancing_test_times*len(self.exp_port_list)
        if self.symmetric_hashing:
            total_hit_cnt = total_hit_cnt*2
        nhs_with_packets_rcvd = 0
        for ecmp_entry in dest_port_list:
            total_entry_hit_cnt = 0
            for member in ecmp_entry:
                total_entry_hit_cnt += port_hit_cnt.get(member, 0)
            logging.info("%-10s \t %10s" % (str(ecmp_entry), total_entry_hit_cnt))

            if total_entry_hit_cnt > 0:
                nhs_with_packets_rcvd = nhs_with_packets_rcvd + 1
                assert (total_entry_hit_cnt == total_hit_cnt)
        assert (nhs_with_packets_rcvd == 1)


    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """

        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)
