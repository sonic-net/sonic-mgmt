'''
Description:    This file contains the FIB test for SONIC

                Design is available in https://github.com/sonic-net/SONiC/wiki/FIB-Scale-Test-Plan

Usage:          Examples of how to use log analyzer
                ptf --test-dir ptftests fib_test.FibTest \
                    --platform-dir ptftests \
                    --qlen=2000 \
                    --platform remote \
                    -t 'setup_info="/root/test_fib_setup_info.json";\
                        testbed_mtu=1514;ipv4=True;test_balancing=True;ipv6=True' \
                    --relax \
                    --debug info \
                    --socket-recv-size 16384 \
                    --log-file /tmp/fib_test.FibTest.ipv4.True.ipv6.True.2020-12-22-08:17:05.log
'''

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------
import logging
import random
import time
import json
import itertools
import fib
import macsec

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_tcpv6_packet
from ptf.testutils import send_packet
from ptf.testutils import verify_packet_any_port
from ptf.testutils import verify_no_packet_any

from collections import Iterable, defaultdict


class FibTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test routes advertised by BGP peers of SONIC are working properly.
    The setup of peers is described in 'VM set' section in
    https://github.com/sonic-net/sonic-mgmt/blob/master/docs/ansible/README.testbed.md

    Routes advertized by the peers have ECMP groups. The purpose of the test is to make sure
    that packets are forwarded through one of the ports specified in route's ECMP group.

    This class receives a text file describing the bgp routes added to the switch.
    File contains information about each bgp route which was added to the switch.

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

    # ---------------------------------------------------------------------
    # Class variables
    # ---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 625
    DEFAULT_BALANCING_TEST_NUMBER = 1
    ACTION_FWD = 'fwd'
    ACTION_DROP = 'drop'
    DEFAULT_SWITCH_TYPE = 'voq'

    _required_params = [
        'fib_info_files',
        'ptf_test_port_map'
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
        Some test parameters are used:
         - setup_info: various configuration required by the FIB ptf test
         - src_ports: this list should include all enabled ports, both up links
                     and down links.
         - pkt_action: expect to receive test traffic or not. Default: fwd
         - ipv4/ipv6: enable ipv4/ipv6 tests

        Other test parameters:
         - ttl:                   ttl of test pkts. Auto decrease 1 for expected pkts.
         - ip_options             enable ip option header in ipv4 pkts. Default: False(disable)
         - src_vid                vlan tag id of src pkts. Default: None(untag)
         - dst_vid                vlan tag id of dst pkts. Default: None(untag)
         - ignore_ttl:            mask the ttl field in the expected packet
         - single_fib_for_duts:   have a single fib file for all DUTs in multi-dut case. Default: False
        '''
        self.dataplane = ptf.dataplane_instance
        self.asic_type = self.test_params.get('asic_type')
        if self.asic_type == "marvell":
            fib.EXCLUDE_IPV4_PREFIXES.append("240.0.0.0/4")

        self.fibs = []
        for fib_info_file in self.test_params.get('fib_info_files'):
            self.fibs.append(fib.Fib(fib_info_file))

        ptf_test_port_map = self.test_params.get('ptf_test_port_map')
        with open(ptf_test_port_map) as f:
            self.ptf_test_port_map = json.load(f)

        # preprocess ptf_test_port_map to support multiple DUTs as target_dut
        for port_map in self.ptf_test_port_map.values():
            if not isinstance(port_map["target_dut"], Iterable):
                port_map["target_dut"] = [port_map["target_dut"]]
                port_map["target_src_mac"] = [port_map["target_src_mac"]]

        self.pktlen = self.test_params.get('testbed_mtu', 9114)
        self.test_ipv4 = self.test_params.get('ipv4', True)
        self.test_ipv6 = self.test_params.get('ipv6', True)
        self.test_balancing = self.test_params.get('test_balancing', True)
        self.balancing_range = self.test_params.get(
            'balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get(
            'balancing_test_times', self.BALANCING_TEST_TIMES)
        self.balancing_test_number = self.test_params.get(
            'balancing_test_number', self.DEFAULT_BALANCING_TEST_NUMBER)
        self.balancing_test_count = 0
        self.switch_type = self.test_params.get(
            'switch_type', self.DEFAULT_SWITCH_TYPE)

        self.pkt_action = self.test_params.get('pkt_action', self.ACTION_FWD)
        self.ttl = self.test_params.get('ttl', 64)

        self.ip_options = False
        ip_options_list = self.test_params.get('ip_options', False)
        if isinstance(ip_options_list, list) and ip_options_list:
            self.ip_options = scapy.IPOption(ip_options_list[0])
            for opt in ip_options_list[1:]:
                self.ip_options /= scapy.IPOption(opt)

        self.src_vid = self.test_params.get('src_vid', None)
        self.dst_vid = self.test_params.get('dst_vid', None)

        self.src_ports = self.test_params.get('src_ports', None)
        if not self.src_ports:
            self.src_ports = [int(port)
                              for port in self.ptf_test_port_map.keys()]

        self.ignore_ttl = self.test_params.get('ignore_ttl', False)
        self.single_fib = self.test_params.get(
            'single_fib_for_duts', "multiple-fib")

    def check_ip_ranges(self, ipv4=True):
        for dut_index, dut_fib in enumerate(self.fibs):
            if ipv4:
                ip_ranges = dut_fib.ipv4_ranges()
            else:
                ip_ranges = dut_fib.ipv6_ranges()

            if len(ip_ranges) > 150:
                # Limit test execution time
                covered_ip_ranges = ip_ranges[:100] + \
                    random.sample(ip_ranges[100:], 50)
            else:
                covered_ip_ranges = ip_ranges[:]

            for ip_range in covered_ip_ranges:
                if ip_range.get_first_ip() in dut_fib:
                    self.check_ip_range(ip_range, dut_index, ipv4)

            random.shuffle(covered_ip_ranges)
            self.check_balancing(covered_ip_ranges, dut_index, ipv4)

    def get_src_and_exp_ports(self, dst_ip):
        while True:
            src_port = int(random.choice(self.src_ports))
            active_dut_indexes = [0]
            if self.single_fib == "multiple-fib":
                active_dut_indexes = self.ptf_test_port_map[str(
                    src_port)]['target_dut']

            next_hops = [self.fibs[active_dut_index][dst_ip]
                         for active_dut_index in active_dut_indexes]
            exp_port_lists = [next_hop.get_next_hop_list()
                              for next_hop in next_hops]
            for exp_port_list in exp_port_lists:
                if src_port in exp_port_list:
                    break
            else:
                # MACsec link only receive encrypted packets
                # It's hard to simulate encrypted packets on the injected port
                # Because the MACsec is session based channel but the injected ports are stateless ports
                if src_port in macsec.MACSEC_INFOS.keys():
                    continue
                if self.switch_type == "chassis-packet":
                    exp_port_lists = self.check_same_asic(src_port, exp_port_lists)
                logging.info('src_port={}, exp_port_lists={}, active_dut_indexes={}'.format(
                    src_port, exp_port_lists, active_dut_indexes))
                break
        return src_port, exp_port_lists, next_hops

    def check_ip_range(self, ip_range, dut_index, ipv4=True):

        dst_ips = []
        dst_ips.append(ip_range.get_first_ip())
        if ip_range.length() > 1:
            dst_ips.append(ip_range.get_last_ip())
        if ip_range.length() > 2:
            dst_ips.append(ip_range.get_random_ip())

        for dst_ip in dst_ips:
            src_port, exp_port_lists, _ = self.get_src_and_exp_ports(dst_ip)
            # if dst_ip is local to DUT, the nexthops will be empty.
            # for active-active dualtor testbed, if the dst_ip is local to the upper ToR and src_port is an
            # active-active port, the expect egress ports of upper ToR will be empty, exp_port_lists will be
            # like [[], [30, 31, 32, 33]] if src_port .
            # for single DUT testbed, if the dst_ip is local to the ToR, the exp_port_lists will be like [[]].
            # so let's skip checking this IP range if any sub-list is empty.
            for exp_port_list in exp_port_lists:
                if not exp_port_list:
                    logging.info('Skip checking ip range {} with exp_ports {}'.format(
                        ip_range, exp_port_lists))
                    return
            logging.info('Checking ip range {}, src_port={}, exp_port_lists={}, dst_ip={}, dut_index={}'
                         .format(ip_range, src_port, exp_port_lists, dst_ip, dut_index))
            self.check_ip_route(src_port, dst_ip, exp_port_lists, ipv4)

    def check_balancing(self, ip_ranges, dut_index, ipv4=True):
        # Test traffic balancing across ECMP/LAG members
        if self.test_balancing and self.pkt_action == self.ACTION_FWD:
            for ip_range in ip_ranges:
                dst_ip = ip_range.get_random_ip()
                src_port, exp_port_lists, next_hops = self.get_src_and_exp_ports(
                    dst_ip)
                if self.single_fib == "single-fib-multi-hop":
                    updated_exp_port_list = []
                    # assume only test `single-fib-multi-hop` scenario on a single DUT testbed
                    exp_port_list = exp_port_lists[0]
                    for port in exp_port_list:
                        if (self.ptf_test_port_map[str(port)]['target_dut'] ==
                            self.ptf_test_port_map[str(src_port)]['target_dut'] and
                            self.ptf_test_port_map[str(port)]['asic_idx'] ==
                                self.ptf_test_port_map[str(src_port)]['asic_idx']):
                            updated_exp_port_list.append(port)
                    if updated_exp_port_list:
                        exp_port_lists = [updated_exp_port_list]

                skip = False
                for exp_port_list in exp_port_lists:
                    if len(exp_port_list) <= 1:
                        # Only 1 expected output port is not enough for balancing test.
                        skip = True
                        break
                if skip:
                    continue
                hit_count_map = {}
                # Change balancing_test_times according to number of next hop groups
                logging.info('Checking ip range balancing {}, src_port={}, exp_ports={}, dst_ip={}, dut_index={}'
                             .format(ip_range, src_port, exp_port_lists, dst_ip, dut_index))
                for i in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
                    (matched_port, _) = self.check_ip_route(
                        src_port, dst_ip, exp_port_lists, ipv4)
                    hit_count_map[matched_port] = hit_count_map.get(
                        matched_port, 0) + 1
                for next_hop in next_hops:
                    # only check balance on a DUT
                    self.check_hit_count_map(
                        next_hop.get_next_hop(), hit_count_map, src_port)
                    self.balancing_test_count += 1
                if self.balancing_test_count >= self.balancing_test_number:
                    break

    def check_ip_route(self, src_port, dst_ip_addr, dst_port_lists, ipv4=True):
        if ipv4:
            res = self.check_ipv4_route(src_port, dst_ip_addr, dst_port_lists)
        else:
            res = self.check_ipv6_route(src_port, dst_ip_addr, dst_port_lists)

        if self.pkt_action == self.ACTION_DROP:
            return res

        (matched_port, received) = res

        assert received

        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def check_ipv4_route(self, src_port, dst_ip_addr, dst_port_lists):
        '''
        @summary: Check IPv4 route works.
        @param src_port: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = "30.0.0.1"
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, src_port)

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        pkt = simple_tcp_packet(
            pktlen=self.pktlen,
            eth_dst=router_mac,
            eth_src=src_mac,
            ip_src=ip_src,
            ip_dst=ip_dst,
            tcp_sport=sport,
            tcp_dport=dport,
            ip_ttl=self.ttl,
            ip_options=self.ip_options,
            dl_vlan_enable=self.src_vid is not None,
            vlan_vid=self.src_vid or 0)
        exp_pkt = simple_tcp_packet(
            self.pktlen,
            ip_src=ip_src,
            ip_dst=ip_dst,
            tcp_sport=sport,
            tcp_dport=dport,
            ip_ttl=max(self.ttl-1, 0),
            ip_options=self.ip_options,
            dl_vlan_enable=self.dst_vid is not None,
            vlan_vid=self.dst_vid or 0)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={}) on port {}'
                     .format(pkt.src,
                             pkt.dst,
                             pkt['IP'].src,
                             pkt['IP'].dst,
                             sport,
                             dport,
                             src_port))
        logging.info('Expect Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={})'
                     .format('any',
                             'any',
                             ip_src,
                             ip_dst,
                             sport,
                             dport))

        dst_ports = list(itertools.chain(*dst_port_lists))
        if self.pkt_action == self.ACTION_FWD:
            rcvd_port_index, rcvd_pkt = verify_packet_any_port(
                self, masked_exp_pkt, dst_ports, timeout=1)
            rcvd_port = dst_ports[rcvd_port_index]
            len_rcvd_pkt = len(rcvd_pkt)
            logging.info('Recieved packet at port {} and packet is {} bytes'.format(
                rcvd_port, len_rcvd_pkt))
            logging.info(
                'Recieved packet with length of {}'.format(len_rcvd_pkt))
            exp_src_mac = None
            if len(self.ptf_test_port_map[str(rcvd_port)]["target_src_mac"]) > 1:
                # active-active dualtor, the packet could be received from either ToR, so use the received
                # port to find the corresponding ToR
                for dut_index, port_list in enumerate(dst_port_lists):
                    if rcvd_port in port_list:
                        exp_src_mac = self.ptf_test_port_map[str(
                            rcvd_port)]["target_src_mac"][dut_index]
            else:
                exp_src_mac = self.ptf_test_port_map[str(
                    rcvd_port)]["target_src_mac"][0]
            actual_src_mac = scapy.Ether(rcvd_pkt).src
            if exp_src_mac != actual_src_mac:
                raise Exception(
                    "Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                    "but the src mac doesn't match, expected {}, got {}".
                    format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
            return (rcvd_port, rcvd_pkt)
        elif self.pkt_action == self.ACTION_DROP:
            verify_no_packet_any(self, masked_exp_pkt, dst_ports)
            return (None, None)
    # ---------------------------------------------------------------------

    def check_ipv6_route(self, src_port, dst_ip_addr, dst_port_lists):
        '''
        @summary: Check IPv6 route works.
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        sport = random.randint(0, 65535)
        dport = random.randint(0, 65535)
        ip_src = '2000:0030::1'
        ip_dst = dst_ip_addr
        src_mac = self.dataplane.get_mac(0, src_port)

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        pkt = simple_tcpv6_packet(
            pktlen=self.pktlen,
            eth_dst=router_mac,
            eth_src=src_mac,
            ipv6_dst=ip_dst,
            ipv6_src=ip_src,
            tcp_sport=sport,
            tcp_dport=dport,
            ipv6_hlim=self.ttl,
            dl_vlan_enable=self.src_vid is not None,
            vlan_vid=self.src_vid or 0)
        exp_pkt = simple_tcpv6_packet(
            pktlen=self.pktlen,
            ipv6_dst=ip_dst,
            ipv6_src=ip_src,
            tcp_sport=sport,
            tcp_dport=dport,
            ipv6_hlim=max(self.ttl-1, 0),
            dl_vlan_enable=self.dst_vid is not None,
            vlan_vid=self.dst_vid or 0)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={}) on port {}'
                     .format(pkt.src,
                             pkt.dst,
                             pkt['IPv6'].src,
                             pkt['IPv6'].dst,
                             sport,
                             dport,
                             src_port))
        logging.info('Expect Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={})'
                     .format('any',
                             'any',
                             ip_src,
                             ip_dst,
                             sport,
                             dport))

        dst_ports = list(itertools.chain(*dst_port_lists))
        if self.pkt_action == self.ACTION_FWD:
            rcvd_port_index, rcvd_pkt = verify_packet_any_port(
                self, masked_exp_pkt, dst_ports, timeout=1)
            rcvd_port = dst_ports[rcvd_port_index]
            len_rcvd_pkt = len(rcvd_pkt)
            logging.info('Recieved packet at port {} and packet is {} bytes'.format(
                rcvd_port, len_rcvd_pkt))
            logging.info(
                'Recieved packet with length of {}'.format(len_rcvd_pkt))
            exp_src_mac = None
            if len(self.ptf_test_port_map[str(rcvd_port)]["target_src_mac"]) > 1:
                # active-active dualtor, the packet could be received from either ToR, so use the received
                # port to find the corresponding ToR
                for dut_index, port_list in enumerate(dst_port_lists):
                    if rcvd_port in port_list:
                        exp_src_mac = self.ptf_test_port_map[str(
                            rcvd_port)]["target_src_mac"][dut_index]
            else:
                exp_src_mac = self.ptf_test_port_map[str(
                    rcvd_port)]["target_src_mac"][0]
            actual_src_mac = scapy.Ether(rcvd_pkt).src
            if exp_src_mac != actual_src_mac:
                raise Exception(
                    "Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                    "but the src mac doesn't match, expected {}, got {}".
                    format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
            return (rcvd_port, rcvd_pkt)
        elif self.pkt_action == self.ACTION_DROP:
            verify_no_packet_any(self, masked_exp_pkt, dst_ports)
            return (None, None)

    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)

    def check_same_asic(self, src_port, exp_port_list):
        updated_exp_port_list = list()
        for port in exp_port_list:
            if type(port) == list:
                per_port_list = list()
                for per_port in port:
                    if self.ptf_test_port_map[str(per_port)]['target_dut'] \
                            != self.ptf_test_port_map[str(src_port)]['target_dut']:
                        return exp_port_list
                    else:
                        if self.ptf_test_port_map[str(per_port)]['asic_idx'] \
                                == self.ptf_test_port_map[str(src_port)]['asic_idx']:
                            per_port_list.append(per_port)
                if per_port_list:
                    updated_exp_port_list.append(per_port_list)
            else:
                if self.ptf_test_port_map[str(port)]['target_dut'] \
                        != self.ptf_test_port_map[str(src_port)]['target_dut']:
                    return exp_port_list
                else:
                    if self.ptf_test_port_map[str(port)]['asic_idx'] \
                            == self.ptf_test_port_map[str(src_port)]['asic_idx']:
                        updated_exp_port_list.append(port)
        if updated_exp_port_list:
            exp_port_list = updated_exp_port_list
        return exp_port_list

    def check_hit_count_map(self, dest_port_list, port_hit_cnt, src_port):
        '''
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @return bool
        '''
        logging.info("%-10s \t %-10s \t %10s \t %10s \t %10s" %
                     ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
        result = True

        if self.switch_type == "chassis-packet":
            dest_port_list = self.check_same_asic(src_port, dest_port_list)

        asic_list = defaultdict(list)
        if self.switch_type == "voq":
            asic_list['voq'] = dest_port_list
        else:
            for port in dest_port_list:
                if type(port) == list:
                    port_map = self.ptf_test_port_map[str(port[0])]
                    asic_id = port_map.get('asic_idx', 0)
                    member = asic_list.get(asic_id)
                    if member is None:
                        member = []
                    member.append(port)
                    asic_list[asic_id] = member
                else:
                    port_map = self.ptf_test_port_map[str(port)]
                    asic_id = port_map.get('asic_idx', 0)
                    member = asic_list.get(asic_id)
                    if member is None:
                        member = []
                    member.append(port)
                    asic_list[asic_id] = member

        total_hit_cnt = 0
        for ecmp_entry in dest_port_list:
            for member in ecmp_entry:
                total_hit_cnt += port_hit_cnt.get(member, 0)

        total_hit_cnt = total_hit_cnt//len(asic_list.keys())

        for asic_member in asic_list.values():
            for ecmp_entry in asic_member:
                total_entry_hit_cnt = 0
                for member in ecmp_entry:
                    total_entry_hit_cnt += port_hit_cnt.get(member, 0)
                (p, r) = self.check_within_expected_range(
                    total_entry_hit_cnt, float(total_hit_cnt)/len(asic_member))
                logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                             % ("ECMP", str(ecmp_entry), total_hit_cnt//len(asic_member),
                                total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
                result &= r
                if len(ecmp_entry) == 1 or total_entry_hit_cnt == 0:
                    continue
                for member in ecmp_entry:
                    (p, r) = self.check_within_expected_range(port_hit_cnt.get(
                        member, 0), float(total_entry_hit_cnt)/len(ecmp_entry))
                    logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                                 % ("LAG", str(member), total_entry_hit_cnt//len(ecmp_entry),
                                    port_hit_cnt.get(member, 0), str(round(p, 4)*100) + '%'))
                    result &= r

        assert result

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        # IPv4 Test
        if (self.test_ipv4):
            self.check_ip_ranges()
        # IPv6 Test
        if (self.test_ipv6):
            self.check_ip_ranges(ipv4=False)
