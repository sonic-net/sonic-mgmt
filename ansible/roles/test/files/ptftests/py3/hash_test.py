'''
Description:    This file contains the hash test for SONiC
'''

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------
import logging
import random
import json
import time
import six
import itertools

from collections import Iterable, defaultdict
from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_tcpv6_packet
from ptf.testutils import send_packet
from ptf.testutils import verify_packet_any_port
from ptf.testutils import simple_ipv4ip_packet
from ptf.testutils import simple_vxlan_packet
from ptf.testutils import simple_vxlanv6_packet
from ptf.testutils import simple_nvgre_packet

import fib
import lpm
import macsec


class HashTest(BaseTest):

    # ---------------------------------------------------------------------
    # Class variables
    # ---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 250
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
        '''
        self.dataplane = ptf.dataplane_instance

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

        self.src_ip_range = [six.text_type(
            x) for x in self.test_params['src_ip_range'].split(',')]
        self.dst_ip_range = [six.text_type(
            x) for x in self.test_params['dst_ip_range'].split(',')]
        self.src_ip_interval = lpm.LpmDict.IpInterval(ip_address(
            self.src_ip_range[0]), ip_address(self.src_ip_range[1]))
        self.dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(
            self.dst_ip_range[0]), ip_address(self.dst_ip_range[1]))
        self.vlan_ids = self.test_params.get('vlan_ids', [])
        self.hash_keys = self.test_params.get(
            'hash_keys', ['src-ip', 'dst-ip', 'src-port', 'dst-port'])
        self.src_ports = [int(port) for port in self.ptf_test_port_map.keys()]

        self.balancing_range = self.test_params.get(
            'balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get(
            'balancing_test_times', self.BALANCING_TEST_TIMES)
        self.switch_type = self.test_params.get(
            'switch_type', self.DEFAULT_SWITCH_TYPE)

        self.ignore_ttl = self.test_params.get('ignore_ttl', False)
        self.single_fib = self.test_params.get(
            'single_fib_for_duts', 'multiple-fib')

        self.ipver = self.test_params.get('ipver', 'ipv4')
        self.is_active_active_dualtor = self.test_params.get("is_active_active_dualtor", False)

        # set the base mac here to make it persistent across calls of check_ip_route
        self.base_mac = self.dataplane.get_mac(
            *random.choice(list(self.dataplane.ports.keys())))
        self.vxlan_dest_port = int(self.test_params.get('vxlan_dest_port', 0))

    def _get_nexthops(self, src_port, dst_ip):
        active_dut_indexes = [0]
        if self.single_fib == "multiple-fib":
            active_dut_indexes = self.ptf_test_port_map[str(
                src_port)]['target_dut']
        next_hops = [self.fibs[active_dut_index][dst_ip]
                     for active_dut_index in active_dut_indexes]
        return next_hops

    def get_src_and_exp_ports(self, dst_ip):
        while True:
            src_port = int(random.choice(self.src_ports))
            next_hops = self._get_nexthops(src_port, dst_ip)
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
                if self.single_fib == "single-fib-single-hop" and exp_port_lists[0]:
                    dest_port_dut_index = self.ptf_test_port_map[str(exp_port_lists[0][0])]['target_dut'][0]
                    src_port_dut_index = self.ptf_test_port_map[str(src_port)]['target_dut'][0]
                    if src_port_dut_index == 0 and dest_port_dut_index == 0:
                        ptf_non_upstream_ports = []
                        for ptf_port, ptf_port_info in self.ptf_test_port_map.items():
                            if ptf_port_info['target_dut'][0] != 0:
                                ptf_non_upstream_ports.append(ptf_port)
                        src_port = int(random.choice(ptf_non_upstream_ports))

                break
        return src_port, exp_port_lists, next_hops

    def get_ingress_ports(self, exp_port_lists, dst_ip):
        # To test ingress-port hash, we need to ensure that the exp_port_list be identical for all the ingress ports.
        # For dualtor topology, the exp_port_list could be T1 facing ports on either one of the ToR if the ingress
        # ports include all ports. For example:
        # scenario 1: Ingress port is one of PTF ports connected to VLAN interfaces of both ToRs. Then exp_port_list
        #             should be T1 faccing ports of the active side ToR. (Before test, we always set active side of all
        #             mux cables to same side.)
        # scenario 2: Ingress port is one of PTF ports connected to T1 facing ports of upper ToR. Then exp_port_list
        #             will be upper ToR's T1 facing ports.
        # scenario 3: Ingress port is one of PTF ports connected to T1 facing ports of lower ToR. Then exp_port_list
        #             will be lower ToR's T1 facing ports.
        # Scenario 2&3 could cause problem. That's why we need to further filter the ingress ports.
        exp_ports = list(itertools.chain(*exp_port_lists))
        ports = list(set(self.src_ports) - set(exp_ports))
        filtered_ports = []
        for port in ports:
            next_hops = self._get_nexthops(port, dst_ip)
            possible_exp_port_lists = [
                next_hop.get_next_hop_list() for next_hop in next_hops]
            possible_exp_ports = list(
                itertools.chain(*possible_exp_port_lists))
            if set(possible_exp_ports) == set(exp_ports):
                filtered_ports.append(port)
        logging.info('ports={}'.format(ports))
        logging.info('filtered_ports={}'.format(filtered_ports))
        return filtered_ports

    def check_hash(self, hash_key):
        dst_ip = self.dst_ip_interval.get_random_ip()
        src_port, exp_port_lists, next_hops = self.get_src_and_exp_ports(
            dst_ip)
        if self.switch_type == "chassis-packet":
            exp_port_lists = self.check_same_asic(src_port, exp_port_lists)
        logging.info("dst_ip={}, src_port={}, exp_port_lists={}".format(
            dst_ip, src_port, exp_port_lists))
        for exp_port_list in exp_port_lists:
            if len(exp_port_list) <= 1:
                logging.warning("{} has only {} nexthop".format(
                    dst_ip, exp_port_list))
                assert False

        hit_count_map = {}
        if hash_key == 'ingress-port':
            # The 'ingress-port' key is not used in hash by design. We are doing negative test for 'ingress-port'.
            # When 'ingress-port' is included in HASH_KEYS, the PTF test will try to inject same packet to different
            # ingress ports and expect that they are forwarded from same egress port.
            for ingress_port in self.get_ingress_ports(exp_port_lists, dst_ip):
                print(ingress_port)
                logging.info('Checking hash key {}, src_port={}, exp_ports={}, dst_ip={}'
                             .format(hash_key, ingress_port, exp_port_lists, dst_ip))
                (matched_port, _) = self.check_ip_route(
                    hash_key, ingress_port, dst_ip, exp_port_lists)
                hit_count_map[matched_port] = hit_count_map.get(
                    matched_port, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            # if the packet from the ingress port could go to both ToRs(active-active dualtor), we should
            # expect that the packets go to the same ToR has same egress port, so there should be two entries
            # in the hit count map.
            assert len(hit_count_map.keys()) == len(
                self.ptf_test_port_map[str(ingress_port)]["target_dut"])
        else:
            for _ in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
                logging.info('Checking hash key {}, src_port={}, exp_ports={}, dst_ip={}'
                             .format(hash_key, src_port, exp_port_lists, dst_ip))
                (matched_port, _) = self.check_ip_route(
                    hash_key, src_port, dst_ip, exp_port_lists)
                hit_count_map[matched_port] = hit_count_map.get(
                    matched_port, 0) + 1
            logging.info("hash_key={}, hit count map: {}".format(
                hash_key, hit_count_map))

            for next_hop in next_hops:
                self.check_balancing(next_hop.get_next_hop(), hit_count_map, src_port)

    def check_ip_route(self, hash_key, src_port, dst_ip, dst_port_lists):
        if ip_network(six.text_type(dst_ip)).version == 4:
            (matched_port, received) = self.check_ipv4_route(
                hash_key, src_port, dst_port_lists)
        else:
            (matched_port, received) = self.check_ipv6_route(
                hash_key, src_port, dst_port_lists)

        assert received

        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def _get_ip_proto(self, ipv6=False):
        # ip_proto 2 is IGMP, should not be forwarded by router
        # ip_proto 4 and 41 are encapsulation protocol, ip payload will be malformat
        # ip_proto 60 is redirected to ip_proto 4 as encapsulation protocol, ip payload will be malformat
        # ip_proto 254 is experimental
        # MLNX ASIC can't forward ip_proto 254, BRCM is OK, skip for all for simplicity
        skip_protos = [2, 253, 4, 41, 60, 254]

        if self.is_active_active_dualtor:
            # Skip ICMP for active-active dualtor as it is duplicated to both ToRs
            skip_protos.append(1)

        if ipv6:
            # Skip ip_proto 0 for IPv6
            skip_protos.append(0)
            # Skip IPv6-ICMP for active-active dualtor as it is duplicated to both ToRs
            skip_protos.append(58)

        while True:
            ip_proto = random.randint(0, 255)
            if ip_proto not in skip_protos:
                return ip_proto

    def check_ipv4_route(self, hash_key, src_port, dst_port_lists):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param src_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto() if hash_key == 'ip-proto' else None

        pkt = simple_tcp_packet(pktlen=100 if vlan_id == 0 else 104,
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                dl_vlan_enable=False if vlan_id == 0 else True,
                                vlan_vid=vlan_id,
                                vlan_pcp=0,
                                ip_src=ip_src,
                                ip_dst=ip_dst,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            ip_src=ip_src,
            ip_dst=ip_dst,
            tcp_sport=sport,
            tcp_dport=dport,
            ip_ttl=63)

        if hash_key == 'ip-proto':
            pkt['IP'].proto = ip_proto
            exp_pkt['IP'].proto = ip_proto
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={}, proto={})/TCP(sport={}, dport={} on port {})'
                     .format(pkt.src,
                             pkt.dst,
                             pkt['IP'].src,
                             pkt['IP'].dst,
                             pkt['IP'].proto,
                             sport,
                             dport,
                             src_port))
        logging.info('Expect Ether(src={}, dst={})/IP(src={}, dst={}, proto={})/TCP(sport={}, dport={})'
                     .format('any',
                             'any',
                             ip_src,
                             ip_dst,
                             ip_proto,
                             sport,
                             dport))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports, timeout=1)
        rcvd_port = dst_ports[rcvd_port_index]

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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ipv6_route(self, hash_key, src_port, dst_port_lists):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()

        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto(
            ipv6=True) if hash_key == "ip-proto" else None

        pkt = simple_tcpv6_packet(pktlen=100 if vlan_id == 0 else 104,
                                  eth_dst=router_mac,
                                  eth_src=src_mac,
                                  dl_vlan_enable=False if vlan_id == 0 else True,
                                  vlan_vid=vlan_id,
                                  vlan_pcp=0,
                                  ipv6_dst=ip_dst,
                                  ipv6_src=ip_src,
                                  tcp_sport=sport,
                                  tcp_dport=dport,
                                  ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
            ipv6_dst=ip_dst,
            ipv6_src=ip_src,
            tcp_sport=sport,
            tcp_dport=dport,
            ipv6_hlim=63)

        if hash_key == 'ip-proto':
            pkt['IPv6'].nh = ip_proto
            exp_pkt['IPv6'].nh = ip_proto

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IPv6(src={}, dst={}, proto={})/TCP(sport={}, dport={} on port {})'
                     .format(pkt.src,
                             pkt.dst,
                             pkt['IPv6'].src,
                             pkt['IPv6'].dst,
                             pkt['IPv6'].nh,
                             sport,
                             dport,
                             src_port))
        logging.info('Expect Ether(src={}, dst={})/IPv6(src={}, dst={}, proto={})/TCP(sport={}, dport={})'
                     .format('any',
                             'any',
                             ip_src,
                             ip_dst,
                             ip_proto,
                             sport,
                             dport))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports, timeout=1)
        rcvd_port = dst_ports[rcvd_port_index]

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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

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

    def check_balancing(self, dest_port_list, port_hit_cnt, src_port):
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
        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)


class IPinIPHashTest(HashTest):
    '''
    This test is to verify the hash key for IPinIP packet.
    The src_ip, dst_ip, src_port and dst_port of inner frame are expected to be hash keys
    for IPinIP packet.
    '''

    def check_ipv4_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param src_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto() if hash_key == 'ip-proto' else None

        inner_pkt_len = random.randrange(
            100, 1024) if hash_key == 'inner_length' else 100

        pkt = simple_tcp_packet(pktlen=inner_pkt_len if vlan_id == 0 else inner_pkt_len + 4,
                                dl_vlan_enable=False if vlan_id == 0 else True,
                                vlan_vid=vlan_id,
                                vlan_pcp=0,
                                ip_src=ip_src,
                                ip_dst=ip_dst,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ip_ttl=64)

        ipinip_pkt = simple_ipv4ip_packet(
            eth_dst=router_mac,
            eth_src=src_mac,
            ip_src=outer_src_ip,
            ip_dst=outer_dst_ip,
            inner_frame=pkt['IP'])

        exp_pkt = ipinip_pkt.copy()
        exp_pkt['IP'].ttl -= 1

        if hash_key == 'ip-proto':
            ipinip_pkt['IP'].payload.proto = ip_proto
            exp_pkt['IP'].payload.proto = ip_proto
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, ipinip_pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={}, proto={})/IP(src={}, '
                     'dst={}, proto={})/TCP(sport={}, dport={} on port {})'
                     .format(ipinip_pkt.src,
                             ipinip_pkt.dst,
                             ipinip_pkt['IP'].src,
                             ipinip_pkt['IP'].dst,
                             ipinip_pkt['IP'].proto,
                             pkt['IP'].src,
                             pkt['IP'].dst,
                             pkt['IP'].proto,
                             sport,
                             dport,
                             src_port))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]
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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ipv6_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()

        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto(
            ipv6=True) if hash_key == "ip-proto" else None

        inner_pkt_len = random.randrange(
            100, 1024) if hash_key == 'inner_length' else 100

        pkt = simple_tcpv6_packet(pktlen=inner_pkt_len if vlan_id == 0 else inner_pkt_len + 4,
                                  dl_vlan_enable=False if vlan_id == 0 else True,
                                  vlan_vid=vlan_id,
                                  vlan_pcp=0,
                                  ipv6_dst=ip_dst,
                                  ipv6_src=ip_src,
                                  tcp_sport=sport,
                                  tcp_dport=dport,
                                  ipv6_hlim=64)

        ipinip_pkt = simple_ipv4ip_packet(
            eth_dst=router_mac,
            eth_src=src_mac,
            ip_src=outer_src_ip,
            ip_dst=outer_dst_ip,
            inner_frame=pkt['IPv6'])

        exp_pkt = ipinip_pkt.copy()
        exp_pkt['IP'].ttl -= 1

        if hash_key == 'ip-proto':
            ipinip_pkt['IP'].payload['IPv6'].nh = ip_proto
            exp_pkt['IP'].payload['IPv6'].nh = ip_proto

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, ipinip_pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={}, proto={})/IPv6(src={}, '
                     'dst={}, proto={})/TCP(sport={}, dport={} on port {})'
                     .format(ipinip_pkt.src,
                             ipinip_pkt.dst,
                             ipinip_pkt['IP'].src,
                             ipinip_pkt['IP'].dst,
                             ipinip_pkt['IP'].proto,
                             pkt['IPv6'].src,
                             pkt['IPv6'].dst,
                             pkt['IPv6'].nh,
                             sport,
                             dport,
                             src_port))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]

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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ip_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip):
        if self.ipver == 'ipv4':
            (matched_port, received) = self.check_ipv4_route(
                hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip)
        else:
            (matched_port, received) = self.check_ipv6_route(
                hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip)

        assert received

        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def check_hash(self, hash_key):
        # Use dummy IPv4 address for outer_src_ip and outer_dst_ip
        # We don't care the actually value as long as the outer_dst_ip is routed by default routed
        # The outer_src_ip and outer_dst_ip are fixed
        outer_src_ip = '80.1.0.31'
        outer_dst_ip = '80.1.0.32'
        src_port, exp_port_lists, next_hops = self.get_src_and_exp_ports(
            outer_dst_ip)
        if self.switch_type == "chassis-packet":
            exp_port_lists = self.check_same_asic(src_port, exp_port_lists)

        logging.info("outer_src_ip={}, outer_dst_ip={}, src_port={}, exp_port_lists={}".format(
            outer_src_ip, outer_dst_ip, src_port, exp_port_lists))
        for exp_port_list in exp_port_lists:
            if len(exp_port_list) <= 1:
                logging.warning("{} has only {} nexthop".format(
                    outer_dst_ip, exp_port_list))
                assert False

        hit_count_map = {}
        if hash_key == 'ingress-port':
            # The 'ingress-port' key is not used in hash by design. We are doing negative test for 'ingress-port'.
            # When 'ingress-port' is included in HASH_KEYS, the PTF test will try to inject same packet to different
            # ingress ports and expect that they are forwarded from same egress port.
            for ingress_port in self.get_ingress_ports(exp_port_lists, outer_dst_ip):
                logging.info('Checking hash key {}, src_port={}, exp_ports={}, outer_src_ip={}, outer_dst_ip={}'
                             .format(hash_key, ingress_port, exp_port_lists, outer_src_ip, outer_dst_ip))
                (matched_index, _) = self.check_ip_route(hash_key,
                                                         ingress_port, exp_port_lists, outer_src_ip, outer_dst_ip)
                hit_count_map[matched_index] = hit_count_map.get(
                    matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            assert True if len(hit_count_map.keys()) == 1 else False
        elif hash_key == 'inner_length':
            # The length of inner_frame is not used as hash key for IPinIP packet.
            # The test generates IPinIP packets with random inner_frame_length, and then verify the egress path.
            # The egress port should never change
            for _ in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
                logging.info('Checking hash key {}, exp_ports={}, outer_src_ip={}, outer_dst_ip={}'
                             .format(hash_key, exp_port_lists, outer_src_ip, outer_dst_ip))
                (matched_index, _) = self.check_ip_route(hash_key,
                                                         src_port, exp_port_lists, outer_src_ip, outer_dst_ip)
                hit_count_map[matched_index] = hit_count_map.get(
                    matched_index, 0) + 1
            logging.info("hit count map: {}".format(hit_count_map))
            assert True if len(hit_count_map.keys()) == 1 else False
        else:
            for _ in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
                logging.info('Checking hash key {}, src_port={}, exp_ports={}, outer_src_ip={}, outer_dst_ip={}'
                             .format(hash_key, src_port, exp_port_lists, outer_src_ip, outer_dst_ip))
                (matched_index, _) = self.check_ip_route(hash_key,
                                                         src_port, exp_port_lists, outer_src_ip, outer_dst_ip)
                hit_count_map[matched_index] = hit_count_map.get(
                    matched_index, 0) + 1
            logging.info("hash_key={}, hit count map: {}".format(
                hash_key, hit_count_map))

            for next_hop in next_hops:
                self.check_balancing(next_hop.get_next_hop(), hit_count_map, src_port)

    def runTest(self):
        """
        @summary: Send IPinIP packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        logging.info("List of hash_keys: {}".format(self.hash_keys))
        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)


class VxlanHashTest(HashTest):
    '''
    This test is to verify the hash key for VxLAN packet.
    The src_ip, dst_ip, src_port and dst_port of inner frame are expected to be hash keys
    for IPinIP packet.
    '''

    def check_ipv4_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param src_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80
        outer_sport = random.randint(0, 65536) if hash_key == 'outer-src-port' else 1234

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        dst_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'dst-mac' else self.base_mac

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        if self.ipver == "ipv4-ipv4":
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ip_dst": ip_dst,
                "ip_src": ip_src,
                "ip_ttl": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}

            inner_pkt = simple_tcp_packet(**pkt_opts)
        else:
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ipv6_dst": ip_dst,
                "ipv6_src": ip_src,
                "ipv6_hlim": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcpv6_packet(**pkt_opts)
        pkt_opts = {
            'eth_dst': router_mac,
            'ip_src': outer_src_ip,
            'ip_dst': outer_dst_ip,
            'ip_ttl': 64,
            'udp_sport': outer_sport,
            'udp_dport': self.vxlan_dest_port,
            'with_udp_chksum': False,
            'vxlan_vni': 2000,
            'inner_frame': inner_pkt}
        vxlan_pkt = simple_vxlan_packet(**pkt_opts)

        exp_pkt = vxlan_pkt.copy()
        exp_pkt['IP'].ttl -= 1

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        # mask the chksum also if masking the ttl
        if self.ignore_ttl:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        send_packet(self, src_port, vxlan_pkt)
        logging.info('Sent Outer Ether(src={}, dst={})/IP(src={}, dst={})VxLAN(sport={}, '
                     'dport={})/Inner Ether(src={}, dst={}), IP(src={}, '
                     'dst={} )/TCP(sport={}, dport={} on port {})'
                     .format(vxlan_pkt.src,
                             vxlan_pkt.dst,
                             vxlan_pkt['IP'].src,
                             vxlan_pkt['IP'].dst,
                             outer_sport,
                             self.vxlan_dest_port,
                             inner_pkt.src,
                             inner_pkt.dst,
                             ip_src,
                             ip_dst,
                             sport,
                             dport,
                             src_port))
        logging.info(vxlan_pkt.show())

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]
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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ipv6_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()

        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        dst_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'dst-mac' else self.base_mac
        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        outer_sport = random.randint(0, 65536) if hash_key == 'outer-src-port' else 1234

        if self.ipver == 'ipv6-ipv6':
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ipv6_dst": ip_dst,
                "ipv6_src": ip_src,
                "ipv6_hlim": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcpv6_packet(**pkt_opts)
        else:
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ip_dst": ip_dst,
                "ip_src": ip_src,
                "ip_ttl": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcp_packet(**pkt_opts)

        pkt_opts = {
            'eth_dst': router_mac,
            'ipv6_src': outer_src_ip,
            'ipv6_dst': outer_dst_ip,
            'ipv6_hlim': 64,
            'udp_sport': outer_sport,
            'udp_dport': self.vxlan_dest_port,
            'with_udp_chksum': False,
            'vxlan_vni': 2000,
            'inner_frame': inner_pkt}
        vxlan_pkt = simple_vxlanv6_packet(**pkt_opts)

        exp_pkt = vxlan_pkt.copy()
        exp_pkt['IPv6'].hlim -= 1

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, src_port, vxlan_pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={})VxLAN(sport={}, dport={})'
                     '/Inner Ether(src={}, dst={}), Inner IPv6(src={}, '
                     'dst={})/TCP(sport={}, dport={} on port {})'
                     .format(vxlan_pkt.src,
                             vxlan_pkt.dst,
                             vxlan_pkt['IPv6'].src,
                             vxlan_pkt['IPv6'].dst,
                             outer_sport,
                             self.vxlan_dest_port,
                             inner_pkt.src,
                             inner_pkt.dst,
                             ip_src,
                             ip_dst,
                             sport,
                             dport,
                             src_port))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]

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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ip_route(self, hash_key, src_port, dst_port_lists, outer_src_ip,
                       outer_dst_ip, outer_src_ipv6, outer_dst_ipv6):
        if self.ipver == 'ipv4-ipv4' or self.ipver == 'ipv4-ipv6':
            (matched_port, received) = self.check_ipv4_route(
                hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip)
        else:
            (matched_port, received) = self.check_ipv6_route(
                hash_key, src_port, dst_port_lists, outer_src_ipv6, outer_dst_ipv6)

        assert received

        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def check_hash(self, hash_key):
        # Use dummy IPv4 address for outer_src_ip and outer_dst_ip
        # We don't care the actually value as long as the outer_dst_ip is routed by default routed
        # The outer_src_ip and outer_dst_ip are fixed
        outer_src_ip = '80.1.0.31'
        outer_dst_ip = '80.1.0.32'
        outer_src_ipv6 = '80::31'
        outer_dst_ipv6 = '80::32'
        src_port, exp_port_lists, next_hops = self.get_src_and_exp_ports(
            outer_dst_ip)
        if self.switch_type == "chassis-packet":
            exp_port_lists = self.check_same_asic(src_port, exp_port_lists)

        logging.info("outer_src_ip={}, outer_dst_ip={}, src_port={}, exp_port_lists={}".format(
            outer_src_ip, outer_dst_ip, src_port, exp_port_lists))
        for exp_port_list in exp_port_lists:
            if len(exp_port_list) <= 1:
                logging.warning("{} has only {} nexthop".format(
                    outer_dst_ip, exp_port_list))
                assert False

        hit_count_map = {}
        for _ in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
            logging.info('Checking hash key {}, src_port={}, exp_ports={}, outer_src_ip={}, outer_dst_ip={}'
                         .format(hash_key, src_port, exp_port_lists, outer_src_ip, outer_dst_ip))
            (matched_index, _) = self.check_ip_route(hash_key,
                                                     src_port, exp_port_lists, outer_src_ip, outer_dst_ip,
                                                     outer_src_ipv6, outer_dst_ipv6)
            hit_count_map[matched_index] = hit_count_map.get(
                matched_index, 0) + 1
        logging.info("hash_key={}, hit count map: {}".format(
            hash_key, hit_count_map))

        for next_hop in next_hops:
            self.check_balancing(next_hop.get_next_hop(), hit_count_map, src_port)

    def runTest(self):
        """
        @summary: Send IPinIP packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        logging.info("List of hash_keys: {}".format(self.hash_keys))
        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)


class NvgreHashTest(HashTest):
    '''
    This test is to verify the hash key for NvGRE packet.
    The src_ip, dst_ip, src_port and dst_port of inner frame are expected to be hash keys
    for NvGRE packet.
    '''

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
            logging.error(
                "A NVGRE packet was requested but NVGRE is not supported by your Scapy. "
                "See README for more information")
            return None

        nvgre_hdr = scapy.NVGRE(vsid=nvgre_tni, flowid=nvgre_flowid)

        if (dl_vlan_enable):
            pkt = scapy.Ether(dst=eth_dst, src=eth_src) / \
                scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid) / \
                scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim, nh=47) / \
                nvgre_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src) / \
                scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim, nh=47) / \
                nvgre_hdr

        if inner_frame:
            pkt = pkt / inner_frame
        else:
            pkt = pkt / scapy.IP()
            pkt = pkt/("D" * (pktlen - len(pkt)))

        return pkt

    def check_ipv4_route(self, hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip, ipver):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param src_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        dst_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'dst-mac' else self.base_mac

        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        if self.ipver == 'ipv4-ipv4':
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ip_dst": ip_dst,
                "ip_src": ip_src,
                "ip_ttl": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcp_packet(**pkt_opts)
        else:
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ipv6_dst": ip_dst,
                "ipv6_src": ip_src,
                "ipv6_hlim": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcpv6_packet(**pkt_opts)

        tni = random.randint(1, 254) + 20000
        pkt_opts = {
            'eth_dst': router_mac,
            'ip_src': outer_src_ip,
            'ip_dst': outer_dst_ip,
            'ip_ttl': 64,
            'nvgre_tni': tni,
            'inner_frame': inner_pkt}
        nvgre_pkt = simple_nvgre_packet(**pkt_opts)

        exp_pkt = nvgre_pkt.copy()
        exp_pkt['IP'].ttl -= 1

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, src_port, nvgre_pkt)
        logging.info('Sent Outer Ether(src={}, dst={})/IP(src={}, dst={}, nvgre_tni={})'
                     '/Inner Ether(src={}, dst={}), IP(src={}, '
                     'dst={} )/TCP(sport={}, dport={} on port {})'
                     .format(nvgre_pkt.src,
                             nvgre_pkt.dst,
                             nvgre_pkt['IP'].src,
                             nvgre_pkt['IP'].dst,
                             tni,
                             inner_pkt.src,
                             inner_pkt.dst,
                             ip_src,
                             ip_dst,
                             sport,
                             dport,
                             src_port))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]
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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ipv6_route(self, hash_key, src_port, dst_port_lists, outer_src_ipv6, outer_dst_ipv6, ipver):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_lists: list of ports on which to expect packet to come back from the switch
        @param outer_src_ip: source ip at the outer layer
        @param outer_dst_ip: destination ip at the outer layer
        '''
        ip_src = self.src_ip_interval.get_random_ip(
        ) if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip(
        ) if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()

        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'src-mac' else self.base_mac
        dst_mac = (self.base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) \
            if hash_key == 'dst-mac' else self.base_mac
        router_mac = self.ptf_test_port_map[str(src_port)]['target_dest_mac']

        if self.ipver == 'ipv6-ipv6':
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ipv6_dst": ip_dst,
                "ipv6_src": ip_src,
                "ipv6_hlim": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcpv6_packet(**pkt_opts)
        else:
            pkt_opts = {
                "eth_src": src_mac,
                "eth_dst": dst_mac,
                "ip_dst": ip_dst,
                "ip_src": ip_src,
                "ip_ttl": 64,
                "tcp_sport": sport,
                "tcp_dport": dport}
            inner_pkt = simple_tcp_packet(**pkt_opts)

        tni = random.randint(1, 254) + 20000
        pkt_opts = {
            'eth_dst': router_mac,
            'ipv6_src': outer_src_ipv6,
            'ipv6_dst': outer_dst_ipv6,
            'ipv6_hlim': 64,
            'nvgre_tni': tni,
            'inner_frame': inner_pkt}
        nvgre_pkt = self.simple_nvgrev6_packet(**pkt_opts)

        exp_pkt = nvgre_pkt.copy()

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        send_packet(self, src_port, nvgre_pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={}, proto={})/IPv6(src={}, '
                     'dst={})/TCP(sport={}, dport={} on port {})'
                     .format(nvgre_pkt.src,
                             nvgre_pkt.dst,
                             nvgre_pkt['IPv6'].src,
                             nvgre_pkt['IPv6'].dst,
                             nvgre_pkt['IPv6'].proto,
                             ip_src,
                             ip_dst,
                             sport,
                             dport,
                             src_port))

        dst_ports = list(itertools.chain(*dst_port_lists))
        rcvd_port_index, rcvd_pkt = verify_packet_any_port(
            self, masked_exp_pkt, dst_ports)
        rcvd_port = dst_ports[rcvd_port_index]

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
            raise Exception("Pkt sent from {} to {} on port {} was rcvd pkt on {} which is one of the expected ports, "
                            "but the src mac doesn't match, expected {}, got {}".
                            format(ip_src, ip_dst, src_port, rcvd_port, exp_src_mac, actual_src_mac))
        return (rcvd_port, rcvd_pkt)

    def check_ip_route(self, hash_key, src_port, dst_port_lists, outer_src_ip,
                       outer_dst_ip, outer_src_ipv6, outer_dst_ipv6):
        if self.ipver == 'ipv4-ipv4' or self.ipver == 'ipv4-ipv6':
            (matched_port, received) = self.check_ipv4_route(
                hash_key, src_port, dst_port_lists, outer_src_ip, outer_dst_ip, self.ipver)
        else:
            (matched_port, received) = self.check_ipv6_route(
                hash_key, src_port, dst_port_lists, outer_src_ipv6, outer_dst_ipv6, self.ipver)

        assert received

        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def check_hash(self, hash_key):
        # Use dummy IPv4 address for outer_src_ip and outer_dst_ip
        # We don't care the actually value as long as the outer_dst_ip is routed by default routed
        # The outer_src_ip and outer_dst_ip are fixed
        outer_src_ip = '80.1.0.31'
        outer_dst_ip = '80.1.0.32'
        outer_src_ipv6 = '80::31'
        outer_dst_ipv6 = '80::32'
        src_port, exp_port_lists, next_hops = self.get_src_and_exp_ports(
            outer_dst_ip)
        if self.switch_type == "chassis-packet":
            exp_port_lists = self.check_same_asic(src_port, exp_port_lists)

        logging.info("outer_src_ip={}, outer_dst_ip={}, src_port={}, exp_port_lists={}".format(
            outer_src_ip, outer_dst_ip, src_port, exp_port_lists))
        for exp_port_list in exp_port_lists:
            if len(exp_port_list) <= 1:
                logging.warning("{} has only {} nexthop".format(
                    outer_dst_ip, exp_port_list))
                assert False

        hit_count_map = {}
        for _ in range(0, self.balancing_test_times*len(list(itertools.chain(*exp_port_lists)))):
            logging.info('Checking hash key {}, src_port={}, exp_ports={}, outer_src_ip={}, outer_dst_ip={}'
                         .format(hash_key, src_port, exp_port_lists, outer_src_ip, outer_dst_ip))
            (matched_index, _) = self.check_ip_route(hash_key,
                                                     src_port, exp_port_lists, outer_src_ip, outer_dst_ip,
                                                     outer_src_ipv6, outer_dst_ipv6)
            hit_count_map[matched_index] = hit_count_map.get(
                matched_index, 0) + 1
        logging.info("hash_key={}, hit count map: {}".format(
            hash_key, hit_count_map))

        for next_hop in next_hops:
            self.check_balancing(next_hop.get_next_hop(), hit_count_map, src_port)

    def runTest(self):
        """
        @summary: Send NvGRE packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """
        logging.info("List of hash_keys: {}".format(self.hash_keys))
        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)
