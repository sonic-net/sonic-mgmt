"""
Description:    This file contains the generic hash test for SONiC
"""

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------
import logging
import math
import random
import time
import ptf
import ptf.packet as scapy
import re
import ptf.testutils as testutils
import lpm
from ipaddress import ip_address
from ptf.base_tests import BaseTest
from ptf.mask import Mask


def validate_protocol_distribution(protocol_ports, protocol_domain, port_groups, repeats):
    """Check distinct protocol flows, not repeated packets, against an ideal-uniform ECMP model."""
    assert set(protocol_ports) == set(protocol_domain), "Incomplete or unexpected protocol domain."
    assert len(port_groups) > 1 and all(port_groups), "Protocol sensitivity requires multiple nonempty ECMP paths."
    ports = sum(port_groups, [])
    assert len(ports) == len(set(ports)), "ECMP paths must have disjoint receiving ports."
    counts = [0] * len(port_groups)
    members = [set() for _ in port_groups]
    for protocol, observations in protocol_ports.items():
        assert len(observations) == repeats, f"Protocol {protocol} is missing repeated observations."
        assert len(set(observations)) == 1, f"Protocol {protocol} changed receiving port: {observations}."
        port = observations[0]
        assert port in ports, f"Protocol {protocol} reached unexpected port {port}."
        group_index = next(index for index, group in enumerate(port_groups) if port in group)
        counts[group_index] += 1
        members[group_index].add(port)
    assert all(counts), f"Protocol changes did not exercise every ECMP path: {counts}."
    assert all(len(group) == 1 for group in members), "Protocol changes selected multiple members within a LAG."

    # Two marginal binomial tails per path; Bonferroni limits the family-wise
    # false-alarm probability to 1% under the ideal-uniform hash model.
    n = len(protocol_domain)
    p = 1.0 / len(port_groups)
    tail_limit = 0.01 / (2 * len(port_groups))
    probabilities = [math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n + 1)]
    for index, count in enumerate(counts):
        lower_tail = sum(probabilities[:count + 1])
        upper_tail = sum(probabilities[count:])
        assert min(lower_tail, upper_tail) >= tail_limit, (
            f"Protocol-domain ECMP bias on path {index}: counts={counts}, "
            f"lower_tail={lower_tail}, upper_tail={upper_tail}, minimum_tail={tail_limit}."
        )
    logging.info("Protocol-domain distribution: distinct_flows=%s, path_counts=%s, family_wise_alpha=0.01", n, counts)
    return counts


class GenericHashTest(BaseTest):
    # ---------------------------------------------------------------------
    # Class variables
    # ---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.3
    BALANCING_TEST_TIMES = 480
    VXLAN_PORT = 4789
    VXLAN_VNI = 20001
    NVGRE_TNI = 20001
    L4_SRC_PORT = 1234
    L4_DST_PORT = 80
    PROTOCOL_DOMAIN_REPEATS = 3
    PROTOCOL_DUPLICATE_TIMEOUT = 0.1

    _required_params = [
        'sending_ports',
        'expected_port_groups',
        'hash_field',
        'ipver',
        'src_ip_range',
        'dst_ip_range',
        'ecmp_hash',
        'lag_hash'
    ]

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
        self.check_required_params()

    def check_required_params(self):
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception(f"Missing required parameter {param}")

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.ipver = self.test_params['ipver']
        self.inner_ipver = self.test_params.get('inner_ipver')
        if self.inner_ipver == 'None':
            self.inner_ipver = None
        src_ip_range = [str(x) for x in self.test_params['src_ip_range'].split(',')]
        dst_ip_range = [str(x) for x in self.test_params['dst_ip_range'].split(',')]
        self.src_ip_interval = lpm.LpmDict.IpInterval(ip_address(src_ip_range[0]), ip_address(src_ip_range[1]))
        self.dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(dst_ip_range[0]), ip_address(dst_ip_range[1]))
        if self.inner_ipver:
            inner_src_ip_range = [str(x) for x in self.test_params['inner_src_ip_range'].split(',')]
            inner_dst_ip_range = [str(x) for x in self.test_params['inner_dst_ip_range'].split(',')]
            self.inner_src_ip_interval = lpm.LpmDict.IpInterval(ip_address(inner_src_ip_range[0]),
                                                                ip_address(inner_src_ip_range[1]))
            self.inner_dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(inner_dst_ip_range[0]),
                                                                ip_address(inner_dst_ip_range[1]))
        self.hash_field = self.test_params['hash_field']
        self.sending_ports = self.test_params['sending_ports']
        self.expected_port_groups = self.test_params['expected_port_groups']
        self.expected_port_list = sum(self.expected_port_groups, [])
        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get('balancing_test_times', self.BALANCING_TEST_TIMES)
        self.ecmp_hash = self.test_params['ecmp_hash']
        self.lag_hash = self.test_params['lag_hash']
        self.protocol_domain_validation = self.test_params.get('protocol_domain_validation', False)
        self.require_all_expected_ports = self.test_params.get('require_all_expected_ports', False)
        self.vlan_range = self.test_params.get('vlan_range', [1032, 1060])
        self.flow_lable_range = self.test_params.get('flow_label_range', [0, 1048575])
        self.ethertype_range = self.test_params.get('ethertype_range', [0x0801, 0x0900])
        self.is_l2_test = self.test_params.get('is_l2_test', False)
        self.encap_type = self.test_params.get('encap_type')
        self.vxlan_port = self.test_params.get('vxlan_port', self.VXLAN_PORT)
        self.vxlan_vni = self.test_params.get('vxlan_vni', self.VXLAN_VNI)
        self.nvgre_tni = self.test_params.get('nvgre_tni', self.NVGRE_TNI)
        logging.info("=============Test Setup==============")
        logging.info(f"balancing_range:  {self.balancing_range}")
        logging.info(f"balancing_test_times:  {self.balancing_test_times}")
        logging.info(f"hash_field:  {self.hash_field}")
        logging.info(f"ipver:  {self.ipver}")
        if self.inner_ipver:
            logging.info(f"inner_ipver:  {self.inner_ipver}")
            logging.info(f"encap_type:  {self.encap_type}")
        if self.encap_type == 'vxlan':
            logging.info(f"vxlan_port:  {self.vxlan_port}")
        logging.info(f"sending_ports:  {self.sending_ports}")
        logging.info(f"expected_port_groups:  {self.expected_port_groups}")
        logging.info(f"ecmp_hash:  {self.ecmp_hash}")
        logging.info(f"lag_hash:  {self.lag_hash}")
        logging.info(f"is_l2_test:  {self.is_l2_test}")

    def get_ip_protocol_domain(self):
        # ip_proto 2 is IGMP, should not be forwarded by router
        # ip_proto 253, 254 is experimental
        # Nvidia ASIC can't forward ip_proto 254, BRCM is OK, skip for all for simplicity
        # For Nvidia platforms, when the ip_proto are 4, 6, 17, 41, the parser behavior is different with other
        # protocols, skip them for simplicity
        skip_protos = [2, 4, 6, 17, 41, 253, 254]
        if self.ipver == 'ipv6':
            # Skip ip_proto 0 for IPv6
            skip_protos.append(0)
        return sorted(set(range(255)) - set(skip_protos))

    def get_ip_proto(self):
        return random.choice(self.get_ip_protocol_domain())

    def randomize_mac(self, base_mac):
        return base_mac[:-5] + '{0:02x}:{1:02x}'.format(random.randint(0, 255), random.randint(0, 255))

    def generate_pkt(self, src_ip, dst_ip, src_port, dst_port, ip_proto, inner_src_ip, inner_dst_ip):

        def _get_pkt_ip_protocol(pkt):
            if 'IPv6' in pkt.summary():
                return pkt['IPv6'].nh
            elif pkt.getlayer('IP'):
                return pkt['IP'].proto
            else:
                return None

        def _get_src_mac():
            src_base_mac = self.dataplane.get_mac(0, self.sending_ports[0])
            if self.hash_field == 'SRC_MAC':
                src_mac = self.randomize_mac(src_base_mac)
            else:
                src_mac = src_base_mac
            return src_mac

        def _get_dst_mac():
            dst_base_mac = '11:22:33:44:55:66'
            if self.is_l2_test:
                if self.hash_field == 'DST_MAC':
                    dst_mac = self.randomize_mac(dst_base_mac)
                else:
                    dst_mac = '11:22:33:44:55:66'
            else:
                dst_mac = self.router_mac
            return dst_mac

        def _get_vlan_id():
            if self.hash_field == 'VLAN_ID':
                vlan_id = random.choice(range(self.vlan_range[0], self.vlan_range[1]))
            else:
                vlan_id = 0
            return vlan_id

        def _get_flow_label():
            if self.hash_field == 'IPV6_FLOW_LABEL':
                flow_label = random.choice(range(self.flow_lable_range[0], self.flow_lable_range[1]))
            else:
                flow_label = 0
            return flow_label

        def _get_single_layer_packet():
            # Generate a tcp packet to cover the outer IP header fields
            if self.ipver == 'ipv4':  # IP version is ipv4
                pkt = testutils.simple_tcp_packet(
                    pktlen=100 if vlan_id == 0 else 104,
                    eth_dst=dst_mac,
                    eth_src=src_mac,
                    dl_vlan_enable=False if vlan_id == 0 else True,
                    vlan_vid=vlan_id,
                    vlan_pcp=0,
                    ip_src=src_ip,
                    ip_dst=dst_ip,
                    tcp_sport=src_port,
                    tcp_dport=dst_port,
                    ip_ttl=64)
                if self.hash_field == 'IP_PROTOCOL':
                    pkt['IP'].proto = ip_proto
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "chksum")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "ttl")
                masked_expected_pkt.set_do_not_care_packet(scapy.TCP, "chksum")
            else:  # IP version is ipv6
                pkt = testutils.simple_tcpv6_packet(
                    pktlen=100 if vlan_id == 0 else 104,
                    eth_dst=dst_mac,
                    eth_src=src_mac,
                    dl_vlan_enable=False if vlan_id == 0 else True,
                    vlan_vid=vlan_id,
                    vlan_pcp=0,
                    ipv6_dst=dst_ip,
                    ipv6_src=src_ip,
                    tcp_sport=src_port,
                    tcp_dport=dst_port,
                    ipv6_fl=flow_label,
                    ipv6_hlim=64)
                if self.hash_field == 'IP_PROTOCOL':
                    pkt['IPv6'].nh = ip_proto
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")
                masked_expected_pkt.set_do_not_care_packet(scapy.TCP, "chksum")
            if self.hash_field == 'ETHERTYPE':
                pkt['Ether'].type = random.choice(range(self.ethertype_range[0], self.ethertype_range[1]))
            if not self.is_l2_test:
                pkt_summary = f"{self.ipver} packet with src_mac: {src_mac}, dst_mac: {dst_mac}, src_ip: {src_ip}, " \
                              f"dst_ip: {dst_ip}, src_port: {src_port}, dst_port: {dst_port}, " \
                              f"ip_protocol: {_get_pkt_ip_protocol(pkt)}"
            else:
                pkt_summary = f"Ethernet packet with src_mac: {src_mac}, dst_mac: {dst_mac}, " \
                              f"ether_type: {hex(pkt['Ether'].type)}, vlan_id: {vlan_id if vlan_id != 0 else 'N/A'}"
            if self.hash_field == 'IPV6_FLOW_LABEL':
                pkt_summary += f", ipv6 flow label: {flow_label} "

            return pkt, masked_expected_pkt, pkt_summary

        def _get_ipinip_packet():
            # Generate an ipinip packet
            if self.ipver == 'ipv4':  # Outer IP version is ipv4
                pkt = testutils.simple_ipv4ip_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_src=src_ip,
                    ip_dst=dst_ip,
                    ip_ttl=64,
                    inner_frame=inner_pkt['IP'] if self.inner_ipver == 'ipv4' else inner_pkt['IPv6'])
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "chksum")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "ttl")
            else:  # Outer IP version is ipv6
                pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src=src_ip,
                    ipv6_dst=dst_ip,
                    ipv6_hlim=64,
                    inner_frame=inner_pkt['IP'] if self.inner_ipver == 'ipv4' else inner_pkt['IPv6'])
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")
            pkt_summary = f"{self.ipver} ipinip packet with src_ip: {src_ip}, dst_ip: {dst_ip}, " \
                f"ip_protocol: {_get_pkt_ip_protocol(pkt)}, inner_ipver: {self.inner_ipver}, " \
                f"inner_src_ip: {inner_src_ip}, inner_dst_ip: {inner_dst_ip}, inner_src_port: {src_port}, " \
                f" inner_dst_port: {dst_port}, inner_ip_protocol: {_get_pkt_ip_protocol(inner_pkt)}"
            return pkt, masked_expected_pkt, pkt_summary

        def _get_vxlan_packet():
            # Generate an vxlan packet to cover the inner IP header fields
            if self.ipver == 'ipv4':  # Outer IP version is ipv4
                pkt = testutils.simple_vxlan_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src=src_ip,
                    ip_dst=dst_ip,
                    ip_ttl=64,
                    udp_sport=self.L4_SRC_PORT,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=self.vxlan_vni,
                    with_udp_chksum=False,
                    inner_frame=inner_pkt)
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "chksum")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "ttl")
            else:  # Outer IP version is ipv6
                pkt = testutils.simple_vxlanv6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src=src_ip,
                    ipv6_dst=dst_ip,
                    ipv6_hlim=64,
                    udp_sport=self.L4_SRC_PORT,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=self.vxlan_vni,
                    with_udp_chksum=False,
                    inner_frame=inner_pkt)
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")
            pkt_summary = f"{self.ipver} vxlan packet with src_ip: {src_ip}, dst_ip: {dst_ip}, " \
                f"src_port: {self.L4_SRC_PORT}, dst_port: {self.vxlan_port}, " \
                f"ip_protocol: {_get_pkt_ip_protocol(pkt)}, " \
                f"inner_ipver: {self.inner_ipver}, inner_src_ip: {inner_src_ip}, inner_dst_ip: {inner_dst_ip}, " \
                f"inner_src_port: {src_port}, inner_dst_port: {dst_port}, " \
                f"inner_ip_protocol: {_get_pkt_ip_protocol(inner_pkt)}"
            return pkt, masked_expected_pkt, pkt_summary

        def _get_nvgre_packet():
            # Generate an nvgre packet to cover the inner IP header fields
            if self.ipver == 'ipv4':  # Outer IP version is ipv4
                pkt = testutils.simple_nvgre_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src=src_ip,
                    ip_dst=dst_ip,
                    ip_ttl=64,
                    nvgre_tni=self.nvgre_tni,
                    nvgre_flowid=0,
                    inner_frame=inner_pkt)
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "chksum")
                masked_expected_pkt.set_do_not_care_packet(scapy.IP, "ttl")
            else:  # Outer IP version is ipv6
                pkt = GenericHashTest.simple_nvgrev6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src=src_ip,
                    ipv6_dst=dst_ip,
                    ipv6_hlim=64,
                    nvgre_tni=self.nvgre_tni,
                    nvgre_flowid=0,
                    inner_frame=inner_pkt)
                masked_expected_pkt = Mask(pkt)
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
                masked_expected_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")
            pkt_summary = f"{self.ipver} nvgre packet with src_ip: {src_ip}, dst_ip: {dst_ip}, " \
                f"ip_protocol: {_get_pkt_ip_protocol(pkt)}, inner_ipver: {self.inner_ipver}, " \
                f"inner_src_ip: {inner_src_ip}, inner_dst_ip: {inner_dst_ip}, inner_src_port: {src_port}, " \
                f"inner_dst_port: {dst_port}, inner_ip_protocol: {_get_pkt_ip_protocol(inner_pkt)}"
            return pkt, masked_expected_pkt, pkt_summary

        src_mac = _get_src_mac()
        dst_mac = _get_dst_mac()
        vlan_id = _get_vlan_id()
        flow_label = _get_flow_label()

        if 'INNER' not in self.hash_field:
            packet, masked_expected_packet, packet_summary = _get_single_layer_packet()
        else:
            # For the inner fields, need an encapsulated packet
            inner_pkt = self.generate_inner_pkt(inner_src_ip, inner_dst_ip, src_port, dst_port, ip_proto)
            if self.encap_type == 'ipinip':
                packet, masked_expected_packet, packet_summary = _get_ipinip_packet()
            elif self.encap_type == 'vxlan':
                packet, masked_expected_packet, packet_summary = _get_vxlan_packet()
            elif self.encap_type == 'nvgre':
                packet, masked_expected_packet, packet_summary = _get_nvgre_packet()
        return packet, masked_expected_packet, packet_summary

    def generate_inner_pkt(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        src_mac = '00:12:ab:34:cd:01'
        dst_mac = '01:12:ab:34:cd:00'
        if self.hash_field == 'INNER_SRC_MAC':
            src_mac = self.randomize_mac(src_mac)
        if self.hash_field == 'INNER_DST_MAC':
            dst_mac = self.randomize_mac(dst_mac)
        if self.hash_field == 'INNER_ETHERTYPE':
            eth_type = random.choice(range(self.ethertype_range[0], self.ethertype_range[1]))
            inner_pkt = testutils.simple_eth_packet(
                eth_dst=dst_mac,
                eth_src=src_mac,
                eth_type=eth_type
            )
        elif self.inner_ipver == 'ipv4':  # Inner IP version is ipv4
            inner_pkt = testutils.simple_tcp_packet(
                eth_dst=dst_mac,
                eth_src=src_mac,
                ip_dst=dst_ip,
                ip_src=src_ip,
                tcp_sport=src_port,
                tcp_dport=dst_port,
                ip_ttl=64
            )
            inner_pkt["IP"].proto = ip_proto
        else:  # Inner IP version is ipv6
            inner_pkt = testutils.simple_tcpv6_packet(
                eth_dst=dst_mac,
                eth_src=src_mac,
                ipv6_dst=dst_ip,
                ipv6_src=src_ip,
                tcp_sport=src_port,
                tcp_dport=dst_port,
                ipv6_hlim=64
            )
            inner_pkt["IPv6"].nh = ip_proto
        return inner_pkt

    def check_ip_route(self, pkt, masked_expected_pkt, sending_port):
        """
        send the packet and check it is received by one of the expected ports
        """
        testutils.send_packet(self, sending_port, pkt)
        try:
            port_index, received = testutils.verify_packet_any_port(
                self, masked_expected_pkt, self.expected_port_list, timeout=0.1)
        except AssertionError:
            logging.warning("Packet wasn't received successfully, trying again")
            logging.info(f"Expected packet: {masked_expected_pkt}")
            for _ in range(5):
                testutils.send_packet(self, sending_port, pkt, count=1)
                time.sleep(0.1)
            port_index, received = testutils.verify_packet_any_port(
                self, masked_expected_pkt, self.expected_port_list, timeout=1)
            logging.info("Packet was received successfully after retry.")
        # The port_index is the index of expected_port_list, need to convert it to the ptf port index
        return self.expected_port_list[port_index], received

    def check_within_expected_range(self, actual, expected):
        """
        Check if the actual number is within the accepted range of the expected number
        """
        percentage = (actual - expected) / float(expected)
        return percentage, abs(percentage) <= self.balancing_range

    @staticmethod
    def simple_nvgrev6_packet(
            pktlen=300,
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
            ipv6_hlim=64,
            nvgre_tni=None,
            nvgre_flowid=0,
            inner_frame=None
    ):
        """
        Helper function to construct an IPv6 NVGRE packet
        """
        if testutils.MINSIZE > pktlen:
            pktlen = testutils.MINSIZE

        nvgre_hdr = scapy.NVGRE(vsid=nvgre_tni, flowid=nvgre_flowid)

        if dl_vlan_enable:
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
            pkt = pkt / ("D" * (pktlen - len(pkt)))

        return pkt

    def check_balancing(self, hit_count_map):
        """
        Check if the traffic is balanced across the ECMP groups and the LAG members
        """

        def _calculate_balance(hit_cnt_per_port):
            result = True
            for port_index in hit_count_map.keys():
                (p, r) = self.check_within_expected_range(hit_count_map[port_index], hit_cnt_per_port)
                result &= r
            return result

        def _check_ecmp_and_lag_hash_balancing():
            logging.info('Checking there is ecmp and lag hash')
            if self.require_all_expected_ports:
                missing_ports = [port for port in self.expected_port_list if hit_count_map.get(port, 0) <= 0]
                assert not missing_ports, f"Traffic was not received on expected ports: {missing_ports}."
            expected_hit_cnt_per_port = self.balancing_test_times
            assert _calculate_balance(expected_hit_cnt_per_port), "The balancing result is beyond the range."

        def _check_only_ecmp_hash_balancing():
            logging.info('Checking there is only ecmp hash')
            if len(self.expected_port_groups[0]) > 1:
                logging.info('There are multi-member portchannels, check no hash over the members')
                for port_group in self.expected_port_groups:
                    hit_port_number = len(set(port_group).intersection(set(hit_count_map.keys())))
                    if hit_port_number > 1:
                        logging.info('Check only one port in a portchannel received traffic')
                        assert False, 'The traffic is balanced over portchannel members.'
                    if hit_port_number == 0:
                        logging.info('Check the traffic is balanced over all the portchannels')
                        assert False, 'Traffic is not balanced over all nexthops.'
            # Check the balance
            expected_hit_cnt_per_port = expected_total_hit_cnt / len(self.expected_port_groups)
            assert _calculate_balance(expected_hit_cnt_per_port), "The balancing result is beyond the range."

        def _check_only_lag_hash_balancing():
            logging.info('Checking there is only lag hash')
            hit_ports = sorted(hit_count_map.keys())
            assert hit_ports in self.expected_port_groups, "Traffic is not received by all lag members in 1 nexthop."
            # Check the traffic is balanced over the members
            expected_hit_cnt_per_port = expected_total_hit_cnt / len(self.expected_port_groups[0])
            assert _calculate_balance(expected_hit_cnt_per_port), "The balancing result is beyond the range."

        expected_total_hit_cnt = self.balancing_test_times * len(self.expected_port_list)
        # If check ecmp hash and lag hash, traffic should be balanced through all expected ports
        if self.ecmp_hash and self.lag_hash:
            _check_ecmp_and_lag_hash_balancing()
        # If check ecmp hash but not lag hash, traffic should be balanced through
        # all portchannels but not the members in a same portchannel
        elif self.ecmp_hash and not self.lag_hash:
            _check_only_ecmp_hash_balancing()
        # If check lag hash but not ecmp hash, traffic should be received
        # by only one portchannel and balanced over the members
        elif not self.ecmp_hash and self.lag_hash:
            _check_only_lag_hash_balancing()

    def print_result_summary(self, hit_count_map):
        total_receiving_ports = len(hit_count_map)
        total_received_packets = sum(hit_count_map.values())
        average_packets = total_received_packets / total_receiving_ports
        min_received_packets = min(hit_count_map.values())
        max_received_packets = max(hit_count_map.values())
        min_received_ports = [port for port, count in hit_count_map.items() if count == min_received_packets]
        max_received_ports = [port for port, count in hit_count_map.items() if count == max_received_packets]
        expected_total_hit_cnt = self.balancing_test_times * len(self.expected_port_list)
        expected_hit_cnt_per_port = self.balancing_test_times
        if self.ecmp_hash and not self.lag_hash:
            expected_hit_cnt_per_port = expected_total_hit_cnt / len(self.expected_port_groups)
        elif not self.ecmp_hash and self.lag_hash:
            expected_hit_cnt_per_port = expected_total_hit_cnt / len(self.expected_port_groups[0])
        max_deviation = max(abs(expected_hit_cnt_per_port - min_received_packets),
                            abs(expected_hit_cnt_per_port - max_received_packets))
        max_deviation_percentage = str(max_deviation / expected_hit_cnt_per_port * 100) + "%"
        logging.info(f"\nTotal number of receiving ports: {total_receiving_ports}\n"
                     f"Total packet count: {total_received_packets}\n"
                     f"Average packet count: {average_packets}\n"
                     f"Min packets on a port: {min_received_packets}(Ports: {min_received_ports})\n"
                     f"Max packets on a port: {max_received_packets}(Ports: {max_received_ports})\n"
                     f"Max deviation: {max_deviation}\n"
                     f"Max deviation percentage: {max_deviation_percentage}\n")

    def runTest(self):
        logging.info("=============Test Start==============")
        if self.protocol_domain_validation:
            self.run_protocol_domain()
            return
        hit_count_map = {}
        for _ in range(0, self.balancing_test_times * len(self.expected_port_list)):
            src_ip = self.src_ip_interval.get_random_ip() if self.hash_field == 'SRC_IP' \
                else self.src_ip_interval.get_first_ip()
            dst_ip = self.dst_ip_interval.get_random_ip() if self.hash_field == 'DST_IP' \
                else self.dst_ip_interval.get_first_ip()
            inner_src_ip = ''
            inner_dst_ip = ''
            if self.inner_ipver:
                inner_src_ip = self.inner_src_ip_interval.get_random_ip() if self.hash_field == 'INNER_SRC_IP' \
                    else self.inner_src_ip_interval.get_first_ip()
                inner_dst_ip = self.inner_dst_ip_interval.get_random_ip() if self.hash_field == 'INNER_DST_IP' \
                    else self.inner_dst_ip_interval.get_first_ip()
            src_port = random.randint(0, 65535) if self.hash_field in ['L4_SRC_PORT', 'INNER_L4_SRC_PORT'] else \
                self.L4_SRC_PORT
            dst_port = random.randint(0, 65535) if self.hash_field in ['L4_DST_PORT', 'INNER_L4_DST_PORT'] else \
                self.L4_DST_PORT
            ip_proto = self.get_ip_proto() if self.hash_field in ['IP_PROTOCOL', 'INNER_IP_PROTOCOL'] else 6

            pkt, masked_expected_pkt, pkt_summary = self.generate_pkt(
                src_ip, dst_ip, src_port, dst_port, ip_proto, inner_src_ip, inner_dst_ip)
            sending_port = self.sending_ports[0] if self.hash_field != 'IN_PORT' \
                else random.choice(self.sending_ports)
            logging.info('Sending ' + pkt_summary + ' from ptf port ' + str(sending_port))
            (matched_port, received) = self.check_ip_route(pkt, masked_expected_pkt, sending_port)

            # Check there is no packet loss
            assert received is not None, 'Packet is not received at any expected port.'

            logging.info("Received packet at index {}: {}".format(
                str(matched_port), re.sub(r"(?<=\w)(?=(?:\w\w)+$)", ' ', received.hex())))

            hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1
        logging.info(f"hash_field={self.hash_field}, hit count map: {hit_count_map}")
        self.print_result_summary(hit_count_map)
        # Check if the traffic is properly balanced
        self.check_balancing(hit_count_map)

    def run_protocol_domain(self):
        assert self.hash_field == 'IP_PROTOCOL' and self.ipver in ('ipv4', 'ipv6'), \
            "Protocol-domain validation requires plain IPv4 or IPv6 IP_PROTOCOL traffic."
        assert not self.inner_ipver and not self.is_l2_test and self.ecmp_hash and not self.lag_hash, \
            "Protocol-domain validation requires ECMP entropy without LAG-member entropy."
        protocol_domain = self.get_ip_protocol_domain()
        observations = {protocol: [] for protocol in protocol_domain}
        for repetition in range(self.PROTOCOL_DOMAIN_REPEATS):
            ordered_protocols = protocol_domain if repetition % 2 == 0 else reversed(protocol_domain)
            for protocol in ordered_protocols:
                pkt, expected, summary = self.generate_pkt(
                    self.src_ip_interval.get_first_ip(), self.dst_ip_interval.get_first_ip(),
                    self.L4_SRC_PORT, self.L4_DST_PORT, protocol, '', '')
                logging.info("Protocol-domain round=%s: %s", repetition, summary)
                # No retransmission: a missing packet must fail the contract.
                testutils.send_packet(self, self.sending_ports[0], pkt)
                port_index, received = testutils.verify_packet_any_port(
                    self, expected, self.expected_port_list, timeout=1)
                assert received is not None, f"Protocol {protocol} packet was not received."
                # --relax disables the implicit check; reject matching copies on any port.
                extra = testutils.dp_poll(
                    self, device_number=0, timeout=self.PROTOCOL_DUPLICATE_TIMEOUT, exp_pkt=expected)
                assert isinstance(extra, self.dataplane.PollFailure), \
                    f"Protocol {protocol} was duplicated: {extra.format()}"
                port = self.expected_port_list[port_index]
                observations[protocol].append(port)
                assert port == observations[protocol][0], f"Protocol {protocol} changed receiving port."
        logging.info("Protocol-domain observations: %s", observations)
        validate_protocol_distribution(
            observations, protocol_domain, self.expected_port_groups, self.PROTOCOL_DOMAIN_REPEATS)
        logging.info("Protocol-domain packets: sent=%s, received=%s, retries=0, duplicates=0, "
                     "duplicate_check_seconds=%s",
                     len(protocol_domain) * self.PROTOCOL_DOMAIN_REPEATS,
                     sum(len(ports) for ports in observations.values()), self.PROTOCOL_DUPLICATE_TIMEOUT)
