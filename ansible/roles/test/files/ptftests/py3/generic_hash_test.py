"""
Description:    This file contains the generic hash test for SONiC
"""

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------
import logging
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


class GenericHashTest(BaseTest):
    # ---------------------------------------------------------------------
    # Class variables
    # ---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 625
    VXLAN_PORT = 4789
    VXLAN_VNI = 20001
    NVGRE_TNI = 20001
    L4_SRC_PORT = 1234
    L4_DST_PORT = 80

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
        """
        @summary: constructor
        """
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
        self.check_required_params()

    def check_required_params(self):
        """
        @summary: Check the required parameters
        """
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception("Missing required parameter {}".format(param))

    def setUp(self):
        """
        @summary: Setup for the test
        """

        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.ipver = self.test_params['ipver']
        self.inner_ipver = self.test_params.get('inner_ipver')
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
        self.vlan_range = self.test_params.get('vlan_range', [1032, 1060])
        self.ethertype_range = self.test_params.get('ethertype_range', [0x0800, 0x0900])
        self.is_l2_test = self.test_params.get('is_l2_test', False)
        self.encap_type = self.test_params.get('encap_type')
        self.vxlan_port = self.test_params.get('vxlan_port', self.VXLAN_PORT)
        self.vxlan_vni = self.test_params.get('vxlan_vni', self.VXLAN_VNI)
        self.nvgre_tni = self.test_params.get('nvgre_tni', self.NVGRE_TNI)
        logging.info("=============Test Setup==============")
        logging.info("balancing_range:  {}".format(self.balancing_range))
        logging.info("balancing_test_times:  {}".format(self.balancing_test_times))
        logging.info("hash_field:  {}".format(self.hash_field))
        logging.info("ipver:  {}".format(self.ipver))
        if self.inner_ipver:
            logging.info("inner_ipver:  {}".format(self.inner_ipver))
            logging.info("encap_type:  {}".format(self.encap_type))
        if self.encap_type == 'vxlan':
            logging.info("vxlan_port:  {}".format(self.vxlan_port))
        logging.info("sending_ports:  {}".format(self.sending_ports))
        logging.info("expected_port_groups:  {}".format(self.expected_port_groups))
        logging.info("ecmp_hash:  {}".format(self.ecmp_hash))
        logging.info("lag_hash:  {}".format(self.lag_hash))
        logging.info("is_l2_test:  {}".format(self.is_l2_test))

    def get_ip_proto(self):
        """
        @summary: Get the ip protocol value for test
        @return: The randomly selected ip protocol value
        """
        # ip_proto 2 is IGMP, should not be forwarded by router
        # ip_proto 253, 254 is experimental
        # Nvidia ASIC can't forward ip_proto 254, BRCM is OK, skip for all for simplicity
        # For Nvidia platforms, when the ip_proto are 4, 6, 17, 41, the parser behavior is different with other
        # protocols, skip them for simplicity
        skip_protos = [2, 4, 6, 17, 41, 253, 254]
        if self.ipver == 'ipv6':
            # Skip ip_proto 0 for IPv6
            skip_protos.append(0)
        return random.choice(list(set(range(255)) - set(skip_protos)))

    def generate_expected_pkt_mask(self, pkt, *args):
        masked_expected_pkt = Mask(pkt)
        masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "dst")
        masked_expected_pkt.set_do_not_care_packet(scapy.Ether, "src")
        masked_expected_pkt.set_do_not_care_packet(scapy.IP, "chksum")
        masked_expected_pkt.set_do_not_care_packet(scapy.IP, "ttl")
        masked_expected_pkt.set_do_not_care_packet(scapy.TCP, "chksum")
        return masked_expected_pkt

    def generate_pkt(self, src_ip, dst_ip, src_port, dst_port, ip_proto, inner_src_ip, inner_dst_ip):
        '''
        @summary: Generate the packet for test
        @param src_ip: the source ip address of the packet
        @param dst_ip: the destination ip address of the packet
        @param src_port: the source l4 port of the packet
        @param dst_port: the destination l4 port of the packet
        @param ip_proto: the ip protocol of the packet
        @return: the full packet to test
        '''

        def get_pkt_ip_protocol(pkt):
            return pkt['IPv6'].nh if 'IPv6' in pkt.summary() else pkt['IP'].proto

        src_base_mac = self.dataplane.get_mac(0, self.sending_ports[0])
        if self.hash_field == 'SRC_MAC':
            src_mac = src_base_mac[:-5] + '{0:02x}:{1:02x}'.format(random.randint(0, 255), random.randint(0, 255))
        else:
            src_mac = src_base_mac

        dst_base_mac = '11:22:33:44:55:66'
        if self.is_l2_test:
            if self.hash_field == 'DST_MAC':
                dst_mac = dst_base_mac[:-5] + '{0:02x}:{1:02x}'.format(random.randint(0, 255), random.randint(0, 255))
            else:
                dst_mac = '11:22:33:44:55:66'
        else:
            dst_mac = self.router_mac

        if self.hash_field == 'VLAN_ID':
            vlan_id = random.choice(range(self.vlan_range[0], self.vlan_range[1]))
        else:
            vlan_id = 0

        if 'INNER' not in self.hash_field:
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
                pkt_summary = "{} packet with src_mac:{}, dst_mac:{}, src_ip:{}, dst_ip:{}, " \
                              "src_port:{}, dst_port: {}, ip_protocol:{}".format(self.ipver, src_mac, dst_mac,
                                                                                 src_ip, dst_ip, src_port,
                                                                                 dst_port, get_pkt_ip_protocol(pkt))
            else:
                pkt_summary = "Ethernet packet with src_mac:{}, dst_mac:{}, ether_type:{}, vlan_id:{}". \
                    format(src_mac, dst_mac, hex(pkt['Ether'].type), vlan_id if vlan_id != 0 else 'N/A')
        else:
            # For the inner fields, need an encapsulated packet
            inner_pkt = self.generate_inner_pkt(inner_src_ip, inner_dst_ip, src_port, dst_port, ip_proto)
            if self.encap_type == 'ipinip':
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
                pkt_summary = "{} ipinip packet with src_ip:{}, dst_ip:{}, ip_protocol:{}," \
                              " inner_ipver:{}, inner_src_ip:{}, inner_dst_ip:{}, inner_src_port:{}," \
                              " inner_dst_port:{}, inner_ip_protocol:{}" \
                    .format(self.ipver, src_ip, dst_ip, get_pkt_ip_protocol(pkt), self.inner_ipver,
                            inner_src_ip, inner_dst_ip, src_port, dst_port, get_pkt_ip_protocol(inner_pkt))
            elif self.encap_type == 'vxlan':
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
                pkt_summary = "{} vxlan packet with src_ip:{}, dst_ip:{}, src_port:{}, dst_port: {}, ip_protocol:{}," \
                              " inner_ipver:{}, inner_src_ip:{}, inner_dst_ip:{}, inner_src_port:{}," \
                              " inner_dst_port:{}, inner_ip_protocol:{}" \
                    .format(self.ipver, src_ip, dst_ip, self.L4_SRC_PORT, self.vxlan_port, get_pkt_ip_protocol(pkt),
                            self.inner_ipver, inner_src_ip, inner_dst_ip, src_port, dst_port,
                            get_pkt_ip_protocol(inner_pkt))
            elif self.encap_type == 'nvgre':
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
                pkt_summary = "{} nvgre packet with src_ip:{}, dst_ip:{}, ip_protocol:{}," \
                              " inner_ipver:{}, inner_src_ip:{}, inner_dst_ip:{}, inner_src_port:{}," \
                              " inner_dst_port:{}, inner_ip_protocol:{}" \
                    .format(self.ipver, src_ip, dst_ip, get_pkt_ip_protocol(pkt), self.inner_ipver,
                            inner_src_ip, inner_dst_ip, src_port, dst_port, get_pkt_ip_protocol(inner_pkt))
        return pkt, masked_expected_pkt, pkt_summary

    def generate_inner_pkt(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        """
        @summary: Generate the inner packet for test
        @param src_ip: the source ip address of the inner packet
        @param dst_ip: the destination ip address of the inner packet
        @param src_port: the source l4 port of the inner packet
        @param dst_port: the destination l4 port of the inner packet
        @param ip_proto: the ip protocol of the inner packet
        @return: the inner packet to test
        """
        src_mac = '00:12:ab:34:cd:01'
        dst_mac = '01:12:ab:34:cd:00'
        if self.inner_ipver == 'ipv4':  # Inner IP version is ipv4
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
        @summary: send the packet and check it is received by one of the expected ports
        @param pkt: the packet to send
        @param masked_expected_pkt: the mask to validate the received packet
        @param sending_port: the ptf port for sending the packet
        @return: the ptf port index of the port received the packet, the received packet
        """
        testutils.send_packet(self, sending_port, pkt)
        port_index, received = testutils.verify_packet_any_port(
            self, masked_expected_pkt, self.expected_port_list, timeout=0.1)
        # The port_index is the index of expected_port_list, need to convert it to the ptf port index
        return self.expected_port_list[port_index], received

    def check_within_expected_range(self, actual, expected):
        """
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
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
        @summary: Helper function to construct an IPv6 NVGRE packet
        """
        if scapy.NVGRE is None:
            logging.error("A NVGRE packet was requested but NVGRE is not "
                          "supported by your Scapy. See README for more information")
            return None

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
            pkt = pkt/("D" * (pktlen - len(pkt)))

        return pkt

    def check_balancing(self, hit_count_map):
        """
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param hit_count_map : hit count map of the test
        """

        def _calculate_balance(hit_cnt_per_port):
            result = True
            for port_index in hit_count_map.keys():
                (p, r) = self.check_within_expected_range(hit_count_map[port_index], hit_cnt_per_port)
                result &= r
            return result

        def _check_ecmp_and_lag_hash_balancing():
            logging.info('Checking there is ecmp and lag hash')
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
            hit_ports = list(hit_count_map.keys())
            hit_ports.sort()
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

    def runTest(self):
        """
        @summary: body of the generic_hash_test
        """
        logging.info("=============Test Start==============")
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
            src_port = random.randint(0, 65535) if self.hash_field == 'L4_SRC_PORT' else self.L4_SRC_PORT
            dst_port = random.randint(0, 65535) if self.hash_field == 'L4_DST_PORT' else self.L4_DST_PORT
            ip_proto = self.get_ip_proto() if self.hash_field == 'IP_PROTOCOL' else 17

            pkt, masked_expected_pkt, pkt_summary = self.generate_pkt(
                src_ip, dst_ip, src_port, dst_port, ip_proto, inner_src_ip, inner_dst_ip)
            sending_port = self.sending_ports[0] if self.hash_field != 'IN_PORT' \
                else random.choice(self.sending_ports)
            logging.info('Sending ' + pkt_summary + ' from ptf port {}.'.format(sending_port))
            (matched_port, received) = self.check_ip_route(pkt, masked_expected_pkt, sending_port)

            # Check there is no packet loss
            assert received is not None, 'Packet is not received at any expected port.'

            logging.info("Received packet at index {}: {}".format(
                str(matched_port), re.sub(r"(?<=\w)(?=(?:\w\w)+$)", ' ', received.hex())))
            time.sleep(0.02)

            hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1
        logging.info("hash_field={}, hit count map: {}".format(self.hash_field, hit_count_map))
        # Check if the traffic is properly balanced
        self.check_balancing(hit_count_map)
