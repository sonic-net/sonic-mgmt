import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask
from ptf.base_tests import BaseTest


class ECNMarkingTest(BaseTest):
    """Verify an ingress ACL SET_ECN action marks routed traffic with ECN=CE (3).

    Topology/family-agnostic: all ports, IPs, MAC and IP version are supplied
    as params by the sonic-mgmt test, so the same PTF test runs on IPv4 or IPv6
    topologies (Mellanox, Broadcom, etc.). A packet is injected with ECN=00 on
    the ingress port (which carries the ECN ACL); the DUT routes it to the
    egress port; the egress copy must have ECN bits = 3 (CE).
    """

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        p = testutils.test_params_get()
        self.ip_version = p['ip_version']
        self.src_port = int(p['src_port'])
        self.dst_port = int(p['dst_port'])
        self.router_mac = p['router_mac']
        self.src_ip = p['src_ip']
        self.dst_ip = p['dst_ip']
        self.udp_sport = int(p.get('udp_sport', 5000))
        self.udp_dport = int(p.get('udp_dport', 6000))

    def runTest(self):
        if self.ip_version == 'ipv6':
            pkt = testutils.simple_udpv6_packet(
                eth_dst=self.router_mac, eth_src='00:11:22:33:44:55',
                ipv6_src=self.src_ip, ipv6_dst=self.dst_ip,
                ipv6_hlim=64, ipv6_tc=0,
                udp_sport=self.udp_sport, udp_dport=self.udp_dport)
            exp = testutils.simple_udpv6_packet(
                ipv6_src=self.src_ip, ipv6_dst=self.dst_ip,
                ipv6_hlim=63, ipv6_tc=3,
                udp_sport=self.udp_sport, udp_dport=self.udp_dport)
            m = Mask(exp)
            m.set_do_not_care_scapy(scapy.Ether, 'dst')
            m.set_do_not_care_scapy(scapy.Ether, 'src')
            m.set_do_not_care_scapy(scapy.IPv6, 'hlim')
            m.set_do_not_care_scapy(scapy.IPv6, 'fl')
        else:
            pkt = testutils.simple_udp_packet(
                eth_dst=self.router_mac, eth_src='00:11:22:33:44:55',
                ip_src=self.src_ip, ip_dst=self.dst_ip,
                ip_ttl=64, ip_tos=0,
                udp_sport=self.udp_sport, udp_dport=self.udp_dport)
            exp = testutils.simple_udp_packet(
                ip_src=self.src_ip, ip_dst=self.dst_ip,
                ip_ttl=63, ip_tos=3,
                udp_sport=self.udp_sport, udp_dport=self.udp_dport)
            m = Mask(exp)
            m.set_do_not_care_scapy(scapy.Ether, 'dst')
            m.set_do_not_care_scapy(scapy.Ether, 'src')
            m.set_do_not_care_scapy(scapy.IP, 'ttl')
            m.set_do_not_care_scapy(scapy.IP, 'chksum')
            m.set_do_not_care_scapy(scapy.IP, 'id')

        testutils.send_packet(self, self.src_port, pkt)
        testutils.verify_packet(self, m, self.dst_port)

    def tearDown(self):
        BaseTest.tearDown(self)
