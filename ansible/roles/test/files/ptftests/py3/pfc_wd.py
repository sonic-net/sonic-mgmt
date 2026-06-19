import ipaddress
import random
import socket
import struct
import re
import six
import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import (
    test_params_get,
    simple_tcp_packet,
    simple_tcpv6_packet,
    send_packet,
    verify_no_packet_any,
    verify_packet_any_port
)
import macsec  # noqa F401


class PfcWdTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.vlan_mac = self.test_params.get('vlan_mac', self.router_mac)
        self.queue_index = int(self.test_params['queue_index'])
        self.pkt_count = int(self.test_params['pkt_count'])
        self.port_src = int(self.test_params['port_src'])
        self.port_dst = self.test_params['port_dst']
        self.ip_dst = self.test_params['ip_dst']
        self.port_type = self.test_params['port_type']
        self.wd_action = self.test_params.get('wd_action', 'drop')
        self.port_src_vlan_id = self.test_params.get('port_src_vlan_id')
        self.port_dst_vlan_id = self.test_params.get('port_dst_vlan_id')
        self.ip_version = self.test_params.get('ip_version')

    def runTest(self):
        ecn = 1
        dscp = self.queue_index
        tos = dscp << 2
        tos |= ecn

        matches = re.findall(r'\[([\d\s]+)\]', self.port_dst)

        dst_port_list = []
        for match in matches:
            for port in match.split():
                dst_port_list.append(int(port))
        src_mac = self.dataplane.get_mac(
            *random.choice(list(self.dataplane.ports.keys())))

        if self.port_type == "portchannel":
            for x in range(0, self.pkt_count):
                sport = random.randint(0, 65535)
                dport = random.randint(0, 65535)
                if self.ip_version == 'IPv4':
                    ip_src = socket.inet_ntoa(struct.pack(
                        '>I', random.randint(1, 0xffffffff)))
                    ip_src = ipaddress.IPv4Address(ip_src)
                    if not isinstance(self.ip_dst, six.text_type):
                        self.ip_dst = six.text_type(self.ip_dst, 'utf-8')
                    ip_dst = ipaddress.IPv4Address(self.ip_dst)
                    while ip_src == ip_dst or ip_src.is_multicast or ip_src.is_private or\
                            ip_src.is_global or ip_src.is_reserved:
                        ip_src = socket.inet_ntoa(struct.pack(
                            '>I', random.randint(1, 0xffffffff)))
                        ip_src = ipaddress.IPv4Address(ip_src)
                else:
                    if not isinstance(self.ip_dst, six.text_type):
                        self.ip_dst = six.text_type(self.ip_dst, 'utf-8')
                    ip_dst = ipaddress.IPv6Address(self.ip_dst)
                    ip_src = ip_dst
                    while ip_src == ip_dst:
                        # pick randomly from safe range inside global unicast
                        # [2003::, 3FFE:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]
                        ip_src = socket.inet_ntop(
                            socket.AF_INET6,
                            struct.pack(
                                '>QQ',
                                random.randint(0x2003000000000000, 0x3FFEFFFFFFFFFFFF),
                                random.randint(0, 0xFFFFFFFFFFFFFFFF)
                            )
                        )
                        ip_src = ipaddress.IPv6Address(ip_src)

                ip_src = str(ip_src)
                masked_exp_pkt = self.create_and_send_pkt(self.router_mac, src_mac, sport, dport, ip_src, tos, 1)
        else:
            sport = random.randint(0, 65535)
            dport = random.randint(0, 65535)
            # Cloudflare’s public DNS resolver
            ip_src = "1.1.1.1" if self.ip_version == "IPv4" else "2606:4700:4700::1111"

            masked_exp_pkt = self.create_and_send_pkt(self.vlan_mac, src_mac, sport, dport, ip_src, tos, self.pkt_count)

        if self.wd_action == 'drop':
            return verify_no_packet_any(self, masked_exp_pkt, dst_port_list)
        elif self.wd_action == 'forward':
            return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

    def create_and_send_pkt(self, eth_dst, eth_src, sport, dport, ip_src, tos, pkt_count):
        pkt_args = {
            'eth_dst': eth_dst,
            'eth_src': eth_src,
            'tcp_sport': sport,
            'tcp_dport': dport,
        }

        if self.port_src_vlan_id is not None:
            pkt_args['dl_vlan_enable'] = True
            pkt_args['vlan_vid'] = int(self.port_src_vlan_id)
            pkt_args['vlan_pcp'] = self.queue_index

        if self.ip_version == "IPv4":
            pkt_args.update({
                'ip_src': ip_src,
                'ip_dst': self.ip_dst,
                'ip_tos': tos,
                'ip_ttl': 64
            })
            pkt = simple_tcp_packet(**pkt_args)
        else:
            pkt_args.update({
                'ipv6_src': ip_src,
                'ipv6_dst': self.ip_dst,
                'ipv6_tc': tos,
                'ipv6_hlim': 64
            })
            pkt = simple_tcpv6_packet(**pkt_args)

        exp_pkt_args = {
            'tcp_sport': sport,
            'tcp_dport': dport,
        }
        if self.port_dst_vlan_id is not None:
            exp_pkt_args['dl_vlan_enable'] = True
            exp_pkt_args['vlan_vid'] = int(self.port_dst_vlan_id)
            exp_pkt_args['vlan_pcp'] = self.queue_index

        if self.ip_version == "IPv4":
            exp_pkt_args.update({
                'ip_src': ip_src,
                'ip_dst': self.ip_dst,
                'ip_tos': tos,
                'ip_ttl': 63
            })
            exp_pkt = simple_tcp_packet(**exp_pkt_args)
        else:
            exp_pkt_args.update({
                'ipv6_src': ip_src,
                'ipv6_dst': self.ip_dst,
                'ipv6_tc': tos,
                'ipv6_hlim': 63
            })
            exp_pkt = simple_tcpv6_packet(**exp_pkt_args)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        if self.ip_version == "IPv4":
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        else:
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        send_packet(self, self.port_src, pkt, pkt_count)
        return masked_exp_pkt
