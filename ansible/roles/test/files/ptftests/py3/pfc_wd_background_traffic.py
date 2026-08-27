import ipaddress
import ptf
import logging
import random
from ptf.base_tests import BaseTest
import time
from ptf.testutils import test_params_get, simple_udp_packet, simple_udpv6_packet, send_packet
import macsec  # noqa F401


class PfcWdBackgroundTrafficTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.pkt_count = int(self.test_params['pkt_count'])
        self.src_ports = self.test_params['src_ports']
        self.dst_ports = self.test_params['dst_ports']
        self.src_ips = self.test_params['src_ips']
        self.dst_ips = self.test_params['dst_ips']
        self.queues = self.test_params['queues'] if 'queues' in self.test_params else [3, 4]
        self.bidirection = self.test_params['bidirection'] if 'bidirection' in self.test_params else True

    @staticmethod
    def _is_ipv6(addr):
        """Return True if addr is an IPv6 address string."""
        try:
            return ipaddress.ip_address(str(addr)).version == 6
        except ValueError:
            return False

    @staticmethod
    def _rand_src_ip(base_ip):
        """Randomize the low host bits of the source IP to add L3 hashing entropy.

        Randomizing only the L4 sport/dport is not enough on platforms whose LAG
        hash does not include L4 ports (observed on Mellanox SN4600C): the second
        member of each LAG then receives no background traffic and never enters
        PFC storm state. Varying the source IP as well spreads the flow across all
        LAG members regardless of which fields the ASIC hashes on.
        """
        ip = ipaddress.ip_address(str(base_ip))
        if ip.version == 4:
            return str(ipaddress.IPv4Address((int(ip) & 0xFFFFFF00) | random.randint(1, 254)))
        return str(ipaddress.IPv6Address((int(ip) & ~0xFFFF) | random.randint(1, 0xFFFE)))

    @staticmethod
    def _build_udp_pkt(eth_src, eth_dst, ip_src, ip_dst, dscp, ttl, is_ipv6, ip_ecn=0):
        """Build a UDP packet, choosing IPv4 or IPv6 based on is_ipv6 flag."""
        if is_ipv6:
            return simple_udpv6_packet(
                eth_src=eth_src,
                eth_dst=eth_dst,
                ipv6_src=ip_src,
                ipv6_dst=ip_dst,
                ipv6_tc=dscp << 2,
                ipv6_hlim=ttl
            )
        else:
            return simple_udp_packet(
                eth_src=eth_src,
                eth_dst=eth_dst,
                ip_src=ip_src,
                ip_dst=ip_dst,
                ip_dscp=dscp,
                ip_ecn=ip_ecn,
                ip_ttl=ttl
            )

    def runTest(self):
        ttl = 64
        pkts_dict = {}
        if len(self.dst_ports) > len(self.src_ports):
            self.src_ports.append(self.src_ports[0])
            self.src_ips.append(self.src_ips[0])
        for i in range(len(self.src_ports)):
            src_port = int(self.src_ports[i])
            dst_port = int(self.dst_ports[i])
            if src_port not in pkts_dict:
                pkts_dict[src_port] = []
            if dst_port not in pkts_dict:
                pkts_dict[dst_port] = []
            src_mac = self.dataplane.get_mac(0, src_port)
            dst_mac = self.dataplane.get_mac(0, dst_port)
            is_ipv6 = self._is_ipv6(self.src_ips[i]) or self._is_ipv6(self.dst_ips[i])
            for queue in self.queues:
                print(f"traffic from {src_port} to {dst_port}: {queue} ")
                logging.info(f"traffic from {src_port} to {dst_port}: {queue} ")
                pkt = self._build_udp_pkt(
                    eth_src=src_mac, eth_dst=self.router_mac,
                    ip_src=self.src_ips[i], ip_dst=self.dst_ips[i],
                    dscp=queue, ttl=ttl, is_ipv6=is_ipv6
                )
                pkts_dict[src_port].append(pkt)
                if self.bidirection:
                    print(f"traffic from {dst_port} to {src_port}: {queue} ")
                    logging.info(f"traffic from {dst_port} to {src_port}: {queue} ")
                    pkt = self._build_udp_pkt(
                        eth_src=dst_mac, eth_dst=self.router_mac,
                        ip_src=self.dst_ips[i], ip_dst=self.src_ips[i],
                        dscp=queue, ttl=ttl, is_ipv6=is_ipv6
                    )
                    pkts_dict[dst_port].append(pkt)

        start = time.time()
        logging.info("Start to send the background traffic")
        print("Start to send the background traffic")
        timeout = 500
        pkt_count_in_batch = 100
        while True:
            for port, pkts in pkts_dict.items():
                for pkt in pkts:
                    sent_count = 0
                    """
                    Randomize the sport/dport to add entropy to the packets so that
                    the traffic can be hashed to different egress ports.
                    This is to ensure all the LAG members in the LAG take traffic.
                    """
                    while sent_count < self.pkt_count:
                        pkt['UDP'].sport = random.randint(1, 65535)
                        pkt['UDP'].dport = random.randint(1, 65535)
                        # Also vary the source IP so LAG member selection does not
                        # depend on the platform hashing L4 ports. Clear the stale
                        # checksums so scapy recomputes them for the new source IP.
                        if 'IPv6' in pkt:
                            pkt['IPv6'].src = self._rand_src_ip(pkt['IPv6'].src)
                        else:
                            pkt['IP'].src = self._rand_src_ip(pkt['IP'].src)
                            del pkt['IP'].chksum
                        del pkt['UDP'].chksum
                        send_packet(self, port, pkt, pkt_count_in_batch)
                        sent_count += pkt_count_in_batch

            now = time.time()
            if now - start > timeout:
                break
