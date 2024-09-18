import ptf
import logging
import random
from ptf.base_tests import BaseTest
import time
from ptf.testutils import test_params_get, simple_udp_packet, send_packet


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
            for queue in self.queues:
                print(f"traffic from {src_port} to {dst_port}: {queue} ")
                logging.info(f"traffic from {src_port} to {dst_port}: {queue} ")
                pkt = simple_udp_packet(
                    eth_src=src_mac,
                    eth_dst=self.router_mac,
                    ip_src=self.src_ips[i],
                    ip_dst=self.dst_ips[i],
                    ip_dscp=queue,
                    ip_ecn=0,
                    ip_ttl=ttl
                )
                pkts_dict[src_port].append(pkt)
                if self.bidirection:
                    print(f"traffic from {dst_port} to {src_port}: {queue} ")
                    logging.info(f"traffic from {dst_port} to {src_port}: {queue} ")
                    pkt = simple_udp_packet(
                        eth_src=dst_mac,
                        eth_dst=self.router_mac,
                        ip_src=self.dst_ips[i],
                        ip_dst=self.src_ips[i],
                        ip_dscp=queue,
                        ip_ecn=0,
                        ip_ttl=ttl
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
                        send_packet(self, port, pkt, pkt_count_in_batch)
                        sent_count += pkt_count_in_batch

            now = time.time()
            if now - start > timeout:
                break
