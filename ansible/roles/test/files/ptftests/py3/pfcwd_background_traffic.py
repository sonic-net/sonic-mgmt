#!/usr/bin/env python

from ptf.testutils import test_params_get, verify_packet, simple_udp_packet
from ptf.base_tests import BaseTest
from scapy.all import sendp
import ptf.packet as scapy
from ptf.mask import Mask
import ptf


class BG_pkt_sender(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        params = ['dest_mac', 'dst_ip_addr', 'ptf_src_port', 'ptf_dst_port', 'pfc_queue_idx']
        for param in params:
            if self.test_params.get(param, None) is None:
                raise RuntimeError("Need all these args:{}".format(params))

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

    def runTest(self):
        required_pkt = None
        for ip_count in range(100):
            pkt_args = {
                'eth_dst': self.test_params['dest_mac'],
                'ip_src': '100.4.{}.4'.format(ip_count),
                'ip_dst': self.test_params['dst_ip_addr'],
                'ip_tos': (int(self.test_params['pfc_queue_idx']) << 2) | 1,
                'pktlen': 1024}

            pkt = simple_udp_packet(**pkt_args)
            exp_pkt = Mask(simple_udp_packet(**pkt_args))
            exp_pkt.exp_pkt[scapy.Ether].dst = pkt[scapy.Ether].src
            exp_pkt.exp_pkt[scapy.Ether].src = self.test_params['dest_mac']
            exp_pkt.exp_pkt[scapy.IP].ttl = pkt[scapy.IP].ttl - 1
            exp_pkt.set_do_not_care_scapy(scapy.Ether, 'src')
            exp_pkt.set_do_not_care_scapy(scapy.Ether, 'dst')
            exp_pkt.set_do_not_care_scapy(scapy.IP, 'ttl')
            sendp(pkt, iface="eth"+str(int(self.test_params['ptf_src_port'])), count=1, verbose=False)
            try:
                verify_packet(self, exp_pkt, int(self.test_params['ptf_dst_port']), timeout=1)
                required_pkt = pkt
                break
            except AssertionError:
                print("Pkt didn't come back, or not received on the required dst port.")
        if required_pkt is None:
            raise RuntimeError("Couldn't identify the required packet, exiting.")
        while True:
            sendp(required_pkt, iface="eth"+str(int(self.test_params['ptf_src_port'])), count=1000000, verbose=False)
