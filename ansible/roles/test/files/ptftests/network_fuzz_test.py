import logging
import ptf

import random
from scapy.all import fuzz, RandIP, Raw
from scapy.layers.inet import IP, UDP, TCP
from ptf.base_tests import BaseTest
from ptf.testutils import *
from pprint import pformat


class NetworkFuzzTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

    def log(self, message):
        logging.info(message)

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.dataplane.flush()

    def build_fuzz_ip_packet(self, src_ip, dest_ip):
        return fuzz(IP(src=src_ip, dst=dest_ip, version=4))

    def build_fuzz_tcp_packet(self, src_ip, dest_ip, dport=None):
        self.log("Building TCP packet for {}->{} with dport={}".format(
            src_ip, dest_ip, dport
        ))
        if dport:
            layer4 = fuzz(TCP(dport=int(dport)))
        else:
            layer4 = fuzz(TCP())
        return IP(src=src_ip, dst=dest_ip)/layer4/fuzz(Raw())

    def build_fuzz_udp_packet(self, src_ip, dest_ip, dport=None):
        self.log("Building UDP packet for {}->{} with dport={}".format(
            src_ip, dest_ip, dport
        ))
        if dport:
            layer4 = fuzz(UDP(dport=int(dport)))
        else:
            layer4 = fuzz(UDP())
        return IP(src=src_ip, dst=dest_ip)/layer4/fuzz(Raw())

    def check_param(self, param, default, required):
        if param not in self.test_params:
            if required:
                raise Exception("Test parameter '%s' is required" % param)
            self.test_params[param] = default

    def runTest(self):
        self.log('test_params:\n' + pformat(self.test_params))
        self.check_param('port_list', '', required=True)
        self.test_params['port_list'] = self.test_params['port_list'].split(',')
        self.check_param('packet_type', 'ip', required=False)
        self.check_param('packet_count', 1, required=False)
        self.check_param('src_ip', None, required=False)
        self.check_param('dest_ip', None, required=False)
        self.check_param('dest_port', None, required=False)

        if not self.test_params['src_ip']:
            self.test_params['src_ip'] = RandIP()
        if not self.test_params['dest_ip']:
            self.test_params['dest_ip'] = RandIP()

        common_params = {
           'src_ip': self.test_params['src_ip'],
           'dest_ip': self.test_params['dest_ip'],
        }
        if self.test_params['packet_type'] == 'ip':
            pkt = self.build_fuzz_ip_packet(**common_params)
        elif self.test_params['packet_type'] == 'tcp':
            pkt = self.build_fuzz_tcp_packet(dport=self.test_params['dest_port'],
                                             **common_params)
        elif self.test_params['packet_type'] == 'udp':
            pkt = self.build_fuzz_udp_packet(dport=self.test_params['dest_port'],
                                             **common_params)
        else:
            raise ValueError('Unknown packet type: ' + self.test_params['packet_type'])

        for i in range(int(self.test_params['packet_count'])):
            # Choose randomly from the port list
            port = random.choice(self.test_params['port_list'])
            self.log("Sending test packet #{} to device port {}: {}".format(i, port, pkt.summary()))
            send(self, port, pkt)
            self.dataplane.flush()
