"""
Description:
    This file contains test implementation for asymmetric PFC feature.

Topologies:
    Supports only T0 topology (asymmetric PFC is only for T0).

Notes:
    Test is executed from asym_pfc.yml ansible playbook.
"""


import ptf
from sai_base_test import *
from collections import defaultdict
from switch import *
import multiprocessing
import subprocess
import json
import logging


class PfcAsymBaseTest(ThriftInterfaceDataPlane):
    """Provides common logic for the asymmetric PFC test cases."""
    # Port
    EGRESS_DROP = 0
    INGRESS_DROP = 1
    TRANSMITTED_PKTS = 11
    STOP_PORT_MAX_RATE = 1
    RELEASE_PORT_MAX_RATE = 0
    # Packet
    PACKET_ECN = 1
    PACKET_TTL = 64
    PACKET_LEN = 72
    PACKET_NUM = 100000

    def __init__(self):
        ThriftInterfaceDataPlane.__init__(self)

    def log(self, message):
        logging.info(message)

    def shell(self, cmds):
        sp = subprocess.Popen(cmds, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sp.communicate()
        rc = sp.returncode

        return stdout, stderr, rc

    def setUpArpResponder(self, server_ports):
        d = defaultdict(list)

        for server_port in server_ports:
            d[server_port['ptf_name']].append(server_port['ptf_ip'].split('/')[0])
        with open('/tmp/arp_responder_pfc_asym.json', 'w') as file:
            json.dump(d, file)

    def setUp(self):
        ThriftInterfaceDataPlane.setUp(self)
        switch_init(self.client)      
        self.dataplane = ptf.dataplane_instance

        self.server_ports = self.test_params['server_ports']
        self.non_server_port = self.test_params['non_server_port']
        self.router_mac = self.test_params['router_mac']
        self.pfc_to_dscp = self.test_params['pfc_to_dscp']
        self.lossless_priorities = map(int, self.test_params['lossless_priorities'])
        self.lossy_priorities = map(int, self.test_params['lossy_priorities'])

        self.setUpArpResponder(self.server_ports)
        self.shell(["supervisorctl", "start", "arp_responder"])

        attr_value = sai_thrift_attribute_value_t(mac=self.router_mac)
        attr = sai_thrift_attribute_t(id=SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, value=attr_value)
        self.client.sai_thrift_set_switch_attribute(attr)

    def tearDown(self):
        ThriftInterfaceDataPlane.tearDown(self)

        self.shell(["supervisorctl", "stop", "arp_responder"])

    def send(self, packets):
        threads = []

        for pkt in packets:
            thread = multiprocessing.Process(
                target=send_packet,
                args=(self, int(pkt['port']),
                    pkt['packet'], self.PACKET_NUM)
            )
            thread.daemon = True
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


class PfcAsymOffOnTxTest(PfcAsymBaseTest):
    """Provides test for the transmitting PFC frames when asymmetric PFC is disabled/enabled.

    DUT should generate PFC frames only on lossless priorities, regardless of asymmetric off/on.
    """
    def __init__(self):
        PfcAsymBaseTest.__init__(self)

    def setUp(self):
        PfcAsymBaseTest.setUp(self)


    def tearDown(self):
        PfcAsymBaseTest.tearDown(self)

    def sendData(self, server_ports, non_server_port, router_mac, priorities):
        packets = []

        for sp in server_ports:
            for p in priorities:
                tos = (self.pfc_to_dscp[p] << 2) | self.PACKET_ECN

                pkt = simple_tcp_packet(pktlen=self.PACKET_LEN,
                                        eth_dst=router_mac,
                                        eth_src=self.dataplane.get_mac(0, int(sp['index'])),
                                        ip_src=sp['ptf_ip'].split('/')[0],
                                        ip_dst=non_server_port['ip'].split('/')[0],
                                        ip_tos=tos,
                                        ip_ttl=self.PACKET_TTL)

                packets.append({'port': int(sp['index']), 'packet': pkt})

        self.send(packets)

    def runTest(self):
        # Clear all counters for all ports
        sai_thrift_clear_all_counters(self.client)

        # Send packets for lossless priorities from all server ports (src) to non-server port (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossless_priorities)

        # 1. Verify that some packets are dropped on src ports, which means that Rx queue is full
        # 2. Verify that PFC frames are generated for lossless priorities
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("\nLossless: port_counters = {}\n queue_counters = {}\nserver port = {}".format(
                port_counters, queue_counters, sp))
            assert(port_counters[self.INGRESS_DROP] > 0)
            for p in self.lossless_priorities:
                assert(port_counters[p + 2] > 0)

        # Send packets for lossy priorities from all server ports (src) to non-server port (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossy_priorities)

        # Verify that PFC frames are not generated for lossy priorities
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("\Lossy: port_counters = {}\n queue_counters = {}\nserver_ports = {}".format(
                port_counters, queue_counters, sp))
            for p in self.lossy_priorities:
                assert(port_counters[p + 2] == 0)


class PfcAsymOffRxTest(PfcAsymBaseTest):
    """Provides test for the receiving PFC frames when asymmetric mode is disabled.

    When asymetric mode is disabled DUT should handle PFC frames only on lossless priorities.
    """
    def __init__(self):
        PfcAsymBaseTest.__init__(self)

    def setUp(self):
        PfcAsymBaseTest.setUp(self)

    def tearDown(self):
        PfcAsymBaseTest.tearDown(self)

    def sendData(self, server_ports, non_server_port, router_mac, priorities):
        packets = []

        for sp in server_ports:
            for p in priorities:
                tos = (self.pfc_to_dscp[p] << 2) | self.PACKET_ECN

                pkt = simple_tcp_packet(pktlen=self.PACKET_LEN,
                                        eth_dst=router_mac,
                                        eth_src=self.dataplane.get_mac(0, int(non_server_port['index'])),
                                        ip_src=non_server_port['ip'].split('/')[0],
                                        ip_dst=sp['ptf_ip'].split('/')[0],
                                        ip_tos=tos,
                                        ip_ttl=self.PACKET_TTL)

                packets.append({'port': int(non_server_port['index']), 'packet': pkt})

        self.send(packets)

    def runTest(self):
        # Clear all counters for all ports
        sai_thrift_clear_all_counters(self.client)

        # Send packets for lossy priorities from non-server port (src) to all server ports (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossy_priorities)

        # Verify that packets are not dropped on src port
        port_counters, queue_counters = sai_thrift_read_port_counters(
            self.client, self.non_server_port['oid'])
        assert(port_counters[self.INGRESS_DROP] == 0)

        # 1. Verify that packets are not dropped on dst ports
        # 2. Verify that packets are transmitted from dst ports
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("Lossy - EGRESS_DROP: port_counters = {}\n queue_counters = {}\nserver_port = {}".format(
                port_counters, queue_counters, sp))
            assert(port_counters[self.EGRESS_DROP] == 0)
            for p in self.lossy_priorities:
                assert(port_counters[self.TRANSMITTED_PKTS] > 0)

        # Send packets for lossless priorities from non-server port (src) to all server ports (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossless_priorities)

        # Verify that some packets are dropped on src port, which means that Rx queue is full
        port_counters, queue_counters = sai_thrift_read_port_counters(
            self.client, self.non_server_port['oid'])
        self.log("\nLossless - INGRESS_DROP: port_counters = {}\n queue_counters = {}".format(
            port_counters, queue_counters))
        assert(port_counters[self.INGRESS_DROP] > 0)

        # Verify that some packets are dropped on dst ports, which means that Tx buffer is full
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("\nLossless - EGRESS_DROP: port_counters = {}\n queue_counters = {}\nserver_port = {}".format(
                port_counters, queue_counters, sp))
            assert(port_counters[self.EGRESS_DROP] > 0)


class PfcAsymOnRxTest(PfcAsymBaseTest):
    """Provides test for the receiving PFC frames when asymmetric PFC is enabled.

    When asymetric mode is enabled DUT should handle PFC frames on all priorities.
    """
    def __init__(self):
        PfcAsymBaseTest.__init__(self)

    def setUp(self):
        PfcAsymBaseTest.setUp(self)

    def tearDown(self):
        PfcAsymBaseTest.tearDown(self)

    def sendData(self, server_ports, non_server_port, router_mac, priorities):
        packets = []

        for sp in server_ports:
            for p in priorities:
                tos = (self.pfc_to_dscp[p] << 2) | self.PACKET_ECN

                pkt = simple_tcp_packet(pktlen=self.PACKET_LEN,
                                        eth_dst=router_mac,
                                        eth_src=self.dataplane.get_mac(0, int(non_server_port['index'])),
                                        ip_src=non_server_port['ip'].split('/')[0],
                                        ip_dst=sp['ptf_ip'].split('/')[0],
                                        ip_tos=tos,
                                        ip_ttl=self.PACKET_TTL)

                packets.append({'port': int(non_server_port['index']), 'packet': pkt})

        self.send(packets)

    def runTest(self):
        # Clear all counters for all ports
        sai_thrift_clear_all_counters(self.client)

        # Send packets for lossy priorities from non-server port (src) to all server ports (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossy_priorities)

        # Verify that packets are not dropped on src port
        port_counters, queue_counters = sai_thrift_read_port_counters(
            self.client, self.non_server_port['oid'])
        self.log("Lossy - INGRESS_DROP: port_counters = {}\n queue_counters = {}".format(
            port_counters, queue_counters))
        assert(port_counters[self.INGRESS_DROP] == 0)

        # Verify that some packets are dropped on dst ports, which means that Tx buffer is full
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("Lossy - EGRESS_DROP: port_counters = {}\n queue_counters = {}\nserver_port = {}".format(
                port_counters, queue_counters, sp))
            assert(port_counters[self.EGRESS_DROP] > 0)

        # Send packets for lossless priorities from non-server port (src) to all server ports (dst)
        self.sendData(self.server_ports, self.non_server_port, self.router_mac, self.lossless_priorities)

        # Verify that some packets are dropped on src port, which means that Rx queue is full
        port_counters, queue_counters = sai_thrift_read_port_counters(
            self.client, self.non_server_port['oid'])
        self.log("Lossy - INGRESS_DROP: port_counters = {}\n queue_counters = {}".format(
            port_counters, queue_counters))
        assert(port_counters[self.INGRESS_DROP] > 0)

        # Verify that some packets are dropped on dst ports, which means that Tx buffer is full
        for sp in self.server_ports:
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, sp['oid'])
            self.log("\nLossless - EGRESS_DROP: port_counters = {}\n queue_counters = {}\nserver_port = {}".format(
                port_counters, queue_counters, sp))
            assert(port_counters[self.EGRESS_DROP] > 0)
