import time
import subprocess
import logging

from ipaddress import ip_address
import ptf
from ptf.base_tests import BaseTest
from ptf.testutils import *

import fdb

class FdbTest(BaseTest):

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()
    #--------------------------------------------------------------------------

    def log(self, message):
        logging.info(message)
    #--------------------------------------------------------------------------

    def shell(self, cmds):
        sp = subprocess.Popen(cmds, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sp.communicate()
        rc = sp.returncode

        return stdout, stderr, rc
    #--------------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.fdb = fdb.Fdb(self.test_params['fdb_info'])
        self.vlan_ip = ip_address(unicode(self.test_params['vlan_ip']))
        self.dummy_mac_prefix = self.test_params["dummy_mac_prefix"]
        self.dummy_mac_number = int(self.test_params["dummy_mac_number"])
        self.dummy_mac_table = {}

        self.setUpFdb()
    #--------------------------------------------------------------------------

    def setUpFdb(self):
        vlan_table = self.fdb.get_vlan_table()
        for vlan in vlan_table:
            for member in vlan_table[vlan]:
                mac = self.dataplane.get_mac(0, member)
                self.fdb.insert(mac, member)

                # Send a packet to switch to populate the layer 2 table with MAC of PTF interface
                pkt = simple_eth_packet(eth_dst=self.test_params['router_mac'],
                                        eth_src=mac,
                                        eth_type=0x1234)
                send(self, member, pkt)

                # Send packets to switch to populate the layer 2 table with dummy MACs for each port
                # Totally 10 dummy MACs for each port, send 1 packet for each dummy MAC
                dummy_macs = [self.dummy_mac_prefix + ":{:02x}:{:02x}".format(member, i)
                              for i in range(self.dummy_mac_number)]
                self.dummy_mac_table[member] = dummy_macs
                for dummy_mac in dummy_macs:
                    pkt = simple_eth_packet(eth_dst=self.test_params['router_mac'],
                                            eth_src=dummy_mac,
                                            eth_type=0x1234)
                    send(self, member, pkt)

        time.sleep(2)
    #--------------------------------------------------------------------------

    def test_l2_forwarding(self, src_mac, dst_mac, src_port, dst_port):
        pkt = simple_eth_packet(eth_dst=dst_mac,
                                eth_src=src_mac,
                                eth_type=0x1234)
        self.log("Send packet " + str(src_mac) + "->" + str(dst_mac) + " from " + str(src_port) + " to " + str(dst_port) + "...")
        send(self, src_port, pkt)
        verify_packet_any_port(self, pkt, [dst_port])
    #--------------------------------------------------------------------------

    def runTest(self):
        vlan_table = self.fdb.get_vlan_table()
        arp_table = self.fdb.get_arp_table()
        for vlan in vlan_table:
            for src in vlan_table[vlan]:
                for dst in [i for i in vlan_table[vlan] if i != src]:
                    self.test_l2_forwarding(arp_table[src], arp_table[dst], src, dst)

                    for dummy_mac in self.dummy_mac_table[dst]:
                        self.test_l2_forwarding(arp_table[src], dummy_mac, src, dst)
    #--------------------------------------------------------------------------


class FdbConfigReloadTest(BaseTest):

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()
    #--------------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params["router_mac"]
        self.vlan_ports = self.test_params["vlan_ports"].split()
        self.lag_ports = self.test_params["lag_ports"].split()
        self.dummy_mac_prefix = self.test_params["dummy_mac_prefix"]
        self.vlan_port_idx = 0
        self.lag_port_idx = 0
    #--------------------------------------------------------------------------

    def runTest(self):
        max_time = 300  # seconds
        i = 0
        start_time = time.time()
        while i < 0xffff - 128 and time.time() - start_time < max_time:
            # Send frame to vlan and lag port in interleaved way
            if i % 2 == 0:
                port = self.vlan_ports[self.vlan_port_idx]
                self.vlan_port_idx += 1
                if self.vlan_port_idx >= len(self.vlan_ports):
                    self.vlan_port_idx = 0
            else:
                port = self.lag_ports[self.lag_port_idx]
                self.lag_port_idx += 1
                if self.lag_port_idx >= len(self.lag_ports):
                    self.lag_port_idx = 0

            field_0 = i % 256
            field_1 = i / 256
            dummy_mac = self.dummy_mac_prefix + ":{:02x}:{:02x}".format(field_1, field_0)
            pkt = simple_eth_packet(eth_dst=self.router_mac,
                                    eth_src=dummy_mac,
                                    eth_type=0x1234)
            logging.debug("Send packet to port %s, src mac: %s" % (str(port), dummy_mac))
            send(self, port, pkt)
            i += 1

            if i % len(self.lag_ports)*2 == 0:
                time.sleep(0.1)
    #--------------------------------------------------------------------------
