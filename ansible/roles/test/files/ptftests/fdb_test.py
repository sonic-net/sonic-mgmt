import fdb
import json
import logging
import subprocess

from collections import defaultdict
from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.testutils import *

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

        self.setUpFdb()
        self.setUpArpResponder()

        self.log("Start arp_responder")
        self.shell(["supervisorctl", "start", "arp_responder"])
    #--------------------------------------------------------------------------

    def tearDown(self):
        self.log("Stop arp_responder")
        self.shell(["supervisorctl", "stop", "arp_responder"])
    #--------------------------------------------------------------------------

    def setUpFdb(self):
        vlan_table = self.fdb.get_vlan_table()
        for vlan in vlan_table:
            for member in vlan_table[vlan]:
                mac = self.dataplane.get_mac(0, member)
                self.fdb.insert(mac, member)
    #--------------------------------------------------------------------------

    def setUpArpResponder(self):
        vlan_table = self.fdb.get_vlan_table()
        arp_table = self.fdb.get_arp_table()
        d = defaultdict(list)
        for vlan in vlan_table:
            network = ip_network(vlan)
            length = int(network[-1]) - int(network[0])
            index = 1
            for member in vlan_table[vlan]:
                iface = "eth%d" % member
                index = index + 1 if network[index + 1] != self.vlan_ip else index + 2
                d[iface].append(str(network[index]))
        with open('/tmp/from_t1.json', 'w') as file:
            json.dump(d, file)
    #--------------------------------------------------------------------------

    def check_route(self, src_mac, dst_mac, src_port, dst_port):
        pkt = simple_eth_packet(eth_dst=dst_mac,
                                eth_src=src_mac,
                                eth_type=0x1234)
        self.log("Send packet " + str(src_mac) + "->" + str(dst_mac) + " from " + str(src_port) + " to " + str(dst_port) + "...")
        send(self, src_port, pkt)
        verify_packet(self, pkt, dst_port)
    #--------------------------------------------------------------------------

    def runTest(self):
        vlan_table = self.fdb.get_vlan_table()
        arp_table = self.fdb.get_arp_table()
        for vlan in vlan_table:
            for src in vlan_table[vlan]:
                for dst in [i for i in vlan_table[vlan] if i != src]:
                    self.check_route(arp_table[src], arp_table[dst], src, dst)
    #--------------------------------------------------------------------------
