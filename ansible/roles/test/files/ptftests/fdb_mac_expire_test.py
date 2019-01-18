import fdb

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.testutils import *

class FdbMacExpireTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()
    #--------------------------------------------------------------------------
    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.dummy_mac_prefix = self.test_params['dummy_mac_prefix']
        self.fdb_info = self.test_params['fdb_info']
    #--------------------------------------------------------------------------
    def populateFdb(self):
        self.fdb = fdb.Fdb(self.fdb_info)
        vlan_table = self.fdb.get_vlan_table()
        for vlan in vlan_table:
            for member in vlan_table[vlan]:
                mac = self.dummy_mac_prefix + ":" + "{:02X}".format(member)
                # Send a packet to switch to populate the layer 2 table
                pkt = simple_eth_packet(eth_dst=self.router_mac,
                                        eth_src=mac,
                                        eth_type=0x1234)
                send(self, member, pkt)
    #--------------------------------------------------------------------------
    def runTest(self):
        self.populateFdb()
	return
    #--------------------------------------------------------------------------
