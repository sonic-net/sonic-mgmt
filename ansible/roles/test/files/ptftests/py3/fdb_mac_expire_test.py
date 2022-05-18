import fdb

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.testutils import *
import datetime
import time

DISABLE_REFRESH = "disable_refresh"
REFRESH_DEST_MAC = "refresh_with_dest_mac"

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
        self.refresh_type = self.test_params.get('refresh_type', DISABLE_REFRESH)
        self.aging_time = self.test_params.get('aging_time', 0)
        self.mac_table = []
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
                # Save the MAC table for possible refresh
                self.mac_table.append((member, mac))
    
    def refreshFdbWithInvalidPackets(self):
        # Keep sending packets with Dest MAC address equals to router MAC for aging_time
        # The FDB is not supposed to be refreshed on DUT
        t1 = t0 = datetime.datetime.now()
        while (t1 - t0).seconds < self.aging_time:
            for member, mac in self.mac_table:
                pkt = simple_eth_packet(eth_dst=mac, eth_type=0x1234)
                send(self, member, pkt)
            time.sleep(5)
            t1 = datetime.datetime.now()
            
    #--------------------------------------------------------------------------
    def runTest(self):
        self.populateFdb()
        if self.refresh_type == REFRESH_DEST_MAC:
            self.refreshFdbWithInvalidPackets()
    #--------------------------------------------------------------------------
