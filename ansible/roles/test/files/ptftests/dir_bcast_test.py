'''
Description:    This file contains the Directed Broadcast test for SONIC

Usage:          Examples of how to use log analyzer
                ptf --test-dir ptftests dir_bcast_test.BcastTest  --platform remote  -t "testbed_type='t0';router_mac='00:01:02:03:04:05';vlan_info='/root/vlan_info.txt'" --relax --debug info --log-file /tmp/dir_bcast_test.log  --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre

'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import random
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *
from ipaddress import ip_address, ip_network

class BcastTest(BaseTest):
    '''
    @summary: Overview of functionality
    Test sends a directed broadcast packet on one of the non-VLAN RIF interface and destined to the
    broadcast IP of the VLAN RIF. It expects the packet to be broadcasted to all the member port of
    VLAN

    This class receives a text file containing the VLAN IP address/prefix and the member port list

    For the device configured with VLAN interface and member ports,
     - IP frame, Dst Mac = Router MAC, Dst IP = Directed Broadcast IP
    '''

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    DHCP_SERVER_PORT = 67
    TEST_SRC_IP = "1.1.1.1"  # Some src IP

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.setUpVlan(self.test_params['vlan_info'])
        if self.test_params['testbed_type'] == 't0':
            self.src_ports = range(1, 25) + range(28, 32)
        if self.test_params['testbed_type'] == 't0-52':
            self.src_ports = range(0, 52)
        if self.test_params['testbed_type'] == 't0-64':
            self.src_ports = range(0, 2) + range(4, 18) + range(20, 33) + range(36, 43) + range(48, 49) + range(52, 59)
        if self.test_params['testbed_type'] == 't0-116':
            self.src_ports = range(24, 32)
        if self.test_params['testbed_type'] == 't0-120':
            self.src_ports = [48, 49, 54, 55, 60, 61, 66, 67]

    #---------------------------------------------------------------------

    def setUpVlan(self, file_path):
        '''
        @summary: Populate the VLAN dictionary with IP/Prefix and member port list
        '''
        self._vlan_dict = {}
        with open(file_path, 'r') as f:
            for line in f.readlines():
                entry = line.split(' ', 1)
                prefix = ip_network(unicode(entry[0]))
                if prefix.version != 4:
                    continue
                self._vlan_dict[prefix] = [int(i) for i in entry[1].split()]

    #---------------------------------------------------------------------

    def check_all_dir_bcast(self):
        '''
        @summary: Loop through all the VLANs and send directed broadcast packets
        '''
        for vlan_pfx in self._vlan_dict:
            bcast_ip = str(ip_network(vlan_pfx).broadcast_address)
            dst_port_list = self._vlan_dict[vlan_pfx]
            self.check_ip_dir_bcast(bcast_ip, dst_port_list)
            self.check_bootp_dir_bcast(bcast_ip, dst_port_list)

    #---------------------------------------------------------------------

    def check_ip_dir_bcast(self, dst_bcast_ip, dst_port_list):
        '''
        @summary: Check directed broadcast IP forwarding and receiving on all member ports.
        '''
        ip_src = self.TEST_SRC_IP
        ip_dst = dst_bcast_ip
        src_mac = self.dataplane.get_mac(0, 0)
        bcast_mac = self.BROADCAST_MAC

        pkt = simple_ip_packet(eth_dst=self.router_mac,
                               eth_src=src_mac,
                               ip_src=ip_src,
                               ip_dst=ip_dst)

        exp_pkt = simple_ip_packet(eth_dst=bcast_mac,
                               eth_src=self.router_mac,
                               ip_src=ip_src,
                               ip_dst=ip_dst)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        src_port = random.choice([port for port in self.src_ports if port not in dst_port_list])
        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst)

        pkt_count = count_matched_packets_all_ports(self, masked_exp_pkt, dst_port_list)
        '''
        Check if broadcast packet is received on all member ports of vlan
        '''
        logging.info("Received " + str(pkt_count) + " broadcast packets, expecting " + str(len(dst_port_list)))
        assert (pkt_count == len(dst_port_list))

        return

    #---------------------------------------------------------------------

    def check_bootp_dir_bcast(self, dst_bcast_ip, dst_port_list):
        '''
        @summary: Check directed broadcast BOOTP packet forwarding and receiving on all member ports.
        '''
        ip_src = self.TEST_SRC_IP
        ip_dst = dst_bcast_ip
        src_mac = self.dataplane.get_mac(0, 0)
        bcast_mac = self.BROADCAST_MAC
        udp_port = self.DHCP_SERVER_PORT

        pkt = simple_udp_packet(eth_dst=self.router_mac,
                                eth_src=src_mac,
                                ip_src=ip_src,
                                ip_dst=ip_dst,
                                udp_sport=udp_port,
                                udp_dport=udp_port)

        exp_pkt = simple_udp_packet(eth_dst=bcast_mac,
                                    eth_src=self.router_mac,
                                    ip_src=ip_src,
                                    ip_dst=ip_dst,
                                    udp_sport=udp_port,
                                    udp_dport=udp_port)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        src_port = random.choice([port for port in self.src_ports if port not in dst_port_list])
        send_packet(self, src_port, pkt)
        logging.info("Sending BOOTP packet from port " + str(src_port) + " to " + ip_dst)

        pkt_count = count_matched_packets_all_ports(self, masked_exp_pkt, dst_port_list)
        '''
        Check if broadcast BOOTP packet is received on all member ports of vlan
        '''
        logging.info("Received " + str(pkt_count) + " broadcast BOOTP packets, expecting " + str(len(dst_port_list)))
        assert (pkt_count == len(dst_port_list))

        return

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary: Send Broadcast IP packet destined to a VLAN RIF and with unicast Dst MAC
        Expect the packet to be received on all member ports of VLAN
        """
        self.check_all_dir_bcast()
