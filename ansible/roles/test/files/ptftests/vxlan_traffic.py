# ptf --test-dir ptftests vxlan_traffic.VXLAN --platform-dir ptftests --qlen=1000 --platform remote \
#    -t 't2_ports=[16, 17, 0, 1, 4, 5, 21, 20];dut_mac=u"64:3a:ea:c1:73:f8";expect_encap_success=True; \
#        vxlan_port=4789;topo_file="/tmp/vxlan_topo_file.json";config_file="/tmp/vxlan-config-TC1-v6_in_v4.json";t0_ports=[u"Ethernet42"]' --relax --debug info \
#        --log-file /tmp/vxlan-tests.TC1.v6_in_v4.log

# The test checks vxlan encapsulation:
# The test runs three tests for each vlan on the DUT:
# 'test_encap' : Sends regular packets to T0-facing interface and expects to see the encapsulated packets on the T2-facing interfaces.
#
# The test has the following parameters:
# 1. 'config_file' is a filename of a file which contains all necessary information to run the test. The file is populated by ansible. This parameter is mandatory.

import sys
import os.path
import json
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf import config
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
import datetime
import subprocess
import ipaddress
from pprint import pprint
from ipaddress import ip_address
import random
VARS = {}
VARS['tcp_sport'] = 1234
VARS['tcp_dport'] = 5000

# Some constants used in this code
TEST_ECN = False

def get_incremental_value(key):

    global VARS
    VARS[key] = VARS[key] + 1
    return VARS[key]

def read_ptf_macs():
    addrs = {}
    for intf in os.listdir('/sys/class/net'):
        if os.path.isdir('/sys/class/net/%s' % intf):
            with open('/sys/class/net/%s/address' % intf) as fp:
                addrs[intf] = fp.read().strip()

    return addrs

class VXLAN(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.DEFAULT_PKT_LEN = 100

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.dut_mac = self.test_params['dut_mac']
        self.vxlan_port = self.test_params['vxlan_port']
        self.expect_encap_success = self.test_params['expect_encap_success']

        self.random_mac = "00:aa:bb:cc:dd:ee"
        self.ptf_mac_addrs = read_ptf_macs()
        with open(self.test_params['config_file']) as fp:
            self.config_data = json.load(fp)
        with open(self.test_params['topo_file']) as fp:
            self.topo_data = json.load(fp)

        self.fill_loopback_ip()
        self.t2_ports = self.test_params['t2_ports']
        self.nbr_info = self.config_data['neighbors']
        self.packets = []
        self.dataplane.flush()
        self.vxlan_enabled = True
        return

    def tearDown(self):
        if self.vxlan_enabled:
            json.dump(self.packets, open("/tmp/vnet_pkts.json", 'w'))
        return

    def fill_loopback_ip(self):
        loop_config_data = self.topo_data['minigraph_facts']['minigraph_lo_interfaces']
        for entry in loop_config_data:
            if isinstance(ipaddress.ip_address(entry['addr']), ipaddress.IPv4Address):
                self.loopback_ipv4 = entry['addr']
            if isinstance(ipaddress.ip_address(entry['addr']), ipaddress.IPv6Address):
                self.loopback_ipv6 = entry['addr']

    def runTest(self):
        for t0_intf in self.test_params['t0_ports']:
            # find the list of neigh addresses for the t0_ports. For each neigh address(Addr1):
            # for each destination address(Addr2) in the same Vnet as t0_intf,
            # send traffic from Add1 to it. If there
            # are multiple nexthops for the Addr2, then send that many different 
            # streams(different tcp ports).
            neighbors = [self.config_data['neighbors'][t0_intf]]
            ptf_port = self.get_ptf_port(t0_intf)
            vnet = self.config_data['vnet_intf_map'][t0_intf]
            vni  = self.config_data['vnet_vni_map'][vnet]
            for addr in neighbors:
                for destination,nh in self.config_data['dest_to_nh_map'][vnet].iteritems():
                    self.test_encap(ptf_port, vni, addr, destination, nh, test_ecn=TEST_ECN)

    def get_ptf_port(self, dut_port):
        m = re.search('Ethernet([0-9]+)', dut_port)
        if m:
            return self.topo_data['tbinfo']['topo']['ptf_dut_intf_map'][m.group(1)]['0']
        else:
            raise RuntimeError("dut_intf:{} doesn't match 'EthernetNNN'".format(dut_port))

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def read_ptf_macs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            if os.path.isdir('/sys/class/net/%s' % intf):
                with open('/sys/class/net/%s/address' % intf) as fp:
                    addrs[intf] = fp.read().strip()

        return addrs

    def test_encap(self, ptf_port, vni, ptf_addr, destination, nhs, test_ecn=False, vlan=0):
        rv = True
        try:
            pkt_len = self.DEFAULT_PKT_LEN
            if 'vlan' != 0:
                tagged = True
                pkt_len += 4
            else:
                tagged = False

            
            options =  {'ip_tos' : 0}
            options_v6 = {'ipv6_tc' : 0}
            if test_ecn:
                options = {'ip_tos' : random.randint(0, 3)}
                options_v6 = {'ipv6_tos' : random.randint(0, 3)}

            # ECMP support, assume it is a string of comma seperated list of addresses.
            returned_ip_addresses = {}
            check_ecmp = False
            for host_address in nhs:
                check_ecmp = True
                # This will ensure that every nh is used atleast once.
                for i in range(4):
                    tcp_sport = get_incremental_value('tcp_sport')
                    tcp_dport = 5000
                    valid_combination = True
                    if isinstance(ip_address(destination), ipaddress.IPv4Address) and isinstance(ip_address(ptf_addr), ipaddress.IPv4Address):
                        pkt_opts = {
                            "pktlen": pkt_len,
                            "eth_dst": self.dut_mac,
                            "eth_src": self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ip_dst":destination,
                            "ip_src":ptf_addr,
                            "ip_id":105,
                            "ip_ttl":64,
                            "tcp_sport":tcp_sport,
                            "tcp_dport":tcp_dport}
                        pkt_opts.update(options)
                        pkt = simple_tcp_packet(**pkt_opts)
                        pkt_opts['ip_ttl'] = 63
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcp_packet(**pkt_opts)
                    elif isinstance(ip_address(destination), ipaddress.IPv6Address) and isinstance(ip_address(ptf_addr), ipaddress.IPv6Address):
                        pkt_opts = {
                            "pktlen":pkt_len,
                            "eth_dst":self.dut_mac,
                            "eth_src":self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ipv6_dst":destination,
                            "ipv6_src":ptf_addr,
                            "ipv6_hlim":64,
                            "tcp_sport":tcp_sport,
                            "tcp_dport":tcp_dport}
                        pkt_opts.update(options_v6)
                        pkt = simple_tcpv6_packet(**pkt_opts)
                        pkt_opts['ipv6_hlim'] = 63
                        pkt_opts['eth_dst'] = self.dut_mac
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcpv6_packet(**pkt_opts)
                    else:
                        valid_combination = False
                        print("Unusable combination:src:{} and dst:{}".format(src, destination))
                    udp_sport = 1234 # Use entropy_hash(pkt), it will be ignored in the test later.
                    udp_dport = self.vxlan_port
                    if isinstance(ip_address(host_address), ipaddress.IPv4Address):
                        encap_pkt = simple_vxlan_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ip_id=0,
                            ip_src=self.loopback_ipv4,
                            ip_dst=host_address,
                            ip_ttl=128,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt)
                        encap_pkt[IP].flags = 0x2
                    elif isinstance(ip_address(host_address), ipaddress.IPv6Address):
                        encap_pkt = simple_vxlanv6_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ipv6_src=self.loopback_ipv6,
                            ipv6_dst=host_address,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt)
                    send_packet(self, ptf_port, str(pkt), count=2)

                    masked_exp_pkt = Mask(encap_pkt)
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
                    if isinstance(ip_address(host_address), ipaddress.IPv4Address):
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "dst")
                    else:
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "dst")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "sport")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "chksum")

                    logging.info("Sending packet from port " + str(ptf_port) + " to " + destination)

                    if self.expect_encap_success:
                        status, received_pkt = verify_packet_any_port(self, masked_exp_pkt, self.t2_ports)
                        scapy_pkt  = Ether(received_pkt)
                        # Store every destination that was received.
                        if isinstance(ip_address(host_address), ipaddress.IPv6Address):
                            dest_ip = scapy_pkt['IPv6'].dst
                        else:
                            dest_ip = scapy_pkt['IP'].dst
                        try:
                            returned_ip_addresses[dest_ip] = returned_ip_addresses[dest_ip] + 1
                        except KeyError:
                            returned_ip_addresses[dest_ip] = 1

                    else:
                        check_ecmp = False
                        print ("Verifying no packet")
                        verify_no_packet_any(self, masked_exp_pkt, self.t2_ports)

            # Verify ECMP:
            if check_ecmp:
                if set(nhs) - set(returned_ip_addresses.keys()) == set([]):
                    print ("Each address has been used")
                else:
                    raise RuntimeError('''ECMP might have failed for:{}, we expected every ip address in the nexthop group({} of them) 
                        to be used, but only {} are used:\nUsed addresses:{}\nUnused Addresses:{}'''.format(destination,
                        len(nhs), len(returned_ip_addresses.keys()),
                        returned_ip_addresses.keys(), set(nhs)-set(returned_ip_addresses.keys())))
            pkt.load = '0' * 60 + str(len(self.packets))
            self.packets.append((ptf_port, str(pkt).encode("base64")))

        finally:
            print
