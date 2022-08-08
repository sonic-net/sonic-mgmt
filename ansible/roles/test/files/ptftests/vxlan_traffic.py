# ptf --test-dir ptftests vxlan_traffic.VXLAN --platform-dir ptftests --qlen=1000 --platform remote \
#    -t 't2_ports=[16, 17, 0, 1, 4, 5, 21, 20];dut_mac=u"64:3a:ea:c1:73:f8";expect_encap_success=True;packet_count=10; \
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
from ptf.testutils import (simple_tcp_packet, simple_tcpv6_packet, simple_vxlan_packet, simple_vxlanv6_packet,
                           verify_packet_any_port, verify_no_packet_any,
                           send_packet, test_params_get)
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
import datetime
import subprocess
import logging
from ipaddress import ip_address, IPv4Address, IPv6Address
import random

VARS = {}
VARS['tcp_sport'] = 1234
VARS['tcp_dport'] = 5000

logger = logging.getLogger(__name__)

# Some constants used in this code
MIN_PACKET_COUNT = 4
MINIMUM_PACKETS_FOR_ECMP_VALIDATION = 300
TEST_ECN = True

def get_incremental_value(key):
    global VARS
    # We would like to use the ports from 1234 to 65535
    VARS[key] = max(1234, (VARS[key] + 1) % 65535)
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
        self.packet_count = self.test_params['packet_count']
        # The ECMP check fails occasionally if there is not enough packets.
        # We should keep the packet count atleast MIN_PACKET_COUNT.
        if self.packet_count < MIN_PACKET_COUNT:
            logger.warning("Packet_count is below minimum, resetting to {}", MIN_PACKET_COUNT)
            self.packet_count = MIN_PACKET_COUNT

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
            if isinstance(ip_address(entry['addr']), IPv4Address):
                self.loopback_ipv4 = entry['addr']
            if isinstance(ip_address(entry['addr']), IPv6Address):
                self.loopback_ipv6 = entry['addr']

    def runTest(self):
        for t0_intf in self.test_params['t0_ports']:
            # find the list of neigh addresses for the t0_ports. For each neigh address(Addr1):
            # for each destination address(Addr2) in the same Vnet as t0_intf,
            # send traffic from Add1 to it. If there
            # are multiple nexthops for the Addr2, then send that many different
            # streams(different tcp ports).
            neighbors = [self.config_data['neighbors'][t0_intf]]
            ptf_port = self.topo_data['minigraph_facts']['minigraph_ptf_indices'][t0_intf]
            vnet = self.config_data['vnet_intf_map'][t0_intf]
            vni  = self.config_data['vnet_vni_map'][vnet]
            for addr in neighbors:
                for destination,nh in self.config_data['dest_to_nh_map'][vnet].iteritems():
                    self.test_encap(ptf_port, vni, addr, destination, nh, test_ecn=TEST_ECN)

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

    def verify_all_addresses_used_equally(self, nhs, returned_ip_addresses):
        '''
           Verify the ECMP functionality using 2 checks.
           Check 1 verifies every nexthop address has been used.
           Check 2 verifies the distribution of number of packets among the nexthops.
           Params: nhs: the nexthops that are configured.
                   returned_ip_addresses: The dict containing the nh addresses and corresponding packet counts.
        '''
        # Check #1 : All addresses have been used.
        if set(nhs) - set(returned_ip_addresses.keys()) == set([]):
            logger.info("    Each address has been used")
            logger.info("Packets sent:{} distribution:".format(self.packet_count))
            for nh_address in returned_ip_addresses.keys():
                logger.info("      {} : {}".format(nh_address, returned_ip_addresses[nh_address]))
            # Check #2 : The packets are almost equally distributed.
            # Every next-hop should have received within 1% of the packets that we sent per nexthop(which is self.packet_count).
            # This check is valid only if there are large enough number of packets(300). Any lower number will need higher tolerance(more than 2%).
            if self.packet_count > MINIMUM_PACKETS_FOR_ECMP_VALIDATION:
                tolerance = 0.01
                for nh_address in returned_ip_addresses.keys():
                    if (1.0-tolerance) * self.packet_count <= returned_ip_addresses[nh_address] <= (1.0+tolerance) * self.packet_count:
                        pass
                    else:
                        raise RuntimeError("ECMP nexthop address: {} received too less or too many of the "
                            "packets expected. Expected:{}, received on that address:{}".format(nh_address, self.packet_count, returned_ip_addresses[nh_address]))

    def test_encap(self, ptf_port, vni, ptf_addr, destination, nhs, test_ecn=False, vlan=0):
        rv = True
        try:
            pkt_len = self.DEFAULT_PKT_LEN
            if 'vlan' != 0:
                tagged = True
                pkt_len += 4
            else:
                tagged = False

            options =  {'ip_ecn' : 0}
            options_v6 = {'ipv6_ecn' : 0}
            if test_ecn:
                ecn = random.randint(0, 3)
                options = {'ip_ecn' : ecn}
                options_v6 = {'ipv6_ecn' : ecn}

            # ECMP support, assume it is a string of comma seperated list of addresses.
            returned_ip_addresses = {}
            check_ecmp = False
            for host_address in nhs:
                check_ecmp = True
                # This will ensure that every nh is used atleast once.
                for i in range(self.packet_count):
                    tcp_sport = get_incremental_value('tcp_sport')
                    valid_combination = True
                    if isinstance(ip_address(destination), IPv4Address) and isinstance(ip_address(ptf_addr), IPv4Address):
                        pkt_opts = {
                            "pktlen": pkt_len,
                            "eth_dst": self.dut_mac,
                            "eth_src": self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ip_dst":destination,
                            "ip_src":ptf_addr,
                            "ip_id":105,
                            "ip_ttl":64,
                            "tcp_sport":tcp_sport,
                            "tcp_dport":VARS['tcp_dport']}
                        pkt_opts.update(options)
                        pkt = simple_tcp_packet(**pkt_opts)
                        pkt_opts['ip_ttl'] = 63
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcp_packet(**pkt_opts)
                    elif isinstance(ip_address(destination), IPv6Address) and isinstance(ip_address(ptf_addr), IPv6Address):
                        pkt_opts = {
                            "pktlen":pkt_len,
                            "eth_dst":self.dut_mac,
                            "eth_src":self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ipv6_dst":destination,
                            "ipv6_src":ptf_addr,
                            "ipv6_hlim":64,
                            "tcp_sport":tcp_sport,
                            "tcp_dport":VARS['tcp_dport']}
                        pkt_opts.update(options_v6)
                        pkt = simple_tcpv6_packet(**pkt_opts)
                        pkt_opts['ipv6_hlim'] = 63
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcpv6_packet(**pkt_opts)
                    else:
                        valid_combination = False
                    udp_sport = 1234 # Use entropy_hash(pkt), it will be ignored in the test later.
                    udp_dport = self.vxlan_port
                    if isinstance(ip_address(host_address), IPv4Address):
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
                            inner_frame=exp_pkt,
                            **options)
                        encap_pkt[scapy.IP].flags = 0x2
                    elif isinstance(ip_address(host_address), IPv6Address):
                        encap_pkt = simple_vxlanv6_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ipv6_src=self.loopback_ipv6,
                            ipv6_dst=host_address,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt,
                            **options_v6)
                    send_packet(self, ptf_port, str(pkt))

                    masked_exp_pkt = Mask(encap_pkt)
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
                    if isinstance(ip_address(host_address), IPv4Address):
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "dst")
                    else:
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "dst")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "sport")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "chksum")

                    logger.info("Sending packet from port " + str(ptf_port) + " to " + destination)

                    if self.expect_encap_success:
                        _, received_pkt = verify_packet_any_port(self, masked_exp_pkt, self.t2_ports)
                        scapy_pkt  = scapy.Ether(received_pkt)
                        # Store every destination that was received.
                        if isinstance(ip_address(host_address), IPv6Address):
                            dest_ip = scapy_pkt['IPv6'].dst
                        else:
                            dest_ip = scapy_pkt['IP'].dst
                        try:
                            returned_ip_addresses[dest_ip] = returned_ip_addresses[dest_ip] + 1
                        except KeyError:
                            returned_ip_addresses[dest_ip] = 1

                    else:
                        check_ecmp = False
                        logger.info("Verifying no packet")
                        verify_no_packet_any(self, masked_exp_pkt, self.t2_ports)

            # Verify ECMP:
            if check_ecmp:
                self.verify_all_addresses_used_equally(nhs, returned_ip_addresses)

            pkt.load = '0' * 60 + str(len(self.packets))
            self.packets.append((ptf_port, str(pkt).encode("base64")))

        finally:
            logger.info("")
