# ptf -t "config_file='/tmp/vnet_vxlan.json';vxlan_enabled=True" --platform-dir ptftests --test-dir ptftests --platform remote vnet-vxlan

# The test checks vxlan encapsulation/decapsulation for the dataplane.
# The test runs three tests for each vlan on the DUT:
# 1. 'FromVM'   : Sends encapsulated packets to PortChannel interfaces and expects to see the decapsulated inner packets on the vlan interface.
# 2. 'FromServ' : Sends regular packets to Vlan member interface and expects to see the encapsulated packets on the corresponding PortChannel interface.
# 3. 'Serv2Serv': Sends regular packets to Vlan member interfaces and expects to see the regular packets on the one of Vlan interfaces.
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
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
import datetime
import subprocess
import ipaddress
from pprint import pprint
from ipaddress import ip_address, ip_network

class VNET(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

        self.vxlan_enabled = False
        self.routes_removed = False
        self.random_mac = '00:01:02:03:04:05'
        self.vxlan_router_mac = '00:aa:bb:cc:78:9a'
        self.vxlan_port = 13330
        self.DEFAULT_PKT_LEN = 100
        self.max_routes_wo_scaling = 1000
        self.vnet_batch = 8
        self.packets = []

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def readMacs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            if os.path.isdir('/sys/class/net/%s' % intf):
                with open('/sys/class/net/%s/address' % intf) as fp:
                    addrs[intf] = fp.read().strip()

        return addrs

    def generate_ArpResponderConfig(self):
        config = {}
        for nbr in self.nbr_info:
            if nbr[1] != 0:
                key = 'eth%d@%d' % (nbr[2],nbr[1])
            else:
                key = 'eth%d' % (nbr[2])
            if key in config:
                config[key].append(nbr[0])
            else:
                config[key] = [nbr[0]]

        with open('/tmp/vnet_arpresponder.conf', 'w') as fp:
            json.dump(config, fp)

        return

    def getSrvInfo(self, vnet, ifname=''):
        for item in self.serv_info[vnet]:
            if ifname == '' or item['ifname'] == ifname:
                return item['ip'], item['port'], item['vlan_id'], item['vni']

        return None

    def checkPeer(self, test):
        for peers in self.peering:
            for key, peer in peers.items():
                if test['name'] == key:
                    ptest = dict(test)
                    ptest['name'] = peer
                    ptest['src'], ptest['port'], ptest['vlan'], ptest['vni'] = self.getSrvInfo(ptest['name'])
                    if 'dst_vni' in test:
                        ptest['dst_vni'] = test['dst_vni']
                    self.tests.append(ptest)

    def checklocal(self, graph, test):
        for routes in graph['vnet_local_routes']:
            for name, rt_list in routes.items():
                if test['name'] == name.split('_')[0]:
                    if self.total_routes <= self.max_routes_wo_scaling: 
                        for entry in rt_list:
                            self.addLocalTest(test, entry)
                    else:
                        vnet_id = int(name.split('_')[0][4:])
                        rt_idx = ((vnet_id-1)//4)%len(rt_list)
                        entry = rt_list[rt_idx]
                        self.addLocalTest(test, entry)

    def getPeerTest(self, test):
        peer_vnets = []
        peer_tests = []
        for peers in self.peering:
            for key, peer in peers.items():
                if test['name'] == key:
                    peer_vnets.append(peer)

        for peer_test in self.tests:
            if peer_test['name'] not in peer_vnets:
                continue
            peer_tests.append(peer_test)

        return peer_tests

    def getRifTests(self, test):
        neighbor_rifs = self.serv_info[test['name']]
        rif_tests = []

        for rif in neighbor_rifs:
            if rif['vlan_id'] != test['vlan']:
                new_test = {}
                new_test['src'] = rif['ip']
                new_test['port'] = rif['port']
                new_test['vlan'] = rif['vlan_id']

                rif_tests.append(new_test)

        return rif_tests

    def addTest(self, graph, name, entry):
        test = {}
        test['name'] = name.split('_')[0]
        test['dst'] = entry['pfx'].split('/')[0]
        test['host'] = entry['end']
        if 'mac' in entry:
            test['mac'] = entry['mac']
        else:
            test['mac'] = self.vxlan_router_mac
        test['src'], test['port'], test['vlan'], test['vni'] = self.getSrvInfo(test['name'])
        if 'vni' in entry:
            test['dst_vni'] = entry['vni']
        self.tests.append(test)
        self.checkPeer(test)
        self.checklocal(graph, test)

    def addLocalTest(self, test, entry):
        nhtest = dict(test)
        nhtest['src'], nhtest['port'], nhtest['vlan'], nhtest['vni'] = self.getSrvInfo(nhtest['name'], entry['ifname'])
        prefix = ip_network(unicode(entry['pfx']))
        nhtest['src'] = str(list(prefix.hosts())[0])
        self.tests.append(nhtest)

    def calculateTotalRoutes(self, graph):
        self.total_routes = 0 
        for routes in graph['vnet_routes']:
            for name, rt_list in routes.items():
                self.total_routes += len(rt_list)
                for peers in graph['vnet_peers']:
                    for key, peer in peers.items():
                        if name.split('_')[0] == key:
                            self.total_routes += len(rt_list)
                for l_routes in graph['vnet_local_routes']:
                    for l_name, l_rt_list in l_routes.items():
                        if name == l_name:
                            self.total_routes += len(l_rt_list)

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        self.test_params = testutils.test_params_get()

        if 'config_file' not in self.test_params:
            raise Exception("required parameter 'config_file' is not present")

        if 'vxlan_enabled' in self.test_params and self.test_params['vxlan_enabled']:
            self.vxlan_enabled = True

        if 'routes_removed' in self.test_params and self.test_params['routes_removed']:
            self.routes_removed = True

        config = self.test_params['config_file']

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.pc_info = []
        self.net_ports = []
        for name, val in graph['minigraph_portchannels'].items():
            members = [graph['minigraph_port_indices'][member] for member in val['members']]
            self.net_ports.extend(members)
            ip = None

            for d in graph['minigraph_portchannel_interfaces']:
                if d['attachto'] == name:
                    ip = d['peer_addr']
                    break
            else:
                raise Exception("Portchannel '%s' ip address is not found" % name)

            self.pc_info.append((ip, members))

        self.acc_ports = []
        for name, data in graph['minigraph_vlans'].items():
            ports = [graph['minigraph_port_indices'][member] for member in data['members'][1:]]
            self.acc_ports.extend(ports)

        vni_base = 10000
        self.serv_info = {}
        self.nbr_info = []
        acc_ports_size = len(self.acc_ports)
        for idx, data in enumerate(graph['vnet_interfaces']):
            if data['vnet'] not in self.serv_info:
                self.serv_info[data['vnet']] = []
                ports = self.acc_ports[idx % acc_ports_size]
            elif self.serv_info[data['vnet']]:
                # Specify the port when there are multiple RIFs per VNET
                # We want all RIFs in one VNET to use the same port/interface
                # If we have already seen a RIF from this VNET, use the port of the previously seen RIF for consistency
                ports = self.serv_info[data['vnet']][0].get('port', ports)
            serv_info = {}
            for nbr in graph['vnet_neighbors']:
                if nbr['ifname'] == data['ifname']:
                    if 'Vlan' in data['ifname']:
                        vlan_id = int(data['ifname'].replace('Vlan', ''))
                    else:
                        vlan_id = 0
                    ip = nbr['ip']
                    self.nbr_info.append((ip, vlan_id, ports))
            serv_info['ifname'] = data['ifname']
            serv_info['vlan_id'] = vlan_id
            serv_info['ip'] = ip
            serv_info['port'] = ports
            serv_info['vni'] = vni_base + int(data['vnet'].replace('Vnet',''))
            self.serv_info[data['vnet']].extend([serv_info])

        self.peering = graph['vnet_peers']
        self.calculateTotalRoutes(graph)

        self.tests = []
        for routes in graph['vnet_routes']:
            for name, rt_list in routes.items():
                if self.total_routes <= self.max_routes_wo_scaling:
                    for entry in rt_list:
                        self.addTest(graph, name, entry)
                else:
                    vnet_id = int(name.split('_')[0][4:])
                    len_rt = len(rt_list)
                    group_8 = (vnet_id-1)//self.vnet_batch
                    rt_idx = (group_8//2)%len_rt
                    if group_8%2:
                        rt_idx = (len_rt-1)-rt_idx

                    entry = rt_list[rt_idx]
                    self.addTest(graph, name, entry)

        self.dut_mac = graph['dut_mac']

        ipv4 = None
        ipv6 = None
        for data in graph['minigraph_lo_interfaces']:
            if data['prefixlen'] == 32:
                ipv4 = data['addr']
            elif data['prefixlen'] == 128:
                ipv6 = data['addr']
        if ipv4 is None:
            raise Exception("ipv4 lo interface not found")
        if ipv6 is None:
            raise Exception("ipv6 lo interface not found")

        self.loopback_ipv4 = ipv4
        self.loopback_ipv6 = ipv6

        self.ptf_mac_addrs = self.readMacs()

        self.generate_ArpResponderConfig()

        self.cmd(["supervisorctl", "start", "arp_responder"])

        self.dataplane.flush()

        return

    def tearDown(self):
        if self.vxlan_enabled:
            self.cmd(["supervisorctl", "stop", "arp_responder"])

        json.dump(self.packets, open("/tmp/vnet_pkts.json", 'w'))

        return

    def runTest(self):
        if not self.vxlan_enabled:
            return

        print
        for test in self.tests:
            print test['name']
            self.FromServer(test)
            print "  FromServer passed"
            self.FromVM(test)
            print "  FromVM  passed"
            self.Serv2Serv(test)
            print

    def FromVM(self, test):
        rv = True
        pkt_len = self.DEFAULT_PKT_LEN
        if test['vlan'] != 0:
            tagged = True
            pkt_len += 4
        else:
            tagged = False

        for net_port in self.net_ports:
            pkt = simple_tcp_packet(
                eth_dst=self.vxlan_router_mac,
                eth_src=self.random_mac,
                ip_dst=test['src'],
                ip_src=test['dst'],
                ip_id=108,
                ip_ttl=64,
                tcp_sport=1234,
                tcp_dport=5000)
            udp_sport = 1234 # Use entropy_hash(pkt)
            udp_dport = self.vxlan_port
            if isinstance(ip_address(test['host']), ipaddress.IPv4Address):
                vxlan_pkt = simple_vxlan_packet(
                    eth_dst=self.dut_mac,
                    eth_src=self.random_mac,
                    ip_id=0,
                    ip_src=test['host'],
                    ip_dst=self.loopback_ipv4,
                    ip_ttl=64,
                    udp_sport=udp_sport,
                    udp_dport=udp_dport,
                    vxlan_vni=int(test['vni']),
                    with_udp_chksum=False,
                    inner_frame=pkt)
            elif isinstance(ip_address(test['host']), ipaddress.IPv6Address):
                vxlan_pkt = simple_vxlanv6_packet(
                    eth_dst=self.dut_mac,
                    eth_src=self.random_mac,
                    ipv6_src=test['host'],
                    ipv6_dst=self.loopback_ipv6,
                    udp_sport=udp_sport,
                    udp_dport=udp_dport,
                    vxlan_vni=int(test['vni']),
                    with_udp_chksum=False,
                    inner_frame=pkt)
            else:
                raise Exception("Found invalid IP address in test")
            exp_pkt = simple_tcp_packet(
                pktlen=pkt_len,
                eth_src=self.dut_mac,
                eth_dst=self.ptf_mac_addrs['eth%d' % test['port']],
                dl_vlan_enable=tagged,
                vlan_vid=test['vlan'],
                ip_dst=test['src'],
                ip_src=test['dst'],
                ip_id=108,
                ip_ttl=63,
                tcp_sport=1234,
                tcp_dport=5000)
            send_packet(self, net_port, str(vxlan_pkt))

            log_str = "Sending packet from port " + str(net_port) + " to " + test['src']
            logging.info(log_str)

            log_str = "Expecing packet on " + str("eth%d" % test['port']) + " from " + test['dst']
            logging.info(log_str)

            if not self.routes_removed:
                verify_packet(self, exp_pkt, test['port'])
            else:
                verify_no_packet(self, exp_pkt, test['port'])

            vxlan_pkt.load = '0' * 60 + str(len(self.packets))
            self.packets.append((net_port, str(vxlan_pkt).encode("base64")))

    def FromServer(self, test):
        rv = True
        try:
            pkt_len = self.DEFAULT_PKT_LEN
            if test['vlan'] != 0:
                tagged = True
                pkt_len += 4
            else:
                tagged = False

            vni = int(test['vni'])
            if 'dst_vni' in test:
                vni = int(test['dst_vni'])

            pkt = simple_tcp_packet(
                pktlen=pkt_len,
                eth_dst=self.dut_mac,
                eth_src=self.ptf_mac_addrs['eth%d' % test['port']],
                dl_vlan_enable=tagged,
                vlan_vid=test['vlan'],
                ip_dst=test['dst'],
                ip_src=test['src'],
                ip_id=105,
                ip_ttl=64,
                tcp_sport=1234,
                tcp_dport=5000)
            exp_pkt = simple_tcp_packet(
                eth_dst=test['mac'],
                eth_src=self.dut_mac,
                ip_dst=test['dst'],
                ip_src=test['src'],
                ip_id=105,
                ip_ttl=63,
                tcp_sport=1234,
                tcp_dport=5000)
            udp_sport = 1234 # Use entropy_hash(pkt)
            udp_dport = self.vxlan_port
            if isinstance(ip_address(test['host']), ipaddress.IPv4Address):
                encap_pkt = simple_vxlan_packet(
                    eth_src=self.dut_mac,
                    eth_dst=self.random_mac,
                    ip_id=0,
                    ip_src=self.loopback_ipv4,
                    ip_dst=test['host'],
                    ip_ttl=128,
                    udp_sport=udp_sport,
                    udp_dport=udp_dport,
                    with_udp_chksum=False,
                    vxlan_vni=vni,
                    inner_frame=exp_pkt)
                encap_pkt[IP].flags = 0x2
            elif isinstance(ip_address(test['host']), ipaddress.IPv6Address):
                encap_pkt = simple_vxlanv6_packet(
                    eth_src=self.dut_mac,
                    eth_dst=self.random_mac,
                    ipv6_src=self.loopback_ipv6,
                    ipv6_dst=test['host'],
                    udp_sport=udp_sport,
                    udp_dport=udp_dport,
                    with_udp_chksum=False,
                    vxlan_vni=vni,
                    inner_frame=exp_pkt)
            else:
                raise Exception("Found invalid IP address in test")
            send_packet(self, test['port'], str(pkt))

            masked_exp_pkt = Mask(encap_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            if isinstance(ip_address(test['host']), ipaddress.IPv4Address):
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            else:
                masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "sport")

            log_str = "Sending packet from port " + str('eth%d' % test['port']) + " to " + test['dst']
            logging.info(log_str)

            if not self.routes_removed:
                verify_packet_any_port(self, masked_exp_pkt, self.net_ports)
            else:
                verify_no_packet_any(self, masked_exp_pkt, self.net_ports)

            pkt.load = '0' * 60 + str(len(self.packets))
            self.packets.append((test['port'], str(pkt).encode("base64")))

        finally:
            print


    def Serv2Serv(self, test):
        try:
            pkt_len = self.DEFAULT_PKT_LEN
            if test['vlan'] != 0:
                tagged = True
                pkt_len += 4
            else:
                tagged = False

            peer_tests = self.getPeerTest(test)
            rif_tests = self.getRifTests(test)
            serv_tests = rif_tests + peer_tests

            for serv in serv_tests:
                print "  Testing Serv2Serv "
                pkt = simple_tcp_packet(
                    pktlen=pkt_len,
                    eth_dst=self.dut_mac,
                    eth_src=self.ptf_mac_addrs['eth%d' % test['port']],
                    dl_vlan_enable=tagged,
                    vlan_vid=test['vlan'],
                    ip_dst=serv['src'],
                    ip_src=test['src'],
                    ip_id=205,
                    ip_ttl=2,
                    tcp_sport=1234,
                    tcp_dport=5000)

                exp_pkt = simple_tcp_packet(
                    pktlen=pkt_len,
                    eth_src=self.dut_mac,
                    eth_dst=self.ptf_mac_addrs['eth%d' % serv['port']],
                    dl_vlan_enable=tagged,
                    vlan_vid=serv['vlan'],
                    ip_dst=serv['src'],
                    ip_src=test['src'],
                    ip_id=205,
                    ip_ttl=1,
                    tcp_sport=1234,
                    tcp_dport=5000)

                send_packet(self, test['port'], str(pkt))

                log_str = "Sending packet from port " + str('eth%d' % test['port']) + " to " + serv['src']
                logging.info(log_str)

                log_str = "Expecting packet on " + str("eth%d" % serv['port']) + " from " + test['src']
                logging.info(log_str)

                if not self.routes_removed:
                    verify_packet(self, exp_pkt, serv['port'])
                else:
                    verify_no_packet(self, exp_pkt, serv['port'])

                pkt.load = '0' * 60 + str(len(self.packets))
                self.packets.append((test['port'], str(pkt).encode("base64")))

        finally:
            print
