'''
Description:    This file contains the IPinIP test for dualtor testbed

Usage:          Examples of how to start this script
                /usr/bin/ptf --test-dir ptftests ip_in_ip_tunnel_test.IpinIPTunnelTest --platform-dir ptftests --qlen=2000 --platform remote -t hash_key_list=['src-port', 'dst-port', 'src-mac', 'dst-mac', 'src-ip'];server_ip='192.168.0.2';active_tor_ip='10.1.0.33';standby_tor_mac='d4:af:f7:4d:af:18';standby_tor_ip='10.1.0.32';ptf_portchannel_indices={u'PortChannel0001': [29], u'PortChannel0003': [33], u'PortChannel0002': [31], u'PortChannel0004': [35]} --relax --debug info --log-file /tmp/ip_in_ip_tunnel_test.2021-02-10-07:14:46.log --socket-recv-size 16384

'''
#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import random
from ipaddress import ip_address
import ptf
from scapy.all import IP, Ether
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *

# packet count for verifying traffic is forwarded via IPinIP tunnel
PACKET_NUM = 10000
# packet count for verifying traffic is not forwarded from standby tor to server directly
PACKET_NUM_FOR_NEGATIVE_CHECK = 100

DIFF = 0.25 # The valid range for balance check
SRC_IP_RANGE = [unicode('8.0.0.0'), unicode('8.255.255.255')]
TIMEOUT = 1

class IpinIPTunnelTest(BaseTest):
    '''
    @summary: Overview of functionality
        This script send traffic to standby ToR, and capture traffic
         on all portchannel interfaces to check balance.
    '''
    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()
        self.logger = logging.getLogger("IPinIPTunnel")

    def setUp(self):
        self.server_ip = self.test_params['server_ip']
        self.server_port = int(self.test_params['server_port'])
        self.vlan_mac = self.test_params['vlan_mac']
        self.standby_tor_mac = self.test_params['standby_tor_mac']
        self.active_tor_ip = self.test_params['active_tor_ip']
        self.standby_tor_ip = self.test_params['standby_tor_ip']
        self.ptf_portchannel_indices = self.test_params['ptf_portchannel_indices']
        self.indice_to_portchannel = {}
        for port_channel, indices in self.ptf_portchannel_indices.items():
            for indice in indices:
                self.indice_to_portchannel[indice] = port_channel

        self.hash_key_list = self.test_params['hash_key_list']
        self.dataplane = ptf.dataplane_instance

    def runTest(self):
        """
        Entrypoint of test script.
        """
        self.send_and_verify_packets()

    def random_ip(self, begin, end):
        """
        Generate a random IP from given ip range
        """
        length = int(ip_address(end)) - int(ip_address(begin))
        return str(ip_address(begin) + random.randint(0, length))

    def generate_packet_to_server(self, hash_key):
        """
        Generate a packet to server. The value of field in packet is filled with random value according to hash_key
        """
        base_src_mac = self.dataplane.get_mac(0, 0)
        ip_src = self.random_ip(SRC_IP_RANGE[0], SRC_IP_RANGE[1]) if hash_key == 'src-ip' else SRC_IP_RANGE[0]
        ip_dst = self.server_ip
        sport = random.randint(1, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(1, 65535) if hash_key == 'dst-port' else 80
        src_mac = (base_src_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) if hash_key == 'src-mac' else base_src_mac
        dst_mac = self.standby_tor_mac
        vlan_id = random.randint(1, 4094) if hash_key == 'vlan-id' else 0
        pkt = simple_tcp_packet(pktlen=128 if vlan_id == 0 else 132,
                            eth_dst=dst_mac,
                            eth_src=src_mac,
                            dl_vlan_enable=False if vlan_id == 0 else True,
                            vlan_vid=vlan_id,
                            vlan_pcp=0,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        return pkt

    def generate_expected_packet(self, inner_pkt):
        """
        Generate ip_in_ip packet for verifying.
        """
        inner_pkt = inner_pkt.copy()
        inner_pkt.ttl = inner_pkt.ttl - 1
        pkt = scapy.Ether(dst="aa:aa:aa:aa:aa:aa", src=self.standby_tor_mac) / \
            scapy.IP(src=self.standby_tor_ip, dst=self.active_tor_ip) / inner_pkt[IP]
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, 'dst')

        exp_pkt.set_do_not_care_scapy(scapy.IP, "ihl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "frag")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "proto")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        exp_pkt.set_do_not_care_scapy(scapy.TCP, "sport")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "seq")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "ack")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "reserved")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "dataofs")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "window")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")
        exp_pkt.set_do_not_care_scapy(scapy.TCP, "urgptr")
        exp_pkt.set_ignore_extra_bytes()

        return exp_pkt

    def generate_unexpected_packet(self, inner_pkt):
        """
        Generate a packet that shouldn't be observed.
        All packet should be forward via tunnel, so no packet should be observed on server port
        """
        pkt = inner_pkt.copy()
        pkt[Ether].src = self.vlan_mac
        # TTL of packets from active tor to server is decreased by 1
        pkt[IP].ttl -= 1
        unexpected_packet = Mask(pkt)
        # Ignore dst mac
        unexpected_packet.set_do_not_care_scapy(scapy.Ether, 'dst')

        # Ignore check sum
        unexpected_packet.set_do_not_care_scapy(scapy.IP, "chksum")

        #Ignore extra bytes
        unexpected_packet.set_ignore_extra_bytes()

        return unexpected_packet

    def check_balance(self, pkt_distribution, hash_key):
        portchannel_num = len(self.ptf_portchannel_indices)
        expect_packet_num = PACKET_NUM / portchannel_num
        pkt_num_lo = expect_packet_num * (1.0 - DIFF)
        pkt_num_hi = expect_packet_num * (1.0 + DIFF)
        self.logger.info("hash key = {}".format(hash_key))
        self.logger.info("%-10s \t %10s \t %10s \t" % ("port(s)", "exp_cnt", "act_cnt"))
        balance = True
        for portchannel, count in pkt_distribution.items():
            self.logger.info("%-10s \t %10s \t %10s \t" % (portchannel, str(expect_packet_num), str(count)))
            if count < pkt_num_lo or count > pkt_num_hi:
                balance = False
        if not balance:
            print("Check balance failed for {}".format(hash_key))
        assert(balance)

    def send_and_verify_packets(self):
        """
        Send packet from ptf (T1) to standby ToR, and verify
        """
        dst_ports = self.indice_to_portchannel.keys()
        # Select the first ptf indice as src port
        src_port = dst_ports[0]
        # Step 1. verify no packet is received from standby_tor to server
        for i in range(0, PACKET_NUM_FOR_NEGATIVE_CHECK):
            inner_pkt = self.generate_packet_to_server('src-ip')
            unexpected_packet = self.generate_unexpected_packet(inner_pkt)
            send_packet(self, src_port, inner_pkt)
            verify_no_packet(test=self,
                             port_id=self.server_port,
                             pkt=unexpected_packet,
                             timeout=TIMEOUT)

        # Step 2. verify packet is received from IPinIP tunnel and check balance
        for hash_key in self.hash_key_list:
            self.logger.info("Verifying traffic balance for hash key {}".format(hash_key))
            pkt_distribution = {}
            for i in range(0, PACKET_NUM):
                inner_pkt = self.generate_packet_to_server(hash_key)
                tunnel_pkt = self.generate_expected_packet(inner_pkt)
                self.logger.info("Sending packet dst_mac = {} src_mac = {} dst_ip = {} src_ip = {} from port {}" \
                    .format(inner_pkt[Ether].dst, inner_pkt[Ether].src, inner_pkt[IP].dst, inner_pkt[IP].src, src_port))
                send_packet(self, src_port, inner_pkt)
                # Verify packet is received from IPinIP tunnel
                idx, count = verify_packet_any_port(test=self,
                                                    pkt=tunnel_pkt,
                                                    ports=dst_ports,
                                                    device_number=0,
                                                    timeout=TIMEOUT)
                pkt_distribution[self.indice_to_portchannel[dst_ports[idx]]] = pkt_distribution.get(self.indice_to_portchannel[dst_ports[idx]], 0) + 1
            self.check_balance(pkt_distribution, hash_key)


