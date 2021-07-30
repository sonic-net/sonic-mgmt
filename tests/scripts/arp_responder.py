import binascii
import socket
import struct
import select
import json
import argparse
import os.path
from collections import defaultdict
from fcntl import ioctl
from pprint import pprint
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import ptf.packet as scapy
import scapy.all as scapy2
scapy2.conf.use_pcap=True
import scapy.arch.pcapdnet

NEIGH_SOLICIT_ICMP_MSG_TYPE = 135

def hexdump(data):
    print " ".join("%02x" % ord(d) for d in data)

def get_if(iff, cmd):
    s = socket.socket()
    ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
    s.close()

    return ifreq

def get_mac(iff):
    SIOCGIFHWADDR = 0x8927          # Get hardware address
    return get_if(iff, SIOCGIFHWADDR)[18:24]


class Interface(object):
    ETH_P_ALL = 0x03
    ETH_P_ARP = 0x806
    RCV_TIMEOUT = 1000
    RCV_SIZE = 4096

    def __init__(self, iface):
        self.iface = iface
        self.socket = None
        self.mac_address = get_mac(iface)

    def __del__(self):
        if self.socket:
            self.socket.close()

    def bind(self):
        self.socket = scapy2.conf.L2listen(iface=self.iface, filter='arp || ip6[40] = {}'.format(NEIGH_SOLICIT_ICMP_MSG_TYPE))

    def handler(self):
        return self.socket

    def recv(self):
        sniffed = self.socket.recv()
        pkt = sniffed[0]
        str_pkt = str(pkt).encode("HEX")
        binpkt = binascii.unhexlify(str_pkt)
        return binpkt

    def send(self, data):
        scapy2.sendp(data, iface=self.iface)

    def mac(self):
        return self.mac_address

    def name(self):
        return self.iface


class Poller(object):
    def __init__(self, interfaces, responder):
        self.responder = responder
        self.mapping = {}
        for interface in interfaces:
            self.mapping[interface.handler()] = interface

    def poll(self):
        handlers = self.mapping.keys()
        while True:
            (rdlist, _, _) = select.select(handlers, [], [])
            for handler in rdlist:
                self.responder.action(self.mapping[handler])


class ARPResponder(object):
    ARP_PKT_LEN = 64
    NDP_PKT_LEN = 90
    ARP_OP_REQUEST = 1
    def __init__(self, ip_sets):
        self.arp_chunk = binascii.unhexlify('08060001080006040002') # defines a part of the packet for ARP Reply
        self.arp_pad = binascii.unhexlify('00' * 18)

        self.ip_sets = ip_sets

        return

    def action(self, interface):
        data = interface.recv()

        if len(data) <= self.ARP_PKT_LEN:
            return self.reply_to_arp(data, interface)
        elif len(data) <= self.NDP_PKT_LEN:
            return self.reply_to_ndp(data, interface)

    def reply_to_arp(self, data, interface):
        remote_mac, remote_ip, request_ip, op_type, vlan_id = self.extract_arp_info(data)

        # Don't send ARP response if the ARP op code is not request
        if op_type != self.ARP_OP_REQUEST:
            return

        request_ip_str = socket.inet_ntoa(request_ip)
        if request_ip_str not in self.ip_sets[interface.name()]:
            return

        if 'vlan' in self.ip_sets[interface.name()]:
            vlan_list = self.ip_sets[interface.name()]['vlan']
        else:
            vlan_list = [None]

        for vlan_id in vlan_list:
            arp_reply = self.generate_arp_reply(self.ip_sets[interface.name()][request_ip_str], remote_mac, request_ip, remote_ip, vlan_id)
            interface.send(arp_reply)

        return

    def reply_to_ndp(self, data, interface):
        remote_mac, remote_ip, target_ip = self.extract_ndp_info(data)

        target_ip_str = socket.inet_ntop(socket.AF_INET6, target_ip)
        if target_ip_str in self.ip_sets[interface.name()]:
            remote_ip_str = socket.inet_ntop(socket.AF_INET6, remote_ip)
            neigh_adv_pkt = self.generate_neigh_adv(self.ip_sets[interface.name()][target_ip_str], remote_mac, target_ip_str, remote_ip_str)
            interface.send(neigh_adv_pkt)

        return
        
    def extract_ndp_info(self, data):
        vlan_offset = 0

        if len(data) == 90:
            vlan_offset = 4

        remote_mac = data[6:12]
        remote_ip = data[22 + vlan_offset:38 + vlan_offset]
        target_ip = data[62 + vlan_offset:78 + vlan_offset]

        return remote_mac, remote_ip, target_ip

    def extract_arp_info(self, data):
        # remote_mac, remote_ip, request_ip, op_type
        rem_ip_start = 28
        req_ip_start = 38
        op_type_start = 20
        eth_offset = 0
        vlan_id = None
        ether_type = str(data[12:14]).encode("HEX")
        if (ether_type == '8100'):
            vlan = str(data[14:16]).encode("HEX")
            if (vlan != '0000'):
                eth_offset = 4
                vlan_id = data[14:16]
        rem_ip_start = rem_ip_start + eth_offset
        req_ip_start = req_ip_start + eth_offset
        op_type_start = op_type_start + eth_offset
        rem_ip_end = rem_ip_start + 4
        req_ip_end = req_ip_start + 4
        op_type_end = op_type_start + 1

        return data[6:12], data[rem_ip_start:rem_ip_end], data[req_ip_start:req_ip_end], (ord(data[op_type_start]) * 256 + ord(data[op_type_end])), vlan_id

    def generate_arp_reply(self, local_mac, remote_mac, local_ip, remote_ip, vlan_id):
        eth_hdr = remote_mac + local_mac
        if vlan_id is not None:
            eth_type = binascii.unhexlify('8100')
            eth_hdr += eth_type + vlan_id

        return eth_hdr + self.arp_chunk + local_mac + local_ip + remote_mac + remote_ip + self.arp_pad

    def generate_neigh_adv(self, local_mac, remote_mac, target_ip, remote_ip):
        neigh_adv_pkt = Ether(src=local_mac, dst=remote_mac)/IPv6(src=target_ip, dst=remote_ip)
        neigh_adv_pkt /= ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
        neigh_adv_pkt /= ICMPv6NDOptDstLLAddr(lladdr=local_mac)

        return neigh_adv_pkt

def parse_args():
    parser = argparse.ArgumentParser(description='ARP autoresponder')
    parser.add_argument('--conf', '-c', type=str, dest='conf', default='/tmp/from_t1.json', help='path to json file with configuration')
    parser.add_argument('--extended', '-e', action='store_true', dest='extended', default=False, help='enable extended mode')
    args = parser.parse_args()

    return args

def main():
    args = parse_args()

    if not os.path.exists(args.conf):
        print "Can't find file %s" % args.conf
        return

    with open(args.conf) as fp:
        data = json.load(fp)

    # generate ip_sets. every ip address will have it's own uniq mac address
    ip_sets = {}
    counter = 0
    for iface, ip_dict in data.items():
        vlan = None
        if iface.find('@') != -1:
            iface, vlan = iface.split('@')
            vlan_tag = format(int(vlan), 'x')
            vlan_tag = vlan_tag.zfill(4)
        if str(iface) not in ip_sets:
            ip_sets[str(iface)] = defaultdict(list)
        if args.extended:
            for ip, mac in ip_dict.items():
                ip_sets[str(iface)][str(ip)] = binascii.unhexlify(str(mac))
                counter += 1
        else:
            for ip in ip_dict:
                ip_sets[str(iface)][str(ip)] = get_mac(str(iface))
        if vlan is not None:
            ip_sets[str(iface)]['vlan'].append(binascii.unhexlify(vlan_tag))

    ifaces = []
    for iface_name in ip_sets.keys():
        iface = Interface(iface_name)
        iface.bind()
        ifaces.append(iface)

    resp = ARPResponder(ip_sets)

    p = Poller(ifaces, resp)
    p.poll()

    return

if __name__ == '__main__':
    main()
