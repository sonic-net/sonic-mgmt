import binascii
import socket
import struct
import select
import json
import argparse
import os.path
from fcntl import ioctl
from pprint import pprint


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
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
        self.socket.bind((self.iface, 0))
        self.socket.settimeout(self.RCV_TIMEOUT)

    def handler(self):
        return self.socket.fileno()

    def recv(self):
        return self.socket.recv(self.RCV_SIZE)

    def send(self, data):
        self.socket.send(data)

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
    ARP_PKT_LEN = 60
    def __init__(self, ip_sets):
        self.arp_chunk = binascii.unhexlify('08060001080006040002') # defines a part of the packet for ARP Reply
        self.arp_pad = binascii.unhexlify('00' * 18)

        self.ip_sets = ip_sets

        return

    def action(self, interface):
        data = interface.recv()
        if len(data) >= self.ARP_PKT_LEN:
            return

        remote_mac, remote_ip, request_ip = self.extract_arp_info(data)

        request_ip_str = socket.inet_ntoa(request_ip)
        if request_ip_str not in self.ip_sets[interface.name()]:
            return

        if 'vlan' in self.ip_sets[interface.name()]:
            vlan_id = self.ip_sets[interface.name()]['vlan']
        else:
            vlan_id = None

        arp_reply = self.generate_arp_reply(self.ip_sets[interface.name()][request_ip_str], remote_mac, request_ip, remote_ip, vlan_id)
        interface.send(arp_reply)

        return
        
    def extract_arp_info(self, data):
        return data[6:12], data[28:32], data[38:42] # remote_mac, remote_ip, request_ip

    def generate_arp_reply(self, local_mac, remote_mac, local_ip, remote_ip, vlan_id):
        eth_hdr = remote_mac + local_mac
        if vlan_id is not None:
            eth_type = binascii.unhexlify('8100')
            eth_hdr += eth_type + vlan_id

        return eth_hdr + self.arp_chunk + local_mac + local_ip + remote_mac + remote_ip + self.arp_pad

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
        ip_sets[str(iface)] = {}
        if args.extended:
            for ip, mac in ip_dict.items():
                ip_sets[str(iface)][str(ip)] = binascii.unhexlify(str(mac))
                counter += 1
        else:
            for ip in ip_dict:
                ip_sets[str(iface)][str(ip)] = get_mac(str(iface))
        if vlan is not None:
            ip_sets[str(iface)]['vlan'] = binascii.unhexlify(vlan_tag)

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
