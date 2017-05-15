import binascii
import socket
import struct
import select
import json
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
        if len(data) != self.ARP_PKT_LEN:
            return

        remote_mac, remote_ip, request_ip = self.extract_arp_info(data)

        request_ip_str = socket.inet_ntoa(request_ip)
        if request_ip_str not in self.ip_sets[interface.name()]:
            return

        arp_reply = self.generate_arp_reply(interface.mac(), remote_mac, request_ip, remote_ip)
        interface.send(arp_reply)

        return
        
    def extract_arp_info(self, data):
        return data[6:12], data[28:32], data[38:42] # remote_mac, remote_ip, request_ip

    def generate_arp_reply(self, local_mac, remote_mac, local_ip, remote_ip):
        return remote_mac + local_mac + self.arp_chunk + local_mac + local_ip + remote_mac + remote_ip + self.arp_pad


def main():
    with open('/tmp/from_t1.json') as fp:
        data = json.load(fp)

    ip_sets = {str(k): set(v) for k, v in data.items()}

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
