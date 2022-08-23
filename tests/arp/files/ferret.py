#/usr/bin/env python

# python t.py -f /tmp/vxlan_decap.json -s 192.168.8.1

import SimpleHTTPServer
import SocketServer
import select
import shutil
import json
import BaseHTTPServer
import time
import socket
import ctypes
import ssl
import struct
import binascii
import itertools
import argparse
import os

from pprint import pprint

from cStringIO import StringIO
from functools import partial
from collections import namedtuple


Record = namedtuple('Record', ['hostname', 'family', 'expired', 'lo', 'mac', 'vxlan_id'])

ASIC_TYPE=None


class Ferret(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = "FerretHTTP/0.1"

    def do_POST(self):
        if not self.path.startswith('/Ferret/NeighborAdvertiser/Slices/'):
            self.send_error(404, "URL is not supported")
        else:
            info = self.extract_info()
            self.update_db(info)
            self.send_resp(info)

    def extract_info(self):
        c_len = int(self.headers.getheader('content-length', 0))
        body = self.rfile.read(c_len)
        j = json.loads(body)
        return j

    def generate_entries(self, hostname, family, expire, lo, info, mapping_family):
        for i in info['vlanInterfaces']:
            vxlan_id = int(i['vxlanId'])
            for j in i[mapping_family]:
                mac = str(j['macAddr']).replace(':', '')
                addr = str(j['ipAddr'])
                r = Record(hostname=hostname, family=family, expired=expire, lo=lo, mac=mac, vxlan_id=vxlan_id)
                self.db[addr] = r

        return

    def update_db(self, info):
        hostname = str(info['switchInfo']['name'])
        lo_ipv4  = str(info['switchInfo']['ipv4Addr'])
        lo_ipv6  = str(info['switchInfo']['ipv6Addr'])
        duration = int(info['respondingSchemes']['durationInSec'])
        expired  = time.time() + duration

        self.generate_entries(hostname, 'ipv4', expired, lo_ipv4, info, 'ipv4AddrMappings')
        self.generate_entries(hostname, 'ipv6', expired, lo_ipv6, info, 'ipv6AddrMappings')

        return

    def send_resp(self, info):
        result = {
            'ipv4Addr': self.src_ip
        }
        f, l = self.generate_response(result)
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(l))
        self.send_header("Last-Modified", self.date_time_string())
        self.end_headers()
        shutil.copyfileobj(f, self.wfile)
        f.close()
        return

    def generate_response(self, response):
        f = StringIO()
        json.dump(response, f)
        l = f.tell()
        f.seek(0)
        return f, l


class RestAPI(object):
    PORT = 448

    def __init__(self, obj, db, src_ip):
        self.httpd = SocketServer.TCPServer(("", self.PORT), obj)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self.context.verify_mode = ssl.CERT_NONE
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="/opt/test.pem", keyfile="/opt/test.key")
        self.httpd.socket=self.context.wrap_socket(self.httpd.socket, server_side=True)
        self.db = db
        obj.db = db
        obj.src_ip = src_ip

    def handler(self):
        return self.httpd.fileno()

    def handle(self):
        return self.httpd.handle_request()


class Interface(object):
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 1000
    RCV_SIZE = 4096
    SO_ATTACH_FILTER = 26

    def __init__(self, iface, bpf_src):
        self.iface = iface
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
        if bpf_src is not None:
            blob = ctypes.create_string_buffer(''.join(struct.pack("HBBI", *e) for e in bpf_src))
            address = ctypes.addressof(blob)
            bpf = struct.pack('HL', len(bpf_src), address)
            self.socket.setsockopt(socket.SOL_SOCKET, self.SO_ATTACH_FILTER, bpf)
        self.socket.bind((self.iface, 0))
        self.socket.settimeout(self.RCV_TIMEOUT)

    def __del__(self):
        self.socket.close()

    def handler(self):
        return self.socket.fileno()

    def recv(self):
        return self.socket.recv(self.RCV_SIZE)

    def send(self, data):
        self.socket.send(data)


class Poller(object):
    def __init__(self, httpd, interfaces, responder):
        self.responder = responder
        self.mapping = {interface.handler(): interface for interface in interfaces}
        self.httpd = httpd

    def poll(self):
        handlers = self.mapping.keys() + [self.httpd.handler()]
        while True:
            (rdlist, _, _) = select.select(handlers, [], [])
            for handler in rdlist:
                if handler == self.httpd.handler():
                    self.httpd.handle()
                else:
                    self.responder.action(self.mapping[handler])


class Responder(object):
    ARP_PKT_LEN = 60
    ARP_OP_REQUEST = 1
    def __init__(self, db, vxlan_port):
        self.arp_chunk = binascii.unhexlify('08060001080006040002') # defines a part of the packet for ARP Reply
        self.arp_pad = binascii.unhexlify('00' * 18)
        self.db = db
        self.vxlan_port = vxlan_port

    def hexdump(self, data):
        print " ".join("%02x" % ord(d) for d in data)

    def action(self, interface):
        data = interface.recv()

        ext_dst_mac  = data[0x00:0x06]
        ext_src_mac  = data[0x06:0x0c]
        ext_eth_type = data[0x0c:0x0e]
        if ext_eth_type != binascii.unhexlify('0800'):
            print "Not 0x800 eth type"
            self.hexdump(data)
            print
            return
        src_ip = data[0x001a:0x001e]
        dst_ip = data[0x1e:0x22]
        gre_flags = data[0x22:0x24]
        gre_type  = data[0x24:0x26]

        gre_type_r = struct.unpack('!H', gre_type)[0]
        self.hexdump(data)
        if gre_type_r == 0x88be:   # Broadcom
            arp_request = data[0x26:]
            if ASIC_TYPE == "barefoot":
                # ERSPAN type 2
                # Ethernet(14) + IP(20) + GRE(4) + ERSPAN(8) = 46 = 0x2e
                # Note: Count GRE as 4 byte, only mandatory fields.
                # References: https://tools.ietf.org/html/rfc1701
                #             https://tools.ietf.org/html/draft-foschiano-erspan-00
                arp_request = data[0x2E:]
            elif ASIC_TYPE == "cisco-8000":
                # Ethernet(14) + IP(20) + GRE(8) + ERSPAN(8) = 50 = 0x32
                arp_request = data[0x32:]

        elif gre_type_r == 0x8949: # Mellanox
            arp_request = data[0x3c:]
        else:
            print "GRE type 0x%x is not supported" % gre_type_r
            self.hexdump(data)
            print
            return

        if len(arp_request) > self.ARP_PKT_LEN:
            print "Too long packet"
            self.hexdump(data)
            print
            return

        vlan_id, remote_mac, remote_ip, request_ip, op_type = self.extract_arp_info(arp_request)
        # Don't send ARP response if the ARP op code is not request
        if op_type != self.ARP_OP_REQUEST:
            return

        request_ip_str = socket.inet_ntoa(request_ip)

        if request_ip_str not in self.db:
            print "Not in db"
            return

        r = self.db[request_ip_str]
        if r.expired < time.time():
            print "Expired row in db"
            del self.db[request_ip_str]
            return

        if r.family == 'ipv4':
            new_pkt  = ext_src_mac + ext_dst_mac + ext_eth_type # outer eth frame
            ipv4 = binascii.unhexlify('45000060977e400040110000') + dst_ip + src_ip # ip
            crc = self.calculate_header_crc(ipv4)
            ipv4 = ipv4[0:10] + crc + ipv4[12:]
            new_pkt += ipv4
            if self.vxlan_port:
                new_pkt += binascii.unhexlify('c000%04x004c1280' % self.vxlan_port) # udp
            else:
                new_pkt += binascii.unhexlify('c00012b5004c1280') # udp
            new_pkt += binascii.unhexlify('08000000%06x00' % r.vxlan_id) # vxlan

            arp_reply = self.generate_arp_reply(binascii.unhexlify(r.mac), remote_mac, request_ip, remote_ip, vlan_id)
            new_pkt += arp_reply
        else:
            print 'Support of family %s is not implemented' % r.family
            return

        interface.send(new_pkt)

        return

    def calculate_header_crc(self, ipv4):
        s = 0
        for l,r in zip(ipv4[::2], ipv4[1::2]):
            l_u = struct.unpack("B", l)[0]
            r_u = struct.unpack("B", r)[0]
            s += (l_u << 8) + r_u

        c = s >> 16
        s = s & 0xffff

        while c != 0:
            s += c
            c = s >> 16
            s = s & 0xffff

        s = 0xffff - s

        return binascii.unhexlify("%x" % s)

    def extract_arp_info(self, data):
        vlan_id = ord(data[14]) * 256 + ord(data[15])
        if vlan_id == 1:
            offset = 0
        else:
            offset = 4
        # vlan_id, remote_mac, remote_ip, request_ip, op_type
        return vlan_id, data[6:12], data[offset+28:offset+32], data[offset+38:offset+42], (ord(data[offset+20]) * 256 + ord(data[offset+21]))

    def generate_arp_reply(self, local_mac, remote_mac, local_ip, remote_ip, vlan_id):
        eth_hdr = remote_mac + local_mac
        #if vlan_id != 1:
        #    eth_hdr = eth_hdr + binascii.unhexlify("8100%04x" % vlan_id)
        return eth_hdr + self.arp_chunk + local_mac + local_ip + remote_mac + remote_ip + self.arp_pad

def get_bpf_for_bgp():
    bpf_src = [
        (0x28, 0, 0, 0x0000000c), # (000) ldh      [12]
        (0x15, 0, 2, 0x00000800), # (001) jeq      #0x800           jt 2    jf 4
        (0x30, 0, 0, 0x00000017), # (002) ldb      [23]
        (0x15, 6, 7, 0x0000002f), # (003) jeq      #0x2f            jt 10   jf 11
        (0x15, 0, 6, 0x000086dd), # (004) jeq      #0x86dd          jt 5    jf 11
        (0x30, 0, 0, 0x00000014), # (005) ldb      [20]
        (0x15, 3, 0, 0x0000002f), # (006) jeq      #0x2f            jt 10   jf 7
        (0x15, 0, 3, 0x0000002c), # (007) jeq      #0x2c            jt 8    jf 11
        (0x30, 0, 0, 0x00000036), # (008) ldb      [54]
        (0x15, 0, 1, 0x0000002f), # (009) jeq      #0x2f            jt 10   jf 11
        (0x6,  0, 0, 0x00040000), # (010) ret      #262144
        (0x6,  0, 0, 0x00000000), # (011) ret      #0
    ]
    return bpf_src


def extract_iface_names(config_file):
    with open(config_file) as fp:
        graph = json.load(fp)

    net_ports = []
    for name, val in graph['minigraph_portchannels'].items():
        members = ['eth%d' % graph['minigraph_port_indices'][member] for member in val['members']]
        net_ports.extend(members)

    return net_ports

def parse_args():
    parser = argparse.ArgumentParser(description='Ferret VXLAN API')
    parser.add_argument('-f', '--config-file', help='file with configuration', required=True)
    parser.add_argument('-s', '--src-ip', help='Ferret endpoint ip', required=True)
    parser.add_argument('-a', '--asic-type', help='ASIC vendor name', type=str, required=False)
    parser.add_argument('-p', '--vxlan-port', help='VXLAN port', type=int, required=False, default=None)
    args = parser.parse_args()
    if not os.path.isfile(args.config_file):
        print "Can't open config file '%s'" % args.config_file
        exit(1)

    global ASIC_TYPE
    ASIC_TYPE = args.asic_type
    return args.config_file, args.src_ip, args.vxlan_port

def main():
    db = {}

    config_file, src_ip, vxlan_port = parse_args()
    iface_names = extract_iface_names(config_file)
    rest = RestAPI(Ferret, db, src_ip)
    bpf_src = get_bpf_for_bgp()
    ifaces = [Interface(iface_name, bpf_src) for iface_name in iface_names]
    responder = Responder(db, vxlan_port)
    p = Poller(rest, ifaces, responder)
    p.poll()

if __name__ == '__main__':
    main()
