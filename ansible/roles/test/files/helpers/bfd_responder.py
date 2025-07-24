import socket
import struct
import select
import json
import argparse
import os.path
from fcntl import ioctl
import logging
import scapy.all as scapy2
from scapy.contrib.bfd import BFD
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy2.conf.use_pcap = True

IPv4 = '4'
IPv6 = '6'
BFD_FLAG_P_BIT = 5
BFD_FLAG_F_BIT = 4
UDP_BFD_PKT_LEN = 32


def get_mac(ifname):
    """
    Retrieves the MAC address for a given network interface name on a Linux system.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a socket.
    # Use fcntl.ioctl to make the SIOCGIFHWADDR request.
    # '0x8927' is the numerical value of SIOCGIFHWADDR.
    # struct.pack prepares the interface name string for the request.
    info = ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    # The MAC address is contained in the response data, bytes 18-24.
    # We format it as a colon-separated hex string.
    value = ':'.join('%02x' % b for b in info[18:24])
    print(f"mac = {value}")
    return value


class Interface(object):

    def __init__(self, iface):
        self.iface = iface
        self.socket = None
        self.mac_address = get_mac(iface)

    def __del__(self):
        if self.socket:
            self.socket.close()

    def bind(self):
        self.socket = scapy2.conf.L2listen(
            iface=self.iface, filter="udp port 4784")

    def handler(self):
        return self.socket

    def recv(self):
        sniffed = self.socket.recv()
        pkt = sniffed[0]
        return pkt

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


class BFDResponder(object):
    def __init__(self, sessions):
        self.sessions = sessions
        self.bfd_default_ip_priority = 192
        return

    def action(self, interface):
        data = interface.recv()
        mac_src, mac_dst, ip_src, ip_dst,  bfd_remote_disc, bfd_state, bfd_flags = self.extract_bfd_info(
            data)
        if ip_dst not in self.sessions:
            return
        session = self.sessions[ip_dst]
        if bfd_state == 3:
            # If packet is not initialized yet, ignore the received UP packet per RFC5880 FSM
            # wait for DUT timeout and DUT will send DOWN BFD packet
            if len(session["pkt"]) == 0:
                return
            # Respond with F bit if P bit is set
            if (bfd_flags & (1 << BFD_FLAG_P_BIT)):
                session["pkt"].payload.payload.payload.load.flags = (1 << BFD_FLAG_F_BIT)
            interface.send(session["pkt"])
            session["pkt"].payload.payload.payload.load.flags = 0
            return

        if bfd_state == 2:
            return
        session["other_disc"] = bfd_remote_disc
        bfd_pkt_init = self.craft_bfd_packet(
            session, data, mac_src, mac_dst, ip_src, ip_dst, bfd_remote_disc, 2)
        bfd_pkt_init.payload.payload.chksum = None
        bfd_pkt_init.payload.payload.payload.load.flags = 0
        interface.send(bfd_pkt_init)
        bfd_pkt_init.payload.payload.payload.load.sta = 3
        bfd_pkt_init.payload.payload.chksum = None
        session["pkt"] = bfd_pkt_init
        return

    def extract_bfd_info(self, data):
        # remote_mac, remote_ip, request_ip, op_type
        ether = data
        mac_src = ether.src
        mac_dst = ether.dst
        ip_src = ether.payload.src
        ip_dst = ether.payload.dst
        # ignore the packet not for me or incomplete BFD packet
        if ip_dst not in self.sessions or len(ether.payload.payload) < UDP_BFD_PKT_LEN:
            return mac_src, mac_dst, ip_src, ip_dst, None, None, None
        ip_version = str(ether.payload.version)
        ip_priority_field = 'tos' if ip_version == IPv4 else 'tc'
        ip_priority = getattr(ether.payload, ip_priority_field)
        bfdpkt = BFD(str(ether.payload.payload.payload).encode("utf-8"))
        bfd_remote_disc = bfdpkt.my_discriminator
        bfd_state = bfdpkt.sta
        bfd_flags = bfdpkt.flags
        if ip_priority != self.bfd_default_ip_priority:
            raise RuntimeError("Received BFD packet with incorrect priority value: {}".format(ip_priority))
        logging.debug('BFD packet info: sip {}, dip {}, priority {}'.format(ip_src, ip_dst, ip_priority))
        return mac_src, mac_dst, ip_src, ip_dst, bfd_remote_disc, bfd_state, bfd_flags

    def craft_bfd_packet(self, session, data, mac_src, mac_dst, ip_src, ip_dst, bfd_remote_disc, bfd_state):
        ethpart = data
        bfdpart = BFD(str(ethpart.payload.payload.payload).encode("utf-8"))
        bfdpart.my_discriminator = session["my_disc"]
        bfdpart.your_discriminator = bfd_remote_disc
        bfdpart.sta = bfd_state

        ethpart.payload.payload.payload.load = bfdpart
        ethpart.src = mac_dst
        ethpart.dst = mac_src
        ethpart.payload.src = ip_dst
        ethpart.payload.dst = ip_src
        return ethpart


def parse_args():
    parser = argparse.ArgumentParser(description='ARP autoresponder')
    parser.add_argument('--conf', '-c', type=str, dest='conf', default='/tmp/from_t1.json',
                        help='path to json file with configuration')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    if not os.path.exists(args.conf):
        print("Can't find file %s" % args.conf)
        return

    with open(args.conf) as fp:
        data = json.load(fp)

    # generate ip_sets. every ip address will have it's own uniq mac address
    sessions = {}
    local_disc_base = 0xcdba0000
    local_src_port = 14000
    ifaces = {}
    for bfd in data:
        curr_session = {}
        curr_session["local"] = bfd["local_addr"]
        curr_session["remote"] = bfd["neighbor_addr"]
        curr_session["intf"] = bfd["ptf_intf"]
        curr_session["multihop"] = bfd["multihop"]
        curr_session["my_disc"] = local_disc_base
        curr_session["other_disc"] = 0x00
        curr_session["mac"] = get_mac(str(bfd["ptf_intf"]))
        curr_session["src_port"] = local_src_port
        curr_session["pkt"] = ""
        if bfd["ptf_intf"] not in ifaces:
            ifaces[curr_session["intf"]] = curr_session["mac"]

        local_disc_base += 1
        local_src_port += 1
        sessions[curr_session["local"]] = curr_session
    ifaceobjs = []
    for iface_name in ifaces.keys():
        iface = Interface(str(iface_name))
        iface.bind()
        ifaceobjs.append(iface)

    resp = BFDResponder(sessions)

    p = Poller(ifaceobjs, resp)
    p.poll()
    return


if __name__ == '__main__':
    main()
