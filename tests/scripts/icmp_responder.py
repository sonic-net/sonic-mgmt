import argparse

from scapy.all import conf, Ether, ICMP, IP
from scapy.arch import get_if_hwaddr
from scapy.data import ETH_P_IP
from select import select


def respond_to_icmp_request(socket, request, src_mac=None):
    """Respond to ICMP request."""
    reply = request.copy()
    reply[ICMP].type = 0
    # Force re-generation of the checksum
    reply[ICMP].chksum = None
    reply[IP].src, reply[IP].dst = request[IP].dst, request[IP].src
    reply[IP].chksum = None

    if src_mac is None:
        icmp_reply_source_mac = request[Ether].src
    else:
        icmp_reply_source_mac = src_mac

    reply[Ether].src, reply[Ether].dst = request[Ether].dst, icmp_reply_source_mac
    socket.send(reply)


class ICMPSniffer(object):
    """Sniff ICMP packets."""

    TYPE_ECHO_REQUEST = 8

    def __init__(self, ifaces, request_handler=None, src_mac=None):
        """
        Init ICMP sniffer.

        @param ifaces: interfaces to listen for ICMP reqest
        @param request_handler: handler function that will be called when
                                receives ICMP request
        """
        self.sniff_sockets = []
        self.iface_hwaddr = {}
        for iface in ifaces:
            self.sniff_sockets.append(conf.L2socket(type=ETH_P_IP, iface=iface, filter="icmp"))
            self.iface_hwaddr[iface] = get_if_hwaddr(iface)
        self.request_handler = request_handler
        self.src_mac = src_mac

    def __call__(self):
        try:
            while True:
                sel = select(self.sniff_sockets, [], [])
                for s in sel[0]:
                    packet = s.recv()
                    if packet is not None:
                        if packet[ICMP].type == self.TYPE_ECHO_REQUEST and self.request_handler:
                            self.request_handler(s, packet, self.src_mac)
        finally:
            for s in self.sniff_sockets:
                s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP responder")
    parser.add_argument("--intf", "-i", dest="ifaces", required=True, action="append", help="interface to listen for ICMP request")
    parser.add_argument("--src_mac", "-m", dest="src_mac", required=False, action="store", help="The source MAC to use for ICMP replies")
    args = parser.parse_args()
    ifaces = args.ifaces
    src_mac = args.src_mac

    icmp_sniffer = ICMPSniffer(ifaces, request_handler=respond_to_icmp_request, src_mac=src_mac)
    icmp_sniffer()
