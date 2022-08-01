import argparse
import logging
import sys

from io import BytesIO
from concurrent.futures.thread import ThreadPoolExecutor
from scapy.all import conf, Ether, ICMP, IP
from scapy.arch import get_if_hwaddr
from scapy.data import ETH_P_IP
from select import select


root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def respond_to_icmp_request(socket, request, dst_mac=None):
    """Respond to ICMP request."""
    reply = request.copy()
    reply[ICMP].type = 0
    # Force re-generation of the checksum
    reply[ICMP].chksum = None
    reply[IP].src, reply[IP].dst = request[IP].dst, request[IP].src
    reply[IP].chksum = None

    if dst_mac is None:
        icmp_reply_dst_mac = request[Ether].src
    else:
        icmp_reply_dst_mac = dst_mac

    reply[Ether].src, reply[Ether].dst = request[Ether].dst, icmp_reply_dst_mac
    socket.send(reply)


class ICMPSniffer(object):
    """Sniff ICMP packets."""

    TYPE_ECHO_REQUEST = 8

    @staticmethod
    def is_icmp_packet_checksum_valid(packet):
        ip_chksum = packet[IP].chksum
        icmp_chksum = packet[ICMP].chksum
        packet[IP].chksum = None
        packet[ICMP].chksum = None
        rebuild_packet = Ether(packet.build())
        return rebuild_packet[IP].chksum == ip_chksum and rebuild_packet[ICMP].chksum == icmp_chksum

    @staticmethod
    def dump_scapy_packet_show_output(packet):
        """Dump packet show output to string."""
        _stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            packet.show()
            return sys.stdout.getvalue()
        finally:
            sys.stdout = _stdout

    def __init__(self, ifaces, request_handler=None, dst_mac=None, validate_checksum=False):
        """
        Init ICMP sniffer.

        @param ifaces: interfaces to listen for ICMP reqest
        @param request_handler: handler function that will be called when
                                receives ICMP request
        @param validate_checksum: validate checksum for received ICMP request before sending reply
        """
        self.sniff_sockets = []
        self.iface_hwaddr = {}
        for iface in ifaces:
            self.sniff_sockets.append(conf.L2socket(type=ETH_P_IP, iface=iface, filter="icmp"))
            self.iface_hwaddr[iface] = get_if_hwaddr(iface)
        self.request_handler = request_handler
        self.dst_mac = dst_mac
        self.validate_checksum = validate_checksum

    def __call__(self):
        try:
            while True:
                sel = select(self.sniff_sockets, [], [])
                for s in sel[0]:
                    packet = s.recv()
                    if packet is not None:
                        if ICMP in packet and packet[ICMP].type == self.TYPE_ECHO_REQUEST and self.request_handler:
                            if self.validate_checksum:
                                if ICMPSniffer.is_icmp_packet_checksum_valid(packet):
                                    self.request_handler(s, packet, self.dst_mac)
                                else:
                                    logging.error(
                                        "Receive ICMP echo message with invalid checksum:\n%s\n",
                                        ICMPSniffer.dump_scapy_packet_show_output(packet)
                                    )
                            else:
                                self.request_handler(s, packet, self.dst_mac)
        finally:
            for s in self.sniff_sockets:
                s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP responder")
    parser.add_argument("--intf", "-i", dest="ifaces", required=True, action="append", help="interface to listen for ICMP request")
    parser.add_argument("--dst_mac", "-m", dest="dst_mac", required=False, action="store", help="The destination MAC to use for ICMP echo replies")
    parser.add_argument("--validate_checksum", "-c", dest="validate_checksum", required=False, default=False,
                        action="store_true", help="validate received ICMP packet checksum before sending reply")
    args = parser.parse_args()
    ifaces = args.ifaces
    dst_mac = args.dst_mac
    validate_checksum = args.validate_checksum

    max_workers = 24 if len(ifaces) > 24 else len(ifaces)
    sniffed_ifaces = [[] for _ in range(max_workers)]
    for i, iface in enumerate(ifaces):
        sniffed_ifaces[i % max_workers].append(iface)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ifaces in sniffed_ifaces:
            icmp_sniffer = ICMPSniffer(ifaces, request_handler=respond_to_icmp_request, dst_mac=dst_mac, validate_checksum=validate_checksum)
            executor.submit(icmp_sniffer)
