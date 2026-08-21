#!/usr/bin/env python3
"""Sustained MAC-move storm sender used by tests/fdb/test_fdb_mac_move.py.

Sends ARP request packets with a rotating pool of source MAC addresses
alternately on two PTF interfaces, generating a continuous stream of
FDB MAC-move events on the DUT to drive syncd CPU load.

Uses raw AF_PACKET sockets and pre-built byte buffers for performance.
Exits cleanly on SIGTERM / SIGINT.
"""
import argparse
import signal
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003


def _mac_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(":"))


def _ip_to_bytes(ip_str):
    return bytes(int(o) for o in ip_str.split("."))


def _int_to_mac(mac_int):
    return ":".join("{:02x}".format((mac_int >> (8 * j)) & 0xFF) for j in range(5, -1, -1))


def build_arp_request(eth_dst, eth_src, sender_ip="10.10.1.3", target_ip="10.10.1.2",
                      vlan_tag=None):
    eth = _mac_to_bytes(eth_dst) + _mac_to_bytes(eth_src)
    if vlan_tag is not None:
        # 802.1Q tag: TPID=0x8100, TCI = PCP(0) | DEI(0) | VID (lower 12 bits)
        eth += b"\x81\x00" + struct.pack("!H", vlan_tag & 0x0FFF)
    eth += b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += _mac_to_bytes(eth_src) + _ip_to_bytes(sender_ip)
    arp += b"\x00" * 6 + _ip_to_bytes(target_ip)
    pkt = eth + arp
    if len(pkt) < 60:
        pkt += b"\x00" * (60 - len(pkt))
    return pkt


def open_raw_socket(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    return sock


_running = True


def _stop(_signum, _frame):
    global _running
    _running = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface-a", required=True)
    parser.add_argument("--iface-b", required=True)
    parser.add_argument("--router-mac", required=True,
                        help="DUT router MAC used as eth_dst on the ARP packets")
    parser.add_argument("--num-macs", type=int, default=1000,
                        help="number of distinct source MACs to rotate through")
    parser.add_argument("--mac-base", default="02:11:22:33:00:00",
                        help="base MAC; lower bits incremented up to --num-macs")
    parser.add_argument("--report-interval", type=float, default=10.0,
                        help="seconds between progress reports on stdout")
    parser.add_argument("--vlan-tag", type=int, default=None,
                        help="if set, insert an 802.1Q tag with this VID on every frame")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sock_a = open_raw_socket(args.iface_a)
    sock_b = open_raw_socket(args.iface_b)

    base_int = int(args.mac_base.replace(":", ""), 16)
    pkts = [
        build_arp_request(args.router_mac, _int_to_mac(base_int + i),
                          vlan_tag=args.vlan_tag)
        for i in range(args.num_macs)
    ]
    n = len(pkts)

    sys.stdout.write(
        "storm started: iface_a={} iface_b={} num_macs={} router_mac={} vlan_tag={}\n".format(
            args.iface_a, args.iface_b, n, args.router_mac, args.vlan_tag))
    sys.stdout.flush()

    sent = 0
    last_report = time.time()
    while _running:
        # One round: each MAC is sent on iface_a immediately followed by iface_b,
        # producing one FDB MAC-move event per MAC per round on the DUT.
        for i in range(n):
            if not _running:
                break
            try:
                sock_a.send(pkts[i])
                sock_b.send(pkts[i])
                sent += 2
            except OSError as e:
                sys.stderr.write("send error on mac index {}: {}\n".format(i, e))
                time.sleep(0.01)
        now = time.time()
        elapsed = now - last_report
        if elapsed >= args.report_interval:
            sys.stdout.write("pkts={} pps={:.0f}\n".format(sent, sent / elapsed))
            sys.stdout.flush()
            sent = 0
            last_report = now

    sock_a.close()
    sock_b.close()
    sys.stdout.write("storm stopped\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
