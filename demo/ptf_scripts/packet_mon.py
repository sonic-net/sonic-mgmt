#!/usr/bin/env python3

from scapy.all import sniff


def packet_callback(packet):
    print(packet.summary())


sniff(iface='eth4', prn=packet_callback)
