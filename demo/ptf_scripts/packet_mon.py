#!/usr/bin/env python

from scapy.all import sniff


def packet_callback(packet):
    print(packet.summary())


sniff(iface='eth4', prn=packet_callback)
