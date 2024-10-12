#!/usr/bin/env python

from scapy.all import sniff


def packet_callback(packet):
    print(packet.summary())


sniff(iface='eth0', prn=packet_callback)
