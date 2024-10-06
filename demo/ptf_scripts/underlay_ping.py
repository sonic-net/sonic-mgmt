#!/usr/bin/env python3

import packet_gen
from scapy.all import sendp
from time import sleep

pkt = packet_gen.new_underlay_ping_packet()
pkt.show()

while True:
    sendp(pkt, iface="eth0")
    sleep(1)
