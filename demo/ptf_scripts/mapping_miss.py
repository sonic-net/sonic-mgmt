#!/usr/bin/env python

import packet_gen
from packet_gen import EniConfig
from scapy.all import sendp
from time import sleep

pkt = packet_gen.new_dash_packet(
    local_eni=EniConfig(mac="F4:93:9F:EF:C4:7E", ip="10.1.1.1", vni=4321, vnet="10.1.1.0/24"),
    remote_eni=EniConfig(mac="F9:22:83:99:22:A2", ip="20.2.2.200", vni=2000, vnet="20.2.2.0/24"),
)
pkt.show()

while True:
    sendp(pkt, iface="eth0")
    sleep(1)
