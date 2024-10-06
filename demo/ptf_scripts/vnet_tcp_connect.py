#!/usr/bin/env python3

import packet_gen
from packet_gen import EniConfig
from scapy.all import sendp
from time import sleep

pkt = packet_gen.new_dash_packet(
    local_eni=EniConfig(mac="F4:93:9F:EF:C4:7E", ip="11.1.1.1", vni=1000, vnet="11.1.1.0/24"),
    remote_eni=EniConfig(mac="F9:22:83:99:22:A2", ip="22.2.2.2", vni=2000, vnet="22.2.2.0/24"),
)
pkt.show()

while True:
    sendp(pkt, iface="eth0")
    sleep(1)
