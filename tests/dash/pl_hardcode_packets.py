#!/usr/bin/python
import ptf.testutils as testutils
from scapy.sendrecv import sendp


def outbound_pl_packets():
    inner_packet = testutils.simple_udp_packet(
        eth_src="F4:93:9F:EF:C4:7E",
        ip_src="10.2.2.2",
        ip_dst="10.1.1.5",
    )

    vxlan_packet = testutils.simple_vxlan_packet(
        eth_src="ae:b4:97:5c:6a:0c",
        eth_dst="24:D5:E4:32:49:F0",
        ip_src="25.1.1.1",
        ip_dst="10.2.0.1",
        udp_dport=4789,
        with_udp_chksum=False,
        vxlan_vni=45654,
        inner_frame=inner_packet
    )

    return vxlan_packet


def send_packets():
    pkt = outbound_pl_packets()
    sendp(pkt, iface="eth8", count=1)


if __name__ == "__main__":
    send_packets()
