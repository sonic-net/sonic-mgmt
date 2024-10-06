from ptf import testutils


class UnderlayConfig:
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip


class OverlayConfig:
    def __init__(self, mac, ip, vni, vnet):
        self.mac = mac
        self.ip = ip
        self.vni = vni
        self.vnet = vnet


# Underlay configuration
underlay = {
    "local": UnderlayConfig(mac="9a:50:c1:b1:9f:00", ip="10.0.0.1"),
    "remote": UnderlayConfig(mac="22:48:23:27:33:d8", ip="10.0.0.37"),
}


# Overlay configuration
overlay = {
    "local": OverlayConfig(mac="F4:93:9F:EF:C4:7E", ip="11.1.1.1", vni=1000, vnet="11.1.1.0/24"),
    "remote": OverlayConfig(mac="F9:22:83:99:22:A2", ip="22.2.2.2", vni=2000, vnet="22.2.2.0/24"),
}


def new_underlay_ping_packet():
    testutils.simple_icmp_packet(
        eth_src=underlay["local"].mac,
        eth_dst=underlay["remote"].mac,
        ip_src=underlay["local"].ip,
        ip_dst=underlay["remote"].ip,
        ip_ttl=underlay["ttl"]
    )


def new_overlay_packet():
    testutils.simple_tcp_packet(
        eth_src=overlay["local"].mac,
        eth_dst=overlay["remote"].mac,
        ip_src=overlay["local"].ip,
        ip_dst=overlay["remote"].ip,
        tcp_sport=1234,
        tcp_dport=5000
    )


def new_vnet_packet():
    testutils.simple_vxlan_packet(
        eth_src=underlay["local"].mac,
        eth_dst=underlay["remote"].mac,
        ip_src=underlay["local"].ip,
        ip_dst=underlay["remote"].ip,
        udp_dport=4789,
        vxlan_vni=overlay["local"].vni,
        ip_ttl=64,
        inner_frame=new_overlay_packet()
    )
