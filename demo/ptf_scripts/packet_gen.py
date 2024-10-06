from ptf import testutils


class UnderlayConfig:
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip


class EniConfig:
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


def new_underlay_ping_packet():
    testutils.simple_icmp_packet(
        eth_src=underlay["local"].mac,
        eth_dst=underlay["remote"].mac,
        ip_src=underlay["local"].ip,
        ip_dst=underlay["remote"].ip,
        ip_ttl=underlay["ttl"]
    )


def new_overlay_packet(local_eni: EniConfig, remote_eni: EniConfig):
    testutils.simple_tcp_packet(
        eth_src=local_eni.mac,
        eth_dst=remote_eni.mac,
        ip_src=local_eni.ip,
        ip_dst=remote_eni.ip,
        tcp_sport=1234,
        tcp_dport=5000
    )


def new_dash_packet(local_eni: EniConfig, remote_eni: EniConfig):
    testutils.simple_vxlan_packet(
        eth_src=underlay["local"].mac,
        eth_dst=underlay["remote"].mac,
        ip_src=underlay["local"].ip,
        ip_dst=underlay["remote"].ip,
        udp_dport=4789,
        vxlan_vni=local_eni.vni,
        ip_ttl=64,
        inner_frame=new_overlay_packet(local_eni, remote_eni)
    )
