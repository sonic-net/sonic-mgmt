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


def new_underlay_ping_packet(local_dev=UnderlayConfig(mac="9a:50:c1:b1:9f:00", ip="10.0.0.2"),
                             remote_dev=UnderlayConfig(mac="22:48:23:27:33:d8", ip="10.0.0.37")):
    return testutils.simple_icmp_packet(
        eth_src=local_dev.mac,
        eth_dst=remote_dev.mac,
        ip_src=local_dev.ip,
        ip_dst=remote_dev.ip,
        ip_ttl=64,
    )


def new_overlay_packet(local_eni, remote_eni):
    return testutils.simple_tcp_packet(
        eth_src=local_eni.mac,
        eth_dst=remote_eni.mac,
        ip_src=local_eni.ip,
        ip_dst=remote_eni.ip,
        tcp_sport=1234,
        tcp_dport=5000
    )


def new_dash_packet(local_eni,
                    remote_eni,
                    local_dev=UnderlayConfig(mac="9a:50:c1:b1:9f:00", ip="10.0.0.2"),
                    remote_dev=UnderlayConfig(mac="22:48:23:27:33:d8", ip="10.0.0.37")):
    return testutils.simple_vxlan_packet(
        eth_src=local_dev.mac,
        eth_dst=remote_dev.mac,
        ip_src=local_dev.ip,
        ip_dst=remote_dev.ip,
        ip_ttl=64,
        udp_dport=4789,
        vxlan_vni=local_eni.vni,
        inner_frame=new_overlay_packet(local_eni, remote_eni)
    )
