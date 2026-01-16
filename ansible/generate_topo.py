#!/usr/bin/env python3

from collections import defaultdict, namedtuple
import copy
from typing import Any, Dict, List, Tuple, Union
from ipaddress import IPv4Network, IPv6Network, IPv4Address
import click
import jinja2

PTF_BACKPLANE_IPV4 = "10.10.246.254"
# current PTF subnet is  10.10.246.0/22
PTF_BACKPLANE_IPV4_LOWER_BOUND = "10.10.244.1"
PTF_BACKPLANE_IPV4_UPPER_BOUND = "10.10.247.254"
PTF_BACKPLANE_IPV4_DEFAULT_START = "10.10.246.1"
backplane_additional_offset_ipv4 = 0
PTF_BACKPLANE_IPV6 = "fc0a::ff"
backplane_additional_offset_ipv6 = 0


class LagPort(set):
    def __init__(self, *ports):
        super().__init__(ports)


class PortList(list):
    def __init__(self, *lag_ports: Union[LagPort, int]):
        super().__init__(lag_ports)

    def __contains__(self, key):
        if super().__contains__(key):
            return True
        return any([key in lag_port for lag_port in self if isinstance(lag_port, LagPort)])


class LagLink(set):
    def __init__(self, *links):
        super().__init__(links)


class LinkList(list):
    def __init__(self, *lag_links: Union[LagLink, int]):
        super().__init__(lag_links)

    def __contains__(self, key):
        if super().__contains__(key):
            return True
        return any([key in lag_link for lag_link in self if isinstance(lag_link, LagLink)])


Breakout = namedtuple('Breakout', ['port', 'index'])

# Define the roles for the devices in the topology
roles_cfg = {
    "t0": {
        "asn": 65100,
        "asn_v6": 4200000000,
        "downlink": None,
        "uplink": {"role": "t1", "asn": 64600, "asn_v6": 4200100000, "asn_increment": 0},
        "peer": {"role": "pt0", "asn": 65100, "asn_v6": 64620, "asn_increment": 1},
    },
    "t1": {
        "asn": 65100,
        "asn_v6": 4200100000,
        "downlink": {"role": "t0", "asn": 64000, "asn_v6": 4200000000, "asn_increment": 1},
        "uplink": {"role": "t2", "asn": 65200, "asn_v6": 4200200000, "asn_increment": 0},
        "peer": None,
    },
    "lt2": {
        "asn": 4200100000,
        "asn_v6": 4200100000,
        "downlink": {"role": "t1", "asn": 4200000000, "asn_v6": 4200000000, "asn_increment": 0, "num_lags": 1},
        "uplink": {"role": "ut2", "asn": 4200200000, "asn_v6": 4200200000, "asn_increment": 0},
        "fabric": {"role": "ft2", "asn": 4200100000, "asn_v6": 4200100000, "asn_increment": 0},
        "peer": None
    },
}

hw_port_cfg = {
    'default':          {"ds_breakout": 1, "us_breakout": 1, "ds_link_step": 1, "us_link_step": 1,
                         "panel_port_step": 1},
    'c256':             {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': [8, 10, 12, 14, 16, 18, 20, 22, 40, 42, 44, 46, 48, 50, 52, 54],
                         'peer_ports': [64, 65],
                         'skip_ports': [p for p in range(64) if p % 2 != 0],
                         "panel_port_step": 2},
    'c224o8':           {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': [12, 16, 44, 48],
                         'peer_ports': [],
                         'skip_ports': [p for p in range(64) if p % 2 != 0],
                         "panel_port_step": 2},
    'o128t0':           {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': list(range(16)),
                         'peer_ports': [64, 65],
                         'skip_ports': [],
                         "panel_port_step": 1},
    'o128t1':           {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': [],
                         'peer_ports': [],
                         'skip_ports': [],
                         "panel_port_step": 1},
    'c256-sparse':      {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 8, "us_link_step": 8,
                         'uplink_ports': [8, 10, 12, 14, 16, 18, 20, 22, 40, 42, 44, 46, 48, 50, 52, 54],
                         'peer_ports': [64, 65],
                         'skip_ports': [p for p in range(64) if p % 2 != 0],
                         "panel_port_step": 2},
    'c224o8-sparse':    {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 8, "us_link_step": 2,
                         'uplink_ports': [12, 16, 44, 48],
                         'peer_ports': [],
                         'skip_ports': [p for p in range(64) if p % 2 != 0] + [16, 44, 48],
                         "panel_port_step": 2},
    'o128-sparse':      {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 2,
                         "panel_port_step": 1},
    'c512s2':           {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': list(range(8, 24)) + list(range(40, 56)),
                         'peer_ports': [64, 65],
                         'skip_ports': [],
                         "panel_port_step": 1},
    'c512s2-sparse':    {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 8, "us_link_step": 8,
                         'uplink_ports': list(range(8, 24)) + list(range(40, 56)),
                         'peer_ports': [64, 65],
                         'skip_ports': [],
                         "panel_port_step": 1},
    'c448o16-lag':      {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': PortList(LagPort(12), 13, 16, 17, 44, 45, 48, 49),
                         'peer_ports': [],
                         'skip_ports': [],
                         "panel_port_step": 1},
    'c448o16-sparse':   {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 8, "us_link_step": 2,
                         'uplink_ports': [12, 13, 16, 17, 44, 45, 48, 49],
                         'peer_ports': [],
                         'skip_ports': [16, 17, 44, 45, 48, 49],
                         "panel_port_step": 1},
    'c448o16-lag-sparse':   {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 8, "us_link_step": 2,
                             'uplink_ports': PortList(LagPort(12), 13, 16, 17, 44, 45, 48, 49),
                             'peer_ports': [],
                             'skip_ports': [13, 16, 17, 44, 45, 48, 49],
                             "panel_port_step": 1},
    'o128lt2':          {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': PortList(45, 46, 47, 48, 49, 50, 51, 52),
                         'peer_ports': [],
                         'skip_ports': PortList(63),
                         'continuous_vms': True,
                         "panel_port_step": 1},
    'p32o64lt2':        {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': PortList(45, 49, 46, 50),
                         'skip_ports': PortList(11, 12, 13, 14, 27, 28, 29, 30),
                         "fabric_breakout": 1,
                         'fabric_ports': PortList(
                                 *[p for p in range(0, 32)]
                                 ),
                         'peer_ports': [],
                         'continuous_vms': True,
                         "panel_port_step": 1},
    'p32v128f2':        {"ds_breakout": 4, "us_breakout": 1, "ds_link_step": 1, "us_link_step": 1,
                         'uplink_ports': PortList(*list(range(0, 32))),
                         'lag_list': LinkList(LagLink(8, 9), LagLink(10, 11), LagLink(12, 13), LagLink(14, 15),
                                              LagLink(16, 17), LagLink(18, 19), LagLink(20, 21), LagLink(22, 23)),
                         'skip_ports': PortList(*list(range(0, 8)), *list(range(24, 32))),
                         'skip_links': (
                                        [link for port in range(32, 64)
                                         for link in [32 + (port - 32) * 4 + 2, 32 + (port - 32) * 4 + 3]]),
                         'peer_ports': [],
                         'continuous_vms': True,
                         'panel_port_step': 1,
                         "link_based": True},
    'p32o64f2':          {"ds_breakout": 1, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                          'uplink_ports': PortList(*list(range(32, 64))),
                          "lag_list": LinkList(
                                LagLink(0, 1), LagLink(2, 3), LagLink(4, 5), LagLink(6, 7), LagLink(8, 9),
                                LagLink(16, 17), LagLink(18, 19), LagLink(20, 21), LagLink(22, 23), LagLink(24, 25),
                                LagLink(56), LagLink(58), LagLink(60), LagLink(62),
                                LagLink(64), LagLink(66), LagLink(68), LagLink(70)),
                          'skip_ports': PortList(*list(range(10, 16)), *list(range(26, 44)), *list(range(52, 64))),
                          'skip_links': [link for port in range(44, 52) for link in [32 + (port - 32) * 2 + 1]],
                          'peer_ports': [],
                          'continuous_vms': True,
                          "panel_port_step": 1,
                          "link_based": True},
}

overwrite_file_name = {
    'lt2': {
        'p32o64': "lt2-p32o64",
        'o128': "lt2-o128",
    },
    't0': {
        'f2': "t0-f2-d40u8"
    }
}

vlan_group_cfgs = [
    {"name": "one_vlan_a", "vlan_count": 1,
        "v4_prefix": "192.168.0.0/21", "v6_prefix": "fc02:1000::0/64"},
    {"name": "two_vlan_a", "vlan_count": 2,
        "v4_prefix": "192.168.0.0/22", "v6_prefix": "fc02:100::0/64"},
    {"name": "four_vlan_a", "vlan_count": 4,
        "v4_prefix": "192.168.0.0/22", "v6_prefix": "fc02:100::0/64"},
]


# Utility functions to calculate IP addresses
def calc_ipv4_pair(subnet_str, port_id):
    subnet = IPv4Network(subnet_str)
    return (str(subnet.network_address + 2*port_id), str(subnet.network_address + 2*port_id + 1))


def calc_ipv6_pair(subnet_str, port_id):
    subnet = IPv6Network(subnet_str)
    return (str(subnet.network_address + 4*port_id+1), str(subnet.network_address + 4*port_id + 2))


def calc_ipv4(subnet_str, port_id):
    subnet = IPv4Network(subnet_str)
    return str(subnet.network_address + port_id)


def calc_ipv6(subnet_str, port_id):
    subnet = IPv6Network(subnet_str)
    return str(subnet.network_address + port_id)


class VM:
    """ Class to represent a VM in the topology """
    def __init__(self,
                 link_id: int,
                 vm_id: int,
                 name_id: int,
                 tornum: int,
                 dut_asn: int,
                 dut_asn_v6: int,
                 role_cfg: Dict[str, Any],
                 ip_offset: int = None,
                 num_lags=0):

        self.role = role_cfg["role"]

        # IDs of the VM
        self.link_id = link_id
        self.vm_offset = vm_id
        self.ip_offset = vm_id if ip_offset is None else ip_offset
        self.name = f"ARISTA{name_id:02d}{self.role.upper()}"
        self.tornum = tornum

        # VLAN configuration
        self.vlans = link_id

        # BGP configuration
        self.asn = role_cfg["asn"]
        self.asn_v6 = role_cfg["asn_v6"]
        self.peer_asn = dut_asn
        self.peer_asn_v6 = dut_asn_v6

        # IP addresses
        self.dut_intf_ipv4, self.pc_intf_ipv4 = calc_ipv4_pair(
            "10.0.0.0", self.ip_offset)
        self.dut_intf_ipv6, self.pc_intf_ipv6 = calc_ipv6_pair(
            "FC00::", self.ip_offset)
        self.loopback_ipv4 = calc_ipv4("100.1.0.0", self.ip_offset+1)
        self.loopback_ipv6 = calc_ipv6(
            "2064:100::", (self.ip_offset+1) * 2**64)

        # Set lags
        self.num_lags = num_lags

        # Backplane IPs
        global backplane_additional_offset_ipv4
        self.bp_ipv4 = calc_ipv4(
            PTF_BACKPLANE_IPV4_DEFAULT_START, self.ip_offset+1+backplane_additional_offset_ipv4)
        if self.bp_ipv4 == PTF_BACKPLANE_IPV4:
            backplane_additional_offset_ipv4 = 1
            self.bp_ipv4 = calc_ipv4(
                PTF_BACKPLANE_IPV4_DEFAULT_START, self.ip_offset+1+backplane_additional_offset_ipv4)
        # Ensure backplane IP is within the allowed range
        # Default [10.10.246.1 ---- 10.10.247.254], once crossed the upper bound, it will be starting from
        # lower bound [10.10.244.1 -- 10.10.245.255]. If the backplane IP reaches to 10.10.246.1 again. that
        # means the range is exhausted.
        if IPv4Address(self.bp_ipv4) > IPv4Address(PTF_BACKPLANE_IPV4_UPPER_BOUND):
            diff = int(IPv4Address(self.bp_ipv4)) - int(IPv4Address(PTF_BACKPLANE_IPV4_UPPER_BOUND))
            self.bp_ipv4 = IPv4Address(PTF_BACKPLANE_IPV4_LOWER_BOUND) + diff - 1
            if self.bp_ipv4 >= IPv4Address(PTF_BACKPLANE_IPV4_DEFAULT_START):
                assert False, "Backplane IP address exceeds the allowed range"

        global backplane_additional_offset_ipv6
        self.bp_ipv6 = calc_ipv6(
            "fc0a::1", (self.ip_offset+1+backplane_additional_offset_ipv6))
        if self.bp_ipv6 == PTF_BACKPLANE_IPV6:
            backplane_additional_offset_ipv6 = 1
            self.bp_ipv6 = calc_ipv6(
                "fc0a::1", self.ip_offset+1+backplane_additional_offset_ipv6)


class HostInterface:
    """ Class to represent a host interface in the topology """
    def __init__(self, port_id: int):
        self.port_id = port_id

    def __repr__(self):
        return f"HostInterface(port_id={self.port_id})"


class Vlan:
    """ Class to represent a VLAN in the topology """
    def __init__(self,
                 vlan_id: int,
                 hostifs: List[HostInterface],
                 v4_prefix: IPv4Network,
                 v6_prefix: IPv6Network):

        self.id = vlan_id
        self.intfs = hostifs
        self.port_ids = [hostif.port_id for hostif in hostifs]
        self.v4_prefix = copy.deepcopy(v4_prefix)
        self.v4_prefix.network_address += 1
        self.v6_prefix = copy.deepcopy(v6_prefix)
        self.v6_prefix.network_address += 1


class VlanGroup:
    """ Class to represent a group of VLANs in the topology """
    def __init__(self, name: str, vlan_count: int, hostifs: List[HostInterface], v4_prefix: str, v6_prefix: str):
        self.name = name
        self.vlans = []

        # Split host if into the number of VLANs
        hostif_count_per_vlan = len(hostifs) // vlan_count
        hostif_groups = [
            hostifs[i*hostif_count_per_vlan:(i+1)*hostif_count_per_vlan] for i in range(vlan_count)]

        v4_prefix = IPv4Network(v4_prefix)
        v6_prefix = IPv6Network(v6_prefix)
        for vlan_index in range(len(hostif_groups)):
            vlan = Vlan(1000 + vlan_index * 100,
                        hostif_groups[vlan_index], v4_prefix, v6_prefix)
            self.vlans.append(vlan)

            # Move to next subnet based on the prefix length
            v4_prefix.network_address += 2**(32 - v4_prefix.prefixlen)
            v6_prefix.network_address += 2**96


def generate_topo_link_based(role: str,
                             panel_port_count: int,
                             port_cfg_type: str = "default",
                             ) -> Tuple[List[VM], List[HostInterface]]:

    def _find_lag_link(link_id: int) -> bool:
        nonlocal port_cfg
        if not isinstance(port_cfg["lag_list"], LinkList):
            return False, None

        lag_link = next(
            (lp for lp in (port_cfg["lag_list"])
             if isinstance(lp, LagLink) and link_id in lp), None)
        return (lag_link is not None, lag_link)

    dut_role_cfg = roles_cfg[role]
    port_cfg = hw_port_cfg[port_cfg_type]
    uplink_ports = port_cfg.get('uplink_ports', [])
    peer_ports = port_cfg.get('peer_ports', [])
    skip_ports = port_cfg.get('skip_ports', [])
    skip_links = port_cfg.get("skip_links", [])

    vm_list = []
    downlinkif_list = []
    uplinkif_list = []
    disabled_hostif_list = []
    per_role_vm_count = defaultdict(lambda: 0)
    lag_links_assigned = set()
    tornum = 1
    link_id_start = 0

    for panel_port_id in list(range(0, panel_port_count, port_cfg['panel_port_step'])) + peer_ports:
        vm_role_cfg = None
        link_step = 1
        link_type = None

        if panel_port_id in uplink_ports:
            if dut_role_cfg["uplink"] is None:
                raise ValueError(
                    "Uplink port specified for a role that doesn't have an uplink")

            vm_role_cfg = dut_role_cfg["uplink"]

            link_id_end = link_id_start + port_cfg['us_breakout']
            link_step = port_cfg['us_link_step']
            link_type = 'up'
        elif panel_port_id in peer_ports:
            if dut_role_cfg["peer"] is None:
                raise ValueError(
                    "Peer port specified for a role that doesn't have a peer")

            vm_role_cfg = dut_role_cfg["peer"]

            link_id_end = link_id_start + 1
            link_step = 1
            link_type = 'peer'
        elif panel_port_id in port_cfg.get("fabric_ports", []):
            vm_role_cfg = dut_role_cfg["fabric"]

            link_id_end = link_id_start + port_cfg.get("fabric_breakout", 1)
            link_step = 1
            link_type = 'fabric'
        else:
            # If downlink is not specified, we consider it is host interface
            if dut_role_cfg["downlink"] is not None:
                vm_role_cfg = dut_role_cfg["downlink"]

            link_id_end = link_id_start + port_cfg['ds_breakout']
            link_step = port_cfg['ds_link_step']
            link_type = 'down'

        for link_id in range(link_id_start, link_id_end):
            vm = None
            hostif = None

            # Create the VM or host interface based on the configuration
            if vm_role_cfg is not None:
                if not port_cfg.get('continuous_vms', False):  # the VM id is per-link basis if setting is False
                    per_role_vm_count[vm_role_cfg["role"]] += 1

                if (link_id - link_id_start) % link_step == 0 and panel_port_id not in skip_ports:
                    # Skip breakout if defined
                    if panel_port_id in skip_ports:
                        continue

                    if link_id in skip_links or link_id in lag_links_assigned:
                        continue

                    is_lag_link, lag_link = _find_lag_link(link_id)

                    if port_cfg.get('continuous_vms', False):  # the VM id is continuous if setting is true
                        per_role_vm_count[vm_role_cfg["role"]] += 1

                    vm_role_cfg["asn"] += vm_role_cfg.get("asn_increment", 1)
                    vm_role_cfg["asn_v6"] += vm_role_cfg.get("asn_increment", 1)

                    if is_lag_link:
                        # only create VM for first link in the lag
                        vm = VM(list(lag_link), len(vm_list), per_role_vm_count[vm_role_cfg["role"]], tornum,
                                dut_role_cfg["asn"], dut_role_cfg["asn_v6"], vm_role_cfg, link_id_start,
                                num_lags=len(lag_link))
                        lag_links_assigned.update(lag_link)
                    else:
                        vm = VM([link_id], len(vm_list), per_role_vm_count[vm_role_cfg["role"]], tornum,
                                dut_role_cfg["asn"], dut_role_cfg["asn_v6"], vm_role_cfg, link_id,
                                num_lags=0)
                    vm_list.append(vm)
                    if link_type == 'up':
                        uplinkif_list.append(link_id)
                    elif link_type == 'down':
                        tornum += 1
                        downlinkif_list.append(link_id)
            else:
                if ((link_id - link_id_start) % link_step == 0
                        and panel_port_id not in skip_ports
                        and link_id not in port_cfg.get("skip_links", [])):
                    hostif = HostInterface(link_id)
                    downlinkif_list.append(hostif)
                elif (panel_port_id in skip_ports) or (link_id in port_cfg.get("skip_links", [])):
                    hostif = HostInterface(link_id)
                    disabled_hostif_list.append(hostif)
        link_id_start = link_id_end

    return vm_list, downlinkif_list, uplinkif_list, disabled_hostif_list


def generate_topo(role: str,
                  panel_port_count: int,
                  uplink_ports: List[int],
                  peer_ports: List[int],
                  skip_ports: List[int],
                  port_cfg_type: str = "default",
                  ) -> Tuple[List[VM], List[HostInterface]]:

    def _find_lag_port(port_id: int) -> bool:
        nonlocal port_cfg
        if not isinstance(port_cfg["uplink_ports"], PortList):
            return False, None

        lag_port = next(
            (lp for lp in (port_cfg["uplink_ports"] + port_cfg.get("downlink_ports", []))
             if isinstance(lp, LagPort) and port_id in lp), None)
        return (lag_port is not None, lag_port)

    dut_role_cfg = roles_cfg[role]
    port_cfg = hw_port_cfg[port_cfg_type]

    if port_cfg.get("link_based", False):
        return generate_topo_link_based(role, panel_port_count, port_cfg_type)

    vm_list = []
    downlinkif_list = []
    uplinkif_list = []
    disabled_hostif_list = []
    per_role_vm_count = defaultdict(lambda: 0)
    lag_port_assigned = set()
    tornum = 1
    link_id_start = 0

    for panel_port_id in list(range(0, panel_port_count, port_cfg['panel_port_step'])) + peer_ports:
        vm_role_cfg = None
        link_step = 1
        link_type = None

        if panel_port_id in uplink_ports:
            if dut_role_cfg["uplink"] is None:
                raise ValueError(
                    "Uplink port specified for a role that doesn't have an uplink")

            vm_role_cfg = dut_role_cfg["uplink"]

            link_id_end = link_id_start + port_cfg['us_breakout']
            num_breakout = port_cfg['us_breakout']
            link_step = port_cfg['us_link_step']
            link_type = 'up'
        elif panel_port_id in peer_ports:
            if dut_role_cfg["peer"] is None:
                raise ValueError(
                    "Peer port specified for a role that doesn't have a peer")

            vm_role_cfg = dut_role_cfg["peer"]

            link_id_end = link_id_start + 1
            link_step = 1
            link_type = 'peer'
        elif panel_port_id in port_cfg.get("fabric_ports", []):
            vm_role_cfg = dut_role_cfg["fabric"]

            link_id_end = link_id_start + port_cfg.get("fabric_breakout", 1)
            link_step = 1
            link_type = 'fabric'
        else:
            # If downlink is not specified, we consider it is host interface
            if dut_role_cfg["downlink"] is not None:
                vm_role_cfg = dut_role_cfg["downlink"]

            link_id_end = link_id_start + port_cfg['ds_breakout']
            num_breakout = port_cfg['ds_breakout']
            link_step = port_cfg['ds_link_step']
            link_type = 'down'

        is_lag_port, lag_port = _find_lag_port(panel_port_id)

        if panel_port_id in lag_port_assigned:
            continue

        if is_lag_port:
            per_role_vm_count[vm_role_cfg["role"]] += 1
            end_vlan_range = link_id_start + len(lag_port) * num_breakout

            vm_role_cfg["asn"] += vm_role_cfg.get("asn_increment", 1)
            vm_role_cfg["asn_v6"] += vm_role_cfg.get("asn_increment", 1)
            vm = VM(list(range(link_id_start, end_vlan_range)), len(vm_list),
                    per_role_vm_count[vm_role_cfg["role"]], tornum,
                    dut_role_cfg["asn"], dut_role_cfg["asn_v6"], vm_role_cfg, link_id_start,
                    num_lags=len(lag_port) * num_breakout)

            vm_list.append(vm)

            if link_type == 'up':
                uplinkif_list.append(link_id_start)
            elif link_type == 'down':
                tornum += 1
                downlinkif_list.append(link_id_start)

            lag_port_assigned.update(lag_port)

            link_id_start = end_vlan_range
            continue

        for link_id in range(link_id_start, link_id_end):
            vm = None
            hostif = None

            # Create the VM or host interface based on the configuration
            if vm_role_cfg is not None:
                if not port_cfg.get('continuous_vms', False):  # the VM id is per-link basis if setting is False
                    per_role_vm_count[vm_role_cfg["role"]] += 1

                if (link_id - link_id_start) % link_step == 0 and panel_port_id not in skip_ports:
                    # Skip breakout if defined
                    if panel_port_id in skip_ports:
                        continue

                    if port_cfg.get('continuous_vms', False):  # the VM id is continuous if setting is true
                        per_role_vm_count[vm_role_cfg["role"]] += 1

                    vm_role_cfg["asn"] += vm_role_cfg.get("asn_increment", 1)
                    vm_role_cfg["asn_v6"] += vm_role_cfg.get("asn_increment", 1)
                    vm = VM([link_id], len(vm_list), per_role_vm_count[vm_role_cfg["role"]], tornum,
                            dut_role_cfg["asn"], dut_role_cfg["asn_v6"], vm_role_cfg, link_id,
                            num_lags=vm_role_cfg.get('num_lags', 0))
                    vm_list.append(vm)
                    if link_type == 'up':
                        uplinkif_list.append(link_id)
                    elif link_type == 'down':
                        tornum += 1
                        downlinkif_list.append(link_id)
            else:
                if ((link_id - link_id_start) % link_step == 0
                        and panel_port_id not in skip_ports
                        and link_id not in port_cfg.get("skip_links", [])):
                    hostif = HostInterface(link_id)
                    downlinkif_list.append(hostif)
                elif (panel_port_id in skip_ports) or (link_id in port_cfg.get("skip_links", [])):
                    hostif = HostInterface(link_id)
                    disabled_hostif_list.append(hostif)
        link_id_start = link_id_end

    return vm_list, downlinkif_list, uplinkif_list, disabled_hostif_list


def generate_vlan_groups(hostif_list: List[HostInterface]) -> List[VlanGroup]:
    if len(hostif_list) == 0:
        return []

    vlan_groups = []
    for vlan_group_cfg in vlan_group_cfgs:
        vlan_group = VlanGroup(vlan_group_cfg["name"], vlan_group_cfg["vlan_count"], hostif_list,
                               vlan_group_cfg["v4_prefix"], vlan_group_cfg["v6_prefix"])
        vlan_groups.append(vlan_group)

    return vlan_groups


def generate_topo_file(role: str,
                       template_file: str,
                       vm_list: List[VM],
                       hostif_list: List[HostInterface],
                       disabled_hostif_list: List[HostInterface],
                       vlan_group_list: List[VlanGroup]
                       ) -> str:

    with open(template_file) as f:
        template = jinja2.Template(f.read())

    output = template.render(role=role,
                             dut=roles_cfg[role],
                             vm_list=vm_list,
                             hostif_list=hostif_list,
                             disabled_hostif_list=disabled_hostif_list,
                             vlan_group_list=vlan_group_list)

    return output


def write_topo_file(role: str,
                    keyword: str,
                    downlink_port_count: int,
                    uplink_port_count: int,
                    peer_port_count: int,
                    suffix: str,
                    file_content: str):
    downlink_keyword = f"d{downlink_port_count}" if downlink_port_count > 0 else ""
    uplink_keyword = f"u{uplink_port_count}" if uplink_port_count > 0 else ""
    peer_keyword = f"s{peer_port_count}" if peer_port_count > 0 else ""

    if keyword != "":
        file_path = f"vars/topo_{role}-{keyword}-{downlink_keyword}{uplink_keyword}{peer_keyword}{suffix}.yml"
    else:
        file_path = f"vars/topo_{role}-{downlink_keyword}{uplink_keyword}{peer_keyword}{suffix}.yml"

    if role in overwrite_file_name and keyword in overwrite_file_name[role]:
        file_path = f"vars/topo_{overwrite_file_name[role][keyword]}.yml"

    with open(file_path, "w") as f:
        f.write(file_content)

    print(f"Generated topology file: {file_path}")


@click.command()
@click.option("--role", "-r", required=True, type=click.Choice(['t0', 't1', 'lt2']), help="Role of the device")
@click.option("--keyword", "-k", required=False, type=str, default="", help="Keyword for the topology file")
@click.option("--template", "-t", required=True, type=str, help="Path to the Jinja template file")
@click.option("--port-count", "-c", required=True, type=int, help="Number of physical ports used on the device")
@click.option("--uplinks", "-u", required=False, type=str, default="", help="Comma-separated list of uplink ports")
@click.option("--peers", "-p", required=False, type=str, default="", help="Comma-separated list of peer ports")
@click.option("--link-cfg", "-l", required=False, type=str, default="default", help="hw port/link configuration")
@click.option("--skips", "-s", required=False, type=str, default="", help="skip physical port list")
def main(role: str, keyword: str, template: str, port_count: int, uplinks: str, peers: str, link_cfg: str, skips: str):
    """
    Generate a topology file for a device:

    \b
    Examples (in the ansible directory):
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 128
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -p 64,65 -l 'c256'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -p 64,65 -l 'c256-sparse'
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -u 12,16,44,48 -l 'c224o8'
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -u 12,16,44,48 -l 'c224o8-sparse' -s 16,44,48
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -u 25,26,27,28,29,30,31,32 -l 'o128'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -l 'o128t0'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -l 'c256'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -l 'c256-sparse'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -p 64 -l 'c256-sparse'
    - ./generate_topo.py -r t1 -k isolated-v6 -t t1-isolated-v6 -c 64 -l 'c224o8'
    - ./generate_topo.py -r t1 -k isolated-v6 -t t1-isolated-v6 -c 64 -l 'c224o8-sparse'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -l 'o128t0'
    - ./generate_topo.py -r t1 -k isolated-v6 -t t1-isolated-v6 -c 64 -l 'o128t1'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -l 'c512s2'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -l 'c512s2-sparse'
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -l 'c448o16-lag'
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -l 'c448o16-lag-sparse'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -l 'c512s2'
    - ./generate_topo.py -r t0 -k isolated-v6 -t t0-isolated-v6 -c 64 -l 'c512s2-sparse'
    - ./generate_topo.py -r t1 -k isolated-v6 -t t1-isolated-v6 -c 64 -l 'c448o16-lag'
    - ./generate_topo.py -r t1 -k isolated-v6 -t t1-isolated-v6 -c 64 -l 'c448o16-lag-sparse'
    - ./generate_topo.py -r lt2 -k o128 -t lt2_128 -c 64 -l 'o128lt2'
    - ./generate_topo.py -r lt2 -k p32o64 -t lt2_p32o64 -c 64 -l 'p32o64lt2'
    - ./generate_topo.py -r t0 -k f2 -t t0 -c 64 -l 'p32v128f2'
    - ./generate_topo.py -r t1 -k f2 -t t1 -c 64 -l 'p32o64f2'
    """
    uplink_ports = [int(port) for port in uplinks.split(",")] if uplinks != "" else \
        hw_port_cfg[link_cfg]['uplink_ports']
    peer_ports = [int(port) for port in peers.split(
        ",")] if peers != "" else hw_port_cfg[link_cfg]['peer_ports']
    skip_ports = [int(port) for port in skips.split(
        ",")] if skips != "" else hw_port_cfg[link_cfg]['skip_ports']

    vm_list, downlinkif_list, uplinkif_list, disabled_hostif_list = \
        generate_topo(role, port_count, uplink_ports, peer_ports, skip_ports, link_cfg)
    vlan_group_list = []
    if role == "t0":
        vlan_group_list = generate_vlan_groups(downlinkif_list)
    file_content = generate_topo_file(
        role, f"templates/topo_{template}.j2", vm_list, downlinkif_list, disabled_hostif_list, vlan_group_list)
    write_topo_file(role, keyword, len(downlinkif_list), len(uplinkif_list),
                    len(peer_ports), '-lag' if 'lag' in link_cfg else '',
                    file_content)


if __name__ == "__main__":
    main()
