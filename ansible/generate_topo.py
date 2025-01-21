#!/usr/bin/env python3

import copy
from typing import Any, Dict, List, Tuple
from ipaddress import IPv4Network, IPv6Network
import click
import jinja2

# Define the roles for the devices in the topology
roles_cfg = {
    "t0": {
        "asn": 65100,
        "downlink": None,
        "uplink": {"role": "t1", "asn": 64600},
        "peer": {"role": "pt0", "asn": 65100},
    },
    "t1": {
        "asn": 65100,
        "downlink": {"role": "t0", "asn": 64000},
        "uplink": {"role": "t2", "asn": 65200},
        "peer": None,
    },
}

hw_port_cfg = {
    'default':          {"ds_breakout": 1, "us_breakout": 1, "ds_link_step": 1, "us_link_step": 1,
                         "panel_port_step": 1},
    'c256':             {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 1, "us_link_step": 1,
                         "panel_port_step": 2},
    'c224o8':           {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         "panel_port_step": 2},
    'o128':             {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 1,
                         "panel_port_step": 1},
    'c256-sparse':      {"ds_breakout": 8, "us_breakout": 8, "ds_link_step": 8, "us_link_step": 8,
                         "panel_port_step": 2},
    'c224o8-sparse':    {"ds_breakout": 8, "us_breakout": 2, "ds_link_step": 8, "us_link_step": 2,
                         "panel_port_step": 2},
    'o128-sparse':      {"ds_breakout": 2, "us_breakout": 2, "ds_link_step": 1, "us_link_step": 2,
                         "panel_port_step": 1},
}

vlan_group_cfgs = [
    {"name": "one_vlan_a", "vlan_count": 1, "v4_prefix": "192.168.0.0/21", "v6_prefix": "fc02:1000::0/64"},
    {"name": "two_vlan_a", "vlan_count": 2, "v4_prefix": "192.168.0.0/22", "v6_prefix": "fc02:100::0/64"},
    {"name": "four_vlan_a", "vlan_count": 4, "v4_prefix": "192.168.0.0/22", "v6_prefix": "fc02:100::0/64"},
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
                 dut_asn: int,
                 role_cfg: Dict[str, Any],
                 ip_offset: int = None):

        self.role = role_cfg["role"]

        # IDs of the VM
        self.link_id = link_id
        self.vm_offset = vm_id
        self.ip_offset = vm_id if ip_offset is None else ip_offset
        self.name = f"ARISTA{name_id:02d}{self.role.upper()}"

        # VLAN configuration
        self.vlans = [link_id]

        # BGP configuration
        self.asn = role_cfg["asn"]
        self.peer_asn = dut_asn

        # IP addresses
        self.dut_intf_ipv4, self.pc_intf_ipv4 = calc_ipv4_pair("10.0.0.0", self.ip_offset)
        self.dut_intf_ipv6, self.pc_intf_ipv6 = calc_ipv6_pair("FC00::", self.ip_offset)
        self.loopback_ipv4 = calc_ipv4("100.1.0.0", self.ip_offset+1)
        self.loopback_ipv6 = calc_ipv6("2064:100::", (self.ip_offset+1) * 2**64)

        # Backplane IPs
        self.bp_ipv4 = calc_ipv4("10.10.246.1", self.ip_offset+1)
        self.bp_ipv6 = calc_ipv6("fc0a::1", (self.ip_offset+1))


class HostInterface:
    """ Class to represent a host interface in the topology """
    def __init__(self, port_id: int):
        self.port_id = port_id


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
        hostif_groups = [hostifs[i*hostif_count_per_vlan:(i+1)*hostif_count_per_vlan] for i in range(vlan_count)]

        v4_prefix = IPv4Network(v4_prefix)
        v6_prefix = IPv6Network(v6_prefix)
        for vlan_index in range(len(hostif_groups)):
            vlan = Vlan(1000 + vlan_index * 100, hostif_groups[vlan_index], v4_prefix, v6_prefix)
            self.vlans.append(vlan)

            # Move to next subnet based on the prefix length
            v4_prefix.network_address += 2**(32 - v4_prefix.prefixlen)
            v6_prefix.network_address += 2**96


def generate_topo(role: str,
                  panel_port_count: int,
                  uplink_ports: List[int],
                  peer_ports: List[int],
                  skip_ports: List[int],
                  port_cfg_type: str = "default",
                  ) -> Tuple[List[VM], List[HostInterface]]:

    dut_role_cfg = roles_cfg[role]
    port_cfg = hw_port_cfg[port_cfg_type]

    vm_list = []
    downlinkif_list = []
    uplinkif_list = []
    per_role_vm_count = {}
    link_id_start = 0
    for panel_port_id in list(range(0, panel_port_count, port_cfg['panel_port_step'])) + peer_ports:
        vm_role_cfg = None
        link_step = 1
        link_type = None
        if panel_port_id in uplink_ports:
            if dut_role_cfg["uplink"] is None:
                raise ValueError("Uplink port specified for a role that doesn't have an uplink")

            vm_role_cfg = dut_role_cfg["uplink"]

            link_id_end = link_id_start + port_cfg['us_breakout']
            link_step = port_cfg['us_link_step']
            link_type = 'up'
        elif panel_port_id in peer_ports:
            if dut_role_cfg["peer"] is None:
                raise ValueError("Peer port specified for a role that doesn't have a peer")

            vm_role_cfg = dut_role_cfg["peer"]

            link_id_end = link_id_start + 1
            link_step = 1
            link_type = 'peer'
        else:
            # If downlink is not specified, we consider it is host interface
            if dut_role_cfg["downlink"] is not None:
                vm_role_cfg = dut_role_cfg["downlink"]
                vm_role_cfg["asn"] += 1

            link_id_end = link_id_start + port_cfg['ds_breakout']
            link_step = port_cfg['ds_link_step']
            link_type = 'down'

        for link_id in range(link_id_start, link_id_end):
            vm = None
            hostif = None

            # Create the VM or host interface based on the configuration
            if vm_role_cfg is not None:
                if vm_role_cfg["role"] not in per_role_vm_count:
                    per_role_vm_count[vm_role_cfg["role"]] = 0
                per_role_vm_count[vm_role_cfg["role"]] += 1

                if link_id % link_step == 0 and panel_port_id not in skip_ports:
                    vm = VM(link_id, len(vm_list), per_role_vm_count[vm_role_cfg["role"]],
                            dut_role_cfg["asn"], vm_role_cfg, link_id)
                    vm_list.append(vm)
                    if link_type == 'up':
                        uplinkif_list.append(link_id)
                    elif link_type == 'down':
                        downlinkif_list.append(link_id)
            else:
                if link_id % link_step == 0 and panel_port_id not in skip_ports:
                    hostif = HostInterface(link_id)
                    downlinkif_list.append(hostif)
        print(panel_port_id, link_id_start, link_id_end, link_step, vm_role_cfg)
        link_id_start = link_id_end

    return vm_list, downlinkif_list, uplinkif_list


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
                       vlan_group_list: List[VlanGroup]
                       ) -> str:

    with open(template_file) as f:
        template = jinja2.Template(f.read())

    output = template.render(role=role,
                             dut=roles_cfg[role],
                             vm_list=vm_list,
                             hostif_list=hostif_list,
                             vlan_group_list=vlan_group_list)

    return output


def write_topo_file(role: str,
                    keyword: str,
                    downlink_port_count: int,
                    uplink_port_count: int,
                    peer_port_count: int,
                    file_content: str):
    downlink_keyword = f"d{downlink_port_count}" if downlink_port_count > 0 else ""
    uplink_keyword = f"u{uplink_port_count}" if uplink_port_count > 0 else ""
    peer_keyword = f"s{peer_port_count}" if peer_port_count > 0 else ""

    file_path = f"vars/topo_{role}-{keyword}-{downlink_keyword}{uplink_keyword}{peer_keyword}.yml"

    with open(file_path, "w") as f:
        f.write(file_content)

    print(f"Generated topology file: {file_path}")


@click.command()
@click.option("--role", "-r", required=True, type=click.Choice(['t0', 't1']), help="Role of the device")
@click.option("--keyword", "-k", required=True, type=str, help="Keyword for the topology file")
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
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -u 12,16,44,48 -l 'c224o8'
    - ./generate_topo.py -r t1 -k isolated -t t1-isolated -c 64 -u 12,16,44,48 -l 'c224o8-sparse' -s 16,44,48
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -u 25,26,27,28,29,30,31,32 -l 'o128'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -u 8,10,12,14,16,18,20,22,40,42,44,46,48,50,52,54 \
        -p 64,65 -l 'c256'
    - ./generate_topo.py -r t0 -k isolated -t t0-isolated -c 64 -u 8,10,12,14,16,18,20,22,40,42,44,46,48,50,52,54 \
        -p 64,65 -l 'c256-sparse'
    """
    uplink_ports = [int(port) for port in uplinks.split(",")] if uplinks != "" else []
    peer_ports = [int(port) for port in peers.split(",")] if peers != "" else []
    skip_ports = [int(port) for port in skips.split(",")] if skips != "" else []

    vm_list, downlinkif_list, uplinkif_list = generate_topo(role, port_count, uplink_ports, peer_ports,
                                                            skip_ports, link_cfg)
    vlan_group_list = []
    if role == "t0":
        vlan_group_list = generate_vlan_groups(downlinkif_list)
    file_content = generate_topo_file(role, f"templates/topo_{template}.j2", vm_list, downlinkif_list, vlan_group_list)
    write_topo_file(role, keyword, len(downlinkif_list), len(uplinkif_list),
                    len(peer_ports), file_content)


if __name__ == "__main__":
    main()
