#!/usr/bin/env python3

from typing import Any, Dict, List
import ipaddress
import click
import jinja2

# Define the roles for the devices in the topology
roles_cfg = {
    "t0": {
        "asn": 64601,
        "downlink": None,
        "uplink": {"role": "t1", "asn": 64802},
        "peer": {"role": "pt0", "asn": 64601},
    },
    "t1": {
        "asn": 65100,
        "downlink": {"role": "t0", "asn": 64002},
        "uplink": {"role": "t2", "asn": 65200},
        "peer": None,
    },
    "pt0": {},
}


# Utility functions to calculate IP addresses
def calc_ipv4_pair(subnet_str, port_id):
    subnet = ipaddress.IPv4Network(subnet_str)
    return (str(subnet.network_address + 2*port_id), str(subnet.network_address + 2*port_id + 1))


def calc_ipv6_pair(subnet_str, port_id):
    subnet = ipaddress.IPv6Network(subnet_str)
    return (str(subnet.network_address + 4*port_id+1), str(subnet.network_address + 4*port_id + 2))


def calc_ipv4(subnet_str, port_id):
    subnet = ipaddress.IPv4Network(subnet_str)
    return str(subnet.network_address + port_id)


def calc_ipv6(subnet_str, port_id):
    subnet = ipaddress.IPv6Network(subnet_str)
    return str(subnet.network_address + port_id)


class VM:
    """ Class to represent a VM in the topology """
    def __init__(self,
                 port_id: int,
                 vm_id: int,
                 name_id: int,
                 dut_asn: int,
                 role_cfg: Dict[str, Any],
                 ip_offset: int = None):

        self.role = role_cfg["role"]

        # IDs of the VM
        self.port_id = port_id
        self.vm_offset = vm_id
        self.ip_offset = vm_id if ip_offset is None else ip_offset
        self.name = f"ARISTA{name_id:02d}{self.role.upper()}"

        # VLAN configuration
        self.vlans = [port_id]

        # BGP configuration
        self.asn = role_cfg["asn"]
        self.peer_asn = dut_asn

        # IP addresses
        self.dut_intf_ipv4, self.pc_intf_ipv4 = calc_ipv4_pair("10.0.0.0", self.ip_offset)
        self.dut_intf_ipv6, self.pc_intf_ipv6 = calc_ipv6_pair("FC00::", self.ip_offset)
        self.loopback_ipv4 = calc_ipv4("100.1.0.0", self.ip_offset+1)
        self.loopback_ipv6 = calc_ipv6("2064:100::", self.ip_offset+1)

        # Backplane IPs will go with the VM ID
        self.bp_ipv4 = calc_ipv4("10.10.246.1", self.vm_offset+1)
        self.bp_ipv6 = calc_ipv6("fc0a::1", (self.vm_offset+1))


class HostInterface:
    """ Class to represent a host interface in the topology """
    def __init__(self, port_id: int):
        self.port_id = port_id


def generate_topo(role: str, port_count: int, uplink_ports: List[int], peer_ports: List[int]):
    role_cfg = roles_cfg[role]

    vm_list = []
    hostif_list = []
    per_role_vm_count = {key: 0 for key in roles_cfg}
    for port_id in range(0, port_count):
        vm = None
        hostif = None

        if port_id in uplink_ports:
            if role_cfg["uplink"] is None:
                raise ValueError("Uplink port specified for a role that doesn't have an uplink")

            vm = VM(port_id, len(vm_list), per_role_vm_count[role_cfg["uplink"]["role"]] + 1,
                    role_cfg["asn"], role_cfg["uplink"])

        elif port_id in peer_ports:
            if role_cfg["peer"] is None:
                raise ValueError("Peer port specified for a role that doesn't have a peer")

            vm = VM(port_id, len(vm_list), per_role_vm_count[role_cfg["peer"]["role"]] + 1,
                    role_cfg["asn"], role_cfg["peer"])

        else:
            if role_cfg["downlink"] is None:
                hostif = HostInterface(port_id)
            else:
                vm = VM(port_id, len(vm_list), per_role_vm_count[role_cfg["downlink"]["role"]] + 1,
                        role_cfg["asn"], role_cfg["downlink"])

        if vm is not None:
            vm_list.append(vm)
            per_role_vm_count[vm.role] += 1

        if hostif is not None:
            hostif_list.append(hostif)

    return vm_list, hostif_list


def generate_topo_file_content(role: str,
                               template_file: str,
                               vm_list: List[VM],
                               hostif_list: List[HostInterface]):

    with open(template_file) as f:
        template = jinja2.Template(f.read())

    output = template.render(role=role,
                             vm_list=vm_list,
                             hostif_list=hostif_list)

    return output


def output_topo_file(role: str,
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
@click.option("--role", "-r", required=True, type=click.Choice(['t1']), help="Role of the device")
@click.option("--keyword", "-k", required=True, type=str, help="Keyword for the topology file")
@click.option("--template", "-t", required=True, type=str, help="Path to the Jinja template file")
@click.option("--port-count", "-c", required=True, type=int, help="Number of ports on the device")
@click.option("--uplinks", "-u", required=False, type=str, default="", help="Comma-separated list of uplink ports")
@click.option("--peers", "-p", required=False, type=str, default="", help="Comma-separated list of peer ports")
def main(role: str, keyword: str, template: str, port_count: int, uplinks: str, peers: str):
    """
    Generate a topology file for a device:

    Example (in the ansible directory):
    - ./generate_topo.py -r t1 -k isolated -t t1 -c 128
    - ./generate_topo.py -r t1 -k uplink -t t1 -c 130 -u 0,1 -p 128,129
    """
    uplink_ports = [int(port) for port in uplinks.split(",")] if uplinks != "" else []
    peer_ports = [int(port) for port in peers.split(",")] if peers != "" else []

    vm_list, hostif_list = generate_topo(role, port_count, uplink_ports, peer_ports)
    file_content = generate_topo_file_content(role, f"templates/topo_{template}.j2", vm_list, hostif_list)
    output_topo_file(role, keyword, port_count - len(uplink_ports) - len(peer_ports), len(uplink_ports),
                     len(peer_ports), file_content)


if __name__ == "__main__":
    main()
