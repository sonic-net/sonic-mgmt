"""Common dualtor related utilities."""
import ipaddress
import re


def get_intf_index(intf):
    """Get interface index."""
    if isinstance(intf, str):
        intf = intf.split(",")[0]
        return tuple(map(int, re.split(r'\.|@', intf.strip())))[1]
    else:
        return intf


def generate_mux_cable_facts(topology):
    """Generate mux cable table facts for dualtor topology."""
    mux_cable_facts = {}
    host_interfaces = set(get_intf_index(_) for _ in topology.get("host_interfaces", []))
    disabled_host_interfaces = set(get_intf_index(_) for _ in topology.get("disabled_host_interfaces", []))
    host_interfaces_active_active = set(get_intf_index(_) for _ in topology.get("host_interfaces_active_active", []))
    enabled_interfaces = sorted(list(host_interfaces - disabled_host_interfaces))

    vlan_config = list(topology["DUT"]["vlan_configs"][topology["DUT"]["vlan_configs"]["default_vlan_config"]].values())[0]
    # NOTE: vlan prefix will be 192.168.0.1/21 and fc02:1000::1/64
    vlan_prefix_v4 = vlan_config["prefix"]
    vlan_prefix_v6 = vlan_config["prefix_v6"]
    vlan_address_v4, netmask_v4 = vlan_prefix_v4.split("/")
    vlan_address_v6, netmask_v6 = vlan_prefix_v6.split("/")
    vlan_address_v4 = ipaddress.ip_address(vlan_address_v4.decode())
    vlan_address_v6 = ipaddress.ip_address(vlan_address_v6.decode())
    for index, intf in enumerate(enabled_interfaces):
        if host_interfaces_active_active:
            is_active_active = intf in host_interfaces_active_active
            # server IPs should be even-numbered
            mux_cable_facts[intf] = dict(
                server_ipv4=str(vlan_address_v4 + index * 2 + 1) + "/" + netmask_v4,
                server_ipv6=str(vlan_address_v6 + index * 2 + 1) + "/" + netmask_v6,
                cable_type="active-standby"
            )
            if is_active_active:
                mux_cable_facts[intf]["cable_type"] = "active-active"
                # SoC IPs should be odd-numbered
                mux_cable_facts[intf]["soc_ipv4"] = str(vlan_address_v4 + (index + 1) * 2) + "/" + netmask_v4
        else:
            mux_cable_facts[intf] = dict(
                server_ipv4=str(vlan_address_v4 + index + 1) + "/" + netmask_v4,
                server_ipv6=str(vlan_address_v6 + index + 1) + "/" + netmask_v6,
                cable_type="active-standby"
            )

    return mux_cable_facts
