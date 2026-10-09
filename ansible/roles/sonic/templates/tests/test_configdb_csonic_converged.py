"""Unit tests for the converged cSONiC CONFIG_DB renderer."""

import ipaddress
import json
import os

from jinja2 import Environment, FileSystemLoader, StrictUndefined


TEMPLATES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_NAME = "configdb-csonic-converged.j2"


def _context():
    peers = ("ARISTA01T1", "ARISTA02T1")
    configuration = {
        "ARISTA01T1": {
            "bgp": {"asn": 64600, "peers": {65100: ["10.0.0.56", "fc00::71"]}},
            "bp_interface": {"ipv4": "10.10.246.29/24", "ipv6": "fc0a::1d/64"},
        },
        "ARISTA02T1": {
            "bgp": {
                "asn": 64601,
                "router-id": "9.9.9.9",
                "peers": {65100: ["10.0.0.58", "fc00::75"]},
            },
        },
    }
    converged_vrfs = {
        "ARISTA01T1": {
            "Vlan2000": {"ipv4": "10.10.246.100/31", "ipv6": "fc0a::64/127"},
            "Ethernet1": {"lacp": 1},
            "Port-Channel1": {"ipv4": "10.0.0.57/31", "ipv6": "fc00::72/126"},
            "Loopback1": {"ipv4": "100.1.0.29/32", "ipv6": "2064:100::1d/128"},
        },
        "ARISTA02T1": {
            "Vlan2001": {"ipv4": "10.10.246.102/31", "ipv6": "fc0a::66/127"},
            "Ethernet2": {"lacp": 2},
            "Port-Channel2": {"ipv4": "10.0.0.59/31", "ipv6": "fc00::76/126"},
            "Loopback2": {"ipv4": "100.1.0.30/32", "ipv6": "2064:100::1e/128"},
        },
    }
    return {
        "hostname": "ARISTA01T1",
        "configuration": configuration,
        "topology": {"VMs": {"ARISTA01T1": {"vlans": [28, 29]}}},
        "convergence_data": {
            "converged_peers": {
                "ARISTA01T1": {
                    "bgp": {"asn": 64600},
                    "vrf": converged_vrfs,
                },
            },
            "convergence_mapping": {"ARISTA01T1": list(peers)},
            "vrf_name_mapping": {
                "ARISTA01T1": "VrfARISTA01T1",
                "ARISTA02T1": "VrfARISTA02T1",
            },
            "ptf_backplane_addrs": {
                "ARISTA01T1": {"ipv4": "10.10.246.101/31", "ipv6": "fc0a::65/127", "vlan": 2000},
                "ARISTA02T1": {"ipv4": "10.10.246.103/31", "ipv6": "fc0a::67/127", "vlan": 2001},
            },
        },
        "props": {"swrole": "leaf"},
        "snmp_rocommunity": "strcommunity",
    }


def _render_json(context=None):
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        undefined=StrictUndefined,
    )
    env.filters["ansible.utils.ipaddr"] = lambda value, query: (
        str(ipaddress.ip_interface(value).network) if query == "subnet" else value
    )
    rendered = env.get_template(TEMPLATE_NAME).render(**(context or _context()))
    return json.loads(rendered)


def test_renders_flattened_vrfs_and_backplane_trunk():
    cfg = _render_json()
    assert set(cfg["VRF"]) == {"VrfARISTA01T1", "VrfARISTA02T1"}
    assert set(cfg["PORT"]) == {"Ethernet1", "Ethernet2", "Ethernet3"}
    assert cfg["PORT"]["Ethernet3"]["lanes"] == "33,34,35,36"
    assert cfg["PORTCHANNEL_INTERFACE"]["PortChannel2"] == {"vrf_name": "VrfARISTA02T1"}
    assert cfg["PORTCHANNEL_MEMBER"]["PortChannel2|Ethernet2"] == {}
    assert cfg["VLAN_INTERFACE"]["Vlan2001"] == {"vrf_name": "VrfARISTA02T1"}
    assert cfg["VLAN_MEMBER"]["Vlan2001|Ethernet3"] == {"tagging_mode": "tagged"}
    assert cfg["VLAN_INTERFACE"]["Vlan1"] == {"vrf_name": "VrfARISTA01T1"}
    assert cfg["VLAN_INTERFACE"]["Vlan1|10.10.246.29/24"] == {}
    assert cfg["VLAN_MEMBER"]["Vlan1|Ethernet3"] == {"tagging_mode": "untagged"}
    assert cfg["BGP_GLOBALS_AF_NETWORK"][
        "VrfARISTA01T1|ipv4_unicast|10.10.246.0/24"] == {}


def test_t0_backplane_uses_canonical_sonic_vm_eth5_lanes():
    context = _context()
    mapping = context["convergence_data"]["convergence_mapping"]["ARISTA01T1"]
    vrfs = context["convergence_data"]["converged_peers"]["ARISTA01T1"]["vrf"]
    vrf_names = context["convergence_data"]["vrf_name_mapping"]
    ptf = context["convergence_data"]["ptf_backplane_addrs"]
    for index in (3, 4):
        logical = "ARISTA0{}T1".format(index)
        mapping.append(logical)
        context["configuration"][logical] = {
            "bgp": {"asn": 64600, "peers": {65100: ["10.0.0.{}".format(54 + index * 2)]}},
        }
        vrfs[logical] = {
            "Vlan200{}".format(index - 1): {"ipv4": "10.10.246.{}/31".format(96 + index * 2)},
            "Ethernet{}".format(index): {"ipv4": "10.0.0.{}/31".format(55 + index * 2)},
            "Loopback{}".format(index): {"ipv4": "100.1.0.{}/32".format(28 + index)},
        }
        vrf_names[logical] = "Vrf{}".format(logical)
        ptf[logical] = {"ipv4": "10.10.246.{}/31".format(97 + index * 2), "vlan": 1999 + index}
    cfg = _render_json(context)
    assert cfg["PORT"]["Ethernet5"]["lanes"] == "45,46,47,48"


def test_enables_frrcfgd_and_builds_one_bgp_instance_per_vrf():
    cfg = _render_json()
    metadata = cfg["DEVICE_METADATA"]["localhost"]
    assert metadata["frr_mgmt_framework_config"] == "true"
    assert metadata["docker_routing_config_mode"] == "unified"
    assert metadata["use_template_render_for_restore"] == "false"
    assert cfg["BGP_GLOBALS"]["VrfARISTA01T1"]["local_asn"] == "64600"
    assert cfg["BGP_GLOBALS"]["VrfARISTA02T1"]["local_asn"] == "64601"
    assert cfg["BGP_GLOBALS"]["VrfARISTA02T1"]["router_id"] == "9.9.9.9"
    assert cfg["BGP_GLOBALS_AF_NETWORK"][
        "VrfARISTA02T1|ipv4_unicast|100.1.0.30/32"] == {}


def test_dut_and_exabgp_neighbors_are_vrf_scoped_and_activated():
    cfg = _render_json()
    dut = cfg["BGP_NEIGHBOR"]["VrfARISTA02T1|10.0.0.58"]
    assert dut["asn"] == "65100"
    assert "local_asn" not in dut
    exabgp = cfg["BGP_NEIGHBOR"]["VrfARISTA02T1|10.10.246.103"]
    assert exabgp["asn"] == "64601"
    assert "local_asn" not in exabgp
    assert exabgp["local_addr"] == "10.10.246.102"
    assert cfg["BGP_NEIGHBOR_AF"][
        "VrfARISTA02T1|fc00::75|ipv6_unicast"] == {
            "admin_status": "up", "nhself": "true"}
    assert cfg["BGP_NEIGHBOR_AF"][
        "VrfARISTA02T1|fc0a::67|ipv6_unicast"] == {"admin_status": "up"}


def test_can_disable_exabgp_route_generation():
    context = _context()
    context["props"]["enable_ipv4_routes_generation"] = False
    context["props"]["enable_ipv6_routes_generation"] = False
    cfg = _render_json(context)
    assert len(cfg["BGP_NEIGHBOR"]) == 4
    assert all("exabgp" not in value["name"] for value in cfg["BGP_NEIGHBOR"].values())


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
            print("PASS", name)
