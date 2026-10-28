"""Exercise converged backplane allocation without a physical testbed."""

import importlib.util
from ipaddress import ip_address, ip_interface
from pathlib import Path

import pytest
import yaml


ANSIBLE_DIR = Path(__file__).resolve().parents[4] / "ansible"


@pytest.fixture(scope="module")
def converger_class():
    spec = importlib.util.spec_from_file_location(
        "ceos_topo_converger", ANSIBLE_DIR / "ceos_topo_converger.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SonicTopoConverger


def _converge(converger_class, topology):
    converger = converger_class(topology, "unused")
    converger.parse_properties()
    converger.converge_topo()
    return converger.converged_topo["convergence_data"]


def _assert_no_backplane_conflicts(data, reserved_addresses):
    allocated = set()
    for prime in data["converged_peers"].values():
        for peer, interfaces in prime["vrf"].items():
            ptf_addresses = data["ptf_backplane_addrs"][peer]
            svi = interfaces[f"Vlan{ptf_addresses['vlan']}"]
            for family in ("ipv4", "ipv6"):
                if family not in ptf_addresses:
                    continue
                ptf = ip_interface(ptf_addresses[family])
                ceos = ip_interface(svi[family])
                assert ptf.network == ceos.network
                assert ptf.ip != ceos.ip
                for address in (ptf.ip, ceos.ip):
                    assert address not in reserved_addresses
                    assert address not in allocated
                    allocated.add(address)


@pytest.mark.parametrize("topology_name", [
    "lt2-o128", "lt2-p32o64", "lt2-u32d128", "t1-isolated-v6-d128",
])
def test_converged_backplanes_avoid_legacy_ptf_addresses(converger_class, topology_name):
    """Keep both ends of each VRF link distinct from the legacy PTF next hops."""
    topology = yaml.safe_load(
        (ANSIBLE_DIR / "vars" / f"topo_{topology_name}.yml").read_text(encoding="utf-8"))
    common = topology["configuration_properties"]["common"]
    reserved = {ip_address(common[key]) for key in ("nhipv4", "nhipv6") if key in common}

    data = _converge(converger_class, topology)

    _assert_no_backplane_conflicts(data, reserved)


def test_converged_backplanes_skip_consecutive_reserved_pairs(converger_class):
    """Honor configured addresses on either endpoint and in either address family."""
    topology = yaml.safe_load(
        (ANSIBLE_DIR / "vars" / "topo_lt2-p32o64.yml").read_text(encoding="utf-8"))
    common = topology["configuration_properties"]["common"]
    for key in ("nhipv4", "nhipv6"):
        common.pop(key)
    original = _converge(converger_class, topology)
    first, second = list(original["ptf_backplane_addrs"].values())[:2]
    common["nhipv4"] = str(ip_interface(first["ipv4"]).ip)
    common["nhipv6"] = str(ip_interface(second["ipv6"]).network.network_address)
    reserved = {ip_address(common[key]) for key in ("nhipv4", "nhipv6")}

    data = _converge(converger_class, topology)

    _assert_no_backplane_conflicts(data, reserved)
