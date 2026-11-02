"""Hardware-independent coverage for parent and per-VRF backplane allocation."""

import importlib.util
from ipaddress import ip_address, ip_interface
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


ANSIBLE_DIR = Path(__file__).resolve().parents[4] / "ansible"
SPEC = importlib.util.spec_from_file_location(
    "ceos_topo_converger", ANSIBLE_DIR / "ceos_topo_converger.py"
)
converger_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(converger_module)


@pytest.fixture
def topology():
    """Load enough peers to reach the default parent-backplane addresses."""
    return yaml.safe_load(
        (ANSIBLE_DIR / "vars" / "topo_lt2-u32d128.yml").read_text(encoding="utf-8")
    )


def _converge(topology, **kwargs):
    converger = converger_module.SonicTopoConverger(topology, "unused", **kwargs)
    converger.parse_properties()
    converger.converge_topo()
    return converger.converged_topo["convergence_data"]


def _assert_no_conflicts(data, reserved):
    allocated = set()
    for prime in data["converged_peers"].values():
        for name, interfaces in prime["vrf"].items():
            ptf = data["ptf_backplane_addrs"][name]
            ceos = interfaces[f"Vlan{ptf['vlan']}"]
            for family in ("ipv4", "ipv6"):
                endpoints = [ip_interface(config[family]) for config in (ptf, ceos)]
                assert endpoints[0].network == endpoints[1].network
                for endpoint in endpoints:
                    assert endpoint.ip not in reserved
                    assert endpoint.ip not in allocated
                    allocated.add(endpoint.ip)


@pytest.mark.parametrize("common", [
    {},
    {"nhipv4": "10.10.246.200", "nhipv6": "fc0a::c9"},
])
def test_parent_defaults_are_reserved_independently_of_common(topology, common):
    """Reserve parent defaults even if common next hops are omitted or different."""
    topology["configuration_properties"]["common"] = common
    data = _converge(topology)
    reserved = {ip_address("10.10.246.254"), ip_address("fc0a::ff")}
    reserved.update(ip_address(value) for value in common.values())
    _assert_no_conflicts(data, reserved)


def test_effective_parent_addresses_skip_consecutive_pairs(topology):
    """Honor CIDR deployment overrides on either end of consecutive address pairs."""
    parent_addresses = ["10.10.246.100/22", "fc0a::67/64"]
    data = _converge(topology, ptf_bp_addrs=parent_addresses)
    common = topology["configuration_properties"]["common"]
    reserved = {ip_interface(address).ip for address in parent_addresses}
    reserved.update(ip_address(common[key]) for key in ("nhipv4", "nhipv6"))
    _assert_no_conflicts(data, reserved)
    first = next(iter(data["ptf_backplane_addrs"].values()))
    assert first["ipv4"] == "10.10.246.105/31"
    assert first["ipv6"] == "fc0a::69/127"


@pytest.mark.parametrize("override_style", ["key-value", "vars-file"])
def test_testbed_cli_passes_effective_inventory_addresses(tmp_path, topology, override_style):
    """Use inventory overrides during convergence without connecting to any devices."""
    pytest.importorskip("ansible")
    ansible_dir = tmp_path / "ansible"
    ansible_dir.mkdir()
    for filename in ("testbed-cli.sh", "ceos_topo_converger.py"):
        shutil.copyfile(ANSIBLE_DIR / filename, ansible_dir / filename)
    defaults = ansible_dir / "group_vars" / "vm_host"
    defaults.mkdir(parents=True)
    shutil.copyfile(ANSIBLE_DIR / "group_vars" / "vm_host" / "main.yml", defaults / "main.yml")
    (ansible_dir / "vars").mkdir()
    topo_file = ansible_dir / "vars" / "topo_unit.yml"
    topo_file.write_text(yaml.safe_dump(topology), encoding="utf-8")
    (ansible_dir / "testbed.yaml").write_text(yaml.safe_dump([{
        "conf-name": "unit",
        "topo": "unit",
        "server": "server_1",
        "dut": ["unit_dut"],
        "use_converged_peers": True,
    }]), encoding="utf-8")
    (ansible_dir / "inventory.yml").write_text(yaml.safe_dump({
        "all": {"children": {
            "vm_host": {"hosts": {"unit_host": {
                "ptf_bp_ip": "10.10.246.202/22",
                "ptf_bp_ipv6": "fc0a::cb/64",
            }}},
            "server_1": {"hosts": {"unit_host": {}}},
        }},
    }), encoding="utf-8")
    (ansible_dir / "password").write_text("unused\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    playbook = bin_dir / "ansible-playbook"
    playbook.write_text("#!/bin/sh\ncp vars/topo_unit.yml captured.yml\n", encoding="utf-8")
    playbook.chmod(0o755)
    addresses = {"ptf_bp_ip": "10.10.246.100/22", "ptf_bp_ipv6": "fc0a::67/64"}
    if override_style == "key-value":
        extra_vars = ["-e", " ".join(f"{key}={value}" for key, value in addresses.items())]
    else:
        (ansible_dir / "override.yml").write_text(yaml.safe_dump(addresses), encoding="utf-8")
        extra_vars = ["--extra-vars=@override.yml"]
    result = subprocess.run(
        ["bash", "testbed-cli.sh", "-m", "inventory.yml",
         "announce-routes", "unit", "password", *extra_vars],
        cwd=ansible_dir, env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = yaml.safe_load((ansible_dir / "captured.yml").read_text())["convergence_data"]
    _assert_no_conflicts(data, {ip_interface(value).ip for value in addresses.values()})
    first = next(iter(data["ptf_backplane_addrs"].values()))
    assert first["ipv4"] == "10.10.246.105/31"
    assert yaml.safe_load(topo_file.read_text()) == topology
