"""Unit tests for the cSONiC-only topology converger."""

import importlib.util
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.topology("any"),
]


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "ansible" / "csonic_topo_converger.py"
SPEC = importlib.util.spec_from_file_location("csonic_topo_converger", MODULE_PATH)
CONVERGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONVERGER)


def test_vrf_names_are_schema_safe_stable_and_collision_resistant():
    logical_names = (
        "ARISTA01T1",
        "peer.with.long.invalid/name",
        "peer with long invalid name",
        "a" * 40,
    )
    names = [CONVERGER.csonic_vrf_name(name) for name in logical_names]

    assert names[0] == "VrfARISTA01T1"
    assert names == [CONVERGER.csonic_vrf_name(name) for name in logical_names]
    assert len(set(names)) == len(names)
    assert all(name.startswith("Vrf") and len(name) <= 15 for name in names)
    assert all(name[3:].replace("_", "").replace("-", "").isalnum()
               for name in names)


def test_prime_allocation_reserves_the_32nd_injected_port_for_backplane(tmp_path):
    configuration = {}
    vms = {}
    for index in range(32):
        name = "ARISTA{:02d}T1".format(index + 1)
        configuration[name] = {
            "properties": ["configuration_properties"],
            "bgp": {"asn": 64600, "peers": {}},
            "interfaces": {},
            "bp_interface": {},
        }
        vms[name] = {"vlans": [index], "vm_offset": index}

    topology = {
        "configuration_properties": {
            "configuration_properties": {"swrole": "spine"},
        },
        "configuration": configuration,
        "topology": {"VMs": vms},
    }
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))
    converger.parse_properties()

    assert len(converger.prime_devices) == 2
    assert [len(converger.prime_device_mapping[prime])
            for prime in converger.prime_devices] == [31, 1]


def test_prime_allocation_counts_front_panel_links_not_logical_peers(tmp_path):
    configuration = {}
    vms = {}
    for index in range(16):
        name = "ARISTA{:02d}T2".format(index + 1)
        configuration[name] = {
            "properties": ["spine"],
            "bgp": {"asn": 65200, "peers": {}},
            "interfaces": {},
            "bp_interface": {},
        }
        vms[name] = {"vlans": [index * 2, index * 2 + 1],
                     "vm_offset": index}

    topology = {
        "configuration_properties": {"spine": {"swrole": "spine"}},
        "configuration": configuration,
        "topology": {"VMs": vms},
    }
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))
    converger.parse_properties()

    assert len(converger.prime_devices) == 2
    assert [len(converger.prime_device_mapping[prime])
            for prime in converger.prime_devices] == [15, 1]
    assert [sum(len(vms[peer]["vlans"])
                for peer in converger.prime_device_mapping[prime])
            for prime in converger.prime_devices] == [30, 2]


def test_stock_t1_lag_converges_to_two_16_link_role_primes(tmp_path):
    topo_path = REPO_ROOT / "ansible" / "vars" / "topo_t1-lag.yml"
    # The session startup hook converges this shared file before collection on
    # converged testbeds. Its backup is the canonical stock topology this unit
    # test is intended to exercise; ordinary unit runs have no backup.
    source_topo_path = topo_path.with_name(topo_path.name + ".bak")
    if not source_topo_path.exists():
        source_topo_path = topo_path
    topology = CONVERGER.yaml.safe_load(source_topo_path.read_text())
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))
    converger.parse_properties()
    converger.converge_topo()

    result = converger.converged_topo
    assert converger.prime_devices == ["ARISTA01T2", "ARISTA01T0"]
    assert [len(converger.prime_device_mapping[prime])
            for prime in converger.prime_devices] == [8, 16]
    assert [len(result["topology"]["VMs"][prime]["vlans"])
            for prime in converger.prime_devices] == [16, 16]
    assert result["max_fp_num_provided"] == 16

    spine = result["convergence_data"]["converged_peers"]["ARISTA01T2"]
    for index, peer in enumerate(
            result["convergence_data"]["convergence_mapping"]["ARISTA01T2"], 1):
        vrf = spine["vrf"][peer]
        portchannel = "Port-Channel{}".format(index)
        members = [data for name, data in vrf.items()
                   if name.startswith("Ethernet")]
        assert portchannel in vrf
        assert len(members) == 2
        assert {member["lacp"] for member in members} == {index}
