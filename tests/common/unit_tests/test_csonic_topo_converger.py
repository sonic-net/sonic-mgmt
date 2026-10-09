"""Unit tests for the cSONiC-only topology converger."""

import importlib.util
from pathlib import Path


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
