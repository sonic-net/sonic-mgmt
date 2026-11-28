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


def _topology_with_role_link_counts(role_link_counts):
    configuration_properties = {}
    configuration = {}
    vms = {}
    next_vlan = 0
    for index, (role, link_count) in enumerate(role_link_counts, start=1):
        name = "ARISTA{:02d}T1".format(index)
        configuration_properties.setdefault(role, {"swrole": role})
        configuration[name] = {
            "properties": [role],
            "bgp": {"asn": 64600, "peers": {}},
            "interfaces": {
                "Ethernet{}".format(link + 1): {}
                for link in range(link_count)
            },
            "bp_interface": {},
        }
        vms[name] = {
            "vlans": list(range(next_vlan, next_vlan + link_count)),
            "vm_offset": index - 1,
        }
        next_vlan += link_count

    return {
        "configuration_properties": configuration_properties,
        "configuration": configuration,
        "topology": {"VMs": vms},
    }


def _topology_with_front_panel_link_counts(link_counts):
    return _topology_with_role_link_counts(
        [("spine", link_count) for link_count in link_counts])


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


def test_prime_allocation_counts_front_panel_links_and_allows_31(tmp_path):
    # Fifteen two-link peers plus one single-link peer exactly fill a prime's
    # 31 front-panel ports. The next peer must start a new prime even though
    # only 17 logical peers are present.
    topology = _topology_with_front_panel_link_counts(
        ([2] * 15) + [1, 1])
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))

    converger.parse_properties()
    converged_vms = converger.converge_vms()

    assert [len(converger.prime_device_mapping[prime])
            for prime in converger.prime_devices] == [16, 1]
    assert [len(converged_vms[prime]["vlans"])
            for prime in converger.prime_devices] == [31, 1]

    converger.converge_topo()
    assert converger.converged_topo["max_fp_num_provided"] == 31


def test_rejects_a_logical_peer_with_more_than_31_front_panel_links(tmp_path):
    topology = _topology_with_front_panel_link_counts([32])
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))

    with pytest.raises(ValueError, match=r"ARISTA01T1.*32.*31"):
        converger.run()


def test_prime_allocation_tracks_each_role_independently(tmp_path):
    topology = _topology_with_role_link_counts([
        ("role_a", 30),
        ("role_b", 30),
        ("role_a", 1),
        ("role_b", 1),
        ("role_a", 1),
    ])
    converger = CONVERGER.CsonicTopoConverger(
        topology, str(tmp_path / "converged.yml"))

    converger.parse_properties()

    prime_link_counts_by_role = {}
    for prime in converger.prime_devices:
        role = topology["configuration"][prime]["properties"][0]
        link_count = sum(
            len(topology["topology"]["VMs"][peer]["vlans"])
            for peer in converger.prime_device_mapping[prime]
        )
        prime_link_counts_by_role.setdefault(role, []).append(link_count)

    assert prime_link_counts_by_role == {
        "role_a": [31, 1],
        "role_b": [31],
    }
    mapped_peers = [
        peer
        for peers in converger.prime_device_mapping.values()
        for peer in peers
    ]
    assert len(mapped_peers) == len(set(mapped_peers))
    assert set(mapped_peers) == set(topology["configuration"])
    assert all(
        link_count <= CONVERGER.CSONIC_INTF_LIMIT
        for role_counts in prime_link_counts_by_role.values()
        for link_count in role_counts
    )
