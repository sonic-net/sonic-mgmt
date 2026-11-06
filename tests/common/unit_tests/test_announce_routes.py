"""Focused tests for multi-VRF route announcement inputs."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import patch

import pytest


pytestmark = [
    pytest.mark.topology("any"),
]


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "ansible" / "library" / "announce_routes.py"


def _load_announce_routes():
    """Load the Ansible module without requiring an Ansible runtime."""
    ansible = ModuleType("ansible")
    module_utils = ModuleType("ansible.module_utils")
    basic = ModuleType("ansible.module_utils.basic")
    debug_utils = ModuleType("ansible.module_utils.debug_utils")
    multi_servers_utils = ModuleType(
        "ansible.module_utils.multi_servers_utils")
    basic.AnsibleModule = object
    debug_utils.config_module_logging = lambda *args, **kwargs: None
    multi_servers_utils.MultiServersUtils = object
    stubs = {
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.debug_utils": debug_utils,
        "ansible.module_utils.multi_servers_utils": multi_servers_utils,
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location(
            "announce_routes", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("csonic", "v4_next_hops", "v6_next_hops"),
    [
        (True, ("10.10.246.101", "10.10.246.103"),
         ("fc0a::65", "fc0a::67")),
        (False, ("10.10.246.254", "10.10.246.254"),
         ("fc0a::ff", "fc0a::ff")),
    ],
)
def test_multi_vrf_t0_isolates_csonic_next_hop_change(
        csonic, v4_next_hops, v6_next_hops):
    announce_routes = _load_announce_routes()
    topo = {
        "topo_is_multi_vrf": True,
        "topology": {"VMs": {"ARISTA01T1": {"vm_offset": 0}}},
        "configuration_properties": {
            "common": {
                "podset_number": 0,
                "enable_ipv4_routes_generation": True,
                "enable_ipv6_routes_generation": True,
            },
        },
        "configuration": {
            "ARISTA01T1": {"properties": ["common"]},
            "ARISTA02T1": {"properties": ["common"]},
        },
        "convergence_data": {
            "convergence_mapping": {
                "ARISTA01T1": ["ARISTA01T1", "ARISTA02T1"],
            },
            "vm_offset_mapping": {
                "ARISTA01T1": 0,
                "ARISTA02T1": 1,
            },
            "ptf_backplane_addrs": {
                "ARISTA01T1": {
                    "ipv4": "10.10.246.101/31",
                    "ipv6": "fc0a::65/127",
                },
                "ARISTA02T1": {
                    "ipv4": "10.10.246.103/31",
                    "ipv6": "fc0a::67/127",
                },
            },
        },
    }
    if csonic:
        topo["convergence_data"]["vrf_name_mapping"] = {
            "ARISTA01T1": "VrfARISTA01T1",
            "ARISTA02T1": "VrfARISTA02T1",
        }
    generated = {}

    announce_routes.fib_t0(
        topo,
        "10.250.0.102",
        action=announce_routes.GENERATE_WITHOUT_APPLY,
        topo_routes=generated,
    )

    assert generated["ARISTA01T1"]["ipv4"][0][0:2] == (
        "0.0.0.0/0", v4_next_hops[0])
    assert generated["ARISTA02T1"]["ipv4"][0][0:2] == (
        "0.0.0.0/0", v4_next_hops[1])
    assert generated["ARISTA01T1"]["ipv6"][0][0:2] == (
        "::/0", v6_next_hops[0])
    assert generated["ARISTA02T1"]["ipv6"][0][0:2] == (
        "::/0", v6_next_hops[1])
