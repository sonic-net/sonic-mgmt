"""Focused tests for cSONiC converged ExaBGP endpoint selection."""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock, patch

import pytest


pytestmark = [
    pytest.mark.topology("any"),
]

REPO_ROOT = Path(__file__).resolve().parents[3]


def _package(name):
    package = types.ModuleType(name)
    package.__path__ = []
    package.__package__ = name
    return package


def _module(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    return module


def _load_route_flap():
    ptf = _package("ptf")
    stubs = {
        "ptf": ptf,
        "ptf.testutils": _module("ptf.testutils"),
        "ptf.packet": _module("ptf.packet"),
        "ptf.mask": _module("ptf.mask", Mask=object),
        "tests.common": _package("tests.common"),
        "tests.common.dualtor": _package("tests.common.dualtor"),
        "tests.common.dualtor.mux_simulator_control": _module(
            "tests.common.dualtor.mux_simulator_control",
            toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m=None,
        ),
        "tests.common.helpers": _package("tests.common.helpers"),
        "tests.common.helpers.assertions": _module(
            "tests.common.helpers.assertions", pytest_assert=assertion),
        "tests.common.utilities": _module(
            "tests.common.utilities", wait_until=lambda *args, **kwargs: True),
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location(
            "csonic_route_flap", REPO_ROOT / "tests" / "route" / "test_route_flap.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def _load_route_bgp_ecmp():
    spec = importlib.util.spec_from_file_location(
        "csonic_route_bgp_ecmp",
        REPO_ROOT / "tests" / "route" / "test_route_bgp_ecmp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assertion(condition, message=""):
    if not condition:
        raise AssertionError(message)


def _tbinfo(converged, include_vm_type=True):
    properties = {
        "configuration_properties": {"common": {"nhipv4": "10.10.246.254"}},
        "topology": {
            "VMs": {
                "ARISTA01T1": {"vm_offset": 0},
                "ARISTA02T1": {"vm_offset": 1},
            },
        },
    }
    tbinfo = {"topo": {"properties": properties}}
    if include_vm_type:
        tbinfo["vm_type"] = "csonic"
    if converged:
        properties.update({
            "topo_is_multi_vrf": True,
            "convergence_data": {
                "vrf_name_mapping": {
                    "ARISTA01T1": "VrfARISTA01T1",
                    "ARISTA02T1": "VrfARISTA02T1",
                },
                "vm_offset_mapping": {"ARISTA01T1": 0, "ARISTA02T1": 1},
                "ptf_backplane_addrs": {
                    "ARISTA01T1": {"ipv4": "10.10.246.101/31"},
                    "ARISTA02T1": {"ipv4": "10.10.246.103/31"},
                },
            },
        })
    return tbinfo


def test_route_flap_selects_matching_converged_nexthop():
    route_flap = _load_route_flap()
    duthost = Mock()
    duthost.shell.return_value = {"stdout": "ARISTA02T1"}

    assert route_flap.get_exabgp_endpoint(
        duthost, _tbinfo(True, include_vm_type=False),
        "PortChannel2", "10.10.246.254") == (5001, "10.10.246.103")


def test_route_flap_preserves_ordinary_endpoint():
    route_flap = _load_route_flap()
    duthost = Mock()
    duthost.shell.return_value = {"stdout": "ARISTA02T1"}

    assert route_flap.get_exabgp_endpoint(
        duthost, _tbinfo(False), "PortChannel2", "10.10.246.254") == (
            5001, "10.10.246.254")


def test_bgp_ecmp_selects_per_peer_converged_nexthops():
    route_bgp_ecmp = _load_route_bgp_ecmp()

    assert route_bgp_ecmp.get_exabgp_endpoints(
        _tbinfo(True, include_vm_type=False), "10.10.246.254") == [
            (5000, "10.10.246.101"),
            (5001, "10.10.246.103"),
        ]


def test_bgp_ecmp_preserves_ordinary_endpoints():
    route_bgp_ecmp = _load_route_bgp_ecmp()

    assert route_bgp_ecmp.get_exabgp_endpoints(
        _tbinfo(False), "10.10.246.254") == [
            (5000, "10.10.246.254"),
            (5001, "10.10.246.254"),
        ]
