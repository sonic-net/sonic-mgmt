"""Focused tests for converged BGP Monitor backplane selection."""

from pathlib import Path
import sys
from unittest.mock import Mock, patch


_TESTS_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "bgp"))

from bgp import test_bgp_stress_link_flap as bgp_stress  # noqa: E402
from bgp.test_bgp_stress_link_flap import (  # noqa: E402
    add_route_to_dut_lo,
    get_bgp_monitor_backplane,
)


def _tbinfo(converged=False):
    properties = {
        "configuration_properties": {
            "common": {
                "nhipv4": "10.10.246.254",
                "nhipv6": "FC0A::FF",
            },
        },
        "configuration": {
            "ARISTA01T1": {
                "properties": ["common"],
                "bp_interface": {
                    "ipv4": "10.10.246.29/24",
                    "ipv6": "fc0a::1d/64",
                },
            },
        },
    }
    if converged:
        properties.update({
            "topo_is_multi_vrf": True,
            "convergence_data": {
                "vrf_name_mapping": {
                    "ARISTA01T1": "VrfARISTA01T1",
                    "ARISTA02T1": "VrfARISTA02T1",
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
        })
    return {"topo": {"name": "t0", "type": "t0", "properties": properties}}


def test_ordinary_topology_keeps_shared_monitor_backplane():
    v4, v6, next_hops, converged = get_bgp_monitor_backplane(_tbinfo())
    assert v4 == "10.10.246.254"
    assert v6 == "fc0a::ff"
    assert next_hops == {
        "ARISTA01T1": {"ipv4": "10.10.246.29", "ipv6": "fc0a::1d"}
    }
    assert converged is False


def test_converged_csonic_uses_one_reachable_point_to_point_backplane():
    v4, v6, next_hops, converged = get_bgp_monitor_backplane(_tbinfo(converged=True))
    assert v4 == "10.10.246.101"
    assert v6 == "fc0a::65"
    assert next_hops == {
        "ARISTA01T1": {"ipv4": "10.10.246.100", "ipv6": "fc0a::64"}
    }
    assert converged is True


def test_route_probes_bind_to_exabgp_source_not_parent_backplane():
    ptfhost = Mock()
    ptfhost.shell.return_value = {"rc": 0}
    with patch.object(bgp_stress.time, "sleep"):
        assert add_route_to_dut_lo(
            ptfhost,
            {"ARISTA01T1": {"ipv4": "10.10.246.100", "ipv6": "fc0a::64"}},
            "10.1.0.32",
            "fc00:1::32",
            "10.10.246.101",
            "fc0a::65",
            True,
        ) == ("10.10.246.100", "fc0a::64")

    commands = [call.args[0] for call in ptfhost.shell.call_args_list]
    assert commands == [
        "ip route replace 10.1.0.32 via 10.10.246.100 src 10.10.246.101",
        "ping 10.1.0.32 -c 3 -I 10.10.246.101",
        "ip -6 route replace fc00:1::32 via fc0a::64 src fc0a::65",
        "ping fc00:1::32 -c 3 -I fc0a::65",
    ]


def test_ordinary_route_commands_remain_unchanged():
    ptfhost = Mock()
    ptfhost.shell.return_value = {"rc": 0}
    with patch.object(bgp_stress.time, "sleep"):
        assert add_route_to_dut_lo(
            ptfhost,
            {"ARISTA01T1": {"ipv4": "10.10.246.29", "ipv6": "fc0a::1d"}},
            "10.1.0.32",
            "fc00:1::32",
        ) == ("10.10.246.29", "fc0a::1d")

    commands = [call.args[0] for call in ptfhost.shell.call_args_list]
    assert commands == [
        "ip route add 10.1.0.32 via 10.10.246.29",
        "ping 10.1.0.32 -c 3 -I backplane",
        "ip route add fc00:1::32 via fc0a::1d",
        "ping fc00:1::32 -c 3 -I backplane",
    ]
