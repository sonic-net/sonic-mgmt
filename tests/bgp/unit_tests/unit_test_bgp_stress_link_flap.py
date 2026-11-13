"""Focused tests for BGP Monitor backplane selection and stress recovery."""

from pathlib import Path
import sys
from unittest.mock import DEFAULT, Mock, call, patch

import pytest


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
                "dut_asn": 65100,
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


@pytest.mark.parametrize("test_function", [
    bgp_stress.test_bgp_stress_link_flap_with_monitor,
    bgp_stress.test_bgp_stress_link_flap_with_sentinel_and_monitor,
])
@pytest.mark.parametrize("monitor_recovers", [True, False])
def test_monitor_recovery_waits_after_regular_peers(test_function, monitor_recovers):
    duthost = Mock(is_multi_asic=False)
    duthost.setup.return_value = {
        "ansible_facts": {
            "ansible_Loopback0": {
                "ipv4": {"address": "10.1.0.32"},
                "ipv6": [{"address": "fc00:1::32"}],
            },
        },
    }
    monitor_ips = ["10.10.246.254", "fc0a::ff"]
    with patch.multiple(
        bgp_stress,
        setup_bgp_sentinel=DEFAULT,
        add_route_to_dut_lo=DEFAULT,
        setup_bgp_monitor=DEFAULT,
        start_exabgp_monitors=DEFAULT,
        _run_stress_link_flap_test=DEFAULT,
        is_bgp_monitor_session_established=DEFAULT,
        cleanup_bgp_sentinel=DEFAULT,
        cleanup_bgp_monitor=DEFAULT,
        wait_until=DEFAULT,
    ) as mocks:
        mocks["add_route_to_dut_lo"].return_value = ("10.10.246.29", "fc0a::1d")
        mocks["setup_bgp_monitor"].return_value = monitor_ips
        mocks["wait_until"].side_effect = [True, True, monitor_recovers]
        kwargs = {
            "duthosts": {"dut": duthost},
            "enum_frontend_dut_hostname": "dut",
            "setup": {"neighhosts": {"10.0.0.57": {}}},
            "nbrhosts": {},
            "fanouthosts": {},
            "ptfhost": Mock(),
            "tbinfo": _tbinfo(),
            "test_type": "dut",
            "get_function_completeness_level": "debug",
            "backup_and_restore_config_db": None,
        }
        if monitor_recovers:
            test_function(**kwargs)
        else:
            with pytest.raises(pytest.fail.Exception, match="BGP Monitor sessions not established after stress test"):
                test_function(**kwargs)

        monitor_check = mocks["is_bgp_monitor_session_established"]
        assert mocks["wait_until"].call_args_list == [
            call(300, 10, 0, monitor_check, duthost, monitor_ips),
            call(600, 10, 0, duthost.check_bgp_session_state, ["10.0.0.57"]),
            call(300, 10, 0, monitor_check, duthost, monitor_ips),
        ]
        mocks["cleanup_bgp_monitor"].assert_called_once()
        if test_function is bgp_stress.test_bgp_stress_link_flap_with_sentinel_and_monitor:
            mocks["cleanup_bgp_sentinel"].assert_called_once_with(duthost)
