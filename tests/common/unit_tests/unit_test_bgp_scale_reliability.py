"""Exercise BGP scale helpers without importing Ansible or PTF testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_bgp_scale_reliability.py -v
"""

import ast
import datetime
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


ROOT = Path(__file__).resolve().parents[3]
ANNOUNCE_ROUTES = ROOT / "ansible" / "library" / "announce_routes.py"
BGP_SCALE = ROOT / "tests" / "bgp" / "test_ipv6_bgp_scale.py"


def _load_helpers(path, names, namespace, constants=False):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = []
    for node in tree.body:
        if constants and isinstance(node, ast.Assign) and all(
                isinstance(target, ast.Name) and target.id.isupper() for target in node.targets):
            for target in node.targets:
                namespace[target.id] = ast.literal_eval(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            functions.append(node)
    assert {node.name for node in functions} == set(names)
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.fixture
def routes():
    return _load_helpers(ANNOUNCE_ROUTES, ["fib_t1_lag", "fib_t2_lag"], {
        "re": re,
        "get_change_routes_ports": Mock(return_value=(5000, 6000)),
        "get_ipv4_routes": Mock(return_value=[]),
        "get_ipv6_routes": Mock(return_value=[]),
        "generate_t1_to_t0_routes": Mock(side_effect=lambda family, *args, **kwargs: ([family + "-shared"], 256)),
        "generate_routes": Mock(side_effect=lambda family, *args, **kwargs: ([family + "-regular"], 256)),
        "generate_t2_routes": Mock(return_value=[]),
        "change_routes": Mock(),
        "send_routes_in_parallel": Mock(),
    }, constants=True)


@pytest.mark.parametrize("topology", ["t1-isolated-d254u2", "t1-lag"])
@pytest.mark.parametrize("ipv4,ipv6", [(True, True), (True, False), (False, True)])
def test_t1_route_inventory_matches_announcements(routes, topology, ipv4, ipv6):
    """Keep shared and regular routes in both inventory and announcements."""
    topo = {
        "configuration_properties": {"common": {
            "enable_ipv4_routes_generation": ipv4,
            "enable_ipv6_routes_generation": ipv6,
        }},
        "topology": {"VMs": {"VM1T0": {}}},
        "configuration": {"VM1T0": {"properties": ["tor"], "tornum": 1}},
    }
    inventory = {}
    routes["fib_t1_lag"](topo, "127.0.0.1", topology, topo_routes=inventory)

    expected = {}
    announcements = []
    for enabled, family, port in [(ipv4, "v4", 5000), (ipv6, "v6", 6000)]:
        if enabled:
            prefixes = [family + "-regular"]
            if topology in routes["BGP_SCALE_T1S"]:
                prefixes.insert(0, family + "-shared")
            expected["ip" + family] = prefixes
            announcements.append(call("announce", "127.0.0.1", port, prefixes))
    assert inventory == {"VM1T0": expected}
    assert routes["change_routes"].call_args_list == announcements


@pytest.mark.parametrize("vlan,dut_index", [(0, 0), (42, 0), ("2.10@3", 2)])
def test_t2_vlan_formats(routes, vlan, dut_index):
    """Integer VLANs select DUT zero; encoded VLAN strings select their DUT."""
    topo = {"topology": {"VMs": {"VM1T1": {"vlans": [vlan]}}}}
    inventory = {}
    routes["fib_t2_lag"](topo, "127.0.0.1", action="generate", topo_routes=inventory)
    assert routes["generate_t2_routes"].call_args_list == [
        call({dut_index: ["VM1T1"]}, topo, "127.0.0.1", "generate", inventory),
        call({}, topo, "127.0.0.1", "generate", inventory),
    ]
    routes["send_routes_in_parallel"].assert_not_called()


class IntSubclass(int):
    pass


@pytest.mark.parametrize("vlan", [True, IntSubclass(42)])
def test_t2_vlan_check_remains_exact_type(routes, vlan):
    """The lint fix must not silently accept bools or integer subclasses."""
    topo = {"topology": {"VMs": {"VM1T1": {"vlans": [vlan]}}}}
    with pytest.raises(TypeError):
        routes["fib_t2_lag"](topo, "127.0.0.1", action="generate", topo_routes={})
    routes["generate_t2_routes"].assert_not_called()


@pytest.fixture
def traffic():
    return _load_helpers(BGP_SCALE, ["wait_for_rx_quiescence", "_send_with_retry", "calculate_downtime"], {
        "time": Mock(),
        "logger": Mock(),
        "_get_backplane_ports": Mock(return_value={(0, 99)}),
        "current_test": "unit",
        "test_results": {},
    })


def test_send_succeeds_without_retry(traffic):
    """Successful sends must not sleep or duplicate packets."""
    dataplane = Mock()
    assert traffic["_send_with_retry"](dataplane, 0, 1, b"packet") is True
    dataplane.send.assert_called_once_with(0, 1, b"packet")
    traffic["time"].sleep.assert_not_called()


def test_send_recovers_after_timeouts(traffic):
    """Timeout retries resend the same packet with exponential backoff."""
    dataplane = Mock()
    dataplane.send.side_effect = [RuntimeError("Timed out"), RuntimeError("timed out"), None]
    assert traffic["_send_with_retry"](dataplane, 0, 1, b"packet") is True
    assert dataplane.send.call_args_list == [call(0, 1, b"packet")] * 3
    assert traffic["time"].sleep.call_args_list == [call(0.1), call(0.2)]


def test_send_retry_limit_and_backoff_cap(traffic):
    """Persistent timeouts return failure after ten attempts with bounded backoff."""
    dataplane = Mock()
    dataplane.send.side_effect = RuntimeError("timed out")
    assert traffic["_send_with_retry"](dataplane, 0, 1, b"packet") is False
    assert dataplane.send.call_count == 10
    assert traffic["time"].sleep.call_args_list == [
        call(delay) for delay in [0.1, 0.2, 0.4, 0.8] + [1.6] * 6
    ]


def test_send_other_errors_propagate(traffic):
    """Only timeout failures are retried; other errors must remain visible."""
    dataplane = Mock()
    dataplane.send.side_effect = RuntimeError("socket closed")
    with pytest.raises(RuntimeError, match="socket closed"):
        traffic["_send_with_retry"](dataplane, 0, 1, b"packet")
    dataplane.send.assert_called_once()
    traffic["time"].sleep.assert_not_called()


@pytest.mark.parametrize("arrivals,max_timeout,elapsed,timed_out", [
    ([], 20, 3, False),
    ([2, 4], 20, 7, False),
    (list(range(1, 10)), 5, 6, True),
])
def test_quiescence_waits_for_stability_or_timeout(traffic, arrivals, max_timeout, elapsed, timed_out):
    """Late arrivals reset the stable window, but continuous traffic is bounded."""
    dataplane = SimpleNamespace(mask_rx_cnt={"mask": {(0, 1): 0}})
    clock = SimpleNamespace(now=0)

    def sleep(seconds):
        clock.now += seconds
        if clock.now in arrivals:
            dataplane.mask_rx_cnt["mask"][(0, 1)] += 1

    traffic["time"].time.side_effect = lambda: clock.now
    traffic["time"].sleep.side_effect = sleep
    traffic["wait_for_rx_quiescence"](dataplane, "mask", stable_secs=3, max_timeout=max_timeout)
    assert clock.now == elapsed
    assert traffic["logger"].warning.called is timed_out


def test_downtime_waits_before_reading_counters(traffic):
    """Read drained counters and continue excluding backplane packets from downtime."""
    dataplane = SimpleNamespace(
        mask_rx_cnt={"mask": {(0, 1): 0, (0, 99): 100}},
        mask_tx_cnt={"mask": {(0, 1): 100}},
    )

    def drain(pdp, exp_mask):
        pdp.mask_rx_cnt[exp_mask][(0, 1)] = 90

    traffic["wait_for_rx_quiescence"] = Mock(side_effect=drain)
    start = datetime.datetime(2026, 1, 1)
    end = start + datetime.timedelta(seconds=10)
    assert traffic["calculate_downtime"](dataplane, end, start, "mask") == 1
    traffic["wait_for_rx_quiescence"].assert_called_once_with(dataplane, "mask")
    assert "Missing packets: 10" in traffic["test_results"]["unit"]
