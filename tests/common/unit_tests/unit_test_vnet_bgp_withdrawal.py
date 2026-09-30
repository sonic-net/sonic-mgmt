"""Exercise the VNET/BGP regression without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_vnet_bgp_withdrawal.py -v
"""

import ast
import itertools
import json
import logging
import shlex
from ipaddress import ip_network
from pathlib import Path
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "vxlan" / "test_vnet_bgp_route_precedence.py"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def namespace():
    tree = ast.parse(MODULE_PATH.read_text())
    names = {"_get_app_bgp_route_key", "_get_asic_route_nexthops", "Test_VNET_BGP_route_Precedence"}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    ns = {
        "pytest": pytest, "json": json, "ip_network": ip_network, "py_assert": _assert,
        "Logger": logging.getLogger(__name__),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), ns)
    return ns


@pytest.mark.parametrize("prefix", ["20.1.0.0/32", "dc4a:20:1::/128"])
@pytest.mark.parametrize("maskless", [False, True])
def test_find_competing_bgp_route(namespace, prefix, maskless):
    """Accept both fpmsyncd host-key formats, using a real BGP next hop."""
    key = "ROUTE_TABLE:{}".format(prefix.split('/')[0] if maskless else prefix)
    host = Mock()

    def shell(command):
        tokens = shlex.split(command)
        fields = {"protocol": "bgp", "nexthop": "10.0.0.1"}
        return {"stdout": fields[tokens[-1]] if tokens[-2] == key else ""}

    host.shell.side_effect = shell
    assert namespace["_get_app_bgp_route_key"](host, prefix) == key


@pytest.mark.parametrize("protocol,nexthop", [
    ("", ""), ("static", "10.0.0.1"), ("bgp", ""), ("bgp", "0.0.0.0"), ("bgp", "::"),
])
def test_reject_noncompeting_route(namespace, protocol, nexthop):
    """A VNET-only, local, or non-BGP route cannot satisfy BGP convergence."""
    host = Mock()
    host.shell.side_effect = lambda cmd: {"stdout": protocol if cmd.endswith("protocol") else nexthop}
    assert namespace["_get_app_bgp_route_key"](host, "20.1.0.0/32") is None


def test_asic_snapshot_preserves_vr_and_exact_prefix(namespace):
    """Do not merge virtual routers or accept substring matches."""
    def key(dest, vr):
        return "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:" + json.dumps(
            {"dest": dest, "vr": vr, "switch_id": "oid:0x1"})

    first = key("20.1.0.0/32", "oid:0x2")
    second = key("20.1.0.0/32", "oid:0x3")
    unrelated = key("120.1.0.0/32", "oid:0x2")
    host = Mock()
    host.shell.side_effect = [
        {"stdout_lines": [first, second, unrelated]}, {"stdout": "oid:0x4"}, {"stdout": "oid:0x5"},
    ]
    assert namespace["_get_asic_route_nexthops"](host, "20.1.0.0/32") == {
        first: "oid:0x4", second: "oid:0x5",
    }
    assert host.shell.call_count == 3


@pytest.mark.parametrize("helper", ["_get_app_bgp_route_key", "_get_asic_route_nexthops"])
def test_db_failure_is_not_absence(namespace, helper):
    """Database failures propagate instead of looking like a successful withdrawal."""
    host = Mock()
    host.shell.side_effect = RuntimeError("Database unavailable")
    with pytest.raises(RuntimeError, match="Database unavailable"):
        namespace[helper](host, "20.1.0.0/32")


@pytest.mark.parametrize("prefix_type,address,mask,route_mask,loopback", [
    ("v4", "20.1.0.0", 32, 32, "20.1.0.0"),
    ("v4", "20.1.0.0", 24, 24, "20.1.0.1"),
    ("v4", "20.1.0.0", 16, 24, "20.1.0.1"),
    ("v6", "dc4a:20:1::", 128, 128, "dc4a:20:1::"),
    ("v6", "dc4a:20:1::", 64, 64, "dc4a:20:1::1"),
    ("v6", "dc4a:20:1::", 60, 64, "dc4a:20:1::1"),
])
def test_bgp_loopback_add_remove(namespace, prefix_type, address, mask, route_mask, loopback):
    """Host routes use the exact address; cleanup uses the advertised mask."""
    case = namespace["Test_VNET_BGP_route_Precedence"]()
    case.prefix_type, case.adv_mask, case.prefix_mask = prefix_type, mask, route_mask
    case._test_bgp_routes = []
    tor = {"host": Mock()}
    tor["host"].run_command.return_value = {"stdout": ["router bgp 65100"]}
    routes = {"Vnet": {address: ["202.1.1.1"]}}
    advertised = {"Vnet": {address: address}}
    case.add_bgp_route_to_neighbor_tor(tor, routes, advertised)
    assert len(case._test_bgp_routes) == 1
    case.remove_bgp_route_from_neighbor_tor(tor, routes, advertised)
    assert not case._test_bgp_routes
    add, remove = [call.args[0] for call in tor["host"].run_command_list.call_args_list]
    family = "ip" if prefix_type == "v4" else "ipv6"
    assert "{} address {}/{}".format(family, loopback, mask) in add
    assert "network {}/{}".format(address, mask) in add
    assert "no {} address {}/{}".format(family, loopback, mask) in remove
    assert "no network {}/{}".format(address, mask) in remove


@pytest.mark.parametrize("encap_type,address", [
    ("v4_in_v4", "20.1.0.0"), ("v6_in_v4", "dc4a:20:1::"),
])
@pytest.mark.parametrize("failure,message", [
    (None, None),
    ("delete", "BGP withdrawal removed or changed"),
    ("late_delete", "BGP withdrawal removed or changed"),
    ("replace_nh", "BGP withdrawal removed or changed"),
    ("move_vr", "BGP withdrawal removed or changed"),
    ("monitor_down", "VNET monitor changed state"),
    ("missing_bgp", "did not reach APP_DB"),
    ("stuck_bgp", "was not withdrawn from APP_DB"),
    ("drop", "No VXLAN packet"),
])
def test_regression_sequence(namespace, encap_type, address, failure, message):
    """The real test fails on deletion, replacement, loss, or an unexercised BGP path."""
    case = namespace["Test_VNET_BGP_route_Precedence"]()
    host, request = Mock(), Mock()
    setup = {"t0": [{"host": Mock()}]}
    routes = {"Vnet": {address: ["202.1.1.1"]}}
    case.generate_vnet_routes = Mock(return_value=({"Vnet": {address: address}}, routes))
    events = []
    state = {"active": False, "bgp": False, "withdrawn": False, "withdraw_checks": 0}
    namespace["wait_until"] = lambda timeout, interval, delay, condition, *args: condition(*args)
    namespace["time"] = Mock(monotonic=Mock(side_effect=itertools.count(0, 5)))
    namespace["_check_redis_key_gone"] = lambda *args: not state["bgp"]
    namespace["_get_app_bgp_route_key"] = lambda *args: "ROUTE_TABLE:{}".format(address) if state["bgp"] else None

    def snapshot(*args):
        if not state["active"]:
            return {}
        if state["withdrawn"]:
            state["withdraw_checks"] += 1
            if failure == "delete" or (failure == "late_delete" and state["withdraw_checks"] > 1):
                return {}
            if failure == "replace_nh":
                return {"original-vr-and-prefix": "oid:0x2"}
            if failure == "move_vr":
                return {"other-vr-and-prefix": "oid:0x1"}
        return {"original-vr-and-prefix": "oid:0x1"}

    namespace["_get_asic_route_nexthops"] = snapshot
    case.add_monitored_vnet_route = Mock(side_effect=lambda *args: events.append("add_vnet"))

    def activate(*args):
        events.append("monitor_up")
        state["active"] = True

    def advertise(*args):
        events.append("add_bgp")
        state["bgp"] = failure != "missing_bgp"

    def withdraw(*args):
        events.append("withdraw_bgp")
        state["withdrawn"] = True
        state["bgp"] = failure == "stuck_bgp"

    def traffic(*args):
        events.append("traffic")
        if state["withdrawn"] and failure == "drop":
            raise AssertionError("No VXLAN packet")

    def shell(command):
        if command.endswith("packet_type"):
            return {"stdout": "vxlan"}
        return {"stdout": "down" if state["withdrawn"] and failure == "monitor_down" else "up"}

    host.shell.side_effect = shell
    case.update_monitors_state = Mock(side_effect=activate)
    case.add_bgp_route_to_neighbor_tor = Mock(side_effect=advertise)
    case.remove_bgp_route_from_neighbor_tor = Mock(side_effect=withdraw)
    case.wait_for_route_checks_pass = Mock()
    case.verify_tunnel_route_with_traffic = Mock(side_effect=traffic)
    case.remove_vnet_route = Mock()
    run = case.test_vnet_route_before_bgp_with_early_bgp_removal
    if message:
        with pytest.raises(AssertionError, match=message):
            run(setup, encap_type, host, request)
    else:
        run(setup, encap_type, host, request)
        assert events == [
            "add_vnet", "monitor_up", "traffic", "add_bgp", "traffic", "traffic",
            "withdraw_bgp", "traffic", "traffic",
        ]
    case.add_monitored_vnet_route.assert_called_once_with(routes, {"Vnet": {address: address}}, '', 'custom')
    case.update_monitors_state.assert_called_once_with(routes, "Up")
    case.remove_vnet_route.assert_not_called()
    request.addfinalizer.assert_called_once()
    request.addfinalizer.call_args.args[0]()
    host.shell.assert_called_with(
        "sonic-db-cli STATE_DB DEL 'VNET_MONITOR_TABLE|202.1.1.1|{}/{}'".format(address, case.prefix_mask))
