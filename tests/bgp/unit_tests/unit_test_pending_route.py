"""Focused regressions for neighbor-controlled installation and cleanup."""

import ast
import ipaddress
import json
import logging
import random
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def pending_class():
    source = Path(__file__).resolve().parents[1] / "pending_route.py"
    tree = ast.parse(source.read_text())
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]

    def assert_condition(condition, message):
        assert condition, message

    namespace = {
        "ipaddress": ipaddress, "json": json, "pytest": pytest, "random": random,
        "pytest_assert": assert_condition, "logger": logging.getLogger(__name__),
        "wait_until": lambda timeout, interval, delay, condition, *args: condition(*args),
    }
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["PendingRoute"]


def make_pending(pending_class):
    pending = pending_class.__new__(pending_class)
    family = {"prefixes": ["198.19.1.1/32"], "namespace": "asic1",
              "nexthop": "198.18.1.99", "interface": "PortChannel1", "address": "198.18.1.1/24"}
    pending.families = {4: family}
    pending.announced = []
    pending.addresses = []
    pending.neighbors = []
    pending.sessions = []
    pending.ptf_addresses = []
    pending.peer_keys = []
    pending.dut = SimpleNamespace(hostname="dut")
    pending.vrf = "Vrf1"
    return pending


@pytest.mark.parametrize("selected,delivered,asic_present,neighbor_resolved,expected", [
    (True, True, False, False, True),
    (False, True, False, False, False),
    (True, False, False, False, False),
    (True, True, True, False, False),
    (True, True, False, True, False),
])
def test_pending_requires_selection_delivery_and_unresolved_hardware_absence(
        pending_class, selected, delivered, asic_present, neighbor_resolved, expected):
    """Require agreement between selection, delivery, neighbor, and ASIC evidence."""
    pending = make_pending(pending_class)
    prefix = "198.19.1.1/32"
    pending.asic_prefixes = lambda namespace: {ipaddress.ip_network(prefix)} if asic_present else set()
    pending.vty = lambda command, namespace: {
        "routes": {prefix: [{"valid": True, "bestpath": selected}]}}
    pending.app_routes = lambda family: {
        "ROUTE_TABLE:Vrf1:" + prefix: "198.18.1.99" if delivered else ""}
    pending.shell = lambda command, namespace: json.dumps(
        [{"lladdr": "02:00:00:00:00:99"}] if neighbor_resolved else [])
    assert pending.installation_matches(False) is expected


def test_cleanup_continues_after_pytest_failure_and_retries_safely(pending_class):
    """Finish owned-resource removal after pytest failures and allow a safe retry."""
    pending = make_pending(pending_class)
    family = pending.families[4]
    pending.neighbors = [(4, family)]
    pending.addresses = [family]
    calls = []

    def withdraw_failure():
        pytest.fail("withdraw unavailable")

    pending.withdraw = withdraw_failure

    def shell(command, namespace):
        calls.append((command, namespace))
        return '[{"lladdr":"02:00:00:00:00:99"}]' if "neigh show" in command else ""

    pending.shell = shell
    config_commands = []
    pending.dut.shell = lambda command: config_commands.append(command)
    with pytest.raises(AssertionError, match="withdraw unavailable"):
        pending.cleanup()
    assert any("neigh del" in command for command, _ in calls)
    assert config_commands == ["sudo config interface -n asic1 ip remove PortChannel1 198.18.1.1/24"]
    assert all(namespace == "asic1" for _, namespace in calls)
    previous_calls = len(calls)
    pending.withdraw = lambda: None
    pending.cleanup()
    assert len(calls) == previous_calls
    assert len(config_commands) == 1


def test_withdraw_attempts_both_families_after_first_failure(pending_class):
    """Try both API families even when the first withdrawal raises pytest.fail."""
    pending = make_pending(pending_class)
    pending.families[6] = {"prefixes": ["2001:db8:2665::1/128"], "nexthop": "2001:db8:2664::99"}
    pending.announced = [4, 6]
    pending.tbinfo = {"ptf_ip": "127.0.0.1"}
    pending.ports = {4: 5001, 6: 6001}
    pending.withdrawn = lambda: True
    calls = []

    def announce(ptf_ip, prefixes, port, **kwargs):
        calls.append(port)
        if port == 5001:
            pytest.fail("IPv4 API unavailable")

    pending.announce_callback = announce
    with pytest.raises(AssertionError, match="IPv4 API unavailable"):
        pending.withdraw()
    assert calls == [5001, 6001]


def test_setup_ignores_default_route_but_avoids_existing_asic_prefix(pending_class, monkeypatch):
    """Ignore default routes while rejecting actual address collisions."""
    pending = make_pending(pending_class)
    pending.count = 2
    pending.vty = lambda command, namespace: {"routes": {"0.0.0.0/0": []}, "localAS": 65100}
    pending.asic_prefixes = lambda namespace: {ipaddress.ip_network("198.18.1.0/24")}
    slots = iter([1, 2, 10])
    monkeypatch.setattr(random, "randrange", lambda *args: next(slots))

    def shell(command, namespace):
        if "address show" in command or "route show" in command or "neigh show" in command:
            return "[]"
        return '[{"dev":"PortChannel1"}]'

    pending.shell = shell
    pending.ptfhost = SimpleNamespace(shell=lambda command: {"stdout": "[]"})
    pending.start_session = lambda *args: None
    calls = []
    pending.configure_address = lambda family, action: calls.append((family["address"], action))
    pending.setup()
    assert calls == [("198.18.2.1/24", "add")]


def test_cleanup_attempts_remaining_peers_and_addresses_after_session_failure(pending_class):
    """Continue peer and address cleanup when a private session cannot be stopped."""
    pending = make_pending(pending_class)
    calls = []

    def failed_stop():
        calls.append("failed session")
        pytest.fail("session unavailable")

    pending.sessions = [
        SimpleNamespace(stop_session=lambda: calls.append("other session")),
        SimpleNamespace(stop_session=failed_stop),
    ]
    pending.peer_keys = [("BGP_NEIGHBOR|198.18.1.2", "asic1")]
    pending.ptf_addresses = [("198.18.1.2/24", "eth0")]
    pending.withdraw = lambda: None
    pending.db = lambda *args: calls.append("DUT peer")
    pending.ptfhost = SimpleNamespace(shell=lambda command: calls.append("PTF address"))
    with pytest.raises(AssertionError, match="session unavailable"):
        pending.cleanup()
    assert calls == ["failed session", "other session", "DUT peer", "PTF address"]
    assert len(pending.sessions) == 1


def test_setup_uses_ipv6_subnets_accepted_by_tor_import_policy(pending_class, monkeypatch):
    """Allocate IPv6 prefixes with policy-compatible lengths."""
    pending = make_pending(pending_class)
    pending.families = {6: pending.families[4]}
    pending.count = 2
    pending.vty = lambda command, namespace: {"routes": {"::/0": []}, "localAS": 65100}
    pending.asic_prefixes = lambda namespace: set()
    monkeypatch.setattr(random, "randrange", lambda *args: 10)

    def shell(command, namespace):
        return "[]" if any(value in command for value in ("address show", "route show", "neigh show")) else \
            '[{"dev":"PortChannel1"}]'

    pending.shell = shell
    pending.ptfhost = SimpleNamespace(shell=lambda command: {"stdout": "[]"})
    pending.start_session = lambda *args: None
    pending.configure_address = lambda *args: None
    pending.setup()
    assert [ipaddress.ip_network(prefix).prefixlen for prefix in pending.families[6]["prefixes"]] == [64, 64]


@pytest.mark.parametrize("advertised,has_peer,expected", [
    (True, True, True), (False, True, False), (True, False, False),
])
def test_static_advertisement_checks_the_explicit_prefix_and_requires_an_upstream_peer(
        pending_class, advertised, has_peer, expected):
    """Require an upstream peer and advertisement of the requested static prefix."""
    pending = make_pending(pending_class)
    pending.tbinfo = {"topo": {"type": "t1"}}
    pending_class.advertisement_matches.__globals__.update({
        "UPSTREAM_NEIGHBOR_MAP": {"t1": "T2"},
        "get_vm_name_list": lambda tbinfo, kind: ["ARISTA01T2"],
    })
    facts = {
        "minigraph_bgp": [{"name": "ARISTA01T2", "addr": "10.0.0.1"}] if has_peer else [],
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T2", "namespace": "asic1"}},
    }
    dut = SimpleNamespace(
        hostname="dut", get_extended_minigraph_facts=lambda tbinfo: facts,
        get_vtysh_cmd_for_namespace=lambda command, namespace: command,
        shell=lambda *args, **kwargs: {"stdout": json.dumps({
            "advertisedRoutes": {"1.1.1.0/24": {}} if advertised else {}})},
    )
    assert pending.advertisement_matches(dut, True, {4: ["1.1.1.0/24"]}) is expected


@pytest.mark.parametrize("multi_asic", [False, True])
@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("remote_ingress", [False, True])
def test_packet_masks_use_scapy_layers_and_check_the_resolved_mac(
        pending_class, monkeypatch, multi_asic, installed, remote_ingress):
    """Use valid packet masks without masking the installed route's destination MAC."""
    import ptf.packet as scapy
    import ptf.testutils as testutils
    from ptf.mask import Mask

    pending = make_pending(pending_class)
    pending_class.verify_forwarding.__globals__.update({
        "scapy": scapy, "testutils": testutils, "Mask": Mask, "UPSTREAM_NEIGHBOR_MAP": {"t1": "T2"},
    })
    pending.dut.is_multi_asic = multi_asic
    pending.dut.facts = {"router_mac": "02:00:00:00:00:01"}
    pending.tbinfo = {"topo": {"type": "t1"}}
    pending.mg_facts = {
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T2"}},
        "minigraph_ptf_indices": {"Ethernet0": 0},
    }
    pending.families = {
        version: {"prefixes": [prefix], "mac": "02:00:00:00:00:99", "ptf_ports": [1]}
        for version, prefix in ((4, "198.19.1.0/30"), (6, "2001:db8:2665::/64"))
    }
    pending.ptfadapter = SimpleNamespace(dataplane=SimpleNamespace(flush=lambda: None))
    ingress = None
    if remote_ingress:
        ingress_facts = {
            "minigraph_neighbors": {"Ethernet8": {"name": "ARISTA01T2"}},
            "minigraph_ptf_indices": {"Ethernet8": 2},
        }
        ingress = SimpleNamespace(
            facts={"router_mac": "02:00:00:00:00:02"},
            get_extended_minigraph_facts=lambda tbinfo: ingress_facts)
    checked = []
    sent = []
    monkeypatch.setattr(testutils, "send", lambda adapter, port, packet: sent.append((port, packet)))

    def verify(adapter, expected, ports, timeout):
        checked.append(expected)
        wrong_mac = expected.exp_pkt.copy()
        wrong_mac[scapy.Ether].dst = "02:00:00:00:00:98"
        assert expected.pkt_match(bytes(wrong_mac)) is (not installed)

    monkeypatch.setattr(testutils, "verify_packet_any_port", verify)
    monkeypatch.setattr(testutils, "verify_no_packet_any", verify)
    pending.verify_forwarding(installed, ingress)
    assert len(checked) == 2
    for port, packet in sent:
        assert port == (2 if remote_ingress else 0)
        assert packet[scapy.Ether].dst == (ingress or pending.dut).facts["router_mac"]


def test_resolution_normalizes_the_ptf_receiving_mac_from_bytes(pending_class):
    """Use the ASCII receiving MAC when releasing the neighbor-dependent delay."""
    facts = {
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T0"}},
        "minigraph_portchannels": {"PortChannel1": {"members": ["Ethernet0"]}},
        "minigraph_bgp": [{"name": "ARISTA01T0", "asn": 64001}],
        "minigraph_devices": {"ARISTA01T0": {"type": "ToRRouter"}},
    }
    dut = SimpleNamespace(hostname="dut", get_extended_minigraph_facts=lambda tbinfo: facts)
    ptfadapter = SimpleNamespace(dataplane=SimpleNamespace(get_mac=lambda *args: b"0a:00:00:00:00:99"))
    tbinfo = {"topo": {"properties": {"topology": {"VMs": {"ARISTA01T0": {"vm_offset": 0}}}}}}
    pending = pending_class(dut, tbinfo, ptfadapter, None, None, {4: 5000}, {4: [0]})
    pending.families[4]["nexthop"] = "198.18.1.99"
    pending.installation_matches = lambda installed: installed
    commands = []
    pending.shell = lambda command, namespace: commands.append(command)
    pending.resolve()
    assert commands == [
        "sudo ip -4 neigh replace 198.18.1.99 lladdr 0a:00:00:00:00:99 nud permanent dev PortChannel1"]
