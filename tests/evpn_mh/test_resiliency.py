"""EVPN-MH forwarding resiliency and lifecycle cases."""

from copy import deepcopy
import json
import re
import shlex
import sys
import threading
import time

import pytest

from tests.common.errors import RunAnsibleModuleFail

from .eos_overlay import (collect_remote_eos_evidence, eos_aliasing_vteps,
                          eos_contains_value)
from .lag import ptf_bond_member_operational
from .operations import (bounce_ptf_member, interface_down, portchannel_members,
                         portchannel_config_snapshot,
                         restore_interfaces, restore_portchannel_config,
                         set_interface_admin, wait_interface, wait_until)
from .provision import (configure_temporary_l3_orphan,
                        remove_temporary_l3_orphan, uses_frrcfgd,
                        wait_evpn_mh_overlay)
from .state import (CommandUnavailableError, command_json, contains_prefix,
                    ethernet_segment, neighbor_matches,
                    route_nexthop_count, segment_is_df, vni_is_present)
from .test_traffic import _assert_bum_control_plane, _df_runtime
from .topology import temporary_l3_orphan_endpoint
from .traffic import (finish_traffic_profile, run_traffic_profile,
                      start_traffic_profile, traffic_event_window)


pytestmark = [
    pytest.mark.topology("dualtor"),
    pytest.mark.dualtor_skip_setup_mux_ports,
    pytest.mark.skip_check_dut_health,
    pytest.mark.sanity_check(check_items=["-check_bgp"]),
]


def _run(ptfhost, name, ports, topology, runtime=None):
    run_traffic_profile(ptfhost, name, ports, topology, runtime)


def _wait_forwarding(ptfhost, name, ports, topology, timeout=120, runtime=None):
    def forwarding_ready():
        try:
            _run(ptfhost, name, ports, topology, runtime)
            return True
        except RunAnsibleModuleFail:
            # A nonzero PTF run is the retryable "not forwarding yet" signal.
            return False

    return wait_until(timeout, 10, 0, forwarding_ready)


def _primary_segment(topology):
    name = topology["primary_test_segment"]
    return name, topology["ethernet_segments"][name]


def _segment_bond(ptf_lags, segment_name, segment):
    """Accept the new mapping fixture while retaining focused-unit compatibility."""
    if isinstance(ptf_lags, dict):
        return ptf_lags[segment_name]
    return segment["ptf_bond_interface"] if ptf_lags is None else ptf_lags


def _df_role(duts, topology, definition=None):
    definition = definition or _primary_segment(topology)[1]
    states = {}
    for role in definition["leaf_roles"]:
        observed = ethernet_segment(
            command_json(duts[role], "show evpn es json"), definition["esi"])
        states[role] = observed is not None and segment_is_df(observed)
    if list(states.values()).count(True) != 1:
        return None
    return next(role for role, is_df in states.items() if is_df)


def _ecmp_to_leg(leg, forbidden):
    return {"flow_overrides": {
        "announce_h2_for_ecmp": {"tx_endpoint": leg},
        "h3_to_mh_ecmp": {
            "receive_groups": [[leg]], "forbidden_endpoints": [forbidden],
        },
    }}


def _local_bias_runtime(duts):
    """The frozen local-bias contract is strict on all supported platforms."""
    return None


def _df_preference(dut, portchannel):
    """Read only this interface's explicit DF override using supported FRR CLI.

    FRR does not consistently implement ``show running-config interface NAME``.
    Keep the complete supported-query output on the DUT and return only the
    parsed preference and bounded command metadata to the controller.
    """
    assert re.fullmatch(r"PortChannel[0-9]+", portchannel), portchannel
    source = r"""
import json
import re
import subprocess
import sys

report = {"interface": sys.argv[1]}
try:
    native = subprocess.run(
        ["vtysh", "-c", "show running-config"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=30)
except (OSError, subprocess.TimeoutExpired) as error:
    report["error"] = "native query {}".format(type(error).__name__)
    print(json.dumps(report, sort_keys=True))
    sys.exit(1)

report.update({
    "native_rc": native.returncode,
    "stdout_lines": len(native.stdout.splitlines()),
    "stderr_lines": len(native.stderr.splitlines()),
})
if native.returncode:
    report["error"] = "native show running-config command failed"
    print(json.dumps(report, sort_keys=True))
    sys.exit(1)

lines = native.stdout.splitlines()
header = "interface " + sys.argv[1]
starts = [index for index, line in enumerate(lines) if line.rstrip() == header]
report["interface_count"] = len(starts)
if len(starts) != 1:
    report["error"] = "expected exactly one interface stanza"
    print(json.dumps(report, sort_keys=True))
    sys.exit(1)

preferences = []
for line in lines[starts[0] + 1:]:
    if line and not line[0].isspace():
        break
    statement = line.strip()
    if not statement.startswith("evpn mh es-df-pref"):
        continue
    match = re.fullmatch(r"evpn\s+mh\s+es-df-pref\s+([0-9]+)", statement)
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        report["error"] = "malformed DF preference statement"
        print(json.dumps(report, sort_keys=True))
        sys.exit(1)
    preferences.append(int(match.group(1)))
if len(preferences) > 1:
    report["error"] = "duplicate DF preference statements"
    print(json.dumps(report, sort_keys=True))
    sys.exit(1)

report["preference"] = preferences[0] if preferences else None
print(json.dumps(report, sort_keys=True))
"""
    result = dut.shell(
        "python3 -c {} {}".format(shlex.quote(source), shlex.quote(portchannel)),
        module_ignore_errors=True)
    diagnostic = "DF preference query for {}: rc={}, stdout={!r}, stderr={!r}".format(
        portchannel, result.get("rc"), result.get("stdout", "")[:1000],
        result.get("stderr", "")[:500])
    assert result.get("rc", 1) == 0, diagnostic
    try:
        report = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError):
        raise AssertionError(diagnostic)
    assert (report.get("native_rc") == 0
            and report.get("interface") == portchannel
            and report.get("interface_count") == 1
            and "preference" in report
            and "error" not in report), diagnostic
    preference = report["preference"]
    assert (preference is None or
            (type(preference) is int and 1 <= preference <= 65535)), diagnostic
    return preference


def _set_df_preference(dut, portchannel, preference):
    command = ("no evpn mh es-df-pref" if preference is None
               else "evpn mh es-df-pref {}".format(int(preference)))
    result = dut.shell(
        "vtysh -c 'configure terminal' -c 'interface {}' -c '{}'".format(
            portchannel, command), module_ignore_errors=True)
    assert result.get("rc", 1) == 0, result.get("stderr", result)


def _restore_df_preferences(duts, portchannel, original_preferences):
    """Attempt and verify every runtime-only FRR preference restoration."""
    failures = []
    for role, preference in sorted(original_preferences.items()):
        try:
            _set_df_preference(duts[role], portchannel, preference)
        except Exception as error:
            failures.append("{} restore command: {}".format(role, error))
    for role, preference in sorted(original_preferences.items()):
        try:
            actual = _df_preference(duts[role], portchannel)
        except Exception as error:
            failures.append("{} restore verification: {}".format(role, error))
            continue
        if actual != preference:
            failures.append(
                "{} preference is {!r}, expected {!r}".format(
                    role, actual, preference))
    if failures:
        raise AssertionError(
            "DF preference cleanup failed: {}".format("; ".join(failures)))


def _remote_segment_nhg_ready(remote_eos, topology, definition,
                              expected_roles):
    endpoint = topology["endpoints"][definition["endpoint"]]
    expected_vteps = {topology["vtep_ip"][role] for role in expected_roles}
    candidate_vteps = {
        topology["vtep_ip"][role]
        for role in ("mh_leaf0", "mh_leaf1")
    }
    evidence = collect_remote_eos_evidence(remote_eos)
    return (
        eos_contains_value(evidence["routes"], endpoint["mac"])
        and eos_contains_value(evidence["routes"], endpoint["ipv4"])
        and eos_contains_value(evidence["fdb"], endpoint["mac"])
        and eos_aliasing_vteps(
            evidence["routes"], endpoint["mac"], candidate_vteps
        ) == expected_vteps
    )


def _affected_dut_control_plane_ready(dut, topology):
    vnis = command_json(dut, "show evpn vni json")
    if not all(vni_is_present(vnis, vni)
               for vni in (topology["l2vni"], topology["l3vni"])):
        return False
    type5 = command_json(
        dut, "show bgp l2vpn evpn route type prefix json")
    return all(contains_prefix(type5, prefix) for prefix in (
        topology["remote_ipv4_prefix"], topology["remote_ipv6_prefix"]))


def _ipv6_control_plane_ready(duts, remote_eos, topology):
    segment_endpoints = [
        topology["endpoints"][definition["endpoint"]]
        for definition in topology["ethernet_segments"].values()
    ]
    for role in ("mh_leaf0", "mh_leaf1"):
        dut = duts[role]
        vnis = command_json(dut, "show evpn vni json")
        if not all(vni_is_present(vnis, vni)
                   for vni in (topology["l2vni"], topology["l3vni"])):
            return False
        type5 = command_json(
            dut, "show bgp l2vpn evpn route type prefix json")
        if not contains_prefix(type5, topology["remote_ipv6_prefix"]):
            return False
        for endpoint in segment_endpoints:
            if not neighbor_matches(
                    dut, topology["mh_vlan"], endpoint["ipv6"],
                    endpoint["mac"]):
                return False
    evidence = collect_remote_eos_evidence(remote_eos)
    if not eos_contains_value(
            evidence["routes"], topology["mh_ipv6_prefix"]):
        return False
    expected_vteps = {
        topology["vtep_ip"]["mh_leaf0"],
        topology["vtep_ip"]["mh_leaf1"],
    }
    for endpoint in segment_endpoints:
        if not (eos_contains_value(evidence["routes"], endpoint["mac"])
                and eos_contains_value(evidence["routes"], endpoint["ipv6"])
                and eos_contains_value(evidence["fdb"], endpoint["mac"])):
            return False
        if eos_aliasing_vteps(
                evidence["routes"], endpoint["mac"],
                expected_vteps) != expected_vteps:
            return False
    return True


def _mark_traffic_event(job, marker):
    """Create a PTF event marker and wait until the worker observes it."""
    if marker not in ("event_start_file", "event_end_file"):
        raise ValueError("unsupported traffic event marker")
    ack_marker = marker.replace("_file", "_ack_file")
    if ack_marker not in job:
        raise RuntimeError("traffic job lacks {}".format(ack_marker))
    result = job["ptfhost"].shell(
        "touch {}".format(shlex.quote(job[marker])),
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError("failed to create {}".format(marker))
    if not wait_until(
            10, 0.1, 0,
            lambda: job["ptfhost"].shell(
                "test -f {}".format(shlex.quote(job[ack_marker])),
                module_ignore_errors=True,
            ).get("rc", 1) == 0):
        raise RuntimeError(
            "PTF worker did not acknowledge {}".format(marker))


def _close_traffic_event(job, started_at, minimum_seconds):
    remaining = float(minimum_seconds) - (time.monotonic() - started_at)
    if remaining > 0:
        time.sleep(remaining)
    _mark_traffic_event(job, "event_end_file")


def _temporary_l3_service_ready(duts, topology, state):
    vlan = state["vlan"]
    member_key = "VLAN_MEMBER|Vlan{}|{}".format(
        vlan, state["source_interface"])
    if not _config_key_exists(duts[state["source_role"]], member_key):
        return False
    for role in ("mh_leaf0", "mh_leaf1"):
        dut = duts[role]
        if not _config_key_exists(dut, "VLAN|Vlan{}".format(vlan)):
            return False
        address = dut.shell(
            "ip -o address show dev Vlan{}".format(vlan),
            module_ignore_errors=True)
        if (address.get("rc", 1) != 0
                or state["gateway_prefix"] not in address.get("stdout", "").split()):
            return False
        if not vni_is_present(
                command_json(dut, "show evpn vni json"),
                topology["remote_l2vni"]):
            return False
    return True


def _l3_orphan_runtime(source_endpoint, receive_leg, forbidden_leg):
    return {"flow_overrides": {"l3_orphan_to_h2": {
        "tx_endpoint": source_endpoint,
        "receive_groups": [[receive_leg]],
        "forbidden_endpoints": [forbidden_leg],
    }}}


def _recovered_bum_runtime(duts, topology):
    return _df_runtime(duts, topology)


def _config_key_exists(dut, key):
    result = dut.shell(
        "sonic-db-cli CONFIG_DB EXISTS '{}'".format(key),
        module_ignore_errors=True)
    return result.get("rc", 1) == 0 and result.get("stdout", "").strip() == "1"


def _local_es_present(dut, topology, definition=None):
    definition = definition or _primary_segment(topology)[1]
    observed = ethernet_segment(
        command_json(dut, "show evpn es json"), definition["esi"])
    return observed is not None


def _underlay_path_count(dut, remote_vtep):
    routes = command_json(
        dut, "show ip route {}/32 json".format(remote_vtep))
    return route_nexthop_count(routes)


def _recover_lag_member(ptfhost, ports, leg, dut, portchannel):
    _run_cleanup_actions("LACP recovery", (
        ("bounce PTF member", lambda: bounce_ptf_member(
            ptfhost, "eth{}".format(ports[leg]))),
        ("verify PortChannel", lambda: _require_cleanup(
            wait_interface(dut, portchannel, True),
            "{} did not return up".format(portchannel))),
    ))


def _restore_physical_lag_member(ptfhost, ports, leg, dut, member,
                                 portchannel):
    """Attempt every physical/LACP recovery step and aggregate failures."""
    failures = []
    try:
        set_interface_admin(dut, member, True)
    except Exception as error:
        failures.append("member startup: {}".format(error))
    try:
        # Restart PTF LACP before waiting for a link that may depend on it.
        _recover_lag_member(ptfhost, ports, leg, dut, portchannel)
    except Exception as error:
        failures.append("LACP recovery: {}".format(error))
    try:
        if not wait_interface(dut, member, True, 90):
            raise AssertionError("{} did not return up".format(member))
    except Exception as error:
        failures.append("member operational recovery: {}".format(error))
    if failures:
        raise AssertionError("; ".join(failures))


def _checked_shell(host, command):
    result = host.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise AssertionError(
            "{} failed: {}".format(
                command,
                result.get("stderr", result.get("stdout", result))))
    return result


def _require_cleanup(condition, message):
    if not condition:
        raise AssertionError(message)


def _run_cleanup_actions(label, actions):
    """Attempt every ordered cleanup action and aggregate all evidence."""
    primary = sys.exc_info()[1]
    failures = []
    for action_label, action in actions:
        try:
            action()
        except Exception as error:
            failures.append("{}: {}".format(action_label, error))
    if failures:
        detail = "{} cleanup failed: {}".format(label, "; ".join(failures))
        if primary is not None:
            raise AssertionError(
                "{}; additionally, {}".format(primary, detail)) from primary
        raise AssertionError(detail)


def _persistence_recovery_actions(duts, topology, segment, dut, timeout):
    """Check the returning DUT even when reload/reboot raises or times out."""
    return [
        ("verify overlay recovery", lambda: _require_cleanup(
            wait_evpn_mh_overlay(duts, topology, timeout),
            "overlay did not recover")),
        ("verify local Ethernet Segments", lambda: _require_cleanup(all(
            _local_es_present(dut, topology, definition)
            for definition in topology["ethernet_segments"].values()),
            "returning DUT did not restore all local Ethernet Segments")),
        ("verify current DF", lambda: _require_cleanup(
            _df_role(duts, topology, segment) is not None,
            "returning Ethernet Segment lacks exactly one DF")),
        ("verify VNI and Type-5 state", lambda: _require_cleanup(wait_until(
            120, 5, 0, _affected_dut_control_plane_ready, dut, topology),
            "returning DUT did not recover exact L2/L3 VNI and Type-5 state")),
    ]


def _rib_prefix_present(dut, topology, prefix):
    routes = command_json(
        dut, "show bgp vrf {} {} unicast json".format(
            topology["vrf"], "ipv6" if ":" in prefix else "ipv4"))
    return contains_prefix(routes, prefix)


def test_local_bias(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                    evpn_mh_control_plane, evpn_mh_topology):
    duts = evpn_mh_control_plane
    _segment_name, segment = _primary_segment(evpn_mh_topology)
    portchannel = segment["portchannel"]
    original_df = _df_role(duts, evpn_mh_topology, segment)
    assert original_df is not None, "local-bias requires exactly one current DF"
    target_df = "mh_leaf1" if original_df == "mh_leaf0" else "mh_leaf0"
    original_preferences = {
        role: _df_preference(dut, portchannel) for role, dut in duts.items()
        if role in ("mh_leaf0", "mh_leaf1")
    }
    assert _wait_forwarding(
        ptfhost, "local_bias", evpn_mh_ptf_ports, evpn_mh_topology,
        runtime=_local_bias_runtime(duts))
    try:
        assert _df_role(duts, evpn_mh_topology, segment) == original_df, (
            "DF changed while preparing the local-bias preference event")
        _set_df_preference(duts[original_df], portchannel, 1)
        _set_df_preference(duts[target_df], portchannel, 1000)
        assert wait_until(
            90, 5, 0,
            lambda: _df_role(duts, evpn_mh_topology, segment) == target_df), (
                "DF did not move from {} to {}".format(original_df, target_df))
        assert _df_role(duts, evpn_mh_topology, segment) != original_df
        assert wait_evpn_mh_overlay(duts, evpn_mh_topology, 90), (
            "ES peer state did not remain converged during DF movement")
        assert _wait_forwarding(
            ptfhost, "local_bias", evpn_mh_ptf_ports, evpn_mh_topology,
            runtime=_local_bias_runtime(duts))
    finally:
        _run_cleanup_actions("local bias", (
            ("restore DF preferences", lambda: _restore_df_preferences(
                duts, portchannel, original_preferences)),
            ("verify original DF", lambda: _require_cleanup(wait_until(
                90, 5, 0,
                lambda: _df_role(duts, evpn_mh_topology, segment) == original_df),
                "DF did not return to original role {}".format(original_df))),
            ("verify recovered dataplane", lambda: _require_cleanup(
                _wait_forwarding(
                    ptfhost, "local_bias", evpn_mh_ptf_ports, evpn_mh_topology,
                    runtime=_local_bias_runtime(duts)),
                "local-bias forwarding did not recover")),
        ))


def test_remote_unicast_for_ecmp(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                 evpn_mh_control_plane, evpn_mh_topology,
                                 evpn_mh_interfaces, evpn_mh_remote_eos):
    _segment_name, segment = _primary_segment(evpn_mh_topology)
    legs = tuple(segment["ptf_member_roles"])
    assert _wait_forwarding(
        ptfhost, "remote_unicast_ecmp", evpn_mh_ptf_ports, evpn_mh_topology)
    try:
        assert wait_until(
            90, 3, 0, _remote_segment_nhg_ready,
            evpn_mh_remote_eos, evpn_mh_topology, segment,
            ("mh_leaf0", "mh_leaf1")), (
                "remote H2 MAC/FDB did not resolve to both MH VTEPs")
    except CommandUnavailableError as error:
        pytest.fail("EVPN Type-2 JSON capability unavailable: {}".format(error))
    leaf0 = evpn_mh_control_plane["mh_leaf0"]
    member = evpn_mh_interfaces[legs[0]]["interface"]
    try:
        with interface_down(leaf0, member, wait_recovery=False):
            assert wait_until(
                90, 3, 0, _remote_segment_nhg_ready,
                evpn_mh_remote_eos, evpn_mh_topology, segment,
                ("mh_leaf1",)), (
                    "remote H2 NHG did not reduce to the surviving MH VTEP")
            assert _wait_forwarding(
                ptfhost, "remote_unicast_ecmp", evpn_mh_ptf_ports,
                evpn_mh_topology,
                runtime=_ecmp_to_leg(legs[1], legs[0]))
    finally:
        _run_cleanup_actions("remote unicast ECMP", (
            ("recover physical member", lambda: _restore_physical_lag_member(
                ptfhost, evpn_mh_ptf_ports, legs[0], leaf0, member,
                segment["portchannel"])),
            ("verify overlay recovery", lambda: _require_cleanup(
                wait_evpn_mh_overlay(evpn_mh_control_plane, evpn_mh_topology),
                "overlay did not recover")),
            ("verify remote H2 NHG", lambda: _require_cleanup(wait_until(
                90, 3, 0, _remote_segment_nhg_ready,
                evpn_mh_remote_eos, evpn_mh_topology, segment,
                ("mh_leaf0", "mh_leaf1")),
                "remote H2 NHG did not restore both MH VTEPs")),
            ("verify recovered dataplane", lambda: _require_cleanup(
                _wait_forwarding(
                    ptfhost, "remote_unicast_ecmp", evpn_mh_ptf_ports,
                    evpn_mh_topology),
                "remote unicast ECMP forwarding did not recover")),
        ))


def test_portchannel_deconf(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                            evpn_mh_control_plane, evpn_mh_topology,
                            evpn_mh_interfaces):
    _segment_name, segment = _primary_segment(evpn_mh_topology)
    role = segment["leaf_roles"][0]
    leg = segment["ptf_member_roles"][0]
    peer = segment["leaf_roles"][1]
    dut = evpn_mh_control_plane[role]
    portchannel = segment["portchannel"]
    member = portchannel_members(dut, portchannel)
    assert len(member) == 1, "expected one local member in {}".format(portchannel)
    commands_remove = [
        "sudo config interface sys-mac remove {} {}".format(
            portchannel, segment["system_mac"]),
        "sudo config interface evpn-esi del {}".format(portchannel),
        "sudo config vlan member del {} {}".format(evpn_mh_topology["mh_vlan"], portchannel),
        "sudo config portchannel member del {} {}".format(portchannel, member[0]),
        "sudo config portchannel del {}".format(portchannel),
    ]
    assert _wait_forwarding(
        ptfhost, "remote_broadcast", evpn_mh_ptf_ports, evpn_mh_topology,
        runtime=_df_runtime(evpn_mh_control_plane, evpn_mh_topology))
    assert wait_interface(dut, portchannel, True, 30), (
        "PortChannel must be operational before deconfiguration")
    assert _local_es_present(dut, evpn_mh_topology, segment), (
        "local Ethernet Segment must exist before deconfiguration")
    baseline = portchannel_config_snapshot(
        dut, portchannel, member[0], evpn_mh_topology["mh_vlan"]
    )
    assert all(baseline.get(component) is not None for component in (
        "portchannel", "member", "vlan_member", "ethernet_segment"
    )), "PortChannel recovery snapshot is incomplete"
    assert baseline["portchannel"].get("system_mac") == segment["system_mac"], (
        "PortChannel recovery snapshot has an unexpected system MAC")
    mutation_started = False
    try:
        mutation_started = True
        for command in commands_remove:
            result = dut.shell(command, module_ignore_errors=True)
            assert result.get("rc", 1) == 0, result.get("stderr", result)
        assert not portchannel_members(dut, portchannel)
        assert not _config_key_exists(dut, "PORTCHANNEL|{}".format(portchannel))
        assert not _config_key_exists(
            dut, "VLAN_MEMBER|Vlan{}|{}".format(
                evpn_mh_topology["mh_vlan"], portchannel))
        assert wait_until(
            60, 3, 0,
            lambda: not _local_es_present(dut, evpn_mh_topology, segment))
        assert wait_until(
            90, 5, 0,
            lambda: _df_role(
                evpn_mh_control_plane, evpn_mh_topology, segment) == peer)
    finally:
        if mutation_started:
            actions = [(
                "reconcile PortChannel CONFIG_DB",
                lambda: restore_portchannel_config(
                    dut, portchannel, member[0],
                    evpn_mh_topology["mh_vlan"], baseline,
                ),
            )]
            actions.append((
                "recover H2 leg",
                lambda: _recover_lag_member(
                    ptfhost, evpn_mh_ptf_ports, leg, dut,
                    portchannel),
            ))
            actions.extend((
                ("verify PortChannel members", lambda: _require_cleanup(
                    portchannel_members(dut, portchannel) == member,
                    "PortChannel membership did not restore")),
                ("verify PortChannel configuration", lambda: _require_cleanup(
                    _config_key_exists(dut, "PORTCHANNEL|{}".format(portchannel)),
                    "PortChannel configuration did not restore")),
                ("verify VLAN membership", lambda: _require_cleanup(
                    _config_key_exists(dut, "VLAN_MEMBER|Vlan{}|{}".format(
                        evpn_mh_topology["mh_vlan"], portchannel)),
                    "PortChannel VLAN membership did not restore")),
                ("verify local ES", lambda: _require_cleanup(wait_until(
                    60, 3, 0, _local_es_present, dut, evpn_mh_topology, segment),
                    "local Ethernet Segment did not restore")),
                ("verify overlay recovery", lambda: _require_cleanup(
                    wait_evpn_mh_overlay(evpn_mh_control_plane, evpn_mh_topology),
                    "overlay did not recover")),
                ("verify recovered dataplane", lambda: _require_cleanup(
                    _wait_forwarding(
                        ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                        evpn_mh_topology, runtime=_recovered_bum_runtime(
                            evpn_mh_control_plane, evpn_mh_topology)),
                    "remote BUM did not recover after deconfiguration")),
            ))
            _run_cleanup_actions("PortChannel deconfiguration", actions)


def test_portchannel_flap(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                          evpn_mh_control_plane, evpn_mh_topology):
    segment_name, segment = _primary_segment(evpn_mh_topology)
    portchannel = segment["portchannel"]
    bond_name = _segment_bond(evpn_mh_ptf_lag, segment_name, segment)
    leaf_roles = tuple(segment["leaf_roles"])
    member_roles = tuple(segment["ptf_member_roles"])
    for role, leg, peer, peer_leg in (
            (leaf_roles[0], member_roles[0], leaf_roles[1], member_roles[1]),
            (leaf_roles[1], member_roles[1], leaf_roles[0], member_roles[0])):
        dut = evpn_mh_control_plane[role]
        try:
            assert wait_interface(dut, portchannel, True, 30), (
                "{} PortChannel was not operational before shutdown".format(
                    role))
            ptf_member = "eth{}".format(evpn_mh_ptf_ports[leg])
            assert wait_until(
                30, 2, 0, ptf_bond_member_operational,
                ptfhost, ptf_member, bond_name), (
                    "{} was not LACP selected before PortChannel shutdown"
                    .format(ptf_member))
            set_interface_admin(evpn_mh_control_plane[role], portchannel, False)
            assert wait_interface(evpn_mh_control_plane[role], portchannel, False, 45)
            assert wait_until(
                90, 5, 0,
                lambda: _df_role(
                    evpn_mh_control_plane, evpn_mh_topology, segment) == peer)
            assert _wait_forwarding(
                ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                evpn_mh_topology,
                runtime=_df_runtime(
                    evpn_mh_control_plane, evpn_mh_topology))
        finally:
            _run_cleanup_actions(
                "PortChannel flap {}".format(role),
                (
                    ("start PortChannel",
                     lambda: set_interface_admin(dut, portchannel, True)),
                    ("recover PTF leg",
                     lambda: _recover_lag_member(
                         ptfhost, evpn_mh_ptf_ports, leg, dut,
                         portchannel)),
                    ("verify overlay recovery", lambda: _require_cleanup(
                        wait_evpn_mh_overlay(
                            evpn_mh_control_plane, evpn_mh_topology),
                        "overlay did not recover")),
                    ("verify recovered dataplane", lambda: _require_cleanup(
                        _wait_forwarding(
                            ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                            evpn_mh_topology, runtime=_df_runtime(
                                evpn_mh_control_plane, evpn_mh_topology)),
                        "remote BUM did not recover after PortChannel flap")),
                ),
            )


def test_interface_to_spine_flap(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                 evpn_mh_control_plane, evpn_mh_topology,
                                 evpn_mh_interfaces):
    dut = evpn_mh_control_plane["mh_leaf0"]
    uplinks = evpn_mh_interfaces["mh_leaf0_spine"]["interfaces"]
    assert len(uplinks) == 3, "3->2->1 requires exactly three independent T1 links"
    remote_vtep = evpn_mh_topology["vtep_ip"]["remote_leaf"]
    assert wait_until(
        90, 5, 0, lambda: _underlay_path_count(dut, remote_vtep) == 3)
    assert _wait_forwarding(
        ptfhost, "remote_broadcast", evpn_mh_ptf_ports, evpn_mh_topology,
        runtime=_df_runtime(evpn_mh_control_plane, evpn_mh_topology))
    down = []
    try:
        for expected_paths, uplink in zip((2, 1), uplinks[:2]):
            assert wait_interface(dut, uplink, True, 30), (
                "{} was not operational before underlay shutdown".format(
                    uplink))
            assert _underlay_path_count(
                dut, remote_vtep) == expected_paths + 1, (
                    "underlay path count changed before shutting {}".format(
                        uplink))
            # Register rollback ownership before the first mutation.  A CLI
            # wrapper can report failure after the shutdown already applied.
            down.append(uplink)
            set_interface_admin(dut, uplink, False)
            assert wait_interface(dut, uplink, False, 45)
            assert wait_until(
                90, 5, 0,
                lambda expected=expected_paths: _underlay_path_count(
                    dut, remote_vtep) == expected)
            assert _wait_forwarding(
                ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                evpn_mh_topology,
                runtime=_df_runtime(
                    evpn_mh_control_plane, evpn_mh_topology))
    finally:
        _run_cleanup_actions("spine interface flap", (
            ("restore uplinks", lambda: restore_interfaces(
                dut, reversed(down), timeout=90)),
            ("verify three underlay paths", lambda: _require_cleanup(wait_until(
                120, 5, 0, lambda: _underlay_path_count(dut, remote_vtep) == 3),
                "underlay did not restore all three paths")),
            ("verify overlay recovery", lambda: _require_cleanup(
                wait_evpn_mh_overlay(evpn_mh_control_plane, evpn_mh_topology),
                "overlay did not recover")),
            ("verify recovered dataplane", lambda: _require_cleanup(
                _wait_forwarding(
                    ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                    evpn_mh_topology, runtime=_df_runtime(
                        evpn_mh_control_plane, evpn_mh_topology)),
                "remote BUM did not recover after underlay flap")),
        ))


def test_vlan_member_flap(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                          evpn_mh_control_plane, evpn_mh_topology,
                          evpn_mh_interfaces):
    endpoint = evpn_mh_interfaces["sh1"]
    dut = evpn_mh_control_plane[endpoint["dut_role"]]
    interface = endpoint["interface"]
    vlan = evpn_mh_topology["mh_vlan"]
    key = "VLAN_MEMBER|Vlan{}|{}".format(vlan, interface)
    assert wait_interface(dut, interface, True, 30), (
        "SH1 physical link must be up before VLAN membership removal")
    assert _config_key_exists(dut, key), (
        "SH1 VLAN membership must exist before removal")
    try:
        result = dut.shell(
            "sudo config vlan member del {} {}".format(vlan, interface),
            module_ignore_errors=True)
        assert result.get("rc", 1) == 0, result.get("stderr", result)
        assert wait_until(30, 2, 0, lambda: not _config_key_exists(dut, key))
        assert wait_interface(dut, interface, True, 30), (
            "case 11 must not flap the SH1 physical link")
        # This profile succeeds only when no matching packet escapes the
        # detached access attachment.  Runner, parser and transport failures
        # still fail the testcase instead of being mistaken for packet loss.
        _run(
            ptfhost, "vlan_detached_drop", evpn_mh_ptf_ports,
            evpn_mh_topology)
    finally:
        _run_cleanup_actions(
            "VLAN member flap",
            (
                ("restore VLAN membership", lambda: _checked_shell(
                    dut,
                    "sudo config vlan member add -u {} {}".format(
                        vlan, interface))),
                ("verify VLAN membership", lambda: _require_cleanup(
                    wait_until(30, 2, 0, _config_key_exists, dut, key),
                    "SH1 VLAN membership did not return")),
                ("verify physical link remains up", lambda: _require_cleanup(
                    wait_interface(dut, interface, True, 30),
                    "SH1 physical link changed during VLAN restore")),
                ("verify recovered dataplane", lambda: _require_cleanup(
                    _wait_forwarding(
                        ptfhost, "intra_subnet", evpn_mh_ptf_ports,
                        evpn_mh_topology),
                    "intra-subnet forwarding did not recover")),
            ),
        )


def test_portchannel_shut_noshut(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                 evpn_mh_control_plane, evpn_mh_topology,
                                 evpn_mh_interfaces):
    _segment_name, segment = _primary_segment(evpn_mh_topology)
    portchannel = segment["portchannel"]
    upper_role, peer = tuple(segment["leaf_roles"])
    leg, peer_leg = tuple(segment["ptf_member_roles"])
    original_df = _df_role(
        evpn_mh_control_plane, evpn_mh_topology, segment)
    assert original_df is not None, (
        "routed orphan testcase requires one current DF")
    original_preferences = {
        role: _df_preference(dut, portchannel)
        for role, dut in evpn_mh_control_plane.items()
        if role in segment["leaf_roles"]
    }
    source_endpoint = "sh1"
    source_interface = evpn_mh_interfaces[source_endpoint]["interface"]
    member = evpn_mh_interfaces[leg]["interface"]
    orphan = temporary_l3_orphan_endpoint(evpn_mh_topology)
    routed_topology = deepcopy(evpn_mh_topology)
    routed_topology["endpoints"]["l3_orphan"] = orphan
    service_state = {
        "vlan": int(evpn_mh_topology["remote_vlan"]),
        "gateway_prefix": "{}/{}".format(
            orphan["gateway_ipv4"], orphan["ipv4_prefixlen"]),
        "host_prefix": "{}/{}".format(
            orphan["ipv4"], orphan["ipv4_prefixlen"]),
        "source_role": upper_role,
        "source_interface": source_interface,
    }
    mutation_started = False
    try:
        # The new topology has one single-homed source, on the upper ToR.
        # Deterministically make that ToR the target ES's DF, then restore the
        # exact runtime-only FRR preferences in the outer finalizer.
        _set_df_preference(
            evpn_mh_control_plane[upper_role], portchannel, 1000)
        _set_df_preference(evpn_mh_control_plane[peer], portchannel, 1)
        assert wait_until(
            90, 5, 0,
            lambda: _df_role(
                evpn_mh_control_plane, evpn_mh_topology,
                segment) == upper_role), (
                    "upper ToR did not become DF for routed SH1 testcase")
        mutation_started = True
        configure_temporary_l3_orphan(
            evpn_mh_control_plane, upper_role, source_interface,
            evpn_mh_topology, orphan)
        assert wait_until(
            90, 3, 0, _temporary_l3_service_ready,
            evpn_mh_control_plane, evpn_mh_topology, service_state), (
                "tagged VLAN{}/L2VNI{} orphan service did not converge".format(
                    evpn_mh_topology["remote_vlan"],
                    evpn_mh_topology["remote_l2vni"]))
        assert _wait_forwarding(
            ptfhost, "l3_orphan_to_mh", evpn_mh_ptf_ports,
            routed_topology,
            runtime=_l3_orphan_runtime(source_endpoint, leg, peer_leg))
        assert _df_role(
            evpn_mh_control_plane, evpn_mh_topology,
            segment) == upper_role, (
            "DF changed while preparing the routed orphan member outage")
        try:
            with interface_down(
                    evpn_mh_control_plane[upper_role], member,
                    wait_recovery=False):
                assert wait_until(
                    90, 5, 0,
                    lambda: _df_role(
                        evpn_mh_control_plane, evpn_mh_topology,
                        segment) == peer), (
                            "peer did not take DF after {} member outage".format(
                                upper_role))
                assert _wait_forwarding(
                    ptfhost, "l3_orphan_to_mh", evpn_mh_ptf_ports,
                    routed_topology,
                    runtime=_l3_orphan_runtime(
                        source_endpoint, peer_leg, leg))
        finally:
            _run_cleanup_actions("routed orphan member", (
                ("recover physical member", lambda: _restore_physical_lag_member(
                    ptfhost, evpn_mh_ptf_ports, leg,
                    evpn_mh_control_plane[upper_role], member, portchannel)),
            ))
        assert wait_evpn_mh_overlay(
            evpn_mh_control_plane, evpn_mh_topology)
        assert wait_until(
            90, 5, 0,
            lambda: _df_role(
                evpn_mh_control_plane, evpn_mh_topology,
                segment) == upper_role), (
                    "forced upper DF did not recover after member no-shut")
        assert _wait_forwarding(
            ptfhost, "l3_orphan_to_mh", evpn_mh_ptf_ports,
            routed_topology,
            runtime=_l3_orphan_runtime(source_endpoint, leg, peer_leg))
    finally:
        cleanup_actions = []
        if mutation_started:
            cleanup_actions.append((
                "remove temporary routed SH1 service",
                lambda: remove_temporary_l3_orphan(
                    evpn_mh_control_plane, evpn_mh_topology,
                    service_state),
            ))
        cleanup_actions.append((
            "restore DF preferences",
            lambda: _restore_df_preferences(
                evpn_mh_control_plane, portchannel,
                original_preferences),
        ))
        cleanup_actions.extend((
            ("verify overlay recovery", lambda: _require_cleanup(
                wait_evpn_mh_overlay(evpn_mh_control_plane, evpn_mh_topology),
                "overlay did not recover")),
            ("verify original DF", lambda: _require_cleanup(wait_until(
                90, 5, 0,
                lambda: _df_role(
                    evpn_mh_control_plane, evpn_mh_topology, segment) == original_df),
                "original DF did not return after SH1 testcase cleanup")),
        ))
        _run_cleanup_actions("PortChannel shut/no-shut", cleanup_actions)


def test_portchannel_member_flap(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                 evpn_mh_control_plane, evpn_mh_topology,
                                 evpn_mh_interfaces):
    segment_name, segment = _primary_segment(evpn_mh_topology)
    portchannel = segment["portchannel"]
    bond_name = _segment_bond(evpn_mh_ptf_lag, segment_name, segment)
    leg0, leg1 = tuple(segment["ptf_member_roles"])
    event_window = traffic_event_window("member_flap_continuous")
    for leg, surviving_leg in ((leg0, leg1), (leg1, leg0)):
        endpoint = evpn_mh_interfaces[leg]
        dut = evpn_mh_control_plane[endpoint["dut_role"]]
        member = endpoint["interface"]
        members = portchannel_members(
            dut, portchannel)
        assert member in members, (
            "{} is not a physical member of {}".format(
                member, portchannel))
        transition_job = start_traffic_profile(
            ptfhost, "member_flap_continuous", evpn_mh_ptf_ports,
            evpn_mh_topology,
            runtime={"flow_overrides": {
                "h3_to_h2_during_member_flap": {
                    "receive_groups": [[surviving_leg, leg]],
                    "forbidden_endpoints": [],
                },
            }})
        transition_started = None
        transition_ended = False
        outage_job = None
        outage_started = None
        outage_ended = False
        recovery_job = None
        recovery_started = None
        recovery_ended = False
        mutation_attempted = False
        try:
            # A configured PortChannel member is not necessarily an active
            # physical path.  Prove this iteration will cause a real down
            # transition before opening the acknowledged grading window.
            _require_cleanup(
                wait_interface(dut, member, True, 30),
                "{} was not operationally up before member flap".format(
                    member))
            ptf_member = "eth{}".format(evpn_mh_ptf_ports[leg])
            _require_cleanup(
                wait_until(
                    30, 2, 0, ptf_bond_member_operational,
                    ptfhost, ptf_member, bond_name),
                "{} was not LACP selected/collecting/distributing before "
                "member flap".format(ptf_member))
            # Grade the down transition with either currently-valid leg.  The
            # acknowledgement prevents shutdown from racing ahead of the PTF
            # sequence boundary; the leg is not declared forbidden until its
            # operational-down state is proven.
            _mark_traffic_event(transition_job, "event_start_file")
            transition_started = time.monotonic()
            mutation_attempted = True
            set_interface_admin(dut, member, False)
            _require_cleanup(
                wait_interface(dut, member, False, 45),
                "physical member did not remain down")
            _close_traffic_event(
                transition_job, transition_started, event_window)
            transition_ended = True
            try:
                finish_traffic_profile(transition_job, 60)
            finally:
                transition_job = None

            # Once physical down is proven, grade a strict steady-outage
            # window: only the survivor can receive and the failed leg is
            # forbidden with the profile's zero-copy allowance.
            outage_job = start_traffic_profile(
                ptfhost, "member_flap_continuous", evpn_mh_ptf_ports,
                evpn_mh_topology,
                runtime={"flow_overrides": {
                    "h3_to_h2_during_member_flap": {
                        "receive_groups": [[surviving_leg]],
                        "forbidden_endpoints": [leg],
                    },
                }})
            _mark_traffic_event(outage_job, "event_start_file")
            outage_started = time.monotonic()
            _close_traffic_event(outage_job, outage_started, event_window)
            outage_ended = True
            try:
                finish_traffic_profile(outage_job, 60)
            finally:
                outage_job = None

            # Grade the up/LACP/DF transition separately.  Either physical leg
            # is valid after restoration, so the outage-only forbidden-leg
            # assertion must not leak into this phase.
            recovery_job = start_traffic_profile(
                ptfhost, "member_flap_continuous", evpn_mh_ptf_ports,
                evpn_mh_topology,
                runtime={"flow_overrides": {
                    "h3_to_h2_during_member_flap": {
                        "receive_groups": [[surviving_leg, leg]],
                        "forbidden_endpoints": [],
                    },
                }})
            _mark_traffic_event(recovery_job, "event_start_file")
            recovery_started = time.monotonic()
            _restore_physical_lag_member(
                ptfhost, evpn_mh_ptf_ports, leg, dut, member,
                portchannel)
            mutation_attempted = False
            _require_cleanup(
                wait_evpn_mh_overlay(
                    evpn_mh_control_plane, evpn_mh_topology),
                "overlay did not recover")
            _close_traffic_event(
                recovery_job, recovery_started, event_window)
            recovery_ended = True
            try:
                finish_traffic_profile(recovery_job, 60)
            finally:
                recovery_job = None
        finally:
            cleanup_actions = []
            if transition_job is not None:
                if transition_started is not None and not transition_ended:
                    cleanup_actions.append((
                        "close down-transition event",
                        lambda: _close_traffic_event(
                            transition_job, transition_started, event_window),
                    ))
                cleanup_actions.append((
                    "finish down-transition traffic",
                    lambda: finish_traffic_profile(transition_job, 60),
                ))
            if outage_job is not None:
                if outage_started is not None and not outage_ended:
                    cleanup_actions.append((
                        "close outage event", lambda: _close_traffic_event(
                            outage_job, outage_started, event_window),
                    ))
                cleanup_actions.append((
                    "finish outage traffic", lambda: finish_traffic_profile(
                        outage_job, 60),
                ))
            if mutation_attempted:
                cleanup_actions.append((
                    "recover physical member",
                    lambda: _restore_physical_lag_member(
                        ptfhost, evpn_mh_ptf_ports, leg, dut, member,
                        portchannel),
                ))
            cleanup_actions.append((
                "verify overlay recovery", lambda: _require_cleanup(
                    wait_evpn_mh_overlay(
                        evpn_mh_control_plane, evpn_mh_topology),
                    "overlay did not recover"),
            ))
            if recovery_job is not None:
                if recovery_started is not None and not recovery_ended:
                    cleanup_actions.append((
                        "close recovery event", lambda: _close_traffic_event(
                            recovery_job, recovery_started, event_window),
                    ))
                cleanup_actions.append((
                    "finish recovery traffic", lambda: finish_traffic_profile(
                        recovery_job, 60),
                ))
            cleanup_actions.append(
                ("verify recovered dataplane", lambda: _require_cleanup(
                    _wait_forwarding(
                        ptfhost, "remote_broadcast",
                        evpn_mh_ptf_ports, evpn_mh_topology,
                        runtime=_df_runtime(
                            evpn_mh_control_plane,
                            evpn_mh_topology)),
                    "remote BUM did not recover after member restore"))
            )
            _run_cleanup_actions(
                "PortChannel member flap {}".format(leg),
                cleanup_actions,
            )
    assert wait_evpn_mh_overlay(evpn_mh_control_plane, evpn_mh_topology)


def test_config_reload(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                       evpn_mh_control_plane, evpn_mh_topology,
                       evpn_mh_interfaces, evpn_mh_routed_egress):
    from tests.common.config_reload import config_reload

    _segment_name, segment = _primary_segment(evpn_mh_topology)
    assert _wait_forwarding(
        ptfhost, "remote_routed_bum", evpn_mh_ptf_ports, evpn_mh_topology)
    df = _df_role(evpn_mh_control_plane, evpn_mh_topology, segment)
    assert df is not None, "config reload requires one current DF"
    if not uses_frrcfgd(evpn_mh_control_plane[df]):
        pytest.fail(
            "config reload persistence requires a model-driven frrcfgd image")
    assert _df_role(
        evpn_mh_control_plane, evpn_mh_topology, segment) == df, (
        "DF changed while binding the config-reload target")
    try:
        config_reload(evpn_mh_control_plane[df], safe_reload=True,
                      wait_for_bgp=True)
    finally:
        actions = _persistence_recovery_actions(
            evpn_mh_control_plane, evpn_mh_topology, segment,
            evpn_mh_control_plane[df], 300)
        for prefix in (
                evpn_mh_topology["mh_ipv4_prefix"],
                evpn_mh_topology["remote_ipv4_prefix"],
                evpn_mh_topology["mh_ipv6_prefix"],
                evpn_mh_topology["remote_ipv6_prefix"]):
            actions.append((
                "verify restored prefix {}".format(prefix),
                lambda prefix=prefix: _require_cleanup(
                    _rib_prefix_present(
                        evpn_mh_control_plane[df], evpn_mh_topology, prefix),
                    "{} missing after reload".format(prefix)),
            ))
        actions.append((
            "verify recovered dataplane", lambda: _require_cleanup(
                _wait_forwarding(
                    ptfhost, "remote_routed_bum", evpn_mh_ptf_ports,
                    evpn_mh_topology),
                "routed BUM did not recover after config reload"),
        ))
        _run_cleanup_actions("config reload", actions)


def test_continuous_traffic_reboot_df(
        ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
        evpn_mh_control_plane, evpn_mh_topology,
        evpn_mh_interfaces, localhost, evpn_mh_routed_egress):
    _segment_name, segment_definition = _primary_segment(evpn_mh_topology)
    assert _wait_forwarding(
        ptfhost, "remote_routed_bum", evpn_mh_ptf_ports, evpn_mh_topology)
    # Resolve and validate the grading contract before any worker is started.
    event_window = traffic_event_window("df_reboot_continuous")
    for role, candidate in sorted(evpn_mh_control_plane.items()):
        if not uses_frrcfgd(candidate):
            pytest.fail(
                "cold-reboot persistence requires model-driven frrcfgd on {}"
                .format(role))
    df = None
    dut = None
    peer = None
    returning_leg = None
    observed_df_roles = []
    stop_observer = threading.Event()
    reboot_observation_gate = threading.Event()
    traffic_job = None
    observer = None
    event_started = None

    def observe_df_takeover():
        while not stop_observer.is_set():
            if not reboot_observation_gate.wait(timeout=0.1):
                continue
            for role in ("mh_leaf0", "mh_leaf1"):
                try:
                    observed = ethernet_segment(
                        command_json(
                            evpn_mh_control_plane[role], "show evpn es json"),
                        segment_definition["esi"])
                    if observed is not None and segment_is_df(observed):
                        observed_df_roles.append(role)
                except RuntimeError:
                    continue
            time.sleep(2)

    try:
        traffic_job = start_traffic_profile(
            ptfhost, "df_reboot_continuous", evpn_mh_ptf_ports,
            evpn_mh_topology)
        # ACK first, then bind the reboot target to the DF that is current at
        # the event boundary.  No pre-event observation can satisfy takeover.
        _mark_traffic_event(traffic_job, "event_start_file")
        event_started = time.monotonic()
        df = _df_role(
            evpn_mh_control_plane, evpn_mh_topology,
            segment_definition)
        assert df is not None, "cold reboot requires one current DF"
        dut = evpn_mh_control_plane[df]
        role_to_leg = dict(zip(
            segment_definition["leaf_roles"],
            segment_definition["ptf_member_roles"]))
        returning_leg = role_to_leg[df]
        peer = next(
            role for role in segment_definition["leaf_roles"] if role != df)
        observed_df_roles.clear()
        observer = threading.Thread(target=observe_df_takeover)
        observer.daemon = True
        observer.start()
        # Reconfirm the selected target immediately before opening the
        # takeover-observation gate and invoking cold reboot.
        assert _df_role(
            evpn_mh_control_plane, evpn_mh_topology,
            segment_definition) == df, (
            "DF changed while binding the cold-reboot target")
        from tests.common.reboot import REBOOT_TYPE_COLD, reboot
        reboot_observation_gate.set()
        reboot(dut, localhost, reboot_type=REBOOT_TYPE_COLD,
               safe_reboot=True, wait_for_bgp=True)
    finally:
        cleanup_actions = []
        if dut is not None:
            # Keep the original recovery checks inside the graded traffic
            # window and DF observation, even when the reboot helper raises.
            cleanup_actions.extend(_persistence_recovery_actions(
                evpn_mh_control_plane, evpn_mh_topology,
                segment_definition, dut, 360))
        if observer is not None:
            def join_observer():
                stop_observer.set()
                observer.join(timeout=10)
                if observer.is_alive():
                    raise RuntimeError(
                        "DF observer did not stop after its bounded join")
            cleanup_actions.append(("stop DF observer", join_observer))
        if event_started is not None and traffic_job is not None:
            remaining = event_window - (time.monotonic() - event_started)
            if remaining > 0:
                time.sleep(remaining)
            cleanup_actions.append((
                "mark event end",
                lambda: _mark_traffic_event(traffic_job, "event_end_file"),
            ))
        if traffic_job is not None:
            cleanup_actions.append((
                "finish continuous traffic",
                lambda: finish_traffic_profile(traffic_job, 90),
            ))
            if returning_leg is not None and dut is not None:
                cleanup_actions.extend((
                    # Renegotiate only after PTF released its long-lived capture.
                    ("renegotiate returning PTF member",
                     lambda: bounce_ptf_member(
                         ptfhost,
                         "eth{}".format(evpn_mh_ptf_ports[returning_leg]))),
                    ("verify returning PortChannel", lambda: _require_cleanup(
                        wait_interface(
                            dut, segment_definition["portchannel"], True, 90),
                        "rebooted PortChannel did not return")),
                ))
        if dut is not None:
            cleanup_actions.append((
                "verify recovered dataplane", lambda: _require_cleanup(
                    _wait_forwarding(
                        ptfhost, "remote_routed_bum", evpn_mh_ptf_ports,
                        evpn_mh_topology),
                    "routed BUM did not recover after cold reboot"),
            ))
        _run_cleanup_actions("DF cold reboot", cleanup_actions)
    assert peer in observed_df_roles, (
        "peer {} never became DF during {} reboot".format(peer, df))


def test_ipv6_traffic(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                      evpn_mh_control_plane, evpn_mh_remote_eos,
                      evpn_mh_topology, evpn_mh_routed_egress):
    _assert_bum_control_plane(
        evpn_mh_control_plane, evpn_mh_remote_eos, evpn_mh_topology)
    _run(
        ptfhost, "ipv6_baseline", evpn_mh_ptf_ports, evpn_mh_topology,
        runtime=_df_runtime(evpn_mh_control_plane, evpn_mh_topology))
    try:
        assert wait_until(
            90, 3, 0, _ipv6_control_plane_ready,
            evpn_mh_control_plane, evpn_mh_remote_eos,
            evpn_mh_topology), (
                "exact IPv6 Type-5, NDP, VNI and aliased L2 NHG state "
                "did not converge")
    except CommandUnavailableError as error:
        pytest.fail("IPv6 EVPN JSON capability unavailable: {}".format(error))
