"""
Unit tests for tests/common/devices/csonic.py (CsonicHost).

CsonicHost mirrors the EosHost/SonicHost neighbor API for cSONiC
(docker-sonic-vs) neighbors by parsing FRR/vtysh JSON obtained via
``_docker_exec``. These tests mock ``_docker_exec`` with representative FRR
JSON so the pure parsing/merging logic can be verified without a live
container. They cover:

  * minigraph_facts        - synthesizing {'minigraph_bgp': [...]} from FRR
                             ``show ip/ipv6 bgp neighbors json``
  * check_bgp_session_state - reading ``show bgp <afi> summary json`` and
                             deciding established-ness
  * _bgp_summary_peers      - summary parsing + FRR address-family nesting
  * _bgp_neighbors_json     - neighbors parsing + malformed-output handling
  * get_route              - ``show bgp ipv4|ipv6 unicast <prefix> json``
                             (SonicHost-compatible shape, {} on error)

Follows the repo unit-test convention (unit_test_*.py, unittest.mock).
"""

import os
import sys
from unittest.mock import patch

import pytest

# Make the repo root importable so ``tests.common.devices.csonic`` resolves
# regardless of the pytest invocation directory.
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.devices.csonic import CsonicHost  # noqa: E402


def make_host():
    """Instantiate a CsonicHost without touching Docker (init does no I/O)."""
    return CsonicHost("csonic_test_VM0100")


def make_converged_host():
    return CsonicHost(
        "csonic_test_VM0100",
        bgp_vrf="VrfARISTA02T1",
        bgp_prime_asn=64600,
        intf_map={
            "Ethernet1": "Ethernet2",
            "Port-Channel1": "Port-Channel2",
            "Loopback0": "Loopback2",
        },
    )


def docker_ok(stdout):
    """Shape a successful _docker_exec return with the given stdout."""
    return {"rc": 0, "stdout": stdout, "stderr": ""}


# --- FRR JSON fixtures -----------------------------------------------------

# ``show ip bgp neighbors json`` (v4) / ``show bgp ipv6 neighbors json`` (v6)
NEIGHBORS_V4 = {
    "10.0.0.56": {"hostname": "dut-1", "remoteAs": 65100},
    "10.0.0.58": {"hostname": "Unknown", "remoteAs": "64600"},
}
NEIGHBORS_V6 = {
    "FC00::71": {"hostname": "dut-1", "remoteAs": "not-a-number"},
}

# ``show bgp vrf default ipv4 summary json`` etc.
SUMMARY_V4 = {
    "ipv4Unicast": {
        "peers": {
            "10.0.0.56": {"state": "Established", "description": "DUT"},
            "10.0.0.58": {"state": "Active"},
        }
    }
}
SUMMARY_V6 = {
    "ipv6Unicast": {
        "peers": {
            "fc00::71": {"state": "Established"},
        }
    }
}


def route_docker_exec(cmd, **kwargs):
    """Dispatch mock: return the right FRR JSON based on the vtysh command."""
    import json as _json
    if "show ip bgp neighbors json" in cmd or "ipv4 unicast neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V4))
    if "show bgp ipv6 neighbors json" in cmd or "ipv6 unicast neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V6))
    if "ipv4 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V4))
    if "ipv6 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V6))
    return {"rc": 1, "stdout": "", "stderr": "unexpected cmd"}


# --- minigraph_facts -------------------------------------------------------

class TestStockHostInvariance:
    def test_commands_pass_through_unchanged(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.command("show interfaces Port-Channel1 status")
        assert mock_exec.call_args[0][0] == "show interfaces Port-Channel1 status"
        assert host._interface_name("Port-Channel1") == "Port-Channel1"

    def test_config_command_keeps_historical_shape(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.config(lines=["shutdown"], parents=["router bgp 64600"])
        assert mock_exec.call_args[0][0] == (
            "vtysh -c 'configure terminal' -c 'router bgp 64600' -c 'shutdown'")

    def test_neighbor_queries_keep_historical_commands(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("{}")) as mock_exec:
            host._bgp_neighbors_json("ipv4")
            host._bgp_neighbors_json("ipv6")
        commands = [invocation.args[0] for invocation in mock_exec.call_args_list]
        assert commands == [
            "vtysh -c 'show ip bgp neighbors json'",
            "vtysh -c 'show bgp ipv6 neighbors json'",
        ]

    def test_hash_and_equality_remain_container_based(self):
        first = make_host()
        second = make_host()
        assert first == second
        assert hash(first) == hash(first.container_name)
        assert len({first, second}) == 1


class TestMinigraphFacts:
    def test_flat_shape_and_contents(self):
        """Returns the flat {'minigraph_bgp': [...]} shape the ospf/conftest
        caller consumes (it reads mg['minigraph_bgp'] directly, NOT
        mg['ansible_facts']['minigraph_bgp'])."""
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            facts = host.minigraph_facts(host="dut-1")
        assert set(facts.keys()) == {"minigraph_bgp"}
        entries = facts["minigraph_bgp"]
        # 2 v4 peers + 1 v6 peer, all distinct IPs
        assert len(entries) == 3
        by_addr = {e["addr"]: e for e in entries}
        assert by_addr["10.0.0.56"]["name"] == "dut-1"
        assert by_addr["10.0.0.56"]["asn"] == 65100          # int passthrough
        assert by_addr["10.0.0.58"]["asn"] == 64600          # numeric string -> int
        # exabgp-style injectors are still included with FRR's 'Unknown' name
        assert by_addr["10.0.0.58"]["name"] == "Unknown"

    def test_asn_parse_failure_is_none(self):
        """A non-numeric remoteAs yields asn=None (loud), not the raw string,
        so a downstream ``== <int asn>`` comparison fails predictably."""
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            facts = host.minigraph_facts()
        v6 = next(e for e in facts["minigraph_bgp"] if e["addr"] == "FC00::71")
        assert v6["asn"] is None

    def test_dedup_is_case_insensitive(self):
        """If FRR ever reports the same peer under both AFIs with differing
        case, it is counted once (dedup key is normalized)."""
        host = make_host()
        dup_v6 = {"10.0.0.56": {"hostname": "dut-1", "remoteAs": 65100}}

        def side(cmd, **kwargs):
            import json as _json
            if "show ip bgp neighbors json" in cmd or "ipv4 unicast neighbors json" in cmd:
                return docker_ok(_json.dumps({"10.0.0.56": {"hostname": "dut-1", "remoteAs": 65100}}))
            if "show bgp ipv6 neighbors json" in cmd or "ipv6 unicast neighbors json" in cmd:
                return docker_ok(_json.dumps(dup_v6))
            return {"rc": 1, "stdout": "", "stderr": ""}

        with patch.object(host, "_docker_exec", side_effect=side):
            facts = host.minigraph_facts()
        assert len(facts["minigraph_bgp"]) == 1

    def test_empty_when_frr_unavailable(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value={"rc": 1, "stdout": "", "stderr": "down"}):
            assert host.minigraph_facts() == {"minigraph_bgp": []}


# --- check_bgp_session_state ----------------------------------------------

class TestCheckBgpSessionState:
    def test_all_established_true(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            assert host.check_bgp_session_state(["10.0.0.56"]) is True

    def test_case_insensitive_v6_match(self):
        """Caller may pass an uppercase v6 IP; summary keys are lowercased."""
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            assert host.check_bgp_session_state(["FC00::71"]) is True

    def test_not_established_false(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            # 10.0.0.58 is Active, not Established
            assert host.check_bgp_session_state(["10.0.0.58"]) is False

    def test_v4_and_v6_both_required(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            assert host.check_bgp_session_state(["10.0.0.56", "fc00::71"]) is True

    def test_empty_summary_returns_false(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value={"rc": 1, "stdout": "", "stderr": "no frr"}):
            assert host.check_bgp_session_state(["10.0.0.56"]) is False

    def test_description_matching(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            # description present for 10.0.0.56 ("DUT"); matching desc passes
            assert host.check_bgp_session_state(["10.0.0.56"], neigh_desc=["DUT"]) is True
            # wrong description fails when FRR does report one
            assert host.check_bgp_session_state(["10.0.0.56"], neigh_desc=["OTHER"]) is False


# --- bgpd restart / config replay -----------------------------------------

class TestStartBgpd:
    def test_stock_host_keeps_bgpcfgd_restart_behavior(self):
        host = make_host()

        def side(command, **kwargs):
            if command == "supervisorctl start bgpd":
                return docker_ok("bgpd: started")
            if command == "supervisorctl status bgpd":
                return docker_ok("bgpd RUNNING")
            if command == "supervisorctl restart bgpcfgd":
                return {"rc": 1, "stdout": "", "stderr": "restart failed"}
            raise AssertionError(command)

        with patch.object(host, "_docker_exec", side_effect=side):
            result = host.start_bgpd()
        assert result["rc"] == 0

    def test_converged_host_surfaces_frrcfgd_restart_failure(self):
        host = make_converged_host()

        def side(command, **kwargs):
            if command == "supervisorctl start bgpd":
                return docker_ok("bgpd: started")
            if command == "supervisorctl status bgpd":
                return docker_ok("bgpd RUNNING")
            if command == "supervisorctl restart frrcfgd":
                return {"rc": 1, "stdout": "", "stderr": "restart failed"}
            raise AssertionError(command)

        with patch.object(host, "_docker_exec", side_effect=side):
            result = host.start_bgpd()
        assert result["rc"] == 1
        assert result["stderr"] == "restart failed"

    def test_converged_host_waits_for_logical_vrf_after_frrcfgd_restart(self):
        host = make_converged_host()
        calls = []

        def side(command, **kwargs):
            calls.append(command)
            if command == "supervisorctl start bgpd":
                return docker_ok("bgpd: started")
            if command == "supervisorctl status bgpd":
                return docker_ok("bgpd RUNNING")
            if command == "supervisorctl restart frrcfgd":
                return docker_ok("frrcfgd: restarted")
            if "show bgp vrf VrfARISTA02T1 summary json" in command:
                return docker_ok('{"ipv4Unicast": {"peers": {}}}')
            raise AssertionError(command)

        with patch.object(host, "_docker_exec", side_effect=side):
            result = host.start_bgpd()
        assert result["rc"] == 0
        assert any("show bgp vrf VrfARISTA02T1 summary json" in cmd for cmd in calls)


# --- lower-level parsers ---------------------------------------------------

class TestSummaryAndNeighborParsers:
    def test_summary_peers_afi_nesting(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec):
            v4 = host._bgp_summary_peers("ipv4", "default")
            v6 = host._bgp_summary_peers("ipv6", "default")
        assert set(v4.keys()) == {"10.0.0.56", "10.0.0.58"}
        assert set(v6.keys()) == {"fc00::71"}

    def test_summary_peers_malformed_json_is_empty(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok("this is not json")):
            assert host._bgp_summary_peers("ipv4", "default") == {}

    def test_neighbors_json_malformed_is_empty(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok("<<garbage>>")):
            assert host._bgp_neighbors_json("ipv4") == {}

    def test_neighbors_json_nonobject_is_empty(self):
        """A JSON array (not an object) must not blow up .items()."""
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("[1,2,3]")):
            assert host._bgp_neighbors_json("ipv4") == {}


# --- get_route --------------------------------------------------------------

# Trimmed ``show bgp ipv4|ipv6 unicast <prefix> json`` output.
ROUTE_V4 = {
    "prefix": "192.168.0.0/21",
    "pathCount": 1,
    "paths": [{"aspath": {"string": "65100"}, "valid": True,
               "nexthops": [{"ip": "10.0.0.56", "afi": "ipv4"}]}],
}
ROUTE_V6 = {
    "prefix": "fc02:1000::/64",
    "pathCount": 1,
    "paths": [{"aspath": {"string": "65100"}, "valid": True,
               "nexthops": [{"ip": "fc00::71", "afi": "ipv6"}]}],
}


class TestGetRoute:
    def test_ipv4_prefix_uses_bgp_ipv4_unicast(self):
        import json as _json
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok(_json.dumps(ROUTE_V4))) as mock_exec:
            route = host.get_route("192.168.0.0/21")
        assert route == ROUTE_V4
        assert route["paths"]
        cmd = mock_exec.call_args[0][0]
        assert "show bgp ipv4 unicast 192.168.0.0/21 json" in cmd

    def test_ipv6_prefix_uses_bgp_ipv6_unicast(self):
        import json as _json
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok(_json.dumps(ROUTE_V6))) as mock_exec:
            route = host.get_route("fc02:1000::/64")
        assert route == ROUTE_V6
        cmd = mock_exec.call_args[0][0]
        assert "show bgp ipv6 unicast fc02:1000::/64 json" in cmd

    def test_prefix_absent_is_empty(self):
        """FRR prints '{}' when the prefix is not in the BGP table."""
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("{\n}")):
            assert host.get_route("10.255.0.0/24") == {}

    def test_command_failure_is_empty(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value={"rc": 1, "stdout": "", "stderr": "no frr"}):
            assert host.get_route("192.168.0.0/21") == {}

    def test_malformed_output_is_empty(self):
        host = make_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok("% Unknown command")):
            assert host.get_route("fc02:1000::/64") == {}

    def test_nonobject_output_is_empty(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("[1,2,3]")):
            assert host.get_route("192.168.0.0/21") == {}

    def test_converged_host_defaults_to_logical_vrf(self):
        import json as _json
        host = make_converged_host()
        with patch.object(host, "_docker_exec",
                          return_value=docker_ok(_json.dumps(ROUTE_V4))) as mock_exec:
            assert host.get_route("192.168.0.0/21") == ROUTE_V4
        assert "show bgp vrf VrfARISTA02T1 ipv4 unicast" in mock_exec.call_args[0][0]


# --- converged logical-host translation -----------------------------------

class TestConvergedLogicalHost:
    def test_logical_vrfs_on_same_container_have_distinct_identity(self):
        first = CsonicHost("csonic_test_VM0100", bgp_vrf="VrfARISTA01T1")
        second = CsonicHost("csonic_test_VM0100", bgp_vrf="VrfARISTA02T1")
        assert first != second
        assert len({first, second}) == 2

    def test_interface_commands_use_converged_name(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.command("show interfaces Ethernet1 status")
        assert mock_exec.call_args[0][0] == "show interfaces Ethernet2 status"

    def test_interface_mapping_does_not_cascade_through_actual_name(self):
        host = CsonicHost(
            "csonic_test_VM0100",
            bgp_vrf="VrfARISTA02T1",
            intf_map={"Ethernet1": "Ethernet2", "Ethernet2": "Ethernet3"},
        )
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.command("show interfaces Ethernet1 status")
        assert mock_exec.call_args[0][0] == "show interfaces Ethernet2 status"

    def test_bare_sonic_interface_tokens_use_converged_name(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.command("config portchannel retry-count set PortChannel1 5")
        assert mock_exec.call_args[0][0] == (
            "config portchannel retry-count set PortChannel2 5")

    def test_bgp_show_commands_are_scoped_to_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.shell("show ip bgp summary")
            host.shell("show ipv6 bgp neighbors fc00::75 | grep Established")
        commands = [call.args[0] for call in mock_exec.call_args_list]
        assert commands[0] == (
            'vtysh -c "show bgp vrf VrfARISTA02T1 ipv4 summary"')
        assert commands[1] == (
            'vtysh -c "show bgp vrf VrfARISTA02T1 ipv6 unicast '
            'neighbors fc00::75" | grep Established')

    def test_bgp_clear_commands_are_scoped_to_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.command("sudo vtysh -c 'clear bgp ipv4 *'")
        assert mock_exec.call_args[0][0] == (
            "sudo vtysh -c 'clear bgp vrf VrfARISTA02T1 ipv4 *'")

    def test_inline_vtysh_bgp_config_is_scoped_to_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.shell("sudo vtysh -c 'configure terminal' -c 'router bgp 64601'")
        assert "-c 'router bgp 64601 vrf VrfARISTA02T1'" in mock_exec.call_args[0][0]

    def test_bgp_config_is_scoped_to_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.config(lines=["shutdown"], parents=["router bgp 64601"])
        command = mock_exec.call_args[0][0]
        assert "-c 'router bgp 64601 vrf VrfARISTA02T1'" in command

    def test_interface_config_maps_portchannel_spelling(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("")) as mock_exec:
            host.config(lines=["shutdown"], parents=["interface Port-Channel1"])
        assert "-c 'interface PortChannel2'" in mock_exec.call_args[0][0]

    def test_bgp_summary_defaults_to_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec) as mock_exec:
            assert host.check_bgp_session_state(["10.0.0.56"])
        commands = [call.args[0] for call in mock_exec.call_args_list]
        assert all("show bgp vrf VrfARISTA02T1" in command for command in commands)

    def test_minigraph_facts_reads_logical_vrf(self):
        host = make_converged_host()
        with patch.object(host, "_docker_exec", side_effect=route_docker_exec) as mock_exec:
            host.minigraph_facts()
        commands = [call.args[0] for call in mock_exec.call_args_list]
        assert all("show bgp vrf VrfARISTA02T1" in command for command in commands)


# --- LACP rate (userspace OVS LAG backend) --------------------------------

def lacp_docker_exec(lacp_time='fast', member_key="PORTCHANNEL_MEMBER|PortChannel1|Ethernet1",
                     bond_exists=True, calls=None, lacp_time_rc=0):
    """Dispatch mock for the CONFIG_DB/ovs-vsctl commands used by the LACP rate methods."""
    def side(cmd, **kwargs):
        if calls is not None:
            calls.append(cmd)
        if cmd.startswith("sonic-db-cli CONFIG_DB keys"):
            return {"rc": 0, "stdout": member_key, "stdout_lines": [member_key] if member_key else [],
                    "stderr": ""}
        if cmd.endswith(" name"):
            return docker_ok("PortChannel1-bond" if bond_exists else "")
        if "get Port" in cmd and "lacp-time" in cmd:
            if lacp_time_rc != 0:
                return {"rc": lacp_time_rc, "stdout": "",
                        "stderr": "ovs-vsctl: unix:/run/openvswitch/db.sock: database connection failed"}
            return docker_ok(lacp_time)
        if cmd.startswith("ovs-vsctl set Port"):
            return docker_ok("")
        return {"rc": 1, "stdout": "", "stderr": "unexpected cmd"}
    return side


class TestLacpRate:
    def test_get_fast(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec("fast")):
            assert host.get_interface_lacp_rate_mode("Ethernet1") == "fast"

    def test_get_slow_is_normal(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec('"slow"')):
            assert host.get_interface_lacp_rate_mode("Ethernet1") == "normal"

    def test_get_unset_is_normal(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec("")):
            assert host.get_interface_lacp_rate_mode("Ethernet1") == "normal"

    def test_set_maps_mode_to_bond(self):
        host = make_host()
        calls = []
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec(calls=calls)):
            host.set_interface_lacp_rate_mode("Ethernet1", "fast")
            host.set_interface_lacp_rate_mode("Ethernet1", "normal")
        sets = [c for c in calls if c.startswith("ovs-vsctl set Port")]
        assert sets == ["ovs-vsctl set Port PortChannel1-bond other_config:lacp-time=fast",
                        "ovs-vsctl set Port PortChannel1-bond other_config:lacp-time=slow"]

    def test_non_member_not_supported(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec(member_key="")):
            with pytest.raises(NotImplementedError):
                host.get_interface_lacp_rate_mode("Ethernet5")

    def test_teamd_backend_not_supported(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec(bond_exists=False)):
            with pytest.raises(NotImplementedError):
                host.set_interface_lacp_rate_mode("Ethernet1", "fast")

    def test_get_raises_when_ovs_read_fails(self):
        """A failed ovs-vsctl read must raise, not be reported as the 'normal' default."""
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=lacp_docker_exec(lacp_time_rc=1)):
            with pytest.raises(Exception) as excinfo:
                host.get_interface_lacp_rate_mode("Ethernet1")
        assert "lacp rate" in str(excinfo.value)

    def test_invalid_mode(self):
        host = make_host()
        with pytest.raises(ValueError):
            host.set_interface_lacp_rate_mode("Ethernet1", "medium")


# --- shutdown / no_shutdown (backend aware) -------------------------------

def link_docker_exec(calls, member_key="PORTCHANNEL_MEMBER|PortChannel1|Ethernet1",
                     bond_exists=True, bond_ifaces=("eth1", "eth2")):
    """Dispatch mock for config-interface / CONFIG_DB / ovs-vsctl / ip link commands."""
    def side(cmd, **kwargs):
        calls.append(cmd)
        if cmd.startswith("config interface"):
            return docker_ok("")
        if cmd.startswith("sonic-db-cli CONFIG_DB keys"):
            return {"rc": 0, "stdout": member_key,
                    "stdout_lines": [member_key] if member_key else [], "stderr": ""}
        if cmd.endswith(" name"):
            return docker_ok("PortChannel1-bond" if bond_exists else "")
        if cmd.startswith("ovs-vsctl list-ifaces"):
            return {"rc": 0, "stdout": "\n".join(bond_ifaces),
                    "stdout_lines": list(bond_ifaces), "stderr": ""}
        if cmd.startswith("ip link set"):
            return docker_ok("")
        return {"rc": 1, "stdout": "", "stdout_lines": [], "stderr": "unexpected cmd"}
    return side


class TestShutdownBackendAware:
    def test_ovs_backend_toggles_port_and_bond_member(self):
        """On the userspace OVS LAG backend the bond is built on ethN, so downing
        only EthernetN would leave the member up and LACP active."""
        host = make_host()
        calls = []
        with patch.object(host, "_docker_exec", side_effect=link_docker_exec(calls)):
            host.shutdown("Ethernet1")
        assert "config interface shutdown Ethernet1" in calls
        assert "ip link set eth1 down" in calls

    def test_ovs_backend_no_shutdown_toggles_port_and_bond_member(self):
        host = make_host()
        calls = []
        with patch.object(host, "_docker_exec", side_effect=link_docker_exec(calls)):
            host.no_shutdown("Ethernet1")
        assert "config interface startup Ethernet1" in calls
        assert "ip link set eth1 up" in calls

    def test_non_ovs_backend_touches_only_sonic_port(self):
        """teamd-backed (or non-member) interfaces keep the SONiC-CLI-only path."""
        host = make_host()
        for kwargs in ({"member_key": ""}, {"bond_exists": False}):
            calls = []
            with patch.object(host, "_docker_exec",
                              side_effect=link_docker_exec(calls, **kwargs)):
                host.shutdown("Ethernet1")
                host.no_shutdown("Ethernet1")
            assert not [c for c in calls if c.startswith("ip link set")]
            assert "config interface shutdown Ethernet1" in calls
            assert "config interface startup Ethernet1" in calls

    def test_member_not_in_bond_raises(self):
        """A derived device missing from the bond must raise, never silently fall
        back to an EthernetN-only shutdown."""
        host = make_host()
        calls = []
        with patch.object(host, "_docker_exec",
                          side_effect=link_docker_exec(calls, bond_ifaces=("eth2",))):
            with pytest.raises(Exception) as excinfo:
                host.shutdown("Ethernet1")
        message = str(excinfo.value)
        assert "Ethernet1" in message and "eth1" in message and "PortChannel1-bond" in message
        assert not [c for c in calls if c.startswith("ip link set")]

    def test_unmappable_member_name_raises(self):
        host = make_host()
        calls = []
        side = link_docker_exec(
            calls, member_key="PORTCHANNEL_MEMBER|PortChannel1|Ethernet-BP0")
        with patch.object(host, "_docker_exec", side_effect=side):
            with pytest.raises(Exception) as excinfo:
                host.shutdown("Ethernet-BP0")
        assert "Ethernet-BP0" in str(excinfo.value)
        assert not [c for c in calls if c.startswith("ip link set")]


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.abspath(__file__), "-v"]))
