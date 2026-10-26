"""
Unit tests for tests/common/devices/csonic.py (CsonicHost).

CsonicHost mirrors the EosHost/SonicHost neighbor API for cSONiC
(docker-sonic-vs) neighbors by parsing FRR/vtysh JSON obtained via
``_docker_exec``. These tests mock ``_docker_exec`` with representative FRR
JSON so the pure parsing/merging logic can be verified without a live
container. They cover:

  * iface_macsec_ok        - reading MACsec readiness from STATE_DB inside the
                             cSONiC container
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
import shlex
import sys
from types import SimpleNamespace
from unittest.mock import call, patch

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
    """Instantiate the opt-in userspace-OVS host used by these unit tests."""
    return CsonicHost(
        "csonic_test_VM0100", lag_backend="userspace_ovs")


def docker_ok(stdout):
    """Shape a successful _docker_exec return with the given stdout."""
    return {"rc": 0, "stdout": stdout, "stderr": ""}


def test_remote_docker_exec_shell_quotes_every_argument():
    host = CsonicHost(
        "csonic_vm", vm_host_ip="192.0.2.10", vm_host_user="admin")
    script = (
        "set -e\n"
        "sonic-db-cli STATE_DB HSET "
        "'FIPS_MACSEC_POST_TABLE|sai' post_state disabled\n"
        "printf '%s\\n' \"done\""
    )
    expected_docker = ["docker", "exec", "csonic_vm", "bash", "-c", script]
    expected_remote = " ".join(shlex.quote(part) for part in expected_docker)

    with patch(
            "tests.common.devices.csonic.subprocess.run",
            return_value=SimpleNamespace(
                stdout="ok\n", stderr="", returncode=0)) as run:
        result = host.shell(script, timeout=123)

    assert result["rc"] == 0
    run.assert_called_once_with(
        [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-l", "admin", "192.0.2.10", expected_remote,
        ],
        capture_output=True,
        text=True,
        timeout=123,
    )


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
    if "show ip bgp neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V4))
    if "show bgp ipv6 neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V6))
    if "ipv4 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V4))
    if "ipv6 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V6))
    return {"rc": 1, "stdout": "", "stderr": "unexpected cmd"}


# --- MACsec host contract -------------------------------------------------

class TestMacsecHostContract:
    def test_does_not_claim_the_shared_sonic_host_contract(self):
        host = make_host()

        assert not hasattr(host, "is_multi_asic")
        assert not hasattr(host, "facts")

    def test_get_dut_iface_mac_reads_sonic_interface(self):
        host = make_host()
        with patch.object(
                host, "_docker_exec",
                return_value=docker_ok("52:54:00:65:43:21\n")) as execute:
            assert host.get_dut_iface_mac("Ethernet4") == "52:54:00:65:43:21"
        execute.assert_called_once_with("cat /sys/class/net/Ethernet4/address")

    def test_get_macsec_iface_mac_reads_macsec_interface(self):
        host = make_host()
        with patch.object(
                host, "_docker_exec",
                side_effect=[
                    docker_ok("eth0\neth1\neth2\nEthernet0\nEthernet4\n"),
                    docker_ok("52:54:00:12:34:56\n"),
                ]) as execute:
            assert host.get_macsec_iface_mac("Ethernet4") == "52:54:00:12:34:56"
        assert execute.call_args_list == [
            call("ls /sys/class/net/"),
            call("cat /sys/class/net/macsec_eth2/address"),
        ]

    def test_get_macsec_iface_sci_reads_kernel_macsec_record(self):
        host = make_host()
        macsec_state = (
            '[{"ifname":"macsec_eth1","sci":"0x1111111111110001"},'
            '{"ifname":"macsec_eth2","sci":"0x8e6c5b52f5160001"}]')
        with patch.object(
                host, "_docker_exec",
                side_effect=[
                    docker_ok("eth0\neth1\neth2\nEthernet0\nEthernet4\n"),
                    docker_ok(macsec_state),
                ]) as execute:
            assert host.get_macsec_iface_sci("Ethernet4") == "8e6c5b52f5160001"
        assert execute.call_args_list == [
            call("ls /sys/class/net/"),
            call("ip -j macsec show"),
        ]

    def test_get_macsec_iface_sci_rejects_malformed_state(self):
        host = make_host()
        with patch.object(
                host, "_docker_exec",
                side_effect=[
                    docker_ok("eth0\neth1\nEthernet0\n"),
                    docker_ok('[{"ifname":"macsec_eth1","sci":"invalid"}]'),
                ]):
            assert host.get_macsec_iface_sci("Ethernet0") is None

    def test_get_dut_iface_mac_fails_closed(self):
        host = make_host()
        with patch.object(
                host, "_docker_exec",
                return_value={"rc": 1, "stdout": "", "stderr": "missing"}):
            assert host.get_dut_iface_mac("Ethernet1") is None
            assert host.get_macsec_iface_mac("Ethernet1") is None


# --- iface_macsec_ok ------------------------------------------------------

class TestIfaceMacsecOk:
    def test_ready_state_is_true(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("ok\n")) as execute:
            assert host.iface_macsec_ok("Ethernet1") is True
        execute.assert_called_once_with(
            'sonic-db-cli STATE_DB HGET "MACSEC_PORT_TABLE|Ethernet1" state')

    def test_non_ready_state_is_false(self):
        host = make_host()
        with patch.object(host, "_docker_exec", return_value=docker_ok("pending")):
            assert host.iface_macsec_ok("Ethernet1") is False

    def test_command_error_is_false(self):
        host = make_host()
        with patch.object(host, "_docker_exec", side_effect=RuntimeError("unavailable")):
            assert host.iface_macsec_ok("Ethernet1") is False


# --- minigraph_facts -------------------------------------------------------

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
            if "show ip bgp neighbors json" in cmd:
                return docker_ok(_json.dumps({"10.0.0.56": {"hostname": "dut-1", "remoteAs": 65100}}))
            if "show bgp ipv6 neighbors json" in cmd:
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
        if cmd == "ls /sys/class/net/":
            return docker_ok("eth0\neth1\neth2\nEthernet1\nEthernet2\n")
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

    def test_ovs_backend_toggles_active_macsec_member(self):
        host = make_host()
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=link_docker_exec(
                    calls, bond_ifaces=("macsec_eth1", "eth2"))):
            host.shutdown("Ethernet1")
        assert "ip link set macsec_eth1 down" in calls

    def test_non_ovs_backend_touches_only_sonic_port(self):
        """teamd-backed interfaces must not probe the optional OVS CLI."""
        host = CsonicHost("csonic_test_VM0100", lag_backend="teamd")
        calls = []
        with patch.object(host, "_docker_exec",
                          side_effect=link_docker_exec(calls)):
            host.shutdown("Ethernet1")
            host.no_shutdown("Ethernet1")
        assert not [c for c in calls if c.startswith("ovs-vsctl")]
        assert not [c for c in calls if c.startswith("ip link set")]
        assert "config interface shutdown Ethernet1" in calls
        assert "config interface startup Ethernet1" in calls

    def test_ovs_non_member_touches_only_sonic_port(self):
        host = make_host()
        for kwargs in ({"member_key": ""}, {"bond_exists": False}):
            calls = []
            with patch.object(host, "_docker_exec",
                              side_effect=link_docker_exec(calls, **kwargs)):
                host.shutdown("Ethernet1")
                host.no_shutdown("Ethernet1")
            assert not [c for c in calls if c.startswith("ip link set")]

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


# --- MACsec data path on userspace OVS LAGs ------------------------------


def ovs_macsec_docker_exec(calls, initial_members=("eth1", "eth2"),
                           missing_device=None,
                           link_names=("eth0", "eth1", "eth2",
                                       "Ethernet1", "Ethernet2")):
    members = list(initial_members)
    interface_ids = {
        "eth1": "00000000-0000-0000-0000-000000000001",
        "eth2": "00000000-0000-0000-0000-000000000002",
        "macsec_eth1": "00000000-0000-0000-0000-000000000101",
        "macsec_eth2": "00000000-0000-0000-0000-000000000102",
    }

    def side(cmd, **kwargs):
        calls.append(cmd)
        if cmd.startswith("sonic-db-cli CONFIG_DB keys"):
            member = cmd.rsplit("|", 1)[-1].rstrip("'")
            key = "PORTCHANNEL_MEMBER|PortChannel1|{}".format(member)
            return {"rc": 0, "stdout": key, "stdout_lines": [key],
                    "stderr": ""}
        if cmd.startswith("ovs-vsctl --if-exists get Port") and cmd.endswith(" name"):
            return docker_ok("PortChannel1-bond")
        if cmd == "ls /sys/class/net/":
            return docker_ok("\n".join(link_names))
        if cmd == "ovs-vsctl get Port PortChannel1-bond interfaces":
            return docker_ok("[{}]".format(
                ", ".join(interface_ids[member] for member in members)))
        if cmd.startswith("ovs-vsctl get Interface") and cmd.endswith(" name"):
            interface_id = cmd.split()[3]
            name = next(name for name, value in interface_ids.items()
                        if value == interface_id)
            return docker_ok('"{}"'.format(name))
        if cmd.startswith("ip link show dev"):
            device = cmd.rsplit(" ", 1)[-1]
            if device == missing_device:
                return {"rc": 1, "stdout": "", "stdout_lines": [],
                        "stderr": "Device not found"}
            return docker_ok(device)
        if cmd.startswith("ip link set"):
            return docker_ok("")
        if cmd.startswith("ovs-vsctl list-ifaces"):
            return {"rc": 0, "stdout": "\n".join(members),
                    "stdout_lines": list(members), "stderr": ""}
        if cmd.startswith("ovs-vsctl --"):
            replacements = {
                "eth1": "macsec_eth1",
                "eth2": "macsec_eth2",
                "macsec_eth1": "eth1",
                "macsec_eth2": "eth2",
            }
            for current, desired in replacements.items():
                if "create Interface name={}".format(desired) in cmd:
                    members[members.index(current)] = desired
                    break
            return docker_ok("")
        return {"rc": 1, "stdout": "", "stdout_lines": [],
                "stderr": "unexpected cmd"}
    return side


class TestOvsMacsecMember:
    def test_enable_replaces_plain_member_and_preserves_siblings(self):
        host = make_host()
        calls = []
        with patch.object(host, "_docker_exec",
                          side_effect=ovs_macsec_docker_exec(calls)):
            host.set_ovs_macsec_member("Ethernet1", True)

        swap = next(command for command in calls
                    if command.startswith("ovs-vsctl -- --id="))
        assert "--id=@current get Interface eth1 _uuid" in swap
        assert "--id=@desired create Interface name=macsec_eth1" in swap
        add = "add Port PortChannel1-bond interfaces @desired"
        remove = "remove Port PortChannel1-bond interfaces @current"
        assert add in swap and remove in swap
        assert swap.index(add) < swap.index(remove)

    def test_disable_restores_plain_member(self):
        host = make_host()
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=ovs_macsec_docker_exec(
                    calls, initial_members=("macsec_eth1", "eth2"))):
            host.set_ovs_macsec_member("Ethernet1", False)

        swap = next(command for command in calls
                    if command.startswith("ovs-vsctl -- --id="))
        assert "--id=@current get Interface macsec_eth1 _uuid" in swap
        assert "--id=@desired create Interface name=eth1" in swap
        assert "remove Port PortChannel1-bond interfaces @current" in swap
        assert "add Port PortChannel1-bond interfaces @desired" in swap

    def test_enable_is_idempotent_when_macsec_member_is_active(self):
        host = make_host()
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=ovs_macsec_docker_exec(
                    calls, initial_members=("macsec_eth1", "eth2"))):
            assert host.set_ovs_macsec_member("Ethernet1", True) is None
        assert not [command for command in calls
                    if command.startswith("ovs-vsctl -- --id=")]

    def test_enable_maps_logical_converged_interface_before_ovs_lookup(self):
        host = make_host()
        host._interface_name = lambda interface: (
            "Ethernet2" if interface == "Ethernet1" else interface)
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=ovs_macsec_docker_exec(
                    calls, initial_members=("eth2",))):
            host.set_ovs_macsec_member("Ethernet1", True)

        assert any(
            "PORTCHANNEL_MEMBER|*|Ethernet2" in command
            for command in calls)
        swap = next(command for command in calls
                    if command.startswith("ovs-vsctl -- --id="))
        assert "create Interface name=macsec_eth2" in swap

    def test_enable_maps_noncontiguous_sonic_port_to_injected_device(self):
        host = make_host()
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=ovs_macsec_docker_exec(
                    calls, initial_members=("eth2",),
                    link_names=("eth0", "eth1", "eth2",
                                "Ethernet0", "Ethernet4"))):
            host.set_ovs_macsec_member("Ethernet4", True)

        swap = next(command for command in calls
                    if command.startswith("ovs-vsctl -- --id="))
        assert "get Interface eth2 _uuid" in swap
        assert "create Interface name=macsec_eth2" in swap

    def test_enable_fails_when_macsec_device_never_appears(self):
        host = make_host()
        calls = []
        with patch.object(
                host, "_docker_exec",
                side_effect=ovs_macsec_docker_exec(
                    calls, missing_device="macsec_eth1")):
            with pytest.raises(Exception, match="did not appear"):
                host.set_ovs_macsec_member("Ethernet1", True, timeout=0)

    def test_enable_fails_when_desired_link_cannot_be_brought_up(self):
        host = make_host()
        calls = []
        normal = ovs_macsec_docker_exec(calls)

        def side(command, **kwargs):
            if command == "ip link set macsec_eth1 up":
                calls.append(command)
                return {"rc": 1, "stdout": "", "stdout_lines": [],
                        "stderr": "link failure"}
            return normal(command, **kwargs)

        with patch.object(host, "_docker_exec", side_effect=side):
            with pytest.raises(Exception, match="Unable to bring"):
                host.set_ovs_macsec_member("Ethernet1", True)

    def test_enable_fails_closed_when_portchannel_query_fails(self):
        host = make_host()
        calls = []
        normal = ovs_macsec_docker_exec(calls)

        def side(command, **kwargs):
            if command.startswith("sonic-db-cli CONFIG_DB keys"):
                calls.append(command)
                return {"rc": 1, "stdout": "", "stdout_lines": [],
                        "stderr": "database unavailable"}
            return normal(command, **kwargs)

        with patch.object(host, "_docker_exec", side_effect=side):
            with pytest.raises(Exception, match="Unable to query PortChannel"):
                host.set_ovs_macsec_member("Ethernet1", True)


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


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.abspath(__file__), "-v"]))
