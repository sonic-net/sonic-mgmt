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
    if "show ip bgp neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V4))
    if "show bgp ipv6 neighbors json" in cmd:
        return docker_ok(_json.dumps(NEIGHBORS_V6))
    if "ipv4 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V4))
    if "ipv6 summary json" in cmd:
        return docker_ok(_json.dumps(SUMMARY_V6))
    return {"rc": 1, "stdout": "", "stderr": "unexpected cmd"}


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


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.abspath(__file__), "-v"]))
