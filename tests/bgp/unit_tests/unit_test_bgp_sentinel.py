"""Regression tests for sentinel routing through converged backplanes."""

from pathlib import Path
import sys
from unittest.mock import Mock, patch

import pytest


_TESTS_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "bgp"))

from bgp import test_bgp_sentinel as sentinel  # noqa: E402


def _tbinfo(converged=False, ipv6_only=False):
    properties = {
        "configuration_properties": {
            "common": {"nhipv4": "10.10.246.254", "nhipv6": "FC0A::FF"},
        },
        "configuration": {
            "ARISTA01UT2": {
                "properties": ["spine"],
                "bp_interface": {"ipv4": "10.10.246.92/24", "ipv6": "fc0a::5c/64"},
            },
        },
    }
    if converged:
        backplane = {"ipv6": "fc0a::121/127"}
        if not ipv6_only:
            backplane["ipv4"] = "10.10.247.33/31"
        properties.update({
            "topo_is_multi_vrf": True,
            "convergence_data": {"ptf_backplane_addrs": {"ARISTA01UT2": backplane}},
        })
    return {"topo": {"type": "lt2", "properties": properties}}


@pytest.mark.parametrize("converged,ipv6_only", [(False, False), (True, False), (True, True)])
def test_sentinel_uses_matching_backplane_endpoints(converged, ipv6_only):
    with patch.object(sentinel, "get_upstream_neigh_type", return_value="UT2"), \
            patch.object(sentinel, "is_ipv6_only_topology", return_value=ipv6_only):
        v4_subnet, v6_subnet, neighbors, v4_source, v6_source = sentinel.get_sentinel_backplane(
            _tbinfo(converged, ipv6_only))

    if converged:
        assert v6_source == "fc0a::121"
        assert v6_subnet == "fc0a::120/127"
        assert neighbors["ARISTA01UT2"]["ipv6"] == "fc0a::120"
        if ipv6_only:
            assert v4_source is None
            assert v4_subnet is None
            assert "ipv4" not in neighbors["ARISTA01UT2"]
        else:
            assert v4_source == "10.10.247.33"
            assert v4_subnet == "10.10.247.32/31"
            assert neighbors["ARISTA01UT2"]["ipv4"] == "10.10.247.32"
    else:
        assert v4_source == "10.10.246.254"
        assert v6_source == "fc0a::ff"
        assert v4_subnet == "10.10.246.0/24"
        assert v6_subnet == "fc0a::/64"
        assert neighbors["ARISTA01UT2"] == {"ipv4": "10.10.246.92", "ipv6": "fc0a::5c"}


@pytest.mark.parametrize("converged,ipv6_only", [(False, False), (False, True), (True, False), (True, True)])
def test_sentinel_probes_use_exabgp_source_only_when_converged(converged, ipv6_only):
    host = Mock()
    host.shell.return_value = {"rc": 0}
    with patch.object(sentinel.time, "sleep"):
        result = sentinel.add_route_to_dut_lo(
            host, {"upstream": {"ipv4": "10.10.247.32", "ipv6": "fc0a::120"}},
            "10.1.0.32", "fc00:1::32", ipv6_only, "fc0a::121",
            ptf_bp_v4="10.10.247.33", use_converged_backplane=converged)

    assert result == (None if ipv6_only else "10.10.247.32", "fc0a::120")
    commands = [call.args[0] for call in host.shell.call_args_list]
    probes = [command for command in commands if command.startswith("ping ")]
    expected_sources = ["fc0a::121"] if ipv6_only else ["10.10.247.33", "fc0a::121"]
    assert probes == [
        "ping {} -c 3 -I {}".format(
            destination, source if converged else "backplane")
        for destination, source in zip(
            ["fc00:1::32"] if ipv6_only else ["10.1.0.32", "fc00:1::32"], expected_sources)
    ]
    if converged:
        assert "ip -6 route add fc00:1::32/128 via fc0a::120 src fc0a::121" in commands
        if not ipv6_only:
            assert "ip route add 10.1.0.32 via 10.10.247.32 src 10.10.247.33" in commands
