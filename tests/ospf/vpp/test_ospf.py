import re

import pytest

from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("t0")]


def _full_neighbor_count(duthost):
    output = duthost.shell('vtysh -c "show ip ospf neighbor"')["stdout"]
    return sum(
        1 for line in output.splitlines()
        if len(line.split()) >= 7 and line.split()[2].startswith("Full")
    )


def _route_prefixes(duthost):
    output = duthost.shell("show ip route ospf")["stdout"]
    pattern = re.compile(r"^O[^\n]*?([0-9]+(?:\.[0-9]+){3}/[0-9]+)", re.MULTILINE)
    return sorted(set(pattern.findall(output)))


def _routes_match(duthost, expected):
    return set(expected).issubset(set(_route_prefixes(duthost)))


def _route_present(duthost, prefix, present):
    return (prefix in _route_prefixes(duthost)) is present


def test_ospf_neighborship(vpp_ospf_setup, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    expected_neighbors = len(vpp_ospf_setup["nbr_addr"])
    expected_routes = vpp_ospf_setup["expected_routes"]

    assert wait_until(
        180, 5, 0, lambda: _full_neighbor_count(duthost) == expected_neighbors
    ), "Expected {} Full OSPF neighbors, found {}".format(
        expected_neighbors, _full_neighbor_count(duthost)
    )
    assert wait_until(
        90, 5, 0, _routes_match, duthost, expected_routes
    ), "OSPF routes {} do not contain cEOS loopbacks {}".format(
        _route_prefixes(duthost), expected_routes
    )


def test_ospf_dynamic_routing(vpp_ospf_setup, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    neighbor = vpp_ospf_setup["neighbors"][sorted(vpp_ospf_setup["neighbors"])[0]]
    host = neighbor["host"]
    assert isinstance(host, EosHost), "SONiC-VPP OSPF qualification requires cEOS neighbors"

    prefix = "192.168.10.1/32"
    loopback_name = "Loopback1010" if host.bgp_vrf else "Loopback10"
    loopback_added = False

    try:
        lines = []
        if host.bgp_vrf:
            lines.append("vrf {}".format(host.bgp_vrf))
        lines.append("ip address {}".format(prefix))
        result = host.eos_config(
            lines=lines,
            parents=["interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        loopback_added = True

        result = host.eos_config(
            lines=["ip ospf area 0.0.0.0"],
            parents=["interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result

        assert wait_until(60, 3, 0, _route_present, duthost, prefix, True), \
            "OSPF route {} was not installed".format(prefix)

        result = host.eos_config(
            lines=["no interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        loopback_added = False

        assert wait_until(60, 3, 0, _route_present, duthost, prefix, False), \
            "OSPF route {} was not withdrawn".format(prefix)
    finally:
        if loopback_added:
            host.eos_config(
                lines=["no interface {}".format(loopback_name)],
                module_ignore_errors=True,
            )
