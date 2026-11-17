"""Shared setup for OSPF tests."""

import ipaddress
import re
import shlex
import time

import pytest

from tests.common.config_reload import config_reload
from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost


def _vtysh(commands):
    return "vtysh {}".format(" ".join("-c {}".format(shlex.quote(command)) for command in commands))


def _run_or_fail(host, command, description):
    result = host.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        pytest.fail("{} failed: {}".format(description, result.get("stderr", result)))
    return result


def _ipv4(values):
    for value in values:
        address = str(value).split("/", 1)[0]
        if ipaddress.ip_address(address).version == 4:
            return value
    return None


def _route_prefixes(output, protocol):
    pattern = re.compile(
        r"^{}[^\n]*?([0-9]+(?:\.[0-9]+){{3}}/[0-9]+)".format(protocol),
        re.MULTILINE,
    )
    return sorted(set(pattern.findall(output)))


def _start_dut_daemon(duthost, daemon, container="bgp"):
    command = (
        "docker exec {container} bash -lc "
        "'pgrep -x {daemon} >/dev/null || /usr/lib/frr/{daemon} -d'"
    ).format(container=container, daemon=daemon)
    _run_or_fail(duthost, command, "starting DUT {}".format(daemon))


def eos_ospf_parent(host):
    if not host.bgp_vrf:
        return "router ospf 1"
    match = re.search(r"(\d+)", host.bgp_vrf)
    assert match, "Unable to derive OSPF process ID from VRF {}".format(host.bgp_vrf)
    return "router ospf {} vrf {}".format(int(match.group(1)), host.bgp_vrf)


def _configure_neighbor_ospf(nbr_info, enable_bfd=False):
    """Configure a standard t0-vpp cEOS neighbor or a SONiC neighbor."""
    host = nbr_info["host"]
    ipv4 = _ipv4(list(nbr_info["conf"]["bgp"]["peers"].values())[0])
    loopback = nbr_info["conf"]["interfaces"]["Loopback0"]["ipv4"]
    assert ipv4, "No IPv4 DUT peer address for {}".format(host.hostname)

    if isinstance(host, EosHost):
        lines = ["redistribute bgp"]
        if enable_bfd:
            lines.append("bfd default")
        result = host.config(lines=lines, parents=[eos_ospf_parent(host)], module_ignore_errors=True)
        if result.get("failed"):
            pytest.fail("configuring OSPF on {} failed: {}".format(host.hostname, result))

        routed_interface = next(
            name for name in nbr_info["conf"]["interfaces"] if name.startswith("Port-Channel")
        )
        ospf_interfaces = [routed_interface, "Loopback0"]
        for interface in ospf_interfaces:
            result = host.config(lines=["ip ospf area 0.0.0.0"],
                                 parents=["interface {}".format(interface)],
                                 module_ignore_errors=True)
            if result.get("failed"):
                pytest.fail("enabling OSPF on {} {} failed: {}".format(
                    host.hostname, interface, result
                ))
        return {
            "dut_ip": ipv4,
            "loopback": loopback,
            "kind": "eos",
            "ospf_interfaces": ospf_interfaces,
        }

    direct = isinstance(host, CsonicHost)
    start = "pgrep -x ospfd >/dev/null || /usr/lib/frr/ospfd -d"
    if enable_bfd:
        start += "; pgrep -x bfdd >/dev/null || /usr/lib/frr/bfdd -d"
    start_command = start if direct else "docker exec bgp bash -lc {}".format(shlex.quote(start))
    _run_or_fail(host, start_command, "starting neighbor routing daemons")

    commands = [
        "configure terminal",
        "router ospf",
        "network {}/31 area 0".format(ipv4),
        "network {} area 0".format(loopback),
        "redistribute bgp",
    ]
    if enable_bfd:
        commands.extend(["exit", "bfd", "peer {}".format(ipv4)])
    commands.append("end")
    command = _vtysh(commands)
    if not direct:
        command = "docker exec bgp {}".format(command)
    _run_or_fail(host, command, "configuring neighbor OSPF")
    return {"dut_ip": ipv4, "loopback": loopback, "kind": "sonic"}


def _cleanup_neighbor_ospf(host, details=None):
    if isinstance(host, EosHost):
        for interface in (details or {}).get("ospf_interfaces", []):
            host.config(lines=["no ip ospf area 0.0.0.0"],
                        parents=["interface {}".format(interface)],
                        module_ignore_errors=True)
        host.config(lines=["no {}".format(eos_ospf_parent(host))], module_ignore_errors=True)
    elif isinstance(host, CsonicHost):
        host.shell(_vtysh(["configure terminal", "no router ospf", "no bfd", "end"]),
                   module_ignore_errors=True)
    else:
        config_reload(host, is_dut=False)


@pytest.fixture(scope="module")
def trap_copp_ospf(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    path = "/tmp/copp_trap_ospf.json"
    payload = """{
    \"COPP_TRAP\": {
        \"ospf\": {
            \"trap_ids\": \"ospf,ospfv6\",
            \"trap_group\": \"queue4_group1\",
            \"always_enabled\": \"true\"
        }
    }
}
"""
    duthost.copy(content=payload, dest=path)
    config_file = path if not duthost.is_multi_asic else ",".join(
        [path for _ in range(duthost.num_asics() + 1)]
    )
    duthost.command("sudo config load {} -y".format(config_file))

    yield

    duthost.command("sudo rm -f {}".format(path))


@pytest.fixture(scope="module")
def ospf_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, request):
    if request.config.getoption("neighbor_type") not in ("eos", "sonic", "csonic"):
        pytest.skip("Neighbor type must support OSPF configuration")

    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    setup_info = {"nbr_addr": {}, "neighbors": {}, "bgp_routes": []}

    for neighbor in mg_facts["minigraph_bgp"]:
        if neighbor["name"] in nbrhosts and ipaddress.ip_address(neighbor["addr"]).version == 4:
            setup_info["nbr_addr"][neighbor["name"]] = neighbor["addr"]

    assert setup_info["nbr_addr"], "No IPv4 T0 neighbors found for OSPF"
    setup_info["bgp_routes"] = _route_prefixes(duthost.shell("show ip route bgp")["stdout"], "B")
    assert setup_info["bgp_routes"], "No IPv4 BGP routes found before OSPF conversion"

    configured_hosts = []
    try:
        for name in sorted(setup_info["nbr_addr"]):
            details = _configure_neighbor_ospf(nbrhosts[name], enable_bfd=False)
            details["host"] = nbrhosts[name]["host"]
            setup_info["neighbors"][name] = details
            configured_hosts.append((nbrhosts[name]["host"], details))

        _start_dut_daemon(duthost, "ospfd")
        commands = [
            "configure terminal",
            "no router bgp {}".format(mg_facts["minigraph_bgp_asn"]),
            "router ospf",
        ]
        commands.extend("network {}/31 area 0".format(ip) for ip in setup_info["nbr_addr"].values())
        commands.append("end")
        _run_or_fail(duthost, _vtysh(commands), "configuring DUT OSPF")

        yield setup_info
    finally:
        for host, details in configured_hosts:
            _cleanup_neighbor_ospf(host, details)
        config_reload(duthost, safe_reload=True)
        time.sleep(10)


@pytest.fixture(scope="module")
def ospf_Bfd_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo,
                   trap_copp_ospf, request):
    if request.config.getoption("neighbor_type") not in ("eos", "sonic", "csonic"):
        pytest.skip("Neighbor type must support OSPF/BFD configuration")

    duthost = duthosts[rand_one_dut_hostname]
    dut_asn = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_bgp_asn"]
    setup_info = {}

    for asic in duthost.asics:
        for ip, facts in asic.bgp_facts()["ansible_facts"]["bgp_neighbors"].items():
            if facts["ip_version"] == 4 and facts["description"] in nbrhosts:
                setup_info[ip] = {
                    "asic": asic,
                    "neighbor_name": facts["description"],
                    "dut_asn": dut_asn,
                }

    assert setup_info, "No IPv4 BGP peers found for OSPF/BFD"
    configured_hosts = []
    try:
        for ip, details in setup_info.items():
            nbr_info = nbrhosts[details["neighbor_name"]]
            details.update(_configure_neighbor_ospf(nbr_info, enable_bfd=True))
            details["host"] = nbr_info["host"]
            configured_hosts.append((nbr_info["host"], details))
        yield setup_info
    finally:
        for host, details in configured_hosts:
            _cleanup_neighbor_ospf(host, details)
        config_reload(duthost, config_source="config_db", safe_reload=True)
        time.sleep(10)
