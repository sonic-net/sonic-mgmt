"""Shared setup for SONiC-VPP OSPF tests with cEOS neighbors."""

import ipaddress
import json
import re
import shlex
import time

import pytest

from tests.common.config_reload import config_reload
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


def _start_dut_daemon(duthost, daemon, container="bgp"):
    command = (
        "docker exec {container} bash -lc "
        "'pgrep -x {daemon} >/dev/null || /usr/lib/frr/{daemon} -d'"
    ).format(container=container, daemon=daemon)
    _run_or_fail(duthost, command, "starting DUT {}".format(daemon))


def _eos_ospf_parent(host):
    if not host.bgp_vrf:
        return "router ospf 1"
    match = re.search(r"(\d+)", host.bgp_vrf)
    assert match, "Unable to derive OSPF process ID from VRF {}".format(host.bgp_vrf)
    return "router ospf {} vrf {}".format(int(match.group(1)), host.bgp_vrf)


def _eos_config_or_raise(host, description, **kwargs):
    result = host.eos_config(module_ignore_errors=True, **kwargs)
    if result.get("failed"):
        raise AssertionError("{} failed: {}".format(description, result))
    return result


def _ceos_bfd_agent_is_shutdown(host):
    result = host.run_command("show running-config | include ^agent Bfd")
    stdout = result.get("stdout", [])
    text = stdout if isinstance(stdout, str) else "\n".join(stdout)
    return any(line.strip() == "agent Bfd shutdown" for line in text.splitlines())


def _configure_ceos_ospf(nbr_info, enable_bfd=False):
    host = nbr_info["host"]
    assert isinstance(host, EosHost), "SONiC-VPP OSPF qualification requires cEOS neighbors"

    ipv4 = _ipv4(list(nbr_info["conf"]["bgp"]["peers"].values())[0])
    loopback = nbr_info["conf"]["interfaces"]["Loopback0"]["ipv4"]
    assert ipv4, "No IPv4 DUT peer address for {}".format(host.hostname)

    routed_interface = next(
        name for name in nbr_info["conf"]["interfaces"] if name.startswith("Port-Channel")
    )
    details = {
        "dut_ip": ipv4,
        "loopback": loopback,
        "ospf_interfaces": [],
        "ospf_process_changed": False,
        "bfd_agent_changed": False,
    }

    try:
        if enable_bfd and _ceos_bfd_agent_is_shutdown(host):
            # Record ownership before the write so even a partial module
            # failure restores the administrative state observed above.
            details["bfd_agent_changed"] = True
            _eos_config_or_raise(
                host,
                "enabling the BFD agent on {}".format(host.hostname),
                lines=["no agent Bfd shutdown"],
            )

        lines = ["router-id {}".format(loopback.split("/", 1)[0])]
        if enable_bfd:
            lines.extend(["bfd default", "bfd adjacency state any"])
        details["ospf_process_changed"] = True
        _eos_config_or_raise(
            host,
            "configuring OSPF on {}".format(host.hostname),
            lines=lines,
            parents=[_eos_ospf_parent(host)],
        )

        for interface in (routed_interface, "Loopback0"):
            # Add the attempted interface before mutating it so the helper's
            # exception path also rolls back a partially applied command.
            details["ospf_interfaces"].append(interface)
            lines = ["ip ospf area 0.0.0.0"]
            if interface.startswith("Port-Channel"):
                lines.append("ip ospf mtu-ignore")
            _eos_config_or_raise(
                host,
                "enabling OSPF on {} {}".format(host.hostname, interface),
                lines=lines,
                parents=["interface {}".format(interface)],
            )
    except Exception:
        _cleanup_ceos_ospf(host, details)
        raise

    return details


def _cleanup_ceos_ospf(host, details):
    assert isinstance(host, EosHost)
    for interface in reversed(details.get("ospf_interfaces", [])):
        lines = ["no ip ospf area 0.0.0.0"]
        if interface.startswith("Port-Channel"):
            lines.append("no ip ospf mtu-ignore")
        host.eos_config(
            lines=lines,
            parents=["interface {}".format(interface)],
            module_ignore_errors=True,
        )
    if details.get("ospf_process_changed"):
        host.eos_config(
            lines=["no {}".format(_eos_ospf_parent(host))],
            module_ignore_errors=True,
        )
    if details.get("bfd_agent_changed"):
        host.eos_config(lines=["agent Bfd shutdown"], module_ignore_errors=True)


def _linux_interface_for_peer(host, peer_ip):
    result = host.shell("ip -j route get {}".format(shlex.quote(peer_ip)))
    routes = json.loads(result["stdout"])
    assert routes and routes[0].get("dev"), "No Linux interface for {}".format(peer_ip)
    return routes[0]["dev"]


def _require_vpp_ceos(duthost, tbinfo, request):
    if duthost.facts.get("asic_type") != "vpp":
        pytest.skip("This OSPF qualification is specific to SONiC-VPP")
    if request.config.getoption("neighbor_type") != "eos":
        pytest.skip("SONiC-VPP OSPF qualification uses cEOS neighbors")
    if tbinfo["topo"]["name"] != "t0":
        pytest.skip("SONiC-VPP OSPF qualification requires the standard t0 topology")


@pytest.fixture(scope="module")
def ospf_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, request):
    duthost = duthosts[rand_one_dut_hostname]
    _require_vpp_ceos(duthost, tbinfo, request)

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    setup_info = {"nbr_addr": {}, "neighbors": {}, "expected_routes": []}

    for neighbor in mg_facts["minigraph_bgp"]:
        if neighbor["name"] in nbrhosts and ipaddress.ip_address(neighbor["addr"]).version == 4:
            setup_info["nbr_addr"][neighbor["name"]] = neighbor["addr"]

    assert setup_info["nbr_addr"], "No IPv4 cEOS neighbors found for SONiC-VPP OSPF"

    configured_hosts = []
    try:
        for name in sorted(setup_info["nbr_addr"]):
            details = _configure_ceos_ospf(nbrhosts[name], enable_bfd=False)
            details["host"] = nbrhosts[name]["host"]
            setup_info["neighbors"][name] = details
            setup_info["expected_routes"].append(details["loopback"])
            configured_hosts.append((nbrhosts[name]["host"], details))

        _start_dut_daemon(duthost, "ospfd")
        commands = [
            "configure terminal",
            "no router bgp {}".format(mg_facts["minigraph_bgp_asn"]),
            "router ospf",
        ]
        commands.extend("network {}/31 area 0".format(ip) for ip in setup_info["nbr_addr"].values())
        commands.append("exit")
        for interface in sorted({
            _linux_interface_for_peer(duthost, ip)
            for ip in setup_info["nbr_addr"].values()
        }):
            commands.extend(["interface {}".format(interface), "ip ospf mtu-ignore", "exit"])
        commands.append("end")
        _run_or_fail(duthost, _vtysh(commands), "configuring SONiC-VPP OSPF")

        yield setup_info
    finally:
        try:
            for host, details in configured_hosts:
                _cleanup_ceos_ospf(host, details)
        finally:
            config_reload(duthost, safe_reload=True)
            time.sleep(10)


@pytest.fixture(scope="module")
def ospf_Bfd_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, request):
    duthost = duthosts[rand_one_dut_hostname]
    _require_vpp_ceos(duthost, tbinfo, request)

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

    assert setup_info, "No IPv4 cEOS peers found for SONiC-VPP OSPF/BFD"
    configured_hosts = []
    try:
        for details in setup_info.values():
            nbr_info = nbrhosts[details["neighbor_name"]]
            details.update(_configure_ceos_ospf(nbr_info, enable_bfd=True))
            details["host"] = nbr_info["host"]
            configured_hosts.append((nbr_info["host"], details))
        yield setup_info
    finally:
        try:
            for host, details in configured_hosts:
                _cleanup_ceos_ospf(host, details)
        finally:
            config_reload(duthost, config_source="config_db", safe_reload=True)
            time.sleep(10)
