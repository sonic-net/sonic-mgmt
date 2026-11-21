"""cEOS setup adapter for the existing OSPF tests on a VPP DUT."""

from contextlib import contextmanager
import ipaddress
import json
import logging
import re
import shlex
import sys
import time

from tests.common.config_reload import config_reload
from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

_BFD_FIREWALL_RULE = "! -i eth0 -p udp -m multiport --dports 3784,4784 -j ACCEPT"
_VPP_CEOS_KEY = "***"


def is_vpp_eos_requested(duthost, request):
    return (
        duthost.facts.get("asic_type") == "vpp"
        and request.config.getoption("neighbor_type") == "eos"
    )


def is_vpp_ceos(duthost, request, nbrhosts):
    """Select this adapter by DUT and actual neighbor type, not topology name."""
    return (
        is_vpp_eos_requested(duthost, request)
        and bool(nbrhosts)
        and all(isinstance(info["host"], EosHost) for info in nbrhosts.values())
    )


def is_vpp_ceos_setup(setup_info):
    return isinstance(setup_info, dict) and setup_info.get(_VPP_CEOS_KEY) is True


def _vtysh(commands):
    return "vtysh {}".format(" ".join("-c {}".format(shlex.quote(command)) for command in commands))


def _run_or_fail(host, command, description):
    result = host.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise AssertionError("{} failed: {}".format(description, result.get("stderr", result)))
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
    assert isinstance(host, EosHost), "VPP OSPF qualification requires cEOS neighbors"

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
    errors = []

    def cleanup(description, **kwargs):
        try:
            result = host.eos_config(module_ignore_errors=True, **kwargs)
            if result.get("failed"):
                errors.append("{}: {}".format(description, result))
        except Exception as error:
            errors.append("{}: {}".format(description, error))

    for interface in reversed(details.get("ospf_interfaces", [])):
        lines = ["no ip ospf area 0.0.0.0"]
        if interface.startswith("Port-Channel"):
            lines.append("no ip ospf mtu-ignore")
        cleanup(
            "removing OSPF from {} {}".format(host.hostname, interface),
            lines=lines,
            parents=["interface {}".format(interface)],
        )
    if details.get("ospf_process_changed"):
        cleanup(
            "removing OSPF process from {}".format(host.hostname),
            lines=["no {}".format(_eos_ospf_parent(host))],
        )
    if details.get("bfd_agent_changed"):
        cleanup(
            "restoring the BFD agent on {}".format(host.hostname),
            lines=["agent Bfd shutdown"],
        )
    if errors:
        raise AssertionError("; ".join(errors))


def _cleanup_ceos_hosts(configured_hosts):
    errors = []
    for host, details in configured_hosts:
        try:
            _cleanup_ceos_ospf(host, details)
        except Exception as error:
            errors.append(str(error))
    if errors:
        raise AssertionError("; ".join(errors))


def _linux_interface_for_peer(host, peer_ip):
    result = host.shell("ip -j route get {}".format(shlex.quote(peer_ip)))
    routes = json.loads(result["stdout"])
    assert routes and routes[0].get("dev"), "No Linux interface for {}".format(peer_ip)
    return routes[0]["dev"]


def _configure_dut_ospf(duthost, peer_ips, dut_asn):
    _start_dut_daemon(duthost, "ospfd")
    commands = [
        "configure terminal",
        "no router bgp {}".format(dut_asn),
        "router ospf",
    ]
    commands.extend("network {}/31 area 0".format(ip) for ip in peer_ips)
    commands.append("exit")
    for interface in sorted({_linux_interface_for_peer(duthost, ip) for ip in peer_ips}):
        commands.extend(["interface {}".format(interface), "ip ospf mtu-ignore", "exit"])
    commands.append("end")
    _run_or_fail(duthost, _vtysh(commands), "configuring VPP OSPF")


def _ospf_peers_full(duthost, peer_ips):
    output = duthost.shell('vtysh -c "show ip ospf neighbor"')["stdout"]
    lines = [line.split() for line in output.splitlines()]
    return all(
        any(peer_ip in columns and any(item.startswith("Full") for item in columns) for columns in lines)
        for peer_ip in peer_ips
    )


def _wait_for_ospf_peers(duthost, peer_ips):
    peer_ips = list(peer_ips)
    assert wait_until(180, 5, 0, _ospf_peers_full, duthost, peer_ips), \
        "OSPF peers did not all reach Full: {}".format(peer_ips)


def _collect_ospf_peers(duthost, nbrhosts, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    peers = {}
    for neighbor in mg_facts["minigraph_bgp"]:
        if neighbor["name"] in nbrhosts and ipaddress.ip_address(neighbor["addr"]).version == 4:
            peers[neighbor["name"]] = neighbor["addr"]
    assert peers, "No IPv4 cEOS neighbors found for VPP OSPF"
    return mg_facts, peers


@contextmanager
def ospf_setup(duthost, nbrhosts, tbinfo):
    mg_facts, peers = _collect_ospf_peers(duthost, nbrhosts, tbinfo)
    setup_info = {
        _VPP_CEOS_KEY: True,
        "nbr_addr": peers,
        "bgp_routes": None,
        "neighbors": {},
    }
    configured_hosts = []
    try:
        for name in sorted(peers):
            details = _configure_ceos_ospf(nbrhosts[name], enable_bfd=False)
            details["host"] = nbrhosts[name]["host"]
            setup_info["neighbors"][name] = details
            configured_hosts.append((nbrhosts[name]["host"], details))

        _configure_dut_ospf(duthost, peers.values(), mg_facts["minigraph_bgp_asn"])
        _wait_for_ospf_peers(duthost, peers.values())
        yield setup_info
    finally:
        try:
            _cleanup_ceos_hosts(configured_hosts)
        finally:
            config_reload(duthost, safe_reload=True)
            time.sleep(10)


def _allow_bfd_in_host_firewall(duthost):
    inserted = []
    try:
        for command in ("iptables", "ip6tables"):
            check = duthost.shell(
                "sudo {} -C INPUT {}".format(command, _BFD_FIREWALL_RULE),
                module_ignore_errors=True,
            )
            if check.get("rc") == 0:
                continue
            result = duthost.shell(
                "sudo {} -I INPUT 2 {}".format(command, _BFD_FIREWALL_RULE),
                module_ignore_errors=True,
            )
            assert result.get("rc") == 0, result.get("stderr", result)
            inserted.append(command)
    except Exception:
        _restore_bfd_host_firewall(duthost, inserted)
        raise
    return inserted


def _restore_bfd_host_firewall(duthost, inserted):
    errors = []
    for command in reversed(inserted):
        try:
            result = duthost.shell(
                "sudo {} -D INPUT {}".format(command, _BFD_FIREWALL_RULE),
                module_ignore_errors=True,
            )
            if result.get("rc") != 0:
                errors.append(str(result.get("stderr", result)))
        except Exception as error:
            errors.append(str(error))
    if errors:
        raise AssertionError("; ".join(errors))


@contextmanager
def ospf_bfd_setup(duthost, nbrhosts, tbinfo):
    dut_asn = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_bgp_asn"]
    peers = {}
    for asic in duthost.asics:
        for ip, facts in asic.bgp_facts()["ansible_facts"]["bgp_neighbors"].items():
            if facts["ip_version"] == 4 and facts["description"] in nbrhosts:
                peers[ip] = {
                    "asic": asic,
                    "neighbor_name": facts["description"],
                }
    assert peers, "No IPv4 cEOS peers found for VPP OSPF/BFD"

    configured_hosts = []
    inserted = []
    try:
        for details in peers.values():
            nbr_info = nbrhosts[details["neighbor_name"]]
            details.update(_configure_ceos_ospf(nbr_info, enable_bfd=True))
            configured_hosts.append((nbr_info["host"], details))

        inserted = _allow_bfd_in_host_firewall(duthost)
        _start_dut_daemon(duthost, "bfdd")
        _configure_dut_ospf(duthost, peers.keys(), dut_asn)
        _wait_for_ospf_peers(duthost, peers.keys())
        yield peers
    finally:
        try:
            _restore_bfd_host_firewall(duthost, inserted)
        finally:
            try:
                _cleanup_ceos_hosts(configured_hosts)
            finally:
                config_reload(duthost, config_source="config_db", safe_reload=True)
                time.sleep(10)


def _route_prefixes(duthost):
    output = duthost.shell("show ip route ospf")["stdout"]
    pattern = re.compile(r"^O[^\n]*?([0-9]+(?:\.[0-9]+){3}/[0-9]+)", re.MULTILINE)
    return sorted(set(pattern.findall(output)))


def verify_dynamic_routing(setup_info, duthost):
    neighbor = setup_info["neighbors"][sorted(setup_info["neighbors"])[0]]
    host = neighbor["host"]
    prefix = "192.168.10.1/32"
    loopback_name = "Loopback1010" if host.bgp_vrf else "Loopback10"
    loopback_added = False
    try:
        lines = []
        if host.bgp_vrf:
            lines.append("vrf {}".format(host.bgp_vrf))
        lines.append("ip address {}".format(prefix))
        # Own cleanup before the write so a partially applied failed command
        # still removes the temporary interface.
        loopback_added = True
        result = host.eos_config(
            lines=lines,
            parents=["interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        result = host.eos_config(
            lines=["ip ospf area 0.0.0.0"],
            parents=["interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        assert wait_until(60, 3, 0, lambda: prefix in _route_prefixes(duthost)), \
            "OSPF route {} was not installed".format(prefix)
        result = host.eos_config(
            lines=["no interface {}".format(loopback_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        loopback_added = False
        assert wait_until(60, 3, 0, lambda: prefix not in _route_prefixes(duthost)), \
            "OSPF route {} was not withdrawn".format(prefix)
    finally:
        if loopback_added:
            original_error = sys.exc_info()[1]
            try:
                result = host.eos_config(
                    lines=["no interface {}".format(loopback_name)],
                    module_ignore_errors=True,
                )
                if result.get("failed"):
                    raise AssertionError(result)
            except Exception as cleanup_error:
                if original_error is None:
                    raise
                logger.error(
                    "Failed to remove %s after test failure %r: %s",
                    loopback_name,
                    original_error,
                    cleanup_error,
                )
