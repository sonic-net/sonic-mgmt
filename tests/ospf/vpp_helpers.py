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
_BFD_FAULT_ACL_PREFIX = "SONIC_MGMT_BFD_"
_VPP_CEOS_KEY = "***"


def is_vpp_eos_requested(duthost, request):
    return (
        duthost.facts.get("asic_type") == "vpp"
        and request.config.getoption("neighbor_type") == "eos"
    )


def is_vpp_ceos_topology(tbinfo):
    return tbinfo["topo"]["name"] == "t0"


def is_vpp_ceos(duthost, request, nbrhosts, tbinfo):
    """Select this adapter by DUT, topology, and actual neighbor type."""
    return (
        is_vpp_eos_requested(duthost, request)
        and is_vpp_ceos_topology(tbinfo)
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


def _command_text(result):
    stdout = result.get("stdout", [])
    if isinstance(stdout, str):
        return stdout
    return "\n".join(str(item) for item in stdout)


def _handle_cleanup_errors(primary_error, errors):
    if not errors:
        return
    if primary_error is not None:
        for description, error in errors:
            logger.error(
                "Cleanup failed during primary failure %r (%s): %s",
                primary_error,
                description,
                error,
            )
        return
    raise AssertionError("; ".join("{}: {}".format(*error) for error in errors))


def _run_cleanup_actions(primary_error, actions):
    errors = []
    for description, action in actions:
        try:
            action()
        except Exception as error:
            errors.append((description, error))
    _handle_cleanup_errors(primary_error, errors)


def _reload_and_wait(duthost, **kwargs):
    config_reload(duthost, **kwargs)
    time.sleep(10)


def _ceos_bfd_agent_is_shutdown(host):
    result = host.run_command("show running-config | include ^agent Bfd")
    text = _command_text(result)
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
        "host": host,
        "dut_ip": ipv4,
        "loopback": loopback,
        "routed_interface": routed_interface,
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
    except Exception as original_error:
        try:
            _cleanup_ceos_ospf(host, details)
        except Exception as cleanup_error:
            logger.error(
                "Failed to roll back partial cEOS OSPF setup after %r: %s",
                original_error,
                cleanup_error,
            )
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


def _linux_route_for_peer(host, peer_ip):
    result = host.shell("ip -j route get {}".format(shlex.quote(peer_ip)))
    routes = json.loads(result["stdout"])
    assert routes and routes[0].get("dev"), "No Linux interface for {}".format(peer_ip)
    return routes[0]


def _linux_interface_for_peer(host, peer_ip):
    return _linux_route_for_peer(host, peer_ip)["dev"]


def _vpp_lcp_pair(duthost, linux_interface):
    assert linux_interface.startswith("PortChannel"), \
        "Expected a PortChannel for OSPF peer, got {}".format(linux_interface)
    vpp_interface = "BondEthernet{}".format(linux_interface[len("PortChannel"):])
    output = duthost.shell("docker exec syncd vppctl show lcp")["stdout"]
    match = re.search(
        r"^itf-pair:.*\b{}\s+(\S+)\s+\S+\s+\d+\s+type\s+tap\r?$".format(
            re.escape(vpp_interface)
        ),
        output,
        re.MULTILINE,
    )
    assert match, "No VPP linux-cp pair for {}".format(vpp_interface)
    return vpp_interface, match.group(1)


def _remove_vpp_ospf_mroutes(duthost, paths):
    errors = []
    for source, group, via, role in reversed(paths):
        result = duthost.shell(
            "docker exec syncd vppctl ip mroute del {} {} via {} {}".format(
                source, group, via, role
            ),
            module_ignore_errors=True,
        )
        if result.get("rc") != 0:
            errors.append(result.get("stderr", result))
    if errors:
        raise AssertionError("; ".join(str(error) for error in errors))


def _configure_vpp_ospf_mroutes(duthost, peer_ips):
    """Route OSPF multicast between VPP LAGs and their linux-cp taps."""
    paths = []
    try:
        for peer_ip in peer_ips:
            route = _linux_route_for_peer(duthost, peer_ip)
            linux_interface = route["dev"]
            local_ip = route.get("prefsrc") or route.get("src")
            assert local_ip, "No preferred source address for {}".format(peer_ip)
            vpp_interface, vpp_host_interface = _vpp_lcp_pair(duthost, linux_interface)

            for group in ("224.0.0.5", "224.0.0.6"):
                route_paths = (
                    (peer_ip, group, vpp_interface, "Accept"),
                    (peer_ip, group, "local", "Forward"),
                    (local_ip, group, vpp_host_interface, "Accept"),
                    (local_ip, group, vpp_interface, "Forward"),
                )
                for path in route_paths:
                    result = duthost.shell(
                        "docker exec syncd vppctl ip mroute add {} {} via {} {}".format(*path),
                        module_ignore_errors=True,
                    )
                    assert result.get("rc") == 0, result.get("stderr", result)
                    paths.append(path)
    except Exception as original_error:
        try:
            _remove_vpp_ospf_mroutes(duthost, paths)
        except Exception as cleanup_error:
            logger.error(
                "Failed to roll back partial VPP OSPF multicast setup after %r: %s",
                original_error,
                cleanup_error,
            )
        raise
    return paths


def _configure_dut_ospf(duthost, peer_ips, dut_asn):
    peer_ips = list(peer_ips)
    _start_dut_daemon(duthost, "ospfd")
    interfaces = sorted({_linux_interface_for_peer(duthost, ip) for ip in peer_ips})
    commands = [
        "configure terminal",
        "no router bgp {}".format(dut_asn),
        "router ospf",
        "exit",
    ]
    for interface in interfaces:
        commands.extend([
            "interface {}".format(interface),
            "ip ospf area 0.0.0.0",
            "ip ospf mtu-ignore",
            "exit",
        ])
    commands.extend(["do write", "end"])
    _run_or_fail(duthost, _vtysh(commands), "configuring VPP OSPF")


def _configure_dut_bfd(duthost, peer_ips):
    peer_ips = list(peer_ips)
    interfaces = sorted({_linux_interface_for_peer(duthost, ip) for ip in peer_ips})
    commands = ["configure terminal", "bfd"]
    commands.extend("peer {}".format(ip) for ip in peer_ips)
    commands.append("exit")
    for interface in interfaces:
        commands.extend([
            "interface {}".format(interface),
            "ip ospf bfd",
            "exit",
        ])
    commands.extend(["do write", "end"])
    _run_or_fail(duthost, _vtysh(commands), "configuring VPP OSPF BFD")


def _json_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _json_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _json_objects(child)


def _bfd_peer_state(duthost, peer_ip):
    result = duthost.shell(
        'vtysh -c "show bfd peers json"',
        module_ignore_errors=True,
    )
    if result.get("rc") != 0:
        return None
    try:
        data = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError):
        return None

    for entry in _json_objects(data):
        peer = entry.get("peer") or entry.get("peerAddress") or entry.get("remote")
        state = entry.get("status") or entry.get("state") or entry.get("sessionState")
        if str(peer) == str(peer_ip) and state is not None:
            return str(state).lower()
    return None


def _bfd_peer_up(duthost, peer_ip):
    return _bfd_peer_state(duthost, peer_ip) == "up"


def _ceos_bfd_peer_state(host, dut_ip):
    vrf = host.bgp_vrf or "default"
    command = "show bfd peers"
    if host.bgp_vrf:
        command = "{} vrf {}".format(command, host.bgp_vrf)
    try:
        data = host.run_command_json(command)
    except Exception:
        return None

    neighbor = (
        data.get("vrfs", {})
        .get(vrf, {})
        .get("ipv4Neighbors", {})
        .get(str(dut_ip))
    )
    if not isinstance(neighbor, dict):
        return None
    for entry in _json_objects(neighbor):
        if entry.get("status") is not None:
            return str(entry["status"]).lower()
    return None


def _wait_for_bfd_peers(duthost, peers):
    peer_ips = list(peers)
    assert wait_until(
        90,
        3,
        0,
        lambda: all(_bfd_peer_up(duthost, peer_ip) for peer_ip in peer_ips),
    ), "DUT BFD peers did not all reach Up: {}".format(peer_ips)
    assert wait_until(
        90,
        3,
        0,
        lambda: all(
            _ceos_bfd_peer_state(peers[peer_ip]["host"], peers[peer_ip]["dut_ip"]) == "up"
            for peer_ip in peer_ips
        ),
    ), "cEOS BFD peers did not all reach Up: {}".format(peer_ips)


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


def _ospf_routes_present(duthost, prefixes):
    return set(prefixes).issubset(set(_route_prefixes(duthost)))


def _wait_for_ospf_routes(duthost, prefixes):
    prefixes = list(prefixes)
    assert wait_until(90, 5, 0, _ospf_routes_present, duthost, prefixes), \
        "OSPF routes do not contain cEOS loopbacks: {}".format(prefixes)


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
        "expected_routes": [],
    }
    configured_hosts = []
    mroute_paths = []
    try:
        for name in sorted(peers):
            details = _configure_ceos_ospf(nbrhosts[name], enable_bfd=False)
            details["host"] = nbrhosts[name]["host"]
            setup_info["neighbors"][name] = details
            setup_info["expected_routes"].append(details["loopback"])
            configured_hosts.append((nbrhosts[name]["host"], details))

        mroute_paths = _configure_vpp_ospf_mroutes(duthost, peers.values())
        _configure_dut_ospf(duthost, peers.values(), mg_facts["minigraph_bgp_asn"])
        _wait_for_ospf_peers(duthost, peers.values())
        _wait_for_ospf_routes(duthost, setup_info["expected_routes"])
        yield setup_info
    finally:
        primary_error = sys.exc_info()[1]
        _run_cleanup_actions(
            primary_error,
            [
                (
                    "removing VPP OSPF multicast routes",
                    lambda: _remove_vpp_ospf_mroutes(duthost, mroute_paths),
                ),
                (
                    "cleaning cEOS OSPF configuration",
                    lambda: _cleanup_ceos_hosts(configured_hosts),
                ),
                (
                    "restoring DUT configuration",
                    lambda: _reload_and_wait(duthost, safe_reload=True),
                ),
            ],
        )


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
    except Exception as original_error:
        try:
            _restore_bfd_host_firewall(duthost, inserted)
        except Exception as cleanup_error:
            logger.error(
                "Failed to roll back partial BFD firewall setup after %r: %s",
                original_error,
                cleanup_error,
            )
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
    mroute_paths = []
    try:
        for details in peers.values():
            nbr_info = nbrhosts[details["neighbor_name"]]
            details.update(_configure_ceos_ospf(nbr_info, enable_bfd=True))
            configured_hosts.append((nbr_info["host"], details))

        inserted = _allow_bfd_in_host_firewall(duthost)
        _start_dut_daemon(duthost, "bfdd")
        mroute_paths = _configure_vpp_ospf_mroutes(duthost, peers.keys())
        _configure_dut_ospf(duthost, peers.keys(), dut_asn)
        _configure_dut_bfd(duthost, peers.keys())
        _wait_for_ospf_peers(duthost, peers.keys())
        _wait_for_ospf_routes(duthost, [peer["loopback"] for peer in peers.values()])
        _wait_for_bfd_peers(duthost, peers)
        yield {
            _VPP_CEOS_KEY: True,
            "peers": peers,
        }
    finally:
        primary_error = sys.exc_info()[1]
        _run_cleanup_actions(
            primary_error,
            [
                (
                    "removing VPP OSPF multicast routes",
                    lambda: _remove_vpp_ospf_mroutes(duthost, mroute_paths),
                ),
                (
                    "restoring DUT BFD firewall rules",
                    lambda: _restore_bfd_host_firewall(duthost, inserted),
                ),
                (
                    "cleaning cEOS OSPF/BFD configuration",
                    lambda: _cleanup_ceos_hosts(configured_hosts),
                ),
                (
                    "restoring DUT configuration",
                    lambda: _reload_and_wait(
                        duthost,
                        config_source="config_db",
                        safe_reload=True,
                    ),
                ),
            ],
        )


def _route_prefixes(duthost):
    output = duthost.shell("show ip route ospf")["stdout"]
    pattern = re.compile(r"^\s*O[^\n]*?([0-9]+(?:\.[0-9]+){3}/[0-9]+)", re.MULTILINE)
    return sorted(set(pattern.findall(output)))


def _bfd_fault_acl_name(peer_ip):
    return "{}{}".format(_BFD_FAULT_ACL_PREFIX, str(peer_ip).replace(".", "_"))


def _ceos_interface_connected(host, interface):
    output = host.run_command_json("show interfaces {} status".format(interface))
    status = output.get("interfaceStatuses", {}).get(interface, {})
    return (
        status.get("linkStatus") == "connected"
        and status.get("lineProtocolStatus") == "up"
    )


def _cleanup_ceos_bfd_fault(host, fault):
    errors = []

    def cleanup(description, **kwargs):
        try:
            result = host.eos_config(module_ignore_errors=True, **kwargs)
            if result.get("failed"):
                errors.append((description, result))
        except Exception as error:
            errors.append((description, error))

    acl_name = fault["acl_name"]
    if fault.get("acl_attached"):
        cleanup(
            "detaching BFD fault ACL",
            lines=["no ip access-group {} out".format(acl_name)],
            parents=["interface {}".format(fault["interface"])],
        )
    if fault.get("acl_created"):
        cleanup(
            "deleting BFD fault ACL",
            lines=["no ip access-list {}".format(acl_name)],
        )

    try:
        residue = _command_text(
            host.run_command("show running-config | include {}".format(acl_name))
        )
        if acl_name in residue:
            errors.append(("verifying BFD fault ACL removal", residue))
    except Exception as error:
        errors.append(("verifying BFD fault ACL removal", error))

    if errors:
        raise AssertionError("; ".join("{}: {}".format(*error) for error in errors))


def _assert_ceos_bfd_fault_available(host, interface, acl_name):
    acl_config = _command_text(
        host.run_command(
            "show running-config section ip access-list {}".format(acl_name)
        )
    )
    assert not re.search(
        r"^\s*ip access-list\s+{}\s*$".format(re.escape(acl_name)),
        acl_config,
        re.MULTILINE,
    ), "Refusing to overwrite existing cEOS ACL {}".format(acl_name)

    interface_config = _command_text(
        host.run_command("show running-config interfaces {}".format(interface))
    )
    outbound_acls = re.findall(
        r"^\s*ip access-group\s+(\S+)\s+out\s*$",
        interface_config,
        re.MULTILINE,
    )
    assert not outbound_acls, \
        "Refusing to replace outbound cEOS ACL(s) {} on {}".format(
            outbound_acls, interface
        )


def _configure_ceos_bfd_fault(host, interface, dut_ip, peer_ip):
    fault = {
        "acl_name": _bfd_fault_acl_name(peer_ip),
        "interface": interface,
        "acl_created": False,
        "acl_attached": False,
    }
    _assert_ceos_bfd_fault_available(host, interface, fault["acl_name"])
    try:
        # Register ownership before each write because a remote command can
        # apply successfully and still return an ambiguous failure.
        fault["acl_created"] = True
        _eos_config_or_raise(
            host,
            "creating silent BFD-loss ACL",
            lines=[
                "10 deny udp any host {} eq 3784".format(dut_ip),
                "20 deny udp any host {} eq 4784".format(dut_ip),
                "30 permit ip any any",
            ],
            parents=["ip access-list {}".format(fault["acl_name"])],
        )
        fault["acl_attached"] = True
        _eos_config_or_raise(
            host,
            "attaching silent BFD-loss ACL",
            lines=["ip access-group {} out".format(fault["acl_name"])],
            parents=["interface {}".format(interface)],
        )
    except Exception as original_error:
        try:
            _cleanup_ceos_bfd_fault(host, fault)
        except Exception as cleanup_error:
            logger.error(
                "Failed to roll back partial BFD fault injection after %r: %s",
                original_error,
                cleanup_error,
            )
        raise
    return fault


def verify_bfd_failure(setup_info, duthost):
    peers = setup_info["peers"]
    peer_ip = sorted(peers)[0]
    peer = peers[peer_ip]
    host = peer["host"]
    interface = peer["routed_interface"]
    loopback = peer["loopback"]

    assert _bfd_peer_state(duthost, peer_ip) == "up", \
        "DUT BFD peer {} is not explicitly Up".format(peer_ip)
    assert _ceos_bfd_peer_state(host, peer["dut_ip"]) == "up", \
        "cEOS BFD peer {} is not explicitly Up".format(peer["dut_ip"])
    assert loopback in _route_prefixes(duthost), \
        "OSPF route {} is absent before BFD failure injection".format(loopback)
    assert _ceos_interface_connected(host, interface), \
        "cEOS interface {} is not connected before BFD failure injection".format(interface)

    fault = _configure_ceos_bfd_fault(
        host,
        interface,
        peer["dut_ip"],
        peer_ip,
    )
    try:
        assert _ceos_interface_connected(host, interface), \
            "cEOS interface {} lost carrier during BFD fault injection".format(interface)
        assert wait_until(
            20,
            1,
            0,
            lambda: _bfd_peer_state(duthost, peer_ip) == "down",
        ), "DUT BFD peer {} did not explicitly reach Down after silent loss".format(peer_ip)
        assert wait_until(
            20,
            1,
            0,
            lambda: _ceos_bfd_peer_state(host, peer["dut_ip"]) in ("down", "init"),
        ), "cEOS BFD peer {} did not explicitly leave Up after silent loss".format(
            peer["dut_ip"]
        )
        assert wait_until(20, 1, 0, lambda: loopback not in _route_prefixes(duthost)), \
            "OSPF route {} was not withdrawn after BFD failure".format(loopback)
        assert _ceos_interface_connected(host, interface), \
            "cEOS interface {} lost carrier during BFD failure".format(interface)
    finally:
        primary_error = sys.exc_info()[1]
        try:
            _cleanup_ceos_bfd_fault(host, fault)
        except Exception as cleanup_error:
            if primary_error is None:
                raise
            logger.error(
                "Failed to remove BFD fault after test failure %r: %s",
                primary_error,
                cleanup_error,
            )

    assert wait_until(60, 2, 0, lambda: _bfd_peer_state(duthost, peer_ip) == "up"), \
        "DUT BFD peer {} did not recover to Up".format(peer_ip)
    assert wait_until(
        60,
        2,
        0,
        lambda: _ceos_bfd_peer_state(host, peer["dut_ip"]) == "up",
    ), "cEOS BFD peer {} did not recover to Up".format(peer["dut_ip"])
    assert wait_until(60, 2, 0, lambda: loopback in _route_prefixes(duthost)), \
        "OSPF route {} did not recover after removing BFD fault".format(loopback)
    assert _ceos_interface_connected(host, interface), \
        "cEOS interface {} is not connected after BFD recovery".format(interface)


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
