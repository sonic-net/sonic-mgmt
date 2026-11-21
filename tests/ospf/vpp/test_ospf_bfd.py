import json
import shlex

import pytest

from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("t0")]

_BFD_FIREWALL_RULE = "! -i eth0 -p udp -m multiport --dports 3784,4784 -j ACCEPT"


def _allow_bfd_in_host_firewall(duthost):
    """Open the same FRR BFD ports that caclmgrd opens for SAI-backed sessions."""
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
    for command in reversed(inserted):
        result = duthost.shell(
            "sudo {} -D INPUT {}".format(command, _BFD_FIREWALL_RULE),
            module_ignore_errors=True,
        )
        assert result.get("rc") == 0, result.get("stderr", result)


def _start_daemon(duthost, daemon, container):
    command = (
        "docker exec {container} bash -lc "
        "'pgrep -x {daemon} >/dev/null || /usr/lib/frr/{daemon} -d'"
    ).format(container=container, daemon=daemon)
    result = duthost.shell(command, module_ignore_errors=True)
    assert result["rc"] == 0, result.get("stderr", result)


@pytest.fixture(scope="module")
def start_ospfd(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    for asic in duthost.asics:
        container = "bgp{}".format(asic.asic_index) if duthost.is_multi_asic else "bgp"
        _start_daemon(duthost, "ospfd", container)


@pytest.fixture(scope="module")
def start_bfdd(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    # caclmgrd opens UDP/3784 and UDP/4784 only after a SAI-backed
    # BFD_SESSION_TABLE event. This qualification uses FRR BFD directly and
    # intentionally creates no SAI BFD object, so mirror caclmgrd's rules for
    # the lifetime of the module and remove only rules inserted here.
    inserted = _allow_bfd_in_host_firewall(duthost)
    try:
        for asic in duthost.asics:
            container = "bgp{}".format(asic.asic_index) if duthost.is_multi_asic else "bgp"
            _start_daemon(duthost, "bfdd", container)
        yield
    finally:
        _restore_bfd_host_firewall(duthost, inserted)


def _ospf_interface(asic, peer_ip):
    command = asic.get_vtysh_cmd_for_namespace('vtysh -c "show ip ospf neighbor"')
    output = asic.shell(command)["stdout"]
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 6 and columns[2].startswith("Full") and peer_ip in columns:
            index = columns.index(peer_ip)
            if index + 1 < len(columns):
                return columns[index + 1].split(":", 1)[0]
    return None


def _bfd_status(asic, peer_ip):
    command = asic.get_vtysh_cmd_for_namespace('vtysh -c "show bfd peers json"')
    result = asic.shell(command, module_ignore_errors=True)
    if result.get("rc") != 0:
        return None
    try:
        sessions = json.loads(result["stdout"])
    except (TypeError, ValueError):
        return None
    for session in sessions:
        if session.get("peer") == peer_ip:
            return session.get("status")
    return None


def _route_present(asic, prefix):
    command = asic.get_vtysh_cmd_for_namespace('vtysh -c "show ip route ospf"')
    return prefix in asic.shell(command)["stdout"]


def _linux_interface_for_peer(asic, peer_ip):
    routes = json.loads(asic.shell("ip -j route get {}".format(shlex.quote(peer_ip)))["stdout"])
    assert routes and routes[0].get("dev"), "No Linux interface for {}".format(peer_ip)
    return routes[0]["dev"]


def _vtysh(commands):
    return "vtysh {}".format(" ".join("-c {}".format(shlex.quote(command)) for command in commands))


def _set_remote_bfd_drop(peer, enabled):
    """Silently drop cEOS BFD output without changing OSPF or link state."""
    host = peer["host"]
    assert isinstance(host, EosHost), "SONiC-VPP OSPF/BFD qualification requires cEOS neighbors"
    acl_name = "OSPF_BFD_TEST_DROP"
    interface = peer["ospf_interfaces"][0]
    if enabled:
        result = host.eos_config(
            lines=[
                "10 deny udp any host {} eq 3784".format(peer["dut_ip"]),
                "20 deny udp any host {} eq 4784".format(peer["dut_ip"]),
                "30 permit ip any any",
            ],
            parents=["ip access-list {}".format(acl_name)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        try:
            result = host.eos_config(
                lines=["ip access-group {} out".format(acl_name)],
                parents=["interface {}".format(interface)],
                module_ignore_errors=True,
            )
            assert not result.get("failed"), result
        except Exception:
            host.eos_config(
                lines=["no ip access-group {} out".format(acl_name)],
                parents=["interface {}".format(interface)],
                module_ignore_errors=True,
            )
            host.eos_config(
                lines=["no ip access-list {}".format(acl_name)],
                module_ignore_errors=True,
            )
            raise
        return
    else:
        result = host.eos_config(
            lines=["no ip access-group {} out".format(acl_name)],
            parents=["interface {}".format(interface)],
            module_ignore_errors=True,
        )
        assert not result.get("failed"), result
        result = host.eos_config(
            lines=["no ip access-list {}".format(acl_name)],
            module_ignore_errors=True,
        )
    assert not result.get("failed"), result


def _remote_interface_up(peer):
    interface = peer["ospf_interfaces"][0]
    status = peer["host"].run_command_json("show interfaces {} status".format(interface))
    interfaces = status.get("interfaceStatuses", {})
    return bool(interfaces) and all(item.get("linkStatus") == "connected" for item in interfaces.values())


def test_ospf_with_bfd(vpp_ospf_bfd_setup, duthosts, rand_one_dut_hostname,
                       start_ospfd, start_bfdd):
    """A cEOS BFD-only failure must withdraw and then restore a SONiC-VPP OSPF route."""
    duthost = duthosts[rand_one_dut_hostname]
    peer_ip = sorted(vpp_ospf_bfd_setup)[0]
    peer = vpp_ospf_bfd_setup[peer_ip]
    asic = peer["asic"]

    peer_ips = [
        address for address, info in vpp_ospf_bfd_setup.items()
        if info["asic"].asic_index == asic.asic_index
    ]
    commands = [
        "configure terminal",
        "no router bgp {}".format(peer["dut_asn"]),
        "router ospf",
    ]
    commands.extend("network {}/31 area 0".format(address) for address in peer_ips)
    commands.append("exit")
    for interface in sorted({_linux_interface_for_peer(asic, address) for address in peer_ips}):
        commands.extend(["interface {}".format(interface), "ip ospf mtu-ignore", "exit"])
    commands.append("end")
    command = asic.get_vtysh_cmd_for_namespace(_vtysh(commands))
    result = duthost.shell(command, module_ignore_errors=True)
    assert result["rc"] == 0, result.get("stderr", result)

    assert wait_until(180, 5, 0, lambda: _ospf_interface(asic, peer_ip) is not None), \
        "OSPF peer {} did not reach Full".format(peer_ip)
    interface_name = _ospf_interface(asic, peer_ip)

    commands = [
        "configure terminal",
        "bfd",
        "peer {}".format(peer_ip),
        "exit",
        "exit",
        "interface {}".format(interface_name),
        "ip ospf bfd",
        "end",
    ]
    command = asic.get_vtysh_cmd_for_namespace(_vtysh(commands))
    result = duthost.shell(command, module_ignore_errors=True)
    assert result["rc"] == 0, result.get("stderr", result)

    prefix = peer["loopback"]
    remote_dropped = False
    try:
        assert wait_until(60, 3, 0, lambda: _bfd_status(asic, peer_ip) == "up"), \
            "BFD peer {} did not reach Up".format(peer_ip)
        assert wait_until(60, 3, 0, _route_present, asic, prefix), \
            "OSPF route {} was not installed".format(prefix)

        _set_remote_bfd_drop(peer, True)
        remote_dropped = True
        assert wait_until(30, 1, 0, lambda: _bfd_status(asic, peer_ip) == "down"), \
            "BFD peer {} did not report Down after remote packet loss".format(peer_ip)
        assert wait_until(30, 1, 0, lambda: not _route_present(asic, prefix)), \
            "OSPF route {} was not withdrawn after BFD failure".format(prefix)
        assert _remote_interface_up(peer), "cEOS routed interface went down during the BFD-only fault"

        _set_remote_bfd_drop(peer, False)
        remote_dropped = False
        assert wait_until(90, 3, 0, lambda: _bfd_status(asic, peer_ip) == "up"), \
            "BFD peer {} did not recover".format(peer_ip)
        assert wait_until(90, 3, 0, _route_present, asic, prefix), \
            "OSPF route {} did not recover".format(prefix)
    finally:
        if remote_dropped:
            _set_remote_bfd_drop(peer, False)
        cleanup = [
            "configure terminal",
            "interface {}".format(interface_name),
            "no ip ospf bfd",
            "exit",
            "bfd",
            "no peer {}".format(peer_ip),
            "end",
        ]
        asic.shell(
            asic.get_vtysh_cmd_for_namespace(_vtysh(cleanup)),
            module_ignore_errors=True,
        )
