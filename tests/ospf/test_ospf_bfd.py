import json
import shlex

import pytest

from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("t0")]


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
    for asic in duthost.asics:
        container = "bgp{}".format(asic.asic_index) if duthost.is_multi_asic else "bgp"
        _start_daemon(duthost, "bfdd", container)


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


def _set_remote_bfd(peer, shutdown):
    host = peer["host"]
    assert isinstance(host, EosHost), "SONiC-VPP OSPF/BFD qualification requires cEOS neighbors"
    result = host.config(
        lines=["shutdown" if shutdown else "no shutdown"],
        parents=["router bfd"],
        module_ignore_errors=True,
    )
    assert not result.get("failed"), result


def test_ospf_with_bfd(ospf_Bfd_setup, duthosts, rand_one_dut_hostname,
                       start_ospfd, start_bfdd):
    """A cEOS BFD-only failure must withdraw and then restore a SONiC-VPP OSPF route."""
    duthost = duthosts[rand_one_dut_hostname]
    peer_ip = sorted(ospf_Bfd_setup)[0]
    peer = ospf_Bfd_setup[peer_ip]
    asic = peer["asic"]

    peer_ips = [
        address for address, info in ospf_Bfd_setup.items()
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
    remote_stopped = False
    try:
        assert wait_until(60, 3, 0, lambda: _bfd_status(asic, peer_ip) == "up"), \
            "BFD peer {} did not reach Up".format(peer_ip)
        assert wait_until(60, 3, 0, _route_present, asic, prefix), \
            "OSPF route {} was not installed".format(prefix)

        _set_remote_bfd(peer, True)
        remote_stopped = True
        assert wait_until(30, 1, 0, lambda: _bfd_status(asic, peer_ip) != "up"), \
            "BFD peer {} remained Up after remote BFD shutdown".format(peer_ip)
        assert wait_until(30, 1, 0, lambda: not _route_present(asic, prefix)), \
            "OSPF route {} was not withdrawn after BFD failure".format(prefix)

        _set_remote_bfd(peer, False)
        remote_stopped = False
        assert wait_until(90, 3, 0, lambda: _bfd_status(asic, peer_ip) == "up"), \
            "BFD peer {} did not recover".format(peer_ip)
        assert wait_until(90, 3, 0, _route_present, asic, prefix), \
            "OSPF route {} did not recover".format(prefix)
    finally:
        if remote_stopped:
            _set_remote_bfd(peer, False)
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
