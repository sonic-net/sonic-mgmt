"""Focused tests; run with pytest ansible/roles/bmc_usb_link/tests."""

import importlib.util
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys
import types

from jinja2 import Environment, StrictUndefined
import pytest
import yaml


ROLE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bmc_usb_link", ROLE / "files" / "bmc_usb_link.py")
link = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(link)
ADDRESS = "169.254.100.2/30"
HOST = ipaddress.IPv4Interface(ADDRESS)


@pytest.fixture
def platform(monkeypatch):
    """Provide public Switch-Host classification APIs without SONiC dependencies."""
    device_info = types.SimpleNamespace(
        is_switch_host=lambda: True, is_switch_bmc=lambda: False,
        get_bmc_address=lambda: "169.254.100.1")
    monkeypatch.setitem(sys.modules, "sonic_py_common", types.SimpleNamespace(device_info=device_info))
    return device_info


@pytest.fixture
def environment(monkeypatch):
    """Model an unmanaged USB interface without executing network commands."""
    state = {
        "links": [{"ifname": "usb0", "ifindex": 8, "addr_info": []}],
        "config": {},
        "networkd": None,
        "ifquery": None,
        "nmcli": None,
        "commands": [],
    }

    def which(name):
        return "/sbin/" + name if name in ("ip", "sonic-cfggen") or state.get(name) is not None else None

    def run(command):
        state["commands"].append(command)
        if command[1:4] == ["-j", "address", "show"]:
            return json.dumps(state["links"])
        if command[0].endswith("ifquery"):
            return state["ifquery"]
        if command[0].endswith("nmcli"):
            return state["nmcli"]
        if command[0].endswith("sonic-cfggen"):
            return json.dumps(state["config"])
        return ""

    def read_text(path):
        return state["networkd"]

    monkeypatch.setattr(link.shutil, "which", which)
    monkeypatch.setattr(link, "run", run)
    monkeypatch.setattr(link.Path, "exists", lambda path: state["networkd"] is not None)
    monkeypatch.setattr(link.Path, "read_text", read_text)
    return state


@pytest.mark.parametrize("interface,address", [
    ("eth0", ADDRESS), ("usb0;reboot", ADDRESS), ("usb-0", ADDRESS),
    ("usb1234567890123", ADDRESS), ("usb0", "192.0.2.2/30"),
    ("usb0", "169.254.100.0/30"), ("usb0", "169.254.100.3/30"),
    ("usb0", "169.254.100.2"), ("usb0", "169.254.100.2/31"),
    ("usb0", "169.254.100.2/15"), ("usb0", "::1/128"),
    ("usb0", "169.254.999.2/30"), ("usb0", ADDRESS + "\n"),
])
def test_invalid_settings(interface, address):
    """Unsafe interface names and invalid or non-link-local host CIDRs must fail."""
    with pytest.raises(ValueError):
        link.validate_settings(interface, address)


def test_valid_settings():
    """The documented dedicated USB link example must be accepted."""
    assert link.validate_settings("usb0", ADDRESS) == HOST


@pytest.mark.parametrize("is_host,is_bmc", [(False, False), (False, True), (True, True)])
def test_reject_other_platforms(platform, is_host, is_bmc):
    """Neither ordinary switches nor BMCs may be configured."""
    platform.is_switch_host = lambda: is_host
    platform.is_switch_bmc = lambda: is_bmc
    with pytest.raises(ValueError, match="only supported"):
        link.check_platform(HOST)


@pytest.mark.parametrize("peer", [
    "169.254.200.1", "169.254.100.2", "169.254.100.0", "169.254.100.3", None, "invalid", "::1",
])
def test_reject_invalid_peer(platform, peer):
    """The configured BMC address must be a distinct usable IPv4 peer in the subnet."""
    platform.get_bmc_address = lambda: peer
    with pytest.raises(ValueError):
        link.check_platform(HOST)


def test_missing_platform_api_fails(platform):
    """Older unsupported platform libraries must fail, not enable an ordinary switch."""
    del platform.is_switch_host
    with pytest.raises(AttributeError):
        link.check_platform(HOST)


@pytest.mark.parametrize("existing", [
    [], [{"family": "inet", "local": "169.254.100.2", "prefixlen": 30}],
    [{"family": "inet6", "local": "fe80::1", "prefixlen": 64}],
])
def test_accept_unmanaged_or_existing_address(environment, existing):
    """An unmanaged interface, including one already configured by this role, is safe."""
    environment["links"][0]["addr_info"] = existing
    link.check_ownership("usb0", HOST, "/sbin/ip")


@pytest.mark.parametrize("links", [[], [{"ifname": "eth0", "ifindex": 1}]])
def test_missing_interface(environment, links):
    """Absent USB interfaces must prevent installation."""
    environment["links"] = links
    with pytest.raises(ValueError, match="missing"):
        link.check_ownership("usb0", HOST, "/sbin/ip")


def test_enslaved_interface(environment):
    """Do not take over a USB interface assigned to a bridge or VRF."""
    environment["links"][0]["master"] = "br0"
    with pytest.raises(ValueError, match="enslaved"):
        link.check_ownership("usb0", HOST, "/sbin/ip")


@pytest.mark.parametrize("address,prefix", [("169.254.100.1", 30), ("169.254.100.2", 16), ("192.0.2.1", 24)])
def test_reject_existing_other_address(environment, address, prefix):
    """Never silently replace or retain an unexpected IPv4 address."""
    environment["links"][0]["addr_info"] = [{"family": "inet", "local": address, "prefixlen": prefix}]
    with pytest.raises(ValueError, match="different IPv4"):
        link.check_ownership("usb0", HOST, "/sbin/ip")


def test_overlapping_subnet(environment):
    """A competing connected subnet must fail before touching the link."""
    environment["links"].append({
        "ifname": "eth0", "ifindex": 1,
        "addr_info": [{"family": "inet", "local": "169.254.1.1", "prefixlen": 16}]})
    with pytest.raises(ValueError, match="overlaps another interface: eth0"):
        link.check_ownership("usb0", HOST, "/sbin/ip")


@pytest.mark.parametrize("owner,value", [
    ("ifquery", "lo\nusb0\n"), ("networkd", "NETWORK_FILE=/etc/systemd/network/usb.network\n"),
    ("nmcli", "yes"), ("nmcli", ""),
])
def test_reject_network_managers(environment, owner, value):
    """Known network managers, including inconclusive NM status, prohibit takeover."""
    environment[owner] = value
    with pytest.raises(ValueError, match="ifupdown|networkd|NetworkManager"):
        link.check_ownership("usb0", HOST, "/sbin/ip")


def test_unmanaged_network_managers(environment):
    """Unrelated ifupdown definitions and explicit unmanaged states are acceptable."""
    environment.update(ifquery="lo\neth0\n", networkd="NETWORK_FILE=\n", nmcli="no")
    link.check_ownership("usb0", HOST, "/sbin/ip")


@pytest.mark.parametrize("table,key", [
    ("PORT", "usb0"), ("MGMT_PORT", "usb0"), ("INTERFACE", "usb0|169.254.100.2/30"),
    ("MGMT_INTERFACE", "usb0|169.254.100.2/30"), ("VLAN_INTERFACE", "usb0"),
    ("PORTCHANNEL_INTERFACE", "usb0"),
])
def test_reject_config_db_ownership(environment, table, key):
    """Live SONiC interface definitions must not be overridden."""
    environment["config"] = {table: {key: {}}}
    with pytest.raises(ValueError, match=table):
        link.check_ownership("usb0", HOST, "/sbin/ip")


def test_probe_failure_propagates(environment, monkeypatch):
    """Failed ownership probes must never permit a network change."""
    def fail(command):
        raise subprocess.CalledProcessError(1, command, stderr="probe failed")

    monkeypatch.setattr(link, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        link.check_ownership("usb0", HOST, "/sbin/ip")


def test_configure_and_reapply(platform, environment):
    """Every apply must issue link-up and address-replace even on an already configured link."""
    link.configure("usb0", ADDRESS)
    environment["links"][0]["addr_info"] = [{"family": "inet", "local": "169.254.100.2", "prefixlen": 30}]
    link.configure("usb0", ADDRESS)
    changes = [command for command in environment["commands"] if command[1] in ("link", "address")]
    expected = [["/sbin/ip", "link", "set", "dev", "usb0", "up"],
                ["/sbin/ip", "address", "replace", ADDRESS, "dev", "usb0"]]
    assert changes == expected * 2


def test_check_mode_does_not_change_link(platform, environment):
    """Read-only preflight must not bring up a link or assign an address."""
    link.configure("usb0", ADDRESS, check=True)
    assert environment["commands"] == [
        ["/sbin/ip", "-j", "address", "show"], ["/sbin/sonic-cfggen", "-d", "--print-data"]]


def test_conflict_prevents_changes(platform, environment):
    """A conflict must be detected before either modifying command runs."""
    environment["ifquery"] = "usb0"
    with pytest.raises(ValueError):
        link.configure("usb0", ADDRESS)
    assert all(command[1] not in ("link", "address") for command in environment["commands"])


def test_missing_iproute2(platform, environment, monkeypatch):
    """Missing required executables must give an actionable error."""
    monkeypatch.setattr(link.shutil, "which", lambda name: None)
    with pytest.raises(ValueError, match="iproute2 is required"):
        link.configure("usb0", ADDRESS)


def test_missing_cfggen(platform, environment, monkeypatch):
    """Without a live CONFIG_DB ownership check the helper must fail closed."""
    monkeypatch.setattr(link.shutil, "which", lambda name: "/sbin/ip" if name == "ip" else None)
    with pytest.raises(ValueError, match="sonic-cfggen is required"):
        link.configure("usb0", ADDRESS)
    assert environment["commands"] == [["/sbin/ip", "-j", "address", "show"]]


def test_address_apply_failure(platform, environment, monkeypatch):
    """An address assignment failure must propagate even when link-up succeeded."""
    run = link.run

    def fail_address(command):
        if command[1:3] == ["address", "replace"]:
            raise subprocess.CalledProcessError(2, command, stderr="address rejected")
        return run(command)

    monkeypatch.setattr(link, "run", fail_address)
    with pytest.raises(subprocess.CalledProcessError):
        link.configure("usb0", ADDRESS)


def test_cli_error_is_explicit(monkeypatch, capsys):
    """Subprocess failures must be surfaced with a failing exit status and stderr."""
    monkeypatch.setattr(sys, "argv", ["bmc_usb_link.py", "usb0", ADDRESS])

    def fail(*args):
        raise subprocess.CalledProcessError(1, ["ip"], stderr="permission denied")

    monkeypatch.setattr(link, "configure", fail)
    assert link.main() == 1
    error = capsys.readouterr().err
    assert "BMC USB link provisioning failed:" in error
    assert "permission denied" in error


def test_unit_and_role_contract():
    """The unit must order against the USB device and PMON, and the role must always reapply."""
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert defaults == {"bmc_usb_link_enabled": False}
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    block = tasks[1]
    assert block["when"] == "bmc_usb_link_enabled"
    assert block["become"] is True
    preflight = block["block"][1]
    assert "--check" in preflight["script"]
    assert "{{ bmc_usb_link_interface | quote }}" in preflight["script"]
    assert "{{ bmc_usb_link_address | quote }}" in preflight["script"]
    assert preflight["check_mode"] is False
    assert preflight["changed_when"] is False
    assert block["block"][-1]["systemd"] == {
        "name": "sonic-bmc-usb-link.service", "daemon_reload": True, "enabled": True, "state": "restarted"}
    unit = Environment(undefined=StrictUndefined).from_string(
        (ROLE / "templates" / "sonic-bmc-usb-link.service.j2").read_text()
    ).render(bmc_usb_link_interface="usb0", bmc_usb_link_address=ADDRESS)
    assert "Requires=sys-subsystem-net-devices-usb0.device" in unit
    assert "After=sys-subsystem-net-devices-usb0.device" in unit
    assert "usb0.device config-setup.service" in unit
    assert "Before=pmon.service" in unit
    assert "JobTimeoutSec=300s" in unit
    assert "ExecStart=/usr/local/sbin/sonic-bmc-usb-link usb0 " + ADDRESS in unit
    assert "WantedBy=multi-user.target" in unit
    assert "ExecStop=" not in unit


def test_upgrade_hook_after_reboot_wait():
    """Image installs must provision only actual upgrade targets after SONiC initialization."""
    plays = yaml.safe_load((ROLE.parents[1] / "upgrade_sonic.yml").read_text())
    assert plays[1]["hosts"] == "upgrade_targets"
    tasks = plays[1]["tasks"]
    hook = next(index for index, task in enumerate(tasks) if task.get("include_role") == {"name": "bmc_usb_link"})
    assert tasks[hook - 1]["name"] == "Wait for SONiC initialization"


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="Requires Linux systemd-analyze")
def test_systemd_unit_dependency_graph(tmp_path):
    """Verify the rendered unit in an isolated root with representative upstream PMON dependencies."""
    units = tmp_path / "etc" / "systemd" / "system"
    units.mkdir(parents=True)
    executable = tmp_path / "usr" / "local" / "sbin" / "sonic-bmc-usb-link"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    unit = Environment(undefined=StrictUndefined).from_string(
        (ROLE / "templates" / "sonic-bmc-usb-link.service.j2").read_text()
    ).render(bmc_usb_link_interface="usb0", bmc_usb_link_address=ADDRESS)
    (units / "sonic-bmc-usb-link.service").write_text(unit)
    for target in ("basic", "sysinit", "shutdown", "multi-user", "sonic"):
        (units / (target + ".target")).write_text("[Unit]\nDefaultDependencies=no\n")
    for service in ("database", "config-setup", "pmon"):
        dependencies = ""
        if service == "pmon":
            dependencies = ("Requires=database.service config-setup.service\n"
                            "After=database.service config-setup.service sonic.target\n"
                            "BindsTo=sonic.target\n")
        if service == "config-setup":
            dependencies = "Requires=database.service\nAfter=database.service\n"
        (units / (service + ".service")).write_text(
            "[Unit]\n" + dependencies
            + "[Service]\nType=oneshot\nExecStart=/usr/local/sbin/sonic-bmc-usb-link\n")
    result = subprocess.run(
        ["systemd-analyze", "--root=" + str(tmp_path), "verify", "sonic-bmc-usb-link.service", "pmon.service"],
        text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
