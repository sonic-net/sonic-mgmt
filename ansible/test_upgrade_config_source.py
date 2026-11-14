"""Offline tests for configuration policy propagation through upgrade entry points."""

import ast
import importlib.util
import ipaddress
import logging
import runpy
import sys
import types
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlparse

import pytest
import yaml
from jinja2 import Environment


ROOT = Path(__file__).resolve().parents[1]


class UpgradeFailed(Exception):
    pass


def register_module(monkeypatch, name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def sonic(monkeypatch):
    """Load devutil without importing the Ansible execution engine."""
    register_module(monkeypatch, "devutil")
    register_module(monkeypatch, "devutil.devices")
    register_module(monkeypatch, "devutil.devices.ansible_hosts",
                    AnsibleHosts=object, RunAnsibleModuleFailed=UpgradeFailed, HostsUnreachable=UpgradeFailed)
    register_module(monkeypatch, "devutil.devices.chassis_utils",
                    is_chassis=Mock(return_value=False), get_chassis_hostnames=Mock(), ChassisCardType=Mock())
    spec = importlib.util.spec_from_file_location(
        "devutil.devices.sonic", ROOT / "ansible" / "devutil" / "devices" / "sonic.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hosts():
    hosts = Mock()
    hosts.hostnames = ["switch"]
    hosts.SUPPORTED_UPGRADE_TYPES = ["sonic", "onie"]
    hosts.sonic_version = {"switch": {"build_version": "test"}}
    return hosts


@pytest.mark.parametrize("source", [None, "config_db", "minigraph"])
def test_devutil_policy_reaches_module(sonic, hosts, monkeypatch, source):
    """The public helper and sonic installer helper retain the same selected source."""
    post_upgrade = Mock(return_value=True)
    monkeypatch.setattr(sonic, "post_upgrade_actions", post_upgrade)
    options = {} if source is None else {"config_source": source}
    assert sonic.upgrade_image(hosts, Mock(), "image.bin", **options)
    assert hosts.reduce_and_add_sonic_images.call_args.kwargs["config_source"] == (source or "config_db")
    hosts.shell.assert_called_once_with("reboot", module_attrs={"become": True, "async": 300, "poll": 0})
    post_upgrade.assert_called_once()


def test_devutil_failure_prevents_reboot(sonic, hosts, monkeypatch):
    """Rejected source selection must propagate through upgrade_image."""
    post_upgrade = Mock()
    monkeypatch.setattr(sonic, "post_upgrade_actions", post_upgrade)
    hosts.reduce_and_add_sonic_images.side_effect = UpgradeFailed("invalid selected configuration")
    assert not sonic.upgrade_image(hosts, Mock(), "image.bin", config_source="minigraph")
    hosts.shell.assert_not_called()
    post_upgrade.assert_not_called()


def test_invalid_policy_prevents_upgrade(sonic, hosts):
    """Invalid source strings are rejected before any host operations."""
    assert not sonic.upgrade_image(hosts, Mock(), "image.bin", config_source="automatic")
    hosts.reduce_and_add_sonic_images.assert_not_called()
    hosts.shell.assert_not_called()


def test_onie_does_not_receive_config_policy(sonic, hosts, monkeypatch, caplog):
    """ONIE retains its separate reimage behavior and explicitly reports the limitation."""
    onie = Mock(return_value=True)
    monkeypatch.setattr(sonic, "upgrade_by_onie", onie)
    monkeypatch.setattr(sonic, "post_upgrade_actions", Mock(return_value=True))
    localhost = Mock()
    with caplog.at_level(logging.INFO):
        assert sonic.upgrade_image(hosts, localhost, "image.bin", upgrade_type="onie")
    onie.assert_called_once_with(hosts, localhost, "image.bin", 0)
    hosts.reduce_and_add_sonic_images.assert_not_called()
    assert "ONIE reimages do not preserve" in caplog.text


@pytest.fixture
def cli(monkeypatch, sonic, hosts):
    """Exercise full CLI parsers and mains with host/network boundaries mocked."""
    localhost = Mock()
    localhost.conn_graph_facts.return_value = {"ansible_facts": {}}
    register_module(monkeypatch, "devutil.devices.factory", init_localhost=Mock(return_value=localhost),
                    init_testbed_sonichosts=Mock(return_value=hosts), init_sonichosts=Mock(return_value=hosts))
    register_module(monkeypatch, "devutil.devices.dpu_utils", enable_nat_for_dpuhosts=Mock())
    register_module(monkeypatch, "common", get_pdu_managers=Mock(),
                    check_reachability=Mock(return_value={"switch": True}))
    register_module(monkeypatch, "requests", head=Mock(return_value=types.SimpleNamespace(status_code=200)))
    upgrade = Mock(return_value=True)
    monkeypatch.setattr(sonic, "upgrade_image", upgrade)
    # Both scripts append their import roots.
    monkeypatch.setattr(sys, "path", sys.path[:])

    def run(script, extra_args=()):
        filename = ROOT / script
        monkeypatch.setattr(sys, "argv", [
            str(filename), "-i", "unused-inventory", "-t", "unused-testbed",
            "-u", "https://example.com/sonic.bin", *extra_args,
        ])
        return runpy.run_path(str(filename), run_name="__main__")

    return run, upgrade


@pytest.mark.parametrize("script,expected_calls", [
    (".azure-pipelines/upgrade_image.py", 2),
    ("ansible/upgrade_sonic.py", 1),
])
@pytest.mark.parametrize("source", [None, "config_db", "minigraph"])
def test_cli_policy_for_every_image(cli, script, expected_calls, source):
    """CLI defaults and explicit choices reach previous and target image upgrades."""
    run, upgrade = cli
    run(script, [] if source is None else ["--config-source", source])
    assert upgrade.call_count == expected_calls
    assert all(call.kwargs["config_source"] == (source or "config_db") for call in upgrade.call_args_list)
    if expected_calls == 2:
        assert upgrade.call_args_list[0].args[2] == "https://example.com/sonic.bin.PREV.1"
    assert upgrade.call_args_list[-1].args[2] == "https://example.com/sonic.bin"


@pytest.mark.parametrize("script", [".azure-pipelines/upgrade_image.py", "ansible/upgrade_sonic.py"])
def test_cli_rejects_invalid_source(cli, script):
    """The CLI cannot accept ambiguous automatic source selection."""
    run, upgrade = cli
    with pytest.raises(SystemExit) as error:
        run(script, ["--config-source", "automatic"])
    assert error.value.code == 2
    upgrade.assert_not_called()


@pytest.mark.parametrize("results,exit_code", [([False], 2), ([True, False], 3)])
def test_pipeline_upgrade_failure_stops(cli, results, exit_code):
    """Failure on either image prevents subsequent upgrade work."""
    run, upgrade = cli
    upgrade.side_effect = results
    with pytest.raises(SystemExit) as error:
        run(".azure-pipelines/upgrade_image.py", ["--config-source", "minigraph"])
    assert error.value.code == exit_code
    assert upgrade.call_count == len(results)


def load_helper(relative_path, name, **dependencies):
    """Load a production helper without importing the live pytest/DUT fixture tree."""
    filename = ROOT / relative_path
    tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(tree.body) == 1
    exec(compile(tree, str(filename), "exec"), dependencies)
    return dependencies[name]


@pytest.mark.parametrize("source", [None, "config_db", "minigraph"])
@pytest.mark.parametrize("url", ["https://example.com/sonic.bin", "image.bin"])
def test_test_helper_policy_for_url_and_local_image(source, url):
    """install_sonic forwards policy for remote download and local copy paths."""
    install = load_helper("tests/common/helpers/upgrade_helpers.py", "install_sonic",
                          urlparse=urlparse, ipaddress=ipaddress, logger=logging.getLogger(__name__))
    host = Mock()
    host.get_extended_minigraph_facts.return_value = {"minigraph_mgmt_interface": {"gwaddr": "192.0.2.1"}}
    host.get_ip_route_info.return_value = {"nexthops": [(ipaddress.IPv4Address("192.0.2.1"),)]}
    host.command.return_value = {"stdout": "Avail\n4096M\n"}
    host.reduce_and_add_sonic_images.return_value = {"ansible_facts": {"downloaded_image_version": "test"}}
    options = {} if source is None else {"config_source": source}
    assert install(host, url, {}, **options) == "test"
    assert host.reduce_and_add_sonic_images.call_args.kwargs["config_source"] == (source or "config_db")
    host.shell.assert_not_called()


@pytest.mark.parametrize("smartswitch", [False, True])
def test_base_image_explicit_rebuild_and_safety(smartswitch):
    """Intentional base-image rebuilds use module safety, not unconditional JSON deletion."""
    install = Mock(return_value="test")
    helper = load_helper("tests/upgrade_path/utilities.py", "_install_base_image",
                         install_sonic=install, logger=logging.getLogger(__name__))
    host = Mock()
    host.dut_basic_facts.return_value = {"ansible_facts": {"dut_basic_facts": {"is_smartswitch": smartswitch}}}
    assert helper(host, "image.bin", {}) == "test"
    install.assert_called_once_with(host, "image.bin", {},
                                    config_source="config_db" if smartswitch else "minigraph")
    host.shell.assert_not_called()
    install.side_effect = UpgradeFailed("migration or source validation failed")
    with pytest.raises(UpgradeFailed):
        helper(host, "image.bin", {})
    host.shell.assert_not_called()


def test_playbook_policy_only_for_install():
    """The playbook renders the same default/opt-in and leaves cleanup-only calls alone."""
    playbook = yaml.safe_load((ROOT / "ansible" / "upgrade_sonic.yml").read_text(encoding="utf-8"))
    tasks = playbook[1]["tasks"]
    install_block = next(task for task in tasks if task.get("when") == 'upgrade_type == "sonic"')
    install = next(task for task in install_block["block"] if "reduce_and_add_sonic_images" in task)
    template = Environment().from_string(install["args"]["config_source"])
    assert template.render() == "config_db"
    assert template.render(config_source="minigraph") == "minigraph"
    cleanup = next(task for task in tasks if "reduce_and_add_sonic_images" in task)
    assert "config_source" not in cleanup["args"]
    assert "new_image_url" not in cleanup["args"]
    assert "save_as" not in cleanup["args"]
