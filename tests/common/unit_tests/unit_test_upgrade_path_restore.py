"""Exercise UT2 upgrade and restoration without testbed dependencies."""

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


ROOT = Path(__file__).resolve().parents[2]
HELPERS_PATH = ROOT / "common" / "helpers" / "upgrade_helpers.py"
UPGRADE_PATH = ROOT / "upgrade_path" / "test_upgrade_path.py"


def load_functions(path, names, namespace):
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for function in functions:
        function.decorator_list = []
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)


@pytest.fixture
def upgrade():
    events = Mock()
    namespace = {
        "json": json,
        "logger": Mock(),
        "config_reload": events.config_reload,
        "install_sonic": events.install_sonic,
        "reboot": events.reboot,
        "cleanup_prev_images": events.cleanup_prev_images,
        "boot_into_base_image": events.boot_into_base_image,
        "setup_upgrade_test": events.setup_upgrade_test,
        "REBOOT_TYPE_COLD": "cold",
        "pytest": pytest,
    }
    load_functions(HELPERS_PATH, {"regenerate_and_apply_golden_config_db", "restore_image_ut2"}, namespace)
    load_functions(UPGRADE_PATH, {"test_upgrade_path_t2"}, namespace)

    def run_upgrade(*args, **kwargs):
        kwargs["preboot_setup"]()
        kwargs["postboot_setup"]()

    namespace["upgrade_test_helper"] = Mock(side_effect=run_upgrade)
    dut = Mock()
    dut.hostname = "dut1"
    dut.facts = {"num_asic": 1}
    dut.shell.return_value = {"stdout": json.dumps({"DNS_NAMESERVER": {"192.0.2.53": {}}})}
    dut.host.options = {
        "inventory_manager": Mock(),
        "variable_manager": Mock(),
    }
    dut.host.options["variable_manager"].get_vars.return_value = {
        "enable_macsec": True, "macsec_profile": "profile1",
    }
    duthosts = [dut]
    tbinfo = {"topo": {"name": "t2_single_node", "properties": {
        "configuration_properties": {"common": {"dut_confed_asn": "123", "dut_confed_peers": "456"}}
    }}}
    graph = {"device_conn": {"dut1": {"Ethernet0": {"LinkTraining": "on"}}}}
    return SimpleNamespace(ns=namespace, events=events, dut=dut, duthosts=duthosts, tbinfo=tbinfo, graph=graph)


def test_ut2_upgrade_and_restore_regenerate_after_each_boot(upgrade):
    ns, dut, tbinfo, graph, events = upgrade.ns, upgrade.dut, upgrade.tbinfo, upgrade.graph, upgrade.events

    class Hosts(list):
        supervisor_nodes = []

    hosts = Hosts(upgrade.duthosts)
    images = ("cold", "base", "target", "original", False)
    restore = ns["restore_image_ut2"]("localhost", hosts, images, tbinfo, graph)
    dns_config = next(restore)
    dut.shell.return_value = {"stdout": "{}"}
    ns["test_upgrade_path_t2"]("localhost", hosts, "ptf", images, tbinfo, None, None, graph, dns_config)
    with pytest.raises(StopIteration):
        next(restore)

    assert dns_config == {"DNS_NAMESERVER": {"192.0.2.53": {}}}
    assert dut.copy.call_args_list == [
        call(content=json.dumps(dns_config), dest="/tmp/dns_config.json"),
        call(src="common/macsec/profile.json", dest="/tmp/profile.json"),
        call(src="../ansible/templates/golden_config_db_t2.j2", dest="/tmp/golden_config_db_t2.j2"),
    ] * 2
    expected_generate = call(
        topo_name="t2_single_node", num_asics=1, macsec_profile="profile1",
        bgp_confd_asn="123", bgp_confd_peers="456", device_conn=graph["device_conn"]["dut1"])
    assert dut.generate_golden_config_db.call_args_list == [expected_generate, expected_generate]
    assert events.method_calls == [
        call.cleanup_prev_images(dut),
        call.boot_into_base_image(dut, "localhost", "base", tbinfo),
        call.setup_upgrade_test(dut, "localhost", "base", "target", tbinfo, "cold"),
        call.config_reload(dut, config_source="minigraph", override_config=True, safe_reload=True, wait_for_bgp=True),
        call.install_sonic(dut, "original", tbinfo),
        call.reboot(dut, "localhost"),
        call.config_reload(dut, config_source="minigraph", override_config=True, safe_reload=True, wait_for_bgp=True),
    ]


@pytest.mark.parametrize("topology,restore_to_image", [
    ("t2_single_node", ""),
    ("t2", "original"),
])
def test_no_restore_when_disabled_or_modular(upgrade, topology, restore_to_image):
    upgrade.tbinfo["topo"]["name"] = topology
    images = ("cold", "base", "target", restore_to_image, False)
    restore = upgrade.ns["restore_image_ut2"](
        "localhost", upgrade.duthosts, images, upgrade.tbinfo, upgrade.graph)
    dns_config = next(restore)
    with pytest.raises(StopIteration):
        next(restore)
    if topology == "t2":
        assert dns_config is None
        upgrade.dut.shell.assert_not_called()
        upgrade.ns["regenerate_and_apply_golden_config_db"](
            upgrade.dut, upgrade.tbinfo, upgrade.graph, dns_config)
        upgrade.dut.generate_golden_config_db.assert_not_called()
    else:
        assert dns_config == {"DNS_NAMESERVER": {"192.0.2.53": {}}}
    assert upgrade.events.method_calls == []


def test_restore_failure_propagates_without_reload(upgrade):
    upgrade.events.reboot.side_effect = RuntimeError("reboot failed")
    images = ("cold", "base", "target", "original", False)
    restore = upgrade.ns["restore_image_ut2"](
        "localhost", upgrade.duthosts, images, upgrade.tbinfo, upgrade.graph)
    next(restore)
    with pytest.raises(RuntimeError, match="reboot failed"):
        next(restore)
    upgrade.dut.generate_golden_config_db.assert_not_called()
