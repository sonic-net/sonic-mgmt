"""Exercise the upgrade golden-config helper without testbed dependencies."""

import ast
import json
import logging
import unittest
from pathlib import Path
from unittest.mock import Mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "upgrade_path" / "test_upgrade_path.py"


def load_upgrade_functions():
    tree = ast.parse(MODULE_PATH.read_text())
    names = {"regenerate_and_apply_golden_config_db", "test_upgrade_path_t2"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for function in functions:
        function.decorator_list = []
    namespace = {
        "json": json,
        "logger": logging.getLogger(__name__),
        "config_reload": Mock(),
        "cleanup_prev_images": Mock(),
        "boot_into_base_image": Mock(),
        "REBOOT_TYPE_COLD": "cold",
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


class TestUpgradeGoldenConfig(unittest.TestCase):
    def setUp(self):
        self.module = load_upgrade_functions()
        self.dut = Mock()
        self.dut.hostname = "dut-a"
        self.dut.facts = {"num_asic": 1}
        self.dut.host.options = {
            "inventory_manager": Mock(),
            "variable_manager": Mock(),
        }
        self.dut.host.options["variable_manager"].get_vars.return_value = {}
        self.dut.shell.return_value = {"stdout": '{"DNS_NAMESERVER": {}}'}
        self.tbinfo = {
            "topo": {
                "name": "t2_single_node",
                "type": "t2",
                "properties": {"configuration_properties": {"common": {}}},
            }
        }
        self.graph = {
            "device_conn": {
                "dut-a": {"Ethernet0": {"linktraining": "on"}},
                "dut-b": {"Ethernet4": {"linktraining": "off"}},
            }
        }

    def test_postboot_passes_selected_dut_connections(self):
        class DutHosts(list):
            supervisor_nodes = []

        def upgrade(*args, **kwargs):
            kwargs["postboot_setup"]()

        self.module["upgrade_test_helper"] = Mock(side_effect=upgrade)
        self.module["test_upgrade_path_t2"](
            Mock(), DutHosts([self.dut]), Mock(), ("cold", "base", "target", None, False),
            self.tbinfo, Mock(), Mock(), self.graph)

        self.dut.generate_golden_config_db.assert_called_once_with(
            topo_name="t2_single_node", num_asics=1, macsec_profile=None,
            bgp_confd_asn=None, bgp_confd_peers=None,
            device_conn={"Ethernet0": {"linktraining": "on"}})
        self.module["config_reload"].assert_called_once_with(
            self.dut, config_source="minigraph", override_config=True,
            safe_reload=True, wait_for_bgp=True)

    def test_missing_graph_entries_default_to_empty_dict(self):
        for graph in ({}, {"device_conn": {}}, {"device_conn": {"dut-b": {}}}):
            with self.subTest(graph=graph):
                self.dut.generate_golden_config_db.reset_mock()
                self.module["regenerate_and_apply_golden_config_db"](self.dut, self.tbinfo, graph)
                self.assertEqual(self.dut.generate_golden_config_db.call_args.kwargs["device_conn"], {})

    def test_other_topologies_are_unchanged(self):
        self.tbinfo["topo"]["name"] = "t2"
        self.module["regenerate_and_apply_golden_config_db"](self.dut, self.tbinfo, self.graph)
        self.dut.generate_golden_config_db.assert_not_called()
        self.module["config_reload"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
