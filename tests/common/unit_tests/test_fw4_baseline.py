"""Offline regression checks; run with python3 -m unittest discover here.

Load the production functions without importing the DUT-dependent pytest
conftest or Ansible runtime. No switch or inventory is required.
"""
import ast
import copy
import json
import logging
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


def load_function(path, name, globals_):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(module, str(path), "exec"), globals_)
    return globals_[name]


class FakeModule:
    def __init__(self, defaults, rc=0):
        self.defaults = defaults
        self.rc = rc
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.rc, json.dumps(self.defaults), "cfggen failed" if self.rc else ""

    def fail_json(self, **kwargs):
        raise RuntimeError(kwargs["msg"])


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.normalize = load_function("ansible/library/generate_golden_config_db.py",
                                       "complete_fw4_feature_defaults", {"json": json, "copy": copy})
        self.generator = type("Generator", (), {})()
        self.generator.topo_name = "t2_single_node_fw4"
        self.generator.num_asics = 2
        self.defaults = {"FEATURE": {
            "database": {"auto_restart": "always_enabled", "state": "always_enabled"},
            "bgp": {"auto_restart": "enabled", "delayed": "False", "state": "enabled"},
            "dash-ha": {"auto_restart": "enabled", "state": "enabled", "delayed": "False"},
        }}
        self.generator.module = FakeModule(self.defaults)

    def test_partial_entries_keep_image_defaults_and_explicit_policy(self):
        config = {"localhost": {}, "asic0": {"FEATURE": {
            "bgp": {"auto_restart": "disabled"}, "dash-ha": {"state": "disabled"}},
            "BGP_DEVICE_GLOBAL": {"CONFED": {"asn": "65100"}}}, "asic1": {}}
        result = json.loads(self.normalize(self.generator, json.dumps(config)))
        self.assertEqual(result["asic0"]["FEATURE"]["bgp"],
                         {"auto_restart": "disabled", "delayed": "False", "state": "enabled"})
        self.assertEqual(result["asic0"]["FEATURE"]["dash-ha"]["state"], "disabled")
        self.assertEqual(result["asic1"]["FEATURE"]["database"]["auto_restart"], "always_enabled")
        self.assertEqual(result["asic0"]["BGP_DEVICE_GLOBAL"], config["asic0"]["BGP_DEVICE_GLOBAL"])
        self.assertEqual(self.defaults["FEATURE"]["bgp"]["auto_restart"], "enabled")
        self.assertEqual(json.loads(self.normalize(self.generator, json.dumps(result))), result)
        self.assertNotIn("runningconfiguration", " ".join(self.generator.module.commands))

    def test_non_fw4_does_not_read_or_change_configuration(self):
        self.generator.topo_name = "t2_single_node_max"
        config = '{"asic0": {}}'
        self.assertEqual(self.normalize(self.generator, config), config)
        self.assertEqual(self.generator.module.commands, [])

    def test_single_asic_has_flat_tables(self):
        self.generator.num_asics = 1
        result = json.loads(self.normalize(self.generator, '{"PORT": {"Ethernet0": {"speed": "400000"}}}'))
        self.assertIn("FEATURE", result)
        self.assertNotIn("localhost", result)
        self.assertEqual(result["PORT"]["Ethernet0"]["speed"], "400000")

    def test_missing_defaults_and_command_failure_abort(self):
        for module in (FakeModule({}), FakeModule(self.defaults, rc=1)):
            self.generator.module = module
            with self.assertRaises(RuntimeError):
                self.normalize(self.generator, "{}")


class Ut2MetadataTests(unittest.TestCase):
    def setUp(self):
        self.generate = load_function("ansible/library/generate_golden_config_db.py",
                                      "generate_ut2_golden_config_db", {"json": json})
        self.generator = type("Generator", (), {})()
        self.generator.topo_name = "t2_single_node_fw4"
        self.generator.num_asics = 2
        self.generator.bgp_confd_asn = None
        self.generator.bgp_confd_peers = None
        metadata = {"DEVICE_METADATA": {"localhost": {"hwsku": "Arista-7280DR3AM-36"}}}
        self.generator.get_config_from_minigraph_multiasic = lambda: {
            scope: copy.deepcopy(metadata) for scope in ("localhost", "asic0", "asic1")}
        self.generator.get_config_from_minigraph = lambda: json.dumps(metadata)
        self.generator._render_macsec_config = lambda: {}

    def test_every_scope_uses_fairwater_mgmt_type(self):
        result = json.loads(self.generate(self.generator))
        for scope in ("localhost", "asic0", "asic1"):
            self.assertEqual(result[scope]["DEVICE_METADATA"]["localhost"],
                             {"hwsku": "Arista-7280DR3AM-36", "mgmt_type": "FairWater"})

    def test_single_asic_has_flat_metadata(self):
        self.generator.num_asics = 1
        result = json.loads(self.generate(self.generator))
        self.assertEqual(result["DEVICE_METADATA"]["localhost"]["mgmt_type"], "FairWater")

    def test_non_fw4_keeps_minigraph_metadata(self):
        self.generator.topo_name = "t2_single_node_max"
        result = json.loads(self.generate(self.generator))
        for scope in ("localhost", "asic0", "asic1"):
            self.assertNotIn("mgmt_type", result[scope]["DEVICE_METADATA"]["localhost"])


class ImmediateExecutor:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def submit(self, fn, *args):
        fn(*args)


class FakeDut:
    is_multi_asic = True
    facts = {"num_asic": 2}

    def __init__(self, unstable=False, change_on_save=False):
        self.commands = []
        self.files = {}
        self.reads = 0
        self.saves = 0
        self.unstable = unstable
        self.change_on_save = change_on_save

    def shell(self, command, **kwargs):
        self.commands.append(command)
        if command == "config save -y":
            self.saves += 1
        if command.startswith("sonic-cfggen") and ">" not in command:
            sample = self.reads // 3
            self.reads += 1
            value = sample if self.unstable else min(sample, 1)
            if self.change_on_save and self.saves > 1:
                value += 1
            return {"stdout": json.dumps({"FEATURE": {"bgp": {"state": "enabled"}},
                                          "BGP_DEVICE_GLOBAL": {"STATE": {"value": value}}})}
        return {"stdout": ""}

    def copy(self, content, dest, **kwargs):
        self.files[dest] = json.loads(content)


class PretestTests(unittest.TestCase):
    def setUp(self):
        self.reloads = []

        def require(condition, message):
            if not condition:
                raise AssertionError(message)

        def wait(timeout, interval, delay, fn):
            return any(fn() for _ in range(8))

        self.capture = load_function("tests/test_pretest.py", "test_generate_running_golden_config", {
            "json": json, "logger": logging.getLogger(__name__), "pytest_assert": require,
            "wait_until": wait, "SafeThreadPoolExecutor": ImmediateExecutor,
            "config_reload": lambda dut, **kwargs: self.reloads.append(kwargs),
        })

    def test_capture_waits_for_defaults_and_persists_all_scopes(self):
        dut = FakeDut()
        self.capture([dut], {"topo": {"name": "t2_single_node_fw4"}})
        self.assertEqual(dut.saves, 2)
        self.assertEqual(len(self.reloads), 1)
        self.assertTrue(self.reloads[0]["wait_for_bgp"])
        expected_files = {"/etc/sonic/running_golden_config{}.json.tmp".format(i) for i in ("", "0", "1")}
        self.assertEqual(set(dut.files), expected_files)
        self.assertTrue(all(c["BGP_DEVICE_GLOBAL"]["STATE"]["value"] == 1 for c in dut.files.values()))
        self.assertGreaterEqual(dut.reads, 15)

    def test_unstable_config_does_not_replace_baselines(self):
        for dut in (FakeDut(unstable=True), FakeDut(change_on_save=True)):
            with self.assertRaises(AssertionError):
                self.capture([dut], {"topo": {"name": "t2_single_node_fw4"}})
            self.assertEqual(dut.files, {})

    def test_other_topologies_keep_existing_capture_path(self):
        dut = FakeDut()
        self.capture([dut], {"topo": {"name": "t0"}})
        self.assertEqual(self.reloads, [])
        self.assertEqual(dut.saves, 0)
        self.assertEqual(len(dut.commands), 3)
        self.assertTrue(all("> /etc/sonic/running_golden_config" in c for c in dut.commands))


if __name__ == "__main__":
    unittest.main()
