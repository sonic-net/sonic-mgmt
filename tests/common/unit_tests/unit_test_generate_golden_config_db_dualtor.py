"""Unit tests for generate_dualtor_golden_config_db in generate_golden_config_db.py."""

import importlib.util
import json
import os
import sys
import types

import pytest


def _load_golden_module():
    """Load generate_golden_config_db with DUT-only imports stubbed."""
    jinja2 = types.ModuleType("jinja2")
    jinja2.Template = object

    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object
    smartswitch_utils = types.ModuleType("ansible.module_utils.smartswitch_utils")
    smartswitch_utils.smartswitch_hwsku_config = {}
    smartswitch_utils.smartswitch_vlan_config = {}

    sonic_py_common = types.ModuleType("sonic_py_common")
    device_info = types.ModuleType("sonic_py_common.device_info")
    multi_asic = types.ModuleType("sonic_py_common.multi_asic")
    multi_asic.is_multi_asic = lambda: False
    multi_asic.get_num_asics = lambda: 1
    sonic_py_common.device_info = device_info
    sonic_py_common.multi_asic = multi_asic

    saved_modules = {}
    fake_modules = {
        "jinja2": jinja2,
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.smartswitch_utils": smartswitch_utils,
        "sonic_py_common": sonic_py_common,
        "sonic_py_common.device_info": device_info,
        "sonic_py_common.multi_asic": multi_asic,
    }
    for name, module in fake_modules.items():
        saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module

    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        module_path = os.path.join(repo_root, "ansible", "library", "generate_golden_config_db.py")
        spec = importlib.util.spec_from_file_location("generate_golden_config_db", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, module in saved_modules.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


golden_module = _load_golden_module()

MUX_YANG_CMD = "sudo cat /usr/local/yang-models/sonic-mux-cable.yang"

# MUX_CABLE YANG leaves by image: 202411 has neither field, 202505/202511 add
# prober_type, and images built after neighbor_mode support (e.g. 202605) have both.
YANG_WITHOUT_FIELDS = """
            list MUX_CABLE_LIST {
                key "ifname";
                leaf ifname { type string; }
                leaf state { type string; }
                leaf server_ipv4 { type inet:ipv4-prefix; }
            }
"""
YANG_WITH_PROBER_TYPE = YANG_WITHOUT_FIELDS.replace(
    "leaf state", "leaf prober_type { type string; }\n                leaf state")
YANG_WITH_BOTH = YANG_WITH_PROBER_TYPE.replace(
    "leaf state", "leaf neighbor_mode { type string; }\n                leaf state")

MINIGRAPH_CONFIG = {
    "DEVICE_METADATA": {"localhost": {"hostname": "dut", "subtype": "DualToR"}},
    "MUX_CABLE": {
        "Ethernet0": {"state": "auto", "server_ipv4": "192.168.0.2/32"},
        "Ethernet4": {"state": "auto", "server_ipv4": "192.168.0.3/32"},
    },
    "PORT": {"Ethernet0": {"lanes": "0,1"}, "Ethernet4": {"lanes": "4,5"}},
}


class FakeModule(object):
    def __init__(self, yang_rc=0, yang_content=""):
        self.yang_rc = yang_rc
        self.yang_content = yang_content
        self.commands = []
        self.warnings = []

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        if command == MUX_YANG_CMD:
            return (self.yang_rc, self.yang_content, "")
        if command.startswith("sonic-cfggen"):
            return (0, json.dumps(MINIGRAPH_CONFIG), "")
        raise AssertionError("Unexpected command: {}".format(command))

    def warn(self, msg):
        self.warnings.append(msg)

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs.get("msg"))


def make_module(prober_type=None, neighbor_mode=None, yang_rc=0, yang_content=""):
    inst = golden_module.GenerateGoldenConfigDBModule.__new__(
        golden_module.GenerateGoldenConfigDBModule)
    inst.prober_type = prober_type
    inst.neighbor_mode = neighbor_mode
    inst.module = FakeModule(yang_rc, yang_content)
    return inst


@pytest.mark.parametrize("yang_content, expected_fields", [
    (YANG_WITH_BOTH, {"prober_type": "hardware", "neighbor_mode": "prefix-route"}),
    (YANG_WITH_PROBER_TYPE, {"prober_type": "hardware"}),
    (YANG_WITHOUT_FIELDS, {}),
])
def test_mux_cable_fields_follow_installed_yang(yang_content, expected_fields):
    inst = make_module(prober_type="hardware", neighbor_mode="prefix-route", yang_content=yang_content)
    result = json.loads(inst.generate_dualtor_golden_config_db())

    for intf, minigraph_entry in MINIGRAPH_CONFIG["MUX_CABLE"].items():
        expected_entry = dict(minigraph_entry, **expected_fields)
        assert result["MUX_CABLE"][intf] == expected_entry
    skipped = {"prober_type", "neighbor_mode"} - set(expected_fields)
    assert len(inst.module.warnings) == len(skipped)
    for field in skipped:
        assert any(field in msg for msg in inst.module.warnings)


def test_mux_cable_fields_skipped_when_yang_unreadable():
    inst = make_module(neighbor_mode="prefix-route", yang_rc=1)
    result = json.loads(inst.generate_dualtor_golden_config_db())

    assert result["MUX_CABLE"] == MINIGRAPH_CONFIG["MUX_CABLE"]
    assert len(inst.module.warnings) == 1


def test_mux_cable_unchanged_when_fields_not_requested():
    inst = make_module(neighbor_mode="")
    result = json.loads(inst.generate_dualtor_golden_config_db())

    assert result["MUX_CABLE"] == MINIGRAPH_CONFIG["MUX_CABLE"]
    assert result["PORT"] == MINIGRAPH_CONFIG["PORT"]
    assert MUX_YANG_CMD not in inst.module.commands
    assert inst.module.warnings == []
