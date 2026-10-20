"""Unit tests for update_ip_decap_config in generate_golden_config_db.py."""

import importlib.util
import json
import os
import sys
import types

import pytest


def _load_golden_module():
    """Load generate_golden_config_db with DUT-only imports stubbed.

    The module imports sonic_py_common and ansible.module_utils at load time,
    which are only available on a SONiC DUT. Stub them so the module can be
    imported and its pure logic unit-tested on any host.
    """
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


def make_module(metadata=None, hwsku=None, platform=None, is_multi_asic=False,
                num_asics=1, minigraph_system_defaults=None, ns_system_defaults=None):
    """Build a GenerateGoldenConfigDBModule instance without running __init__.

    metadata populates DEVICE_METADATA/localhost returned by the mocked
    get_config_from_minigraph(); hwsku/platform mirror the Ansible-supplied
    attributes read by update_ip_decap_config. minigraph_system_defaults seeds
    the single-ASIC minigraph SYSTEM_DEFAULTS; ns_system_defaults maps each
    asicN namespace to its minigraph SYSTEM_DEFAULTS for the multi-ASIC path.
    """
    inst = golden_module.GenerateGoldenConfigDBModule.__new__(
        golden_module.GenerateGoldenConfigDBModule)
    inst.hwsku = hwsku
    inst.platform = platform
    minigraph_config = {"DEVICE_METADATA": {"localhost": metadata or {}}}
    if minigraph_system_defaults is not None:
        minigraph_config["SYSTEM_DEFAULTS"] = minigraph_system_defaults
    inst.get_config_from_minigraph = lambda: json.dumps(minigraph_config)

    # The multi-ASIC path fetches each namespace via self.module.run_command with a
    # `-n asicN` sonic-cfggen call; return the matching namespace SYSTEM_DEFAULTS.
    ns_defaults = ns_system_defaults or {}

    class FakeModule(object):
        def run_command(self, command, **kwargs):
            for ns, sd in ns_defaults.items():
                if "-n {}".format(ns) in command:
                    return (0, json.dumps({"SYSTEM_DEFAULTS": sd}), "")
            return (0, json.dumps({}), "")

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs.get("msg"))

    inst.module = FakeModule()

    golden_module.multi_asic.is_multi_asic = lambda: is_multi_asic
    golden_module.multi_asic.get_num_asics = lambda: num_asics
    return inst


def run(inst, config=None):
    """Run update_ip_decap_config and return the parsed result dict."""
    return json.loads(inst.update_ip_decap_config(json.dumps(config or {})))


@pytest.mark.parametrize("metadata, hwsku, platform, expected", [
    # DPU switch -> disabled
    ({"switch_type": "dpu"}, "Arista-7060X6-64PE-C256S2", "x86_64-arista_7060x6_64pe", "disabled"),
    # Lossy Arista hwskus -> disabled
    ({"type": "LeafRouter"}, "Arista-7060X6-64PE-B-C512S2", "x86_64-arista_7060x6_64pe_b", "disabled"),
    ({"type": "LeafRouter"}, "Arista-7060X6-64PE-B-C448O16", "x86_64-arista_7060x6_64pe_b", "disabled"),
    # Mellanox/NVIDIA non-storage backend -> disabled
    ({"type": "BackEndToRRouter"}, "Mellanox-SN4700", "x86_64-mlnx_msn4700-r0", "disabled"),
    ({"type": "BackEndLeafRouter"}, "Nvidia-SN5600", "x86_64-nvidia_sn5600-r0", "disabled"),
    ({"type": "BackEndSpineRouter"}, "Mellanox-SN4700", "x86_64-mlnx_msn4700-r0", "disabled"),
    # Mellanox backend WITH storage_device -> enabled
    ({"type": "BackEndToRRouter", "storage_device": "true"}, "Mellanox-SN4700",
     "x86_64-mlnx_msn4700-r0", "enabled"),
    # Mellanox backend but frontend type (not a backend role) -> enabled
    ({"type": "ToRRouter"}, "Mellanox-SN4700", "x86_64-mlnx_msn4700-r0", "enabled"),
    # Backend role but non-Mellanox/NVIDIA platform -> enabled
    ({"type": "BackEndToRRouter"}, "Arista-7060X6-64PE-C256S2", "x86_64-arista_7060x6_64pe", "enabled"),
    # Default frontend device -> enabled
    ({"type": "ToRRouter"}, "Arista-7060X6-64PE-C256S2", "x86_64-arista_7060x6_64pe", "enabled"),
])
def test_policy_branches(metadata, hwsku, platform, expected):
    inst = make_module(metadata=metadata, hwsku=hwsku, platform=platform)
    result = run(inst)
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == expected


def test_metadata_fallback_when_attributes_absent():
    # hwsku/platform come from minigraph metadata when Ansible attrs are empty.
    inst = make_module(
        metadata={"type": "LeafRouter", "hwsku": "Arista-7060X6-64PE-B-C512S2"},
        hwsku=None, platform=None)
    result = run(inst)
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_existing_ip_decap_is_replaced():
    inst = make_module(metadata={"switch_type": "dpu"})
    config = {"SYSTEM_DEFAULTS": {"ip_decap": {"status": "enabled"}}}
    result = run(inst, config)
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_unrelated_system_defaults_preserved():
    inst = make_module(metadata={"switch_type": "dpu"})
    config = {"SYSTEM_DEFAULTS": {"swss_zmq": {"status": "enabled"}}}
    result = run(inst, config)
    assert result["SYSTEM_DEFAULTS"]["swss_zmq"] == {"status": "enabled"}
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_other_tables_preserved():
    inst = make_module(metadata={"type": "ToRRouter"}, hwsku="Arista-7060X6-64PE-C256S2",
                       platform="x86_64-arista_7060x6_64pe")
    config = {"PORT": {"Ethernet0": {"admin_status": "up"}}}
    result = run(inst, config)
    assert result["PORT"] == {"Ethernet0": {"admin_status": "up"}}
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "enabled"


def test_minigraph_system_defaults_seeded_into_golden():
    # override_config replaces SYSTEM_DEFAULTS as a whole table, so minigraph
    # entries must be seeded into the golden table or they get dropped.
    inst = make_module(
        metadata={"type": "ToRRouter"}, hwsku="Arista-7260CX3-C64",
        platform="x86_64-arista_7260cx3_64",
        minigraph_system_defaults={
            "tunnel_qos_remap": {"status": "enabled"},
            "mux_tunnel_egress_acl": {"status": "enabled"},
        })
    # Golden config has no SYSTEM_DEFAULTS of its own (e.g. dualtor/default generators).
    result = run(inst, {"DEVICE_METADATA": {"localhost": {}}})
    assert result["SYSTEM_DEFAULTS"]["tunnel_qos_remap"] == {"status": "enabled"}
    assert result["SYSTEM_DEFAULTS"]["mux_tunnel_egress_acl"] == {"status": "enabled"}
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "enabled"


def test_golden_system_defaults_take_precedence_over_minigraph_seed():
    # Entries already in the golden object win over the minigraph seed.
    inst = make_module(
        metadata={"switch_type": "dpu"},
        minigraph_system_defaults={"swss_zmq": {"status": "disabled"}})
    config = {"SYSTEM_DEFAULTS": {"swss_zmq": {"status": "enabled"}}}
    result = run(inst, config)
    assert result["SYSTEM_DEFAULTS"]["swss_zmq"] == {"status": "enabled"}
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_single_asic_places_knob_at_top_level():
    inst = make_module(metadata={"switch_type": "dpu"}, is_multi_asic=False)
    result = run(inst)
    assert result["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"
    assert "asic0" not in result


def test_multi_asic_places_knob_per_namespace():
    inst = make_module(metadata={"switch_type": "dpu"}, is_multi_asic=True, num_asics=3)
    result = run(inst)
    for asic in range(3):
        ns = "asic{}".format(asic)
        assert result[ns]["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"
    # Top-level SYSTEM_DEFAULTS is not used on multi-ASIC.
    assert "SYSTEM_DEFAULTS" not in result


def test_multi_asic_preserves_existing_namespace_entries():
    inst = make_module(metadata={"switch_type": "dpu"}, is_multi_asic=True, num_asics=2)
    config = {
        "asic0": {"SYSTEM_DEFAULTS": {"swss_zmq": {"status": "enabled"}}},
        "asic1": {},
    }
    result = run(inst, config)
    assert result["asic0"]["SYSTEM_DEFAULTS"]["swss_zmq"] == {"status": "enabled"}
    assert result["asic0"]["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"
    assert result["asic1"]["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_multi_asic_seeds_minigraph_system_defaults_per_namespace():
    inst = make_module(
        metadata={"switch_type": "dpu"}, is_multi_asic=True, num_asics=2,
        ns_system_defaults={
            "asic0": {"tunnel_qos_remap": {"status": "enabled"}},
            "asic1": {"tunnel_qos_remap": {"status": "enabled"}},
        })
    result = run(inst, {})
    for ns in ("asic0", "asic1"):
        assert result[ns]["SYSTEM_DEFAULTS"]["tunnel_qos_remap"] == {"status": "enabled"}
        assert result[ns]["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "disabled"


def test_multi_asic_supervisor_without_port_config_does_not_fail():
    # Chassis supervisors have fabric ASICs with no per-ASIC port_config.ini; the
    # namespace fetch uses no -p, so it succeeds and seeds an empty SYSTEM_DEFAULTS.
    inst = make_module(metadata={"type": "SpineRouter"}, hwsku="Arista-7808R3A-FM",
                       platform="x86_64-arista_7800_sup", is_multi_asic=True, num_asics=3)
    result = run(inst, {})
    for asic in range(3):
        ns = "asic{}".format(asic)
        assert result[ns]["SYSTEM_DEFAULTS"]["ip_decap"]["status"] == "enabled"
