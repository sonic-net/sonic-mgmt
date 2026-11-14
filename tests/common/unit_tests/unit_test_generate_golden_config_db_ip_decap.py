"""Unit tests for golden CONFIG_DB generation without DUT-only dependencies."""

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


@pytest.fixture
def o32v192_generator(tmp_path, monkeypatch):
    """Model native ports, stale admin states, and a partially cabled device."""
    inst = make_module(hwsku="Arista-7060X6-64PE-B-O32V192")
    inst.topo_name = "dualtor-aa-o32v192"
    inst.prober_type = None
    inst.neighbor_mode = "prefix-route"
    ports = {
        "Ethernet{}".format(i): {"admin_status": "up"}
        for i in range(0, 512, 2) if i % 32 not in (2, 6)
    }
    inst.device_conn = {name: {} for name in ports if int(name[8:]) < 448}
    original = {
        "DEVICE_METADATA": {"localhost": {"hwsku": inst.hwsku}},
        "PORT": ports,
        "MUX_CABLE": {"Ethernet8": {"state": "auto", "cable_type": "active-active"}},
    }
    inst.module.run_command = lambda command: (0, json.dumps(original), "")
    interfaces = {
        "Ethernet{}".format(i): {"default_brkout_mode": "2x400G" if i % 32 == 0 else "4x200G"}
        for i in range(0, 512, 8)
    }
    (tmp_path / "hwsku.json").write_text(json.dumps({"interfaces": interfaces}))
    monkeypatch.setattr(golden_module.device_info, "get_path_to_port_config_file",
                        lambda: str(tmp_path.parent / "platform.json"), raising=False)
    monkeypatch.setattr(golden_module.device_info, "get_path_to_hwsku_dir",
                        lambda: str(tmp_path), raising=False)
    config_main = types.ModuleType("config.main")

    def get_child_ports(parent, mode, platform_path):
        assert mode == interfaces[parent]["default_brkout_mode"]
        assert platform_path == str(tmp_path.parent / "platform.json")
        base = int(parent[8:])
        step = 4 if mode == "2x400G" else 2
        return {
            "Ethernet{}".format(base + offset): {"subport": str(index)}
            for index, offset in enumerate(range(0, 8, step), 1)
        }

    config_main.get_child_ports = get_child_ports
    monkeypatch.setitem(sys.modules, "config.main", config_main)
    return inst, interfaces


def test_o32v192_persists_cabling_breakout_and_mux_settings(o32v192_generator):
    """A redeploy must override stale port states and retain native breakout."""
    inst, interfaces = o32v192_generator
    result = json.loads(inst.generate_dualtor_golden_config_db())
    assert {p for p, fields in result["PORT"].items() if fields["admin_status"] == "up"} == set(inst.device_conn)
    assert sum(fields["admin_status"] == "down" for fields in result["PORT"].values()) == 28
    assert result["BREAKOUT_CFG"] == {
        p: {"brkout_mode": fields["default_brkout_mode"]} for p, fields in interfaces.items()
    }
    assert result["MUX_LINKMGR"] == {
        "LINK_PROBER": {"interval_v4": "3000"},
        "TIMED_OSCILLATION": {"oscillation_enabled": "false"},
    }
    assert result["MUX_CABLE"]["Ethernet8"]["neighbor_mode"] == "prefix-route"
    assert [result["PORT"][p]["subport"] for p in ("Ethernet0", "Ethernet4")] == ["1", "2"]
    assert [result["PORT"]["Ethernet{}".format(i)]["subport"] for i in (8, 10, 12, 14)] == [
        "1", "2", "3", "4"
    ]
    assert all("subport" in fields for fields in result["PORT"].values())


def test_o32v192_rejects_mismatched_native_children(o32v192_generator, monkeypatch):
    """Do not publish partial subport metadata when native breakout children differ."""
    inst, _ = o32v192_generator
    monkeypatch.setattr(sys.modules["config.main"], "get_child_ports", lambda *args: {})
    with pytest.raises(AssertionError, match="breakout children"):
        inst.generate_dualtor_golden_config_db()


@pytest.mark.parametrize("invalid", ["hwsku", "empty_graph", "unknown_port", "missing_hwsku_file"])
def test_o32v192_rejects_incomplete_deployment_inputs(o32v192_generator, tmp_path, invalid):
    """Do not silently generate an incomplete or non-native O32V192 config."""
    inst, _ = o32v192_generator
    if invalid == "hwsku":
        inst.hwsku = "Arista-7060X6-64PE-B-C512S2"
    elif invalid == "empty_graph":
        inst.device_conn = {}
    elif invalid == "unknown_port":
        inst.device_conn["Ethernet999"] = {}
    else:
        (tmp_path / "hwsku.json").unlink()
    with pytest.raises(AssertionError):
        inst.generate_dualtor_golden_config_db()


def test_other_dualtor_topologies_keep_existing_behavior(o32v192_generator):
    """The native breakout/admin-state override must not affect other topologies."""
    inst, _ = o32v192_generator
    inst.topo_name = "dualtor-aa"
    result = json.loads(inst.generate_dualtor_golden_config_db())
    assert all(fields["admin_status"] == "up" for fields in result["PORT"].values())
    assert "BREAKOUT_CFG" not in result
    assert "MUX_LINKMGR" not in result
    assert all("subport" not in fields for fields in result["PORT"].values())


def test_o32v192_controller_aliases(monkeypatch):
    """Resolve all native aliases and the topology's uplink indices without SONiC."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    path = os.path.join(repo_root, "ansible", "module_utils", "port_utils.py")
    spec = importlib.util.spec_from_file_location("port_utils", path)
    port_utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(port_utils)
    monkeypatch.setitem(sys.modules, "sonic_py_common", None)
    aliases, _, _ = port_utils.get_port_alias_to_name_map("Arista-7060X6-64PE-B-O32V192")
    assert len(aliases) == len(set(aliases.values())) == 224
    ordered = sorted(aliases.values(), key=lambda port: int(port[8:]))
    assert [ordered[index] for index in (0, 14, 28, 42)] == [
        "Ethernet0", "Ethernet32", "Ethernet64", "Ethernet96",
    ]
    assert [aliases["etp{}{}".format(cage, suffix)] for cage in (2, 6) for suffix in "abcd"] == [
        "Ethernet8", "Ethernet10", "Ethernet12", "Ethernet14",
        "Ethernet40", "Ethernet42", "Ethernet44", "Ethernet46",
    ]
    assert not any(alias.startswith(("etp65", "etp66")) for alias in aliases)


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
