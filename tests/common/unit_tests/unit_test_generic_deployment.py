"""Offline rendering/deployment regressions; no lab connections or reloads."""

from argparse import Namespace
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
import pathlib
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml


SCRIPTS = Path(__file__).resolve().parents[3] / "ansible/scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    import generic_config as renderer
    import generic_device_action as device
    import generic_topology_cli as controller
    from plan_generic_topology import allocate_forwarding
finally:
    sys.path.pop(0)


@pytest.fixture
def layout():
    """One owned cage and one protected port with management/global state."""
    base = {
        "PORT": {
            "Ethernet0": {"lanes": "1,2", "alias": "old", "speed": "200000", "mtu": "9100"},
            "Ethernet8": {"lanes": "3,4", "alias": "protected", "speed": "200000"},
        },
        "DEVICE_METADATA": {"localhost": {"hostname": "dut"}},
        "MGMT_INTERFACE": {"eth0|192.0.2.1/24": {"gwaddr": "192.0.2.254"}},
        "PORTCHANNEL": {"PortChannel1": {}},
        "PORTCHANNEL_MEMBER": {"PortChannel1|Ethernet0": {}},
        "PORTCHANNEL_INTERFACE": {"PortChannel1": {}, "PortChannel1|10.0.0.0/31": {}},
        "BGP_NEIGHBOR": {
            "10.0.0.1": {"local_addr": "10.0.0.0"},
            "192.0.2.2": {"local_addr": "192.0.2.1"},
        },
        "ACL_TABLE": {"acl": {"ports": ["Ethernet0", "PortChannel1", "Ethernet8"]}},
        "QUEUE": {"Ethernet0,Ethernet8|0-7": {"scheduler": "protected"}},
    }
    children = [
        {"port": "Ethernet0", "lanes": [1], "alias": "a"},
        {"port": "Ethernet1", "lanes": [2], "alias": "b"},
    ]
    choice = {"mode": "2x100G", "speed": 100000, "children": children}
    platform = {"interfaces": {"Ethernet0": {"lanes": "1,2"}}}

    def canonical(cage, selection, properties):
        return {child["port"]: {"lanes": str(child["lanes"][0]), "alias": child["alias"], "speed": "100000"}
                for child in selection["children"]}

    return base, platform, {"Ethernet0": choice}, canonical


def test_owned_retirement_preserves_protected_state(layout):
    """Remove owned LAG/BGP/bindings without changing protected or management state."""
    layout[0]["PORT"]["Ethernet8"]["description"] = "ARISTA01PT0:Ethernet0"
    original = deepcopy(layout[0])
    config, owned, selected = renderer.build_ports(*layout)
    assert layout[0] == original
    assert owned == {"Ethernet0"}
    assert selected == {"Ethernet0", "Ethernet1"}
    assert config["PORT"]["Ethernet8"] == original["PORT"]["Ethernet8"]
    assert config["MGMT_INTERFACE"] == original["MGMT_INTERFACE"]
    assert config["PORTCHANNEL"] == {}
    assert config["BGP_NEIGHBOR"] == {"192.0.2.2": {"local_addr": "192.0.2.1"}}
    assert config["QUEUE"] == {"Ethernet8|0-7": {"scheduler": "protected"}}
    assert config["ACL_TABLE"]["acl"]["ports"] == ["Ethernet8"]
    assert config["PORT"]["Ethernet1"]["mtu"] == "9100"


def test_pfc_watchdog_global_and_protected_port_settings_survive(layout):
    """GLOBAL is watchdog policy, not a port; preserve it while retiring only owned port entries."""
    settings = {"POLL_INTERVAL": "200", "BIG_RED_SWITCH": "disable"}
    protected = {"detection_time": "400", "restoration_time": "800", "action": "drop"}
    layout[0]["PFC_WD"] = {"GLOBAL": settings, "Ethernet0": dict(protected), "Ethernet8": protected}
    original = deepcopy(layout[0])
    config, _, _ = renderer.build_ports(*layout)
    assert config["PFC_WD"] == {"GLOBAL": settings, "Ethernet8": protected}
    renderer.validate_references(config)
    assert layout[0] == original


@pytest.mark.parametrize("key", ["Ethernet999", "GLOBAL|3"])
def test_pfc_watchdog_global_exception_does_not_accept_invalid_port_keys(layout, key):
    """Only the exact global key is exempt; missing ports and malformed global keys still fail."""
    layout[0]["PFC_WD"] = {"GLOBAL": {"POLL_INTERVAL": "200"}, key: {"action": "drop"}}
    with pytest.raises(ValueError, match="PFC_WD references absent port"):
        renderer.validate_references(layout[0])


@pytest.mark.parametrize("existing", [
    None,
    {},
    {"Ethernet0": {"brkout_mode": "1x200G"}},
    {"Ethernet8": {"brkout_mode": "1x200G"}},
    {"Ethernet0": {"brkout_mode": "1x200G"}, "Ethernet8": {"brkout_mode": "1x200G"}},
])
def test_breakout_is_represented_only_by_port_entries(layout, existing):
    """Omit all inherited breakout metadata while retaining realized and protected PORT entries."""
    base = layout[0]
    if existing is not None:
        base["BREAKOUT_CFG"] = existing
    original = deepcopy(base)
    config, _, _ = renderer.build_ports(*layout)
    assert "BREAKOUT_CFG" not in config
    assert config["PORT"]["Ethernet8"] == original["PORT"]["Ethernet8"]
    assert {name: (row["lanes"], row["speed"], row["alias"]) for name, row in config["PORT"].items()
            if name != "Ethernet8"} == {
                "Ethernet0": ("1", "100000", "a"), "Ethernet1": ("2", "100000", "b"),
    }
    assert base == original


@pytest.mark.parametrize("exclude_managed_acls", [False, True])
def test_shared_lag_is_rejected(layout, exclude_managed_acls):
    """A LAG cannot be retired if even one member is protected."""
    layout[0]["PORTCHANNEL_MEMBER"]["PortChannel1|Ethernet8"] = {}
    with pytest.raises(ValueError, match="shared with protected"):
        renderer.build_ports(*layout, exclude_managed_acls)


@pytest.mark.parametrize("reference", ["Ethernet0", "PortChannel1"])
def test_unknown_owned_references_are_rejected_even_for_reused_names(layout, reference):
    """Unsupported bindings must not survive just because a new child reuses a name."""
    layout[0]["UNSUPPORTED_FEATURE"] = {reference: {}}
    with pytest.raises(ValueError, match="retired port") as error:
        renderer.build_ports(*layout)
    assert "UNSUPPORTED_FEATURE" in str(error.value)
    assert "key #0" in str(error.value)
    assert "references " + reference in str(error.value)


@pytest.mark.parametrize("row,location", [
    ({"src_port": "private-prefix Ethernet0 private-suffix"}, '["src_port"]'),
    ({"nested": {"ports": ["unrelated", "Ethernet0 private-suffix"]}}, '["nested"]["ports"][1]'),
    ({"private-prefix Ethernet0 private-suffix": {}}, "key #0"),
])
def test_retired_reference_diagnostics_locate_bindings_without_dumping_values(row, location):
    """Identify key/value/nested bindings without exposing their surrounding configuration contents."""
    config = {"PORT": {"Ethernet8": {}}, "UNSUPPORTED_FEATURE": {"entry": row}}
    original = deepcopy(config)
    with pytest.raises(ValueError, match="retired port") as error:
        renderer.validate_references(config, {"Ethernet0"})
    message = str(error.value)
    assert 'CONFIG_DB["UNSUPPORTED_FEATURE"]["entry"]' in message
    assert location in message
    assert "references Ethernet0" in message
    assert "private-prefix" not in message and "private-suffix" not in message
    assert config == original


def test_retired_reference_diagnostics_are_bounded():
    """A large stale configuration must still produce a bounded, fail-closed error."""
    config = {"PORT": {}, "UNSUPPORTED_FEATURE": {
        str(index): {"ports": "Ethernet0"} for index in range(20)}}
    with pytest.raises(ValueError, match="retired port") as error:
        renderer.validate_references(config, {"Ethernet0"})
    assert str(error.value).count("(value references Ethernet0)") == 8


def test_canonical_parser_disagreement_is_rejected(layout):
    """Installed naming, lanes, aliases, and speeds must agree with the plan."""
    layout[2]["Ethernet0"]["children"][0]["alias"] = "wrong"
    base, platform, choices, _ = layout
    with pytest.raises(ValueError, match="lanes/alias/speed"):
        renderer.build_ports(base, platform, choices, lambda *args: {
            "Ethernet0": {"lanes": "1", "alias": "a", "speed": "100000"},
            "Ethernet1": {"lanes": "2", "alias": "b", "speed": "100000"},
        })


@pytest.mark.parametrize("wrong_speed", [False, True])
def test_mixed_children_render_at_their_own_speeds(layout, wrong_speed):
    """Verify each canonical child against its own speed rather than a cage-wide scalar."""
    base, platform, layouts, _ = layout
    choice = layouts["Ethernet0"]
    choice.update(mode="1x100G(1)+1x200G(1)", speed=[100000, 200000])
    for child, speed in zip(choice["children"], choice["speed"]):
        child["speed"] = speed

    def canonical(*args):
        return {
            "Ethernet0": {"lanes": "1", "alias": "a", "speed": "100000"},
            "Ethernet1": {"lanes": "2", "alias": "b", "speed": "100000" if wrong_speed else "200000"},
        }
    if wrong_speed:
        with pytest.raises(ValueError, match="lanes/alias/speed"):
            renderer.build_ports(base, platform, layouts, canonical)
    else:
        config, _, _ = renderer.build_ports(base, platform, layouts, canonical)
        assert config["PORT"]["Ethernet0"]["speed"] == "100000"
        assert config["PORT"]["Ethernet1"]["speed"] == "200000"
        assert config["PORT"]["Ethernet8"] == base["PORT"]["Ethernet8"]
        assert "BREAKOUT_CFG" not in config


@pytest.mark.parametrize("mode,speed,canonical", [
    ("2x200G[100G]", 100000, "2x100G[200G]"),
    ("4x100G(4)+1x400G(4)", [100000, 400000], "4x100G(4)+1x400G(4)"),
    ("1x400G(4)+4x100G(4)", [400000, 100000], "1x400G(4)+4x100G(4)"),
    ("4x100G[50G](4)+1x400G[200G](4)", [50000, 200000], "4x50G[100G](4)+1x200G[400G](4)"),
])
def test_installed_parser_receives_ordered_operating_combination(monkeypatch, mode, speed, canonical):
    """Select alternate speeds without flattening or reordering mixed lane groups."""
    properties = {"breakout_modes": {mode: ["platform aliases"]}}
    expected = {"native": "parser result"}

    def breakout(cage, selected, actual_properties):
        assert cage == "Ethernet16"
        assert selected == canonical
        assert actual_properties is properties
        return SimpleNamespace(get_config=lambda: expected)

    monkeypatch.setitem(sys.modules, "portconfig", SimpleNamespace(BreakoutCfg=breakout))
    assert renderer.canonical_ports("Ethernet16", {"mode": mode, "speed": speed}, properties) is expected


@pytest.fixture
def neighbor_scenario():
    """Frozen reciprocal connections with mixed test roles on one physical peer."""
    layouts = {"dut": {}, "peer": {}}
    connections = []
    for index, direction in enumerate(("uplink", "downlink")):
        link = {"role": direction, "buffer_case": {"speed": "100000", "cable": "5m"}}
        for side, offset in (("dut", 0), ("peer", 4)):
            parent = "Ethernet{}".format(offset)
            child = {"port": "Ethernet{}".format(offset + index), "speed": 100000,
                     "lanes": [offset + index + 1], "alias": side + str(index),
                     "cage": parent, "atoms": ["Ethernet{}".format(index)]}
            link[side] = deepcopy(child)
            layouts[side].setdefault(parent, {"speed": 100000, "mode": "2x100G", "children": []})
            layouts[side][parent]["children"].append(child)
        connections.append(link)
    return {"hostname": "dut", "peer_hostname": "leaf", "connections": connections}, layouts


@pytest.mark.parametrize("role", ["dut", "peer"])
def test_child_neighbors_replace_parent_and_preserve_identity(neighbor_scenario, role):
    """Rebuild both ends from final wiring, preserving protected neighbors and all identity metadata."""
    facts, layouts = neighbor_scenario
    original_scenario = deepcopy(neighbor_scenario)
    parent, choice = next(iter(layouts[role].items()))
    lanes = ",".join(str(child["lanes"][0]) for child in choice["children"])
    base = {
        "PORT": {parent: {"lanes": lanes, "speed": "200000"},
                 "Ethernet8": {"lanes": "90", "speed": "100000"}},
        "DEVICE_METADATA": {"localhost": {"hostname": "native-" + role, "type": "ToRRouter", "hwsku": "base"}},
        "DEVICE_NEIGHBOR": {
            parent: {"name": "old-peer", "port": "Ethernet99"},
            "Ethernet8": {"name": "protected", "port": "Ethernet0"},
        },
        "DEVICE_NEIGHBOR_METADATA": {"old-peer": {"type": "LeafRouter"}, "protected": {"type": "SpineRouter"}},
    }
    original = deepcopy(base)
    config, _, _ = renderer.build_ports(
        base, {"interfaces": {parent: {"lanes": lanes}}}, layouts[role],
        lambda cage, selection, properties: {
            child["port"]: {"lanes": str(child["lanes"][0]), "alias": child["alias"], "speed": "100000"}
            for child in selection["children"]})
    config.setdefault("DEVICE_NEIGHBOR", {}).update(renderer.reconcile_neighbors(facts, layouts)[role])
    remote = "peer" if role == "dut" else "dut"
    expected = {
        link[role]["port"]: {
            "name": facts["peer_hostname" if role == "dut" else "hostname"],
            "port": link[remote]["port"],
        }
        for link in facts["connections"]
    }
    assert config["DEVICE_NEIGHBOR"] == dict(expected, Ethernet8=original["DEVICE_NEIGHBOR"]["Ethernet8"])
    assert config["DEVICE_METADATA"] == original["DEVICE_METADATA"]
    assert config["DEVICE_NEIGHBOR_METADATA"] == original["DEVICE_NEIGHBOR_METADATA"]
    assert base == original
    assert (facts, layouts) == original_scenario


@pytest.mark.parametrize("failure", [
    "duplicate_dut", "duplicate_peer", "missing_connection", "unknown_child", "changed_child",
    "wrong_speed", "wrong_case_speed", "crossed_wiring", "missing_role", "same_host",
])
def test_reconciliation_rejects_inconsistent_frozen_connections(neighbor_scenario, failure):
    """Never infer replacement wiring, roles, or layout when the finalized inputs disagree."""
    facts, layouts = deepcopy(neighbor_scenario)
    links = facts["connections"]
    if failure == "duplicate_dut":
        links.append(deepcopy(links[0]))
    elif failure == "duplicate_peer":
        links[1]["peer"] = deepcopy(links[0]["peer"])
    elif failure == "missing_connection":
        links.pop()
    elif failure == "unknown_child":
        links[0]["dut"]["port"] = "Ethernet99"
    elif failure == "changed_child":
        links[0]["dut"]["lanes"] = [99]
    elif failure == "wrong_speed":
        links[0]["peer"]["speed"] = layouts["peer"]["Ethernet4"]["speed"] = 200000
        for child in layouts["peer"]["Ethernet4"]["children"]:
            child["speed"] = 200000
        links[1]["peer"]["speed"] = 200000
    elif failure == "wrong_case_speed":
        links[0]["buffer_case"]["speed"] = "200000"
    elif failure == "crossed_wiring":
        links[0]["peer"], links[1]["peer"] = links[1]["peer"], links[0]["peer"]
    elif failure == "missing_role":
        del links[0]["role"]
    else:
        facts["peer_hostname"] = facts["hostname"]
    with pytest.raises(ValueError):
        renderer.reconcile_neighbors(facts, layouts)


@pytest.mark.parametrize("failure", ["identity", "peer_mapping", "layout"])
def test_render_rejects_inconsistent_connections_before_device_access(
        rendered, neighbor_scenario, tmp_path, monkeypatch, failure):
    """Final connection reconciliation must run locally before any rendering playbook."""
    artifacts, testbed = rendered
    facts, layouts = deepcopy(neighbor_scenario)
    artifacts["resolved_facts.json"] = facts
    artifacts["manifest.json"].update(peer_hostname="leaf", selected_layouts=layouts)
    artifacts["topology.yml"] = {"generic_topology": {
        "physical_links": {"uplinks": ["Ethernet0"], "downlinks": ["Ethernet1"]},
    }}
    if failure == "identity":
        facts["hostname"] = "other-dut"
    elif failure == "peer_mapping":
        facts["connections"][1]["peer"] = deepcopy(facts["connections"][0]["peer"])
    else:
        del layouts["dut"]["Ethernet0"]["children"][1]
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected device access"))
    destination = tmp_path / "rendered"
    with pytest.raises(ValueError, match="identities|Duplicate resolved peer|frozen breakout"):
        controller.render(Namespace(output_dir=str(destination)), artifacts, testbed, "dut")
    assert not destination.exists()


@pytest.mark.parametrize("minimum,message", [
    (None, "at least 4 physical uplinks"), (3, "at least 3 physical uplinks"), (0, "must be a positive integer"),
])
def test_render_rejects_insufficient_matching_uplinks_before_device_access(
        rendered, neighbor_scenario, tmp_path, monkeypatch, minimum, message):
    """Check the frozen planning count, or legacy default, before accessing devices."""
    artifacts, testbed = rendered
    facts, layouts = deepcopy(neighbor_scenario)
    artifacts["resolved_facts.json"] = facts
    artifacts["manifest.json"].update(peer_hostname="leaf", selected_layouts=layouts)
    if minimum is not None:
        artifacts["manifest.json"]["policy"] = {"min_same_breakout_uplinks": minimum}
    artifacts["topology.yml"] = {"generic_topology": {
        "physical_links": {"uplinks": ["Ethernet0"]},
    }}
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected device access"))
    destination = tmp_path / "rendered"
    with pytest.raises(ValueError, match=message):
        controller.render(Namespace(output_dir=str(destination)), artifacts, testbed, "dut")
    assert not destination.exists()


def test_remote_interface_names_are_not_retired_local_references():
    """A valid remote port may share a name with a retired local child."""
    config = {"PORT": {"Ethernet0": {}},
              "DEVICE_NEIGHBOR": {"Ethernet0": {"name": "leaf", "port": "Ethernet1"}}}
    renderer.validate_references(config, {"Ethernet1"})
    config["DEVICE_NEIGHBOR"]["Ethernet1"] = {"name": "leaf", "port": "Ethernet0"}
    with pytest.raises(ValueError, match="retired port"):
        renderer.validate_references(config, {"Ethernet1"})


@pytest.mark.parametrize("reference_kind", ["description", "field", "key"])
def test_port_descriptions_are_not_bindings_but_other_port_references_still_reject(reference_kind):
    """Preserve protected free-text descriptions without exempting PORT keys or functional fields."""
    config = {"PORT": {
        "Ethernet512": {"description": "ARISTA01PT0:Ethernet1"},
        "Ethernet520": {"description": "ARISTA02PT0:Ethernet1"},
    }}
    if reference_kind == "field":
        config["PORT"]["Ethernet512"]["parent_port"] = "Ethernet1"
    elif reference_kind == "key":
        config["PORT"]["Ethernet1"] = {}
    original = deepcopy(config)
    if reference_kind == "description":
        renderer.validate_references(config, {"Ethernet1"})
    else:
        with pytest.raises(ValueError, match="retired port"):
            renderer.validate_references(config, {"Ethernet1"})
    assert config == original


@pytest.fixture
def qos():
    """Traditional daemon-compatible PFC-to-PG maps with non-identity PFC-to-queue maps."""
    config = {"PORT": {"Ethernet0": {}, "Ethernet8": {}}}
    generated = {
        "BUFFER_POOL": {"ingress_lossless_pool": {"size": "1000", "mode": "dynamic"},
                        "egress_pool": {"size": "1000"}},
        "BUFFER_PROFILE": {
            "lossy": {"pool": "egress_pool", "size": "0"},
            "egress_lossless_profile": {"pool": "egress_pool", "size": "10"},
        },
        "PORT_QOS_MAP": {"Ethernet0": {
            "tc_to_pg_map": "policy", "tc_to_queue_map": "policy", "pfc_enable": "3,4",
            "pfc_to_pg_map": "policy", "pfc_to_queue_map": "policy",
        }},
        "TC_TO_PRIORITY_GROUP_MAP": {"policy": {str(tc): "0" for tc in range(8)}},
        "TC_TO_QUEUE_MAP": {"policy": {str(tc): str(tc) for tc in range(8)}},
        "PFC_PRIORITY_TO_PRIORITY_GROUP_MAP": {"policy": {"3": "3", "4": "4"}},
        "MAP_PFC_PRIORITY_TO_QUEUE": {"policy": {"3": "2", "4": "7"}},
        "BUFFER_PG": {"Ethernet0|0-7": {"profile": "lossy"}},
        "BUFFER_QUEUE": {"Ethernet0|0-7": {"profile": "lossy"}},
    }
    facts = {"connections": [{"dut": {"port": "Ethernet0", "speed": 100000},
                              "buffer_case": {"cable": "5m"}}]}
    lookup = [{"speed": "100000", "cable": "5m", "size": "100", "xon": "020", "xoff": "30",
               "threshold": "-3", "xon_offset": "7"}]
    return config, generated, facts, "dut", lookup, {}, {"Ethernet0"}, {"Ethernet0"}


@pytest.mark.parametrize("role", ["dut", "peer"])
@pytest.mark.parametrize("has_platform_lookup", [False, True])
@pytest.mark.parametrize("template_has_pfc", [False, True, "lossy"])
@pytest.mark.parametrize("exclude_managed_acls", [False, True])
def test_render_lookup_priority_and_missing_file_fallback(
        qos, tmp_path, monkeypatch, role, has_platform_lookup, template_has_pfc, exclude_managed_acls):
    """Select/hash lookup assets and use template PFC policy with missing-field running fallback."""
    platform_dir = tmp_path / "device/test-platform"
    sku_dir = platform_dir / "test-sku"
    sku_dir.mkdir(parents=True)
    (platform_dir / "platform.json").write_text("{}")
    (sku_dir / "qos.json.j2").write_text("synthetic template")
    lookup_text = "# speed cable size xon xoff threshold\n100000 5m 100 20 30 -3\n"
    monkeypatch.setattr(renderer, "read_buffer_daemon", lambda: {
        "path": "/daemon/pg_profile_lookup.ini", "sha256": hashlib.sha256(lookup_text.encode()).hexdigest(),
        "content": lookup_text,
    })
    lookup_path = platform_dir / "pg_profile_lookup.ini"
    if has_platform_lookup:
        lookup_path.write_text(lookup_text)
    sku_lookup = sku_dir / "pg_profile_lookup.ini"
    sku_lookup.write_text(lookup_text.replace("100 20 30", "900 80 70") if has_platform_lookup else lookup_text)
    version_path = tmp_path / "sonic_version.yml"
    version_path.write_text("asic_type: test-asic\n")
    paths = {"/usr/share/sonic/device": tmp_path / "device",
             "/etc/sonic/sonic_version.yml": version_path,
             "/usr/share/sonic/templates": tmp_path / "templates"}
    monkeypatch.setattr(renderer, "Path", lambda path: paths.get(str(path), Path(path)))
    base = deepcopy(qos[0])
    base["PORT"]["Ethernet0"]["lanes"] = "0,1"
    base["PORT_QOS_MAP"] = deepcopy(qos[1]["PORT_QOS_MAP"])
    base["CABLE_LENGTH"] = {"AZURE": {"Ethernet0": "300m", "Ethernet8": "0m"}}
    base["DEVICE_METADATA"] = {"localhost": {
        "platform": "test-platform", "hwsku": "test-sku", "buffer_model": "traditional",
    }}
    base["DEVICE_NEIGHBOR"] = {"Ethernet8": {"name": "protected", "port": "Ethernet1"}}
    base["DEVICE_NEIGHBOR_METADATA"] = {"protected": {"type": "LeafRouter"}}
    base["ACL_TABLE"] = {
        "DATAACL": {"type": "L3", "ports": ["Ethernet0", "Ethernet8"]},
        "EVERFLOW": {"type": "MIRROR", "ports": ["Ethernet0"]},
    }
    monkeypatch.setattr(renderer, "read_running", lambda: deepcopy(base))

    def build(*args):
        assert args[-1] is exclude_managed_acls
        config = deepcopy(base)
        if exclude_managed_acls:
            config["ACL_TABLE"]["DATAACL"]["ports"] = ["Ethernet8"]
            config["ACL_TABLE"]["EVERFLOW"]["ports"] = []
        return config, {"Ethernet0"}, {"Ethernet0"}

    monkeypatch.setattr(renderer, "build_ports", build)
    monkeypatch.setattr(renderer, "transport_plan", lambda *args: [])
    monkeypatch.setattr(renderer, "apply_forwarding", lambda *args: None)
    template_calls = []
    generated = deepcopy(qos[1])
    if template_has_pfc == "lossy":
        generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = ""
        for field in ("pfc_to_pg_map", "pfc_to_queue_map"):
            del generated["PORT_QOS_MAP"]["Ethernet0"][field]
        del generated["BUFFER_PROFILE"]["egress_lossless_profile"]
        monkeypatch.setattr(renderer, "read_buffer_daemon", lambda: pytest.fail("Lossy policy needs no daemon lookup"))
    elif not template_has_pfc:
        for field in ("pfc_enable", "pfc_to_pg_map", "pfc_to_queue_map"):
            del generated["PORT_QOS_MAP"]["Ethernet0"][field]

    def template_json(directory, context, template, template_dir=None):
        template_calls.append(template.name)
        assert context["DEVICE_NEIGHBOR"]["Ethernet8"] == base["DEVICE_NEIGHBOR"]["Ethernet8"]
        assert context["DEVICE_NEIGHBOR_METADATA"] == base["DEVICE_NEIGHBOR_METADATA"]
        return deepcopy(generated) if template.name == "qos.json.j2" else {}

    monkeypatch.setattr(renderer, "template_json", template_json)
    monkeypatch.setattr(renderer, "prepare_qos_template", lambda directory, *args: (
        sku_dir / "qos.json.j2", sku_dir))
    validator = SimpleNamespace(tablesWithOutYang=set(), loadYangModel=lambda: None,
                                loadData=lambda **kwargs: None, validate_data_tree=lambda: None)
    monkeypatch.setitem(sys.modules, "sonic_yang", SimpleNamespace(SonicYang=lambda *args: validator))
    facts = deepcopy(qos[2])
    facts.update(hostname="dut", peer_hostname="leaf")
    facts["connections"][0].update(role="uplink", peer={"port": "Ethernet0", "speed": 100000})
    facts["connections"][0]["buffer_case"]["speed"] = "100000"
    for side in ("dut", "peer"):
        facts["connections"][0][side]["atoms"] = ["Ethernet0"]
    layouts = {side: {"Ethernet0": {
        "mode": "1x100G", "speed": 100000, "children": [deepcopy(facts["connections"][0][side])]}}
               for side in ("dut", "peer")}
    request = {"role": role, "facts": facts, "settings": qos[5], "layouts": layouts, "buffer_wrapper": "",
               "exclude_managed_acls": exclude_managed_acls}
    original_sku = sku_lookup.read_bytes()
    if not has_platform_lookup:
        lookup_path = sku_lookup
    result = renderer.render_device(request)
    assert result["report"]["exclude_managed_acls"] is exclude_managed_acls
    assert result["report"]["excluded_acl_bindings"] == (
        {"DATAACL": ["Ethernet0"], "EVERFLOW": ["Ethernet0"]} if exclude_managed_acls else {})
    assert result["config"]["DEVICE_NEIGHBOR"] == {
        "Ethernet0": {"name": "leaf" if role == "dut" else "dut", "port": "Ethernet0"},
        "Ethernet8": base["DEVICE_NEIGHBOR"]["Ethernet8"],
    }
    expected_metadata = deepcopy(base["DEVICE_METADATA"])
    if role == "dut":
        expected_metadata["localhost"]["hwsku"] = "test-sku_generic"
        assert result["report"]["hwsku_alias"]["target"] == str(sku_dir)
        assert not (platform_dir / "test-sku_generic").exists()
    assert result["config"]["DEVICE_METADATA"] == expected_metadata
    assert result["config"]["DEVICE_NEIGHBOR_METADATA"] == base["DEVICE_NEIGHBOR_METADATA"]
    assert not any(name.startswith(("generic_lossless_", "pg_lossless_100000_5m_"))
                   for name in result["config"]["BUFFER_PROFILE"])
    if template_has_pfc == "lossy":
        assert result["report"]["qos_policy"] == "installed_lossy"
        assert "lossless_buffers" not in result["report"] and "buffer_daemon" not in result["report"]
        assert result["config"]["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] == ""
        assert result["config"]["CABLE_LENGTH"] == {"AZURE": {"Ethernet8": "0m"}}
        assert result["report"]["buffer_policy"]["lossy_cable_cases"] == {
            "Ethernet0": {"speed": "100000", "cable": "5m"}}
        assert request["facts"]["connections"][0]["buffer_case"] == {"speed": "100000", "cable": "5m"}
    else:
        assert result["report"]["lossless_buffers"]["profiles"]["pg_lossless_100000_5m_profile"]["xon"] == "20"
        assert result["report"]["buffer_daemon"]["path"] == "/daemon/pg_profile_lookup.ini"
        assert result["config"]["CABLE_LENGTH"]["AZURE"]["Ethernet0"] == "5m"
        assert result["report"]["buffer_policy"]["lossy_cable_cases"] == {}
    assets = result["report"]["assets"]
    assert assets[str(lookup_path)] == hashlib.sha256(lookup_text.encode()).hexdigest()
    assert (str(sku_lookup) in assets) is (not has_platform_lookup)
    assert lookup_path.read_text() == lookup_text
    lookup_path.write_text(lookup_text.replace("100 20 30", "100 21 30"))
    directory = tmp_path / "stage"
    directory.mkdir()
    renderer.write_private(directory / "request.json", result)
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(base))
    with pytest.raises(ValueError, match="Installed rendering asset changed"):
        device.run("stage", directory)
    assert not (directory / "running-backup.json").exists()
    if has_platform_lookup:
        assert sku_lookup.read_bytes() == original_sku


def test_qos_uses_real_mappings_and_preserves_lookup_values(qos):
    """Leave lossless PGs absent, retain egress policy, and project lookup-backed daemon outputs."""
    expected = renderer.apply_qos(*qos)
    config = qos[0]
    profile = "pg_lossless_100000_5m_profile"
    assert profile not in config["BUFFER_PROFILE"]
    assert not any(name.startswith("generic_lossless_") for name in config["BUFFER_PROFILE"])
    assert expected["profiles"][profile]["xon"] == "020"
    assert expected["profiles"][profile]["dynamic_th"] == "-3"
    assert expected["profiles"][profile]["xon_offset"] == "7"
    assert expected["pgs"] == {"Ethernet0|3": profile, "Ethernet0|4": profile}
    assert "Ethernet0|3" not in config["BUFFER_PG"]
    assert "Ethernet0|4" not in config["BUFFER_PG"]
    assert config["BUFFER_PG"]["Ethernet0|5"]["profile"] == "lossy"
    assert config["BUFFER_QUEUE"]["Ethernet0|2"]["profile"] == "egress_lossless_profile"
    assert config["BUFFER_QUEUE"]["Ethernet0|3"]["profile"] == "lossy"
    assert len(config["BUFFER_PG"]) == 6
    assert len(config["BUFFER_QUEUE"]) == 8
    assert config["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] == "3,4"
    tc_pg = config["PORT_QOS_MAP"]["Ethernet0"]["tc_to_pg_map"]
    assert config["TC_TO_PRIORITY_GROUP_MAP"][tc_pg]["2"] == "3"
    assert config["TC_TO_PRIORITY_GROUP_MAP"][tc_pg]["7"] == "4"
    assert config["TC_TO_PRIORITY_GROUP_MAP"]["policy"] == {str(tc): "0" for tc in range(8)}


@pytest.fixture
def lossy_qos(qos):
    """An explicitly lossy installed policy coexists with smaller protected running pools."""
    config, generated = qos[:2]
    generated["BUFFER_POOL"]["ingress_lossless_pool"]["type"] = "ingress"
    for name in ("egress_lossy_pool", "egress_lossless_pool"):
        generated["BUFFER_POOL"][name] = {"size": "1000", "mode": "dynamic", "type": "egress"}
    del generated["BUFFER_PROFILE"]["egress_lossless_profile"]
    generated["BUFFER_PROFILE"]["egress_lossy_profile"] = {
        "pool": "egress_lossy_pool", "size": "10", "dynamic_th": "7"}
    generated["BUFFER_PROFILE"]["ingress_lossy_profile"] = {
        "pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "7"}
    generated["BUFFER_PG"]["Ethernet0|0-7"]["profile"] = "ingress_lossy_profile"
    generated["BUFFER_QUEUE"]["Ethernet0|0-7"]["profile"] = "egress_lossy_profile"
    generated["BUFFER_PORT_INGRESS_PROFILE_LIST"] = {"Ethernet0": {"profile_list": "ingress_lossy_profile"}}
    generated["BUFFER_PORT_EGRESS_PROFILE_LIST"] = {"Ethernet0": {"profile_list": ["egress_lossy_profile"]}}
    generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = ""
    for field in ("pfc_to_pg_map", "pfc_to_queue_map"):
        del generated["PORT_QOS_MAP"]["Ethernet0"][field]
    config["BUFFER_POOL"] = deepcopy(generated["BUFFER_POOL"])
    config["BUFFER_POOL"]["ingress_lossless_pool"].update(size="900", xoff="40")
    config["BUFFER_PROFILE"] = deepcopy(generated["BUFFER_PROFILE"])
    config["BUFFER_PROFILE"]["ingress_lossy_profile"]["dynamic_th"] = "3"
    config["BUFFER_PG"] = {"Ethernet8|0": {"profile": "ingress_lossy_profile"}}
    config["BUFFER_QUEUE"] = {"Ethernet8|0": {"profile": "egress_lossy_profile"}}
    return qos


def test_installed_lossy_policy_preserves_protected_state_without_enabling_pfc(lossy_qos):
    """Use installed lossy profiles and classification without inventing lossless policy."""
    config, generated = lossy_qos[:2]
    config["CABLE_LENGTH"] = {
        "AZURE": {"Ethernet0": "300m", "Ethernet8": "0m"},
        "CUSTOM": {"Ethernet0": "1000m", "Ethernet8": "40m"},
        "SELECTED_ONLY": {"Ethernet0": "250m"},
    }
    generated["CABLE_LENGTH"] = {"AZURE": {"Ethernet0": "5m", "Ethernet8": "1000m"}}
    planned_cases = deepcopy(lossy_qos[2])
    before = deepcopy(config)
    qos_policy = deepcopy(generated["PORT_QOS_MAP"])
    classification = deepcopy(generated["TC_TO_PRIORITY_GROUP_MAP"])
    report = renderer.scope_buffer_policy(config, generated)
    assert config == before
    assert generated["PORT_QOS_MAP"] == qos_policy
    assert report["preserved_pools"]["ingress_lossless_pool"]["running"] == before["BUFFER_POOL"][
        "ingress_lossless_pool"]
    alias = report["profile_aliases"]["ingress_lossy_profile"]
    assert generated["BUFFER_PORT_INGRESS_PROFILE_LIST"]["Ethernet0"]["profile_list"] == alias
    assert generated["BUFFER_PORT_EGRESS_PROFILE_LIST"]["Ethernet0"]["profile_list"] == ["egress_lossy_profile"]
    expected = renderer.apply_qos(*lossy_qos)
    assert config["BUFFER_POOL"] == before["BUFFER_POOL"]
    assert config["BUFFER_PROFILE"]["ingress_lossy_profile"] == before["BUFFER_PROFILE"]["ingress_lossy_profile"]
    assert config["BUFFER_PROFILE"][alias]["dynamic_th"] == "7"
    assert config["BUFFER_PG"]["Ethernet8|0"] == before["BUFFER_PG"]["Ethernet8|0"]
    assert config["BUFFER_QUEUE"]["Ethernet8|0"] == before["BUFFER_QUEUE"]["Ethernet8|0"]
    assert config["BUFFER_PG"]["Ethernet0|0-7"] == {"profile": alias}
    assert config["BUFFER_QUEUE"]["Ethernet0|0-7"] == {"profile": "egress_lossy_profile"}
    assert config["TC_TO_PRIORITY_GROUP_MAP"] == classification
    assert config["PORT_QOS_MAP"]["Ethernet0"] == qos_policy["Ethernet0"]
    assert config["CABLE_LENGTH"] == {"AZURE": {"Ethernet8": "0m"}, "CUSTOM": {"Ethernet8": "40m"}}
    assert lossy_qos[2] == planned_cases
    assert expected == {"profiles": {}, "pgs": {}, "omitted_profiles": {}}
    assert not any(name.startswith(("pg_lossless_", "generic_egress_")) for name in config["BUFFER_PROFILE"])


@pytest.mark.parametrize("failure", ["pool_mode", "pool_xoff", "alias", "profile_list"])
def test_scoped_buffer_policy_rejects_conflicts(lossy_qos, failure):
    """Keep shared semantics and protected aliases immutable while scoping installed profiles."""
    config, generated = lossy_qos[:2]
    if failure == "pool_mode":
        config["BUFFER_POOL"]["ingress_lossless_pool"]["mode"] = "static"
    elif failure == "pool_xoff":
        generated["BUFFER_POOL"]["ingress_lossless_pool"]["xoff"] = "80"
    elif failure == "profile_list":
        generated["BUFFER_PORT_INGRESS_PROFILE_LIST"]["Ethernet0"]["profile_list"] = {"invalid": "reference"}
    else:
        profile = generated["BUFFER_PROFILE"]["ingress_lossy_profile"]
        alias = "generic_buffer_" + renderer.digest({"name": "ingress_lossy_profile", "profile": profile})[:12]
        config["BUFFER_PROFILE"][alias] = {"pool": "unrelated"}
    before = deepcopy(config)
    with pytest.raises(ValueError, match="Installed buffer"):
        renderer.scope_buffer_policy(config, generated)
    assert config == before


def test_lossy_policy_cannot_exceed_preserved_pool_capacity(lossy_qos):
    """Retaining a smaller pool does not waive reservation checks for installed lossy bindings."""
    config, generated = lossy_qos[:2]
    config["BUFFER_POOL"]["egress_lossy_pool"]["size"] = "70"
    renderer.scope_buffer_policy(config, generated)
    with pytest.raises(ValueError, match="reservations exceed"):
        renderer.apply_qos(*lossy_qos)


def test_lossy_policy_omits_unreferenced_selected_headroom(lossy_qos):
    """A retry from a failed lossless baseline must not retain rejected unused selected profiles."""
    config, generated = lossy_qos[:2]
    name = "pg_lossless_100000_5m_profile"
    stale = {"pool": "ingress_lossless_pool", "size": "999"}
    config["BUFFER_PROFILE"][name] = deepcopy(stale)
    generated["BUFFER_PROFILE"][name] = {"pool": "ingress_lossless_pool", "size": "123"}
    unrelated = "pg_lossless_200000_5m_profile"
    config["BUFFER_PROFILE"][unrelated] = deepcopy(stale)
    report = renderer.scope_buffer_policy(config, generated, daemon_profiles={name})
    expected = renderer.apply_qos(*lossy_qos)
    assert name not in config["BUFFER_PROFILE"]
    assert name not in report["profile_aliases"]
    assert expected["omitted_profiles"] == {name: stale}
    assert expected["profiles"] == expected["pgs"] == {}
    assert config["BUFFER_PROFILE"][unrelated] == stale


@pytest.mark.parametrize("table,row", [
    ("BUFFER_PG", {"profile": "pg_lossless_100000_5m_profile"}),
    ("UNRECOGNIZED_BINDING", {"reference": "[BUFFER_PROFILE|pg_lossless_100000_5m_profile]"}),
])
def test_lossy_policy_preserves_headroom_needed_by_retained_consumers(lossy_qos, table, row):
    """Disabling selected PFC does not authorize deleting protected or unknown profile consumers."""
    config, generated = lossy_qos[:2]
    name = "pg_lossless_100000_5m_profile"
    profile = {"pool": "ingress_lossless_pool", "size": "10"}
    config["BUFFER_PROFILE"][name] = deepcopy(profile)
    config.setdefault(table, {})["Ethernet8|3-4"] = deepcopy(row)
    renderer.scope_buffer_policy(config, generated, daemon_profiles={name})
    expected = renderer.apply_qos(*lossy_qos)
    assert config["BUFFER_PROFILE"][name] == profile
    assert config[table]["Ethernet8|3-4"] == row
    assert expected["omitted_profiles"] == {}


@pytest.mark.parametrize("inherit_disabled", [False, True])
def test_lossy_policy_needs_no_lossless_objects_or_pfc_maps(lossy_qos, inherit_disabled):
    """Empty PFC policy is valid without lossless pools, egress profiles, or fallback map bindings."""
    config, generated, _, _, _, base, _, _ = lossy_qos
    config["CABLE_LENGTH"] = {"AZURE": {"Ethernet0": "300m"}, "CUSTOM": {"Ethernet0": "1000m"}}
    for source in (config, generated):
        source["BUFFER_POOL"]["ingress_pool"] = source["BUFFER_POOL"].pop("ingress_lossless_pool")
        del source["BUFFER_POOL"]["egress_lossless_pool"]
        source["BUFFER_PROFILE"]["ingress_lossy_profile"]["pool"] = "ingress_pool"
    del generated["PFC_PRIORITY_TO_PRIORITY_GROUP_MAP"]
    del generated["MAP_PFC_PRIORITY_TO_QUEUE"]
    if inherit_disabled:
        config["PORT"]["Ethernet0"]["lanes"] = "0"
        base.update(PORT={"Ethernet0": {"lanes": "0"}}, PORT_QOS_MAP={"Ethernet0": {"pfc_enable": ""}})
        del generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"]
    renderer.scope_buffer_policy(config, generated)
    expected = renderer.apply_qos(*lossy_qos)
    assert expected["profiles"] == expected["pgs"] == {}
    assert config["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] == ""
    assert "pfc_to_pg_map" not in config["PORT_QOS_MAP"]["Ethernet0"]
    assert config["CABLE_LENGTH"] == {}


def test_rendered_direction_tables_supply_complete_policy(qos):
    """Consume the whole direction-aware render instead of a second macro-specific binding pass."""
    config, generated = qos[:2]
    generated["TC_TO_QUEUE_MAP"]["uplink"] = deepcopy(generated["TC_TO_QUEUE_MAP"]["policy"])
    generated["PORT_QOS_MAP"]["Ethernet0"]["tc_to_queue_map"] = "uplink"
    generated["QUEUE"] = {"Ethernet0|0-3": {"scheduler": "uplink"},
                          "Ethernet0|4-7": {"scheduler": "uplink"}}
    renderer.apply_qos(*qos)
    assert config["PORT_QOS_MAP"]["Ethernet0"]["tc_to_queue_map"] == "uplink"
    assert "Ethernet0|0-7" not in config["QUEUE"]
    assert all(row["scheduler"] == "uplink" for row in config["QUEUE"].values())


@pytest.mark.parametrize("missing", [
    ("pfc_enable",), ("pfc_to_pg_map", "pfc_to_queue_map"),
    ("pfc_enable", "pfc_to_pg_map", "pfc_to_queue_map"),
])
def test_missing_template_pfc_fields_follow_running_parent_lanes(qos, missing):
    """New children inherit only omitted fields, even when the running parent has a different name."""
    config, generated, _, _, _, base, _, _ = qos
    config["PORT"]["Ethernet0"]["lanes"] = "2,3"
    policy = generated["PORT_QOS_MAP"]["Ethernet0"]
    base.update(PORT={"Ethernet16": {"lanes": "0,1,2,3"}},
                PORT_QOS_MAP={"Ethernet16,Ethernet24": deepcopy(policy)})
    for field in missing:
        del policy[field]
    expected = renderer.apply_qos(*qos)
    assert expected["pgs"] == {"Ethernet0|3": "pg_lossless_100000_5m_profile",
                               "Ethernet0|4": "pg_lossless_100000_5m_profile"}
    assert base["PORT_QOS_MAP"]["Ethernet16,Ethernet24"]["pfc_enable"] == "3,4"


@pytest.mark.parametrize("failure", ["conflict", "missing", "lane_gap"])
def test_running_pfc_fallback_rejects_ambiguous_or_missing_policy(qos, failure):
    """Aggregation must not pick one running parent's PFC policy or invent missing bindings."""
    config, generated, _, _, _, base, _, _ = qos
    config["PORT"]["Ethernet0"]["lanes"] = "0,1"
    base.update(PORT={"Ethernet0": {"lanes": "0"}, "Ethernet1": {"lanes": "1"}},
                PORT_QOS_MAP={"Ethernet0": {"pfc_enable": "3,4"}, "Ethernet1": {"pfc_enable": "3,4"}})
    del generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"]
    if failure == "conflict":
        base["PORT_QOS_MAP"]["Ethernet1"]["pfc_enable"] = "3"
    elif failure == "missing":
        del base["PORT_QOS_MAP"]["Ethernet1"]
    else:
        del base["PORT"]["Ethernet1"]
    with pytest.raises(ValueError, match="Conflicting running|lacks pfc_enable|running lane coverage"):
        renderer.apply_qos(*qos)


def test_running_pfc_fallback_allows_equivalent_aggregated_priorities(qos):
    """Equivalent PFC priority lists on both old ports may be inherited by an aggregate."""
    config, generated, _, _, _, base, _, _ = qos
    config["PORT"]["Ethernet0"]["lanes"] = "0,1"
    base.update(PORT={"Ethernet0": {"lanes": "0"}, "Ethernet1": {"lanes": "1"}},
                PORT_QOS_MAP={"Ethernet0": {"pfc_enable": "3,4"}, "Ethernet1": {"pfc_enable": "4,3"}})
    del generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"]
    renderer.apply_qos(*qos)
    assert config["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] == "3,4"


@pytest.mark.parametrize("invalid", [None, "8", "3,3", "bad"])
def test_invalid_template_pfc_policy_never_falls_back(qos, invalid):
    """An explicitly rendered invalid policy is an error, not a reason to use running defaults."""
    qos[1]["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = invalid
    with pytest.raises(ValueError, match="PFC policy"):
        renderer.apply_qos(*qos)


def test_template_pfc_policy_is_authoritative_and_per_port(qos):
    """Different rendered priorities drive each port's expected daemon PGs without a global override."""
    config, generated, facts, _, _, base, _, selected = qos
    config["PORT"]["Ethernet1"] = {}
    selected.add("Ethernet1")
    link = deepcopy(facts["connections"][0])
    link["dut"]["port"] = "Ethernet1"
    facts["connections"].append(link)
    generated["PORT_QOS_MAP"]["Ethernet1"] = deepcopy(generated["PORT_QOS_MAP"]["Ethernet0"])
    generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = "3"
    generated["PORT_QOS_MAP"]["Ethernet1"]["pfc_enable"] = "4"
    base["PORT_QOS_MAP"] = {"Ethernet0,Ethernet1": {"pfc_enable": "7"}}
    expected = renderer.apply_qos(*qos)
    assert set(expected["pgs"]) == {"Ethernet0|3", "Ethernet1|4"}


def test_disabled_pfc_port_does_not_inherit_another_ports_lossless_policy(qos):
    """Mixed native policy must not enable PFC or expect headroom on explicitly lossy ports."""
    config, generated, facts, _, _, base, _, selected = qos
    config["CABLE_LENGTH"] = {"AZURE": {"Ethernet0": "300m", "Ethernet8": "40m"}}
    selected.add("Ethernet8")
    link = deepcopy(facts["connections"][0])
    link["dut"]["port"] = "Ethernet8"
    facts["connections"].append(link)
    generated["PORT_QOS_MAP"]["Ethernet8"] = dict(generated["PORT_QOS_MAP"]["Ethernet0"], pfc_enable="")
    for field in ("pfc_to_pg_map", "pfc_to_queue_map"):
        del generated["PORT_QOS_MAP"]["Ethernet8"][field]
    generated["BUFFER_PG"]["Ethernet8|0-7"] = {"profile": "lossy"}
    generated["BUFFER_QUEUE"]["Ethernet8|0-7"] = {"profile": "lossy"}
    base["PORT_QOS_MAP"] = {"Ethernet8": {"pfc_enable": "7"}}
    expected = renderer.apply_qos(*qos)
    assert set(expected["pgs"]) == {"Ethernet0|3", "Ethernet0|4"}
    assert config["PORT_QOS_MAP"]["Ethernet8"]["pfc_enable"] == ""
    assert config["PORT_QOS_MAP"]["Ethernet8"]["tc_to_pg_map"] == "policy"
    assert config["BUFFER_PG"]["Ethernet8|0-7"] == {"profile": "lossy"}
    assert config["CABLE_LENGTH"] == {"AZURE": {"Ethernet0": "5m"}}


def test_grouped_port_macros_are_expanded(qos):
    """Grouped maps must reach each port rather than leave overlapping group/single rows."""
    config, generated, facts = qos[:3]
    config["PORT"]["Ethernet1"] = {}
    qos[7].add("Ethernet1")
    link = deepcopy(facts["connections"][0])
    link["dut"]["port"] = "Ethernet1"
    facts["connections"].append(link)
    generated["PORT_QOS_MAP"] = {
        "Ethernet0,Ethernet1": deepcopy(generated["PORT_QOS_MAP"]["Ethernet0"])}
    renderer.apply_qos(*qos)
    assert set(config["PORT_QOS_MAP"]) == {"Ethernet0", "Ethernet1"}
    assert all(row["tc_to_queue_map"] == "policy" for row in config["PORT_QOS_MAP"].values())


@pytest.mark.parametrize("failure", ["missing_classification", "ambiguous_pg", "unreachable_queue"])
def test_lossless_classification_must_be_complete_and_unambiguous(qos, failure):
    """PFC/PG/queue programming must correspond to real ingress traffic classification."""
    generated = qos[1]
    if failure == "missing_classification":
        del generated["TC_TO_QUEUE_MAP"]
    elif failure == "ambiguous_pg":
        generated["MAP_PFC_PRIORITY_TO_QUEUE"]["policy"]["4"] = "2"
    else:
        generated["TC_TO_QUEUE_MAP"]["policy"] = {"0": "0"}
    with pytest.raises(ValueError):
        renderer.apply_qos(*qos)


def test_lookup_cannot_overwrite_a_protected_existing_profile(qos):
    """The daemon reuses existing profiles, so stale values must fail rather than be overwritten."""
    qos[0]["BUFFER_PROFILE"] = {
        "pg_lossless_100000_5m_profile": {"pool": "ingress_lossless_pool", "size": "999"}}
    with pytest.raises(ValueError, match="Existing daemon profile differs"):
        renderer.apply_qos(*qos)


@pytest.mark.parametrize("stale", [False, True])
def test_clean_headroom_inputs_omit_only_unreferenced_selected_profiles(qos, stale):
    """Defer selected profiles to the daemon without purging unrelated unused definitions."""
    name = "pg_lossless_100000_5m_profile"
    profile = {"pool": "ingress_lossless_pool", "size": "100", "xon": "020", "xoff": "30",
               "dynamic_th": "-3", "xon_offset": "7"}
    existing = dict(profile, xoff="999") if stale else deepcopy(profile)
    unrelated = "pg_lossless_200000_5m_profile"
    qos[0]["BUFFER_PROFILE"] = {name: deepcopy(existing), unrelated: deepcopy(existing)}
    qos[0]["BUFFER_PG"] = {"Ethernet0|3-4": {"profile": name}}
    result = renderer.apply_qos(*qos, omit_managed_headroom=True)
    assert name not in qos[0]["BUFFER_PROFILE"]
    assert qos[0]["BUFFER_PROFILE"][unrelated] == existing
    assert result["omitted_profiles"] == {name: existing}
    assert result["profiles"][name] == profile
    assert not device.verify_config(qos[0], deepcopy(qos[0]), {"lossless_buffers": result})
    converged = deepcopy(qos[0])
    converged["BUFFER_PROFILE"][name] = deepcopy(profile)
    converged["BUFFER_PG"]["Ethernet0|3-4"] = {"profile": name}
    assert device.verify_config(qos[0], converged, {"lossless_buffers": result})
    if stale:
        converged["BUFFER_PROFILE"][name] = existing
        with pytest.raises(ValueError, match="Daemon-generated BUFFER_PROFILE"):
            device.verify_config(qos[0], converged, {"lossless_buffers": result})


@pytest.mark.parametrize("table,row", [
    ("BUFFER_PG", {"profile": "pg_lossless_100000_5m_profile"}),
    ("BUFFER_PORT_INGRESS_PROFILE_LIST", {"profile_list": "lossy,pg_lossless_100000_5m_profile"}),
    ("BUFFER_PORT_EGRESS_PROFILE_LIST", {"profile_list": ["pg_lossless_100000_5m_profile"]}),
    ("UNRECOGNIZED_BINDING", {"reference": "[BUFFER_PROFILE|pg_lossless_100000_5m_profile]"}),
])
def test_clean_headroom_inputs_reject_stale_profiles_with_retained_consumers(qos, table, row):
    """Known, grouped-list, and unknown references must prevent removal of shared stale headroom."""
    name = "pg_lossless_100000_5m_profile"
    qos[0]["BUFFER_PROFILE"] = {name: {"pool": "ingress_lossless_pool", "size": "999"}}
    qos[0].setdefault(table, {})["Ethernet8|3"] = deepcopy(row)
    with pytest.raises(ValueError, match="remains referenced by retained configuration"):
        renderer.apply_qos(*qos, omit_managed_headroom=True)
    assert name in qos[0]["BUFFER_PROFILE"]
    assert qos[0][table]["Ethernet8|3"] == row


def test_nonidentity_pfc_pg_map_is_rejected_for_traditional_daemon(qos):
    """The upstream traditional daemon derives PG indices directly from enabled PFC priorities."""
    qos[1]["PFC_PRIORITY_TO_PRIORITY_GROUP_MAP"]["policy"]["3"] = "5"
    with pytest.raises(ValueError, match="identity PFC-priority-to-PG"):
        renderer.apply_qos(*qos)


@pytest.mark.parametrize("omit_managed_headroom", [False, True])
def test_existing_matching_profile_and_protected_pg_are_preserved(qos, omit_managed_headroom):
    """Reuse compatible shared headroom without clearing protected users of the same profile."""
    name = "pg_lossless_100000_5m_profile"
    profile = {"pool": "ingress_lossless_pool", "size": "100", "xon": "020", "xoff": "30",
               "dynamic_th": "-3", "xon_offset": "7"}
    qos[0]["BUFFER_PROFILE"] = {name: deepcopy(profile)}
    qos[0]["BUFFER_PG"] = {"Ethernet8|3-4": {"profile": name}}
    expected = renderer.apply_qos(*qos, omit_managed_headroom=omit_managed_headroom)
    assert qos[0]["BUFFER_PROFILE"][name] == profile
    assert qos[0]["BUFFER_PG"]["Ethernet8|3-4"] == {"profile": name}
    assert "Ethernet0|3" not in qos[0]["BUFFER_PG"]
    assert expected["profiles"][name] == profile
    if omit_managed_headroom:
        assert expected["omitted_profiles"] == {}


@pytest.mark.parametrize("pool_mode", ["dynamic", "static"])
def test_daemon_profile_is_expected_not_materialized_from_template(qos, pool_mode):
    """Ignore template-owned copies of the target headroom profile and use the pool's threshold mode."""
    name = "pg_lossless_100000_5m_profile"
    qos[1]["BUFFER_POOL"]["ingress_lossless_pool"]["mode"] = pool_mode
    qos[1]["BUFFER_PROFILE"][name] = {"size": "wrong", "pool": "ingress_lossless_pool"}
    qos[1]["BUFFER_PG"] = {"Ethernet0|0-7": {"profile": "lossy"}}
    result = renderer.apply_qos(*qos)
    assert name not in qos[0]["BUFFER_PROFILE"]
    assert result["profiles"][name][pool_mode + "_th"] == "-3"
    assert "Ethernet0|3" not in qos[0]["BUFFER_PG"]
    assert qos[0]["PORT"]["Ethernet8"] == {}


@pytest.mark.parametrize("failure", [None, "missing", "different", "duplicate"])
def test_active_daemon_lookup_must_support_platform_cases(qos, failure):
    """The renderer's platform copy does not establish what file the daemon actually reads."""
    expected = renderer.apply_qos(*qos)
    lookup = qos[4]
    columns = list(lookup[0])
    text = "# " + " ".join(columns) + "\n" + " ".join(lookup[0].values()) + "\n"
    if failure == "missing":
        text = text.replace("100000", "200000")
    elif failure == "different":
        text = text.replace("020", "999")
    elif failure == "duplicate":
        text += " ".join(lookup[0].values()) + "\n"
    daemon = {"content": text}
    if failure:
        with pytest.raises(ValueError, match="Active daemon lookup"):
            renderer.validate_daemon_lookup(daemon, expected["profiles"], lookup)
    else:
        renderer.validate_daemon_lookup(daemon, expected["profiles"], lookup)


@pytest.mark.parametrize("arguments", [
    ["-l", "/active.ini"], ["-l/active.ini"], ["-a", "/asic.json", "-l", "/active.ini"], [],
])
def test_daemon_process_query_validates_startup_and_reads_actual_file(monkeypatch, arguments):
    """Execute the container query against a fake process filesystem, never Docker or the lab."""
    content = b"# speed cable size xon xoff threshold\n100000 5m 100 20 30 -3\n"

    class ProcessPath:
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return self.value

        @property
        def name(self):
            return self.value.rsplit("/", 1)[-1]

        def glob(self, pattern):
            return [ProcessPath("/proc/123/cmdline")]

        def read_bytes(self):
            if self.value.endswith("/cmdline"):
                return ("\0".join(["/usr/bin/buffermgrd"] + arguments) + "\0").encode()
            assert self.value == "/active.ini"
            return content

        def is_absolute(self):
            return self.value.startswith("/")

    def query(command, **kwargs):
        output = io.StringIO()
        with monkeypatch.context() as context, redirect_stdout(output):
            context.setattr(pathlib, "Path", ProcessPath)
            exec(compile(command[-1], "<buffer-daemon-query>", "exec"), {})
        return output.getvalue()

    monkeypatch.setattr(renderer.subprocess, "check_output", query)
    if not arguments or "-a" in arguments:
        with pytest.raises(ValueError, match="lookup-based traditional"):
            renderer.read_buffer_daemon()
    else:
        assert renderer.read_buffer_daemon() == {
            "path": "/active.ini", "sha256": hashlib.sha256(content).hexdigest(), "content": content.decode(),
        }


def test_appl_query_reads_swss_tables_and_normalizes_separators(monkeypatch):
    """Exercise the remote query with a fake swsscommon API and actual APPL_DB key shapes."""
    tables = {"BUFFER_PROFILE_TABLE": {"pg_lossless_100000_5m_profile": {"size": "100"}},
              "BUFFER_PG_TABLE": {"Ethernet0:3-4": {"profile": "pg_lossless_100000_5m_profile"}}}
    api = SimpleNamespace(
        DBConnector=lambda name, timeout: (name, timeout),
        Table=lambda db, name: SimpleNamespace(
            getKeys=lambda: list(tables[name]),
            get=lambda key: (True, list(tables[name][key].items()))))
    monkeypatch.setitem(sys.modules, "swsscommon", SimpleNamespace(swsscommon=api))

    def query(command, **kwargs):
        output = io.StringIO()
        with redirect_stdout(output):
            exec(compile(command[-1], "<appl-buffer-query>", "exec"), {})
        return output.getvalue()

    monkeypatch.setattr(device.subprocess, "check_output", query)
    assert device.read_appl_buffers() == {
        "BUFFER_PROFILE": tables["BUFFER_PROFILE_TABLE"],
        "BUFFER_PG": {"Ethernet0|3-4": tables["BUFFER_PG_TABLE"]["Ethernet0:3-4"]},
    }


@pytest.fixture
def daemon_buffers(qos):
    """Rendered inputs and converged CONFIG_DB with grouped daemon-generated PGs."""
    expected = renderer.apply_qos(*qos)
    config = qos[0]
    config["DEVICE_METADATA"] = {"localhost": {"hostname": "dut"}}
    config["BUFFER_PROFILE"]["protected"] = {"pool": "ingress_lossless_pool", "size": "10"}
    config["BUFFER_PG"]["Ethernet8|3-4"] = {"profile": "protected"}
    running = deepcopy(config)
    running["BUFFER_PROFILE"].update(deepcopy(expected["profiles"]))
    running["BUFFER_PG"]["Ethernet0|3-4"] = {"profile": "pg_lossless_100000_5m_profile"}
    report = {"config_sha256": renderer.digest(config), "lossless_buffers": expected}
    return config, running, report


def test_readback_accepts_only_expected_daemon_additions(daemon_buffers):
    """Minimal inputs remain valid while grouped daemon outputs satisfy the final contract."""
    config, running, report = daemon_buffers
    assert device.verify_config(config, config, report) is False
    assert device.verify_config(config, running, report) is True
    renderer.validate_references(running)
    assert config["BUFFER_PG"].get("Ethernet0|3-4") is None


@pytest.mark.parametrize("with_buffers", [False, True])
@pytest.mark.parametrize("empty_in_input", [False, True])
def test_readback_equates_absent_and_empty_tables(daemon_buffers, with_buffers, empty_in_input):
    """Redis drops empty tables; equivalent readback must not initiate paired recovery."""
    config, running, report = daemon_buffers if with_buffers else ({}, {}, {})
    (config if empty_in_input else running)["TC_TO_DSCP_MAP"] = {}
    assert device.verify_config(config, running, report)
    (config if empty_in_input else running)["TC_TO_DSCP_MAP"] = {"AZURE": {"3": "24"}}
    with pytest.raises(ValueError, match="TC_TO_DSCP_MAP"):
        device.verify_config(config, running, report)


@pytest.mark.parametrize("failure", [
    "wrong_profile", "wrong_pg", "protected_pg", "template_profile", "unexpected_profile", "other_table", "overlap",
])
def test_daemon_readback_does_not_ignore_other_drift(daemon_buffers, failure):
    """Allowlist generated objects without relaxing unrelated tables or protected buffer state."""
    config, running, report = daemon_buffers
    if failure == "wrong_profile":
        running["BUFFER_PROFILE"]["pg_lossless_100000_5m_profile"]["xon"] = "999"
    elif failure == "wrong_pg":
        running["BUFFER_PG"]["Ethernet0|3-4"]["profile"] = "lossy"
    elif failure == "protected_pg":
        del running["BUFFER_PG"]["Ethernet8|3-4"]
    elif failure == "template_profile":
        del running["BUFFER_PROFILE"]["lossy"]
    elif failure == "unexpected_profile":
        running["BUFFER_PROFILE"]["unexpected"] = {"size": "1"}
    elif failure == "other_table":
        running["DEVICE_METADATA"]["localhost"]["hostname"] = "other"
    else:
        running["BUFFER_PG"]["Ethernet0|3"] = {"profile": "pg_lossless_100000_5m_profile"}
    with pytest.raises(ValueError):
        device.verify_config(config, running, report)


@pytest.mark.parametrize("state", ["pending", "complete", "wrong"])
def test_daemon_outputs_must_reach_appl_db(daemon_buffers, monkeypatch, state):
    """CONFIG_DB generation alone is not sufficient to mark buffer convergence."""
    _, running, report = daemon_buffers
    tables = running if state != "pending" else {}
    if state == "wrong":
        tables["BUFFER_PROFILE"]["pg_lossless_100000_5m_profile"]["size"] = "999"
    monkeypatch.setattr(device, "read_appl_buffers", lambda: tables)
    if state == "wrong":
        with pytest.raises(ValueError, match="APPL_DB lossless buffer"):
            device.verify_appl_buffers(report["lossless_buffers"])
    else:
        assert device.verify_appl_buffers(report["lossless_buffers"]) is (state == "complete")


def test_verify_waits_for_config_and_appl_convergence(daemon_buffers, tmp_path, monkeypatch):
    """Wait for declared outputs in both databases, not for arbitrary configuration changes."""
    config, running, report = daemon_buffers
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    reads = iter([config, running, running])
    applications = iter([{}, running])
    sleeps = []
    monkeypatch.setattr(device, "read_running", lambda: next(reads))
    monkeypatch.setattr(device, "read_appl_buffers", lambda: next(applications))
    monkeypatch.setattr(device.time, "sleep", lambda seconds: sleeps.append(seconds))
    device.run("verify", tmp_path)
    assert sleeps == [1, 1]


def test_daemon_convergence_timeout_is_explicit(daemon_buffers, tmp_path, monkeypatch):
    """A missing daemon output must fail rather than save an incomplete configuration."""
    config, _, report = daemon_buffers
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    monkeypatch.setattr(device, "read_running", lambda: config)
    ticks = iter([0, 121])
    monkeypatch.setattr(device.time, "monotonic", lambda: next(ticks))
    with pytest.raises(ValueError, match="Timed out waiting"):
        device.run("verify", tmp_path)


def test_save_persists_validated_daemon_outputs(daemon_buffers, tmp_path, monkeypatch):
    """Save/read back the converged state, not the input artifact that intentionally lacks lossless PGs."""
    config, running, report = daemon_buffers
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    startup = tmp_path / "startup.json"
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(running))
    monkeypatch.setattr(device, "read_appl_buffers", lambda: deepcopy(running))
    monkeypatch.setattr(device, "Path", lambda path: (
        startup if str(path) == "/etc/sonic/config_db.json" else Path(path)))
    monkeypatch.setattr(device.subprocess, "run", lambda *args, **kwargs: startup.write_text(json.dumps(running)))
    device.run("save", tmp_path)
    assert json.loads(startup.read_text()) == running
    assert renderer.digest(running) != report["config_sha256"]
    del running["BUFFER_PG"]["Ethernet0|3-4"]
    with pytest.raises(ValueError, match="incomplete before save"):
        device.run("save", tmp_path)


def test_lossy_verify_and_save_accept_empty_tables_without_daemon_expectations(tmp_path, monkeypatch):
    """Lossy save uses the same complete-config validation as verify, including empty-table equivalence."""
    config = {"PORT": {}, "TC_TO_DSCP_MAP": {}}
    running = {"PORT": {}}
    report = {"config_sha256": renderer.digest(config), "qos_policy": "installed_lossy"}
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    startup = tmp_path / "startup.json"
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(running))
    monkeypatch.setattr(device, "read_appl_buffers", lambda: pytest.fail("Unexpected lossless convergence query"))
    monkeypatch.setattr(device, "read_buffer_daemon", lambda: pytest.fail("Unexpected lossless daemon query"))
    monkeypatch.setattr(device, "Path", lambda path: (
        startup if str(path) == "/etc/sonic/config_db.json" else Path(path)))
    saves = []

    def save(*args, **kwargs):
        saves.append(args)
        startup.write_text(json.dumps(running))

    monkeypatch.setattr(device.subprocess, "run", save)
    device.run("verify", tmp_path)
    device.run("save", tmp_path)
    assert len(saves) == 1
    running["BUFFER_PROFILE"] = {"unexpected": {"size": "1"}}
    with pytest.raises(ValueError, match="CONFIG_DB read-back differs"):
        device.run("save", tmp_path)
    assert len(saves) == 1


def test_daemon_lookup_drift_is_refused_before_staging(tmp_path, monkeypatch):
    """The active container lookup is separate from host platform/template asset hashes."""
    base = {"PORT": {}}
    report = {"baseline_sha256": renderer.digest(base), "config_sha256": renderer.digest(base),
              "assets": {}, "buffer_daemon": {"path": "/lookup", "sha256": "original"}}
    renderer.write_private(tmp_path / "request.json", {"config": base, "report": report})
    monkeypatch.setattr(device, "read_running", lambda: base)
    monkeypatch.setattr(device, "read_buffer_daemon", lambda: {"path": "/lookup", "sha256": "changed"})
    with pytest.raises(ValueError, match="Active buffer daemon lookup changed"):
        device.run("stage", tmp_path)
    assert not (tmp_path / "running-backup.json").exists()


@pytest.mark.parametrize("failure", [
    "pool", "missing_case", "duplicate_case", "missing_map", "shared_profile", "pool_mode", "zero_cable",
])
def test_qos_rejects_unsafe_inputs(qos, failure):
    """No missing case/map, oversubscribed pool, or protected global change can pass."""
    config, generated, _, _, lookup, _, _, _ = qos
    if failure == "pool":
        generated["BUFFER_POOL"]["ingress_lossless_pool"]["size"] = "199"
    elif failure == "missing_case":
        lookup[0]["cable"] = "40m"
    elif failure == "duplicate_case":
        lookup.append(deepcopy(lookup[0]))
    elif failure == "missing_map":
        generated["PORT_QOS_MAP"]["Ethernet0"]["pfc_to_pg_map"] = "absent"
    elif failure == "pool_mode":
        del generated["BUFFER_POOL"]["ingress_lossless_pool"]["mode"]
    elif failure == "zero_cable":
        lookup[0]["cable"] = qos[2]["connections"][0]["buffer_case"]["cable"] = "0m"
    else:
        config["BUFFER_POOL"] = {"ingress_lossless_pool": {"size": "9999"}}
    with pytest.raises(ValueError):
        renderer.apply_qos(*qos)


def test_transport_requires_owned_access_and_does_not_invent_tags():
    """Implicit graph tags require ownership; explicit reserved tags still need trunks."""
    facts = {"connections": [{"dut": {"port": "Ethernet0"}, "peer": {"port": "Ethernet1"},
                              "ptf_index": 0, "source_links": [{"VlanID": "100"}, {"VlanID": None}, {}]}]}
    leaf = {"VLAN": {"Vlan100": {"vlanid": "100"}}, "VLAN_MEMBER": {
        "Vlan100|Ethernet0": {"tagging_mode": "untagged"},
        "Vlan100|Ethernet8": {"tagging_mode": "tagged"},
    }}
    assert renderer.transport_plan(facts, leaf, {"Ethernet0"}, {})[0]["vlan_id"] == 100
    with pytest.raises(ValueError, match="owned"):
        renderer.transport_plan(facts, leaf, {"Ethernet2"}, {})
    del leaf["VLAN_MEMBER"]["Vlan100|Ethernet0"]
    with pytest.raises(ValueError, match="owned"):
        renderer.transport_plan(facts, leaf, {"Ethernet0"}, {})
    assert renderer.transport_plan(facts, leaf, {"Ethernet0"}, {"transport": {"vlan_ids": [100]}})
    with pytest.raises(ValueError, match="additional isolated") as error:
        renderer.transport_plan({"connections": facts["connections"] * 2}, leaf, {"Ethernet0"}, {})
    assert "Only 1 candidate transport VLAN IDs for 2 active children (shortfall: 1)" in str(error.value)
    assert "ownership and provisioning are not yet validated" in str(error.value)
    leaf["VLAN_INTERFACE"] = {"Vlan100": {}}
    with pytest.raises(ValueError, match="owned"):
        renderer.transport_plan(facts, leaf, {"Ethernet0"}, {"transport": {"vlan_ids": [100]}})


def test_transport_rejects_non_string_csv_vlan_attributes():
    """A null tag is unset, but malformed non-string CSV attributes must not be silently coerced."""
    facts = {"connections": [{"source_links": [{"VlanID": 100}]}]}
    with pytest.raises(ValueError, match="VlanID must be a string or null"):
        renderer.transport_plan(facts, {}, set(), {})


@pytest.mark.parametrize("sources,expected", [
    ([{}, {"AutoNeg": None, "LinkTraining": None, "FEC": None},
      {"AutoNeg": " ", "LinkTraining": "", "FEC": ""}],
     {"autoneg": "on", "link_training": "off", "fec": "rs"}),
    ([{"AutoNeg": None, "LinkTraining": None, "FEC": None},
      {"AutoNeg": " OFF ", "LinkTraining": " ON ", "FEC": " NONE "}],
     {"autoneg": "off", "link_training": "on", "fec": "none"}),
    ([{"AutoNeg": "on"}, {"AutoNeg": "off"}], "Unsupported or conflicting explicit AutoNeg"),
    ([{"FEC": "invalid"}], "Unsupported or conflicting explicit FEC"),
    ([{"AutoNeg": False}], "AutoNeg must be a string or null"),
    ([{"FEC": 0}], "FEC must be a string or null"),
])
def test_forwarding_handles_unset_source_policies_without_weakening_validation(sources, expected):
    """Null/missing/blank settings leave policy intact; explicit settings still validate and override."""
    config = {"PORT": {"Ethernet0": {"autoneg": "on", "link_training": "off", "fec": "rs"}}}
    facts = {"connections": [{"peer": {"port": "Ethernet0"}, "source_links": sources}]}
    if isinstance(expected, str):
        with pytest.raises(ValueError, match=expected):
            renderer.apply_forwarding(config, facts, {"Ethernet0"}, {"Ethernet0"}, "peer", [])
    else:
        renderer.apply_forwarding(config, facts, {"Ethernet0"}, {"Ethernet0"}, "peer", [])
        assert config["PORT"]["Ethernet0"] == expected


@pytest.mark.parametrize("table,key,routed,svi,conflict", [
    ("MGMT_INTERFACE", "eth0|192.0.2.1/24", "192.0.2.128/31", "198.51.100.1/24", "192.0.2.128/31"),
    ("VLAN_INTERFACE", "Vlan2000|2001:db8:2::1/64",
     "2001:db8:1::/127", "2001:db8:2::2/64", "2001:db8:2::2/64"),
    ("VLAN_INTERFACE", "Vlan2000|2001:db8:1::1/64",
     "2001:db8:1::2/127", "2001:db8:2::1/64", "2001:db8:1::2/127"),
])
def test_forwarding_cannot_overlap_preserved_interface_addresses(table, key, routed, svi, conflict):
    """Identify both allocations without dropping retained SVIs or weakening management protection."""
    config = {"PORT": {"Ethernet0": {}}, table: {key: {}}}
    original = deepcopy(config)
    facts = {"connections": [{"dut": {"port": "Ethernet0"}, "source_links": [],
                              "role": "uplink", "interface_mode": "routed", "dut_address": routed}],
             "forwarding": {"svi": svi, "vlan_id": 1000}}
    with pytest.raises(ValueError, match="overlap preserved " + table) as error:
        renderer.apply_forwarding(config, facts, {"Ethernet0"}, {"Ethernet0"}, "dut")
    assert "planned " + conflict in str(error.value)
    assert key in str(error.value)
    assert config == original


def test_forwarding_vlan_id_collision_identifies_retained_vlan():
    """A different subnet does not authorize overwriting an existing protected VLAN ID."""
    config = {"PORT": {"Ethernet0": {}, "Ethernet512": {}},
              "VLAN": {"Vlan1000": {"vlanid": "1000", "members": ["Ethernet512"]}}}
    protected = deepcopy(config["VLAN"])
    facts = {"connections": [{"dut": {"port": "Ethernet0"}, "source_links": [],
                              "interface_mode": "routed", "dut_address": "192.0.2.0/31"}],
             "forwarding": {"svi": "198.51.100.1/24", "vlan_id": 1000}}
    with pytest.raises(ValueError, match="DUT forwarding VLAN already exists: Vlan1000"):
        renderer.apply_forwarding(config, facts, {"Ethernet0"}, {"Ethernet0"}, "dut")
    assert config["VLAN"] == protected


@pytest.mark.parametrize("ipv6", [False, True])
def test_planner_allocations_feed_complete_dut_forwarding(ipv6):
    """Render explicit mixed-cage roles in either family without changing management."""
    connections = [
        {"dut": {"port": "Ethernet0", "cage": "Ethernet0"}, "source_links": [
            {"AutoNeg": None, "LinkTraining": None, "FEC": None}]},
        {"dut": {"port": "Ethernet1", "cage": "Ethernet0"}, "source_links": []},
        {"dut": {"port": "Ethernet8", "cage": "Ethernet8"}, "source_links": []},
        {"dut": {"port": "Ethernet9", "cage": "Ethernet8"}, "source_links": []},
    ]
    routed_pool = "2001:db8:1::/64" if ipv6 else "192.0.2.0/24"
    access_pool = "2001:db8:2::/64" if ipv6 else "198.51.100.0/24"
    destination_pool = "2001:db8:3::/64" if ipv6 else "203.0.113.0/24"
    settings = {
        "physical_links": {"uplinks": ["Ethernet1", "Ethernet8"], "downlinks": ["Ethernet0", "Ethernet9"]},
        "routed_interfaces": {"address_pool": routed_pool},
        "access_vlan": {"vlan_id": 1000, "subnet": access_pool},
        "external_destinations": {"address_pool": destination_pool},
    }
    forwarding = allocate_forwarding(settings, connections)
    config = {"PORT": {link["dut"]["port"]: {} for link in connections},
              "MGMT_INTERFACE": {"eth0|10.0.0.1/24": {}}}
    renderer.apply_forwarding(config, {"connections": connections, "forwarding": forwarding},
                              set(config["PORT"]), set(config["PORT"]), "dut")
    expected = ({"Ethernet1": {}, "Ethernet1|2001:db8:1::/127": {},
                 "Ethernet8": {}, "Ethernet8|2001:db8:1::2/127": {}} if ipv6 else
                {"Ethernet1": {}, "Ethernet1|192.0.2.0/31": {}, "Ethernet8": {}, "Ethernet8|192.0.2.2/31": {}})
    assert config["INTERFACE"] == expected
    assert config["VLAN"]["Vlan1000"] == {"vlanid": "1000"}
    svi = "2001:db8:2::1/64" if ipv6 else "198.51.100.1/24"
    assert config["VLAN_INTERFACE"]["Vlan1000|" + svi] == {}
    assert config["VLAN_MEMBER"] == {port: {"tagging_mode": "untagged"}
                                     for port in ("Vlan1000|Ethernet0", "Vlan1000|Ethernet9")}
    assert config["STATIC_ROUTE"] == forwarding["static_routes"]
    assert config["STATIC_ROUTE"]["::/0" if ipv6 else "0.0.0.0/0"]["ifname"] == "Ethernet1"
    assert config["MGMT_INTERFACE"] == {"eth0|10.0.0.1/24": {}}
    assert "BGP_NEIGHBOR" not in config
    assert "PORTCHANNEL" not in config


@pytest.mark.parametrize("legacy_members", [False, True])
def test_peer_forwarding_uses_vlan_member_without_inventing_legacy_fields(legacy_members):
    """Use canonical membership rows while maintaining an existing legacy member list if present."""
    row = {"vlanid": "100"}
    if legacy_members:
        row["members"] = ["Ethernet0"]
    config = {"PORT": {"Ethernet0": {}}, "VLAN": {"Vlan100": row}}
    facts = {"connections": [{"peer": {"port": "Ethernet0"}, "source_links": []}]}
    renderer.apply_forwarding(config, facts, {"Ethernet0"}, {"Ethernet0"}, "peer",
                              [{"vlan_id": 100, "peer_port": "Ethernet0"}])
    assert config["VLAN_MEMBER"] == {"Vlan100|Ethernet0": {"tagging_mode": "untagged"}}
    assert ("members" in row) is legacy_members
    if legacy_members:
        assert row["members"] == ["Ethernet0"]


@pytest.fixture
def rendered():
    """Minimal complete-artifact controller fixture, with no actual device data."""
    testbed = {"conf-name": "tb", "topo": "generic", "server": "server", "inv_name": "inventory",
               "group-name": "vms1", "ptf_ip": "192.0.2.1/24", "ptf_image_name": "ptf"}
    report = {role: {"transport": [{"vlan_id": 100}], "owned_ports": ["Ethernet0"]}
              for role in ("dut", "peer")}
    artifacts = {
        "manifest.json": {"hostname": "dut", "scenario_id": "test-id", "deployable": True,
                          "roles_finalized": True, "requires_explicit_apply": True, "testbed": testbed},
        "coverage.json": {"status": "complete"},
        "resolved_facts.json": {"peer_hostname": "leaf"}, "render_report.json": report,
        "dut_config.json": {"PORT": {}}, "leaf_config.json": {"PORT": {}},
    }
    return artifacts, testbed


@pytest.mark.parametrize("action", ["add-topo", "remove-topo", "deploy-mg", "recover"])
def test_dry_run_never_contacts_ansible(rendered, monkeypatch, capsys, action):
    """Every deployment/recovery dry-run is local-only."""
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Ansible was invoked"))
    controller.deploy(Namespace(action=action, apply=False), *rendered, "dut")
    assert "No devices or host infrastructure contacted" in capsys.readouterr().out


@pytest.mark.parametrize("failed_phase", [None, "stage", "apply", "verify", "save"])
def test_pair_deployment_order_and_recovery(rendered, monkeypatch, failed_phase):
    """Both devices stage first; only a failure after staging triggers pair rollback."""
    phases = []

    def run(args, name, variables, local, **kwargs):
        phase = variables.get("generic_action", "host-verify")
        phases.append(phase)
        if phase == failed_phase:
            raise ValueError("simulated " + phase)

    monkeypatch.setattr(controller, "run_playbook", run)
    args = Namespace(action="deploy-mg", apply=True)
    if failed_phase:
        with pytest.raises(ValueError, match="simulated"):
            controller.deploy(args, *rendered, "dut")
    else:
        controller.deploy(args, *rendered, "dut")
    assert phases[:2] == ["host-verify", "stage"]
    if failed_phase and failed_phase != "stage":
        assert phases[-1] == "rollback"
    elif failed_phase is None:
        assert phases == ["host-verify", "stage", "apply", "verify", "save"]
    else:
        assert phases == ["host-verify", "stage"]


def test_failed_rollback_is_reported_as_manual_recovery(rendered, monkeypatch):
    """A second failure during recovery must not look like a recovered deployment."""
    def run(args, name, variables, local, **kwargs):
        if variables.get("generic_action") in ("apply", "rollback"):
            raise ValueError("simulated failure")

    monkeypatch.setattr(controller, "run_playbook", run)
    with pytest.raises(ValueError, match="BOTH-DEVICE RECOVERY FAILED"):
        controller.deploy(Namespace(action="deploy-mg", apply=True), *rendered, "dut")


def test_interrupted_reload_attempts_pair_recovery(rendered, monkeypatch):
    """An operator interrupt after staging must not bypass the recovery attempt."""
    phases = []

    def run(args, name, variables, local, **kwargs):
        phase = variables.get("generic_action")
        phases.append(phase)
        if phase == "apply":
            raise KeyboardInterrupt()

    monkeypatch.setattr(controller, "run_playbook", run)
    with pytest.raises(ValueError, match="Deployment interrupted"):
        controller.deploy(Namespace(action="deploy-mg", apply=True), *rendered, "dut")
    assert phases[-1] == "rollback"


def publish(directory, artifacts):
    """Write synthetic artifacts using the production digest/serialization contract."""
    directory.mkdir(mode=0o700)
    manifest = artifacts["manifest.json"]
    manifest["artifact_sha256"] = {
        name: hashlib.sha256(controller.artifact_text(name, value).encode()).hexdigest()
        for name, value in artifacts.items() if name != "manifest.json"}
    manifest["scenario_id"] = controller.scenario_id(manifest)
    for name, value in artifacts.items():
        renderer.write_private(directory / name, value)


def test_manifest_tampering_and_private_artifacts(rendered, tmp_path):
    """Artifact modification is caught before any remote operation."""
    directory = tmp_path / "scenario"
    publish(directory, rendered[0])
    assert controller.load_scenario(directory)["dut_config.json"] == {"PORT": {}}
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "dut_config.json").stat().st_mode & 0o777 == 0o600
    (directory / "dut_config.json").write_text("{}")
    with pytest.raises(ValueError, match="artifact changed"):
        controller.load_scenario(directory)


@pytest.mark.parametrize("exclude_managed_acls,acknowledge", [
    (False, True), (True, True), (True, False),
])
def test_render_publishes_complete_private_configs_and_actual_port_order(
        rendered, tmp_path, monkeypatch, exclude_managed_acls, acknowledge):
    """The atomic output is digest-verifiable and includes protected ports in DUT indexing."""
    artifacts, testbed = rendered
    artifacts.pop("dut_config.json")
    artifacts.pop("leaf_config.json")
    artifacts["manifest.json"]["peer_hostname"] = "leaf"
    artifacts["topology.yml"] = {"generic_topology": {
        "physical_links": {"uplinks": ["Ethernet1", "Ethernet999"]},
    }, "topology": {}}
    artifacts["manifest.json"]["policy"] = {"min_same_breakout_uplinks": 1}
    artifacts["resolved_facts.json"]["connections"] = [
        {"dut": {"port": "Ethernet1"}, "role": "uplink", "ptf_index": 0},
        {"dut": {"port": "Ethernet8"}, "role": "downlink", "ptf_index": 1}]
    facts = artifacts["resolved_facts.json"]
    facts["hostname"] = "dut"
    layouts = {"dut": {}, "peer": {}}
    for link in facts["connections"]:
        link["dut"].update(speed=100000, atoms=[link["dut"]["port"]])
        link["peer"] = deepcopy(link["dut"])
        link["buffer_case"] = {"speed": "100000"}
        for side in layouts:
            layouts[side][link[side]["port"]] = {
                "mode": "1x100G", "speed": 100000, "children": [deepcopy(link[side])]}
    artifacts["manifest.json"]["selected_layouts"] = layouts

    def run(args, name, variables, local):
        for role in ("dut", "peer"):
            request = json.loads((local / (role + "-request.json")).read_text())
            assert request["layouts"] == layouts
            assert request["exclude_managed_acls"] is exclude_managed_acls
            assert "enable_lossless_adapter" not in request
            report = deepcopy(artifacts["render_report.json"][role])
            if acknowledge:
                report["exclude_managed_acls"] = exclude_managed_acls
            renderer.write_private(local / (role + "-response.json"), {
                "config": {"PORT": {"Ethernet8": {}, "Ethernet0": {}, "Ethernet1": {}}},
                "report": report,
            })

    monkeypatch.setattr(controller, "run_playbook", run)
    destination = tmp_path / "rendered"
    args = Namespace(output_dir=str(destination), exclude_managed_acls=exclude_managed_acls)
    if not acknowledge:
        with pytest.raises(ValueError, match="did not confirm managed ACL exclusion"):
            controller.render(args, artifacts, testbed, "dut")
        assert not destination.exists()
        return
    controller.render(args, artifacts, testbed, "dut")
    result = controller.load_scenario(destination)
    assert result["manifest.json"]["deployable"]
    assert result["manifest.json"]["requires_explicit_apply"]
    assert result["manifest.json"]["policy"]["exclude_managed_acls"] is exclude_managed_acls
    assert "enable_lossless_adapter" not in result["manifest.json"]["policy"]
    assert "dut_config.json" in result and "leaf_config.json" in result
    assert result["resolved_facts.json"]["dut_port_order"] == ["Ethernet0", "Ethernet1", "Ethernet8"]
    assert result["topology.yml"]["topology"]["host_interfaces"] == ["0.1@0", "0.2@1"]
    assert destination.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir())
    with pytest.raises(ValueError, match="already exists"):
        controller.render(args, artifacts, testbed, "dut")


@pytest.mark.parametrize("action", ["finalize", "deploy-mg"])
def test_render_policies_cannot_be_changed_outside_render(monkeypatch, capsys, action):
    """Deployment must consume sealed render policies rather than silently changing their scope."""
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: pytest.fail("Unexpected inventory access"))
    monkeypatch.setattr(sys, "argv", [
        "generic_topology_cli.py", action, "--testbed", "tb", "--testbed-file", "unused",
        "--exclude-managed-acls"])
    with pytest.raises(SystemExit):
        controller.main()
    assert "render-only option" in capsys.readouterr().err


def test_removed_lossless_override_is_rejected_before_inventory_access(monkeypatch, capsys):
    """The old flag cannot silently enable a policy no longer supported by preparation."""
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: pytest.fail("Unexpected inventory access"))
    monkeypatch.setattr(sys, "argv", [
        "generic_topology_cli.py", "render", "--testbed", "tb", "--testbed-file", "unused",
        "--enable-lossless-adapter"])
    with pytest.raises(SystemExit):
        controller.main()
    assert "unrecognized arguments: --enable-lossless-adapter" in capsys.readouterr().err


@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize("source", ["manifest", "report"])
def test_old_override_artifacts_cannot_be_deployed_but_remain_recoverable(rendered, monkeypatch, apply, source):
    """Do not accidentally deploy old sealed lossless proposals when switching to installed policy."""
    artifacts, testbed = rendered
    if source == "manifest":
        artifacts["manifest.json"]["policy"] = {"enable_lossless_adapter": True}
    else:
        artifacts["render_report.json"]["dut"]["enable_lossless_adapter"] = True
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected device access"))
    with pytest.raises(ValueError, match="removed lossless override"):
        controller.deploy(Namespace(action="deploy-mg", apply=apply), artifacts, testbed, "dut")
    controller.deploy(Namespace(action="recover", apply=False), artifacts, testbed, "dut")


@pytest.mark.parametrize("failure", ["legacy", "mismatched_role", "duplicate_child"])
def test_render_rejects_stale_or_conflicting_roles_before_device_access(rendered, tmp_path, monkeypatch, failure):
    """Rendering cannot consume old implicit roles or inconsistent new role assignments."""
    artifacts, testbed = rendered
    artifacts["topology.yml"] = {"generic_topology": {
        "physical_links": {"uplinks": ["Ethernet1"], "downlinks": ["Ethernet8"]},
    }}
    connections = [{"dut": {"port": "Ethernet1"}, "role": "uplink"},
                   {"dut": {"port": "Ethernet8"}, "role": "downlink"}]
    artifacts["resolved_facts.json"]["connections"] = connections
    if failure == "legacy":
        artifacts["topology.yml"]["generic_topology"] = {}
    elif failure == "mismatched_role":
        connections[0]["role"] = "downlink"
    else:
        connections.append(deepcopy(connections[0]))
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected device access"))
    destination = tmp_path / "rendered"
    with pytest.raises(ValueError, match="uplinks must be|roles do not match"):
        controller.render(Namespace(output_dir=str(destination)), artifacts, testbed, "dut")
    assert not destination.exists()


@pytest.mark.parametrize("topology", ["generic", "generic-1", "t0"])
def test_real_bash_dispatch_is_local_only(rendered, tmp_path, topology):
    """Exercise all real Bash generic commands without inventory, vault, or Ansible."""
    artifacts, testbed = rendered
    testbed["topo"] = topology
    directory = tmp_path / "rendered scenario"
    publish(directory, artifacts)
    testbed_file = tmp_path / "testbed.yml"
    testbed_file.write_text(yaml.safe_dump([dict(testbed, dut=["dut"])]))
    # The production resolver records extra testbed keys/digest; match that exact identity.
    _, resolved = controller.resolve_testbed(testbed_file, "tb")
    artifacts["manifest.json"]["testbed"] = resolved
    for name in directory.iterdir():
        name.unlink()
    directory.rmdir()
    publish(directory, artifacts)
    for action, positional in [
        ("add-topo", ["tb", "not-a-real-vault"]),
        ("remove-topo", ["tb", "not-a-real-vault"]),
        ("deploy-mg", ["tb", "not-a-real-inventory", "not-a-real-vault"]),
        ("recover-generic", ["tb", "not-a-real-inventory", "not-a-real-vault"]),
    ]:
        selector = [] if action == "recover-generic" else ["--generic"]
        completed = subprocess.run(
            ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed_file), action]
            + positional + selector + ["--scenario-dir", str(directory)],
            capture_output=True, text=True, cwd=SCRIPTS.parent)
        assert completed.returncode == 0, completed.stderr
        assert "DRY RUN" in completed.stdout
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed_file),
         "deploy-mg", "tb", "not-a-real-inventory", "not-a-real-vault", "--generic"],
        capture_output=True, text=True, cwd=SCRIPTS.parent, env=dict(os.environ, TMPDIR=str(tmp_path)))
    assert completed.returncode != 0
    assert "Required scenario stage is missing" in completed.stderr
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    publish(workspace / "rendered", artifacts)
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed_file),
         "deploy-mg", "tb", "not-a-real-inventory", "not-a-real-vault", "--workspace", str(workspace), "--generic"],
        capture_output=True, text=True, cwd=SCRIPTS.parent)
    assert completed.returncode == 0, completed.stderr
    assert "DRY RUN" in completed.stdout


@pytest.fixture
def lifecycle_cli(tmp_path, monkeypatch):
    """Isolate named topology recipes without modifying the checkout."""
    root = tmp_path / "ansible demo"
    root.mkdir()
    cli = root / "testbed-cli.sh"
    shutil.copyfile(SCRIPTS.parent / "testbed-cli.sh", cli)
    (root / "scripts").symlink_to(SCRIPTS, target_is_directory=True)
    (root / "vars").mkdir()
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text('#!/bin/sh\necho "Unexpected Ansible invocation" >&2\nexit 1\n')
    playbook.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return cli


@pytest.mark.parametrize("action", ["add-topo", "remove-topo"])
@pytest.mark.parametrize("topology", ["generic_a", "lab-mix"])
@pytest.mark.parametrize("extension", ["yaml", "csv"])
def test_host_lifecycle_detects_generic_recipe(rendered, tmp_path, lifecycle_cli, action, topology, extension):
    """Named generic recipes select the guarded dry-run lifecycle without a flag."""
    artifacts, testbed = rendered
    testbed_file = tmp_path / ("testbed." + extension)
    if extension == "csv":
        testbed_file.write_text(
            "#conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,inv_name\n"
            "tb,vms1,{},docker-ptf,ptf,192.0.2.1/24,,server,VM0000,[dut],inventory\n".format(topology))
    else:
        testbed_file.write_text(yaml.safe_dump([dict(testbed, topo=topology, dut=["dut"])]))
    recipe = lifecycle_cli.parent / "vars" / ("topo_" + topology + ".yml")
    recipe.write_text((SCRIPTS.parent / "vars/topo_generic.yml").read_text())
    _, artifacts["manifest.json"]["testbed"] = controller.resolve_testbed(testbed_file, "tb")
    directory = tmp_path / "rendered"
    publish(directory, artifacts)
    completed = subprocess.run(
        ["bash", str(lifecycle_cli), "-t", str(testbed_file), action, "tb", "vault",
         "--scenario-dir", str(directory)],
        capture_output=True, text=True, cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert "DRY RUN: " + action in completed.stdout
    assert "No devices or host infrastructure contacted" in completed.stdout


def test_host_lifecycle_preparation_uses_named_recipe(tmp_path, lifecycle_cli):
    """Automatic add-topo preparation receives the recipe that selected its lifecycle."""
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([{
        "conf-name": "tb", "topo": "lab_mix", "dut": ["dut"], "inv_name": "inventory",
    }]))
    recipe = lifecycle_cli.parent / "vars/topo_lab_mix.yml"
    recipe.write_text((SCRIPTS.parent / "vars/topo_generic.yml").read_text())
    python = tmp_path / "python3"
    python.write_text(
        "#!" + sys.executable + "\nimport json, os, sys\n"
        "if sys.argv[1].endswith('generic_topology_cli.py'):\n"
        "    print(json.dumps(sys.argv[2:]))\n"
        "else:\n"
        "    os.execv(sys.executable, [sys.executable] + sys.argv[1:])\n")
    python.chmod(0o700)
    completed = subprocess.run(
        ["bash", str(lifecycle_cli), "-t", str(testbed_file), "add-topo", "tb", "vault",
         "--peer-hostname", "leaf", "--links-csv", "links.csv"],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"]))
    assert completed.returncode == 0, completed.stderr
    arguments = json.loads(completed.stdout)
    assert arguments[0] == "add-topo"
    assert arguments[arguments.index("--recipe") + 1] == str(recipe)


@pytest.mark.parametrize("action", ["add-topo", "remove-topo"])
def test_host_lifecycle_without_generic_recipe_uses_legacy(tmp_path, lifecycle_cli, action):
    """A generic-looking name without a generic recipe retains traditional host behavior."""
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([{
        "conf-name": "tb", "group-name": "vms1", "topo": "generic_b",
        "dut": ["dut", "other"], "server": "server", "inv_name": "inventory",
    }]))
    (lifecycle_cli.parent / "vars/topo_generic_b.yml").write_text("topology: {}\n")
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    playbook.chmod(0o700)
    completed = subprocess.run(
        ["bash", str(lifecycle_cli), "-t", str(testbed_file), action, "tb", "vault"],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"]))
    assert completed.returncode == 0, completed.stderr
    expected = "testbed_{}_vm_topology.yml".format("add" if action == "add-topo" else "remove")
    assert expected in completed.stdout
    assert "generic_host.yml" not in completed.stdout


@pytest.mark.parametrize("content", [None, "[invalid", "[]", "generic_topology: null"])
def test_host_lifecycle_rejects_invalid_recipe_before_mutation(tmp_path, lifecycle_cli, content):
    """Missing or malformed recipe files never fall through into a mutating legacy path."""
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([{"conf-name": "tb", "topo": "lab_mix"}]))
    if content is not None:
        (lifecycle_cli.parent / "vars/topo_lab_mix.yml").write_text(content)
    completed = subprocess.run(
        ["bash", str(lifecycle_cli), "-t", str(testbed_file), "remove-topo", "tb", "vault"],
        capture_output=True, text=True, cwd=tmp_path)
    assert completed.returncode != 0
    assert "Cannot resolve topology lifecycle" in completed.stderr
    assert "Removing topology" not in completed.stdout


@pytest.mark.parametrize("action", ["add-topo", "remove-topo", "deploy-mg"])
@pytest.mark.parametrize("option", ["--apply", "--workspace=unused", "--scenario-dir=unused", "--finalize-roles"])
def test_non_generic_commands_reject_generic_options(tmp_path, lifecycle_cli, action, option):
    """Generic-only options must not leak into the traditional mutation path."""
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([{"conf-name": "tb", "topo": "t0"}]))
    (lifecycle_cli.parent / "vars/topo_t0.yml").write_text("topology: {}\n")
    completed = subprocess.run(
        ["bash", str(lifecycle_cli), "-t", str(testbed_file),
         action, "tb", "inventory", "vault", option], capture_output=True, text=True, cwd=tmp_path)
    assert completed.returncode != 0
    assert "--generic is required" in completed.stderr


@pytest.mark.parametrize("absolute_inventory", [False, True])
def test_generic_host_dispatch_resolves_inventory_paths(rendered, tmp_path, absolute_inventory):
    """Host actions preserve absolute inventory paths and resolve relative ones beside the testbed."""
    artifacts, testbed = rendered
    inventory = tmp_path / "inventory"
    inventory.write_text("[all]\naudit-host\n")
    testbed["inv_name"] = str(inventory) if absolute_inventory else inventory.name
    testbed_file = tmp_path / "testbed.yaml"
    testbed_file.write_text(yaml.safe_dump([dict(testbed, dut=["dut"])]))
    _, artifacts["manifest.json"]["testbed"] = controller.resolve_testbed(testbed_file, "tb")
    directory = tmp_path / "rendered"
    publish(directory, artifacts)
    vault = tmp_path / "vault"
    vault.write_text("synthetic-test-value\n")
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit 1\n')
    playbook.chmod(0o700)
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed_file), "-m", str(inventory),
         "add-topo", "tb", str(vault), "--generic", "--apply", "--scenario-dir", str(directory)],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"]))
    assert completed.returncode != 0
    assert completed.stdout.splitlines().count(str(inventory)) == 2
    assert "generic_host.yml failed" in completed.stderr


def test_generic_host_dispatch_rejects_missing_inventory_before_controller(tmp_path):
    """An invalid testbed inventory cannot silently fall through into automatic preparation."""
    testbed = tmp_path / "testbed.yaml"
    testbed.write_text(yaml.safe_dump([{"conf-name": "tb", "dut": ["dut"]}]))
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed),
         "add-topo", "tb", "vault", "--generic"], capture_output=True, text=True, cwd=tmp_path)
    assert completed.returncode != 0
    assert "Generic workspace:" not in completed.stdout


@pytest.mark.parametrize("selector,members,eligible,expected,inventory_mtu", [
    ("test_servers", ["host-a"], ["host-a"], "host-a", None),
    ("host-a", [], ["host-a"], "host-a", 9000),
    ("test_servers", ["host-a", "host-b"], ["host-a"], "host-a", None),
    ("test_servers", ["host-a", "host-b"], ["host-a", "host-b"], None, None),
    ("test_servers", [], ["host-a"], None, None),
    ("missing", ["host-a"], ["host-a"], None, None),
    ("host-b", ["host-a"], ["host-a"], None, None),
    ("test_servers", ["outside"], ["outside"], None, None),
])
def test_generic_host_resolution_uses_unique_group_intersection(
        tmp_path, selector, members, eligible, expected, inventory_mtu):
    """Resolve targets and MTU locally; ambiguous or ineligible selections cannot reach a remote host."""
    ansible = shutil.which("ansible-playbook")
    if ansible is None:
        pytest.skip("Inventory-resolution regression requires the existing Ansible CLI")
    inventory = tmp_path / "inventory.yml"
    variables = {"ansible_connection": "local"}
    if inventory_mtu is not None:
        variables["fp_mtu_size"] = inventory_mtu
    inventory.write_text(yaml.safe_dump({"all": {
        "hosts": {"localhost": {}}, "vars": variables, "children": {
            "servers": {"hosts": {"host-a": {}, "host-b": {}}},
            "vm_host": {"hosts": {name: {} for name in eligible}},
            "test_servers": {"hosts": {name: {} for name in members}},
        }}}))
    playbook = tmp_path / "generic_host.yml"
    plays = yaml.safe_load((SCRIPTS.parent / "generic_host.yml").read_text())
    role_variables = SCRIPTS.parent / "roles/vm_set/vars/main.yml"
    role_copy = tmp_path / "roles/vm_set/vars/main.yml"
    role_copy.parent.mkdir(parents=True)
    role_copy.write_text(role_variables.read_text())
    expected_mtu = inventory_mtu or yaml.safe_load(role_variables.read_text())["fp_mtu_size"]
    plays[1]["post_tasks"] = [{"name": "Verify resolved target and MTU", "assert": {
        "that": ["inventory_hostname == " + json.dumps(expected),
                 "fp_mtu_size | int == " + str(expected_mtu)]}, "tags": "generic_host_resolution"}]
    playbook.write_text(yaml.safe_dump(plays))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nstdout_callback = default\nretry_files_enabled = False\n")
    result = subprocess.run(
        [ansible, "-i", str(inventory), str(playbook), "--tags", "generic_host_resolution",
         "--limit", selector + ",localhost", "--extra-vars", json.dumps({"generic_testbed": {"server": selector}})],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOG_PATH=os.devnull,
                 ANSIBLE_DEBUG="0", ANSIBLE_VERBOSITY="0",
                 ANSIBLE_LIBRARY=os.pathsep.join([
                     str(SCRIPTS.parent / "library"), str(SCRIPTS.parent / "roles/vm_set/library")]),
                 ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible")))
    if expected:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Resolved generic VM host: " + expected in result.stdout
        assert "unreachable=1" not in result.stdout
    else:
        assert result.returncode != 0, result.stdout + result.stderr
        assert "must resolve to exactly one host" in result.stdout
        assert "Read PTF data-interface ownership" not in result.stdout


@pytest.mark.parametrize("topology", ["t0", "generic", "generic-1"])
@pytest.mark.parametrize("extension", ["csv", "yaml"])
def test_deploy_without_generic_selector_uses_legacy_playbook(tmp_path, topology, extension):
    """A topology name alone never selects the generic deployment workflow."""
    testbed = tmp_path / ("testbed." + extension)
    if extension == "csv":
        testbed.write_text("tb,vms1,{},docker-ptf,ptf,192.0.2.1/24,,server,VM0000,[dut],inventory\n".format(topology))
    else:
        testbed.write_text(yaml.safe_dump([{
            "conf-name": "tb", "group-name": "vms1", "topo": topology,
            "dut": ["dut"], "server": "server", "inv_name": "inventory",
        }]))
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    playbook.chmod(0o700)
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), "-t", str(testbed),
         "deploy-mg", "tb", "inventory", "vault"], capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"]))
    assert completed.returncode == 0, completed.stderr
    assert "config_sonic_basedon_testbed.yml" in completed.stdout
    assert "generic_devices.yml" not in completed.stdout


def test_rollback_without_reload_does_not_require_running_database(tmp_path, monkeypatch, capsys):
    """Recovery must not read a possibly broken CONFIG_DB before considering its backups."""
    config = {"PORT": {}}
    renderer.write_private(tmp_path / "request.json", {
        "config": config, "report": {"config_sha256": renderer.digest(config)}})
    monkeypatch.setattr(device, "read_running", lambda: pytest.fail("Read unavailable database"))
    device.run("rollback", tmp_path)
    assert "leaving its configuration untouched" in capsys.readouterr().out


@pytest.mark.parametrize("reason", [
    "System is not up. Retry later or use -f to avoid system checks",
    "SwSS container is not ready. Retry later or use -f to avoid system checks",
])
def test_reload_waits_only_for_explicit_readiness_rejections(monkeypatch, reason):
    """A pre-mutation rejection can be retried without bypassing SONiC system checks."""
    calls, sleeps = [], []

    def command(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            raise subprocess.CalledProcessError(
                1, argv, output="Acquired lock\n" + reason + "\nReleased lock\n")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(device.subprocess, "run", command)
    monkeypatch.setattr(device.time, "sleep", sleeps.append)
    device.reload_config(Path("/private/running-backup.json"))
    assert calls == [["config", "reload", "-y", "/private/running-backup.json"]] * 2
    assert sleeps == [5]


def test_reload_readiness_timeout_retains_failure_output(monkeypatch, capsys):
    """An unhealthy device must fail within the retry budget, retaining private diagnostics."""
    ticks = iter([0, 0, 301])
    calls, sleeps = [], []
    reason = "SwSS container is not ready. Retry later or use -f to avoid system checks\n"

    def command(argv, **kwargs):
        calls.append(argv)
        raise subprocess.CalledProcessError(1, argv, output=reason, stderr="readiness detail\n")

    monkeypatch.setattr(device.subprocess, "run", command)
    monkeypatch.setattr(device.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(device.time, "sleep", sleeps.append)
    with pytest.raises(subprocess.CalledProcessError):
        device.reload_config(Path("/private/running-backup.json"))
    assert len(calls) == 2 and sleeps == [5]
    output = capsys.readouterr()
    assert output.out == reason and output.err == "readiness detail\n"


@pytest.mark.parametrize("rc,output", [
    (1, "Reload failed after writing CONFIG_DB"),
    (1, "Unable to acquire lock"),
    (2, "SwSS container is not ready. Retry later or use -f to avoid system checks"),
    (1, None),
])
def test_reload_does_not_retry_other_failures(monkeypatch, rc, output):
    """Do not repeat a possibly partial reload or treat arbitrary errors as readiness races."""
    failure = subprocess.CalledProcessError(rc, ["config", "reload"], output=output)

    def command(*args, **kwargs):
        raise failure

    monkeypatch.setattr(device.subprocess, "run", command)
    monkeypatch.setattr(device.time, "sleep", lambda seconds: pytest.fail("Unexpected retry"))
    with pytest.raises(subprocess.CalledProcessError) as caught:
        device.reload_config(Path("/private/running-backup.json"))
    assert caught.value is failure


@pytest.mark.parametrize("rc", [0, 7])
def test_async_reload_failure_reports_private_job_without_output(tmp_path, rc):
    """Poll private completed jobs locally without starting reloads or revealing command output."""
    ansible = shutil.which("ansible-playbook")
    if ansible is None:
        pytest.skip("Async-result regression requires the existing Ansible CLI")
    plays = yaml.safe_load((SCRIPTS.parent / "generic_devices.yml").read_text())
    tasks = [task for task in plays[1]["tasks"][-1]["block"]
             if task["name"] in ("Wait for the private reload result", "Require the reload action itself to succeed")]
    tasks[0].update(delay=0, retries=20)
    async_directory = tmp_path / "async"
    async_directory.mkdir(mode=0o700)
    renderer.write_private(async_directory / "synthetic-job", {
        "rc": rc, "failed": bool(rc), "stdout": "PRIVATE-RELOAD-OUTPUT", "stderr": "",
    })
    playbook = tmp_path / "async.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"generic_action": "apply", "generic_device_dir": "/private/test-backups",
                 "ansible_async_dir": str(async_directory), "ansible_remote_tmp": str(tmp_path / "remote"),
                 "generic_reload_job": {"ansible_job_id": "synthetic-job"}},
        "tasks": tasks,
    }]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nstdout_callback = default\nretry_files_enabled = False\n")
    result = subprocess.run(
        [ansible, "-i", "localhost,", str(playbook)], capture_output=True, text=True, cwd=tmp_path,
        timeout=60,
        env=dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_LOG_PATH=os.devnull,
                 ANSIBLE_DEBUG="0", ANSIBLE_VERBOSITY="0", ANSIBLE_LOCAL_TEMP=str(tmp_path / "local")))
    assert (result.returncode == 0) == (rc == 0), result.stdout + result.stderr
    assert "PRIVATE-RELOAD-OUTPUT" not in result.stdout + result.stderr
    if rc:
        assert "rc=7" in result.stdout
        assert "/private/test-backups" in result.stdout and "private async job" in result.stdout


def test_stage_drift_guards_and_saved_startup_readback(tmp_path, monkeypatch):
    """Stage preserves backups, apply refuses drift, and save verifies the persisted artifact."""
    base = {"PORT": {}}
    config = {"PORT": {}, "DEVICE_METADATA": {"localhost": {"hostname": "new"}}}
    startup = tmp_path / "original-startup.json"
    startup.write_text(json.dumps(base))
    report = {"baseline_sha256": renderer.digest(base), "config_sha256": renderer.digest(config),
              "assets": {}, "retired_ports": []}
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    monkeypatch.setattr(device, "Path", lambda path: (
        startup if str(path) == "/etc/sonic/config_db.json" else Path(path)))
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(base))
    device.run("stage", tmp_path)
    assert json.loads((tmp_path / "running-backup.json").read_text()) == base
    assert (tmp_path / "startup-backup.json").read_bytes() == startup.read_bytes()
    assert (tmp_path / "startup-backup.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        device.run("stage", tmp_path)
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(config))
    monkeypatch.setattr(device.subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="changed after staging"):
        device.run("apply", tmp_path)
    assert not (tmp_path / "reload-attempted.json").exists()
    device.run("verify", tmp_path)
    with pytest.raises(ValueError, match="Saved startup configuration differs"):
        device.run("save", tmp_path)
    startup.write_text(json.dumps(config))
    device.run("save", tmp_path)


@pytest.mark.parametrize("acl", ["DATAACL", "EVERFLOW"])
def test_acl_membership_follows_lane_overlap_including_old_lag(layout, acl):
    """Children inherit effective membership, including an old owned LAG, without changing protected ports."""
    base = layout[0]
    base["ACL_TABLE"][acl] = {"ports": ["PortChannel1", "Ethernet8"]}
    config, _, _ = renderer.build_ports(*layout)
    assert set(config["ACL_TABLE"][acl]["ports"]) == {"Ethernet0", "Ethernet1", "Ethernet8"}
    assert base["ACL_TABLE"][acl]["ports"] == ["PortChannel1", "Ethernet8"]


@pytest.mark.parametrize("same_memberships", [False, True])
def test_aggregation_requires_identical_acl_membership(layout, same_memberships):
    """An aggregate cannot hide disagreement between the old physical links' ACL memberships."""
    base, platform, _, _ = layout
    base["PORT"]["Ethernet0"]["lanes"] = "1"
    base["PORT"]["Ethernet1"] = {"lanes": "2", "speed": "100000"}
    base["ACL_TABLE"]["DATAACL"] = {"ports": ["Ethernet0"] + (["Ethernet1"] if same_memberships else [])}
    choice = {"Ethernet0": {"speed": 200000, "mode": "1x200G", "children": [
        {"port": "Ethernet0", "lanes": [1, 2], "alias": "aggregate"}]}}

    def canonical(*args):
        return {"Ethernet0": {"speed": "200000", "lanes": "1,2", "alias": "aggregate"}}

    if same_memberships:
        config, _, _ = renderer.build_ports(base, platform, choice, canonical)
        assert config["ACL_TABLE"]["DATAACL"]["ports"] == ["Ethernet0"]
    else:
        original = deepcopy(base)
        with pytest.raises(ValueError, match="Ethernet0=\\[DATAACL\\]; Ethernet1=\\[none\\]"):
            renderer.build_ports(base, platform, choice, canonical)
        assert base == original


@pytest.mark.parametrize("protected_member,references_retired_port", [(True, False), (False, False), (True, True)])
def test_explicit_acl_exclusion_preserves_protected_bindings_and_rules(
        layout, protected_member, references_retired_port):
    """Omit managed ACL inheritance without broadening policy or dropping protected/control-plane state."""
    base, platform, _, _ = layout
    base["PORT"]["Ethernet0"]["lanes"] = "1"
    base["PORT"]["Ethernet1"] = {"lanes": "2", "speed": "100000"}
    base["ACL_TABLE"] = {
        "DATAACL": {"type": "L3", "ports": ["PortChannel1"] + (["Ethernet8"] if protected_member else [])},
        "EVERFLOW": {"type": "MIRROR", "ports": ["Ethernet1"] + (["Ethernet8"] if protected_member else [])},
        "SSH_ONLY": {"type": "CTRLPLANE", "services": ["SSH"]},
    }
    base["ACL_RULE"] = {
        "DATAACL|rule": {"PACKET_ACTION": "DROP", "SRC_IP": "203.0.113.1/32"},
        "SSH_ONLY|rule": {"PACKET_ACTION": "ACCEPT", "SRC_IP": "192.0.2.0/24"},
    }
    if references_retired_port:
        base["ACL_RULE"]["DATAACL|rule"]["IN_PORTS"] = "Ethernet0"
    original = deepcopy(base)
    choice = {"Ethernet0": {"speed": 200000, "mode": "1x200G", "children": [
        {"port": "Ethernet0", "lanes": [1, 2], "alias": "aggregate"}]}}

    def canonical(*args):
        return {"Ethernet0": {"speed": "200000", "lanes": "1,2", "alias": "aggregate"}}

    if references_retired_port:
        with pytest.raises(ValueError, match="retired port"):
            renderer.build_ports(base, platform, choice, canonical, exclude_managed_acls=True)
    else:
        config, _, _ = renderer.build_ports(base, platform, choice, canonical, exclude_managed_acls=True)
        for name in ("DATAACL", "EVERFLOW"):
            expected = dict(original["ACL_TABLE"][name], ports=["Ethernet8"] if protected_member else [])
            assert config["ACL_TABLE"][name] == expected
        assert config["ACL_TABLE"]["SSH_ONLY"] == original["ACL_TABLE"]["SSH_ONLY"]
        assert config["ACL_RULE"] == original["ACL_RULE"]
        assert config["MGMT_INTERFACE"] == original["MGMT_INTERFACE"]
        assert config["PORT"]["Ethernet8"] == original["PORT"]["Ethernet8"]
    assert base == original


@pytest.fixture
def shared_qos_source():
    """Synthetic shared template using only role lists, with no vendor macro-name dependency."""
    return """
{%- set PORT_UPLINK = [] %}
{%- set PORT_DOWNLINK = [] %}
{%- if DEVICE_METADATA is defined %}
  {%- if PORT_UPLINK.append('wrong-uplink') %}{% endif %}
  {%- if PORT_DOWNLINK.append('wrong-downlink') %}{% endif %}
{%- endif %}
{%- set names = PORT_UPLINK + PORT_DOWNLINK %}
{"PORT_QOS_MAP": {
{% for port in names %}
  "{{ port }}": {"direction": "{{ 'uplink' if port in PORT_UPLINK else 'downlink' }}"}
  {% if not loop.last %},{% endif %}
{% endfor %}
}}
"""


def test_temporary_qos_adapter_uses_explicit_roles_without_macro_api(shared_qos_source):
    """Replace classification only; preserve real metadata and arbitrary installed policy output."""
    from jinja2 import Environment

    context = {"DEVICE_METADATA": {"localhost": {"type": "actual-type"}},
               "GENERIC_UPLINK_PORTS": ["Ethernet0"], "GENERIC_DOWNLINK_PORTS": ["Ethernet1"]}
    original = deepcopy(context)
    result = json.loads(Environment().from_string(renderer.direction_template(shared_qos_source)).render(context))
    assert result == {"PORT_QOS_MAP": {"Ethernet0": {"direction": "uplink"}, "Ethernet1": {"direction": "downlink"}}}
    assert context == original


@pytest.mark.parametrize("change", ["missing_initializer", "missing_classifier", "inline_policy", "extra_output"])
def test_unknown_qos_template_contract_is_rejected(shared_qos_source, change):
    """Unsupported templates fail instead of guessing directions or policy values."""
    if change == "inline_policy":
        source = shared_qos_source.replace("{%- set PORT_UPLINK = [] %}", "{%- set PORT_UPLINK = [] %}policy")
    elif change == "extra_output":
        source = shared_qos_source.replace("{%- set names", "policy output\n{%- set names")
    else:
        source = shared_qos_source.replace(
            "{%- set PORT_UPLINK = [] %}" if change == "missing_initializer" else "PORT_UPLINK.append",
            "" if change == "missing_initializer" else "OTHER.append")
    with pytest.raises(ValueError, match="unrecognized direction contract|standalone empty-list"):
        renderer.direction_template(source)


def test_platform_qos_fallback_and_cfggen_search_precedence(shared_qos_source, tmp_path, monkeypatch):
    """The absolute temporary include beats cfggen's system-first loader; source files remain unchanged."""
    from jinja2 import Environment, FileSystemLoader

    platform, system, directory = (tmp_path / name for name in ("platform", "system", "render"))
    sku = platform / "sku"
    for path in (sku, system, directory):
        path.mkdir(parents=True)
    qos = platform / "qos.json.j2"
    qos.write_text("{% include 'qos_config.j2' %}")
    shared = system / "qos_config.j2"
    shared.write_text(shared_qos_source)
    collision = sku / "buffers.j2"
    collision.write_text("installed source must not be overwritten")
    before = {path: path.read_bytes() for path in (qos, shared, collision)}
    monkeypatch.setattr(renderer, "Path", lambda path: (
        shared if str(path) == "/usr/share/sonic/templates/qos_config.j2" else Path(path)))
    template, search = renderer.prepare_qos_template(directory, platform, sku)
    environment = Environment(loader=FileSystemLoader(["/", str(system), str(search), str(directory)]))
    result = json.loads(environment.get_template(template.name).render(
        DEVICE_METADATA={}, GENERIC_UPLINK_PORTS=["Ethernet0"], GENERIC_DOWNLINK_PORTS=["Ethernet1"]))
    assert set(result["PORT_QOS_MAP"]) == {"Ethernet0", "Ethernet1"}
    (directory / "buffers.j2").write_text("temporary wrapper")
    assert before == {path: path.read_bytes() for path in before}


@pytest.fixture
def alias_setup(tmp_path, monkeypatch):
    """A private fake device root; alias actions must never access the host's installed SONiC tree."""
    root = tmp_path / "device"
    platform = root / "test-platform"
    target = platform / "base"
    target.mkdir(parents=True)
    monkeypatch.setattr(device, "Path", lambda path: (
        root if str(path) == "/usr/share/sonic/device" else Path(path)))
    spec = renderer.generic_identity(platform, "base")
    config = {"DEVICE_METADATA": {"localhost": {"hwsku": "base_generic"}}}
    report = {"platform": "test-platform", "hwsku_alias": spec}
    return config, report, Path(spec["alias"]), target


def test_alias_is_apply_owned_and_recovery_removes_only_its_inode(alias_setup, tmp_path):
    """Read-only preflight creates nothing; apply journals ownership, and rollback deletes just its alias."""
    config, report, alias, target = alias_setup
    device.check_hwsku_alias(config, report)
    assert not alias.exists()
    device.create_hwsku_alias(config, report, tmp_path)
    assert alias.is_symlink() and alias.resolve() == target
    assert renderer.generic_identity(alias.parent, alias.name)["hwsku"] == "base_generic"
    device.check_hwsku_alias(config, report, require_present=True)
    device.remove_created_alias(tmp_path)
    assert not alias.exists() and target.is_dir()


def test_preexisting_alias_is_reused_and_never_deleted(alias_setup, tmp_path):
    """An existing correct sibling symlink belongs to its creator, not to this scenario."""
    config, report, alias, target = alias_setup
    alias.symlink_to(target)
    device.create_hwsku_alias(config, report, tmp_path)
    device.remove_created_alias(tmp_path)
    assert alias.is_symlink()
    assert not (tmp_path / "hwsku-alias-created.json").exists()


def test_conflicting_or_replaced_alias_is_not_overwritten_or_removed(alias_setup, tmp_path):
    """Reject path conflicts up front and replacement by another owner during recovery."""
    config, report, alias, _ = alias_setup
    alias.mkdir()
    with pytest.raises(ValueError, match="conflicts"):
        device.create_hwsku_alias(config, report, tmp_path)
    alias.rmdir()
    device.create_hwsku_alias(config, report, tmp_path)
    alias.unlink()
    alias.symlink_to("different-owner")
    with pytest.raises(ValueError, match="another owner's path"):
        device.remove_created_alias(tmp_path)
    assert alias.is_symlink()


def test_lookup_priority_change_after_render_is_rejected(alias_setup, tmp_path):
    """Adding a higher-priority platform lookup invalidates a previously selected SKU fallback."""
    _, report, _, target = alias_setup
    lookup = target / "pg_profile_lookup.ini"
    lookup.write_text("selected fallback")
    report.update(hwsku="base", lookup_path=str(lookup), assets={
        str(lookup): hashlib.sha256(lookup.read_bytes()).hexdigest()})
    device.check_render_assets(report)
    (target.parent / lookup.name).write_text("new platform lookup")
    with pytest.raises(ValueError, match="selection changed"):
        device.check_render_assets(report)


@pytest.mark.parametrize("fail_apply", [False, True])
def test_alias_apply_and_config_recovery_restore_original_identity(alias_setup, tmp_path, monkeypatch, fail_apply):
    """Recover both identity and startup bytes before removing the apply-owned alias, even on reload failure."""
    config, report, alias, target = alias_setup
    config["PORT"] = {}
    base = deepcopy(config)
    base["DEVICE_METADATA"]["localhost"]["hwsku"] = "base"
    running = deepcopy(base)
    startup = tmp_path / "startup.json"
    original_bytes = (json.dumps(base, indent=4) + "\n").encode()
    startup.write_bytes(original_bytes)
    report.update(config_sha256=renderer.digest(config), baseline_sha256=renderer.digest(base),
                  assets={}, retired_ports=[])
    renderer.write_private(tmp_path / "request.json", {"config": config, "report": report})
    original_path, replace, mkstemp = device.Path, device.os.replace, device.tempfile.mkstemp
    monkeypatch.setattr(device, "Path", lambda path: (
        startup if str(path) == "/etc/sonic/config_db.json" else original_path(path)))
    monkeypatch.setattr(device.os, "replace", lambda source, destination: replace(
        source, startup if str(destination) == "/etc/sonic/config_db.json" else destination))
    monkeypatch.setattr(device.tempfile, "mkstemp", lambda **kwargs: mkstemp(
        **dict(kwargs, dir=str(tmp_path))))
    monkeypatch.setattr(device, "read_running", lambda: deepcopy(running))

    def command(argv, **kwargs):
        nonlocal running
        if fail_apply and Path(argv[-1]).name == "new-config.json":
            raise subprocess.CalledProcessError(1, argv)
        running = json.loads(Path(argv[-1]).read_text())
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(device.subprocess, "run", command)
    device.run("stage", tmp_path)
    assert not alias.exists()
    if fail_apply:
        with pytest.raises(subprocess.CalledProcessError):
            device.run("apply", tmp_path)
    else:
        device.run("apply", tmp_path)
        assert running["DEVICE_METADATA"]["localhost"]["hwsku"] == "base_generic"
        device.run("verify", tmp_path)
    assert alias.is_symlink()
    startup.write_text("changed startup")
    device.run("rollback", tmp_path)
    assert running == base
    assert startup.read_bytes() == original_bytes
    assert not alias.is_symlink() and target.is_dir()
