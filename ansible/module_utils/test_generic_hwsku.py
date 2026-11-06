"""Offline tests; run pytest --noconftest ansible/module_utils/test_generic_hwsku.py."""

import copy
import importlib.util
import json
import os
import sys

import pytest


_PATH = os.path.join(os.path.dirname(__file__), "generic_hwsku.py")
_SPEC = importlib.util.spec_from_file_location("generic_hwsku", _PATH)
planner = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = planner
_SPEC.loader.exec_module(planner)


def _port(index, lanes, channels, speed):
    return {"name": "Ethernet{}".format(index), "alias": "port-{}".format(index), "index": index,
            "lanes": lanes, "channels": channels, "speed": speed, "fec": "rs", "autoneg": "off",
            "cables": ["5m", "10m"]}


def _snapshot(cage_count=3):
    devices = []
    for name in ("dut", "leaf"):
        cages = []
        for number in range(cage_count):
            base = number * 4
            lane_base = base + (100 if name == "leaf" else 0)
            cages.append({
                "name": "cage-{}".format(number), "group": "group-{}".format(number), "protected_reason": "",
                "modes": [
                    {"id": "single", "name": "1x400G", "group_mode": "independent",
                     "ports": [_port(base, list(range(lane_base, lane_base + 4)), [0, 1, 2, 3], 400000)]},
                    {"id": "quad", "name": "4x100G", "group_mode": "independent",
                     "ports": [_port(base + channel, [lane_base + channel], [channel], 100000)
                               for channel in range(4)]},
                ],
            })
        devices.append({"name": name, "platform": "synthetic-platform", "base_hwsku": "Synthetic-Base",
                        "realized_hwsku": "Synthetic-Scenario", "image": "synthetic-image", "asic_count": 1,
                        "dedicated": True, "port_capacity": 64, "headroom_capacity": 100000, "cages": cages})
    return {
        "schema_version": 1, "dut": "dut", "devices": devices,
        "links": [{"dut_cage": "cage-{}".format(number), "dut_channel": channel, "leaf": "leaf",
                   "leaf_cage": "cage-{}".format(number), "leaf_channel": channel, "excluded_reason": ""}
                  for number in range(cage_count) for channel in range(4)],
        "endpoints": [{"id": "endpoint-{}".format(number * 4 + channel), "leaf": "leaf",
                       "cage": "cage-{}".format(number), "channels": [channel],
                       "ptf_index": number * 4 + channel, "trunk": "reserved-trunk", "vlan": 200 + number * 4 + channel,
                       "host_interface": "eth{}".format(number * 4 + channel), "roles": ["access", "routed"]}
                      for number in range(cage_count) for channel in range(4)],
        "lookup": [{"speed": 100000, "cable": "5m", "headroom": 1000},
                   {"speed": 100000, "cable": "10m", "headroom": 1200},
                   {"speed": 400000, "cable": "5m", "headroom": 2000}],
        "supported_profiles": ["lossless"],
        "sources": {key: "a" * 64 for key in ("capabilities", "parser", "links", "lookup", "policy")},
    }


@pytest.fixture
def snapshot():
    return _snapshot()


@pytest.fixture
def settings():
    return {"min_subports": 1, "routed_ports": 1, "access_vlan": 100,
            "routed_network": "198.18.0.0/24", "access_network": "198.19.0.0/24",
            "profile": "lossless", "max_search_nodes": 20000}


def test_complete_plan_and_independent_roundtrip(snapshot, settings):
    """Cover every required mode/pair and replay real witnesses after JSON serialization."""
    manifest = planner.plan_scenario(snapshot, settings)
    planner.validate_manifest(json.loads(planner.canonical_json(manifest)), snapshot, settings)
    assert {(row["mode"], row["speed"]) for row in manifest["coverage"]["modes"]} == {
        ("1x400G", 400000), ("4x100G", 100000)}
    assert {(row["speed"], row["cable"]) for row in manifest["coverage"]["lookup"]} == {
        (100000, "5m"), (100000, "10m"), (400000, "5m")}
    assert all(row["ports"] for row in manifest["coverage"]["lookup"])
    endpoints = manifest["endpoints"]
    assert len({row["transport"]["ptf_index"] for row in endpoints}) == len(endpoints)
    assert sum(row["role"] == "routed" for row in endpoints) == 1
    paths = {(case["ingress"], case["egress"]) for case in manifest["traffic_cases"]}
    assert all(ingress != egress for ingress, egress in paths)
    assert {port for path in paths for port in path} == {row["dut_port"] for row in endpoints}


def test_input_order_and_setting_layer_independence(snapshot, settings):
    """Permuting unordered facts or equivalent overrides must not change any manifest byte."""
    expected = planner.canonical_json(planner.plan_scenario(snapshot, settings))
    for key in ("devices", "links", "endpoints", "lookup"):
        snapshot[key].reverse()
    for device in snapshot["devices"]:
        device["cages"].reverse()
        for cage in device["cages"]:
            cage["modes"].reverse()
            for mode in cage["modes"]:
                mode["ports"].reverse()
                for port in mode["ports"]:
                    port["cables"].reverse()
    for endpoint in snapshot["endpoints"]:
        endpoint["roles"].reverse()
    shared = dict(settings, min_subports=3, routed_ports=2)
    actual = planner.plan_scenario(snapshot, shared, {"min_subports": 2}, {"min_subports": 1, "routed_ports": 1})
    assert planner.canonical_json(actual) == expected


def test_inputs_are_not_mutated_or_retained(snapshot, settings):
    """Planning must neither mutate caller facts nor retain mutable input references."""
    original = copy.deepcopy(snapshot)
    original_settings = copy.deepcopy(settings)
    manifest = planner.plan_scenario(snapshot, settings)
    serialized = planner.canonical_json(manifest)
    assert snapshot == original
    assert settings == original_settings
    snapshot["devices"][0]["cages"][0]["modes"][0]["ports"][0]["lanes"].reverse()
    snapshot["sources"]["lookup"] = "b" * 64
    assert planner.canonical_json(manifest) == serialized


def test_n_counts_children_not_cages(settings):
    """One quad contributes four children, but an unsplit mode needs four separate cages."""
    snapshot = _snapshot(5)
    settings["min_subports"] = 4
    manifest = planner.plan_scenario(snapshot, settings)
    for coverage in manifest["coverage"]["modes"]:
        assert len(set(coverage["ports"])) >= 4
    wide = [entry for entry in manifest["layout"] if entry["device"] == "dut"
            and entry["expansion"]["name"] == "1x400G"]
    assert len(wide) >= 4


def test_mixed_and_alternate_modes(settings):
    """Mixed-mode children and alternate operating speeds keep their own coverage obligations."""
    snapshot = _snapshot(5)
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            wide = cage["modes"][0]
            wide["name"] = "1x400G[200G]"
            alternate = copy.deepcopy(wide)
            alternate["id"] = "alternate"
            alternate["ports"][0]["speed"] = 200000
            base = wide["ports"][0]["index"]
            lanes = wide["ports"][0]["lanes"]
            cage["modes"].extend([
                alternate,
                {"id": "mixed", "name": "1x200G(2)+2x100G(2)", "group_mode": "independent",
                 "ports": [_port(base, lanes[:2], [0, 1], 200000),
                           _port(base + 2, lanes[2:3], [2], 100000),
                           _port(base + 3, lanes[3:], [3], 100000)]},
            ])
    snapshot["lookup"].append({"speed": 200000, "cable": "5m", "headroom": 1500})
    manifest = planner.plan_scenario(snapshot, settings)
    coverage = {(row["mode"], row["speed"]): row["ports"] for row in manifest["coverage"]["modes"]}
    assert coverage[("1x400G[200G]", 200000)]
    assert coverage[("1x400G[200G]", 400000)]
    assert coverage[("1x200G(2)+2x100G(2)", 100000)]
    assert coverage[("1x200G(2)+2x100G(2)", 200000)]
    assert len(manifest["coverage"]["lookup"]) == 4


def test_physical_mapping_not_interface_arithmetic(snapshot, settings):
    """Reversed explicit wires map to the real peer, while canonical ASIC lane order is preserved."""
    for link in snapshot["links"]:
        link["leaf_channel"] = 3 - link["dut_channel"]
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            cage["modes"][0]["ports"][0]["lanes"].reverse()
    manifest = planner.plan_scenario(snapshot, settings)
    for endpoint in manifest["endpoints"]:
        if endpoint["speed"] == 100000:
            assert int(endpoint["dut_port"][8:]) % 4 + int(endpoint["leaf_port"][8:]) % 4 == 3
    wide = next(entry for entry in manifest["layout"]
                if entry["device"] == "dut" and entry["expansion"]["id"] == "single")
    assert wide["expansion"]["ports"][0]["lanes"] == sorted(wide["expansion"]["ports"][0]["lanes"], reverse=True)


def test_backtracks_transport_conflict(settings):
    """An early endpoint choice must be retried when it steals a later child's PTF resource."""
    snapshot = _snapshot(1)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    bad = dict(snapshot["endpoints"][0], id="aaa-conflicting", ptf_index=1)
    snapshot["endpoints"].append(bad)
    manifest = planner.plan_scenario(snapshot, settings)
    first = next(endpoint for endpoint in manifest["endpoints"] if endpoint["dut_port"] == "Ethernet0")
    assert first["transport"]["id"] == "endpoint-0"


def test_cable_assignment_backtracks_within_one_layout(settings):
    """Two cages must fit both modes and lookup pairs by assigning different cables to quad children."""
    manifest = planner.plan_scenario(_snapshot(2), settings)
    quad_cables = {endpoint["cable"] for endpoint in manifest["endpoints"] if endpoint["speed"] == 100000}
    assert quad_cables == {"5m", "10m"}
    assert len([row for row in manifest["layout"] if row["device"] == "dut"]) == 2


@pytest.mark.parametrize("routed_count, feasible", [(1, False), (3, True)])
def test_roles_and_address_capacity_are_search_constraints(settings, routed_count, feasible):
    """A /30 access pool has one PTF address; role allocation must fit it rather than silently overrun."""
    snapshot = _snapshot(1)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    settings.update(access_network="198.19.0.0/30", routed_ports=routed_count)
    if not feasible:
        with pytest.raises(planner.InfeasiblePlan):
            planner.plan_scenario(snapshot, settings)
    else:
        manifest = planner.plan_scenario(snapshot, settings)
        assert sum(row["role"] == "routed" for row in manifest["endpoints"]) == 3
        access = [row for row in manifest["endpoints"] if row["role"] == "access"]
        assert access[0]["dut_address"] == "198.19.0.1/30"
        assert access[0]["ptf_address"] == "198.19.0.2/30"


def test_endpoint_role_restrictions_are_respected(settings):
    """A constrained routed endpoint need not be the first port in the generated layout."""
    snapshot = _snapshot(1)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    for index, endpoint in enumerate(snapshot["endpoints"]):
        endpoint["roles"] = ["routed"] if index == 1 else ["access"]
    manifest = planner.plan_scenario(snapshot, settings)
    assert [row["dut_port"] for row in manifest["endpoints"] if row["role"] == "routed"] == ["Ethernet1"]


def test_protection_closes_over_cages_groups_and_wires(settings):
    """An excluded channel protects both complete cages and every connected shared group."""
    snapshot = _snapshot(4)
    snapshot["devices"][0]["cages"][0]["group"] = "shared"
    snapshot["devices"][0]["cages"][1]["group"] = "shared"
    snapshot["links"][0]["excluded_reason"] = "unreserved connection"
    manifest = planner.plan_scenario(snapshot, settings)
    assert all(entry["cage"] not in {"cage-0", "cage-1"} for entry in manifest["layout"])
    protected = {(row["device"], row["cage"]) for row in manifest["exclusions"] if row["kind"] == "cage"}
    assert protected == {("dut", "cage-0"), ("dut", "cage-1"), ("leaf", "cage-0"), ("leaf", "cage-1")}


def test_protected_only_capabilities_are_explained(snapshot, settings):
    """A speed available only on protected cages is recorded as excluded, not silently counted."""
    for device in snapshot["devices"]:
        cage = device["cages"][0]
        cage["protected_reason"] = "reserved elsewhere"
        alternate = copy.deepcopy(cage["modes"][0])
        alternate["id"], alternate["name"] = "protected-mode", "1x200G"
        alternate["ports"][0]["speed"] = 200000
        cage["modes"].append(alternate)
    snapshot["lookup"].append({"speed": 200000, "cable": "5m", "headroom": 1500})
    manifest = planner.plan_scenario(snapshot, settings)
    assert any(row["kind"] == "mode" and row["speed"] == 200000 for row in manifest["exclusions"])
    assert any(row["kind"] == "lookup" and row["speed"] == 200000 for row in manifest["exclusions"])
    assert all(row["speed"] != 200000 for row in manifest["coverage"]["modes"])


@pytest.mark.parametrize("resource", ["ptf_index", "host_interface", "vlan"])
def test_shared_transport_resources_cannot_be_double_counted(snapshot, settings, resource):
    """Distinct endpoint IDs do not authorize reuse of their underlying shared resources."""
    for endpoint in snapshot["endpoints"]:
        endpoint[resource] = snapshot["endpoints"][0][resource]
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", [
    "lane_peer", "fec", "autoneg", "port_capacity", "headroom", "role", "lookup", "shared_group",
])
def test_incompatible_or_insufficient_resources_fail(snapshot, settings, fault):
    """A required capability cannot become an exclusion merely because it does not fit."""
    if fault == "lane_peer":
        snapshot["links"] = [link for link in snapshot["links"] if link["dut_channel"] != 3]
    elif fault in ("fec", "autoneg"):
        for cage in snapshot["devices"][1]["cages"]:
            for mode in cage["modes"]:
                for port in mode["ports"]:
                    port[fault] = "incompatible"
    elif fault == "port_capacity":
        snapshot["devices"][0]["port_capacity"] = 2
    elif fault == "headroom":
        snapshot["devices"][1]["headroom_capacity"] = 0
    elif fault == "role":
        for endpoint in snapshot["endpoints"]:
            endpoint["roles"] = ["access"]
    elif fault == "lookup":
        snapshot["lookup"].append({"speed": 400000, "cable": "unsupported-length", "headroom": 2000})
    else:
        for device in snapshot["devices"]:
            for cage in device["cages"]:
                cage["group"] = "shared"
                for mode in cage["modes"]:
                    mode["group_mode"] = mode["id"]
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)


def test_search_exhaustion_is_not_infeasibility(snapshot, settings):
    """Budget exhaustion raises a distinct error instead of returning partial coverage."""
    settings["max_search_nodes"] = 1
    with pytest.raises(planner.SearchBudgetExceeded, match="feasibility is unknown"):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", ["profile", "platform", "reservation", "multi_asic", "missing_lookup"])
def test_missing_prerequisites_are_distinct(snapshot, settings, fault):
    """Unavailable platform policy and ownership are not reported as successful planning."""
    if fault == "profile":
        settings["profile"] = "unapproved"
    elif fault == "platform":
        snapshot["devices"][1]["platform"] = "different-platform"
    elif fault == "reservation":
        snapshot["devices"][1]["dedicated"] = False
    elif fault == "multi_asic":
        snapshot["devices"][0]["asic_count"] = 2
    else:
        snapshot["lookup"] = snapshot["lookup"][:2]
    with pytest.raises(planner.PrerequisiteError):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", [
    "duplicate_link", "duplicate_lane", "missing_setting", "bool_count",
    "bad_hash", "unknown_field", "overlapping_networks",
])
def test_malformed_contract_is_rejected(snapshot, settings, fault):
    """Reject ambiguous facts and invalid policy rather than guessing defaults."""
    if fault == "duplicate_link":
        snapshot["links"].append(copy.deepcopy(snapshot["links"][0]))
    elif fault == "duplicate_lane":
        port = snapshot["devices"][0]["cages"][0]["modes"][0]["ports"][0]
        port["lanes"].append(port["lanes"][0])
    elif fault == "missing_setting":
        del settings["min_subports"]
    elif fault == "bool_count":
        settings["min_subports"] = True
    elif fault == "bad_hash":
        snapshot["sources"]["parser"] = "unknown"
    elif fault == "unknown_field":
        snapshot["guess_lanes"] = True
    else:
        settings["access_network"] = settings["routed_network"]
    with pytest.raises(planner.InvalidInput):
        planner.plan_scenario(snapshot, settings)


def test_recorded_unsupported_lookup_needs_evidence(snapshot, settings):
    """An explicitly unsupported pair remains visible, separate from the required matrix."""
    snapshot["excluded_lookup"] = [{"speed": 800000, "cable": "5m", "reason": "not advertised by this platform",
                                    "evidence_sha256": "b" * 64}]
    manifest = planner.plan_scenario(snapshot, settings)
    assert any(row.get("evidence_sha256") == "b" * 64 for row in manifest["exclusions"])
    del snapshot["excluded_lookup"][0]["evidence_sha256"]
    with pytest.raises(planner.InvalidInput):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", [
    "coverage", "digest", "address", "source", "duplicate_endpoint",
    "missing_child", "unknown_expansion", "malformed", "boolean_version",
])
def test_independent_validation_rejects_modified_manifest(snapshot, settings, fault):
    """Replay physical/resource constraints and witnesses, rather than trusting a success bit or hash."""
    manifest = planner.plan_scenario(snapshot, settings)
    if fault == "coverage":
        manifest["coverage"]["modes"][0]["ports"] = []
    elif fault == "digest":
        manifest["integrity"]["layout_sha256"] = "f" * 64
    elif fault == "address":
        manifest["endpoints"][0]["ptf_address"] = "198.18.0.99/31"
    elif fault == "source":
        snapshot["sources"]["links"] = "c" * 64
    elif fault == "duplicate_endpoint":
        manifest["endpoints"][1]["transport"] = copy.deepcopy(manifest["endpoints"][0]["transport"])
    elif fault == "missing_child":
        manifest["endpoints"].pop()
    elif fault == "unknown_expansion":
        manifest["layout"][0]["expansion"]["id"] = "not-canonical"
    elif fault == "boolean_version":
        manifest["schema_version"] = True
    else:
        manifest["endpoints"][0]["dut_cage"] = []
    manifest["integrity"].pop("manifest_sha256")
    manifest["integrity"]["manifest_sha256"] = planner._digest(manifest)
    with pytest.raises(planner.InvalidManifest):
        planner.validate_manifest(manifest, snapshot, settings)


def test_unused_leaf_children_remain_explicitly_inactive(settings):
    """A leaf expansion can contain unconnected children, but they must not acquire transport."""
    snapshot = _snapshot(2)
    snapshot["lookup"] = [snapshot["lookup"][-1]]
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            cage["modes"] = cage["modes"][:1]
    leaf_cage = snapshot["devices"][1]["cages"][0]
    leaf_cage["modes"][0]["name"] = "2x400G"
    leaf_cage["modes"][0]["ports"].append(_port(1000, [1000, 1001, 1002, 1003], [4, 5, 6, 7], 400000))
    manifest = planner.plan_scenario(snapshot, settings)
    leaf_layout = next(row for row in manifest["layout"] if row["device"] == "leaf" and row["cage"] == "cage-0")
    assert leaf_layout["inactive_ports"] == ["Ethernet1000"]
    assert all(endpoint["leaf_port"] != "Ethernet1000" for endpoint in manifest["endpoints"])
