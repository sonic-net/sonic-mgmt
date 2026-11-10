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


def _service_snapshot():
    snapshot = _snapshot()
    cables = ["5m", "10m", "20m", "30m", "40m", "50m"]
    for device in snapshot["devices"]:
        for number in range(2):
            index = 12 + number
            modes = []
            for speed in (10000, 25000):
                port = _port(index, [index + (100 if device["name"] == "leaf" else 0)], [0], speed)
                port["cables"] = cables
                modes.append({"id": "service-" + str(speed), "name": "1x25G[10G]",
                              "group_mode": "independent", "ports": [port]})
            device["cages"].append({"name": "service-" + str(number), "group": "service-" + str(number),
                                    "protected_reason": "", "role": "service", "modes": modes})
    snapshot["links"].extend({"dut_cage": "service-" + str(number), "dut_channel": 0, "leaf": "leaf",
                              "leaf_cage": "service-" + str(number), "leaf_channel": 0, "excluded_reason": ""}
                             for number in range(2))
    snapshot["lookup"].extend(
        {"speed": speed, "cable": cable, "headroom": 100} for speed in (10000, 25000) for cable in cables)
    return snapshot


def test_finite_service_capacity_keeps_main_n_and_reports_requested_vs_actual_coverage(settings):
    snapshot = _service_snapshot()
    manifest = planner.plan_scenario(snapshot, settings)
    planner.validate_manifest(manifest, snapshot, settings)
    assert {(row["mode"], row["speed"], row["count"]) for row in manifest["requirements"]["modes"]} == {
        ("1x400G", 400000, 1), ("4x100G", 100000, 4)}
    service = manifest["coverage"]["service"]
    assert not service["complete"] and not manifest["coverage"]["complete"]
    assert {(row["speed"], row["requested_count"], row["actual_count"]) for row in service["modes"]} == {
        (10000, 6, 1), (25000, 6, 1)}
    assert len(service["lookup"]) == 12 and sum(bool(row["ports"]) for row in service["lookup"]) == 2
    assert service["warnings"][0]["code"] == "SERVICE_COVERAGE_INCOMPLETE"
    assert len(service["warnings"][0]["missing_lookup"]) == 10
    assert manifest["coverage"]["unselected"] == {"modes": [], "lookup": []}


def test_service_media_limits_selection_not_advertised_requests_or_primary_coverage(settings, monkeypatch):
    snapshot = _service_snapshot()
    advertised = planner.plan_scenario(snapshot, settings)
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            if cage.get("role") == "service":
                cage["media_speeds"] = [10000]
    manifest = planner.plan_scenario(snapshot, settings)
    assert manifest["requirements"]["modes"] == advertised["requirements"]["modes"]
    assert manifest["requirements"]["service"] == advertised["requirements"]["service"]
    assert {(row["speed"], row["requested_count"], row["actual_count"])
            for row in manifest["coverage"]["service"]["modes"]} == {(10000, 6, 2), (25000, 6, 0)}
    assert all(row["speed"] == 10000 for row in manifest["port_bindings"]
               if row["dut_cage"].startswith("service-"))
    assert manifest["coverage"]["service"]["warnings"] and manifest["traffic_cases"]
    monkeypatch.setattr(planner._Planner, "search", lambda *args: pytest.fail("validation repeated the search"))
    planner.validate_manifest(manifest, snapshot, settings)
    with pytest.raises(planner.InvalidManifest, match="media-limited"):
        planner.validate_manifest(advertised, snapshot, settings)


def test_service_ports_can_supply_the_only_independent_traffic_path(settings):
    snapshot = _service_snapshot()
    snapshot["endpoints"] = [
        {"id": "service-endpoint-" + str(number), "leaf": "leaf", "cage": "service-" + str(number),
         "channels": [0], "ptf_index": number, "trunk": "reserved-trunk", "vlan": 300 + number,
         "host_interface": "service" + str(number), "roles": ["access", "routed"]}
        for number in range(2)]
    manifest = planner.plan_scenario(snapshot, settings)
    planner.validate_manifest(manifest, snapshot, settings)
    assert len(manifest["endpoints"]) == 2 and len(manifest["traffic_cases"]) == 2
    assert {row["speed"] for row in manifest["endpoints"]} == {10000, 25000}
    assert sum(row["role"] == "routed" for row in manifest["endpoints"]) == 1


@pytest.mark.parametrize("fault", ["service-link", "main-links"])
def test_service_shortfall_warns_but_main_infeasibility_still_fails(settings, fault):
    snapshot = _service_snapshot()
    if fault == "service-link":
        snapshot["links"] = [row for row in snapshot["links"] if row["dut_cage"] != "service-0"]
        manifest = planner.plan_scenario(snapshot, settings)
        planner.validate_manifest(manifest, snapshot, settings)
        assert sum(row["actual_count"] for row in manifest["coverage"]["service"]["modes"]) == 1
        assert manifest["coverage"]["service"]["warnings"]
    else:
        snapshot["links"] = [row for row in snapshot["links"] if row["dut_cage"].startswith("service-")]
        with pytest.raises(planner.InfeasiblePlan):
            planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", ["complete", "warnings", "requested-count"])
def test_service_warning_and_coverage_cannot_be_forged_without_repeating_search(settings, monkeypatch, fault):
    snapshot = _service_snapshot()
    manifest = planner.plan_scenario(snapshot, settings)
    monkeypatch.setattr(planner._Planner, "search", lambda *args: pytest.fail("validation repeated the search"))
    planner.validate_manifest(manifest, snapshot, settings)
    if fault == "complete":
        manifest["coverage"]["complete"] = True
    elif fault == "warnings":
        manifest["coverage"]["service"]["warnings"] = []
    else:
        manifest["requirements"]["service"]["modes"][0]["requested_count"] = 1
    with pytest.raises(planner.InvalidManifest):
        planner.validate_manifest(manifest, snapshot, settings)


def test_service_budget_exhaustion_is_not_a_successful_warning(settings, monkeypatch):
    original = planner._Planner.complete_services

    def exhaust(self, state):
        self.settings["max_search_nodes"] = self.nodes
        return original(self, state)

    monkeypatch.setattr(planner._Planner, "complete_services", exhaust)
    with pytest.raises(planner.SearchBudgetExceeded):
        planner.plan_scenario(_service_snapshot(), settings)


@pytest.fixture
def snapshot():
    return _snapshot()


@pytest.fixture
def settings():
    return {"min_subports": 1, "routed_ports": 1, "access_vlan": 100,
            "routed_network": "198.18.0.0/24", "access_network": "198.19.0.0/24",
            "profile": "lossless", "max_search_nodes": 20000}


@pytest.fixture
def shared_indices_snapshot(snapshot):
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            physical_index = cage["modes"][0]["ports"][0]["index"]
            for mode in cage["modes"]:
                for port in mode["ports"]:
                    port["index"] = physical_index
    return snapshot


def test_shared_physical_indices_preserve_logical_endpoints(shared_indices_snapshot, settings):
    """Breakout children sharing a physical index still have distinct logical and PTF endpoints."""
    manifest = planner.plan_scenario(shared_indices_snapshot, settings)
    planner.validate_manifest(json.loads(planner.canonical_json(manifest)), shared_indices_snapshot, settings)
    children = [endpoint for endpoint in manifest["endpoints"] if endpoint["speed"] == 100000]
    assert len({(child["dut_cage"], child["dut_index"]) for child in children}) < len(children)
    endpoints = manifest["endpoints"]
    assert len({endpoint["dut_port"] for endpoint in endpoints}) == len(endpoints)
    assert len({endpoint["transport"]["ptf_index"] for endpoint in endpoints}) == len(endpoints)


@pytest.mark.parametrize("field", ["name", "alias"])
def test_shared_physical_indices_do_not_allow_duplicate_identities(shared_indices_snapshot, settings, field):
    """Sharing a physical index must not relax logical port-name or alias uniqueness."""
    ports = shared_indices_snapshot["devices"][0]["cages"][0]["modes"][1]["ports"]
    ports[1][field] = ports[0][field]
    with pytest.raises(planner.InvalidInput, match="Duplicate port " + field):
        planner.plan_scenario(shared_indices_snapshot, settings)


@pytest.mark.parametrize("protected", [False, True])
def test_zero_available_capacity_on_unused_or_protected_leaf(snapshot, settings, protected):
    """A zero-budget leaf must not block a complete plan using other reserved peers."""
    spare = copy.deepcopy(snapshot["devices"][1])
    spare["name"], spare["port_capacity"] = "spare-leaf", 0
    snapshot["devices"].append(spare)
    if protected:
        for cage in spare["cages"]:
            cage["protected_reason"] = "baseline reservation"
        for link in snapshot["links"]:
            if link["dut_cage"] == "cage-0":
                link["leaf"] = spare["name"]
        for endpoint in snapshot["endpoints"]:
            if endpoint["cage"] == "cage-0":
                endpoint["leaf"] = spare["name"]
    manifest = planner.plan_scenario(snapshot, settings)
    planner.validate_manifest(manifest, snapshot, settings)
    assert all(entry["device"] != spare["name"] for entry in manifest["layout"])
    if protected:
        assert not any(entry["device"] == "dut" and entry["cage"] == "cage-0" for entry in manifest["layout"])


@pytest.mark.parametrize("device", ["dut", "leaf"])
def test_zero_available_capacity_on_required_device_is_infeasible(snapshot, settings, device):
    """A valid zero budget cannot be bypassed when the required DUT/peer expansions consume ports."""
    next(item for item in snapshot["devices"] if item["name"] == device)["port_capacity"] = 0
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)


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


def test_n_and_routed_count_are_generated_without_per_bed_settings(snapshot):
    manifest = planner.plan_scenario(snapshot)
    planner.validate_manifest(manifest, snapshot)
    counts = {(row["mode"], row["speed"]): row["count"] for row in manifest["requirements"]["modes"]}
    assert counts == {("1x400G", 400000): 1, ("4x100G", 100000): 4}
    assert "min_subports" not in manifest["settings"] and "routed_ports" not in manifest["settings"]
    assert manifest["requirements"]["routed_ports"] == sum(
        row["role"] == "routed" for row in manifest["endpoints"])
    assert any(row["role"] == "access" for row in manifest["endpoints"])
    assert manifest["coverage"]["traffic"]["complete"]


def test_fully_protected_scope_is_not_an_empty_success_manifest(snapshot):
    for device in snapshot["devices"]:
        for cage in device["cages"]:
            cage["protected_reason"] = "Another owner's resource"
    with pytest.raises(planner.PrerequisiteError, match="No eligible controlled DUT modes"):
        planner.plan_scenario(snapshot)


def test_lookup_coverage_increases_n_and_optional_override_only_adds_coverage():
    snapshot = _snapshot(4)
    for cable in ("20m", "30m", "40m", "50m"):
        snapshot["lookup"].append({"speed": 100000, "cable": cable, "headroom": 1200})
        for device in snapshot["devices"]:
            for cage in device["cages"]:
                for mode in cage["modes"]:
                    for port in mode["ports"]:
                        if port["speed"] == 100000:
                            port["cables"].append(cable)
    manifest = planner.plan_scenario(snapshot, {"min_subports": 2})
    counts = {(row["mode"], row["speed"]): row["count"] for row in manifest["requirements"]["modes"]}
    assert counts == {("1x400G", 400000): 2, ("4x100G", 100000): 6}
    assert all(row["ports"] for row in manifest["coverage"]["lookup"])
    planner.validate_manifest(manifest, snapshot, {"min_subports": 2})


@pytest.mark.parametrize("transport", [False, True])
def test_one_layout_automatically_covers_l1_and_available_packet_paths(settings, transport):
    snapshot = _snapshot(2)
    snapshot["endpoints"] = ([] if not transport else
                             [row for row in snapshot["endpoints"] if row["channels"] == [0]])
    settings.pop("routed_ports")
    manifest = planner.plan_scenario(snapshot, settings)
    planner.validate_manifest(json.loads(planner.canonical_json(manifest)), snapshot, settings)
    assert all(row["ports"] for row in manifest["coverage"]["modes"] + manifest["coverage"]["lookup"])
    assert len(manifest["port_bindings"]) == 5
    assert manifest["coverage"]["traffic"]["unavailable"]
    untransported = [row for row in manifest["port_bindings"] if row["transport"] is None]
    assert all(row["role"] == "l1" and "ptf_address" not in row for row in untransported)
    assert len(manifest["endpoints"]) == (2 if transport else 0)
    assert not manifest["coverage"]["traffic"]["complete"]
    paths = {port for case in manifest["traffic_cases"] for port in (case["ingress"], case["egress"])}
    assert paths == {row["dut_port"] for row in manifest["endpoints"]}
    expected = planner.canonical_json(manifest)
    for key in ("devices", "links", "endpoints", "lookup"):
        snapshot[key].reverse()
    assert planner.canonical_json(planner.plan_scenario(snapshot, settings)) == expected


def test_automatic_planning_never_drops_unreachable_mode_coverage(settings):
    snapshot = _snapshot(1)
    snapshot["endpoints"] = []
    settings.pop("routed_ports")
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    manifest = planner.plan_scenario(snapshot, settings)
    assert not manifest["exclusions"]
    settings["min_subports"] = 5
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("endpoint_count", [0, 1])
def test_explicit_routed_requirement_is_not_softened_when_packet_resources_are_missing(
        settings, endpoint_count):
    snapshot = _snapshot(2)
    snapshot["endpoints"] = snapshot["endpoints"][:endpoint_count]
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("field", ["routed_ports", "min_subports"])
def test_automatic_defaults_do_not_accept_invalid_explicit_counts(snapshot, settings, field):
    settings[field] = 0
    with pytest.raises(planner.InvalidInput):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", ["wire", "headroom", "budget"])
def test_automatic_l1_preserves_physical_and_search_gates(snapshot, settings, fault):
    settings.pop("routed_ports")
    snapshot["endpoints"] = []
    if fault == "wire":
        snapshot["links"] = [row for row in snapshot["links"] if row["dut_channel"] != 3]
    elif fault == "headroom":
        snapshot["devices"][1]["headroom_capacity"] = 0
    else:
        settings["max_search_nodes"] = 1
    expected = planner.SearchBudgetExceeded if fault == "budget" else planner.InfeasiblePlan
    with pytest.raises(expected):
        planner.plan_scenario(snapshot, settings)


@pytest.mark.parametrize("fault", ["physical_peer", "traffic_witness", "qualification"])
def test_automatic_manifest_cannot_forge_physical_or_packet_coverage(snapshot, settings, fault):
    settings.pop("routed_ports")
    snapshot["endpoints"] = []
    manifest = planner.plan_scenario(snapshot, settings)
    if fault == "physical_peer":
        manifest["port_bindings"][0]["leaf_port"] = "invented-peer"
    elif fault == "traffic_witness":
        manifest["coverage"]["traffic"]["unavailable"] = []
    else:
        settings["routed_ports"] = 1
    with pytest.raises(planner.InvalidManifest):
        planner.validate_manifest(manifest, snapshot, settings)


def test_observed_cage_credits_are_reclaimed_only_for_the_frozen_selected_cages():
    snapshot = _snapshot(2)
    for device in snapshot["devices"]:
        device["port_capacity"], device["headroom_capacity"] = 0, 0
        device["port_credits"] = {"cage-0": 4, "cage-1": 4}
        device["headroom_credits"] = {"cage-0": 4000, "cage-1": 4000}
    manifest = planner.plan_scenario(snapshot)
    planner.validate_manifest(manifest, snapshot)
    assert manifest["resources"]["available"]["dut"] == {"ports": 8, "headroom": 8000}
    assert manifest["resources"]["headroom"]["dut"] <= 8000
    snapshot["devices"][0]["headroom_credits"] = {"cage-0": 0, "cage-1": 0}
    with pytest.raises(planner.InfeasiblePlan):
        planner.plan_scenario(snapshot)


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


def test_transport_vlan_collision_backtracks_to_compatible_endpoint(settings):
    """Skip a conflicting transport without rejecting its compatible alternative."""
    snapshot = _snapshot(1)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    snapshot["endpoints"].append(
        dict(snapshot["endpoints"][0], id="aaa-colliding", vlan=settings["access_vlan"]))
    manifest = planner.plan_scenario(snapshot, settings)
    first = next(endpoint for endpoint in manifest["endpoints"] if endpoint["dut_port"] == "Ethernet0")
    assert first["transport"]["id"] == "endpoint-0"
    assert all(row["transport"]["vlan"] != settings["access_vlan"] for row in manifest["endpoints"])
    planner.validate_manifest(manifest, snapshot, settings)


@pytest.mark.parametrize("explicit_traffic", [False, True])
def test_transport_vlan_collision_preserves_traffic_requirements(settings, explicit_traffic):
    """Only automatic traffic requirements permit a physical-only fallback."""
    snapshot = _snapshot(2)
    for endpoint in snapshot["endpoints"]:
        endpoint.update(vlan=settings["access_vlan"], trunk=endpoint["id"])
    if explicit_traffic:
        with pytest.raises(planner.InfeasiblePlan):
            planner.plan_scenario(snapshot, settings)
    else:
        settings.pop("routed_ports")
        manifest = planner.plan_scenario(snapshot, settings)
        assert not manifest["endpoints"] and not manifest["traffic_cases"]
        assert all(row["role"] == "l1" for row in manifest["port_bindings"])
        planner.validate_manifest(manifest, snapshot, settings)


def test_cable_assignment_backtracks_within_one_layout(settings):
    """Two cages must fit both modes and lookup pairs by assigning different cables to quad children."""
    manifest = planner.plan_scenario(_snapshot(2), settings)
    quad_cables = {endpoint["cable"] for endpoint in manifest["endpoints"] if endpoint["speed"] == 100000}
    assert quad_cables == {"5m", "10m"}
    assert len([row for row in manifest["layout"] if row["device"] == "dut"]) == 2


@pytest.mark.parametrize("routed_count", [1, 3])
def test_roles_and_address_capacity_are_search_constraints(settings, routed_count):
    """A /30 access pool has one PTF address; role allocation must fit it rather than silently overrun."""
    snapshot = _snapshot(1)
    for device in snapshot["devices"]:
        device["cages"][0]["modes"] = device["cages"][0]["modes"][1:]
    snapshot["lookup"] = snapshot["lookup"][:2]
    settings.update(access_network="198.19.0.0/30", routed_ports=routed_count)
    manifest = planner.plan_scenario(snapshot, settings)
    assert sum(row["role"] == "routed" for row in manifest["endpoints"]) == routed_count
    access = [row for row in manifest["endpoints"] if row["role"] == "access"]
    assert len(access) == 1
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
    "duplicate_link", "duplicate_lane", "ambiguous_profile", "bool_count",
    "bad_hash", "unknown_field", "overlapping_networks",
])
def test_malformed_contract_is_rejected(snapshot, settings, fault):
    """Reject ambiguous facts and invalid policy rather than guessing defaults."""
    if fault == "duplicate_link":
        snapshot["links"].append(copy.deepcopy(snapshot["links"][0]))
    elif fault == "duplicate_lane":
        port = snapshot["devices"][0]["cages"][0]["modes"][0]["ports"][0]
        port["lanes"].append(port["lanes"][0])
    elif fault == "ambiguous_profile":
        snapshot["supported_profiles"].append("lossy")
        del settings["profile"]
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


@pytest.mark.parametrize("role", ["routed", "access"])
def test_independent_validation_rejects_transport_vlan_collision(snapshot, settings, role):
    """Even a consistently hashed manifest must keep access and transport VLANs separate."""
    frozen = planner._Planner(planner.normalize_inputs(snapshot, settings))
    selected = frozen.search()
    settings["access_vlan"] = next(
        row["transport"]["vlan"] for row in selected.bindings if row["role"] == role)
    frozen.settings["access_vlan"] = settings["access_vlan"]
    manifest = frozen.manifest(selected)
    with pytest.raises(planner.InvalidManifest):
        planner.validate_manifest(manifest, snapshot, settings)


def test_independent_validation_rejects_hidden_traffic_without_routed_anchor(snapshot, settings):
    """An empty endpoint summary cannot bypass replayed traffic-role requirements."""
    settings.pop("routed_ports")
    manifest = planner.plan_scenario(snapshot, settings)
    manifest["endpoints"] = []
    for binding in manifest["port_bindings"]:
        if binding["transport"] is not None:
            binding["role"] = "access"
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
