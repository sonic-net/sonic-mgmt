"""Joint breakout and offline forwarding regressions, without SONiC/Ansible imports."""

import csv
from argparse import Namespace
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


SCRIPTS = Path(__file__).resolve().parents[3] / "ansible/scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC = importlib.util.spec_from_file_location("plan_generic_topology", SCRIPTS / "plan_generic_topology.py")
    planner = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(planner)
    import generic_topology_cli as controller
    DEVICE_SPEC = importlib.util.spec_from_file_location(
        "collect_generic_device", SCRIPTS / "collect_generic_device.py")
    device_collector = importlib.util.module_from_spec(DEVICE_SPEC)
    DEVICE_SPEC.loader.exec_module(device_collector)
finally:
    sys.path.pop(0)


@pytest.fixture
def fixture(tmp_path):
    """Three two-lane cages cover two modes and every supplied cable case."""
    interfaces = {}
    for index in range(3):
        base = index * 8
        interfaces["Ethernet{}".format(base)] = {
            "lanes": "{},{}".format(80 - index * 2, 79 - index * 2),
            "breakout_modes": {
                "1x200G[100G]": ["etp{}".format(index + 1)],
                "2x100G": ["etp{}a".format(index + 1), "etp{}b".format(index + 1)],
            },
        }
    platform = tmp_path / "dut.json"
    peer = tmp_path / "peer.json"
    platform.write_text(json.dumps({"interfaces": interfaces}))
    peer.write_text(platform.read_text())
    links = tmp_path / "links.csv"
    with links.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["StartDevice", "StartPort", "EndDevice", "EndPort", "BandWidth", "VlanID", "AutoNeg"])
        for index in range(3):
            for offset in range(2):
                writer.writerow(["dut", "Ethernet{}".format(index * 8 + offset),
                                 "leaf", "Ethernet{}".format(index * 8 + 1 - offset),
                                 100000, 100 + index * 2 + offset, "off"])
    lookup = tmp_path / "lookup.ini"
    lookup.write_text("# speed cable size xon xoff threshold\n"
                      "100000 5m 100 20 30 1\n"
                      "100000 40m 200 20 40 2\n"
                      "200000 5m 300 20 50 3\n")
    settings = {
        "physical_links": {"uplinks": ["Ethernet8", "Ethernet9"], "downlinks": ["Ethernet0", "Ethernet16"]},
        "routed_interfaces": {"address_pool": "192.0.2.0/24", "prefix_length": 31},
        "access_vlan": {"vlan_id": 1000, "subnet": "198.51.100.0/24"},
        "external_destinations": {"address_pool": "203.0.113.0/24", "prefix_length": 32},
        "constraints": {},
    }
    recipe = tmp_path / "recipe.yml"
    recipe.write_text(yaml.safe_dump({"topology": {}, "generic_topology": settings}))
    return {"platform": platform, "peer": peer, "links": links, "lookup": lookup,
            "recipe": recipe, "settings": settings, "uplink_minimum": 1}


def inputs(fixture, excluded=()):
    dut, peer = planner.load_device(fixture["platform"]), planner.load_device(fixture["peer"])
    lookup = planner.load_lookup(fixture["lookup"])
    inventory = planner.build_mapping(fixture["links"], "dut", "leaf", dut, peer, lookup, excluded)
    return inventory, dut, peer, lookup


@pytest.fixture
def low_speed_fixture(fixture):
    """Add two dedicated 10G/25G cages with more cable cases than simultaneous children."""
    for side in ("platform", "peer"):
        path = fixture[side]
        document = json.loads(path.read_text())
        for base in (512, 520):
            document["interfaces"]["Ethernet{}".format(base)] = {
                "lanes": str(base), "breakout_modes": {"1x25G[10G]": ["etp{}".format(base)]}}
        path.write_text(json.dumps(document))
    with fixture["links"].open("a") as handle:
        writer = csv.writer(handle)
        for base in (512, 520):
            writer.writerow(["dut", "Ethernet{}".format(base), "leaf",
                             "Ethernet{}".format(base), 25000, base])
    with fixture["lookup"].open("a") as handle:
        for speed in (10000, 25000):
            for cable in ("5m", "30m"):
                handle.write("{} {} 100 20 30 1\n".format(speed, cable))
    return fixture


def generate(fixture, max_states=100000, vlan_backed_only=False, excluded=()):
    artifacts = planner.build_scenario(
        *inputs(fixture, excluded), fixture["settings"], max_states,
        min_same_breakout_uplinks=fixture["uplink_minimum"] if fixture["uplink_minimum"] is not None else 0,
        vlan_backed_only=vlan_backed_only)
    artifacts["manifest.json"]["recipe_paths"] = [str(fixture["recipe"])]
    return artifacts


@pytest.fixture
def vlan_fixture(fixture):
    """One named VLAN endpoint per fully wired cage permits only single-child layouts."""
    with fixture["links"].open() as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["EndPort"] = row["StartPort"]
        if int(row["StartPort"][8:]) % 8:
            row["VlanID"] = ""
    with fixture["links"].open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return fixture


@pytest.fixture
def automatic_uplink_fixture(fixture):
    """Ten VLAN-backed ports allow eight automatic uplinks and two downlinks."""
    modes = ("1x100G", "1x200G[100G]", "1x400G[100G]", "1x800G[100G]")
    interfaces = {
        "Ethernet{}".format(index * 8): {
            "lanes": str(1000 + index),
            "breakout_modes": {modes[index % len(modes)]: ["etp{}".format(index + 1)]},
        }
        for index in range(10)
    }
    for side in ("platform", "peer"):
        fixture[side].write_text(json.dumps({"interfaces": interfaces}))
    with fixture["links"].open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["StartDevice", "StartPort", "EndDevice", "EndPort", "BandWidth", "VlanID"])
        for index in range(10):
            port = "Ethernet{}".format(index * 8)
            writer.writerow(["dut", port, "leaf", port, 100000, 100 + index])
    fixture["settings"]["physical_links"] = {"uplinks": [], "downlinks": []}
    fixture["uplink_minimum"] = None
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    return fixture


def test_empty_source_resolves_first_eight_and_seals_generated_yaml(automatic_uplink_fixture, tmp_path, monkeypatch):
    """Auto roles use numeric selected-port order and never rewrite the editable empty source."""
    fixture = automatic_uplink_fixture
    source = fixture["recipe"].read_bytes()
    artifacts = generate(fixture, vlan_backed_only=True)
    expected = ["Ethernet{}".format(index * 8) for index in range(8)]
    roles = artifacts["topology.yml"]["generic_topology"]["physical_links"]
    assert roles == {"uplinks": expected, "downlinks": ["Ethernet64", "Ethernet72"]}
    assert artifacts["manifest.json"]["policy"]["role_assignment"] == "first_eight_selected"
    assert artifacts["manifest.json"]["policy"]["uplink_repetition_scope"] == "none"
    assert artifacts["manifest.json"]["policy"]["min_same_breakout_uplinks"] == 0
    links = artifacts["resolved_facts.json"]["connections"]
    assert len({link["dut"]["speed"] for link in links if link["role"] == "uplink"}) == 2
    assert all(row["uplink_count"] < 4 for row in artifacts["coverage.json"]["uplink_repetition"]["groups"])
    assert artifacts["coverage.json"]["deployment_eligible"]
    planner.seal_artifacts(artifacts)
    finalized = controller.finalize(
        Namespace(output_dir=str(tmp_path / "finalized")), artifacts, {}, "dut")
    assert finalized["topology.yml"]["generic_topology"]["physical_links"] == roles
    assert fixture["recipe"].read_bytes() == source
    assert controller.coverage_ready(controller.load_scenario(tmp_path / "finalized"))

    def remote(*args, **kwargs):
        raise RuntimeError("mixed-speed automatic uplinks passed render preflight")

    monkeypatch.setattr(controller, "run_playbook", remote)
    with pytest.raises(RuntimeError, match="passed render preflight"):
        controller.render(Namespace(output_dir=str(tmp_path / "rendered")), finalized, {}, "dut")


def test_cli_disables_matching_uplinks_by_default(automatic_uplink_fixture, tmp_path):
    """An empty recipe automatically plans eight uplinks without requiring four equal mode/speed links."""
    output = tmp_path / "auto-plan"
    result = cli(automatic_uplink_fixture, output)
    assert result.returncode == 0, result.stderr
    artifacts = controller.load_scenario(output)
    policy = artifacts["manifest.json"]["policy"]
    assert policy["uplink_repetition_scope"] == "none"
    assert policy["min_same_breakout_uplinks"] == 0
    assert artifacts["coverage.json"]["uplink_repetition"]["selected_target"] is None
    assert artifacts["topology.yml"]["generic_topology"]["physical_links"]["uplinks"] == [
        "Ethernet{}".format(index * 8) for index in range(8)]


def test_automatic_uplinks_cannot_be_swapped_after_freeze(automatic_uplink_fixture, tmp_path):
    """Consistent edits of generated role lists still cannot change the frozen first-eight policy."""
    artifacts = generate(automatic_uplink_fixture, vlan_backed_only=True)
    planner.seal_artifacts(artifacts)
    finalized = controller.finalize(
        Namespace(output_dir=str(tmp_path / "finalized")), artifacts, {}, "dut")
    roles = finalized["topology.yml"]["generic_topology"]["physical_links"]
    roles["uplinks"].remove("Ethernet0")
    roles["uplinks"].append("Ethernet64")
    roles["downlinks"].remove("Ethernet64")
    roles["downlinks"].append("Ethernet0")
    assignments = planner.port_assignments(
        {"physical_links": roles}, finalized["manifest.json"]["policy"]["port_assignments"])
    finalized["manifest.json"]["policy"]["port_assignments"] = assignments
    for link in finalized["resolved_facts.json"]["connections"]:
        link["role"] = assignments[link["dut"]["port"]]
    with pytest.raises(ValueError, match="first eight"):
        controller.coverage_ready(finalized)


def test_automatic_uplinks_still_require_a_downlink(automatic_uplink_fixture):
    """Selecting all eight available links as uplinks cannot bypass the current T0 forwarding model."""
    fixture = automatic_uplink_fixture
    fixture["links"].write_text("\n".join(fixture["links"].read_text().splitlines()[:-2]) + "\n")
    artifacts = generate(fixture, vlan_backed_only=True)
    assert len(artifacts["resolved_facts.json"]["connections"]) == 8
    assert not artifacts["coverage.json"]["deployment_eligible"]
    assert artifacts["resolved_facts.json"]["forwarding"] is None
    assert "downlink" in artifacts["coverage.json"]["allocation_error"]


def test_vlan_named_children_reuse_full_wiring_without_adding_endpoints(vlan_fixture):
    """Blank-tag sibling atoms may aggregate, but cannot become independently exposed children."""
    artifacts = generate(vlan_fixture, vlan_backed_only=True)
    facts, manifest, coverage = (artifacts[name] for name in (
        "resolved_facts.json", "manifest.json", "coverage.json"))
    assert {link["dut"]["port"] for link in facts["connections"]} == {"Ethernet0", "Ethernet8", "Ethernet16"}
    assert all(len(link["dut"]["atoms"]) == 2 for link in facts["connections"])
    assert [link["transport_vlan_id"] for link in facts["connections"]] == [100, 102, 104]
    assert manifest["policy"]["vlan_scope"] == facts["vlan_scope"]
    assert coverage["vlan_scope"] == {"available_endpoints": 3, "selected_endpoints": 3}
    assert coverage["status"] == "incomplete" and coverage["deployment_eligible"]
    assert coverage["uncovered_mode_speeds"] == [{"mode": "2x100G", "speed": 100000}]
    assert any(row["reason"] == "realized child has no CSV-backed transport VLAN"
               for row in coverage["rejected_candidates"])


def test_cages_without_vlan_endpoints_are_preserved(vlan_fixture):
    """A fully wired cage with no named VLAN endpoint remains outside generic ownership."""
    text = vlan_fixture["links"].read_text().replace(",104,", ",,")
    vlan_fixture["links"].write_text(text)
    result = generate(vlan_fixture, vlan_backed_only=True)
    manifest = result["manifest.json"]
    assert manifest["protected_dut_cages"] == manifest["protected_peer_cages"] == ["Ethernet16"]
    assert "Ethernet16" not in manifest["selected_layouts"]["dut"]
    assert {link["dut"]["port"] for link in result["resolved_facts.json"]["connections"]} == {
        "Ethernet0", "Ethernet8"}


@pytest.mark.parametrize("value", ["100", "100-101", "4095"])
def test_csv_vlan_scope_rejects_duplicate_or_invalid_transport(vlan_fixture, value):
    """An existing name cannot authorize shared or malformed transport VLANs."""
    vlan_fixture["links"].write_text(vlan_fixture["links"].read_text().replace(",102,", "," + value + ","))
    with pytest.raises(ValueError, match="CSV transport VLAN"):
        generate(vlan_fixture, vlan_backed_only=True)


def test_partial_mode_and_buffer_coverage_can_render_and_deploy(vlan_fixture, tmp_path, monkeypatch, capsys):
    """Unqualified cases stay visible while a valid finalized scenario reaches all deployment phases."""
    with vlan_fixture["lookup"].open("a") as handle:
        handle.write("100000 80m 400 20 60 4\n")
    artifacts = generate(vlan_fixture, vlan_backed_only=True)
    assert artifacts["coverage.json"]["uncovered_buffer_cases"]
    planner.seal_artifacts(artifacts)
    testbed = {"conf-name": "tb", "topo": "generic", "server": "server"}
    finalized = controller.finalize(
        Namespace(output_dir=str(tmp_path / "finalized")), artifacts, testbed, "dut")
    assert finalized["manifest.json"]["status"] == "finalized_partial_coverage"
    assert controller.coverage_ready(finalized)
    phases = []

    def remote(args, name, variables, local, **kwargs):
        phase = variables.get("generic_action", "host-verify")
        phases.append(phase)
        if phase == "render":
            for role in ("dut", "peer"):
                request = json.loads((local / (role + "-request.json")).read_text())
                assert request["facts"]["vlan_scope"] == artifacts["manifest.json"]["policy"]["vlan_scope"]
                ports = [link[role]["port"] for link in request["facts"]["connections"]]
                controller.write_private(local / (role + "-response.json"), {
                    "config": {"PORT": dict.fromkeys(ports, {})},
                    "report": {"transport": [], "owned_ports": ports},
                })

    monkeypatch.setattr(controller, "run_playbook", remote)
    controller.render(Namespace(output_dir=str(tmp_path / "rendered")), finalized, testbed, "dut")
    rendered = controller.load_scenario(tmp_path / "rendered")
    assert rendered["manifest.json"]["deployable"]
    assert rendered["coverage.json"]["status"] == "incomplete"
    controller.deploy(Namespace(action="deploy-mg", apply=False), rendered, testbed, "dut")
    assert phases == ["render"]
    assert "PARTIAL COVERAGE" in capsys.readouterr().out
    controller.deploy(Namespace(action="deploy-mg", apply=True), rendered, testbed, "dut")
    assert phases == ["render", "host-verify", "stage", "apply", "verify", "save"]


@pytest.mark.parametrize("failure", ["uplinks", "allocation", "endpoint", "frozen_scope"])
def test_partial_coverage_never_waives_deployment_safety(vlan_fixture, tmp_path, monkeypatch, failure):
    """Best-effort plans still reject missing uplinks/forwarding and endpoints outside the frozen scope."""
    artifacts = generate(vlan_fixture, vlan_backed_only=True)
    planner.seal_artifacts(artifacts)
    finalized = controller.finalize(
        Namespace(output_dir=str(tmp_path / "finalized")), artifacts, {}, "dut")
    policy = finalized["manifest.json"]["policy"]
    if failure == "uplinks":
        policy["min_same_breakout_uplinks"] = 4
    elif failure == "allocation":
        finalized["coverage.json"]["allocation_error"] = "insufficient addresses"
    elif failure == "endpoint":
        finalized["resolved_facts.json"]["connections"][0]["dut"]["port"] = "Ethernet1"
    else:
        finalized["resolved_facts.json"]["vlan_scope"]["dut_ports"]["Ethernet1"] = 101
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected device access"))
    with pytest.raises(ValueError):
        controller.render(Namespace(output_dir=str(tmp_path / "rendered")), finalized, {}, "dut")
    finalized["manifest.json"].update(deployable=True, requires_explicit_apply=True)
    with pytest.raises(ValueError):
        controller.deploy(Namespace(action="deploy-mg", apply=True), finalized, {}, "dut")


@pytest.mark.parametrize("overflow", [False, True])
def test_explicitly_protected_low_speed_cases_remain_out_of_scope(low_speed_fixture, tmp_path, overflow):
    """Explicit cage exclusions still scope coverage and survive immutable finalization."""
    fixture = low_speed_fixture
    if overflow:
        with fixture["lookup"].open("a") as handle:
            handle.write("100000 3m 100 20 30 1\n100000 4m 100 20 30 1\n")
    protected = ["Ethernet512", "Ethernet520"]
    artifacts = generate(fixture, excluded=protected)
    manifest, coverage = artifacts["manifest.json"], artifacts["coverage.json"]
    assert manifest["protected_dut_cages"] == manifest["protected_peer_cages"] == protected
    for side in ("dut", "peer"):
        assert not set(protected) & set(manifest["selected_layouts"][side])
        assert not any(link[side]["port"] in protected for link in artifacts["resolved_facts.json"]["connections"])
    assert len(coverage["excluded_buffer_cases"]) == 4
    assert {row["speed"] for row in coverage["excluded_buffer_cases"]} == {"10000", "25000"}
    assert all(row["dut_cages"] == protected for row in coverage["excluded_buffer_cases"])
    assert all(int(row["speed"]) >= 100000 for row in coverage["required_buffer_cases"])
    assert all(int(row["speed"]) >= 100000 for row in coverage["covered_buffer_cases"])
    assert coverage["status"] == ("incomplete" if overflow else "complete")
    assert bool(coverage["uncovered_buffer_cases"]) is overflow
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "protected-plan"
    planner.write_artifacts(plan, artifacts)
    finalized = controller.finalize(
        Namespace(scenario_dir=str(plan), output_dir=str(tmp_path / "protected-finalized")),
        controller.load_scenario(plan), {}, "dut")
    assert finalized["coverage.json"]["status"] == coverage["status"]
    assert finalized["coverage.json"]["excluded_buffer_cases"] == coverage["excluded_buffer_cases"]
    assert finalized["manifest.json"]["protected_dut_cages"] == protected


def test_cli_includes_low_speed_layouts_and_coverage_by_default(low_speed_fixture, tmp_path):
    """New VLAN-scoped plans include low-speed combinations and honestly report missing lookup cases."""
    included = tmp_path / "included-plan"
    completed = cli(low_speed_fixture, included)
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((included / "manifest.json").read_text())
    coverage = json.loads((included / "coverage.json").read_text())
    assert not manifest["protected_dut_cages"] and not manifest["protected_peer_cages"]
    assert {"Ethernet512", "Ethernet520"}.issubset(manifest["selected_layouts"]["dut"])
    assert not coverage["excluded_buffer_cases"]
    assert {row["speed"] for row in coverage["required_buffer_cases"]}.issuperset({"10000", "25000"})
    facts = json.loads((included / "resolved_facts.json").read_text())
    low_speeds = {link["dut"]["speed"] for link in facts["connections"]
                  if link["dut"]["port"] in {"Ethernet512", "Ethernet520"}}
    assert low_speeds == {10000, 25000}
    assert coverage["status"] == "incomplete"
    assert coverage["deployment_eligible"]


def test_low_speed_rows_remain_required_when_managed_cages_support_them(low_speed_fixture):
    """Explicit exclusions do not waive speeds that another eligible cage can still exercise."""
    for side in ("platform", "peer"):
        path = low_speed_fixture[side]
        document = json.loads(path.read_text())
        modes = document["interfaces"]["Ethernet0"]["breakout_modes"]
        modes["2x100G[25G]"] = modes["2x100G"]
        path.write_text(json.dumps(document))
    coverage = generate(low_speed_fixture, excluded=["Ethernet512", "Ethernet520"])["coverage.json"]
    assert {row["speed"] for row in coverage["excluded_buffer_cases"]} == {"10000"}
    assert "25000" in {row["speed"] for row in coverage["required_buffer_cases"]}


def test_low_speed_cages_still_require_csv_vlan_endpoints(low_speed_fixture):
    """Including low speeds cannot expand the scenario onto a child without an existing CSV VLAN."""
    links = low_speed_fixture["links"]
    with links.open() as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row["StartPort"] == "Ethernet512":
            row["VlanID"] = ""
    with links.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    artifacts = generate(low_speed_fixture, vlan_backed_only=True)
    for side in ("dut", "peer"):
        assert artifacts["manifest.json"]["protected_{}_cages".format(side)] == ["Ethernet512"]
        layout = artifacts["manifest.json"]["selected_layouts"][side]
        assert "Ethernet512" not in layout and "Ethernet520" in layout


def test_shared_dut_forwarding_cleanup_is_frozen_without_replanning_breakout(fixture, tmp_path):
    """Outside-peer DUT cages remain fixed while their forwarding-only cleanup scope is sealed."""
    links = fixture["links"]
    with links.open() as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row["StartPort"] in {"Ethernet16", "Ethernet17"}:
            row["EndDevice"] = "shared-leaf"
    with links.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    artifacts = generate(fixture, vlan_backed_only=True)
    expected = {"Ethernet16": inputs(fixture)[1]["cages"]["Ethernet16"]["lanes"]}
    assert artifacts["manifest.json"]["policy"]["dut_forwarding_cleanup"] == expected
    assert artifacts["resolved_facts.json"]["dut_forwarding_cleanup"] == expected
    for side in ("dut", "peer"):
        assert "Ethernet16" in artifacts["manifest.json"]["protected_{}_cages".format(side)]
        assert "Ethernet16" not in artifacts["manifest.json"]["selected_layouts"][side]
    planner.seal_artifacts(artifacts)
    controller.finalize(Namespace(output_dir=str(tmp_path / "finalized")), artifacts, {}, "dut")
    sealed = controller.load_scenario(tmp_path / "finalized")
    assert sealed["resolved_facts.json"]["dut_forwarding_cleanup"] == expected
    controller.validate_forwarding_cleanup(sealed)


def test_planning_matches_mixed_children_and_counts_full_combinations(fixture, tmp_path):
    """Match reversed peer partitions at each child's speed and cover mixed combinations as a whole."""
    mixed = "1x100G(1)+1x50G(1)"
    reverse = "1x50G(1)+1x100G(1)"
    for side in ("platform", "peer"):
        path = fixture[side]
        document = json.loads(path.read_text())
        document["interfaces"]["Ethernet24"] = {
            "lanes": "74,73", "breakout_modes": {
                "1x200G[100G]": ["etp4"], "2x100G": ["etp4a", "etp4b"]}}
        for cage in document["interfaces"].values():
            cage["breakout_modes"][mixed if side == "platform" else reverse] = cage["breakout_modes"]["2x100G"]
        path.write_text(json.dumps(document))
    with fixture["links"].open("a") as handle:
        csv.writer(handle).writerows([
            ["dut", "Ethernet24", "leaf", "Ethernet25", 100000, 106],
            ["dut", "Ethernet25", "leaf", "Ethernet24", 100000, 107],
        ])
    with fixture["lookup"].open("a") as handle:
        handle.write("50000 5m 50 10 20 1\n")
    fixture["settings"]["physical_links"] = {
        "uplinks": ["Ethernet0", "Ethernet8", "Ethernet16", "Ethernet24"], "downlinks": []}
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    artifacts = generate(fixture)
    assert artifacts["coverage.json"]["status"] == "complete"
    assert artifacts["coverage.json"]["breakout_diversity"]["complete"]
    assert {"mode": mixed, "speed": [100000, 50000]} in artifacts["coverage.json"]["required_mode_speeds"]
    connections = artifacts["resolved_facts.json"]["connections"]
    assert {link["dut"]["speed"] for link in connections} == {50000, 100000, 200000}
    assert all(link["dut"]["speed"] == link["peer"]["speed"] == int(link["buffer_case"]["speed"])
               for link in connections)
    mixed_layout = {cage: choice for cage, choice in artifacts["manifest.json"]["selected_layouts"]["dut"].items()
                    if choice["mode"] == mixed}
    assignments = {child["port"]: "uplink" for choice in mixed_layout.values() for child in choice["children"]}
    repetition = planner.validate_uplink_repetition(mixed_layout, assignments, 2)
    assert repetition["complete"]
    assert repetition["groups"][0]["uplink_count"] == 2
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "mixed-plan"
    planner.write_artifacts(plan, artifacts)
    result = controller.finalize(
        Namespace(scenario_dir=str(plan), output_dir=str(tmp_path / "mixed-finalized")),
        controller.load_scenario(plan), {}, "dut")
    assert result["coverage.json"]["status"] == "complete"
    assert result["manifest.json"]["selected_layouts"] == json.loads(json.dumps(
        artifacts["manifest.json"]["selected_layouts"]))
    assert result["manifest.json"]["policy"]["coverage_unit"] == "mode_operating_combination"


def test_physical_diversity_precedes_uplink_repetition(fixture):
    """Represent operating combinations on downlink cages before spending cages on N matching uplinks."""
    for side in ("platform", "peer"):
        path = fixture[side]
        document = json.loads(path.read_text())
        modes = document["interfaces"]["Ethernet16"]["breakout_modes"]
        del modes["1x200G[100G]"]
        path.write_text(json.dumps(document))
    fixture["settings"]["physical_links"] = {
        "uplinks": ["Ethernet0", "Ethernet1", "Ethernet8", "Ethernet9"], "downlinks": []}
    fixture["uplink_minimum"] = 4
    artifacts = generate(fixture)
    coverage = artifacts["coverage.json"]
    assert coverage["breakout_diversity"]["complete"]
    assert not coverage["uplink_repetition"]["complete"]
    assert all(row["uplink_count"] < 4 for row in coverage["uplink_repetition"]["groups"])
    assert coverage["status"] == "incomplete"


def test_one_matching_combination_can_finalize_and_render(fixture, tmp_path, monkeypatch):
    """Only the selected N-uplink combination is required; other combinations may be all downlinks."""
    fixture["settings"]["physical_links"] = {"uplinks": ["Ethernet0", "Ethernet1"], "downlinks": []}
    fixture["uplink_minimum"] = 2
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    artifacts = generate(fixture)
    coverage = artifacts["coverage.json"]
    assert coverage["status"] == "complete"
    assert coverage["breakout_diversity"]["complete"]
    repetition = coverage["uplink_repetition"]
    assert repetition["scope"] == "one"
    assert repetition["selected_target"] == {"mode": "2x100G", "speed": 100000}
    assert sum(row["required"] for row in repetition["groups"]) == 1
    assert any(not row["required"] and row["uplink_count"] == 0 for row in repetition["groups"])
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "one-combination-plan"
    planner.write_artifacts(plan, artifacts)
    finalized = controller.finalize(
        Namespace(scenario_dir=str(plan), output_dir=str(tmp_path / "one-combination-finalized")),
        controller.load_scenario(plan), {}, "dut")
    assert finalized["coverage.json"]["status"] == "complete"
    assert finalized["manifest.json"]["policy"]["uplink_repetition_scope"] == "one"
    assert finalized["manifest.json"]["policy"]["uplink_repetition_target"] == repetition["selected_target"]

    def remote(*args, **kwargs):
        raise RuntimeError("render preflight passed")

    monkeypatch.setattr(controller, "run_playbook", remote)
    with pytest.raises(RuntimeError, match="render preflight passed"):
        controller.render(Namespace(output_dir=str(tmp_path / "rendered")), finalized, {}, "dut")
    finalized["manifest.json"]["policy"]["uplink_repetition_target"] = {
        "mode": "1x200G[100G]", "speed": 100000}
    with pytest.raises(ValueError, match="frozen repetition target"):
        controller.render(Namespace(output_dir=str(tmp_path / "changed-target")), finalized, {}, "dut")
    finalized["manifest.json"]["policy"].pop("uplink_repetition_scope")
    finalized["manifest.json"]["policy"].pop("uplink_repetition_target")
    with pytest.raises(ValueError, match="Every required DUT"):
        controller.render(Namespace(output_dir=str(tmp_path / "legacy-rendered")), finalized, {}, "dut")


@pytest.mark.parametrize("missing", ["diversity", "buffer"])
def test_one_matching_combination_does_not_waive_other_coverage(fixture, missing):
    """One successful repeated group never authorizes missing physical combinations or buffer cases."""
    fixture["uplink_minimum"] = 2
    if missing == "diversity":
        for side in ("platform", "peer"):
            path = fixture[side]
            document = json.loads(path.read_text())
            del document["interfaces"]["Ethernet16"]
            path.write_text(json.dumps(document))
        fixture["links"].write_text("\n".join(fixture["links"].read_text().splitlines()[:-2]) + "\n")
    else:
        with fixture["lookup"].open("a") as handle:
            handle.write("10000 5m 10 2 3 1\n")
    result = generate(fixture)
    coverage = result["coverage.json"]
    assert coverage["uplink_repetition"]["complete"]
    assert coverage["status"] == "incomplete"
    if missing == "diversity":
        assert not coverage["breakout_diversity"]["complete"]
    else:
        assert coverage["breakout_diversity"]["complete"]
        assert [row["speed"] for row in coverage["uncovered_buffer_cases"]] == ["10000"]


def planner_options(fixture, output):
    options = ["--peer-hostname", "leaf",
               "--platform-json", str(fixture["platform"]), "--peer-platform-json", str(fixture["peer"]),
               "--links-csv", str(fixture["links"]), "--pg-profile-lookup", str(fixture["lookup"]),
               "--recipe", str(fixture["recipe"]), "--output-dir", str(output)]
    if fixture["uplink_minimum"] is not None:
        options.extend(["--min-same-breakout-uplinks", str(fixture["uplink_minimum"])])
    return options


def cli(fixture, output, extra=()):
    command = [sys.executable, str(SCRIPTS / "plan_generic_topology.py"),
               "--hostname", "dut"] + planner_options(fixture, output) + list(extra)
    return subprocess.run(command, capture_output=True, text=True)


@pytest.mark.parametrize("ipv6", [False, True])
def test_shared_generic_recipe_supports_both_families_and_testbed_overrides(
        automatic_uplink_fixture, tmp_path, ipv6):
    """Reuse one topology recipe across testbeds without changing it or mixing address families."""
    recipe = SCRIPTS.parent / "vars/topo_generic.yml"
    ipv4 = SCRIPTS.parent / "vars/generic_ipv4.yml"
    before = {path: path.read_bytes() for path in (recipe, ipv4)}
    testbeds = tmp_path / "testbeds.yml"
    testbeds.write_text(yaml.safe_dump([
        {"conf-name": name, "dut": ["dut"], "topo": "generic", "inv_name": "unused-" + name}
        for name in ("tb-first", "tb-second")
    ]))
    override = tmp_path / "allocations.yml"
    override.write_text(yaml.safe_dump({"generic_topology": {"access_vlan": {"vlan_id": 3100}}}))
    for index, name in enumerate(("tb-first", "tb-second")):
        output = tmp_path / name
        options = planner_options(automatic_uplink_fixture, output)
        options[options.index("--recipe") + 1] = str(recipe)
        if not ipv6:
            options += ["--overrides", str(ipv4)]
        if index:
            options += ["--overrides", str(override)]
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS / "plan_generic_topology.py"),
             "--testbed", name, "--testbed-file", str(testbeds)] + options, capture_output=True, text=True)
        assert completed.returncode == 0, completed.stderr
        artifacts = controller.load_scenario(output)
        facts = artifacts["resolved_facts.json"]
        assert artifacts["manifest.json"]["testbed"]["conf-name"] == name
        assert facts["forwarding"]["vlan_id"] == (3100 if index else 3000)
        assert set(facts["forwarding"]["static_routes"]).issuperset({"::/0" if ipv6 else "0.0.0.0/0"})
        uplinks = [link for link in facts["connections"] if link["role"] == "uplink"]
        assert len(uplinks) == 8
        assert all(link["dut_address"].endswith("/127" if ipv6 else "/31") for link in uplinks)
        assert all(link["destination_prefix"].endswith("/128" if ipv6 else "/32") for link in uplinks)
        assert artifacts["manifest.json"]["recipe_paths"] == [
            str(path) for path in [recipe] + ([] if ipv6 else [ipv4]) + ([override] if index else [])]
    assert {path: path.read_bytes() for path in before} == before


def test_unconfigured_recipe_requires_explicit_lab_allocations(fixture, tmp_path):
    """Blank allocations fail closed independently of the editable lab recipe."""
    settings = deepcopy(fixture["settings"])
    settings["routed_interfaces"]["address_pool"] = None
    settings["access_vlan"] = {"vlan_id": None, "subnet": None}
    settings["external_destinations"]["address_pool"] = None
    recipe = tmp_path / "unconfigured.yml"
    recipe.write_text(yaml.safe_dump({"topology": {}, "generic_topology": settings}))
    before = recipe.read_bytes()
    output = tmp_path / "scenario"
    completed = cli(fixture, output, ["--recipe", str(recipe)])
    assert completed.returncode == 1, completed.stderr
    assert "Error:" in completed.stderr
    assert not output.exists()
    completed = cli(fixture, output, [
        "--recipe", str(recipe), "--overrides", str(fixture["recipe"]),
    ])
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["deployable"] is False
    assert json.loads((output / "coverage.json").read_text())["status"] == "complete"
    assert recipe.read_bytes() == before


def test_device_discovery_reads_installed_assets(tmp_path, monkeypatch):
    """Prefer the platform lookup and use a different SKU file only after the platform file is absent."""
    monkeypatch.setattr(device_collector.subprocess, "check_output", lambda command, **kwargs: json.dumps({
        "localhost": {"platform": "test-platform", "hwsku": "test-sku"},
    }))
    platform_dir = tmp_path / "test-platform"
    hwsku_dir = platform_dir / "test-sku"
    hwsku_dir.mkdir(parents=True)
    platform_file = platform_dir / "platform.json"
    platform_file.write_text('{"interfaces": {}}')
    lookup_file = platform_dir / "pg_profile_lookup.ini"
    lookup_file.write_text("# speed cable size\n100000 5m 100\n")
    hwsku_lookup = hwsku_dir / "pg_profile_lookup.ini"
    hwsku_lookup.write_text("# speed cable size\n100000 5m 999\n")
    before = {path: path.read_bytes() for path in (platform_file, lookup_file, hwsku_lookup)}
    result = device_collector.collect_device(True, True, tmp_path)
    assert result["files"]["platform.json"]["remote_path"] == str(platform_file)
    assert result["files"]["pg_profile_lookup.ini"]["remote_path"] == str(lookup_file)
    assert result["files"]["pg_profile_lookup.ini"]["content"] == lookup_file.read_text()
    assert before == {path: path.read_bytes() for path in before}
    platform_file.rename(hwsku_dir / "platform.json")
    assert device_collector.collect_device(True, False, tmp_path)["files"]["platform.json"]["remote_path"] == str(
        hwsku_dir / "platform.json")
    lookup_file.unlink()
    assert device_collector.collect_device(False, True, tmp_path)["files"]["pg_profile_lookup.ini"] == {
        "remote_path": str(hwsku_lookup), "content": hwsku_lookup.read_text()}
    assert not lookup_file.exists()
    assert hwsku_lookup.read_bytes() == before[hwsku_lookup]


@pytest.mark.parametrize("platform", [None, "../outside", "/outside", ""])
def test_device_discovery_rejects_invalid_identity(monkeypatch, platform):
    """Remote metadata cannot redirect discovery outside the installed device root."""
    monkeypatch.setattr(device_collector.subprocess, "check_output", lambda command, **kwargs: json.dumps({
        "localhost": {"platform": platform, "hwsku": "test-sku"},
    }))
    with pytest.raises(ValueError, match="platform is missing or invalid"):
        device_collector.collect_device(True, True)


def collection_args(fixture, tmp_path):
    return Namespace(platform_json=None, peer_platform_json=None, pg_profile_lookup=None,
                     peer_hostname="leaf", inventory=[], testbed_file=str(tmp_path / "testbed.yml"),
                     snapshot_dir=None, output_dir=str(tmp_path / "scenario"), vault_password_file=None)


def test_collection_requires_inventory_and_preserves_offline_use(fixture, tmp_path, monkeypatch):
    """No inventory is needed for explicit snapshots; missing snapshots must not silently fall back."""
    args = collection_args(fixture, tmp_path)
    with pytest.raises(ValueError, match="require --inventory"):
        planner.collect_inputs(args, "dut", None)
    args.platform_json = str(fixture["platform"])
    args.peer_platform_json = str(fixture["peer"])
    args.pg_profile_lookup = str(fixture["lookup"])
    monkeypatch.setattr(planner.subprocess, "run", lambda *args, **kwargs: pytest.fail("Unexpected device access"))
    assert planner.collect_inputs(args, "dut", None) is None


@pytest.mark.parametrize("nested", [False, True])
def test_collection_rejects_snapshots_inside_scenario(fixture, tmp_path, monkeypatch, nested):
    """Collection must not create the scenario directory before atomic artifact publication."""
    args = collection_args(fixture, tmp_path)
    inventory = tmp_path / "inventory"
    inventory.write_text("dut\nleaf\n")
    args.inventory = [str(inventory)]
    args.snapshot_dir = str(Path(args.output_dir) / "inputs") if nested else args.output_dir
    monkeypatch.setattr(planner.subprocess, "run", lambda *args, **kwargs: pytest.fail("Unexpected device access"))
    with pytest.raises(ValueError, match="separate from and outside"):
        planner.collect_inputs(args, "dut", None)
    assert not Path(args.output_dir).exists()


def test_partial_collection_uses_inventory_and_vault_options(fixture, tmp_path, monkeypatch):
    """Keep supplied snapshots and request only the missing DUT lookup through Ansible."""
    args = collection_args(fixture, tmp_path)
    args.platform_json, args.peer_platform_json = str(fixture["platform"]), str(fixture["peer"])
    inventory = tmp_path / "inventory"
    inventory.write_text("dut\nleaf\n")
    vault = tmp_path / "vault-password"
    vault.write_text("test-only")
    args.inventory, args.vault_password_file = [str(inventory)], str(vault)

    def run(command, **kwargs):
        assert command[command.index("-i") + 1] == str(inventory)
        assert command[command.index("--vault-password-file") + 1] == str(vault)
        variables = Path(command[command.index("--extra-vars") + 1][1:])
        request = json.loads(variables.read_text())
        assert request["generic_requests"] == {"dut": ["pg_profile_lookup.ini"]}
        response = {"platform": "test-platform", "hwsku": "test-sku", "files": {
            "pg_profile_lookup.ini": {"remote_path": "/device/test-platform/pg_profile_lookup.ini",
                                      "content": fixture["lookup"].read_text()},
        }}
        (Path(request["generic_collection_dir"]) / "dut.json").write_text(json.dumps(response))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(planner.subprocess, "run", run)
    provenance = planner.collect_inputs(args, "dut", None)
    assert args.platform_json == str(fixture["platform"])
    assert args.peer_platform_json == str(fixture["peer"])
    assert Path(args.pg_profile_lookup).read_bytes() == fixture["lookup"].read_bytes()
    assert set(json.loads(Path(provenance).read_text())) == {"dut"}
    assert not (Path(provenance).parent / "vault-password").exists()


@pytest.mark.parametrize("timeout", [False, True])
def test_failed_collection_does_not_publish_snapshots(fixture, tmp_path, monkeypatch, timeout):
    """Failure or timeout must leave no usable snapshot set and must not continue offline."""
    args = collection_args(fixture, tmp_path)
    inventory = tmp_path / "inventory"
    inventory.write_text("dut\nleaf\n")
    args.inventory = [str(inventory)]

    def run(command, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(planner.subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired if timeout else ValueError):
        planner.collect_inputs(args, "dut", None)
    assert not Path(args.output_dir + ".inputs").exists()
    assert list(tmp_path.glob(".generic-inputs-*")) == []


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="Ansible CLI is required")
@pytest.mark.parametrize("connection", ["local", "multi_passwd_ssh", "network_cli"])
def test_collection_playbook_with_local_inventory(fixture, tmp_path, monkeypatch, capfd, connection):
    """Accept inventory SSH wrappers but reject network CLI before running the simulated probe."""
    ansible_dir = tmp_path / "ansible"
    scripts = ansible_dir / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(SCRIPTS.parent / "collect_generic_inputs.yml", ansible_dir / "collect_generic_inputs.yml")
    response = {
        "platform": "test-platform", "hwsku": "test-sku",
        "files": {
            "platform.json": {"remote_path": "/device/test-platform/platform.json",
                              "content": fixture["platform"].read_text()},
            "pg_profile_lookup.ini": {"remote_path": "/device/test-platform/pg_profile_lookup.ini",
                                      "content": fixture["lookup"].read_text()},
        },
    }
    (scripts / "collect_generic_device.py").write_text("print({!r})\n".format(json.dumps(response)))
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"hosts": {
        "dut": {"ansible_connection": connection}, "leaf": {"ansible_connection": "local"},
    }}}))
    plugins = ansible_dir / "plugins/connection"
    plugins.mkdir(parents=True)
    if connection != "local":
        (plugins / (connection + ".py")).write_text(
            "from ansible.plugins.connection.local import Connection, DOCUMENTATION\n")
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled = False\nconnection_plugins = {}\n".format(plugins))
    monkeypatch.setenv("ANSIBLE_CONFIG", str(config))
    monkeypatch.setattr(planner, "__file__", str(scripts / "plan_generic_topology.py"))
    args = collection_args(fixture, tmp_path)
    args.inventory = [str(inventory)]
    if connection == "network_cli":
        with pytest.raises(ValueError, match="Read-only Ansible collection failed"):
            planner.collect_inputs(args, "dut", None)
        assert "Generic collection requires SONiC shell access" in capfd.readouterr().out
        assert not Path(args.output_dir + ".inputs").exists()
        return
    provenance = planner.collect_inputs(args, "dut", None)
    assert Path(args.platform_json).read_bytes() == fixture["platform"].read_bytes()
    assert Path(args.peer_platform_json).read_bytes() == fixture["peer"].read_bytes()
    assert Path(args.pg_profile_lookup).read_bytes() == fixture["lookup"].read_bytes()
    assert json.loads(Path(provenance).read_text())["dut"]["hostname"] == "dut"
    dut, peer = planner.load_device(args.platform_json), planner.load_device(args.peer_platform_json)
    lookup = planner.load_lookup(args.pg_profile_lookup)
    mapping = planner.build_mapping(fixture["links"], "dut", "leaf", dut, peer, lookup)
    result = planner.build_scenario(
        mapping, dut, peer, lookup, fixture["settings"], min_same_breakout_uplinks=fixture["uplink_minimum"])
    assert result["coverage.json"]["status"] == "complete"
    with pytest.raises(ValueError, match="Snapshot directory already exists"):
        planner.collect_inputs(collection_args(fixture, tmp_path), "dut", {"inv_name": inventory.name})
    missing = collection_args(fixture, tmp_path)
    missing.output_dir = str(tmp_path / "missing-host-scenario")
    missing.peer_hostname = "absent-leaf"
    with pytest.raises(ValueError, match="Ansible collection failed"):
        planner.collect_inputs(missing, "dut", {"inv_name": inventory.name})
    assert not Path(missing.output_dir + ".inputs").exists()


def test_joint_layout_and_forwarding_are_deterministic(fixture):
    """Cover modes/cases, pair whole channels, and allocate all children without input writes."""
    before = {name: path.read_bytes() for name, path in fixture.items() if isinstance(path, Path)}
    result = generate(fixture)
    assert result == generate(fixture)
    assert before == {name: fixture[name].read_bytes() for name in before}
    assert result["coverage.json"]["status"] == "complete"
    assert result["coverage.json"]["covered_modes"] == ["1x200G[100G]", "2x100G"]
    connections = result["resolved_facts.json"]["connections"]
    assert {(link["buffer_case"]["speed"], link["buffer_case"]["cable"]) for link in connections} == {
        ("100000", "5m"), ("100000", "40m"), ("200000", "5m")}
    for link in connections:
        assert link["dut"]["atoms"] == link["peer"]["atoms"]
        assert link["dut"]["speed"] == link["peer"]["speed"] == int(link["buffer_case"]["speed"])
        assert not link["connectivity_verified"]
    manifest = result["manifest.json"]
    assert not manifest["deployable"]
    assert sum(len(choice["children"]) for choice in manifest["selected_layouts"]["dut"].values()) == len(connections)
    uplinks = [link for link in connections if link["role"] == "uplink"]
    downlinks = [link for link in connections if link["role"] == "downlink"]
    actual = {link["dut"]["port"] for link in connections}
    assert {link["dut"]["port"] for link in uplinks} == actual & {"Ethernet8", "Ethernet9"}
    assert {link["dut"]["port"] for link in downlinks} == actual - {"Ethernet8", "Ethernet9"}
    assert result["resolved_facts.json"]["role_resolution"]["ignored_ports"]["uplink"] == ["Ethernet9"]
    assert manifest["policy"]["role_granularity"] == "child_port"
    assert downlinks and all(link["vlan_id"] == 1000 for link in downlinks)
    assert len({link["endpoint_address"] for link in connections}) == len(connections)
    forwarding = result["resolved_facts.json"]["forwarding"]
    assert len(forwarding["static_routes"]) == len(uplinks) + 1
    assert forwarding["svi"] == "198.51.100.1/24"
    assert "VMs" not in result["topology.yml"]["topology"]


def test_reordered_csv_does_not_change_plan(fixture):
    """Stable canonical identities, not input row ordering, control allocation."""
    first = generate(fixture)
    lines = fixture["links"].read_text().splitlines()
    fixture["links"].write_text("\n".join(lines[:1] + list(reversed(lines[1:]))) + "\n")
    assert first == generate(fixture)


def test_explicit_roles_span_cages_and_split_sibling_roles(fixture):
    """Roles belong to final children, not to the lowest cage or whole cages."""
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet16", "Ethernet1"]
    fixture["settings"]["physical_links"]["downlinks"] = ["Ethernet0"]
    result = generate(fixture)
    facts = result["resolved_facts.json"]
    roles = {link["dut"]["port"]: link["role"] for link in facts["connections"]}
    assert roles == {"Ethernet0": "downlink", "Ethernet1": "uplink",
                     "Ethernet8": "downlink", "Ethernet16": "uplink"}
    assert facts["forwarding"]["static_routes"]["0.0.0.0/0"]["ifname"] == "Ethernet1"
    fixture["settings"]["physical_links"]["uplinks"].reverse()
    fixture["settings"]["physical_links"]["downlinks"].reverse()
    reordered = generate(fixture)["resolved_facts.json"]
    assert reordered == facts


def test_one_cage_can_supply_both_explicit_roles(fixture):
    """A split cage can have a routed child and an access child without a two-cage minimum."""
    data = json.loads(fixture["platform"].read_text())
    data["interfaces"] = {"Ethernet8": data["interfaces"]["Ethernet8"]}
    del data["interfaces"]["Ethernet8"]["breakout_modes"]["1x200G[100G]"]
    for side in ("platform", "peer"):
        fixture[side].write_text(json.dumps(data))
    rows = fixture["links"].read_text().splitlines()
    fixture["links"].write_text("\n".join(rows[:1] + rows[3:5]) + "\n")
    fixture["lookup"].write_text("# speed cable size xon xoff threshold\n"
                                 "100000 5m 100 20 30 1\n100000 40m 200 20 40 2\n")
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet8"]
    fixture["settings"]["physical_links"]["downlinks"] = ["Ethernet9"]
    result = generate(fixture)
    assert {link["dut"]["port"]: link["role"] for link in result["resolved_facts.json"]["connections"]} == {
        "Ethernet8": "uplink", "Ethernet9": "downlink"}
    assert set(result["manifest.json"]["selected_layouts"]["dut"]) == {"Ethernet8"}


@pytest.mark.parametrize("ports", [None, "Ethernet8", [8], ["etp2a"], ["PortChannel1"],
                                   ["Ethernet08"], ["Ethernet8", "Ethernet8"]])
def test_invalid_role_declarations_fail_before_collection(fixture, tmp_path, monkeypatch, ports):
    """Unset uplinks, malformed selectors, and duplicate declarations cannot trigger collection."""
    fixture["settings"]["physical_links"]["uplinks"] = ports
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    monkeypatch.setattr(planner, "collect_inputs", lambda *args: pytest.fail("Unexpected device collection"))
    options = planner_options(fixture, tmp_path / "invalid")
    monkeypatch.setattr(sys, "argv", ["planner", "--hostname", "dut"] + options)
    with pytest.raises(SystemExit) as caught:
        planner.main()
    assert caught.value.code == 1
    assert not (tmp_path / "invalid").exists()


def test_missing_role_declaration_has_no_automatic_fallback(fixture):
    """Old recipes must be migrated instead of receiving implicit cage-based roles."""
    del fixture["settings"]["physical_links"]["uplinks"]
    with pytest.raises(ValueError, match="physical_links.uplinks"):
        generate(fixture)


@pytest.mark.parametrize("case", ["unknown", "unassigned_cage", "extra_children"])
def test_role_selectors_do_not_require_exact_cage_children(fixture, case):
    """Ignore unavailable names and default undeclared active children without changing the layout."""
    original = generate(fixture)
    if case == "unknown":
        fixture["settings"]["physical_links"]["uplinks"].append("Ethernet1000")
    elif case == "unassigned_cage":
        fixture["settings"]["physical_links"]["downlinks"].remove("Ethernet16")
    else:
        fixture["settings"]["physical_links"]["downlinks"].extend(["Ethernet1", "Ethernet17"])
    settings = deepcopy(fixture["settings"])
    result = generate(fixture)
    assert fixture["settings"] == settings
    assert result["manifest.json"]["selected_layouts"] == original["manifest.json"]["selected_layouts"]
    assert result["resolved_facts.json"]["connections"] == original["resolved_facts.json"]["connections"]
    resolution = result["resolved_facts.json"]["role_resolution"]
    if case == "unknown":
        assert resolution["ignored_ports"]["uplink"] == ["Ethernet9", "Ethernet1000"]
    elif case == "unassigned_cage":
        assert "Ethernet16" in resolution["defaulted_downlinks"]
    else:
        assert "Ethernet17" in resolution["ignored_ports"]["downlink"]


@pytest.mark.parametrize("downlink_ports", [None, [], "omitted"])
def test_all_other_selected_links_default_to_downlink(fixture, downlink_ports):
    """An explicit downlink list is optional; remaining selected interfaces are access links."""
    if downlink_ports == "omitted":
        del fixture["settings"]["physical_links"]["downlinks"]
    else:
        fixture["settings"]["physical_links"]["downlinks"] = downlink_ports
    result = generate(fixture)
    facts = result["resolved_facts.json"]
    roles = {link["dut"]["port"]: link["role"] for link in facts["connections"]}
    assert roles == {"Ethernet0": "downlink", "Ethernet1": "downlink",
                     "Ethernet8": "uplink", "Ethernet16": "downlink"}
    assert facts["role_resolution"]["defaulted_downlinks"] == ["Ethernet0", "Ethernet1", "Ethernet16"]


def test_conflicting_roles_only_apply_to_existing_selected_links(fixture):
    """Unmatched conflicting names are ignored, but an actual link cannot have two explicit roles."""
    settings = fixture["settings"]
    settings["physical_links"]["uplinks"].append("Ethernet999")
    settings["physical_links"]["downlinks"].append("Ethernet999")
    result = generate(fixture)
    assert "Ethernet999" not in result["manifest.json"]["policy"]["port_assignments"]
    settings["physical_links"]["downlinks"].append("Ethernet8")
    with pytest.raises(ValueError, match="conflicting uplink/downlink roles"):
        generate(fixture)


def test_no_matching_uplink_produces_review_only_layout(fixture):
    """Ignoring all unavailable selectors must not invent an uplink or a default route."""
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet999"]
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert "at least one matching selected uplink" in result["coverage.json"]["allocation_error"]
    assert result["resolved_facts.json"]["forwarding"] is None
    assert all(link["role"] == "downlink" for link in result["resolved_facts.json"]["connections"])


def test_all_possible_children_selected_as_uplinks_remain_review_only(fixture):
    """A physically valid layout without a T0 downlink cannot become deployable."""
    fixture["settings"]["physical_links"]["uplinks"] = [
        "Ethernet0", "Ethernet1", "Ethernet8", "Ethernet9", "Ethernet16", "Ethernet17"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert "at least one selected downlink" in result["coverage.json"]["allocation_error"]
    assert not result["manifest.json"]["deployable"]


def test_role_feasibility_keeps_a_compatible_split_child_candidate(fixture):
    """Role pruning must retain a valid uniform split when an aggregate would lose the only uplink."""
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet9"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    result = generate(fixture)
    assert result["manifest.json"]["selected_layouts"]["dut"]["Ethernet8"]["mode"] == "2x100G"
    roles = {link["dut"]["port"]: link["role"] for link in result["resolved_facts.json"]["connections"]}
    assert {port for port, role in roles.items() if role == "uplink"} == {"Ethernet9"}
    assert any(role == "downlink" for role in roles.values())


def test_csv_planning_prioritizes_required_uplinks_over_diversity(fixture, tmp_path):
    """Best-effort CSV planning preserves the hard repeated-uplink requirement before maximizing coverage."""
    fixture["uplink_minimum"] = 4
    fixture["settings"]["physical_links"]["uplinks"] = [
        "Ethernet0", "Ethernet1", "Ethernet8", "Ethernet9", "Ethernet999"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    result = generate(fixture)
    assert result["coverage.json"]["breakout_diversity"]["complete"]
    facts = result["resolved_facts.json"]
    assert {link["dut"]["port"] for link in facts["connections"] if link["role"] == "uplink"}.issubset({
        "Ethernet0", "Ethernet1", "Ethernet8", "Ethernet9"})
    assert "Ethernet999" in facts["role_resolution"]["ignored_ports"]["uplink"]
    repetition = result["coverage.json"]["uplink_repetition"]
    assert not repetition["complete"]
    assert sum(row["required"] for row in repetition["groups"]) == 1
    assert all(row["shortfall"] > 0 for row in repetition["groups"] if row["required"])
    assert all(row["shortfall"] == 0 for row in repetition["groups"] if not row["required"])
    assert result["coverage.json"]["status"] == "incomplete"
    assert result["manifest.json"]["policy"]["min_same_breakout_uplinks"] == 4
    assert "min_same_breakout_uplinks" not in result["topology.yml"]["generic_topology"]["constraints"]
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    output = tmp_path / "four-uplinks"
    completed = cli(fixture, output)
    assert completed.returncode == 0, completed.stderr
    coverage = json.loads((output / "coverage.json").read_text())
    assert coverage["status"] == "incomplete"
    assert coverage["deployment_eligible"]
    assert coverage["uplink_repetition"]["complete"]
    assert not coverage["breakout_diversity"]["complete"]


def test_initial_planning_option_is_frozen_without_entering_yaml(fixture, tmp_path):
    """A planning-time count drives layout selection and persists only as manifest policy."""
    fixture["uplink_minimum"] = 2
    output = tmp_path / "two-uplinks"
    completed = cli(fixture, output)
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "manifest.json").read_text())
    coverage = json.loads((output / "coverage.json").read_text())
    topology = yaml.safe_load((output / "topology.yml").read_text())
    assert manifest["policy"]["min_same_breakout_uplinks"] == 2
    assert coverage["required_same_breakout_uplinks"] == coverage["uplink_repetition"]["minimum"] == 2
    assert any(group["uplink_count"] >= 2 for group in coverage["uplink_repetition"]["groups"])
    assert topology["generic_topology"] == fixture["settings"]
    fixture["uplink_minimum"] = 4
    completed = cli(fixture, tmp_path / "four-uplinks")
    assert completed.returncode == 0, completed.stderr
    assert json.loads((tmp_path / "four-uplinks/coverage.json").read_text())["status"] == "incomplete"


def test_yaml_repetition_setting_is_rejected_before_collection(fixture, tmp_path, monkeypatch, capsys):
    """Old YAML repetition values must not silently override the initial planning decision."""
    fixture["settings"]["constraints"]["min_same_breakout_uplinks"] = 1
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    monkeypatch.setattr(planner, "collect_inputs", lambda *args: pytest.fail("Unexpected device collection"))
    monkeypatch.setattr(sys, "argv", ["planner", "--hostname", "dut"] + planner_options(fixture, tmp_path / "invalid"))
    with pytest.raises(SystemExit) as caught:
        planner.main()
    assert caught.value.code == 1
    assert "Invalid generic_topology.constraints settings" in capsys.readouterr().err
    assert not (tmp_path / "invalid").exists()


def test_insufficient_matching_uplinks_publish_explicit_review_plan(fixture, tmp_path):
    """Nonexistent selectors cannot rescue a group shortfall, but the physical plan remains reviewable."""
    fixture["uplink_minimum"] = 4
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet0", "Ethernet1", "Ethernet8", "Ethernet999"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert result["coverage.json"]["required_same_breakout_uplinks"] == 4
    assert any(row["shortfall"] for row in result["coverage.json"]["uplink_repetition"]["groups"])
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    output = tmp_path / "insufficient-uplinks"
    completed = cli(fixture, output)
    assert completed.returncode == 0, completed.stderr
    assert (output / "manifest.json").is_file()
    assert json.loads((output / "coverage.json").read_text())["status"] == "incomplete"


@pytest.mark.parametrize("same_speed_only", [False, True])
def test_four_uplinks_split_between_breakout_groups_do_not_satisfy_minimum(fixture, same_speed_only):
    """Mode coverage may permit four uplinks overall without four in any one breakout group."""
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet0", "Ethernet1", "Ethernet8", "Ethernet16"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    if same_speed_only:
        fixture["lookup"].write_text("# speed cable size xon xoff threshold\n"
                                     "100000 5m 100 20 30 1\n100000 40m 200 20 40 2\n")
    baseline = generate(fixture)
    uplinks = [link for link in baseline["resolved_facts.json"]["connections"] if link["role"] == "uplink"]
    assert len(uplinks) >= 3
    if same_speed_only:
        assert {link["dut"]["speed"] for link in uplinks} == {100000}
    fixture["uplink_minimum"] = 4
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert not result["coverage.json"]["uplink_repetition"]["complete"]


@pytest.mark.parametrize("difference", [None, "mode", "speed"])
def test_matching_uplinks_count_physical_links_and_selected_speed(difference):
    """Five matching links pass; splitting four links by mode or operating speed must fail."""
    layout, assignments = {}, {}
    for index in range(5 if difference is None else 4):
        base = index * 8
        mode, speed, count = "2x200G[100G]", 200000, 2
        if index == 3 and difference == "mode":
            mode, count = "4x200G", 4
        elif index == 3 and difference == "speed":
            speed = 100000
        children = [{"port": "Ethernet{}".format(base + child), "speed": speed} for child in range(count)]
        layout["Ethernet{}".format(base)] = {"mode": mode, "speed": speed, "children": children}
        assignments.update({child["port"]: "uplink" if offset == 0 else "downlink"
                            for offset, child in enumerate(children)})
    if difference is None:
        assert planner.validate_uplink_repetition(layout, assignments) == {
            "minimum": 4, "complete": True,
            "groups": [{"mode": "2x200G[100G]", "speed": 200000, "uplink_count": 5, "shortfall": 0}]}
    else:
        repetition = planner.validate_uplink_repetition(layout, assignments)
        assert not repetition["complete"]
        assert len(repetition["groups"]) == 2
        assert all(row["shortfall"] > 0 for row in repetition["groups"])


@pytest.mark.parametrize("different_variant", [False, True])
def test_mixed_repetition_pools_child_speeds_but_not_operating_combinations(different_variant):
    """Count four mixed-speed uplinks together only when their full operating combinations match."""
    mode = "4x100G[50G](4)+1x400G(4)"
    layouts, assignments = {}, {}
    for base in (0, 8):
        speed = 50000 if base and different_variant else 100000
        children = [{"port": "Ethernet{}".format(base + offset),
                     "speed": 400000 if offset == 4 else speed} for offset in range(5)]
        layouts["Ethernet{}".format(base)] = {
            "mode": mode, "speed": [speed, 400000], "children": children}
        assignments.update({child["port"]: "uplink" if index in (0, 4) else "downlink"
                            for index, child in enumerate(children)})
    repetition = planner.validate_uplink_repetition(layouts, assignments, 4)
    assert repetition["complete"] is not different_variant
    assert sorted(row["uplink_count"] for row in repetition["groups"]) == (
        [2, 2] if different_variant else [4])


@pytest.mark.parametrize("minimum,exit_code", [(0, 1), (-1, 1), ("true", 2), ("4.0", 2), ("none", 2)])
def test_invalid_uplink_repetition_fails_before_collection(fixture, tmp_path, monkeypatch, minimum, exit_code):
    """A malformed repetition count must not trigger device collection."""
    monkeypatch.setattr(planner, "collect_inputs", lambda *args: pytest.fail("Unexpected device collection"))
    options = planner_options(fixture, tmp_path / "invalid")
    monkeypatch.setattr(sys, "argv", ["planner", "--hostname", "dut"] + options + [
        "--min-same-breakout-uplinks", str(minimum)])
    with pytest.raises(SystemExit) as caught:
        planner.main()
    assert caught.value.code == exit_code
    assert not (tmp_path / "invalid").exists()


def test_cages_use_uniform_breakouts_including_two_by_200g(fixture):
    """Different cages may differ, but every child in one cage has one shared selected speed."""
    for side in ("platform", "peer"):
        data = json.loads(fixture[side].read_text())
        for cage in data["interfaces"].values():
            modes = cage["breakout_modes"]
            cage["breakout_modes"] = {"1x400G[200G]": modes["1x200G[100G]"], "2x200G": modes["2x100G"]}
        fixture[side].write_text(json.dumps(data))
    fixture["links"].write_text(fixture["links"].read_text().replace("100000", "200000"))
    fixture["lookup"].write_text(fixture["lookup"].read_text().replace("200000", "400000")
                                 .replace("100000", "200000"))
    result = generate(fixture)
    for layouts in result["manifest.json"]["selected_layouts"].values():
        assert any(choice["mode"] == "2x200G" for choice in layouts.values())
        for choice in layouts.values():
            assert {child["speed"] for child in choice["children"]} == {choice["speed"]}


def test_mixed_breakout_without_explicit_lane_partitions_is_rejected(fixture):
    """A mixed speed string without lane widths cannot authorize guessed physical partitions."""
    data = json.loads(fixture["platform"].read_text())
    data["interfaces"]["Ethernet0"]["breakout_modes"]["1x100G+1x200G"] = ["mixed-a", "mixed-b"]
    fixture["platform"].write_text(json.dumps(data))
    with pytest.raises(ValueError, match="require explicit lane counts"):
        generate(fixture)


def test_peer_modes_cannot_be_selected_independently(fixture):
    """A local aggregate mode must not survive when the peer can only split."""
    data = json.loads(fixture["peer"].read_text())
    for cage in data["interfaces"].values():
        del cage["breakout_modes"]["1x200G[100G]"]
    fixture["peer"].write_text(json.dumps(data))
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert all(choice["mode"] == "2x100G" for choice in result["manifest.json"]["selected_layouts"]["dut"].values())
    assert any(row["mode"] == "1x200G[100G]" and row["cage_count"] == 0
               for row in result["coverage.json"]["breakout_diversity"]["groups"])


def test_peer_mode_names_need_not_match_dut_mode_names(fixture):
    """Match child channel sets and operating speeds rather than mode-key strings."""
    data = json.loads(fixture["peer"].read_text())
    for cage in data["interfaces"].values():
        cage["breakout_modes"]["1x200G"] = cage["breakout_modes"].pop("1x200G[100G]")
    fixture["peer"].write_text(json.dumps(data))
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert any(value["mode"] == "1x200G"
               for value in result["manifest.json"]["selected_layouts"]["peer"].values())


def test_cross_cage_wiring_rejects_aggregation(fixture):
    """Do not combine channels whose endpoints belong to distinct remote cages."""
    text = fixture["links"].read_text()
    text = text.replace("leaf,Ethernet0,", "leaf,TEMP,")
    text = text.replace("leaf,Ethernet8,", "leaf,Ethernet0,").replace("leaf,TEMP,", "leaf,Ethernet8,")
    fixture["links"].write_text(text)
    fixture["settings"]["physical_links"]["downlinks"].append("Ethernet1")
    result = generate(fixture)
    for side in ("dut", "peer"):
        assert result["manifest.json"]["selected_layouts"][side]["Ethernet0"]["mode"] == "2x100G"
        assert result["manifest.json"]["selected_layouts"][side]["Ethernet8"]["mode"] == "2x100G"


def test_infeasible_case_capacity_is_not_reported_as_success(fixture):
    """Lookup-case coverage requires one available active child per distinct case."""
    with fixture["lookup"].open("a") as handle:
        for length in range(10, 20):
            handle.write("100000 {}m 1 2 3 4\n".format(length))
    coverage = generate(fixture)["coverage.json"]
    assert coverage["status"] == "incomplete"
    assert len(coverage["covered_buffer_cases"]) < len(coverage["required_buffer_cases"])


def test_lookup_missing_speed_is_reported_and_not_selected(fixture):
    """An alternate speed remains usable without inventing the missing nominal case."""
    fixture["lookup"].write_text("# speed cable size xon xoff threshold\n100000 5m 1 2 3 4\n")
    result = generate(fixture)
    assert all(link["dut"]["speed"] == 100000 for link in result["resolved_facts.json"]["connections"])
    assert any(item["speed"] == 200000 for item in result["coverage.json"]["rejected_candidates"])


def test_protected_cage_remains_outside_layout(fixture):
    """An out-of-scope peer protects the whole connected cage."""
    fixture["links"].write_text(fixture["links"].read_text().replace(
        "dut,Ethernet17,leaf,Ethernet16", "dut,Ethernet17,arista,Ethernet16"))
    result = generate(fixture)
    assert "Ethernet16" in result["manifest.json"]["protected_dut_cages"]
    assert "Ethernet16" not in result["manifest.json"]["selected_layouts"]["dut"]
    assert not any(link["dut"]["cage"] == "Ethernet16"
                   for link in result["resolved_facts.json"]["connections"])
    assert "Ethernet16" in result["resolved_facts.json"]["role_resolution"]["ignored_ports"]["downlink"]


def test_search_limit_is_unknown_feasibility(fixture):
    """A bounded search cannot claim a layout is mathematically impossible."""
    with pytest.raises(planner.PlanningError) as caught:
        generate(fixture, max_states=1)
    assert caught.value.coverage["status"] == "search_limit_reached"


@pytest.mark.parametrize("section,field,value,message", [
    ("access_vlan", "subnet", "192.0.2.0/24", "overlap"),
    ("access_vlan", "subnet", "198.51.100.0/30", "access subnet address capacity"),
    ("access_vlan", "vlan_id", 4095, "integer from"),
    ("routed_interfaces", "prefix_length", 32, "prefix length"),
    ("external_destinations", "address_pool", "203.0.113.1/32", "destination capacity"),
])
def test_invalid_address_allocations_fail(fixture, section, field, value, message):
    """Reject unsafe or insufficient allocations before publishing scenario files."""
    fixture["settings"][section][field] = value
    if section == "external_destinations":
        fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet0", "Ethernet8", "Ethernet16"]
        fixture["settings"]["physical_links"]["downlinks"] = []
    if "capacity" in message:
        coverage = generate(fixture)["coverage.json"]
        assert coverage["status"] == "incomplete"
        assert message in coverage["allocation_error"]
    else:
        with pytest.raises(ValueError, match=message):
            generate(fixture)


def test_ipv6_forwarding_uses_ipv6_default_route(fixture):
    """Use bounded allocations for IPv6 pools without enumerating every subnet."""
    settings = fixture["settings"]
    settings["routed_interfaces"].update(address_pool="2001:db8:1::/64", prefix_length=127)
    settings["access_vlan"]["subnet"] = "2001:db8:2::/64"
    settings["external_destinations"] = {"address_pool": "2001:db8:3::/64", "prefix_length": 128}
    result = generate(fixture)
    forwarding = result["resolved_facts.json"]["forwarding"]
    assert "::/0" in forwarding["static_routes"]
    assert forwarding["svi"] == "2001:db8:2::1/64"


def test_address_capacity_cannot_override_explicit_roles(fixture):
    """An undersized pool must not silently reduce the requested uplink count."""
    fixture["settings"]["routed_interfaces"]["address_pool"] = "192.0.2.0/31"
    fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet0", "Ethernet8", "Ethernet16"]
    fixture["settings"]["physical_links"]["downlinks"] = []
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "incomplete"
    assert "routed-interface address capacity" in result["coverage.json"]["allocation_error"]
    assert sum(link["role"] == "uplink" for link in result["resolved_facts.json"]["connections"]) == 3


def test_reserved_resources_and_field_level_overrides(fixture, tmp_path):
    """Host field overrides preserve group/default fields and reservation checks."""
    group = tmp_path / "group.yml"
    host = tmp_path / "host.yml"
    group.write_text(yaml.safe_dump({"generic_topology": {"access_vlan": {"vlan_id": 1100}}}))
    host.write_text(yaml.safe_dump({"generic_topology": {"access_vlan": {"vlan_id": 1200}}}))
    settings = planner.load_recipe([fixture["recipe"], group, host])
    assert settings["access_vlan"] == {
        "vlan_id": 1200, "subnet": "198.51.100.0/24"}
    assert settings["physical_links"] == fixture["settings"]["physical_links"]
    settings["constraints"].update(reserved_vlan_ids=[1200])
    with pytest.raises(ValueError, match="reserved VLAN"):
        planner.build_scenario(*inputs(fixture), settings, min_same_breakout_uplinks=fixture["uplink_minimum"])
    settings["constraints"].update(reserved_vlan_ids=[], reserved_networks=["192.0.2.128/25"])
    with pytest.raises(ValueError, match="reserved network"):
        planner.build_scenario(*inputs(fixture), settings, min_same_breakout_uplinks=fixture["uplink_minimum"])


def test_cli_artifacts_hashes_and_no_overwrite(fixture, tmp_path):
    """Publish only offline artifacts, with verified hashes and no destructive overwrite."""
    output = tmp_path / "scenario"
    completed = cli(fixture, output)
    assert completed.returncode == 0, completed.stderr
    assert "Ignored unmatched uplink interface selectors: Ethernet9" in completed.stdout
    assert {path.name for path in output.iterdir()} == {
        "manifest.json", "coverage.json", "topology.yml", "resolved_facts.json"}
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["recipe_paths"] == [str(fixture["recipe"].resolve())]
    for name, digest in manifest["artifact_sha256"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    for name, digest in manifest["source_sha256"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest
    before = (output / "manifest.json").read_bytes()
    completed = cli(fixture, output)
    assert completed.returncode == 1
    assert "already exists" in completed.stderr
    assert (output / "manifest.json").read_bytes() == before


def test_cli_failure_publishes_only_coverage(fixture, tmp_path):
    """An infeasible plan leaves a diagnostic report, never success-shaped config artifacts."""
    output = tmp_path / "failed"
    data = json.loads(fixture["peer"].read_text())
    for cage in data["interfaces"].values():
        del cage["breakout_modes"]["1x200G[100G]"]
    fixture["lookup"].write_text("# speed cable size xon xoff threshold\n200000 5m 300 20 50 3\n")
    fixture["peer"].write_text(json.dumps(data))
    completed = cli(fixture, output)
    assert completed.returncode == 2
    assert [path.name for path in output.iterdir()] == ["coverage.json"]
    assert json.loads((output / "coverage.json").read_text())["status"] == "infeasible"


def test_internal_planner_generates_offline_scenario(fixture, tmp_path):
    """Resolve testbed identity through the internal planner without legacy topology mutation."""
    testbeds = tmp_path / "testbed definitions.yml"
    testbeds.write_text(yaml.safe_dump([{
        "conf-name": "tb-generic", "dut": ["dut"], "topo": "t0",
        "use_converged_peers": True, "ptf": "ptf-test", "ptf_ip": "192.0.2.100/24",
    }]))
    original = testbeds.read_bytes()
    output = tmp_path / "scenario output"
    command = [sys.executable, str(SCRIPTS / "plan_generic_topology.py"),
               "--testbed-file", str(testbeds), "--testbed", "tb-generic"] + planner_options(fixture, output)
    completed = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["hostname"] == "dut"
    assert manifest["testbed"]["conf-name"] == "tb-generic"
    assert manifest["testbed"]["ptf"] == "ptf-test"
    assert str(testbeds.resolve()) in manifest["source_sha256"]
    assert testbeds.read_bytes() == original
    conflicting_output = tmp_path / "conflicting"
    completed = subprocess.run(command + ["--hostname", "other", "--output-dir", str(conflicting_output)],
                               cwd=tmp_path, capture_output=True, text=True)
    assert completed.returncode == 2
    assert "not allowed with argument --testbed" in completed.stderr
    assert not conflicting_output.exists()
    completed = subprocess.run(command + ["--max-search-states", "1", "--output-dir", str(tmp_path / "failed")],
                               cwd=tmp_path, capture_output=True, text=True)
    assert completed.returncode == 2
    assert json.loads((tmp_path / "failed/coverage.json").read_text())["status"] == "search_limit_reached"


def test_internal_planner_collects_missing_snapshots(fixture, tmp_path, monkeypatch):
    """Exercise internal collection, inventory inference, and persisted provenance without SSH."""
    inventory = tmp_path / "lab-inventory"
    inventory.write_text("dut\nleaf\n")
    testbeds = tmp_path / "testbeds.yml"
    testbeds.write_text(yaml.safe_dump([{
        "conf-name": "tb", "dut": ["dut"], "inv_name": inventory.name,
    }]))
    response = {"platform": "test-platform", "hwsku": "test-sku", "files": {
        "platform.json": {"remote_path": "/device/platform.json", "content": fixture["platform"].read_text()},
        "pg_profile_lookup.ini": {"remote_path": "/device/test-platform/pg_profile_lookup.ini",
                                  "content": fixture["lookup"].read_text()},
    }}
    binaries = tmp_path / "bin"
    binaries.mkdir()
    executable = binaries / "ansible-playbook"
    executable.write_text(
        "#!{}\n".format(sys.executable)
        + "import json, sys\nfrom pathlib import Path\n"
        + "assert sys.argv[sys.argv.index('-i') + 1] == {!r}\n".format(str(inventory))
        + "request = json.loads(Path(sys.argv[sys.argv.index('--extra-vars') + 1][1:]).read_text())\n"
        + "assert request['generic_requests'] == {'dut': ['pg_profile_lookup.ini'], 'leaf': ['platform.json']}\n"
        + "for host in request['generic_requests']:\n"
        + "    (Path(request['generic_collection_dir']) / (host + '.json')).write_text({!r})\n".format(
            json.dumps(response)))
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries) + ":" + os.environ["PATH"])
    output = tmp_path / "scenario"
    completed = subprocess.run([
        sys.executable, str(SCRIPTS / "plan_generic_topology.py"),
        "--testbed-file", str(testbeds), "--testbed", "tb",
        "--peer-hostname", "leaf", "--links-csv", str(fixture["links"]),
        "--platform-json", str(fixture["platform"]), "--recipe", str(fixture["recipe"]),
        "--output-dir", str(output), "--min-same-breakout-uplinks", str(fixture["uplink_minimum"]),
    ], cwd=tmp_path, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["collection"]["peer"]["hostname"] == "leaf"
    assert manifest["collection"]["dut"]["files"] == {
        "pg_profile_lookup.ini": "/device/test-platform/pg_profile_lookup.ini"}
    for name, digest in manifest["source_sha256"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest
    assert (tmp_path / "scenario.inputs/peer/platform.json").is_file()
    assert not (tmp_path / "scenario.inputs/dut/platform.json").exists()
    assert manifest["deployable"] is False


@pytest.mark.parametrize("entries, message", [
    ([], "found 0"),
    ([{"conf-name": "tb", "dut": ["dut"]}] * 2, "found 2"),
    ([{"conf-name": "tb", "dut": ["dut", "other"]}], "exactly one DUT"),
])
def test_testbed_resolution_rejects_ambiguous_identity(tmp_path, entries, message):
    """Never silently select the first DUT or a duplicate testbed definition."""
    path = tmp_path / "testbed.yml"
    path.write_text(yaml.safe_dump(entries))
    with pytest.raises(ValueError, match=message):
        planner.resolve_testbed(path, "tb")


def test_testbed_csv_resolution(tmp_path):
    """Accept the legacy testbed CSV identity without evaluating its contents."""
    path = tmp_path / "testbed.csv"
    path.write_text("# conf-name,topo,dut,ptf\ntb,t0,[dut],ptf-test\n")
    hostname, testbed = planner.resolve_testbed(path, "tb")
    assert hostname == "dut"
    assert testbed["ptf"] == "ptf-test"


@pytest.mark.parametrize("removed", ["plan-generic", "finalize-generic", "render-generic"])
def test_testbed_cli_rejects_removed_preparation_commands(tmp_path, removed):
    """Removed public preparation commands fail before inventory, credentials, or testbed access."""
    completed = subprocess.run(
        ["bash", str(SCRIPTS.parent / "testbed-cli.sh"), removed, "--help"],
        cwd=tmp_path, capture_output=True, text=True)
    assert completed.returncode == 1
    assert "was removed" in completed.stderr
    assert "add-topo" in completed.stderr and "deploy-mg --generic" in completed.stderr


@pytest.fixture
def complete_fixture(fixture):
    """One uplink per mode/speed and a sibling downlink on the split cage."""
    fixture["settings"]["physical_links"] = {"uplinks": ["Ethernet0", "Ethernet8", "Ethernet16"], "downlinks": []}
    fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": fixture["settings"]}))
    return fixture


@pytest.fixture
def preparation_playbooks(monkeypatch):
    """Emulate rendering and lifecycle playbooks without contacting any inventory target."""
    calls = []

    def run(args, name, variables, local, **kwargs):
        phase = variables.get("generic_action", variables.get("generic_host_action"))
        calls.append((name, phase))
        if phase != "render":
            return
        for role in ("dut", "peer"):
            request = json.loads((local / (role + "-request.json")).read_text())
            links = request["facts"]["connections"]
            ports = [link[role]["port"] for link in links]
            transport = [{"vlan_id": link["transport_vlan_id"], "ptf_index": link["ptf_index"],
                          "dut_port": link["dut"]["port"], "peer_port": link["peer"]["port"],
                          "trunk_ports": ["Ethernet999"]} for link in links]
            controller.write_private(local / (role + "-response.json"), {
                "config": {"PORT": {port: {} for port in ports}},
                "report": {"transport": transport, "owned_ports": ports, "qos_policy": "installed_lossy",
                           "exclude_managed_acls": request["exclude_managed_acls"]},
            })

    monkeypatch.setattr(controller, "run_playbook", run)
    return calls


def test_every_combination_is_represented_but_only_one_needs_four_uplinks(fixture):
    """Keep all operating combinations while concentrating N matching uplinks in a single group."""
    interfaces = {}
    for index in range(11):
        interfaces["Ethernet{}".format(index * 8)] = {
            "lanes": "{},{}".format(index * 2, index * 2 + 1),
            "breakout_modes": {"1x200G[100G]": ["p{}".format(index)],
                               "2x100G": ["p{}a".format(index), "p{}b".format(index)]},
        }
    for side in ("platform", "peer"):
        fixture[side].write_text(json.dumps({"interfaces": interfaces}))
    with fixture["links"].open("w") as handle:
        writer = csv.writer(handle)
        writer.writerow(["StartDevice", "StartPort", "EndDevice", "EndPort", "BandWidth", "VlanID"])
        for index in range(11):
            for child in range(2):
                writer.writerow(["dut", "Ethernet{}".format(index * 8 + child), "leaf",
                                 "Ethernet{}".format(index * 8 + 1 - child), 100000, 100 + index * 2 + child])
    fixture["settings"]["physical_links"] = {
        "uplinks": ["Ethernet{}".format(index * 8) for index in range(10)] + ["Ethernet65", "Ethernet73"],
        "downlinks": [],
    }
    fixture["uplink_minimum"] = 4
    result = generate(fixture)
    assert result["coverage.json"]["status"] == "complete"
    groups = result["coverage.json"]["uplink_repetition"]["groups"]
    assert {(row["mode"], row["speed"]) for row in groups} == {
        ("1x200G[100G]", 100000), ("1x200G[100G]", 200000), ("2x100G", 100000)}
    assert result["coverage.json"]["breakout_diversity"]["complete"]
    assert sum(row["required"] for row in groups) == 1
    assert all(row["uplink_count"] >= 4 for row in groups if row["required"])
    assert all(row["shortfall"] == 0 for row in groups)


def test_bounded_search_keeps_best_physical_layout_and_discloses_limit(fixture):
    """A found layout remains reviewable even when later search cannot prove optimality."""
    fixture["uplink_minimum"] = 4
    result = generate(fixture, max_states=8)
    assert result["coverage.json"]["search_limit_reached"]
    assert not result["coverage.json"]["optimality_proven"]
    assert result["coverage.json"]["status"] == "incomplete"
    assert result["manifest.json"]["selected_layouts"]


def test_unsupported_zero_cable_is_rejected_before_breakout_freeze(fixture, tmp_path):
    """Do not label a known render-fatal traditional-daemon cable case as complete coverage."""
    with fixture["lookup"].open("a") as handle:
        handle.write("100000 0m 1 2 3 4\n")
    with pytest.raises(ValueError, match="cannot assign lookup cable case 0m"):
        generate(fixture)
    output = tmp_path / "unsupported"
    result = cli(fixture, output)
    assert result.returncode == 1
    assert "0m" in result.stderr
    assert not output.exists()


def test_role_finalization_never_replans_breakouts(complete_fixture, tmp_path, monkeypatch):
    """The single editable YAML changes roles and allocations, then seals without layout changes."""
    artifacts = generate(complete_fixture)
    assert artifacts["coverage.json"]["status"] == "complete"
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "plan"
    planner.write_artifacts(plan, artifacts)
    frozen = json.loads(json.dumps(artifacts["manifest.json"]["selected_layouts"]))
    parent, split = next((parent, choice) for parent, choice in frozen["dut"].items()
                         if choice["mode"] == "2x100G")
    roles = yaml.safe_load(complete_fixture["recipe"].read_text())
    settings = roles["generic_topology"]
    settings["physical_links"]["uplinks"].remove(parent)
    settings["physical_links"]["uplinks"] += [split["children"][1]["port"], "Ethernet999"]
    settings["routed_interfaces"]["address_pool"] = "10.30.0.0/24"
    settings["access_vlan"] = {"vlan_id": 2000, "subnet": "10.40.0.0/24"}
    settings["external_destinations"]["address_pool"] = "10.50.0.0/24"
    settings["constraints"] = {"reserved_vlan_ids": [3000], "reserved_networks": ["10.60.0.0/24"]}
    settings["transport"] = {"vlan_ids": list(range(200, 240))}
    complete_fixture["recipe"].write_text(yaml.safe_dump(roles))
    loaded = controller.load_scenario(plan)
    monkeypatch.setattr(controller, "plan_from_args", lambda *args: pytest.fail("Unexpected replanning"))
    output = tmp_path / "finalized"
    result = controller.finalize(
        Namespace(scenario_dir=str(plan), output_dir=str(output)), loaded, {}, "dut")
    assert result["manifest.json"]["selected_layouts"] == frozen
    assert result["manifest.json"]["roles_finalized"]
    assert result["coverage.json"]["status"] == "complete"
    assert result["resolved_facts.json"]["role_resolution"]["ignored_ports"]["uplink"] == ["Ethernet999"]
    by_port = {link["dut"]["port"]: link for link in result["resolved_facts.json"]["connections"]}
    assert by_port[parent]["role"] == "downlink" and "dut_address" not in by_port[parent]
    assert by_port[split["children"][1]["port"]]["interface_mode"] == "routed"
    assert by_port[split["children"][1]["port"]]["dut_address"].startswith("10.30.0.")
    assert by_port[parent]["vlan_id"] == 2000
    assert result["resolved_facts.json"]["forwarding"]["svi"] == "10.40.0.1/24"
    assert result["topology.yml"]["generic_topology"] == settings
    assert result["manifest.json"]["finalized_recipe_sha256"] == planner.source_digests([complete_fixture["recipe"]])
    complete_fixture["recipe"].write_text("{}")
    assert controller.load_scenario(output)["topology.yml"]["generic_topology"] == settings
    (output / "topology.yml").write_text("{}")
    with pytest.raises(ValueError, match="artifact changed"):
        controller.load_scenario(output)


def test_incomplete_finalization_cannot_render_or_deploy(complete_fixture, tmp_path, monkeypatch):
    """Losing one required role after the freeze cannot silently trigger a new layout or deployment."""
    artifacts = generate(complete_fixture)
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "plan"
    planner.write_artifacts(plan, artifacts)
    roles = {"generic_topology": deepcopy(artifacts["topology.yml"]["generic_topology"])}
    roles["generic_topology"]["physical_links"]["uplinks"] = ["Ethernet999"]
    complete_fixture["recipe"].write_text(yaml.safe_dump(roles))
    result = controller.finalize(
        Namespace(scenario_dir=str(plan), output_dir=str(tmp_path / "finalized")),
        artifacts, {}, "dut")
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected device access"))
    assert result["coverage.json"]["status"] == "incomplete"
    assert result["resolved_facts.json"]["forwarding"] is None
    with pytest.raises(ValueError, match="review-only"):
        controller.render(Namespace(output_dir=str(tmp_path / "rendered")), result, {}, "dut")
    result["manifest.json"].update(deployable=True, requires_explicit_apply=True)
    with pytest.raises(ValueError, match="review-only"):
        controller.deploy(Namespace(action="deploy-mg", apply=True), result, {}, "dut")


@pytest.mark.parametrize("failure", ["reserved_vlan", "overlap", "manual_qos"])
def test_finalization_validates_the_complete_edited_yaml(complete_fixture, tmp_path, failure):
    """Edited allocations/exclusions are validated, and the retired manual QoS block is rejected."""
    artifacts = generate(complete_fixture)
    planner.seal_artifacts(artifacts)
    plan = tmp_path / "plan"
    planner.write_artifacts(plan, artifacts)
    document = {"generic_topology": deepcopy(artifacts["topology.yml"]["generic_topology"])}
    settings = document["generic_topology"]
    if failure == "reserved_vlan":
        settings["constraints"] = {"reserved_vlan_ids": [settings["access_vlan"]["vlan_id"]]}
    elif failure == "overlap":
        settings["routed_interfaces"]["address_pool"] = settings["access_vlan"]["subnet"]
    else:
        settings["qos"] = {"lossless_priorities": [3, 4]}
    complete_fixture["recipe"].write_text(yaml.safe_dump(document))
    output = tmp_path / "finalized"
    with pytest.raises(ValueError, match="reserved VLAN|pools overlap|Unknown generic_topology"):
        controller.finalize(
            Namespace(scenario_dir=str(plan), output_dir=str(output)), artifacts, {}, "dut")
    assert not output.exists()


@pytest.mark.parametrize("apply", [False, True])
def test_add_topo_prepares_all_stages_and_honors_apply(
        automatic_uplink_fixture, tmp_path, monkeypatch, preparation_playbooks, apply):
    """One call prepares automatic roles despite coverage gaps; only --apply mutates host/root."""
    fixture = automatic_uplink_fixture
    with fixture["lookup"].open("a") as handle:
        for cable in range(100, 112):
            handle.write("100000 {}m 100 20 30 1\n".format(cable))
    overrides = yaml.safe_load(fixture["recipe"].read_text())
    overrides["generic_topology"]["constraints"] = {"reserved_vlan_ids": [], "reserved_networks": []}
    fixture["recipe"].write_text(yaml.safe_dump(overrides))
    source = fixture["recipe"].read_bytes()
    testbed = tmp_path / "testbed.yml"
    testbed.write_text(yaml.safe_dump([{
        "conf-name": "tb", "dut": ["dut"], "topo": "generic", "inv_name": "not-a-real-inventory",
    }]))
    root = tmp_path / "automatic"
    options = planner_options(fixture, root)
    options[options.index("--recipe")] = "--overrides"
    command = ["generic_topology_cli.py", "add-topo", "--testbed-file", str(testbed), "--testbed", "tb",
               "--exclude-managed-acls"] + options
    if apply:
        command.append("--apply")
    monkeypatch.setattr(sys, "argv", command)
    controller.main()
    assert (root / "rendered").exists()
    manifest = json.loads((root / "plan/manifest.json").read_text())
    assert manifest["status"] == "breakout_frozen" and not manifest["roles_finalized"]
    assert str(SCRIPTS.parent / "vars/topo_generic.yml") in manifest["source_sha256"]
    assert manifest["recipe_paths"] == [
        str(SCRIPTS.parent / "vars/topo_generic.yml"), str(fixture["recipe"])]
    rendered = controller.load_scenario(root / "rendered")
    assert rendered["manifest.json"]["policy"]["exclude_managed_acls"]
    assert rendered["coverage.json"]["status"] == "incomplete"
    assert rendered["coverage.json"]["deployment_eligible"]
    assert rendered["topology.yml"]["generic_topology"]["physical_links"]["uplinks"] == [
        "Ethernet{}".format(index * 8) for index in range(8)]
    assert fixture["recipe"].read_bytes() == source
    expected = [("generic_devices.yml", "render")]
    if apply:
        expected += [("generic_host.yml", "add-topo"), ("fanout_connect.yml", "add-topo")]
    assert preparation_playbooks == expected
    original = (root / "plan/manifest.json").read_bytes()
    controller.main()
    assert (root / "plan/manifest.json").read_bytes() == original
    assert preparation_playbooks.count(("generic_devices.yml", "render")) == 1


@pytest.mark.parametrize("stage", ["plan", "finalized", "rendered"])
@pytest.mark.parametrize("failure", ["hostname", "testbed"])
def test_add_topo_rejects_mismatched_cached_identity(
        complete_fixture, tmp_path, monkeypatch, preparation_playbooks, stage, failure):
    """Reused stages must belong to this exact DUT and testbed before any remote operation."""
    root = planner.resolve_workspace("tb", str(tmp_path / "workspace"))
    artifacts = generate(complete_fixture, vlan_backed_only=True)
    testbed = {"conf-name": "tb", "topo": "generic"}
    artifacts["manifest.json"]["testbed"] = deepcopy(testbed)
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(root / "plan", artifacts)
    if stage != "plan":
        artifacts = controller.finalize(
            Namespace(output_dir=str(root / "finalized")), artifacts, testbed, "dut")
    if stage == "rendered":
        controller.render(Namespace(output_dir=str(root / "rendered")), artifacts, testbed, "dut")
    artifacts = controller.load_scenario(root / stage)
    if failure == "hostname":
        artifacts["manifest.json"]["hostname"] = "other-dut"
    else:
        artifacts["manifest.json"]["testbed"]["server"] = "other-host"
    planner.seal_artifacts(artifacts)
    (root / stage / "manifest.json").write_text(json.dumps(artifacts["manifest.json"]))
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected remote action"))
    with pytest.raises(ValueError, match="different testbed|does not match|settings changed"):
        controller.automatic_prepare(
            Namespace(output_dir=str(root), apply=True, action="add-topo"), testbed, "dut")


def test_add_topo_cannot_change_cached_acl_policy(
        complete_fixture, tmp_path, monkeypatch, preparation_playbooks):
    """A requested ACL exclusion cannot silently replace an already rendered policy."""
    root = planner.resolve_workspace("tb", str(tmp_path / "workspace"))
    artifacts = generate(complete_fixture, vlan_backed_only=True)
    artifacts["manifest.json"]["roles_finalized"] = True
    planner.seal_artifacts(artifacts)
    testbed = {"conf-name": "tb", "topo": "generic"}
    controller.render(Namespace(output_dir=str(root / "rendered")), artifacts, testbed, "dut")
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected remote action"))
    with pytest.raises(ValueError, match="different ACL policy"):
        controller.automatic_prepare(
            Namespace(output_dir=str(root), apply=True, action="add-topo", exclude_managed_acls=True), testbed, "dut")


def test_internal_finalization_rereads_recorded_recipe(complete_fixture, tmp_path, monkeypatch):
    """The recorded source is editable until finalization; finalized settings survive source removal."""
    testbed = tmp_path / "testbed.yml"
    testbed.write_text(yaml.safe_dump([{"conf-name": "tb", "dut": ["dut"], "topo": "generic"}]))
    plan, output = tmp_path / "plan", tmp_path / "finalized"
    command = [sys.executable, str(SCRIPTS / "plan_generic_topology.py"),
               "--testbed", "tb", "--testbed-file", str(testbed)] + planner_options(complete_fixture, plan)
    completed = subprocess.run(command, capture_output=True, text=True, cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    original = controller.load_scenario(plan)
    document = yaml.safe_load(complete_fixture["recipe"].read_text())
    document["generic_topology"]["access_vlan"]["vlan_id"] = 2000
    complete_fixture["recipe"].write_text(yaml.safe_dump(document))
    monkeypatch.chdir(tmp_path)
    controller.finalize(Namespace(output_dir=str(output)), controller.load_scenario(plan), {}, "dut")
    finalized = controller.load_scenario(output)
    assert finalized["topology.yml"]["generic_topology"]["access_vlan"]["vlan_id"] == 2000
    assert finalized["manifest.json"]["selected_layouts"] == original["manifest.json"]["selected_layouts"]
    assert finalized["manifest.json"]["source_sha256"] == original["manifest.json"]["source_sha256"]
    assert finalized["manifest.json"]["finalized_recipe_sha256"] == planner.source_digests([complete_fixture["recipe"]])
    complete_fixture["recipe"].unlink()
    assert controller.load_scenario(output) == finalized
    assert {path.name for path in plan.iterdir()} == {
        "manifest.json", "coverage.json", "topology.yml", "resolved_facts.json"}


def test_finalization_rejects_concurrent_recipe_edits(complete_fixture, tmp_path, monkeypatch):
    """Do not publish a finalized scenario with settings and provenance from different source versions."""
    artifacts = generate(complete_fixture)
    planner.seal_artifacts(artifacts)
    original_load = controller.load_recipe

    def load_and_change(paths):
        settings = original_load(paths)
        with complete_fixture["recipe"].open("a") as handle:
            handle.write("\n# concurrent edit\n")
        return settings

    monkeypatch.setattr(controller, "load_recipe", load_and_change)
    output = tmp_path / "finalized"
    with pytest.raises(ValueError, match="changed during finalization"):
        controller.finalize(Namespace(output_dir=str(output)), artifacts, {}, "dut")
    assert not output.exists()


@pytest.mark.parametrize("explicit_workspace", [False, True])
def test_workspace_is_private_and_reused_without_overwrite(
        complete_fixture, tmp_path, monkeypatch, preparation_playbooks, explicit_workspace):
    """All phases share one retained workspace; repeated preparation never replaces a frozen plan."""
    testbed = tmp_path / "testbed.yml"
    testbed.write_text(yaml.safe_dump([{
        "conf-name": "tb", "dut": ["dut"], "topo": "generic", "inv_name": "not-a-real-inventory",
    }]))
    options = planner_options(complete_fixture, tmp_path / "unused")
    index = options.index("--output-dir")
    del options[index:index + 2]
    command = ["generic_topology_cli.py", "add-topo", "--testbed-file", str(testbed), "--testbed", "tb"] + options
    root = tmp_path / "custom" if explicit_workspace else tmp_path / "sonic-generic-{}".format(os.getuid()) / "tb"
    if explicit_workspace:
        command += ["--workspace", str(root)]
    monkeypatch.setattr(controller.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(sys, "argv", command)
    original = None
    for attempt in range(2):
        controller.main()
        assert root.stat().st_mode & 0o777 == 0o700
        assert (root / "plan").stat().st_mode & 0o777 == 0o700
        assert (root / "plan/manifest.json").stat().st_mode & 0o777 == 0o600
        if original is None:
            original = (root / "plan/manifest.json").read_bytes()
        else:
            assert (root / "plan/manifest.json").read_bytes() == original
        assert (root / "rendered").exists()
    assert preparation_playbooks == [("generic_devices.yml", "render")]


@pytest.mark.parametrize("removed", ["render", "finalize"])
def test_controller_preparation_actions_are_internal_only(monkeypatch, capsys, removed):
    """Preparation functions remain internal stages, not independently exposed CLI actions."""
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: pytest.fail("Unexpected device access"))
    monkeypatch.setattr(sys, "argv", [
        "generic_topology_cli.py", removed, "--testbed", "tb", "--testbed-file", "unused"])
    with pytest.raises(SystemExit):
        controller.main()
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("path_mode", ["default", "workspace", "legacy"])
def test_add_topo_resumes_preparation_and_reuses_sealed_stage(
        complete_fixture, tmp_path, monkeypatch, capsys, path_mode):
    """A failed remote render can be retried without rereading or replacing the reviewed recipe."""
    monkeypatch.setattr(controller.tempfile, "tempdir", str(tmp_path))
    root = planner.resolve_workspace("tb", str(tmp_path / "workspace") if path_mode != "default" else None)
    artifacts = generate(complete_fixture)
    testbed = {"conf-name": "tb", "topo": "generic-1"}
    artifacts["manifest.json"]["testbed"] = testbed
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(root / "plan", artifacts)
    original = (root / "plan/manifest.json").read_bytes()
    document = yaml.safe_load(complete_fixture["recipe"].read_text())
    document["generic_topology"]["access_vlan"]["vlan_id"] = 2000
    complete_fixture["recipe"].write_text(yaml.safe_dump(document))
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: ("dut", testbed))
    command = ["generic_topology_cli.py", "add-topo", "--testbed", "tb", "--testbed-file", "unused", "--apply"]
    if path_mode == "workspace":
        command += ["--workspace", str(root)]
    elif path_mode == "legacy":
        command += ["--output-dir", str(root)]
    monkeypatch.setattr(sys, "argv", command)

    def fail_render(*args):
        raise ValueError("Synthetic remote rendering failure")

    monkeypatch.setattr(controller, "run_playbook", fail_render)
    with pytest.raises(SystemExit):
        controller.main()
    assert "Synthetic remote rendering failure" in capsys.readouterr().err
    finalized = controller.load_scenario(root / "finalized")
    assert finalized["coverage.json"]["status"] == "complete"
    assert finalized["manifest.json"]["roles_finalized"]
    assert finalized["manifest.json"]["selected_layouts"] == json.loads(original)["selected_layouts"]
    assert finalized["topology.yml"]["generic_topology"]["access_vlan"]["vlan_id"] == 2000
    frozen = {path.name: path.read_bytes() for path in (root / "finalized").iterdir()}
    complete_fixture["recipe"].unlink()
    calls = []

    def finish_render(args, name, variables, local):
        calls.append(name)
        for role in ("dut", "peer"):
            request = json.loads((local / (role + "-request.json")).read_text())
            assert request["settings"]["access_vlan"]["vlan_id"] == 2000
            config = {"PORT": {link[role]["port"]: {} for link in request["facts"]["connections"]}}
            controller.write_private(local / (role + "-response.json"), {
                "config": config, "report": {"transport": []},
            })

    monkeypatch.setattr(controller, "run_playbook", finish_render)
    command.remove("--apply")
    controller.main()
    rendered = controller.load_scenario(root / "rendered")
    assert rendered["manifest.json"]["deployable"]
    assert calls == ["generic_devices.yml"]
    assert (root / "plan/manifest.json").read_bytes() == original
    assert {path.name: path.read_bytes() for path in (root / "finalized").iterdir()} == frozen
    controller.main()
    assert "DRY RUN: add-topo" in capsys.readouterr().out
    assert calls == ["generic_devices.yml"]


@pytest.mark.parametrize("apply", [False, True])
def test_add_topo_rejects_invalid_roles_before_render_or_apply(
        complete_fixture, tmp_path, monkeypatch, capsys, apply):
    """Invalid roles cannot cause remote rendering or deployment even when --apply is supplied."""
    root = planner.resolve_workspace("tb", str(tmp_path / "workspace"))
    complete_fixture["uplink_minimum"] = 2
    complete_fixture["settings"]["physical_links"]["uplinks"] = ["Ethernet0", "Ethernet1"]
    complete_fixture["recipe"].write_text(yaml.safe_dump({"generic_topology": complete_fixture["settings"]}))
    artifacts = generate(complete_fixture)
    testbed = {"conf-name": "tb", "topo": "generic"}
    artifacts["manifest.json"]["testbed"] = testbed
    assert artifacts["coverage.json"]["status"] == "complete"
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(root / "plan", artifacts)
    document = yaml.safe_load(complete_fixture["recipe"].read_text())
    document["generic_topology"]["physical_links"]["uplinks"] = ["Ethernet0"]
    complete_fixture["recipe"].write_text(yaml.safe_dump(document))
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: ("dut", testbed))
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected remote access"))
    command = ["generic_topology_cli.py", "add-topo", "--testbed", "tb", "--testbed-file", "unused",
               "--workspace", str(root)]
    if apply:
        command.append("--apply")
    monkeypatch.setattr(sys, "argv", command)
    with pytest.raises(SystemExit):
        controller.main()
    error = capsys.readouterr().err
    assert "incomplete plans are review-only" in error
    assert controller.load_scenario(root / "finalized")["coverage.json"]["status"] == "incomplete"
    assert not (root / "rendered").exists()


def test_add_topo_rejects_unrelated_finalized_stage(complete_fixture, tmp_path, monkeypatch, capsys):
    """Explicit plan inputs cannot accidentally reuse another plan's sealed sibling stage."""
    artifacts = generate(complete_fixture)
    testbed = {"conf-name": "tb", "topo": "generic"}
    artifacts["manifest.json"]["testbed"] = testbed
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(tmp_path / "plan", artifacts)
    artifacts["manifest.json"].update(roles_finalized=True, breakout_plan_id="different-plan")
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(tmp_path / "finalized", artifacts)
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: ("dut", testbed))
    monkeypatch.setattr(controller, "run_playbook", lambda *args: pytest.fail("Unexpected remote access"))
    monkeypatch.setattr(sys, "argv", [
        "generic_topology_cli.py", "add-topo", "--testbed", "tb", "--testbed-file", "unused",
        "--output-dir", str(tmp_path),
    ])
    with pytest.raises(SystemExit):
        controller.main()
    assert "different breakout plan" in capsys.readouterr().err
    assert not (tmp_path / "rendered").exists()


@pytest.mark.parametrize("explicit_workspace", [False, True])
def test_workspace_resolves_all_stages_and_deployment(
        complete_fixture, tmp_path, monkeypatch, capsys, explicit_workspace):
    """Finalization, rendering and dry-run actions reuse the exact workspace without stage path flags."""
    monkeypatch.setattr(controller.tempfile, "tempdir", str(tmp_path))
    root = tmp_path / "chosen" if explicit_workspace else tmp_path / "sonic-generic-{}".format(os.getuid()) / "tb"
    controller.resolve_workspace("tb", str(root) if explicit_workspace else None)
    artifacts = generate(complete_fixture)
    testbed = {"conf-name": "tb", "topo": "generic"}
    artifacts["manifest.json"]["testbed"] = testbed
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(root / "plan", artifacts)
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: ("dut", testbed))
    phases = []

    def render(args, values, *unused):
        assert args.scenario_dir == str(root / "finalized")
        assert args.output_dir == str(root / "rendered")
        values["manifest.json"].update(deployable=True, requires_explicit_apply=True)
        values["render_report.json"] = {
            role: {"transport": [], "qos_policy": "installed_lossy"} for role in ("dut", "peer")}
        planner.seal_artifacts(values)
        planner.write_artifacts(args.output_dir, values)
        phases.append("render")

    monkeypatch.setattr(controller, "render", render)
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected remote access"))
    for action in ("add-topo", "deploy-mg", "remove-topo", "recover"):
        command = ["generic_topology_cli.py", action, "--testbed", "tb", "--testbed-file", "unused"]
        if explicit_workspace:
            command.extend(["--workspace", str(root)])
        monkeypatch.setattr(sys, "argv", command)
        controller.main()
    assert phases == ["render"]
    assert capsys.readouterr().out.count("DRY RUN:") == 4
    assert (root / "plan").exists() and (root / "finalized").exists() and (root / "rendered").exists()


@pytest.mark.parametrize("unsafe", ["symlink", "public", "stage_symlink", "other_owner"])
def test_workspace_rejects_unsafe_directories(tmp_path, monkeypatch, unsafe):
    """Never read/write configurations through unsafe workspace roots or stage directories."""
    root = tmp_path / "workspace"
    root.mkdir(mode=0o700)
    if unsafe == "symlink":
        root = tmp_path / "alias"
        root.symlink_to(tmp_path / "workspace", target_is_directory=True)
    elif unsafe == "public":
        root.chmod(0o755)
    elif unsafe == "stage_symlink":
        (root / "rendered").symlink_to(tmp_path, target_is_directory=True)
    else:
        uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: uid + 1)
    with pytest.raises(ValueError, match="private, and not a symlink"):
        controller.resolve_workspace("tb", str(root))


def test_workspace_rejects_missing_stages_and_mixed_path_options(tmp_path, monkeypatch, capsys):
    """Missing stages fail locally; conflicting old/new path options cannot select a different run."""
    monkeypatch.setattr(controller, "resolve_testbed", lambda *args: ("dut", {"topo": "generic"}))
    monkeypatch.setattr(controller, "run_playbook", lambda *args, **kwargs: pytest.fail("Unexpected remote access"))
    for action in ("deploy-mg", "recover", "remove-topo"):
        command = [
            "generic_topology_cli.py", action, "--testbed", "tb", "--testbed-file", "unused",
            "--workspace", str(tmp_path / "empty"),
        ]
        if action == "deploy-mg":
            command.append("--apply")
        monkeypatch.setattr(sys, "argv", command)
        with pytest.raises(SystemExit):
            controller.main()
        assert "Required scenario stage is missing" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", [
        "generic_topology_cli.py", "add-topo", "--testbed", "tb", "--testbed-file", "unused",
        "--workspace", str(tmp_path / "empty"), "--scenario-dir", "somewhere-else",
    ])
    with pytest.raises(SystemExit):
        controller.main()
    assert "not both" in capsys.readouterr().err


def test_automatic_preparation_finalizes_before_render_and_dry_run(complete_fixture, tmp_path, monkeypatch):
    """A single add-topo call reuses a frozen layout and retains the dry-run boundary after rendering."""
    artifacts = generate(complete_fixture)
    testbed = {"topo": "generic", "conf-name": "tb"}
    artifacts["manifest.json"]["testbed"] = testbed
    planner.seal_artifacts(artifacts)
    planner.write_artifacts(tmp_path / "plan", artifacts)
    frozen = json.loads(json.dumps(artifacts["manifest.json"]["selected_layouts"]))
    phases = []

    def render(args, values, *unused):
        assert values["manifest.json"]["roles_finalized"]
        assert values["manifest.json"]["selected_layouts"] == frozen
        phases.append("render")
        planner.write_artifacts(args.output_dir, values)

    def deploy(args, *unused):
        assert not args.apply
        phases.append("dry-run")

    monkeypatch.setattr(controller, "render", render)
    monkeypatch.setattr(controller, "deploy", deploy)
    controller.automatic_prepare(
        Namespace(output_dir=str(tmp_path), apply=False), testbed, "dut")
    assert phases == ["render", "dry-run"]
