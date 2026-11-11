"""Offline tests for automatic binding of installed facts and unchanged physical wiring."""

import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("generic_hwsku_preflight", ROOT / "scripts/generic_hwsku_preflight.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "recorded_planner_inputs", ROOT / "module_utils/test_generic_hwsku.py")
recorded = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(recorded)


def _recorded_inputs(cages=2):
    source = recorded._snapshot(cages)
    scope = {"testbed": "synthetic-bed", "dut": "dut", "leaves": ["leaf"], "protected_peers": ["shared-peer"]}
    facts = {}
    lookup_text = "\n".join("{} {} {} 100 {} 0".format(
        row["speed"], row["cable"], row["headroom"], row["headroom"] - 100)
                            for row in source["lookup"])
    for device in source["devices"]:
        name = device["name"]
        facts[name] = {
            "hostname": name, "image": "build_version: synthetic-image",
            "metadata": {"platform": device["platform"], "hwsku": device["base_hwsku"], "num_asic": 1,
                         "buffer_model": "traditional"},
            "platform": {"interfaces": {}}, "expansions": {},
            "sources": {"parser": {"path": "installed-parser.py", "sha256": "a" * 64}},
            "lookup_candidates": [{"path": "effective-lookup.ini", "sha256": "b" * 64, "content": lookup_text}],
            "platform_directory": "/installed/" + name, "hwsku_directory": "/installed/" + name + "/base",
            "template_sha256": {"/installed/" + name + "/base/" + template: "c" * 64
                                for template in ("buffers.json.j2", "buffers_dynamic.json.j2", "qos.json.j2")},
            "running": {"PORT": {}, "VLAN": {"Vlan1000": {"vlanid": "1000"}}},
        }
        for cage in device["cages"]:
            facts[name]["platform"]["interfaces"][cage["name"]] = {"port_group": cage["group"]}
            facts[name]["expansions"][cage["name"]] = [{
                "id": mode["id"], "name": mode["name"],
                "ports": {port["name"]: {
                    "alias": port["alias"], "index": str(port["index"]),
                    "lanes": ",".join(map(str, port["lanes"])), "speed": str(port["speed"]),
                    "subport": "canonical-extra"}
                          for port in mode["ports"]},
            } for mode in cage["modes"]]
            for port in cage["modes"][1]["ports"]:
                facts[name]["running"]["PORT"][port["name"]] = {
                    "lanes": ",".join(map(str, port["lanes"])), "speed": str(port["speed"]),
                    "fec": "rs", "autoneg": "off"}
        facts[name]["applied_buffers"] = {
            "pg": {port + ":3": {"profile": "baseline"} for port in facts[name]["running"]["PORT"]},
            "profiles": {"baseline": {"size": "1000", "xon": "100", "xoff": "900", "pool": "ingress"}},
            "pools": {"ingress": {"size": "100000", "xoff": "0"}},
        }
    rows = [{"dut_port": "Ethernet{}".format(index), "leaf": "leaf", "leaf_port": "Ethernet{}".format(index),
             "speed": 100000, "vlan": str(200 + index), "autoneg": "off"} for index in range(cages * 4)]
    host = {"container": {"running": True}, "external_interface": "reserved-parent",
            "host_links": [{"ifname": "reserved-parent", "flags": ["UP"], "mtu": 9216}]}
    return scope, facts, host, rows, {}


def test_native_binding_produces_complete_frozen_plan_and_preserves_canonical_extras():
    """Actual lane facts, not interface-number arithmetic, must survive planning into rendering."""
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(*_recorded_inputs())
    assert snapshot["links"][0]["leaf_channel"] >= 100
    assert all(port["subport"] == "canonical-extra" for ports in canonical.values() for port in ports.values())
    assert all(row["ports"] for row in manifest["coverage"]["modes"] + manifest["coverage"]["lookup"])
    assert not {"min_subports", "routed_ports"} & set(settings)
    assert settings["access_vlan"] == 1001
    assert runtime["templates"]["dut"]["add"] == [
        "/installed/dut/base/buffers.json.j2", "/installed/dut/base/qos.json.j2"]
    assert next(device for device in snapshot["devices"] if device["name"] == "dut")["port_capacity"] == 0
    preflight.validate_manifest(manifest, snapshot, settings)


def test_actual_execution_identity_separates_native_stages_without_changing_the_layout():
    first = {"source_sha": "a" * 40, "owner_plan_id": "platform-plan-one"}
    reference = preflight.plan_collected(*_recorded_inputs(), execution_context=first)[2]
    repeat = preflight.plan_collected(*_recorded_inputs(), execution_context=first)[2]
    assert repeat == reference
    for changed in (dict(first, owner_plan_id="platform-plan-two"), dict(first, source_sha="b" * 40)):
        manifest = preflight.plan_collected(*_recorded_inputs(), execution_context=changed)[2]
        assert manifest["scenario_id"] != reference["scenario_id"]
        assert manifest["layout"] == reference["layout"]
        assert manifest["port_bindings"] == reference["port_bindings"]
        assert manifest["requirements"] == reference["requirements"]


@pytest.mark.parametrize("context", [
    {"source_sha": "not-a-sha", "owner_plan_id": "platform-plan"},
    {"source_sha": "a" * 40, "owner_plan_id": ""},
])
def test_runtime_namespace_does_not_invent_missing_execution_identity(context):
    with pytest.raises(preflight.PrerequisiteError, match="actual source SHA"):
        preflight.plan_collected(*_recorded_inputs(), execution_context=context)


def test_source_verified_service_cages_do_not_depend_on_ethernet_numbering():
    raw = {"metadata": {"platform": "x86_64-nvidia_sn5640-r0", "hwsku": "Mellanox-SN5640-C512S2"},
           "expansions": {
               cage: [{"name": "1x25G[10G]", "ports": {cage: {"lanes": str(index), "speed": str(speed)}}}
                      for speed in (10000, 25000)]
               for index, cage in enumerate(("aux-left", "aux-right"))}}
    assert preflight._service_cages(raw) == {"aux-left", "aux-right"}
    raw["expansions"]["aux-left"][0]["ports"]["aux-left"]["speed"] = "50000"
    with pytest.raises(preflight.PrerequisiteError, match="verified two-port contract"):
        preflight._service_cages(raw)
    raw["metadata"]["platform"] = "unverified-platform"
    assert preflight._service_cages(raw) == set()


@pytest.mark.parametrize("rate,compliance,expected", [
    ("103", "10GBASE-SR", [10000]), ("103", "10GBASE-LR", [10000]), ("255", "10GBASE-SR", None),
])
def test_service_module_evidence_is_separate_from_asic_supported_speeds(rate, compliance, expected):
    module = {"type": "SFP/SFP+/SFP28", "nominal_bit_rate": rate,
              "specification_compliance": repr({"10G Ethernet Compliance": compliance})}
    assert preflight._service_media_speeds(module) == expected


def test_malformed_positive_service_evidence_is_not_silently_admitted():
    with pytest.raises(preflight.PrerequisiteError, match="compliance"):
        preflight._service_media_speeds({
            "type": "SFP/SFP+/SFP28", "nominal_bit_rate": "103", "specification_compliance": "invalid"})


def test_named_entry_without_policy_collects_and_freezes_automatically_derived_inputs(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    import generic_hwsku_lifecycle as lifecycle

    scope, facts, host, rows, policy = _recorded_inputs()
    original = {
        "conf-name": "bed", "group-name": "group", "topo": "t0", "ptf_image_name": "docker-ptf",
        "ptf": "group", "ptf_ip": "192.0.2.3/24", "server": "server", "dut": ["dut"], "inv_name": "inventory",
    }
    generic = copy.deepcopy(original)
    generic.update({"conf-name": "bed-generic", "topo": "generic", "generic_hwsku": {
        "baseline_testbed": "bed", "leaves": ["leaf"], "protected_peers": ["shared-peer"]}})
    path = tmp_path / "testbed.yaml"
    path.write_text(yaml.safe_dump([original, generic]), encoding="utf-8")
    monkeypatch.setattr(lifecycle, "source_identity", lambda: "candidate-source")
    monkeypatch.setattr(lifecycle, "connection_rows", lambda *arguments: rows)
    monkeypatch.setattr(lifecycle, "run_collection", lambda *arguments: (facts, host, []))
    monkeypatch.delenv("ELASTICTEST_TEST_PLAN_ID", raising=False)
    workspace = tmp_path / "private"
    result = lifecycle.main([
        "--action", "preflight", "--testbed", "bed-generic", "--testbed-file", str(path),
        "--inventory", "inventory", "--vm-inventory", "veos", "--vault-password-file", "vault",
        "--workspace", str(workspace)])
    assert result == 0
    report = lifecycle.read_json(workspace / "preflight-report.json")
    manifest = lifecycle.read_json(workspace / "manifest.json")
    runtime = lifecycle.read_json(workspace / "runtime-inputs.json")
    assert report["status"] == "PLAN_READY" and not report["configuration_writes_attempted"]
    assert report["traffic_available"] and manifest["requirements"]["routed_ports"] > 0
    assert "min_subports" not in manifest["settings"] and "routed_ports" not in manifest["settings"]
    assert lifecycle.read_json(workspace / "provenance.json")["runtime_sha256"] == lifecycle.digest(runtime)
    assert not (workspace / "backend.json").exists()


def _double_lanes(facts):
    for raw in facts.values():
        for variants in raw["expansions"].values():
            for variant in variants:
                for port in variant["ports"].values():
                    lanes = [int(value) for value in port["lanes"].split(",")]
                    port["lanes"] = ",".join(str(lane) for value in lanes for lane in (2 * value + 1, 2 * value))
        for port in raw["running"]["PORT"].values():
            lanes = [int(value) for value in port["lanes"].split(",")]
            port["lanes"] = ",".join(str(lane) for value in lanes for lane in (2 * value + 1, 2 * value))


def test_multilane_baseline_groups_use_exact_csv_bindings_without_lane_order_guesses():
    scope, facts, host, rows, policy = _recorded_inputs()
    _double_lanes(facts)
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows)
    assert len(snapshot["links"]) == len(rows)
    for row in manifest["port_bindings"]:
        child = next(port for entry in manifest["layout"] if entry["device"] == "dut"
                     for port in entry["expansion"]["ports"] if port["name"] == row["dut_port"])
        assert len(child["lanes"]) == 2 * len(child["channels"])
        assert child["lanes"][0] > child["lanes"][1]
    preflight.validate_manifest(manifest, snapshot, settings)


@pytest.mark.parametrize("protected", [False, True])
def test_coarse_baseline_channels_block_only_cages_that_are_eligible_for_planning(protected):
    scope, facts, host, rows, policy = _recorded_inputs(3)
    _double_lanes(facts)
    coarse = dict(rows[0], speed=400000, leaf="shared-peer" if protected else "leaf")
    rows = [coarse] + rows[4:]
    if not protected:
        with pytest.raises(preflight.PrerequisiteError, match="not fine-grained enough"):
            preflight.plan_collected(scope, facts, host, rows)
    else:
        snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows)
        assert not any(row["device"] == "dut" and row["cage"] == "cage-0" for row in manifest["layout"])


def test_missing_optional_fec_an_values_remain_installed_defaults_not_guesses():
    scope, facts, host, rows, policy = _recorded_inputs()
    for raw in facts.values():
        for port in raw["running"]["PORT"].values():
            port.pop("fec")
            port.pop("autoneg")
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows)
    assert all(port["fec"] is None and port["autoneg"] is None for device in snapshot["devices"]
               for cage in device["cages"] for mode in cage["modes"] for port in mode["ports"])
    assert all("fec" not in row and "autoneg" not in row for ports in canonical.values() for row in ports.values())


def test_missing_transport_is_reported_without_discarding_physical_coverage():
    scope, facts, host, rows, policy = _recorded_inputs()
    for index, row in enumerate(rows):
        if index % 4:
            row["vlan"] = ""
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows, policy)
    assert not manifest["coverage"]["traffic"]["complete"]
    assert manifest["coverage"]["traffic"]["unavailable"]
    assert len(manifest["endpoints"]) == 2


@pytest.mark.parametrize("transport", [False, True])
def test_blank_csv_vlans_remain_physical_only_without_user_selected_profiles(transport):
    scope, facts, host, rows, policy = _recorded_inputs()
    for index, row in enumerate(rows):
        if not transport or index % 4:
            row["vlan"] = ""
    original_rows = copy.deepcopy(rows)
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows, policy)
    assert rows == original_rows and len(snapshot["links"]) == len(rows)
    assert len(snapshot["endpoints"]) == (2 if transport else 0)
    assert len(manifest["port_bindings"]) > len(manifest["endpoints"])
    assert manifest["coverage"]["traffic"]["unavailable"]
    assert all(row["ports"] for row in manifest["coverage"]["modes"] + manifest["coverage"]["lookup"])
    preflight.validate_manifest(manifest, snapshot, settings)


def test_ambiguous_channel_identity_is_not_guessed():
    """A name/speed that represents several different lane groups must have explicit wiring evidence."""
    scope, facts, host, rows, policy = _recorded_inputs()
    ambiguous = copy.deepcopy(facts["dut"]["expansions"]["cage-0"][1])
    ambiguous["id"], ambiguous["name"] = "ambiguous", "2x100G"
    ambiguous["ports"] = {name: row for name, row in ambiguous["ports"].items()
                          if name in ("Ethernet0", "Ethernet2")}
    ambiguous["ports"]["Ethernet0"]["lanes"] = "0,1"
    ambiguous["ports"]["Ethernet2"]["lanes"] = "2,3"
    facts["dut"]["expansions"]["cage-0"].append(ambiguous)
    with pytest.raises(preflight.PrerequisiteError, match="unique canonical channel binding"):
        preflight.plan_collected(scope, facts, host, rows, policy)


@pytest.mark.parametrize("baseline", ["valid", "missing", "incompatible"])
def test_installed_base_mapping_disambiguates_reused_names_without_trusting_current_breakout(baseline):
    scope, facts, host, rows, policy = _recorded_inputs()
    raw = facts["dut"]
    alternative = copy.deepcopy(raw["expansions"]["cage-0"][1])
    alternative["id"], alternative["name"] = "alternative-two-lane", "2x100G"
    alternative["ports"] = {name: row for name, row in alternative["ports"].items()
                            if name in ("Ethernet0", "Ethernet2")}
    alternative["ports"]["Ethernet0"]["lanes"] = "0,1"
    alternative["ports"]["Ethernet2"]["lanes"] = "2,3"
    raw["expansions"]["cage-0"].append(alternative)
    raw["baseline_ports"] = copy.deepcopy(raw["running"]["PORT"])
    raw["running"]["PORT"]["Ethernet0"]["lanes"] = "0,1"
    if baseline == "missing":
        raw["baseline_ports"].pop("Ethernet0")
    elif baseline == "incompatible":
        raw["baseline_ports"]["Ethernet0"]["lanes"] = "99"
    if baseline == "valid":
        assert preflight.physical_endpoint(raw, "Ethernet0", 100000) == ("cage-0", (0,))
    else:
        with pytest.raises(preflight.PrerequisiteError, match="CSV endpoint"):
            preflight.physical_endpoint(raw, "Ethernet0", 100000)


@pytest.mark.parametrize("missing", ["lookup", "templates", "applied"])
def test_missing_installed_facts_are_specific_errors_not_empty_policy(missing):
    scope, facts, host, rows, policy = _recorded_inputs()
    if missing == "lookup":
        facts["dut"]["lookup_candidates"] = []
        expected = "pg_profile_lookup.ini"
    elif missing == "templates":
        facts["dut"]["template_sha256"] = {}
        expected = "Installed buffers.json.j2"
    else:
        del facts["dut"]["applied_buffers"]
        expected = "Applied BUFFER_PG"
    with pytest.raises(preflight.PrerequisiteError, match=expected):
        preflight.plan_collected(scope, facts, host, rows, policy)


def test_dynamic_templates_and_shared_headroom_use_applied_image_data():
    scope, facts, host, rows, policy = _recorded_inputs()
    for raw in facts.values():
        raw["metadata"]["buffer_model"] = "dynamic"
        raw["applied_buffers"]["pools"]["ingress"]["xoff"] = "100000"
        raw["applied_buffers"]["profiles"]["baseline"]["size"] = "100"
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows, policy)
    assert runtime["templates"]["dut"]["add"][0].endswith("/buffers_dynamic.json.j2")
    assert {row["headroom"] for row in snapshot["lookup"]} == {100}
    preflight.validate_manifest(manifest, snapshot, settings)


def _installed_lossy(facts):
    for raw in facts.values():
        raw["running"]["PORT_QOS_MAP"] = {port: {"pfc_enable": ""} for port in raw["running"]["PORT"]}
        raw["applied_buffers"] = {
            "pg": {port + ":0": {"profile": "lossy"} for port in raw["running"]["PORT"]},
            "profiles": {"lossy": {"size": "0", "pool": "ingress"}},
            "pools": {"ingress": {"size": "100000", "type": "ingress"}},
        }


def test_installed_lossy_policy_keeps_all_mode_and_cable_requirements_without_inventing_headroom():
    scope, facts, host, rows, policy = _recorded_inputs()
    _, _, reference, _, _ = preflight.plan_collected(scope, facts, host, rows, policy)
    _installed_lossy(facts)
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows, policy)
    assert manifest["settings"]["profile"] == "lossy"
    assert manifest["requirements"] == reference["requirements"]
    assert len(manifest["coverage"]["lookup"]) == len(reference["coverage"]["lookup"])
    assert all(row["ports"] for row in manifest["coverage"]["modes"] + manifest["coverage"]["lookup"])
    assert {row["headroom"] for row in snapshot["lookup"]} == {0}
    assert all(not any(row["headroom_credits"].values()) and row["headroom_capacity"] == 0
               for row in snapshot["devices"])
    assert runtime["buffer_profiles"] == {
        name: {"profile": "lossy", "lossless_pg_count": 0} for name in facts}
    preflight.validate_manifest(manifest, snapshot, settings)
    with pytest.raises(preflight.PrerequisiteError, match="selected buffer/QoS profile"):
        preflight.plan_collected(scope, facts, host, rows, {"settings": {"profile": "lossless"}})


@pytest.mark.parametrize("uncertain", ["enabled-pfc", "missing-pg", "reserved-pg"])
def test_incomplete_or_nonzero_pg_evidence_is_not_a_lossy_fallback(uncertain):
    scope, facts, host, rows, policy = _recorded_inputs()
    _installed_lossy(facts)
    raw = facts["dut"]
    if uncertain == "enabled-pfc":
        raw["running"]["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = "3,4"
    elif uncertain == "missing-pg":
        raw["applied_buffers"]["pg"].pop("Ethernet0:0")
    else:
        raw["applied_buffers"]["profiles"]["lossy"]["size"] = "1000"
    with pytest.raises(preflight.PrerequisiteError, match="lossy baseline requires"):
        preflight.plan_collected(scope, facts, host, rows, policy)


def test_mixed_installed_policies_are_not_costed_as_a_uniform_lossy_layout():
    scope, facts, host, rows, policy = _recorded_inputs()
    _installed_lossy({"dut": facts["dut"]})
    with pytest.raises(preflight.PrerequisiteError, match="Mixed installed lossy/lossless"):
        preflight.plan_collected(scope, facts, host, rows, policy)


def test_installed_template_symlinks_keep_their_resolved_source_identity():
    scope, facts, host, rows, policy = _recorded_inputs()
    original = "/installed/dut/base/buffers.json.j2"
    resolved = "/usr/share/sonic/templates/installed-buffer-wrapper.j2"
    facts["dut"]["template_paths"] = {original: resolved}
    facts["dut"]["template_sha256"][resolved] = facts["dut"]["template_sha256"].pop(original)
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows)
    assert runtime["templates"]["dut"]["add"][0] == resolved


def test_overlapping_applied_pg_bindings_are_not_double_credited():
    scope, facts, host, rows, policy = _recorded_inputs()
    facts["dut"]["applied_buffers"]["pg"]["Ethernet0:3-4"] = {"profile": "baseline"}
    with pytest.raises(preflight.PrerequisiteError, match="Overlapping applied PG reservations"):
        preflight.plan_collected(scope, facts, host, rows)


def test_self_asserted_device_flags_cannot_replace_collected_facts():
    scope, facts, host, rows, policy = _recorded_inputs()
    with pytest.raises(preflight.PrerequisiteError, match="Only optional settings overrides"):
        preflight.plan_collected(scope, facts, host, rows, {"image_support": {"ready": True}})


def test_shared_foreign_peer_protects_the_whole_dut_cage():
    """A foreign shared connection must never turn into a controlled leaf or a writable selected cage."""
    scope, facts, host, rows, policy = _recorded_inputs(3)
    rows[0]["leaf"] = "shared-peer"
    snapshot, settings, manifest, canonical, runtime = preflight.plan_collected(scope, facts, host, rows, policy)
    assert {device["name"] for device in snapshot["devices"]} == {"dut", "leaf"}
    assert not any(row["device"] == "dut" and row["cage"] == "cage-0" for row in manifest["layout"])


def test_sanitized_readiness_report_never_exports_original_configs():
    """The handoff report can name evidence and blockers without copying private ConfigDB values."""
    scope, facts, host, rows, policy = _recorded_inputs()
    facts["dut"]["running"] = {"TACPLUS": {"global": {"passkey": "private-config-value"}}}
    report = preflight.readiness_report(scope, facts, host, rows, ["reviewed policy unavailable"])
    assert report["status"] == "NOT_READY" and not report["configuration_writes_attempted"]
    assert "private-config-value" not in json.dumps(report)
