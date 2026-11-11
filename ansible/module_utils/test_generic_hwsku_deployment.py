"""Offline renderer/transaction tests; no Ansible imports, nodes or executors."""

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from types import SimpleNamespace
import uuid

import pytest


def _load(name):
    path = os.path.join(os.path.dirname(__file__), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


planner = _load("generic_hwsku")
deployment = _load("generic_hwsku_deployment")


def _port(cage, child, lanes, channels, speed):
    return {
        "name": "port{}c{}".format(cage, child), "alias": "cage{}-child{}".format(cage, child),
        "index": cage, "lanes": lanes, "channels": channels, "speed": speed,
        "fec": "rs", "autoneg": "off", "cables": ["5m", "10m"],
    }


def _raw(port):
    return {
        "alias": port["alias"], "index": str(port["index"]), "lanes": ",".join(map(str, port["lanes"])),
        "speed": str(port["speed"]), "fec": port["fec"], "autoneg": port["autoneg"],
        "subport": port["name"].split("c")[-1], "mtu": "9100", "description": "canonical extra attributes",
    }


def _inputs(cages=4, inactive_children=False, routed_ports=1, transport_channels=None):
    devices = []
    for name in ("dut", "leaf"):
        expansions = []
        for cage in range(cages):
            width = 8 if name == "leaf" and inactive_children else 4
            base = 100 * (name == "leaf") + cage * width
            lanes = list(range(base, base + width))
            expansions.append({
                "name": "cage-" + str(cage), "group": "group-" + str(cage),
                "protected_reason": "unselected reservation" if cage == cages - 1 else "",
                "modes": [
                    {"id": "single", "name": "1x400G", "group_mode": "independent",
                     "ports": [_port(cage, channel, list(reversed(lanes[channel:channel + 4])),
                                     list(range(channel, channel + 4)), 400000) for channel in range(0, width, 4)]},
                    {"id": "quad", "name": "4x100G", "group_mode": "independent",
                     "ports": [_port(cage, channel, [lanes[channel]], [channel], 100000) for channel in range(width)]},
                ],
            })
        devices.append({
            "name": name, "platform": "recorded-platform", "base_hwsku": "RecordedBase",
            "realized_hwsku": "RecordedScenario",
            "image": "recorded-image", "asic_count": 1, "dedicated": True,
            "port_capacity": 64, "headroom_capacity": 100000, "cages": expansions,
        })
    snapshot = {
        "schema_version": 1, "dut": "dut", "devices": devices,
        "links": [
            {"dut_cage": "cage-" + str(cage), "dut_channel": channel, "leaf": "leaf",
             "leaf_cage": "cage-" + str(cage),
             "leaf_channel": channel, "excluded_reason": ""}
            for cage in range(cages) for channel in range(4)
        ],
        "endpoints": [
            {"id": "endpoint-{}-{}".format(cage, channel), "leaf": "leaf", "cage": "cage-" + str(cage),
             "channels": [channel], "ptf_index": cage * 4 + channel, "trunk": "opaque-host-bridge",
             "vlan": 300 + cage * 4 + channel, "host_interface": "host{}v{}".format(cage, channel),
             "roles": ["access", "routed"]}
            for cage in range(cages) for channel in range(4)
        ],
        "lookup": [{"speed": 100000, "cable": "5m", "headroom": 1000},
                   {"speed": 100000, "cable": "10m", "headroom": 1200},
                   {"speed": 400000, "cable": "5m", "headroom": 2000}],
        "supported_profiles": ["lossless"],
        "sources": {name: "a" * 64 for name in ("capabilities", "parser", "links", "lookup", "policy")},
    }
    settings = {
        "min_subports": 1, "access_vlan": 100, "routed_network": "198.18.0.0/24",
        "access_network": "198.19.0.0/24", "profile": "lossless", "max_search_nodes": 50000,
    }
    if routed_ports is not None:
        settings["routed_ports"] = routed_ports
    if transport_channels is not None:
        snapshot["endpoints"] = [row for row in snapshot["endpoints"] if row["channels"][0] in transport_channels]
    manifest = planner.plan_scenario(snapshot, settings)
    selected = {entry["device"] for entry in manifest["layout"]}
    baselines, canonical, templates = {}, {}, {}
    for device in snapshot["devices"]:
        name = device["name"]
        if name not in selected:
            continue
        old_ports = {port["name"]: _raw(port) for cage in device["cages"] for port in cage["modes"][0]["ports"]}
        old_ports["uplink"] = {
            "alias": "protected-uplink", "index": "900", "lanes": "900,901", "speed": "100000",
            "fec": "rs", "autoneg": "off", "admin_status": "up", "subport": "kept",
        }
        running = {
            "DEVICE_METADATA": {"localhost": {
                "hostname": name, "platform": device["platform"],
                "hwsku": device["base_hwsku"], "running_only": "original",
            }},
            "PORT": old_ports,
            "INTERFACE": {"uplink": {}, "uplink|192.0.2.1/31": {}},
            "VLAN": {"Vlan50": {"vlanid": "50", "members": ["uplink"]}},
            "VLAN_MEMBER": {"Vlan50|uplink": {"tagging_mode": "tagged"}},
            "VLAN_INTERFACE": {"Vlan50": {}, "Vlan50|192.0.2.9/29": {}},
            "STATIC_ROUTE": {"203.0.113.0/24": {"ifname": "uplink", "nexthop": "192.0.2.0"}},
            "ACL_TABLE": {"protected-policy": {"ports": ["uplink"], "type": "L3"}},
            "BUFFER_POOL": {"ingress_pool": {"type": "ingress", "mode": "dynamic", "size": "100000"}},
            "BUFFER_PROFILE": {"baseline_pg": {"pool": "ingress_pool", "xon": "100", "xoff": "200", "size": "300"}},
            "BUFFER_PG": {port + "|3-4": {"profile": "baseline_pg"} for port in old_ports},
            "BUFFER_QUEUE": {port + "|0-7": {"profile": "baseline_pg"} for port in old_ports},
            "PORT_QOS_MAP": {port: {"pfc_enable": "3,4"} for port in old_ports},
            "CABLE_LENGTH": {"AZURE": {port: "5m" for port in old_ports}},
            "PRIVATE_TABLE": {"untouched": {"bound_to": "uplink"}},
        }
        for number, port in enumerate(old_ports):
            if port == "uplink":
                continue
            running["INTERFACE"][port] = {}
            running["INTERFACE"][port + "|10.{}.0.0/31".format(number)] = {}
        if name == "leaf":
            for endpoint in snapshot["endpoints"]:
                vlan = "Vlan{}".format(endpoint["vlan"])
                running["VLAN"][vlan] = {"vlanid": str(endpoint["vlan"]), "members": ["uplink"]}
                running["VLAN_MEMBER"][vlan + "|uplink"] = {"tagging_mode": "tagged"}
        startup = copy.deepcopy(running)
        startup["DEVICE_METADATA"]["localhost"].pop("running_only")
        startup["DEVICE_METADATA"]["localhost"]["startup_only"] = "must-not-be-saved-over"
        data = (" \n" + json.dumps(startup, indent=3) + " \n\n").encode("utf-8")
        baselines[name] = {
            "running": running, "startup": {
                "data": data, "metadata": {"mode": 0o640, "uid": 1000, "gid": 1000, "mtime_ns": 123456789},
            },
        }
        canonical[name] = {port["name"]: _raw(port) for entry in manifest["layout"] if entry["device"] == name
                           for port in entry["expansion"]["ports"]}
        cables = {endpoint["dut_port"] if name == "dut" else endpoint["leaf_port"]: endpoint["cable"]
                  for endpoint in manifest["port_bindings"] if name == "dut" or endpoint["leaf"] == name}
        tables = {
            "BUFFER_POOL": copy.deepcopy(running["BUFFER_POOL"]),
            "BUFFER_PROFILE": {"scenario_pg": {"pool": "ingress_pool", "xon": "110", "xoff": "220", "size": "330"}},
            "BUFFER_PG": {port + "|3-4": {"profile": "[BUFFER_PROFILE|scenario_pg]"} for port in canonical[name]},
            "BUFFER_QUEUE": {port + "|0-7": {"profile": "scenario_pg"} for port in canonical[name]},
            "PORT_QOS_MAP": {port: {"pfc_enable": "3,4"} for port in canonical[name]},
            "CABLE_LENGTH": {"AZURE": cables},
        }
        templates[name] = {"add": tables}
        if name == "dut":
            templates[name]["deploy"] = copy.deepcopy(tables)
            templates[name]["deploy"]["BUFFER_PROFILE"]["scenario_pg"]["xon"] = "111"
    return snapshot, manifest, baselines, canonical, templates


@pytest.fixture
def inputs():
    return _inputs()


@pytest.fixture
def bundle(inputs):
    return deployment.render_bundle(*inputs)


@pytest.fixture
def workspace():
    path = Path(".generic-hwsku-deployment-test-" + uuid.uuid4().hex)
    try:
        yield path / "private-journal"
    finally:
        if path.exists():
            shutil.rmtree(str(path))


def _transaction(workspace, bundle, backend=None, hosts=None, aliases=None):
    if not workspace.parent.exists():
        workspace.parent.mkdir()
    hosts = hosts if hosts is not None else {
        "owned-ptf-and-transport": {
            "baseline": {"interfaces": ["original"], "routes": ["original"]},
            "candidate": {"interfaces": bundle["transport"], "routes": ["manifest-bound"]},
        },
    }
    aliases = aliases if aliases is not None else {
        device: {"device": device, "name": "RecordedScenario", "baseline": None,
                 "candidate": {"name": "RecordedScenario", "content_sha256": "b" * 64}}
        for device in bundle["add_configs"]
    }
    backend = backend or Backend(bundle, hosts, aliases)
    backend.journal_path = str(workspace / "journal.json")
    transaction = deployment.DeploymentTransaction(workspace, bundle, backend, hosts, aliases)
    return transaction, backend, hosts, aliases


class Backend:
    """Conditional, stateful simulator; readback is independent of perform's return."""

    def __init__(self, bundle, hosts, aliases):
        self.values = {}
        for device, baseline in bundle["baselines"].items():
            self.values[("running", device)] = copy.deepcopy(baseline["running"])
            self.values[("startup", device)] = {
                "data": base64.b64decode(baseline["startup"]["data_b64"]),
                "metadata": copy.deepcopy(baseline["startup"]["metadata"]),
            }
        for kind, records in (("host", hosts), ("alias", aliases)):
            for target, record in records.items():
                self.values[(kind, target)] = copy.deepcopy(record["baseline"])
        self.originals = copy.deepcopy(self.values)
        self.writes, self.reads, self.failures, self.owners = [], [], [], {}
        self.journal_path = None
        self.no_write = False

    def verify(self, op):
        self.reads.append(copy.deepcopy(op))
        key = (op["kind"], op["target"])
        return {
            "operation_id": op["id"], "target": op["target"], "kind": op["kind"],
            "value": copy.deepcopy(self.values[key]), "owned_by": self.owners.get(key),
        }

    def perform(self, op):
        with open(self.journal_path, encoding="utf-8") as stream:
            durable = json.load(stream)
        assert any(record["id"] == op["id"] and record["status"] == "INTENT" for record in durable["operations"])
        for reference in (op["before"], op["after"]):
            assert os.path.isfile(reference["path"])
        key = (op["kind"], op["target"])
        assert self.values[key] == deployment.read_artifact(op["before"]), "Backend CAS rejected drift"
        mode = None
        for index, (phase, kind, target, failure) in enumerate(self.failures):
            if (phase, kind, target) == (op["phase"], op["kind"], op["target"]):
                mode = failure
                self.failures.pop(index)
                break
        self.writes.append(copy.deepcopy(op))
        if mode == "before":
            raise RuntimeError("Injected failure before write")
        if not self.no_write:
            self.values[key] = deployment.read_artifact(op["after"])
        if mode == "partial":
            if op["kind"] == "running":
                self.values[key]["PARTIAL"] = {"own-mutation": {"operation": op["id"]}}
            else:
                self.values[key]["partial"] = {"own-mutation": op["id"]}
            self.owners[key] = op["id"]
            raise RuntimeError("Injected partial owned write")
        if mode == "empty-partial":
            self.values[key] = {}
            self.owners[key] = op["id"]
            raise RuntimeError("Injected partial owned write")
        if mode == "truncated":
            self.values[key]["data"] = b'{"partial":'
            self.owners[key] = op["id"]
            raise RuntimeError("Injected interrupted startup replacement")
        if mode == "crash":
            raise KeyboardInterrupt("Injected process interruption after write")
        if mode == "after":
            raise RuntimeError("Injected lost acknowledgement")
        if op["kind"] == "alias" and self.values[key] is None:
            for original_key, original in self.originals.items():
                if original_key[0] in {"running", "startup"}:
                    assert self.values[original_key] == original, "Alias removed before both configurations restored"
        self.owners.pop(key, None)
        return True


@pytest.mark.parametrize("transport_channels", [(), (0,)])
def test_one_workflow_renders_l1_and_actual_forwarding_without_fabrication(transport_channels):
    inputs = _inputs(cages=3, routed_ports=None, transport_channels=transport_channels)
    snapshot, manifest, baselines, canonical, templates = inputs
    contexts = deployment.render_contexts(snapshot, manifest, baselines, canonical)
    bundle = deployment.render_bundle(*inputs)
    assert len(manifest["port_bindings"]) == 5
    assert len(bundle["transport"]) == (2 if transport_channels else 0)
    assert {row["dut_port"] for row in bundle["transport"]} == {row["dut_port"] for row in manifest["endpoints"]}
    for binding in manifest["port_bindings"]:
        for device, port in (("dut", binding["dut_port"]), (binding["leaf"], binding["leaf_port"])):
            config = bundle["add_configs"][device]
            assert config["PORT"][port]["admin_status"] == "up"
            assert config["CABLE_LENGTH"]["AZURE"][port] == binding["cable"]
            assert contexts[device]["add"]["CABLE_LENGTH"]["AZURE"][port] == binding["cable"]
        if binding["transport"] is None:
            config, port = bundle["deploy_configs"]["dut"], binding["dut_port"]
            assert not any(key == port or key.startswith(port + "|") for key in config["INTERFACE"])
            assert not any(key.endswith("|" + port) for key in config["VLAN_MEMBER"])
    if not transport_channels:
        assert not manifest["traffic_cases"]
        assert "Vlan100" not in bundle["deploy_configs"]["dut"]["VLAN"]
        assert "0.0.0.0/0" not in bundle["deploy_configs"]["dut"]["STATIC_ROUTE"]
    assert bundle["add_configs"]["dut"]["PORT"] == bundle["deploy_configs"]["dut"]["PORT"]
    assert bundle["add_configs"]["dut"]["CABLE_LENGTH"] == bundle["deploy_configs"]["dut"]["CABLE_LENGTH"]


@pytest.mark.parametrize("transport_channels", [(), (0,)])
def test_automatic_transaction_restores_distinct_running_and_startup_without_replanning(workspace, transport_channels):
    bundle = deployment.render_bundle(*_inputs(cages=3, routed_ports=None, transport_channels=transport_channels))
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    transaction.add()
    transaction.deploy()
    recovered = deployment.DeploymentTransaction.open(str(workspace), backend)
    recovered.remove()
    assert backend.values == backend.originals
    assert recovered.status()["state"] == "RESTORED"


def test_complete_canonical_rendering_and_phase_ownership(inputs):
    snapshot, manifest, baselines, canonical, templates = inputs
    original = copy.deepcopy(inputs)
    bundle = deployment.render_bundle(*inputs)
    assert inputs == original
    assert bundle["manifest"] == manifest
    assert set(bundle["deploy_configs"]) == {"dut"}
    for device, candidate in bundle["add_configs"].items():
        old = baselines[device]["running"]
        protected = bundle["ownership"][device]["protected_ports"]
        assert protected
        for name in protected:
            assert candidate["PORT"][name] == old["PORT"][name]
            assert candidate["PORT_QOS_MAP"][name] == old["PORT_QOS_MAP"][name]
        assert candidate["ACL_TABLE"] == old["ACL_TABLE"]
        assert candidate["PRIVATE_TABLE"] == old["PRIVATE_TABLE"]
        assert candidate["BUFFER_POOL"] == old["BUFFER_POOL"]
        for name, row in canonical[device].items():
            assert candidate["PORT"][name] == dict(row, admin_status="up")
            assert candidate["PORT"][name]["subport"] == row["subport"]
            assert name not in candidate["INTERFACE"]
        startup = bundle["baselines"][device]["startup"]
        assert base64.b64decode(startup["data_b64"]) == baselines[device]["startup"]["data"]
        assert startup["metadata"] == baselines[device]["startup"]["metadata"]
    quad = next(entry for entry in manifest["layout"] if len(entry["expansion"]["ports"]) == 4)
    assert len({port["index"] for port in quad["expansion"]["ports"]}) == 1
    assert len({port["name"] for port in quad["expansion"]["ports"]}) == 4
    deployed, added = bundle["deploy_configs"]["dut"], bundle["add_configs"]["dut"]
    assert deployed["PORT"] == added["PORT"]
    assert deployed["CABLE_LENGTH"] == added["CABLE_LENGTH"]
    assert "Vlan100" not in added["VLAN"]
    assert len([key for key in deployed["INTERFACE"] if "|" in key and key.split("|")[0] in canonical["dut"]]) == 1
    for endpoint in manifest["endpoints"]:
        peer = endpoint["ptf_address"].split("/")[0]
        interface = endpoint["dut_port"] if endpoint["role"] == "routed" else "Vlan100"
        assert deployed["STATIC_ROUTE"][peer + "/32"] == {"ifname": interface, "nexthop": peer}
    assert deployed["STATIC_ROUTE"]["0.0.0.0/0"]["nexthop"] == next(
        endpoint["ptf_address"].split("/")[0] for endpoint in manifest["endpoints"] if endpoint["role"] == "routed")
    assert deployed["BUFFER_PROFILE"]["scenario_pg"]["xon"] == "111"
    assert added["BUFFER_PROFILE"]["scenario_pg"]["xon"] == "110"
    canonical["dut"].clear()
    manifest["layout"].clear()
    assert bundle["manifest"]["layout"] and bundle["add_configs"]["dut"]["PORT"]


def test_unconnected_leaf_children_down_and_outside_transport():
    inputs = _inputs(inactive_children=True)
    bundle = deployment.render_bundle(*inputs)
    inactive = bundle["ownership"]["leaf"]["inactive_ports"]
    assert inactive
    for name in inactive:
        assert bundle["add_configs"]["leaf"]["PORT"][name]["admin_status"] == "down"
        assert not any(key.endswith("|" + name) for key in bundle["add_configs"]["leaf"]["VLAN_MEMBER"])
    assert all(item["uplink_ports"] == ["uplink"] and item["trunk"] == "opaque-host-bridge"
               for item in bundle["transport"])


def test_configured_routed_count_and_explicit_default_next_hops():
    inputs = _inputs(routed_ports=2)
    bundle = deployment.render_bundle(*inputs)
    routed = [endpoint for endpoint in inputs[1]["endpoints"] if endpoint["role"] == "routed"]
    assert len(routed) == 2
    config = bundle["deploy_configs"]["dut"]
    assert config["STATIC_ROUTE"]["0.0.0.0/0"] == {
        "ifname": ",".join(endpoint["dut_port"] for endpoint in routed),
        "nexthop": ",".join(endpoint["ptf_address"].split("/")[0] for endpoint in routed),
    }
    assert all(endpoint["dut_port"] + "|" + endpoint["dut_address"] in config["INTERFACE"] for endpoint in routed)


@pytest.mark.parametrize("inactive_children", [False, True])
def test_template_contexts_match_final_layout_cables_and_forwarding_without_fabricated_policy(inactive_children):
    inputs = _inputs(inactive_children=inactive_children)
    original = copy.deepcopy(inputs)
    contexts = deployment.render_contexts(*inputs[:4])
    bundle = deployment.render_bundle(*inputs)
    assert inputs == original
    for device, stages in contexts.items():
        assert set(stages) == ({"add", "deploy"} if device == "dut" else {"add"})
        baseline = inputs[2][device]["running"]
        selected = set(inputs[3][device])
        for phase, context in stages.items():
            final = bundle["add_configs" if phase == "add" else "deploy_configs"][device]
            for table in ("PORT", "CABLE_LENGTH", "DEVICE_METADATA", "INTERFACE",
                          "VLAN", "VLAN_MEMBER", "VLAN_INTERFACE", "STATIC_ROUTE"):
                assert context.get(table) == final.get(table)
            assert context["BUFFER_PROFILE"] == baseline["BUFFER_PROFILE"]
            assert context["BUFFER_POOL"] == baseline["BUFFER_POOL"]
            assert not any(key.split("|")[0] in selected for key in context["BUFFER_PG"])
            assert context["CABLE_LENGTH"]["AZURE"]["uplink"] == baseline["CABLE_LENGTH"]["AZURE"]["uplink"]
            for port in bundle["ownership"][device]["inactive_ports"]:
                assert context["PORT"][port]["admin_status"] == "down"
                assert all(port not in row for row in context["CABLE_LENGTH"].values())
    port = next(iter(inputs[3]["dut"]))
    contexts["dut"]["add"]["PORT"][port]["subport"] = "caller-change"
    assert contexts["dut"]["deploy"]["PORT"][port]["subport"] != "caller-change"
    assert inputs == original


def test_context_generated_tables_still_require_independent_complete_bundle_validation(inputs):
    contexts = deployment.render_contexts(*inputs[:4])
    tables = copy.deepcopy(inputs[4])
    for device, stages in contexts.items():
        for phase, context in stages.items():
            tables[device][phase]["CABLE_LENGTH"] = copy.deepcopy(context["CABLE_LENGTH"])
    bundle = deployment.render_bundle(*inputs[:4], tables)
    assert bundle["add_configs"]["leaf"]["CABLE_LENGTH"] == contexts["leaf"]["add"]["CABLE_LENGTH"]
    assert bundle["deploy_configs"]["dut"]["PORT"] == contexts["dut"]["deploy"]["PORT"]
    invalid = copy.deepcopy(tables)
    invalid["dut"]["deploy"]["BUFFER_PG"].pop(next(iter(invalid["dut"]["deploy"]["BUFFER_PG"])))
    with pytest.raises(deployment.DeploymentError, match="complete candidate PORT"):
        deployment.render_bundle(*inputs[:4], invalid)
    invalid = copy.deepcopy(tables)
    invalid["dut"]["add"]["BUFFER_POOL"]["ingress_pool"]["size"] = "1"
    with pytest.raises(deployment.DeploymentError, match="shared protected"):
        deployment.render_bundle(*inputs[:4], invalid)
    with pytest.raises(deployment.DeploymentError, match="Unknown installed"):
        deployment.render_bundle(*inputs[:4], contexts)


def test_template_contexts_use_recorded_cable_groups_instead_of_a_default(inputs):
    endpoint = next(endpoint for endpoint in inputs[1]["endpoints"] if endpoint["speed"] == 400000)
    baseline = inputs[2]["dut"]["running"]
    old_port = endpoint["dut_port"]
    baseline["CABLE_LENGTH"]["SITE_POLICY"] = {old_port: baseline["CABLE_LENGTH"]["AZURE"].pop(old_port)}
    contexts = deployment.render_contexts(*inputs[:4])
    for context in contexts["dut"].values():
        assert context["CABLE_LENGTH"]["SITE_POLICY"] == {endpoint["dut_port"]: endpoint["cable"]}
        assert endpoint["dut_port"] not in context["CABLE_LENGTH"]["AZURE"]
        assert context["CABLE_LENGTH"]["AZURE"]["uplink"] == "5m"


@pytest.mark.parametrize("problem", ["missing", "duplicate", "absent-table"])
def test_template_contexts_reject_missing_or_ambiguous_source_cable_groups(inputs, problem):
    endpoint = next(endpoint for endpoint in inputs[1]["endpoints"] if endpoint["speed"] == 400000)
    baseline = inputs[2]["dut"]["running"]
    if problem == "missing":
        del baseline["CABLE_LENGTH"]["AZURE"][endpoint["dut_port"]]
    elif problem == "duplicate":
        baseline["CABLE_LENGTH"]["OTHER"] = {endpoint["dut_port"]: "5m"}
    else:
        del baseline["CABLE_LENGTH"]
    with pytest.raises(deployment.DeploymentError, match="baseline CABLE_LENGTH group"):
        deployment.render_contexts(*inputs[:4])


@pytest.mark.parametrize("problem", ["canonical", "witness", "dependency"])
def test_template_contexts_share_frozen_witness_and_protected_dependency_checks(inputs, problem):
    if problem == "canonical":
        next(iter(inputs[3]["dut"].values()))["fec"] = "none"
        error = deployment.DeploymentError
    elif problem == "witness":
        inputs[1]["endpoints"][0]["cable"] = "unrecorded"
        error = planner.InvalidManifest
    else:
        port = next(iter(inputs[3]["dut"]))
        inputs[2]["dut"]["running"]["ACL_RULE"] = {"ambiguous": {"IN_PORTS": [port, "uplink"]}}
        error = deployment.DeploymentError
    with pytest.raises(error):
        deployment.render_contexts(*inputs[:4])


@pytest.mark.parametrize("field,value", [
    ("alias", "wrong-alias"), ("index", "999"), ("lanes", "999"), ("speed", "999"),
    ("fec", "none"), ("autoneg", "on"),
])
def test_rejects_noncanonical_full_port_rows(inputs, field, value):
    row = next(iter(inputs[3]["dut"].values()))
    row[field] = value
    with pytest.raises(deployment.DeploymentError, match="disagrees"):
        deployment.render_bundle(*inputs)


def test_rejects_lane_order_change_and_manifest_drift(inputs):
    wide = next(row for row in inputs[3]["dut"].values() if "," in row["lanes"])
    wide["lanes"] = ",".join(reversed(wide["lanes"].split(",")))
    with pytest.raises(deployment.DeploymentError, match="disagrees"):
        deployment.render_bundle(*inputs)
    inputs = _inputs()
    inputs[1]["endpoints"][0]["cable"] = "unrecorded"
    with pytest.raises(planner.InvalidManifest):
        deployment.render_bundle(*inputs)


@pytest.mark.parametrize("table,field", [
    ("ACL_RULE", "IN_PORTS"), ("PORTCHANNEL_MEMBER", None), ("UNREVIEWED_TABLE", "interface"), ("PFC_WD", "interface"),
])
def test_rejects_unknown_or_safety_sensitive_port_dependencies(inputs, table, field):
    device = "dut"
    old = next(entry["expansion"]["ports"][0]["name"] for entry in inputs[1]["layout"] if entry["device"] == device)
    rows = inputs[2][device]["running"].setdefault(table, {})
    if table == "PORTCHANNEL_MEMBER":
        rows["PortChannel1|" + old] = {}
    elif field:
        rows["policy"] = {field: [old, "uplink"]}
    else:
        rows[old] = {"action": "drop"}
    with pytest.raises(deployment.DeploymentError, match="dependency"):
        deployment.render_bundle(*inputs)


@pytest.mark.parametrize("protected", [False, True])
def test_detaches_only_owned_acl_bindings_preserving_definitions_and_rules(inputs, protected):
    old = next(iter(inputs[3]["dut"]))
    running = inputs[2]["dut"]["running"]
    ports = [old, "uplink"] if protected else [old]
    running["ACL_TABLE"]["scenario-shared"] = {"ports": ports, "type": "L3", "stage": "ingress"}
    rule = {"PRIORITY": "100", "SRC_IP": "192.0.2.0/24", "PACKET_ACTION": "DROP"}
    running["ACL_RULE"] = {"scenario-shared|rule": rule}
    bundle = deployment.render_bundle(*inputs)
    for candidate in (bundle["add_configs"]["dut"], bundle["deploy_configs"]["dut"]):
        assert candidate["ACL_TABLE"]["scenario-shared"] == {
            "ports": ["uplink"] if protected else [], "type": "L3", "stage": "ingress"}
        assert candidate["ACL_RULE"] == running["ACL_RULE"]
        assert candidate["ACL_TABLE"]["protected-policy"] == running["ACL_TABLE"]["protected-policy"]
    assert running["ACL_TABLE"]["scenario-shared"]["ports"] == ports


@pytest.mark.parametrize("overlap", [False, True])
def test_shared_vlan_preserves_protected_svi_routes_and_members(inputs, overlap):
    old = next(iter(inputs[3]["dut"]))
    running = inputs[2]["dut"]["running"]
    running["VLAN"]["Vlan60"] = {"vlanid": "60", "members": [old, "uplink"]}
    running["VLAN_MEMBER"]["Vlan60|" + old] = {"tagging_mode": "untagged"}
    running["VLAN_MEMBER"]["Vlan60|uplink"] = {"tagging_mode": "tagged"}
    address = "198.18.0.1/24" if overlap else "10.9.0.1/24"
    running["VLAN_INTERFACE"]["Vlan60"] = {}
    running["VLAN_INTERFACE"]["Vlan60|" + address] = {}
    running["STATIC_ROUTE"]["10.70.0.0/16"] = {"ifname": "Vlan60", "nexthop": "10.9.0.2"}
    if overlap:
        with pytest.raises(deployment.DeploymentError, match="overlaps a protected"):
            deployment.render_bundle(*inputs)
        return
    bundle = deployment.render_bundle(*inputs)
    for candidate in (bundle["add_configs"]["dut"], bundle["deploy_configs"]["dut"]):
        assert candidate["VLAN"]["Vlan60"] == {"vlanid": "60", "members": ["uplink"]}
        assert "Vlan60|" + old not in candidate["VLAN_MEMBER"]
        assert candidate["VLAN_MEMBER"]["Vlan60|uplink"] == running["VLAN_MEMBER"]["Vlan60|uplink"]
        assert {key: row for key, row in candidate["VLAN_INTERFACE"].items()
                if key.split("|", 1)[0] == "Vlan60"} == {
                    "Vlan60": {}, "Vlan60|" + address: {}}
        assert candidate["STATIC_ROUTE"]["10.70.0.0/16"] == running["STATIC_ROUTE"]["10.70.0.0/16"]


@pytest.mark.parametrize("resolved", [False, True])
def test_installed_tc_to_dscp_maps_require_resolved_port_bindings(inputs, resolved):
    for phases in inputs[4].values():
        for tables in phases.values():
            if resolved:
                tables["TC_TO_DSCP_MAP"] = {"scenario-dscp": {"0": "0"}}
            for row in tables["PORT_QOS_MAP"].values():
                row["tc_to_dscp_map"] = "scenario-dscp"
    if not resolved:
        with pytest.raises(deployment.DeploymentError, match="Unresolved.*TC_TO_DSCP_MAP"):
            deployment.render_bundle(*inputs)
        return
    bundle = deployment.render_bundle(*inputs)
    assert bundle["deploy_configs"]["dut"]["TC_TO_DSCP_MAP"]["scenario-dscp"] == {"0": "0"}


@pytest.mark.parametrize("case", ["bounded", "nonzero-pg", "unbounded-port-reservation"])
def test_full_device_templates_preserve_protected_pools_profiles_and_port_rows(inputs, case):
    baseline = inputs[2]["dut"]["running"]
    baseline["BUFFER_POOL"]["ingress_pool"]["xoff"] = "1000"
    original_profile = {"pool": "ingress_pool", "size": "0", "dynamic_th": "3"}
    baseline["BUFFER_PROFILE"]["scenario_pg"] = original_profile
    for table in ("BUFFER_PG", "BUFFER_QUEUE"):
        for row in baseline[table].values():
            row["profile"] = "scenario_pg"
    port_profile = {"pool": "ingress_pool",
                    "size": "221184" if case == "unbounded-port-reservation" else "9216", "dynamic_th": "3"}
    baseline["BUFFER_PROFILE"]["port_reserved"] = port_profile
    baseline["BUFFER_PORT_EGRESS_PROFILE_LIST"] = {"uplink": {"profile_list": "port_reserved"}}
    for tables in inputs[4]["dut"].values():
        tables["BUFFER_POOL"]["ingress_pool"]["size"] = "200000"
        tables["BUFFER_PROFILE"]["scenario_pg"] = {
            "pool": "ingress_pool", "size": "1" if case == "nonzero-pg" else "0", "dynamic_th": "7"}
        tables["BUFFER_PG"]["uplink|0"] = {"profile": "scenario_pg"}
        tables["PORT_QOS_MAP"]["uplink"] = {"pfc_enable": ""}
        tables["BUFFER_PROFILE"]["port_reserved"] = dict(port_profile, size="9216")
        tables["BUFFER_PORT_EGRESS_PROFILE_LIST"] = {
            port: {"profile_list": "port_reserved"} for port in list(inputs[3]["dut"]) + ["uplink"]}
        for row in tables["PORT_QOS_MAP"].values():
            row["pfc_enable"] = ""
    if case != "bounded":
        with pytest.raises(deployment.DeploymentError, match="protected"):
            deployment.render_bundle(*inputs)
        return
    bundle = deployment.render_bundle(*inputs)
    for candidate in (bundle["add_configs"]["dut"], bundle["deploy_configs"]["dut"]):
        assert candidate["BUFFER_POOL"] == baseline["BUFFER_POOL"]
        assert candidate["BUFFER_PROFILE"]["scenario_pg"] == original_profile
        assert candidate["BUFFER_PG"]["uplink|3-4"] == {"profile": "scenario_pg"}
        assert "uplink|0" not in candidate["BUFFER_PG"]
        assert candidate["PORT_QOS_MAP"]["uplink"] == baseline["PORT_QOS_MAP"]["uplink"]
        managed = next(row["profile"] for key, row in candidate["BUFFER_PG"].items()
                       if key.split("|", 1)[0] in inputs[3]["dut"])
        managed = deployment._profile_names(managed, "BUFFER_PROFILE")[0]
        assert managed != "scenario_pg"
        assert candidate["BUFFER_PROFILE"][managed] == {
            "pool": "ingress_pool", "size": "0", "dynamic_th": "7"}


def test_rejects_shared_port_groups(inputs):
    old = next(iter(inputs[3]["dut"]))
    inputs[2]["dut"]["running"]["PORT_QOS_MAP"][old + ",uplink"] = {"pfc_enable": "3,4"}
    with pytest.raises(deployment.DeploymentError, match="shared port group"):
        deployment.render_bundle(*inputs)


def test_protected_address_space_and_shared_route_next_hops_are_not_repurposed(inputs):
    baseline = inputs[2]["dut"]["running"]
    baseline["INTERFACE"]["uplink|198.18.0.1/24"] = {}
    with pytest.raises(deployment.DeploymentError, match="overlaps a protected"):
        deployment.render_bundle(*inputs)
    inputs = _inputs()
    old = next(iter(inputs[3]["dut"]))
    inputs[2]["dut"]["running"]["STATIC_ROUTE"]["10.255.0.0/24"] = {
        "ifname": old + ",uplink", "nexthop": "10.0.0.1,192.0.2.0",
    }
    with pytest.raises(deployment.DeploymentError, match="shared static route"):
        deployment.render_bundle(*inputs)


def test_removes_owned_routes_neighbors_and_interfaces_together(inputs):
    old = next(iter(inputs[3]["dut"]))
    baseline = inputs[2]["dut"]["running"]
    local = next(key.split("|", 1)[1].split("/")[0] for key in baseline["INTERFACE"] if key.startswith(old + "|"))
    baseline["BGP_NEIGHBOR"] = {
        "10.0.0.1": {"local_addr": local, "name": "old-peer"},
        "192.0.2.0": {"local_addr": "192.0.2.1", "name": "protected-peer"},
    }
    baseline["STATIC_ROUTE"]["10.255.0.0/24"] = {"ifname": old, "nexthop": "10.0.0.1"}
    baseline["NEIGH"] = {old + "|10.0.0.1": {"neigh": "00:00:00:00:00:01"}}
    baseline["DEVICE_NEIGHBOR"] = {
        old: {"name": "old-peer", "port": "old-port"},
        "uplink": {"name": "protected-peer", "port": old},
    }
    baseline["PORT"]["uplink"]["description"] = "remote-peer:" + old
    baseline["PFC_WD"] = {
        old: {"action": "drop"}, "uplink": {"action": "alert"}, "GLOBAL": {"POLL_INTERVAL": "200"},
    }
    bundle = deployment.render_bundle(*inputs)
    candidate = bundle["add_configs"]["dut"]
    assert "10.255.0.0/24" not in candidate["STATIC_ROUTE"]
    assert not candidate["NEIGH"]
    assert candidate["DEVICE_NEIGHBOR"] == dict({
        row["dut_port"]: {"name": row["leaf"], "port": row["leaf_port"]} for row in inputs[1]["port_bindings"]},
        uplink=baseline["DEVICE_NEIGHBOR"]["uplink"])
    assert candidate["PORT"]["uplink"] == baseline["PORT"]["uplink"]
    assert candidate["PFC_WD"] == {"uplink": {"action": "alert"}, "GLOBAL": {"POLL_INTERVAL": "200"}}
    assert old not in candidate["INTERFACE"]
    assert candidate["BGP_NEIGHBOR"] == {"192.0.2.0": baseline["BGP_NEIGHBOR"]["192.0.2.0"]}
    assert candidate["STATIC_ROUTE"]["203.0.113.0/24"] == baseline["STATIC_ROUTE"]["203.0.113.0/24"]


def test_requires_reserved_vlan_verified_uplinks_and_isolation(inputs):
    endpoint = inputs[1]["endpoints"][0]
    vlan = "Vlan{}".format(endpoint["transport"]["vlan"])
    baseline = inputs[2]["leaf"]["running"]
    del baseline["VLAN_MEMBER"][vlan + "|uplink"]
    with pytest.raises(deployment.DeploymentError, match="Missing verified"):
        deployment.render_bundle(*inputs)
    override = {endpoint["transport"]["id"]: {"ports": ["uplink"], "evidence_sha256": "c" * 64}}
    bundle = deployment.render_bundle(*inputs, transport_uplinks=override)
    assert bundle["add_configs"]["leaf"]["VLAN_MEMBER"][vlan + "|uplink"] == {"tagging_mode": "tagged"}
    baseline["VLAN_INTERFACE"][vlan + "|10.9.0.1/24"] = {}
    with pytest.raises(deployment.DeploymentError, match="logical L3"):
        deployment.render_bundle(*inputs, transport_uplinks=override)
    inputs = _inputs()
    endpoint = inputs[1]["endpoints"][0]
    del inputs[2]["leaf"]["running"]["VLAN"]["Vlan{}".format(endpoint["transport"]["vlan"])]
    with pytest.raises(deployment.DeploymentError):
        deployment.render_bundle(*inputs)


@pytest.mark.parametrize("change", ["global", "missing", "unknown", "cable", "leaf-deploy"])
def test_installed_templates_cannot_change_protected_globals_or_frozen_assignment(inputs, change):
    tables = inputs[4]["dut"]["deploy"]
    if change == "global":
        tables["BUFFER_POOL"]["ingress_pool"]["size"] = "1"
    elif change == "missing":
        tables["BUFFER_PG"].clear()
    elif change == "unknown":
        tables["BREAKOUT_CFG"] = {"invented": {"mode": "4x100G"}}
    elif change == "cable":
        tables["CABLE_LENGTH"]["AZURE"][next(iter(inputs[3]["dut"]))] = "unplanned"
    else:
        inputs[4]["leaf"]["deploy"] = {}
    with pytest.raises(deployment.DeploymentError):
        deployment.render_bundle(*inputs)


def test_standard_native_templates_need_buffer_coverage_only_for_active_leaf_children():
    inputs = _inputs(inactive_children=True)
    inactive = {port for entry in inputs[1]["layout"] if entry["device"] == "leaf" for port in entry["inactive_ports"]}
    assert inactive
    for tables in inputs[4]["leaf"].values():
        for table in ("BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP"):
            for key in list(tables[table]):
                if key.split("|", 1)[0] in inactive:
                    del tables[table][key]
    bundle = deployment.render_bundle(*inputs)
    assert all(bundle["add_configs"]["leaf"]["PORT"][port]["admin_status"] == "down" for port in inactive)


def test_native_pfc_to_queue_map_resolves_the_standard_configdb_table(inputs):
    for phases in inputs[4].values():
        for tables in phases.values():
            tables["MAP_PFC_PRIORITY_TO_QUEUE"] = {"generic": {"3": "3", "4": "4"}}
            for row in tables["PORT_QOS_MAP"].values():
                row["pfc_to_queue_map"] = "[MAP_PFC_PRIORITY_TO_QUEUE|generic]"
    bundle = deployment.render_bundle(*inputs)
    assert bundle["deploy_configs"]["dut"]["MAP_PFC_PRIORITY_TO_QUEUE"]["generic"]["3"] == "3"
    for row in inputs[4]["dut"]["deploy"]["PORT_QOS_MAP"].values():
        row["pfc_to_queue_map"] = "[MAP_PFC_PRIORITY_TO_QUEUE|missing]"
    with pytest.raises(deployment.DeploymentError, match="Unresolved installed QoS/buffer reference"):
        deployment.render_bundle(*inputs)


def test_durable_private_intents_repeats_and_dut_only_deploy(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    assert transaction.add()["state"] == "ADDED"
    add_writes = len(backend.writes)
    assert add_writes
    assert not transaction.add()["changed"]
    assert len(backend.writes) == add_writes
    leaf_before = {key: copy.deepcopy(value) for key, value in backend.values.items() if key[1] == "leaf"}
    assert transaction.deploy()["state"] == "DEPLOYED"
    assert all(op["target"] == "dut" and op["kind"] in {"running", "startup"}
               for op in backend.writes[add_writes:])
    assert all(backend.values[key] == value for key, value in leaf_before.items())
    after_deploy = len(backend.writes)
    assert not transaction.deploy()["changed"]
    assert not transaction.add()["changed"]
    resumed = deployment.DeploymentTransaction(workspace, bundle, backend, hosts, aliases)
    assert not resumed.deploy()["changed"]
    assert len(backend.writes) == after_deploy
    assert all(op["status"] == "VERIFIED" for op in resumed.status()["operations"])
    for path in [workspace, workspace / "journal.json", workspace / "artifacts"]:
        deployment._private(str(path), directory=path.is_dir())
        if os.name != "nt":
            assert not path.stat().st_mode & 0o077
    assert transaction.remove()["state"] == "RESTORED"
    assert backend.values == backend.originals
    assert not transaction.remove()["changed"]


@pytest.mark.parametrize("kind,target,mode", [
    ("host", "owned-ptf-and-transport", "after"),
    ("host", "owned-ptf-and-transport", "partial"),
    ("running", "leaf", "after"),
    ("running", "leaf", "partial"),
    ("running", "leaf", "empty-partial"),
    ("startup", "leaf", "truncated"),
])
def test_failed_and_unacknowledged_device_or_host_writes_compensate(workspace, bundle, kind, target, mode):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", kind, target, mode))
    with pytest.raises(deployment.TransactionError, match="original state verified restored"):
        transaction.add()
    assert transaction.status()["state"] == "RESTORED"
    assert backend.values == backend.originals
    attempted = next(op for op in transaction.status()["operations"] if op["phase"] == "add"
                     and op["kind"] == kind and op["target"] == target)
    assert attempted["status"] == "INTENT" and attempted["compensated"]
    assert any(op["phase"] == "restore" and op["kind"] == kind and op["target"] == target
               for op in backend.writes)


@pytest.mark.parametrize("legacy", [False, True])
def test_restored_failure_retry_preserves_history_and_resumes_its_new_attempt(workspace, bundle, legacy):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", "running", "leaf", "before"))
    with pytest.raises(deployment.TransactionError):
        transaction.add()
    if legacy:
        journal = deployment._read_json(str(workspace / "journal.json"))
        journal.pop("attempt", None)
        journal.pop("previous_attempts", None)
        for operation in journal["operations"]:
            operation.pop("attempt", None)
        for field in ("attempt", "stage", "message"):
            journal["last_error"].pop(field, None)
        journal.pop("journal_sha256")
        journal["journal_sha256"] = deployment._digest(journal)
        deployment._atomic_json(str(workspace / "journal.json"), journal)
    closed = transaction.status()
    backend.failures.append(("add", "running", "leaf", "crash"))
    resumed = deployment.DeploymentTransaction.open(workspace, backend)
    with pytest.raises(KeyboardInterrupt):
        resumed.add()
    assert resumed.status()["state"] == "ADDING"
    assert resumed.status()["attempt"] == 1
    recovered = deployment.DeploymentTransaction.open(workspace, backend)
    assert recovered.add()["state"] == "ADDED"
    assert recovered.deploy()["state"] == "DEPLOYED"
    current = recovered.status()
    assert current["previous_attempts"][0]["last_error"] == closed["last_error"]
    assert current["operations"][:len(closed["operations"])] == closed["operations"]
    assert current["resources"] == closed["resources"] and current["bundle"] == closed["bundle"]
    assert len({operation["id"] for operation in current["operations"]}) == len(current["operations"])
    assert sum(operation.get("attempt", 0) == 1 and operation["phase"] == "add"
               and operation["kind"] == "running" and operation["target"] == "leaf"
               for operation in backend.writes) == 1
    assert recovered.remove()["state"] == "RESTORED"
    assert backend.values == backend.originals
    assert recovered.status()["operations"][:len(closed["operations"])] == closed["operations"]


@pytest.mark.parametrize("kind", ["running", "startup"])
def test_restored_retry_rechecks_originals_before_creating_an_attempt(workspace, bundle, kind):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", "running", "leaf", "before"))
    with pytest.raises(deployment.TransactionError):
        transaction.add()
    if kind == "running":
        backend.values[(kind, "dut")]["PORT"]["uplink"]["description"] = "external owner's change"
    else:
        backend.values[(kind, "dut")]["data"] += b"\n"
    drift = copy.deepcopy(backend.values)
    writes = len(backend.writes)
    with pytest.raises(deployment.RestorationError, match="Previously restored state has drifted"):
        transaction.add()
    assert len(backend.writes) == writes and backend.values == drift
    assert transaction.status()["state"] == "RESTORE_FAILED"
    assert transaction.status()["attempt"] == 0
    assert not transaction.status()["previous_attempts"]


def test_successful_explicit_teardown_remains_terminal(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    transaction.add()
    transaction.deploy()
    transaction.remove()
    writes = len(backend.writes)
    with pytest.raises(deployment.ConflictError, match="Cannot add"):
        transaction.add()
    assert len(backend.writes) == writes and backend.values == backend.originals


@pytest.mark.parametrize("retry_ready", [False, True])
def test_add_readiness_failure_then_scheduler_retry_deploys_without_losing_recovery(
        workspace, bundle, monkeypatch, retry_ready):
    import generic_hwsku_backend as native_backend

    workspace.mkdir(parents=True, mode=0o700)
    transaction, simulator, hosts, aliases = _transaction(workspace / "transaction", bundle)
    target = next(iter(hosts))
    simulator.payload = {"bundle": bundle, "host_target": target, "host_spec": {}, "aliases": aliases}
    checks = []

    def health(phase):
        checks.append(phase)
        if len(checks) == 1 or not retry_ready:
            raise native_backend.NativeOperationError("Ethernet512: selected physical link is not up")
        return {"dut": {"ready": True}}

    simulator.health = health
    monkeypatch.setattr(native_backend, "prepare_backend", lambda *arguments: simulator)
    monkeypatch.setattr(native_backend, "legacy_cleanup", lambda *arguments: None)
    monkeypatch.setattr(native_backend, "candidate_state", lambda spec: hosts[target]["candidate"])
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    native_backend.private_json(workspace / "provenance.json", {"owner_plan_id": "owned-plan"})
    native_backend.private_json(workspace / "backend.json", simulator.payload)
    with pytest.raises(native_backend.TransactionError, match="add-topo readiness failed"):
        native_backend.run_phase("add-topo", SimpleNamespace(), {}, {}, workspace)
    assert transaction.status()["state"] == "RESTORED" and simulator.values == simulator.originals
    if not retry_ready:
        with pytest.raises(native_backend.TransactionError, match="add-topo readiness failed.*Ethernet512"):
            native_backend.run_phase("add-topo", SimpleNamespace(), {}, {}, workspace)
        assert transaction.status()["state"] == "RESTORED" and transaction.status()["attempt"] == 1
        assert simulator.values == simulator.originals
        assert checks == ["add-topo", "add-topo"]
        return
    added = native_backend.run_phase("add-topo", SimpleNamespace(), {}, {}, workspace)
    assert added["status"] == "TOPO_READY" and added["attempt"] == 1
    deployed = native_backend.run_phase("deploy-mg", SimpleNamespace(), {}, {}, workspace)
    assert deployed["status"] == "DUT_READY" and deployed["attempt"] == 1
    native_backend.verify_smoke_ready(
        deployment.DeploymentTransaction.open(workspace / "transaction", simulator), simulator,
        dict(deployed, scenario_id=bundle["scenario_id"]))
    restored = native_backend.run_phase("remove-topo", SimpleNamespace(), {}, {}, workspace)
    assert restored["status"] == "RESTORED" and simulator.values == simulator.originals
    failure = transaction.status()["previous_attempts"][0]["last_error"]
    assert failure["phase"] == "add-topo" and failure["stage"] == "readiness"
    assert "Ethernet512" in failure["message"]
    assert checks == ["add-topo", "add-topo", "deploy-mg"]


def test_deploy_failure_compensates_entire_add_not_just_last_dut_change(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    transaction.add()
    backend.failures.append(("deploy", "startup", "dut", "after"))
    with pytest.raises(deployment.TransactionError):
        transaction.deploy()
    assert transaction.status()["state"] == "RESTORED"
    assert backend.values == backend.originals
    assert {op["kind"] for op in backend.writes if op["phase"] == "restore"} == {"running", "startup", "host", "alias"}


@pytest.mark.parametrize("enabled,ready", [(False, True), (True, True), (True, False)])
def test_post_image_first_deploy_requires_opt_in_and_runs_real_add_with_recovery(
        workspace, bundle, monkeypatch, enabled, ready):
    import generic_hwsku_backend as native_backend

    workspace.mkdir(parents=True, mode=0o700)
    hosts = {"owned-ptf-and-transport": {
        "baseline": None, "candidate": {"interfaces": bundle["transport"], "routes": ["manifest-bound"]}}}
    unused_transaction, simulator, hosts, aliases = _transaction(workspace / "seed", bundle, hosts=hosts)
    run = workspace / "post-image"
    run.mkdir(mode=0o700)
    simulator.journal_path = str(run / "transaction" / "journal.json")
    target = next(iter(hosts))
    simulator.payload = {"bundle": bundle, "host_target": target, "host_spec": {}, "aliases": aliases}
    checks = []

    def health(phase):
        checks.append(phase)
        if not ready:
            raise native_backend.NativeOperationError("selected post-image link is not ready")
        return {"dut": {"ready": True}}

    simulator.health = health
    monkeypatch.setattr(native_backend, "prepare_backend", lambda *arguments: simulator)
    monkeypatch.setattr(native_backend, "legacy_cleanup", lambda *arguments: None)
    monkeypatch.setattr(native_backend, "candidate_state", lambda spec: hosts[target]["candidate"])
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    monkeypatch.setenv("SONIC_GENERIC_BOOTSTRAP_DEPLOY", "1" if enabled else "")
    native_backend.private_json(run / "provenance.json", {"owner_plan_id": "owned-plan"})
    native_backend.private_json(run / "backend.json", simulator.payload)
    if not enabled:
        with pytest.raises(native_backend.PrerequisiteError, match="add-topo must establish"):
            native_backend.run_phase("deploy-mg", SimpleNamespace(), {}, {}, run)
        assert not simulator.writes and not (run / "transaction").exists()
        return
    if not ready:
        with pytest.raises(native_backend.TransactionError, match="add-topo readiness failed"):
            native_backend.run_phase("deploy-mg", SimpleNamespace(), {}, {}, run)
        journal = deployment.DeploymentTransaction.open(run / "transaction", simulator).status()
        assert journal["state"] == "RESTORED" and simulator.values == simulator.originals
        assert journal["last_error"]["phase"] == "add-topo"
        assert not any(operation["phase"] == "deploy" for operation in simulator.writes)
        ready = True
    result = native_backend.run_phase("deploy-mg", SimpleNamespace(), {}, {}, run)
    assert result["status"] == "DUT_READY" and checks[-2:] == ["add-topo", "deploy-mg"]
    assert result["attempt"] == len(checks) - 2
    transaction = deployment.DeploymentTransaction.open(run / "transaction", simulator)
    assert transaction.status()["state"] == "DEPLOYED"
    native_backend.verify_smoke_ready(transaction, simulator, dict(result, scenario_id=bundle["scenario_id"]))
    restored = native_backend.run_phase("remove-topo", SimpleNamespace(), {}, {}, run)
    assert restored["status"] == "RESTORED" and simulator.values == simulator.originals
    count = len(simulator.writes)
    with pytest.raises(native_backend.ConflictError, match="Cannot deploy.*RESTORED"):
        native_backend.run_phase("deploy-mg", SimpleNamespace(), {}, {}, run)
    assert len(simulator.writes) == count


def test_interrupted_forward_intent_can_resume_or_restore(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", "running", "leaf", "crash"))
    with pytest.raises(KeyboardInterrupt):
        transaction.add()
    assert transaction.status()["state"] == "ADDING"
    writes = len(backend.writes)
    resumed = deployment.DeploymentTransaction.open(workspace, backend)
    assert resumed.add()["state"] == "ADDED"
    assert len([op for op in backend.writes if op["phase"] == "add" and op["kind"] == "running"
                and op["target"] == "leaf"]) == 1
    assert len(backend.writes) > writes
    resumed.remove()
    assert backend.values == backend.originals


def test_pending_host_intent_is_compensated_on_explicit_remove(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", "host", "owned-ptf-and-transport", "crash"))
    with pytest.raises(KeyboardInterrupt):
        transaction.add()
    assert transaction.status()["operations"][-1]["status"] == "INTENT"
    resumed = deployment.DeploymentTransaction(workspace, bundle, backend, hosts, aliases)
    assert resumed.remove()["state"] == "RESTORED"
    assert backend.values == backend.originals


def test_last_unacknowledged_write_is_not_reported_as_no_change(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.failures.append(("add", "startup", "dut", "crash"))
    with pytest.raises(KeyboardInterrupt):
        transaction.add()
    writes = len(backend.writes)
    resumed = deployment.DeploymentTransaction.open(workspace, backend)
    assert resumed.add() == {
        "state": "ADDED", "changed": True, "scenario_id": bundle["scenario_id"],
        "journal": str(workspace.resolve() / "journal.json"), "attempt": 0,
    }
    assert len(backend.writes) == writes
    resumed.remove()


def test_distinct_startup_bytes_metadata_and_interrupted_restoration_are_preserved(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    transaction.add()
    transaction.deploy()
    backend.failures.append(("restore", "startup", "dut", "crash"))
    with pytest.raises(KeyboardInterrupt):
        transaction.remove()
    assert transaction.status()["state"] == "RESTORING"
    resumed = deployment.DeploymentTransaction(workspace, bundle, backend, hosts, aliases)
    assert resumed.remove()["state"] == "RESTORED"
    assert backend.values == backend.originals
    assert b"must-not-be-saved-over" in backend.values[("startup", "dut")]["data"]
    assert backend.values[("startup", "dut")]["data"].startswith(b" \n")
    assert backend.values[("startup", "dut")]["metadata"]["mode"] == 0o640
    assert b"must-not-be-saved-over" not in planner.canonical_json(backend.values[("running", "dut")]).encode()
    assert all(op["status"] == "VERIFIED" for op in resumed.status()["operations"] if op["phase"] == "restore")


def test_restore_failure_retains_aliases_and_can_resume(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    transaction.add()
    backend.failures.append(("restore", "startup", "leaf", "before"))
    with pytest.raises(deployment.RestorationError):
        transaction.remove()
    assert transaction.status()["state"] == "RESTORE_FAILED"
    assert all(backend.values[("alias", target)] is not None for target in aliases)
    assert all(value == backend.originals[key] for key, value in backend.values.items()
               if key[0] != "alias" and key != ("startup", "leaf"))
    assert (workspace / "journal.json").is_file()
    assert list((workspace / "artifacts").iterdir())
    resumed = deployment.DeploymentTransaction(workspace, bundle, backend, hosts, aliases)
    assert resumed.remove()["state"] == "RESTORED"
    assert backend.values == backend.originals


def test_unexplained_external_drift_is_never_overwritten_or_claimed_restored(workspace, bundle):
    transaction, backend, unused_hosts, aliases = _transaction(workspace, bundle)
    transaction.add()
    backend.values[("running", "leaf")]["PORT"]["uplink"]["description"] = "external owner's change"
    drift = copy.deepcopy(backend.values[("running", "leaf")])
    with pytest.raises(deployment.RestorationError):
        transaction.deploy()
    assert transaction.status()["state"] == "RESTORE_FAILED"
    assert backend.values[("running", "leaf")] == drift
    assert all(backend.values[("alias", target)] is not None for target in aliases)
    with pytest.raises(deployment.RestorationError):
        transaction.remove()
    assert transaction.status()["state"] != "RESTORED"
    assert backend.values[("running", "leaf")] == drift


def test_no_callback_success_without_readback_or_mutation(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.no_write = True
    with pytest.raises(deployment.TransactionError, match="original state verified restored"):
        transaction.add()
    assert transaction.status()["state"] == "RESTORED"
    assert backend.values == backend.originals
    assert transaction.status()["operations"][0]["status"] == "INTENT"


def test_boolean_acknowledgement_is_not_independent_verification(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    backend.verify = lambda op: True
    with pytest.raises(deployment.RestorationError):
        transaction.add()
    assert not backend.writes
    assert transaction.status()["state"] == "RESTORE_FAILED"


def test_repeated_remove_detects_drift_after_a_completed_restore(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    transaction.add()
    transaction.remove()
    backend.values[("running", "dut")]["PORT"]["uplink"]["description"] = "new external configuration"
    with pytest.raises(deployment.RestorationError):
        transaction.remove()
    assert transaction.status()["state"] == "RESTORE_FAILED"
    writes = len(backend.writes)
    with pytest.raises(deployment.RestorationError):
        transaction.remove()
    assert len(backend.writes) == writes


def test_conflicting_inputs_and_corrupt_artifacts_fail_before_writes(workspace, bundle):
    transaction, backend, hosts, aliases = _transaction(workspace, bundle)
    changed = copy.deepcopy(hosts)
    changed["owned-ptf-and-transport"]["candidate"]["routes"] = ["drift"]
    with pytest.raises(deployment.ConflictError, match="conflicting"):
        deployment.DeploymentTransaction(workspace, bundle, backend, changed, aliases)
    reference = transaction.status()["resources"][0]["add"]
    with open(reference["path"], "wb") as stream:
        stream.write(b"{}\n")
    with pytest.raises(deployment.DeploymentError, match="integrity"):
        transaction.add()
    assert not backend.writes


def test_in_memory_frozen_plan_drift_is_rejected_before_backend_write(workspace, bundle):
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle)
    transaction.bundle["deploy_configs"]["dut"]["PORT"]["uplink"]["description"] = "not in frozen bundle"
    with pytest.raises(deployment.ConflictError, match="Frozen"):
        transaction.add()
    assert not backend.writes


def test_existing_aliases_are_verified_but_never_deleted(workspace, bundle):
    aliases = {
        device: {"device": device, "name": "RecordedScenario",
                 "baseline": {"name": "RecordedScenario", "content_sha256": "b" * 64},
                 "candidate": {"name": "RecordedScenario", "content_sha256": "b" * 64}}
        for device in bundle["add_configs"]
    }
    transaction, backend, unused_hosts, unused_aliases = _transaction(workspace, bundle, aliases=aliases)
    transaction.add()
    transaction.remove()
    assert not any(op["kind"] == "alias" for op in backend.writes)
    assert backend.values == backend.originals


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode check; Windows DACL is exercised by transaction tests")
def test_refuses_nonprivate_workspace(workspace, bundle):
    workspace.mkdir(parents=True)
    os.chmod(str(workspace), stat.S_IRWXU | stat.S_IRGRP)
    with pytest.raises(deployment.DeploymentError, match="permissions"):
        _transaction(workspace, bundle)
