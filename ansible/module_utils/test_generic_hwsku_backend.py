"""Private native readback, immutable smoke admission and fresh-collection regressions."""

import ast
import base64
import copy
import importlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
backend = importlib.import_module("generic_hwsku_backend")
lifecycle = importlib.import_module("generic_hwsku_lifecycle")


@pytest.mark.parametrize("mmu", [None, "0", "99", "100"])
def test_shared_pool_retention_requires_real_sufficient_sdk_mmu_capacity(mmu):
    bundle = {"add_configs": {"dut": {"BUFFER_POOL": {"pool": {"size": "50"}}}}}
    tables = {"dut": {"add": {"BUFFER_POOL": {"pool": {"size": "100"}}}}}
    facts = {"dut": {"applied_buffers": {"mmu_size": mmu}}}
    if mmu != "100":
        with pytest.raises(backend.PrerequisiteError, match="MMU capacity"):
            backend.verify_shared_pool_capacity(bundle, tables, facts)
        return
    backend.verify_shared_pool_capacity(bundle, tables, facts)


class Runner:
    def __init__(self, value):
        self.value, self.calls = value, []

    def call(self, kind, target, request):
        self.calls.append((kind, target, request))
        return {"value": copy.deepcopy(self.value), "owned_by": "actual-native-operation"}


@pytest.mark.parametrize("changed", [None, "pfc", "headroom"])
def test_lossy_template_readback_cannot_silently_enable_unbudgeted_lossless_state(changed):
    config = {
        "PORT_QOS_MAP": {"Ethernet0": {"pfc_enable": ""}},
        "BUFFER_PG": {"Ethernet0|0": {"profile": "lossy"}},
        "BUFFER_PROFILE": {"lossy": {"size": "0", "pool": "ingress"}},
        "BUFFER_POOL": {"ingress": {"size": "100000", "type": "ingress"}},
    }
    if changed == "pfc":
        config["PORT_QOS_MAP"]["Ethernet0"]["pfc_enable"] = "3,4"
    elif changed == "headroom":
        config["BUFFER_PROFILE"]["lossy"].update(size="1000", xon="100", xoff="900")
    if changed:
        with pytest.raises(backend.PrerequisiteError, match="Generated"):
            backend.verify_lossy_policy(config, {"Ethernet0"})
    else:
        backend.verify_lossy_policy(config, {"Ethernet0"})


def test_native_startup_readback_is_actual_exact_bytes_not_the_requested_after(monkeypatch):
    original = {"data": b'{"original":true}\n', "metadata": {"mode": 0o640, "uid": 1, "gid": 2}}
    desired = {"data": b'{"new":true}\n', "metadata": original["metadata"]}
    artifacts = {"before": original, "after": desired}
    monkeypatch.setattr(backend, "read_artifact", lambda reference: artifacts[reference])
    runner = Runner(backend.startup_wire(original))
    native = backend.NativeBackend({"bundle": {"scenario_id": "scenario"}, "devices": {"dut": {}},
                                    "aliases": {}}, runner)
    operation = {"id": "scenario:add:startup", "kind": "startup", "target": "dut",
                 "before": "before", "after": "after"}
    native.perform(operation)
    observed = native.verify(operation)
    assert observed["value"] == original and observed["value"] != desired
    assert observed["owned_by"] == "actual-native-operation"
    assert runner.calls[0][2]["after"]["bytes_base64"] == base64.b64encode(desired["data"]).decode()
    assert runner.calls[1][2]["action"] == "capture"


def test_missing_native_artifact_is_not_replaced_by_desired_state(tmp_path, monkeypatch):
    runner = backend.AnsibleRunner(SimpleNamespace(), tmp_path, "dut")
    monkeypatch.setattr(runner, "play", lambda *arguments: None)
    with pytest.raises(backend.NativeOperationError, match="Native readback is missing"):
        runner.call("running", "dut", {"action": "capture"})


def _smoke_journal(monkeypatch):
    refs = {
        "bundle": {"bundle_sha256": "bundle"}, "running-before": {"PORT": {"old": {}}},
        "running-after": {"PORT": {"new": {}}}, "alias-before": None,
        "startup-before": {"data": b"original", "metadata": {"mode": 0o600, "uid": 1, "gid": 2}},
        "startup-add": {"data": b"add", "metadata": {"mode": 0o600, "uid": 1, "gid": 2}},
        "startup-deploy": {"data": b'{ "final": true }\n', "metadata": {"mode": 0o600, "uid": 1, "gid": 2}},
    }
    resources = [{"key": kind, "kind": kind, "target": "dut", "baseline": kind + "-before", "context": {}}
                 for kind in ("running", "startup", "alias")]
    operations = [
        {"status": "VERIFIED", "phase": "add", "resource": "running", "after": "running-after"},
        {"status": "VERIFIED", "phase": "add", "resource": "startup", "after": "startup-add"},
        {"status": "VERIFIED", "phase": "deploy", "resource": "startup", "after": "startup-deploy"},
    ]
    journal = {"schema_version": 1, "state": "DEPLOYED", "bundle": "bundle", "scenario_id": "scenario",
               "resources": resources, "operations": operations}
    monkeypatch.setattr(backend, "read_artifact", lambda reference: copy.deepcopy(refs[reference]))
    calls = []

    def verify(probe):
        calls.append(probe)
        return {"operation_id": probe["id"], "target": probe["target"], "kind": probe["kind"],
                "value": copy.deepcopy(refs[probe["after"]]), "owned_by": "does-not-excuse-drift"}

    native = SimpleNamespace(payload={"bundle": {"scenario_id": "scenario", "bundle_sha256": "bundle"}}, verify=verify)
    report = {"status": "DUT_READY", "scenario_id": "scenario", "bundle_sha256": "bundle"}
    return SimpleNamespace(status=lambda: journal), native, report, calls, refs


def test_smoke_probes_latest_deploy_and_unchanged_alias_without_invoking_mutations(monkeypatch):
    transaction, native, report, calls, refs = _smoke_journal(monkeypatch)
    backend.verify_smoke_ready(transaction, native, report)
    assert [(probe["kind"], probe["after"]) for probe in calls] == [
        ("running", "running-after"), ("startup", "startup-deploy"), ("alias", "alias-before")]
    assert all(probe["phase"] == "probe" for probe in calls)


@pytest.mark.parametrize("case", ["valid", "stale-report", "unresolved-old-attempt"])
def test_smoke_is_bound_to_the_new_attempt_and_preserves_closed_failure_history(monkeypatch, case):
    transaction, native, report, calls, refs = _smoke_journal(monkeypatch)
    journal = transaction.status()
    journal["attempt"] = 1
    for operation in journal["operations"]:
        operation["attempt"] = 1
    journal["operations"][:0] = [
        {"attempt": 0, "phase": "add", "status": "INTENT", "compensated": case != "unresolved-old-attempt"},
        {"attempt": 0, "phase": "restore", "status": "VERIFIED"},
    ]
    report["attempt"] = 0 if case == "stale-report" else 1
    if case == "valid":
        backend.verify_smoke_ready(transaction, native, report)
        assert calls
    else:
        with pytest.raises(backend.PrerequisiteError):
            backend.verify_smoke_ready(transaction, native, report)
        assert not calls


@pytest.mark.parametrize("ready", [False, True])
def test_native_health_checks_physical_only_ports_and_preserves_failure_diagnostics(ready):
    calls = []
    manifest = {"port_bindings": [{"dut_port": "l1-child", "leaf": "leaf", "leaf_port": "l1-peer"},
                                  {"dut_port": "traffic-child", "leaf": "leaf", "leaf_port": "traffic-peer"}],
                "resources": {"available": {"dut": {"headroom": 1000}, "leaf": {"headroom": 1000}}}}
    bundle = {"scenario_id": "scenario", "dut": "dut", "manifest": manifest,
              "add_configs": {"dut": {
                  "PORT": {"l1-child": {"pfc_asym": "on"}},
                  "PORT_QOS_MAP": {"l1-child": {"tc_to_queue_map": "frozen-map", "pfc_enable": "3,4"}},
                  "TC_TO_QUEUE_MAP": {"frozen-map": {"0": "1"}}}, "leaf": {}}, "transport": [],
              "ownership": {device: {"ports": ports, "old_ports": ["old-" + device]} for device, ports in (
                  ("dut", ["l1-child", "traffic-child"]), ("leaf", ["l1-peer", "traffic-peer"]))}}
    native = backend.NativeBackend({"bundle": bundle, "devices": {"dut": {}, "leaf": {}}},
                                   SimpleNamespace(call=lambda kind, target, request: (
                                       calls.append((target, request)) or {
                                           "ready": ready,
                                           "blocking_errors": ["Unresolved applied counter identity"]})))
    if ready:
        native.health("add-topo")
    else:
        with pytest.raises(backend.NativeOperationError, match="Unresolved applied counter identity"):
            native.health("add-topo")
    expected = {"dut": ["l1-child", "traffic-child"]}
    if ready:
        expected["leaf"] = ["l1-peer", "traffic-peer"]
    assert {target: request["request"]["ports"] for target, request in calls} == expected
    assert calls[0][1]["request"]["qos_maps"]["TC_TO_QUEUE_MAP"] == {"frozen-map": {"0": "1"}}
    assert calls[0][1]["request"]["pfc_asym"]["l1-child"] == "on"


@pytest.mark.parametrize("available", [False, True])
def test_one_smoke_workflow_executes_only_actual_generated_paths(tmp_path, monkeypatch, available):
    transaction, native, report, calls, refs = _smoke_journal(monkeypatch)
    native.payload["bundle"]["manifest"] = {
        "traffic_cases": [{}, {}] if available else [], "endpoints": [{}, {}] if available else []}
    traffic = []
    native.health = lambda phase: {"dut": {"ready": True}}
    native.host_call = lambda action: traffic.append(action) or {
        "ready": True, "forwarding_cases_passed": 2, "gateway_endpoints_passed": 2}
    lifecycle.private_json(tmp_path / "provenance.json", {"owner_plan_id": "owned-plan"})
    lifecycle.private_json(tmp_path / "deployment-report.json", report)
    (tmp_path / "transaction").mkdir()
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    monkeypatch.setattr(backend, "prepare_backend", lambda *arguments: native)
    monkeypatch.setattr(backend.DeploymentTransaction, "open", lambda *arguments: transaction)
    result = backend.run_phase("smoke", SimpleNamespace(), {}, {}, tmp_path)
    assert traffic == (["smoke"] if available else [])
    assert result["status"] == "SMOKE_PASSED"
    assert result["traffic_executed"] is available
    assert result["traffic_status"] == ("GENERATED_PATHS_PASSED" if available else "BLOCKED_NO_INDEPENDENT_PATH")
    assert result["health"] == {"dut": {"ready": True}}
    assert calls


@pytest.mark.parametrize("owner", ["", "different-plan"])
@pytest.mark.parametrize("action", ["add-topo", "deploy-mg", "remove-topo"])
def test_automatic_inputs_never_grant_a_missing_or_different_platform_owner(tmp_path, monkeypatch, owner, action):
    lifecycle.private_json(tmp_path / "provenance.json", {"owner_plan_id": "original-plan"})
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", owner)

    def forbidden(*arguments):
        raise AssertionError("A different plan must not reach native device operations")

    monkeypatch.setattr(backend, "prepare_backend", forbidden)
    with pytest.raises(backend.PrerequisiteError, match="platform-owned plan"):
        backend.run_phase(action, SimpleNamespace(), {}, {}, tmp_path)


@pytest.mark.parametrize("change", ["bytes", "metadata", "not-deployed", "pending-intent", "different-bundle"])
def test_smoke_refuses_drift_or_incomplete_deployment_even_with_ownership(monkeypatch, change):
    transaction, native, report, calls, refs = _smoke_journal(monkeypatch)
    original = native.verify

    def changed(probe):
        observed = original(probe)
        if probe["kind"] == "startup":
            if change == "bytes":
                observed["value"]["data"] = b'{"final":true}'
            elif change == "metadata":
                observed["value"]["metadata"]["uid"] = True
        return observed

    native.verify = changed
    if change == "not-deployed":
        transaction.status()["state"] = "TOPO_READY"
    elif change == "pending-intent":
        transaction.status()["operations"][-1]["status"] = "INTENT"
    elif change == "different-bundle":
        report["bundle_sha256"] = "different"
    with pytest.raises(backend.PrerequisiteError):
        backend.verify_smoke_ready(transaction, native, report)


def test_failed_new_collection_cannot_reuse_old_facts(tmp_path, monkeypatch):
    lifecycle.private_json(tmp_path / "dut.json", {"private": "stale-baseline"})
    lifecycle.private_json(tmp_path / "host.json", {"stale": True})
    lifecycle.private_json(tmp_path / "collection.json", {"directory": "previous-success"})
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda *arguments, **keywords: SimpleNamespace(returncode=1))
    arguments = SimpleNamespace(vm_inventory="vms", inventory="dut", vault_password_file="vault")
    facts, host, errors = lifecycle.run_collection(
        arguments, {"dut": "dut", "leaves": ["leaf"]},
        {"server": "server", "group-name": "group", "ptf_image_name": "docker-ptf"}, tmp_path)
    assert facts == {} and host is None and errors
    assert lifecycle.read_json(tmp_path / "collection.json")["directory"] == "previous-success"


def test_empty_policy_does_not_block_collection_and_real_errors_remain_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "source_identity", lambda: "source")
    monkeypatch.setattr(lifecycle, "connection_rows", lambda *arguments: [])

    calls = []

    def collect(*arguments):
        calls.append(arguments)
        return {}, None, ["Installed device facts could not be collected"]

    monkeypatch.setattr(lifecycle, "run_collection", collect)
    scope = {"testbed": "bed", "dut": "dut", "leaves": ["leaf"], "protected_peers": [], "policy": {}}
    with pytest.raises(lifecycle.PrerequisiteError, match="Installed device facts"):
        lifecycle.preflight(SimpleNamespace(), scope, {"inv_name": "inventory"}, tmp_path)
    report = lifecycle.read_json(tmp_path / "preflight-report.json")
    assert calls and report["status"] == "NOT_READY" and report["evidence_stage"] == "COLLECTED_FACTS"
    assert not report["configuration_writes_attempted"] and not (tmp_path / "provenance.json").exists()


def _generic_testbeds():
    original = {
        "conf-name": "bed", "group-name": "group", "topo": "t0-test", "ptf_image_name": "docker-ptf",
        "ptf": "group", "ptf_ip": "192.0.2.3/24", "server": "server", "vm_base": "VM00001",
        "dut": ["dut"], "inv_name": "inventory", "auto_recover": "True",
    }
    generic = copy.deepcopy(original)
    generic.update({"conf-name": "bed-generic", "topo": "generic", "auto_recover": "False"})
    generic["generic_hwsku"] = {
        "baseline_testbed": "bed", "leaves": ["leaf"], "protected_peers": ["shared"],
    }
    return [original, generic]


def _testbed_file(tmp_path, entries=None):
    path = tmp_path / "testbed.yaml"
    path.write_text(yaml.safe_dump(_generic_testbeds() if entries is None else entries), encoding="utf-8")
    return path


@pytest.mark.parametrize("requested", ["bed", "bed-generic"])
def test_scheduler_maps_only_the_reserved_bed_to_its_generic_scenario(tmp_path, requested):
    assert lifecycle.resolve_scheduler_testbed(_testbed_file(tmp_path), requested, "bed-generic") == "bed-generic"


@pytest.mark.parametrize("problem", ["other-bed", "different-slot", "not-generic"])
def test_scheduler_generic_mapping_cannot_change_physical_scope(tmp_path, problem):
    entries = _generic_testbeds()
    requested = "other-bed" if problem == "other-bed" else "bed"
    if problem == "different-slot":
        entries[1]["server"] = "another-server"
    elif problem == "not-generic":
        entries[1]["topo"] = "t0"
    with pytest.raises(lifecycle.PrerequisiteError):
        lifecycle.resolve_scheduler_testbed(_testbed_file(tmp_path, entries), requested, "bed-generic")


@pytest.mark.parametrize("smoke_failure", [False, True])
def test_scheduled_smoke_records_only_safe_evidence_and_always_recovers(tmp_path, monkeypatch, caplog, smoke_failure):
    caplog.set_level("INFO")
    source = ROOT.parent / "tests/generic_hwsku/test_deployment_smoke.py"
    spec = importlib.util.spec_from_file_location("scheduled_generic_smoke", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "__file__", str(tmp_path / "tests/generic_hwsku/test_deployment_smoke.py"))
    workspace = tmp_path / ".generic_hwsku/bed-generic"
    workspace.mkdir(parents=True)
    lifecycle.private_json(workspace / "invocation.json", {"testbed": "bed-generic"})
    calls = []

    def run(command, **keywords):
        action = command[command.index("--action") + 1]
        calls.append(action)
        if action == "smoke":
            report = {"status": "SMOKE_PASSED", "scenario_id": "scenario", "source_sha": "source",
                      "bundle_sha256": "bundle", "traffic_executed": False, "traffic_status": "BLOCKED",
                      "qualification_pass": False,
                      "coverage_complete": False,
                      "coverage_warnings": [{"code": "SERVICE_COVERAGE_INCOMPLETE"}],
                      "health": {"dut": {"ready": True, "ports": 4, "private_configuration": "must-not-export"}}}
        else:
            report = {"status": "RESTORED", "restoration_verified": True, "bundle_sha256": "bundle"}
        lifecycle.private_json(workspace / "deployment-report.json", report)
        return SimpleNamespace(returncode=1 if action == "smoke" and smoke_failure else 0)

    monkeypatch.setattr(module.subprocess, "run", run)
    session = module.generic_deployment_lifecycle.__wrapped__({"conf-name": "bed-generic"})
    context = next(session)
    try:
        if smoke_failure:
            with pytest.raises(AssertionError, match="Generic smoke failed"):
                module.test_frozen_generic_deployment_smoke(context)
        else:
            module.test_frozen_generic_deployment_smoke(context)
            output = caplog.text
            assert "GENERIC_VERIFIED_CONFIGURATION" in output and "must-not-export" not in output
            assert '"coverage_complete": false' in output and "SERVICE_COVERAGE_INCOMPLETE" in output
        assert calls == ["smoke"]
    finally:
        session.close()
    assert calls == ["smoke", "remove-topo"]


@pytest.mark.parametrize("smoke_failure,cleanup_failure", [(False, False), (True, False), (False, True)])
def test_scheduled_session_restore_runs_after_legacy_config_checks(tmp_path, smoke_failure, cleanup_failure):
    tests = tmp_path / "tests"
    module = tests / "generic_hwsku" / "test_deployment_smoke.py"
    module.parent.mkdir(parents=True)
    module.write_text((ROOT.parent / "tests/generic_hwsku/test_deployment_smoke.py").read_text())
    workspace = tmp_path / ".generic_hwsku" / "bed-generic"
    workspace.mkdir(parents=True)
    (workspace / "invocation.json").write_text(json.dumps({"testbed": "bed-generic"}))
    conftest = r'''
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / ".generic_hwsku" / "bed-generic"
STATE = {"config": "DEPLOYED"}
EVENTS = []
SMOKE_FAILURE = __SMOKE_FAILURE__
CLEANUP_FAILURE = __CLEANUP_FAILURE__

def event(value):
    EVENTS.append(value)
    (ROOT / "events.json").write_text(json.dumps(EVENTS))

@pytest.fixture(scope="session")
def tbinfo():
    patch = pytest.MonkeyPatch()
    def run(command, **keywords):
        phase = command[command.index("--action") + 1]
        event(phase)
        if phase == "smoke":
            report = {"status": "SMOKE_PASSED", "scenario_id": "scenario", "source_sha": "source",
                      "bundle_sha256": "bundle", "traffic_executed": True, "traffic_status": "GENERATED_PATHS_PASSED",
                      "qualification_pass": False, "coverage_complete": False, "coverage_warnings": [], "health": {}}
            code = int(SMOKE_FAILURE)
        else:
            STATE["config"] = "DEPLOYED" if CLEANUP_FAILURE else "ORIGINALS"
            report = {"status": "RESTORE_FAILED" if CLEANUP_FAILURE else "RESTORED",
                      "restoration_verified": not CLEANUP_FAILURE, "bundle_sha256": "bundle"}
            code = int(CLEANUP_FAILURE)
        (WORKSPACE / "deployment-report.json").write_text(json.dumps(report))
        return SimpleNamespace(returncode=code)
    patch.setattr(subprocess, "run", run)
    yield {"conf-name": "bed-generic"}
    patch.undo()

@pytest.fixture(scope="module", autouse=True)
def core_dump_and_config_check(tbinfo):
    assert STATE["config"] == "DEPLOYED"
    yield
    event("legacy-config-check")
    assert STATE["config"] == "DEPLOYED", "Native restoration raced the legacy configuration guard"
'''
    (tests / "conftest.py").write_text(
        conftest.replace("__SMOKE_FAILURE__", repr(smoke_failure)).replace(
            "__CLEANUP_FAILURE__", repr(cleanup_failure)))
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "--confcutdir=" + str(tests), "--rootdir=" + str(tests),
         "-p", "no:cacheprovider", "--log-cli-level=INFO", str(module)],
        cwd=str(tmp_path), env=dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1"),
        text=True, capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert completed.returncode == int(smoke_failure or cleanup_failure), completed.stdout + completed.stderr
    assert json.loads((tmp_path / "events.json").read_text()) == ["smoke", "legacy-config-check", "remove-topo"]
    if cleanup_failure:
        assert "Generic remove-topo failed" in completed.stdout
        assert "GENERIC_RECOVERY_VERIFIED" not in completed.stdout
    else:
        assert "GENERIC_RECOVERY_VERIFIED" in completed.stdout


@pytest.mark.parametrize("topology,cached,drift", [
    ("generic", True, False), ("generic", False, False), ("generic", True, True),
    ("t0", True, False), ("t0", False, False)])
def test_module_guard_uses_live_generic_baseline_without_touching_shared_golden(topology, cached, drift):
    source = ROOT.parent / "tests" / "conftest.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("compare_running_config", "core_dump_and_config_check")]
    for function in functions:
        function.decorator_list = []
    current = {"PORT": {"deployed": {"admin_status": "up"}}}
    old = {"PORT": {"original": {"admin_status": "up"}}}
    state = {"running": copy.deepcopy(current), "golden": {
        "data": json.dumps(old, indent=4) + "\n", "mode": 0o640, "uid": 12, "gid": 34} if cached else None}
    original_golden = copy.deepcopy(state["golden"])
    commands, repairs, messages = [], [], {}

    def shell(command, **keywords):
        commands.append(command)
        if command == "sonic-cfggen -d --print-data":
            return {"stdout": json.dumps(state["running"])}
        if command == "sonic-cfggen -d --print-data > /etc/sonic/running_golden_config.json":
            state["golden"] = {"data": json.dumps(state["running"]), "mode": 0o644, "uid": 0, "gid": 0}
        if command == "cat /etc/sonic/running_golden_config.json":
            return {"stdout": state["golden"]["data"]}
        return {"stdout": ""}

    class Pool:
        def __init__(self, **keywords):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            return False

        def submit(self, function, *arguments):
            return function(*arguments)

    dut = SimpleNamespace(hostname="dut", os_version="202605", is_multi_asic=False, shell=shell,
                          stat=lambda **keywords: {"stat": {"exists": state["golden"] is not None}})
    namespace = {
        "json": json, "logger": logging.getLogger(__name__), "SafeThreadPoolExecutor": Pool,
        "get_unrestored_runtime_managed_entries_by_context": lambda *arguments: {},
        "refresh_core_dump_inventory": lambda before, collect, previous: (collect(), []),
        "restore_config_db_and_config_reload": lambda data, *arguments: repairs.append(
            copy.deepcopy(data["dut"]["pre_running_config"])),
        "DUT_CHECK_NAMESPACE": "dut_check",
        "add_custom_msg": lambda request, key, value: messages.update({key: value}),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    request = SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace()),
                              node=SimpleNamespace(name="generic-smoke", iter_markers=lambda: []))
    guard = namespace["core_dump_and_config_check"](
        [dut], {"topo": {"type": topology, "name": topology}},
        SimpleNamespace(is_par_run=False), request, None)
    try:
        data = next(guard)
        baseline = current if topology == "generic" or not cached else old
        assert data["dut"]["pre_running_config"] == {None: baseline}
        if drift:
            state["running"] = {"PORT": {"unexpected": {}}}
        with pytest.raises(StopIteration):
            next(guard)
        if drift or topology != "generic" and cached:
            assert repairs == [{None: baseline}]
            assert messages["dut_check.config_db_check_failed"]
        else:
            assert not repairs
        if topology == "generic":
            assert state["golden"] == original_golden
            assert not any("running_golden_config" in command for command in commands)
        elif not cached:
            assert state["golden"] is not None
    finally:
        guard.close()


def test_shared_testbed_entry_needs_no_request_file_or_handwritten_policy(tmp_path, monkeypatch):
    path = _testbed_file(tmp_path)
    scope = lifecycle.load_scope(path, "bed-generic")
    assert scope["dut"] == "dut" and scope["baseline_testbed"] == "bed"
    assert scope["testbed_definition"]["baseline"]["topo"] == "t0-test"
    monkeypatch.setattr(lifecycle, "source_identity", lambda: "source")
    monkeypatch.setattr(lifecycle, "connection_rows", lambda *arguments: [])

    calls = []

    def collect(*arguments):
        calls.append(arguments)
        return {}, None, ["Installed platform asset is unavailable"]

    monkeypatch.setattr(lifecycle, "run_collection", collect)
    workspace = tmp_path / "private"
    result = lifecycle.main([
        "--action", "preflight", "--testbed", "bed-generic", "--testbed-file", str(path),
        "--inventory", "inventory", "--vm-inventory", "veos", "--vault-password-file", "vault",
        "--workspace", str(workspace),
    ])
    assert result == 2
    report = lifecycle.read_json(workspace / "preflight-report.json")
    assert calls and report["testbed"] == "bed-generic" and report["evidence_stage"] == "COLLECTED_FACTS"
    assert not report["configuration_writes_attempted"]


@pytest.mark.parametrize("mismatch", ["dut", "server", "group-name", "generic-baseline", "duplicate-entry"])
def test_generic_entry_rejects_other_physical_bindings_or_recursive_cleanup(tmp_path, mismatch):
    entries = _generic_testbeds()
    if mismatch == "generic-baseline":
        entries[0]["topo"] = "generic"
    elif mismatch == "duplicate-entry":
        entries.append(copy.deepcopy(entries[1]))
    else:
        entries[1][mismatch] = ["another-dut"] if mismatch == "dut" else "another-slot"
    with pytest.raises(lifecycle.PrerequisiteError):
        lifecycle.load_scope(_testbed_file(tmp_path, entries), "bed-generic")


def test_frozen_generic_entry_cannot_rebind_even_when_both_management_rows_change(tmp_path, capsys):
    entries = _generic_testbeds()
    path = _testbed_file(tmp_path, entries)
    scope = lifecycle.load_scope(path, "bed-generic")
    workspace = tmp_path / "private"
    workspace.mkdir()
    lifecycle.private_json(workspace / "provenance.json", {"scope_sha256": lifecycle.digest(scope)})
    for entry in entries:
        entry["ptf_ip"] = "192.0.2.4/24"
    _testbed_file(tmp_path, entries)
    result = lifecycle.main([
        "--action", "preflight", "--testbed", "bed-generic", "--testbed-file", str(path),
        "--inventory", "inventory", "--vm-inventory", "veos", "--vault-password-file", "vault",
        "--workspace", str(workspace),
    ])
    assert result == 2 and "Frozen scenario scope changed" in capsys.readouterr().err
    assert lifecycle.read_json(workspace / "provenance.json")["scope_sha256"] == lifecycle.digest(scope)


def test_original_cleanup_uses_baseline_entry_instead_of_recursing_into_generic(tmp_path, monkeypatch):
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    monkeypatch.setenv("SONIC_GENERIC_TESTBED", "bed-generic")
    calls = []

    def run(command, **keywords):
        assert keywords["env"]["SONIC_GENERIC_TESTBED"] == ""
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(backend.subprocess, "run", run)
    staged = []
    arguments = SimpleNamespace(testbed="bed-generic", testbed_file="testbed.yaml", vm_inventory="veos",
                                vm_type="ceos", vault_password_file="vault", verbosity=2)
    backend.legacy_cleanup(arguments, {"baseline_testbed": "bed"}, tmp_path)
    assert not staged
    backend.legacy_cleanup(arguments, {"baseline_testbed": "bed"}, tmp_path,
                           SimpleNamespace(host_call=lambda action: staged.append(action)))
    assert calls[0][-4:] == ["remove-topo", "bed", "vault", "-vv"]
    assert len(calls) == 1 and staged == ["stage"]
    assert lifecycle.read_json(tmp_path / "legacy-cleanup.json")["testbed"] == "bed"


@pytest.mark.parametrize("recorded_owner", [None, "different-plan"])
def test_original_cleanup_cannot_reuse_an_unbound_or_foreign_complete_receipt(tmp_path, monkeypatch, recorded_owner):
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    receipt = {"status": "COMPLETE", "testbed": "bed"}
    if recorded_owner is not None:
        receipt["owner_plan_id"] = recorded_owner
    lifecycle.private_json(tmp_path / "legacy-cleanup.json", receipt)
    with pytest.raises(backend.PrerequisiteError, match="matching platform plan owner"):
        backend.legacy_cleanup(SimpleNamespace(), {"baseline_testbed": "bed"}, tmp_path)


def test_initial_remove_needs_no_new_platform_policy_or_device_collection(tmp_path, monkeypatch):
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    calls = []

    def forbidden(*arguments):
        raise AssertionError("Initial original-topology cleanup must not prepare a new Generic scenario")

    monkeypatch.setattr(backend, "prepare_backend", forbidden)
    monkeypatch.setattr(backend, "legacy_cleanup", lambda *arguments: calls.append(arguments))
    result = backend.run_phase("remove-topo", SimpleNamespace(), {"baseline_testbed": "bed"}, {}, tmp_path)
    assert result["status"] == "LEGACY_CLEANED" and calls


def test_recovery_does_not_replace_a_missing_native_snapshot_with_new_original_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    (tmp_path / "transaction").mkdir()

    def forbidden(*arguments):
        raise AssertionError("Missing recovery inputs must not trigger original topology cleanup")

    monkeypatch.setattr(backend, "legacy_cleanup", forbidden)
    with pytest.raises(backend.RestorationError, match="Frozen native recovery inputs"):
        backend.run_phase("remove-topo", SimpleNamespace(), {}, {}, tmp_path)


@pytest.mark.parametrize("changed", [
    "settings", "physical_binding", "frozen_scope", "missing_entry", "missing_frozen_scope"])
def test_remove_uses_frozen_inputs_and_never_replans_after_configuration_changes(tmp_path, monkeypatch, changed):
    entries = _generic_testbeds()
    path = _testbed_file(tmp_path, entries)
    frozen_scope = lifecycle.load_scope(path, "bed-generic")
    workspace = tmp_path / "private"
    workspace.mkdir()
    bundle = {"scenario_id": "original-scenario", "bundle_sha256": "frozen-bundle", "manifest": {
        "scenario_id": "original-scenario", "coverage": {"traffic": {"complete": False}}, "traffic_cases": []}}
    lifecycle.private_json(workspace / "backend.json", {"bundle": bundle})
    lifecycle.private_json(workspace / "scope.json", frozen_scope)
    lifecycle.private_json(workspace / "provenance.json", {
        "scope_sha256": lifecycle.digest(frozen_scope), "source_sha": "original-source", "owner_plan_id": "owned-plan"})
    (workspace / "transaction").mkdir()
    removed = []
    transaction = SimpleNamespace(remove=lambda: removed.append(True), status=lambda: {"bundle": "artifact"})
    monkeypatch.setattr(backend.DeploymentTransaction, "open", lambda *arguments: transaction)
    monkeypatch.setattr(backend, "read_artifact", lambda reference: bundle)
    monkeypatch.setenv("ELASTICTEST_TEST_PLAN_ID", "owned-plan")
    monkeypatch.setattr(lifecycle, "source_identity", lambda: "updated-source")

    def forbidden(*arguments):
        raise AssertionError("Frozen recovery must not recollect, render or load new platform inputs")

    monkeypatch.setattr(lifecycle, "run_collection", forbidden)
    monkeypatch.setattr(backend.AnsibleRunner, "play", forbidden)
    if changed == "settings":
        entries[1]["generic_hwsku"]["policy"] = {"unrecognized": "must not block old recovery"}
    elif changed == "physical_binding":
        for row in entries:
            row["ptf_ip"] = "192.0.2.9/24"
    elif changed == "frozen_scope":
        frozen_scope["baseline_testbed"] = "another-bed"
        lifecycle.private_json(workspace / "scope.json", frozen_scope)
    elif changed == "missing_entry":
        entries.pop()
    else:
        (workspace / "scope.json").unlink()
        entries[1]["generic_hwsku"]["settings"] = {"min_subports": 8}
    _testbed_file(tmp_path, entries)
    result = lifecycle.main([
        "--action", "remove-topo", "--testbed", "bed-generic", "--testbed-file", str(path),
        "--inventory", "inventory", "--vm-inventory", "veos", "--vault-password-file", "vault",
        "--workspace", str(workspace)])
    if changed == "settings":
        assert result == 0 and removed == [True]
        report = lifecycle.read_json(workspace / "deployment-report.json")
        assert report["status"] == "RESTORED" and report["scenario_source_sha"] == "original-source"
        assert not (workspace / "runtime-inputs.json").exists() and not (workspace / "inputs.json").exists()
    else:
        assert result == 4 and not removed
        assert lifecycle.read_json(workspace / "recovery-required.json")["reservation_hold_required"]


@pytest.mark.parametrize("parallel", [False, True])
def test_original_remove_propagates_actual_shell_failure_without_a_success_echo(parallel):
    executable = shutil.which("bash")
    if os.name == "nt":
        executable = str(Path(shutil.which("git")).parents[1] / "bin" / "bash.exe")
    if not executable or not Path(executable).is_file():
        pytest.skip("A native Bash interpreter is unavailable")
    source = (ROOT / "testbed-cli.sh").read_text(encoding="utf-8")
    wait = source.split("function wait_parallel_processes()", 1)[1].split("function run_generic", 1)[0]
    remove = source.split("function remove_topo\n", 1)[1].split("function redeploy_topo()", 1)[0]
    harness = """
seq() { echo 0; }
date() { echo test; }
read_file() { topo=t0; server=server; servers=; vmfile=vms; inv_name=inventory; }
parse_parallel_args() { parallel_execution=false; args=(); }
ansible-playbook() { return 23; }
"""
    if parallel:
        harness += """
parallel_execution=true
servers=
declare -a children
(exit 23) &
children[0]=$!
wait_parallel_processes remove children 1 test
exit $?
"""
    else:
        harness += "\nremove_topo bed vault\nexit $?\n"
    completed = subprocess.run(
        [executable, "--noprofile", "--norc", "-s"], input="function wait_parallel_processes()" + wait
        + "\nfunction remove_topo\n" + remove + harness, text=True, capture_output=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert completed.returncode == 23, completed.stderr
    assert "Done" not in completed.stdout


@pytest.mark.parametrize("action", ["add_topo", "remove_topo", "deploy_minigraph"])
def test_scheduler_shell_routes_all_prepare_phases_through_the_verified_generic_entry(tmp_path, action):
    executable = shutil.which("bash")
    if os.name == "nt":
        executable = str(Path(shutil.which("git")).parents[1] / "bin" / "bash.exe")
    if not executable or not Path(executable).is_file():
        pytest.skip("A native Bash interpreter is unavailable")
    source = (ROOT / "testbed-cli.sh").read_text(encoding="utf-8")
    functions = "\n".join(
        "function " + name + source.split("function " + name, 1)[1].split("\nfunction ", 1)[0]
        for name in ("select_generic_testbed", action))
    path = _testbed_file(tmp_path)
    environment = dict(os.environ, NATIVE_PYTHON=sys.executable, TESTBED_PATH=str(path), ANSIBLE_ROOT=str(ROOT),
                       SONIC_GENERIC_TESTBED="bed-generic")
    harness = """
python3() { command "$NATIVE_PYTHON" "$@"; }
dirname() { printf '%s\\n' "$ANSIBLE_ROOT"; }
read_file() { [[ "$1" == bed-generic ]] || exit 98; topo=generic; inv_name=inventory; }
parse_parallel_args() { parallel_execution=false; args=("$@"); }
run_generic() { echo "GENERIC_PHASE $1 $testbed_name"; return 17; }
tbfile="$TESTBED_PATH"
"""
    arguments = "bed inventory vault" if action == "deploy_minigraph" else "bed vault"
    completed = subprocess.run(
        [executable, "--noprofile", "--norc", "-s"], cwd=str(ROOT), env=environment,
        input=functions + harness + "\n" + action + " " + arguments + "\nexit $?\n",
        text=True, capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert completed.returncode == 17, completed.stdout + completed.stderr
    assert "GENERIC_PHASE " + action.replace("_", "-").replace("deploy-minigraph", "deploy-mg") in completed.stdout
    assert "bed-generic" in completed.stdout


def test_existing_testbed_reader_loads_generic_and_preserves_original_static_mapping(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "generic_testbed_reader", ROOT.parent / "tests" / "common" / "testbed.py")
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    topology_directory = tmp_path / "vars"
    topology_directory.mkdir()
    shutil.copyfile(ROOT / "vars" / "topo_generic.yml", topology_directory / "topo_generic.yml")
    (topology_directory / "topo_t0-test.yml").write_text("topology:\n  host_interfaces: ['0']\n", encoding="utf-8")
    monkeypatch.setattr(reader.TestbedInfo, "TOPOLOGY_FILEPATH", "vars")
    information = reader.TestbedInfo(str(_testbed_file(tmp_path)))
    assert information.testbed_topo["bed-generic"]["topo"]["type"] == "generic"
    assert not information.testbed_topo["bed-generic"]["topo"]["ptf_map"]
    assert information.testbed_topo["bed"]["topo"]["ptf_map"] == {"0": {"0": 0}}


@pytest.mark.skipif(os.name == "nt", reason="The real deployment shell entry runs on a Linux controller")
@pytest.mark.parametrize("action", ["add-topo", "deploy-mg", "remove-topo", "ordinary-add"])
def test_normal_shell_commands_select_only_generic_topology_without_request_flags(tmp_path, action):
    directory = tmp_path / "ansible"
    directory.mkdir()
    script = directory / "testbed-cli.sh"
    shutil.copyfile(ROOT / "testbed-cli.sh", script)
    entries = _generic_testbeds()
    if action == "ordinary-add":
        entries[1]["topo"] = "t0-test"
    path = _testbed_file(directory, entries)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    generic_log, legacy_log = tmp_path / "generic.json", tmp_path / "legacy.json"
    for name, log, code in (("python3", generic_log, 17), ("ansible-playbook", legacy_log, 23)):
        executable = binaries / name
        executable.write_text(
            "#!" + sys.executable + "\nimport json,sys\n"
            "with open(" + repr(str(log)) + ", 'w') as handle:\n"
            "    json.dump(sys.argv[1:], handle)\nsys.exit(" + str(code) + ")\n", encoding="utf-8")
        executable.chmod(0o755)
    command = [shutil.which("bash"), str(script), "-t", str(path),
               "add-topo" if action == "ordinary-add" else action, "bed-generic"]
    if action == "deploy-mg":
        command.append("inventory")
    command.extend(["vault", "-vv"])
    environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"])
    result = subprocess.run(command, cwd=str(directory), env=environment,
                            capture_output=True, text=True, timeout=30)
    if action == "ordinary-add":
        assert legacy_log.is_file() and not generic_log.exists(), result.stderr
    else:
        assert result.returncode == 17 and generic_log.is_file() and not legacy_log.exists(), result.stderr
        invocation = json.loads(generic_log.read_text())
        assert invocation[invocation.index("--testbed") + 1] == "bed-generic"
        assert invocation[invocation.index("--testbed-file") + 1] == str(path)
        assert invocation[invocation.index("--verbosity") + 1] == "2"
