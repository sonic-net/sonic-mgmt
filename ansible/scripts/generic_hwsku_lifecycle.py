#!/usr/bin/env python3
"""Named Generic testbed deployment; validate original facts before any configuration write."""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import yaml

from generic_hwsku_preflight import (
    ANSIBLE, PrerequisiteError, connection_rows, digest, plan_collected, read_json, read_testbed, readiness_report)
from generic_hwsku_deployment import RestorationError, TransactionError, _private


def private_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".generic-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, str(path))
        if os.name == "posix":
            descriptor = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_workspace(path):
    if any(parent.is_symlink() for parent in [path] + list(path.parents)):
        raise PrerequisiteError("The Generic private workspace must not traverse symlinks")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and path.parent.stat().st_mode & 0o022:
        raise PrerequisiteError("The Generic workspace parent is group/world writable")
    _private(str(path), directory=True, create=not path.exists())
    return path


def load_scope(path, testbed, recovery=False):
    row = read_testbed(path, testbed)
    configuration = row.get("generic_hwsku")
    if row.get("topo") != "generic" or not isinstance(configuration, dict):
        raise PrerequisiteError("The named testbed must use topo: generic and identify its Generic configuration")
    if set(configuration) - {"baseline_testbed", "leaves", "protected_peers", "settings", "policy"}:
        raise PrerequisiteError("Unsupported Generic testbed configuration fields")
    if not recovery:
        policy = configuration.get("policy", {})
        if not isinstance(policy, dict) or set(policy) - {"settings"}:
            raise PrerequisiteError("Generic policy accepts only optional settings; platform facts are automatic")
        for value in (configuration.get("settings", {}), policy.get("settings", {})):
            if not isinstance(value, dict):
                raise PrerequisiteError("Optional Generic settings must be a dictionary")
    baseline_name = configuration.get("baseline_testbed")
    if (not isinstance(baseline_name, str) or re.fullmatch(r"[A-Za-z0-9_-]+", baseline_name) is None
            or baseline_name == testbed):
        raise PrerequisiteError("The Generic entry must identify a distinct original testbed")
    baseline = read_testbed(path, baseline_name)
    if baseline.get("topo") == "generic":
        raise PrerequisiteError("The original testbed must use its ordinary topology")
    fields = ("group-name", "ptf_image_name", "ptf", "ptf_ip", "ptf_ipv6", "ptf_extra_mgmt_ip",
              "netns_mgmt_ip", "server", "servers", "vm_base", "dut", "inv_name")
    for field in fields + ("ptf_imagetag",):
        if row.get(field) != baseline.get(field):
            raise PrerequisiteError("Generic and original testbed disagree on " + field)
    if any(not row.get(field) for field in ("group-name", "ptf_image_name", "ptf", "server", "inv_name")):
        raise PrerequisiteError("The Generic testbed lacks its original host/inventory identity")
    scope = copy.deepcopy(configuration)
    scope.update(schema_version=1, testbed=testbed, dut=row["dut"][0], testbed_definition={
        "generic": {field: row.get(field) for field in fields},
        "baseline": dict({field: baseline.get(field) for field in fields}, topo=baseline["topo"]),
    })
    if (not isinstance(scope.get("leaves"), list) or not scope["leaves"]
            or not isinstance(scope.get("protected_peers"), list)):
        raise PrerequisiteError("The Generic entry must identify its exact controlled and protected peers")
    names = [scope.get("dut")] + scope["leaves"] + scope["protected_peers"]
    if any(not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", name) is None for name in names):
        raise PrerequisiteError("Invalid exact device identity in Generic scope")
    if len(set(names)) != len(names):
        raise PrerequisiteError("Controlled and protected device identities must be distinct")
    return scope


def resolve_scheduler_testbed(path, requested, target):
    """Map a reserved physical name only to its validated Generic scenario."""
    scope = load_scope(path, target, recovery=True)
    if requested not in (scope["baseline_testbed"], scope["testbed"]):
        raise PrerequisiteError("The Generic scenario does not belong to the scheduler's physical testbed")
    return scope["testbed"]


def run_collection(arguments, scope, testbed, workspace):
    collection = Path(tempfile.mkdtemp(prefix="collection-", dir=str(workspace)))
    # Private directories require owner traversal, not group/world access.
    os.chmod(str(collection), 0o700)  # nosemgrep: insecure-file-permissions
    variables = {
        "generic_collect_hosts": [scope["dut"]] + scope["leaves"], "generic_collect_dut": scope["dut"],
        "generic_collect_server": testbed["server"], "generic_collect_group": testbed["group-name"],
        "generic_collect_ptf_addresses": [testbed[key] for key in ("ptf_ip", "ptf_ipv6") if testbed.get(key)],
        "generic_collect_ptf_image_name": testbed["ptf_image_name"],
        "generic_collect_ptf_image_tag": testbed.get("ptf_imagetag", "latest"),
        "generic_local_directory": str(collection),
    }
    request = collection / "collect-vars.json"
    private_json(request, variables)
    command = ["ansible-playbook", "-i", str(arguments.vm_inventory), "-i", str(arguments.inventory),
               str(ANSIBLE / "generic_hwsku_collect.yml"), "--vault-password-file", str(arguments.vault_password_file),
               "--extra-vars", "@" + str(request)]
    verbosity = getattr(arguments, "verbosity", 0)
    if verbosity:
        command.append("-" + "v" * verbosity)
    environment = dict(os.environ)
    environment["ANSIBLE_LIBRARY"] = os.pathsep.join((str(ANSIBLE / "library"),
                                                     str(ANSIBLE / "roles/vm_set/library"),
                                                     environment.get("ANSIBLE_LIBRARY", "")))
    descriptor = os.open(str(collection / "collect.log"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=str(ANSIBLE), env=environment, stdout=log, stderr=subprocess.STDOUT)
    facts = {}
    for name in variables["generic_collect_hosts"]:
        path = collection / (name + ".json")
        if path.is_file():
            facts[name] = read_json(path)
    host = read_json(collection / "host.json") if (collection / "host.json").is_file() else None
    errors = [] if result.returncode == 0 else [
        "Read-only Ansible collection failed (rc {}); private evidence: {}".format(
            result.returncode, collection / "collect.log")]
    if not errors:
        private_json(workspace / "collection.json", {"directory": str(collection)})
    return facts, host, errors


def source_identity():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ANSIBLE.parent), text=True).strip()


def preflight(arguments, scope, testbed, workspace):
    source_sha = source_identity()
    rows = connection_rows(ANSIBLE / "files" / ("sonic_" + testbed["inv_name"] + "_links.csv"), scope["dut"])
    facts, host, errors = run_collection(arguments, scope, testbed, workspace)
    report = readiness_report(scope, facts, host, rows, errors)
    report["source_sha"] = source_sha
    report["owner_plan_id"] = os.environ.get("ELASTICTEST_TEST_PLAN_ID", "")
    report["scope_sha256"] = digest(scope)
    report["evidence_stage"] = "COLLECTED_FACTS"
    private_json(workspace / "preflight-report.json", report)
    if errors:
        raise PrerequisiteError("; ".join(errors))
    try:
        overrides = dict(scope.get("policy", {}).get("settings", {}))
        overrides.update(scope.get("settings", {}))
        snapshot, settings, manifest, canonical, runtime = plan_collected(
            scope, facts, host, rows, {"settings": overrides},
            execution_context=({"source_sha": source_sha, "owner_plan_id": report["owner_plan_id"]}
                               if report["owner_plan_id"] else None))
    except ValueError as error:
        report["blocking_errors"].append(str(error))
        private_json(workspace / "preflight-report.json", report)
        raise
    private_json(workspace / "inputs.json", {"snapshot": snapshot, "settings": settings})
    private_json(workspace / "manifest.json", manifest)
    private_json(workspace / "canonical-ports.json", canonical)
    private_json(workspace / "runtime-inputs.json", runtime)
    private_json(workspace / "scope.json", scope)
    private_json(workspace / "original-testbed.json", read_testbed(
        arguments.testbed_file, scope["baseline_testbed"]))
    invocation = {key: str(getattr(arguments, key).resolve()) for key in (
        "testbed_file", "inventory", "vm_inventory", "vault_password_file")}
    invocation.update(testbed=arguments.testbed, vm_type=arguments.vm_type, verbosity=str(arguments.verbosity))
    private_json(workspace / "invocation.json", invocation)
    private_json(workspace / "provenance.json", {
        "source_sha": source_sha, "scope_sha256": digest(scope), "scenario_id": manifest["scenario_id"],
        "runtime_sha256": digest(runtime),
        "owner_plan_id": os.environ.get("ELASTICTEST_TEST_PLAN_ID", ""),
    })
    report["scenario_id"] = manifest["scenario_id"]
    if runtime.get("media_sources"):
        report["media_constraints"] = {
            device["name"]: {cage["name"]: cage["media_speeds"] for cage in device["cages"] if "media_speeds" in cage}
            for device in snapshot["devices"]}
    report["coverage_complete"] = manifest["coverage"]["complete"]
    report["coverage_warnings"] = manifest["coverage"]["service"]["warnings"]
    report["status"] = "PLAN_READY_WITH_WARNINGS" if report["coverage_warnings"] else "PLAN_READY"
    report["planned_coverage"] = manifest["coverage"]
    report["traffic_available"] = bool(manifest["traffic_cases"])
    report["buffer_profiles"] = runtime["buffer_profiles"]
    report["meaning"] = "Generated layout and explicit traffic coverage; no configuration applied or qualification"
    private_json(workspace / "preflight-report.json", report)
    if report["coverage_warnings"]:
        print("GENERIC_COVERAGE_WARNING " + json.dumps(report["coverage_warnings"], sort_keys=True), file=sys.stderr)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True,
                        choices=["preflight", "add-topo", "deploy-mg", "remove-topo", "smoke", "status"])
    parser.add_argument("--testbed", required=True)
    parser.add_argument("--testbed-file", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--vm-inventory", required=True, type=Path)
    parser.add_argument("--vault-password-file", required=True, type=Path)
    parser.add_argument("--vm-type", default="ceos")
    parser.add_argument("--verbosity", type=int, choices=range(5), default=0)
    parser.add_argument("--workspace", type=Path)
    arguments = parser.parse_args(argv)
    workspace = None
    try:
        if re.fullmatch(r"[A-Za-z0-9_-]+", arguments.testbed) is None:
            raise PrerequisiteError("Invalid testbed workspace identity")
        recovering = arguments.action == "remove-topo"
        workspace = private_workspace(arguments.workspace or ANSIBLE.parent / ".generic_hwsku" / arguments.testbed)
        scope = load_scope(arguments.testbed_file, arguments.testbed, recovery=recovering)
        testbed = read_testbed(arguments.testbed_file, arguments.testbed)
        if testbed["dut"] != [scope["dut"]]:
            raise PrerequisiteError("Generic scope and branch testbed inventory disagree")
        if arguments.action == "status":
            path = workspace / "deployment-report.json"
            report = read_json(path if path.is_file() else workspace / "preflight-report.json")
            print(json.dumps(report, sort_keys=True))
            return 0
        provenance = workspace / "provenance.json"
        if recovering and (workspace / "scope.json").is_file():
            frozen = read_json(workspace / "scope.json")
            if provenance.is_file() and read_json(provenance)["scope_sha256"] != digest(frozen):
                raise RestorationError("Frozen recovery scope was modified; retain the recovery artifacts")
            if digest(frozen["testbed_definition"]) != digest(scope["testbed_definition"]):
                raise RestorationError("Physical testbed binding changed; retain the frozen recovery artifacts")
            scope = frozen
        elif recovering and provenance.is_file() and read_json(provenance)["scope_sha256"] != digest(scope):
            raise RestorationError("Recovery lacks its frozen scope; restore the original inputs and retain artifacts")
        if not recovering and not provenance.is_file():
            report = preflight(arguments, scope, testbed, workspace)
            print("GENERIC_PREFLIGHT " + json.dumps(report, sort_keys=True))
            if arguments.action == "preflight":
                return 0
        elif not recovering and read_json(provenance)["scope_sha256"] != digest(scope):
            raise PrerequisiteError("Frozen scenario scope changed; recover the original scenario before replanning")
        if arguments.action == "preflight":
            print("GENERIC_PREFLIGHT " + json.dumps(read_json(workspace / "preflight-report.json"), sort_keys=True))
            return 0
        if not recovering and read_json(provenance)["source_sha"] != source_identity():
            raise PrerequisiteError("The frozen source changed; only recovery may use the retained original artifacts")
        from generic_hwsku_backend import run_phase

        result = run_phase(arguments.action, arguments, scope, testbed, workspace)
        result.update(testbed=arguments.testbed, action=arguments.action,
                      source_sha=source_identity(), qualification_pass=False)
        if provenance.is_file():
            result["scenario_source_sha"] = read_json(provenance)["source_sha"]
        backend_path = workspace / "backend.json"
        if backend_path.is_file():
            manifest = read_json(backend_path)["bundle"]["manifest"]
            result.update(scenario_id=manifest["scenario_id"], planned_coverage=manifest["coverage"],
                          traffic_available=bool(manifest["traffic_cases"]))
            if not recovering:
                result["buffer_profile"] = manifest["settings"]["profile"]
                result["coverage_complete"] = manifest["coverage"]["complete"]
                result["coverage_warnings"] = manifest["coverage"]["service"]["warnings"]
        private_json(workspace / "deployment-report.json", result)
        print("GENERIC_DEPLOYMENT " + json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError,
            yaml.YAMLError, subprocess.CalledProcessError) as error:
        attempted = workspace is not None and (workspace / "mutation-attempted.json").is_file()
        retained_recovery = (arguments.action == "remove-topo"
                             and (workspace is None or (workspace / "transaction").exists()))
        status = ("RESTORE_FAILED" if isinstance(error, RestorationError) or retained_recovery else
                  "FAILED_RESTORED" if isinstance(error, TransactionError) else
                  "FAILED_UNVERIFIED" if attempted else "NOT_READY")
        result = {"status": status, "testbed": arguments.testbed, "action": arguments.action,
                  "configuration_writes_attempted": attempted, "error": str(error),
                  "restoration_verified": status == "FAILED_RESTORED",
                  "reservation_hold_required": status in ("RESTORE_FAILED", "FAILED_UNVERIFIED")}
        if workspace is not None:
            private_json(workspace / "deployment-report.json", result)
            if result["reservation_hold_required"]:
                private_json(workspace / "recovery-required.json", dict(
                    result, owner_plan_id=os.environ.get("ELASTICTEST_TEST_PLAN_ID", ""),
                    meaning="Do not release or reuse affected resources until frozen recovery is verified"))
        print("GENERIC_DEPLOYMENT_{}: {}".format(status, error), file=sys.stderr)
        return 4 if status == "RESTORE_FAILED" else 3 if attempted else 2


if __name__ == "__main__":
    sys.exit(main())
