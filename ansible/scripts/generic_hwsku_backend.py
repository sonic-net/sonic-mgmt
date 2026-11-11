#!/usr/bin/env python3
"""Connect the frozen renderer/transaction to private Ansible native readbacks."""

import base64
import copy
import hashlib
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from generic_hwsku_preflight import ANSIBLE, PrerequisiteError, canonical_json, digest, read_json


sys.path.insert(0, str(ANSIBLE / "library"))
from generic_hwsku_deployment import (ConflictError, DeploymentTransaction, RestorationError,  # noqa: E402
                                      TransactionError, _buffer_reservations, read_artifact,
                                      render_bundle, render_contexts)
from generic_hwsku_health import port_bindings, reference  # noqa: E402
from generic_hwsku_host_action import candidate_state, validate_spec  # noqa: E402


class NativeOperationError(RuntimeError):
    """A native call failed or did not return an independently captured artifact."""


def private_json(path, value):
    from generic_hwsku_lifecycle import private_json as write
    write(path, value)


def startup_wire(value):
    return {"bytes_base64": base64.b64encode(value["data"]).decode("ascii"),
            "metadata": copy.deepcopy(value["metadata"])}


def startup_native(value):
    return {"data": base64.b64decode(value["bytes_base64"], validate=True),
            "metadata": copy.deepcopy(value["metadata"])}


def collected_baselines(facts):
    result = {}
    for name, value in facts.items():
        startup = value["startup"]
        data = base64.b64decode(startup["bytes_base64"], validate=True)
        if hashlib.sha256(data).hexdigest() != startup["sha256"]:
            raise PrerequisiteError("Original startup bytes failed their recorded integrity check")
        result[name] = {"running": copy.deepcopy(value["running"]),
                        "startup": {"data": data, "metadata": {
                            key: startup[key] for key in ("mode", "uid", "gid")}}}
    return result


class AnsibleRunner:
    def __init__(self, arguments, workspace, dut):
        self.arguments, self.workspace, self.dut = arguments, workspace, dut

    def play(self, filename, variables):
        directory = Path(tempfile.mkdtemp(prefix="native-call-", dir=str(self.workspace)))
        # Private directories require owner traversal, not group/world access.
        os.chmod(str(directory), 0o700)  # nosemgrep: insecure-file-permissions
        request = directory / "vars.json"
        variables = dict(variables, generic_dut=self.dut)
        private_json(request, variables)
        environment = dict(os.environ)
        environment["ANSIBLE_LIBRARY"] = os.pathsep.join((
            str(ANSIBLE / "library"), str(ANSIBLE / "roles/vm_set/library"),
            environment.get("ANSIBLE_LIBRARY", "")))
        command = ["ansible-playbook", "-i", str(self.arguments.vm_inventory), "-i", str(self.arguments.inventory),
                   str(ANSIBLE / filename), "--vault-password-file", str(self.arguments.vault_password_file),
                   "--extra-vars", "@" + str(request)]
        verbosity = getattr(self.arguments, "verbosity", 0)
        if verbosity:
            command.append("-" + "v" * verbosity)
        descriptor = os.open(str(directory / "ansible.log"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as log:
            completed = subprocess.run(
                command, cwd=str(ANSIBLE), env=environment, stdout=log, stderr=subprocess.STDOUT, check=False)
        if completed.returncode:
            raise NativeOperationError("Native Ansible call failed (rc {}); private evidence: {}".format(
                completed.returncode, directory / "ansible.log"))
        return directory

    def call(self, kind, target, call):
        directory = Path(tempfile.mkdtemp(prefix="readback-", dir=str(self.workspace)))
        # Private directories require owner traversal, not group/world access.
        os.chmod(str(directory), 0o700)  # nosemgrep: insecure-file-permissions
        result = directory / "result.json"
        self.play("generic_hwsku_operation.yml", {
            "generic_device_hosts": [] if kind == "host" else [target],
            "generic_host_hosts": [target] if kind == "host" else [],
            "generic_call": call, "generic_result_file": str(result),
        })
        if not result.is_file() or result.is_symlink():
            raise NativeOperationError("Native readback is missing; desired state cannot substitute for observation")
        return read_json(result)


class NativeBackend:
    def __init__(self, payload, runner):
        self.payload, self.runner = payload, runner
        self.scenario = payload["bundle"]["scenario_id"]

    def device_call(self, device, kind, action, **values):
        if device not in self.payload["devices"]:
            raise PrerequisiteError("A native call attempted to leave the frozen controlled-device scope")
        return self.runner.call(kind, device, dict(
            values, action=action, scenario=self.scenario, kind=kind))

    def host_call(self, action, **values):
        return self.runner.call("host", self.payload["host_inventory_name"], dict(
            values, action=action, request=self.payload["host_spec"]))

    def stage_devices(self):
        for device, request in sorted(self.payload["devices"].items()):
            self.device_call(device, "running", "stage", request=request)

    def _resource(self, operation):
        kind, target = operation["kind"], operation["target"]
        if kind == "host":
            if target != self.payload["host_target"]:
                raise PrerequisiteError("Unknown frozen host resource")
            return None, None
        if kind == "alias":
            entry = self.payload["aliases"][target]
            return entry["device"], entry["name"]
        if kind not in ("running", "startup") or target not in self.payload["devices"]:
            raise PrerequisiteError("Unknown frozen device resource")
        return target, None

    def perform(self, operation):
        device, alias = self._resource(operation)
        kind = operation["kind"]
        before, after = (read_artifact(operation[key]) for key in ("before", "after"))
        if kind == "startup":
            before, after = startup_wire(before), startup_wire(after)
        values = {"before": before, "after": after, "operation_id": operation["id"]}
        if kind == "host":
            self.host_call("perform", **values)
        else:
            if alias is not None:
                values["alias_name"] = alias
            self.device_call(device, kind, "perform", **values)

    def verify(self, operation):
        device, alias = self._resource(operation)
        kind = operation["kind"]
        if kind == "host":
            observed = self.host_call("capture")
        else:
            values = {"alias_name": alias} if alias is not None else {}
            observed = self.device_call(device, kind, "capture", **values)
        value = startup_native(observed["value"]) if kind == "startup" else observed["value"]
        return {"operation_id": operation["id"], "target": operation["target"], "kind": kind,
                "value": value, "owned_by": observed.get("owned_by")}

    def health(self, phase):
        bundle = self.payload["bundle"]
        configs = bundle["add_configs"] if phase == "add-topo" else dict(
            bundle["add_configs"], **bundle["deploy_configs"])
        results = {}
        for device, config in sorted(configs.items()):
            ports = sorted({row["dut_port"] if device == bundle["dut"] else row["leaf_port"]
                            for row in bundle["manifest"]["port_bindings"]
                            if device == bundle["dut"] or row["leaf"] == device})
            qos = {}
            for port in ports:
                qos[port] = {}
                for names, attributes in config.get("PORT_QOS_MAP", {}).items():
                    if port in names.split(","):
                        qos[port].update(attributes)
            result = self.device_call(device, "running", "health", request={
                "device": device, "ports": ports, "qos": qos,
                "pg": {port: port_bindings(config, "BUFFER_PG", port) for port in ports},
                "queues": {port: port_bindings(config, "BUFFER_QUEUE", port) for port in ports},
                "headroom_limit": bundle["manifest"]["resources"]["available"][device]["headroom"],
                "headroom_ports": sorted(set(bundle["ownership"][device]["ports"])
                                         | set(bundle["ownership"][device]["old_ports"])),
                "profiles": config.get("BUFFER_PROFILE", {}), "pools": config.get("BUFFER_POOL", {})})
            results[device] = result
            if result.get("ready") is not True:
                raise NativeOperationError("Selected link/buffer/QoS readiness did not converge on {}: {}".format(
                    device, result.get("blocking_errors", "Native readiness artifact omitted blocking errors")))
        return results


def host_spec(bundle, host, transport_policy):
    scenario = bundle["scenario_id"]
    prefix = digest(scenario)[:10]
    endpoints = copy.deepcopy(bundle["transport"])
    for row in endpoints:
        octets = bytearray(bytes.fromhex(digest([scenario, row["endpoint_id"]])[:12]))
        octets[0] = (octets[0] & 0xfe) | 2
        row["mac"] = ":".join("{:02x}".format(value) for value in octets)
    management = copy.deepcopy(host["requested_management"])
    bridges = [row for row in host["host_links"] if row["ifname"] == management["bridge"]]
    if len(bridges) != 1:
        raise PrerequisiteError("The exact existing management bridge was not collected")
    management["mtu"] = bridges[0]["mtu"]
    management["addresses"] = [str(ipaddress.ip_interface(value)) for value in management["addresses"] if value]
    for key in ("gateway", "gateway_v6"):
        management[key] = str(ipaddress.ip_address(management[key])) if management.get(key) else ""
    image = host["container"].get("image_id") or transport_policy.get("image_id")
    if not isinstance(image, str):
        raise PrerequisiteError("No verified installed immutable PTF image identity")
    spec = {
        "scenario": scenario, "hostname": host["hostname"], "container": host["container"]["name"],
        "image_id": image, "parent": host["external_interface"], "management": management,
        "management_root": "gm" + prefix, "management_peer": "gp" + prefix,
        "mtu": transport_policy["mtu"], "endpoints": endpoints,
        "traffic_available": bool(bundle["manifest"]["traffic_cases"]),
        "router_mac": bundle["add_configs"][bundle["dut"]]["DEVICE_METADATA"]["localhost"].get("mac", "").lower(),
        "traffic_cases": copy.deepcopy(bundle["manifest"]["traffic_cases"]),
    }
    validate_spec(spec)
    return spec


def verify_lossy_policy(config, ports):
    """A zero lossless-headroom budget must survive actual installed-template rendering."""
    for port in ports:
        qos = {}
        for names, attributes in config.get("PORT_QOS_MAP", {}).items():
            if port in names.split(","):
                qos.update(attributes)
        bindings = port_bindings(config, "BUFFER_PG", port)
        if (qos.get("pfc_enable") != "" or qos.get("pfcwd_sw_enable", "") != "" or not bindings):
            raise PrerequisiteError("Generated lossy policy lacks disabled PFC or complete PG bindings on " + port)
        for binding in bindings.values():
            profile = config.get("BUFFER_PROFILE", {}).get(reference(binding["profile"], "BUFFER_PROFILE"), {})
            pool = config.get("BUFFER_POOL", {}).get(reference(profile.get("pool", ""), "BUFFER_POOL"), {})
            if (str(profile.get("size")) != "0" or {"xon", "xoff"} & set(profile)
                    or pool.get("type") != "ingress"):
                raise PrerequisiteError("Generated PG policy exceeds the verified zero-headroom budget on " + port)


def verify_shared_pool_capacity(bundle, tables, facts):
    for device, phases in tables.items():
        for phase, generated in phases.items():
            config = bundle["deploy_configs"][device] if phase == "deploy" else bundle["add_configs"][device]
            pools = generated.get("BUFFER_POOL", {})
            if all(config.get("BUFFER_POOL", {}).get(name) == row for name, row in pools.items()):
                continue
            observed = facts[device].get("applied_buffers", {}).get("mmu_size")
            if not isinstance(observed, str) or not observed.isdigit() or int(observed) <= 0:
                raise PrerequisiteError("Shared-pool retention requires observed SDK MMU capacity on " + device)
            reservations = _buffer_reservations(generated)
            if reservations is None:
                raise PrerequisiteError("Installed template MMU reservations are unresolved on " + device)
            for name, row in pools.items():
                size = row.get("size")
                xoff = row.get("xoff", "0")
                if (not str(size).isdigit() or not str(xoff).isdigit()
                        or int(size) + int(xoff) + reservations.get(name, 0) > int(observed)):
                    raise PrerequisiteError("Installed pool sizing exceeds observed SDK MMU capacity on " + device)


def prepare_backend(arguments, scope, workspace):
    runner = AnsibleRunner(arguments, workspace, scope["dut"])
    saved = workspace / "backend.json"
    if saved.is_file():
        return NativeBackend(read_json(saved), runner)
    collection = Path(read_json(workspace / "collection.json")["directory"])
    facts = {name: read_json(collection / (name + ".json")) for name in [scope["dut"]] + scope["leaves"]}
    host = read_json(collection / "host.json")
    inputs, manifest = read_json(workspace / "inputs.json"), read_json(workspace / "manifest.json")
    canonical = read_json(workspace / "canonical-ports.json")
    selected = sorted({row["device"] for row in manifest["layout"]})
    runtime = read_json(workspace / "runtime-inputs.json")
    if read_json(workspace / "provenance.json")["runtime_sha256"] != digest(runtime):
        raise PrerequisiteError("Generated runtime inputs changed after planning")
    baselines = collected_baselines({name: facts[name] for name in selected})
    contexts = render_contexts(inputs["snapshot"], manifest, baselines, canonical)
    requests = {}
    for device, phases in contexts.items():
        requests[device] = {}
        lookup_source = None
        if facts[device]["metadata"].get("buffer_model") == "traditional":
            candidates = facts[device]["lookup_candidates"]
            if not candidates or len({row["sha256"] for row in candidates}) != 1:
                raise PrerequisiteError("Traditional profile-cache lookup is absent or ambiguous on " + device)
            effective = min(candidates, key=lambda row: row["path"])
            lookup_source = {key: effective[key] for key in ("path", "sha256")}
        for phase, context in phases.items():
            templates = runtime["templates"].get(device, {}).get(phase)
            if not isinstance(templates, list) or not templates:
                raise PrerequisiteError("No installed-template selection for " + device + "/" + phase)
            requests[device][phase] = {
                "context": context, "templates": templates, "template_sha256": facts[device]["template_sha256"],
                "lookup_source": lookup_source,
                "fully_lossy": runtime["buffer_profiles"][device]["profile"] == "lossy"}
    render_directory = Path(tempfile.mkdtemp(prefix="templates-", dir=str(workspace)))
    # Private directories require owner traversal, not group/world access.
    os.chmod(str(render_directory), 0o700)  # nosemgrep: insecure-file-permissions
    runner.play("generic_hwsku_render.yml", {
        "generic_render_hosts": selected, "generic_render_requests": requests,
        "generic_render_directory": str(render_directory)})
    tables = {device: {phase: read_json(render_directory / (device + "-" + phase + ".json"))
                       for phase in phases} for device, phases in contexts.items()}
    bundle = render_bundle(inputs["snapshot"], manifest, baselines, canonical, tables)
    verify_shared_pool_capacity(bundle, tables, facts)
    for device in selected:
        if runtime["buffer_profiles"][device]["profile"] == "lossy":
            ports = {row["dut_port"] if device == bundle["dut"] else row["leaf_port"]
                     for row in manifest["port_bindings"]
                     if device == bundle["dut"] or row["leaf"] == device}
            verify_lossy_policy(bundle["add_configs"][device], ports)
            if device == bundle["dut"]:
                verify_lossy_policy(bundle["deploy_configs"][device], ports)
    devices = {}
    for device in selected:
        candidates = {"add": bundle["add_configs"][device]}
        if device == bundle["dut"]:
            candidates["deploy"] = bundle["deploy_configs"][device]
        devices[device] = {
            "baseline": {"running": baselines[device]["running"],
                         "startup": startup_wire(baselines[device]["startup"])},
            "candidates": candidates,
            "source_sha256": {
                **{entry["path"]: entry["sha256"] for entry in facts[device]["sources"].values()},
                **{entry["path"]: entry["sha256"] for entry in facts[device]["lookup_candidates"]}},
            "media_sources": runtime.get("media_sources", {}).get(device, {}),
        }
    spec = host_spec(bundle, host, runtime["transport"])
    payload = {"bundle": bundle, "devices": devices, "host_spec": spec, "aliases": {},
               "host_inventory_name": host["inventory_name"],
               "host_target": host["inventory_name"] + "/" + spec["container"]}
    backend = NativeBackend(payload, runner)
    backend.stage_devices()
    for name in selected:
        device = next(row for row in manifest["devices"] if row["name"] == name)
        alias = device["realized_hwsku"]
        if alias == device["base_hwsku"]:
            continue
        candidate = {"name": alias, "target": facts[name]["hwsku_directory"]}
        baseline = backend.device_call(name, "alias", "capture", alias_name=alias)["value"]
        if baseline is not None and baseline != candidate:
            raise PrerequisiteError("A realized HWSKU alias conflicts with a pre-existing path")
        payload["aliases"][name + "/" + alias] = {
            "device": name, "name": alias, "baseline": baseline, "candidate": candidate}
    private_json(saved, payload)
    return backend


def legacy_cleanup(arguments, scope, workspace, backend=None):
    path = workspace / "legacy-cleanup.json"
    baseline_name = scope["baseline_testbed"]
    owner = os.environ.get("ELASTICTEST_TEST_PLAN_ID", "")
    if path.is_file():
        retained = read_json(path)
        provenance = workspace / "provenance.json"
        previous_owner = retained.get("owner_plan_id") or (
            read_json(provenance).get("owner_plan_id") if provenance.is_file() else None)
        if not owner or previous_owner != owner:
            raise PrerequisiteError("Original topology cleanup has no matching platform plan owner")
        if retained.get("testbed") != baseline_name:
            raise PrerequisiteError("Retained original-topology cleanup belongs to a different testbed")
        if retained["status"] == "COMPLETE" and backend is not None:
            backend.host_call("stage")
            return
    private_json(path, {"status": "INTENT", "testbed": baseline_name, "owner_plan_id": owner,
                        "meaning": "Original topology host cleanup, before Generic host baseline"})
    private_json(workspace / "mutation-attempted.json", {"phase": "legacy_host_cleanup"})
    command = ["bash", str(ANSIBLE / "testbed-cli.sh"), "-t", str(arguments.testbed_file),
               "-m", str(arguments.vm_inventory), "-k", arguments.vm_type,
               "remove-topo", baseline_name, str(arguments.vault_password_file)]
    verbosity = getattr(arguments, "verbosity", 0)
    if verbosity:
        command.append("-" + "v" * verbosity)
    descriptor = os.open(str(workspace / "legacy-cleanup.log"), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as log:
        completed = subprocess.run(
            command, cwd=str(ANSIBLE), stdout=log, stderr=subprocess.STDOUT, check=False,
            env=dict(os.environ, SONIC_GENERIC_TESTBED=""))
    if completed.returncode:
        raise NativeOperationError(
            "Previous topology cleanup failed; private evidence: " + str(path.with_suffix(".log")))
    if backend is not None:
        backend.host_call("stage")
    private_json(path, {"status": "COMPLETE", "testbed": baseline_name, "owner_plan_id": owner,
                        "meaning": "Previous topology cleanup completed; Generic host baseline is confirmed absent"})


def verify_smoke_ready(transaction, backend, report):
    journal = transaction.status()
    bundle = backend.payload["bundle"]
    attempt = journal.get("attempt", 0)
    if (journal["schema_version"] != 1 or journal["state"] != "DEPLOYED"
            or type(attempt) is not int or attempt < 0 or type(report.get("attempt", 0)) is not int
            or report.get("attempt", 0) != attempt
            or report.get("status") not in ("DUT_READY", "SMOKE_PASSED", "DEPLOYMENT_SMOKE_PASSED")
            or report.get("scenario_id") != bundle["scenario_id"]
            or report.get("bundle_sha256") != bundle["bundle_sha256"]
            or read_artifact(journal["bundle"])["bundle_sha256"] != bundle["bundle_sha256"]):
        raise PrerequisiteError("Packet smoke requires the same verified DUT_READY bundle and deployed attempt")
    expected = {resource["key"]: resource["baseline"] for resource in journal["resources"]}
    for operation in journal["operations"]:
        number = operation.get("attempt", 0)
        if type(number) is not int or not 0 <= number <= attempt:
            raise PrerequisiteError("Packet smoke refuses an invalid operation attempt")
        if number < attempt:
            if ((operation["phase"] == "restore" and operation["status"] == "VERIFIED")
                    or (operation["phase"] in ("add", "deploy") and operation.get("compensated") is True)):
                continue
            raise PrerequisiteError("Packet smoke refuses unresolved history from a previous attempt")
        if (operation["status"] != "VERIFIED" or operation["phase"] not in ("add", "deploy")
                or operation.get("compensated")):
            raise PrerequisiteError("Packet smoke refuses unresolved or inconsistent transaction history")
        expected[operation["resource"]] = operation["after"]
    for resource in journal["resources"]:
        reference = expected[resource["key"]]
        probe = {"id": "{}:probe:{}".format(journal["scenario_id"], resource["key"]),
                 "phase": "probe", "kind": resource["kind"], "target": resource["target"],
                 "resource": resource["key"], "before": copy.deepcopy(reference), "after": copy.deepcopy(reference),
                 "context": copy.deepcopy(resource["context"])}
        observed, wanted = backend.verify(probe), read_artifact(reference)
        if any(observed[key] != probe[key] for key in ("kind", "target")) or observed["operation_id"] != probe["id"]:
            raise PrerequisiteError("Packet smoke received mismatched native resource readback identity")
        actual = observed["value"]
        matches = (isinstance(actual, dict) and set(actual) == {"data", "metadata"}
                   and isinstance(actual["data"], bytes) and actual["data"] == wanted["data"]
                   and canonical_json(actual["metadata"]) == canonical_json(wanted["metadata"])
                   if resource["kind"] == "startup" else canonical_json(actual) == canonical_json(wanted))
        if not matches:
            raise PrerequisiteError("Frozen resource drift blocks packet smoke: " + resource["kind"])
    return attempt


def run_phase(action, arguments, scope, testbed, workspace):
    path = workspace / "provenance.json"
    provenance = read_json(path) if path.is_file() else {}
    owner = os.environ.get("ELASTICTEST_TEST_PLAN_ID", "")
    if not owner or (provenance and provenance["owner_plan_id"] != owner):
        raise PrerequisiteError("Mutations require the original platform-owned plan context; it is not a lease grant")
    bootstrap_option = os.environ.get("SONIC_GENERIC_BOOTSTRAP_DEPLOY", "") if action == "deploy-mg" else ""
    if bootstrap_option not in ("", "1"):
        raise PrerequisiteError("SONIC_GENERIC_BOOTSTRAP_DEPLOY must be 1 or unset")
    bootstrap = bootstrap_option == "1"
    transaction_directory = workspace / "transaction"
    if action == "remove-topo" and not (workspace / "backend.json").is_file():
        if transaction_directory.exists():
            raise RestorationError("Frozen native recovery inputs are missing; retain the transaction and reservation")
        legacy_cleanup(arguments, scope, workspace)
        return {"status": "LEGACY_CLEANED", "configuration_writes_attempted": True,
                "meaning": "Original topology cleanup completed; no Generic device configuration applied"}
    backend = prepare_backend(arguments, scope, workspace)
    if action in ("deploy-mg", "smoke") and not transaction_directory.exists() and not bootstrap:
        raise PrerequisiteError("add-topo must establish the frozen Generic transaction first")
    if action == "remove-topo" and not transaction_directory.exists():
        legacy_cleanup(arguments, scope, workspace, backend)
        return {"status": "LEGACY_CLEANED", "configuration_writes_attempted": True,
                "meaning": "Original host topology removed; no Generic device configuration applied"}
    if action == "remove-topo":
        transaction = DeploymentTransaction.open(transaction_directory, backend)
        if (read_artifact(transaction.status()["bundle"])["bundle_sha256"]
                != backend.payload["bundle"]["bundle_sha256"]):
            raise RestorationError("Native recovery inputs disagree with the original transaction bundle")
        transaction.remove()
        return {"status": "RESTORED", "configuration_writes_attempted": True, "restoration_verified": True,
                "bundle_sha256": backend.payload["bundle"]["bundle_sha256"]}
    if action == "smoke":
        transaction = DeploymentTransaction.open(transaction_directory, backend)
        attempt = verify_smoke_ready(transaction, backend, read_json(workspace / "deployment-report.json"))
        health = backend.health("deploy-mg")
        bundle = backend.payload["bundle"]
        if not bundle["manifest"]["traffic_cases"]:
            return {"status": "SMOKE_PASSED", "configuration_writes_attempted": True,
                    "health": health, "traffic_executed": False, "traffic_status": "BLOCKED_NO_INDEPENDENT_PATH",
                    "bundle_sha256": bundle["bundle_sha256"], "attempt": attempt}
        result = backend.host_call("smoke")
        if (result.get("ready") is not True
                or type(result.get("forwarding_cases_passed")) is not int
                or result["forwarding_cases_passed"] != len(bundle["manifest"]["traffic_cases"])
                or type(result.get("gateway_endpoints_passed")) is not int
                or result["gateway_endpoints_passed"] != len(bundle["manifest"]["endpoints"])):
            raise NativeOperationError("Packet smoke returned no verified success")
        return dict(result, status="SMOKE_PASSED", configuration_writes_attempted=True, health=health,
                    traffic_executed=True, traffic_status="GENERATED_PATHS_PASSED",
                    bundle_sha256=backend.payload["bundle"]["bundle_sha256"], attempt=attempt)
    legacy_cleanup(arguments, scope, workspace, backend)
    host_resources = {backend.payload["host_target"]: {
        "baseline": None, "candidate": candidate_state(backend.payload["host_spec"])}}
    transaction = (DeploymentTransaction.open(transaction_directory, backend) if transaction_directory.exists()
                   else DeploymentTransaction(transaction_directory, backend.payload["bundle"], backend,
                                              host_resources, backend.payload["aliases"]))
    journal = transaction.status()
    bootstrap_add = bootstrap and (
        journal["state"] in ("PREPARED", "ADDING")
        or journal["state"] == "RESTORED" and journal["last_error"] is not None)
    phases = ["add-topo", "deploy-mg"] if bootstrap_add else [action]
    phase, stage = action, "configuration-apply"
    try:
        for phase in phases:
            stage = "configuration-apply"
            if phase == "add-topo":
                outcome = transaction.add()
            elif phase == "deploy-mg":
                outcome = transaction.deploy()
            else:
                raise PrerequisiteError("Unknown Generic lifecycle phase")
            stage = "readiness"
            health = backend.health(phase)
    except (ConflictError, RestorationError):
        raise
    except (OSError, ValueError, RuntimeError) as error:
        failure = transaction.record_failure(phase, error, stage)
        try:
            transaction.remove()
        except (OSError, ValueError, RuntimeError) as restore_error:
            raise RestorationError(
                "{} {} failed and compensation could not prove complete restoration".format(phase, stage)
            ) from restore_error
        raise TransactionError(
            "{} {} failed (attempt {}); original Generic baselines verified restored: {}".format(
                phase, stage, failure.get("attempt", 0) + 1, failure.get("message", str(error)))) from error
    return {"status": "TOPO_READY" if action == "add-topo" else "DUT_READY",
            "configuration_writes_attempted": True, "health": health,
            "bundle_sha256": backend.payload["bundle"]["bundle_sha256"], "attempt": outcome["attempt"],
            "bootstrap_add": len(phases) == 2}
