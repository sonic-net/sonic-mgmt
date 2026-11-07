#!/usr/bin/env python3
"""Generic testbed lifecycle; use --print-data to preview without applying changes."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

from generic_config import traffic_connections, write_private
from plan_generic_topology import (PlanningError, add_connection_arguments, add_planning_arguments, artifact_text,
                                   plan_from_args, resolve_testbed, resolve_workspace, write_artifacts)


ANSIBLE = Path(__file__).resolve().parents[1]


def scenario_id(manifest):
    value = dict(manifest)
    value.pop("scenario_id", None)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_scenario(directory):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / "manifest.json").read_text())
    identifier = manifest["scenario_id"]
    if (not isinstance(identifier, str) or len(identifier) != 64
            or any(character not in "0123456789abcdef" for character in identifier)):
        raise ValueError("Scenario ID must be a SHA-256-shaped ownership key")
    for name in manifest["artifact_sha256"]:
        if Path(name).name != name:
            raise ValueError("Artifact names must not contain paths")
    artifacts = {name: (yaml.safe_load((directory / name).read_text()) if name.endswith(".yml")
                        else json.loads((directory / name).read_text()))
                 for name in manifest["artifact_sha256"]}
    artifacts["manifest.json"] = manifest
    return artifacts


def run_playbook(args, name, variables, local, host=False):
    if not args.inventory or not args.vault_password_file:
        raise ValueError("Device/host operations require --inventory and --vault-password-file")
    request = local / "ansible-vars.json"
    if request.exists():
        request.unlink()
    write_private(request, variables)
    command = ["ansible-playbook", str(ANSIBLE / name)]
    inventories = ([args.vm_inventory] if host else []) + args.inventory
    for inventory in inventories:
        command.extend(["-i", str(Path(inventory).resolve(strict=True))])
    command.extend(["--vault-password-file", str(Path(args.vault_password_file).resolve(strict=True)),
                    "--extra-vars", "@" + str(request)])
    if host:
        limit = variables["generic_testbed"]["server"]
        if name == "generic_host.yml":
            limit += ",localhost"
        command.extend(["--limit", limit])
    environment = dict(os.environ)
    environment["ANSIBLE_LIBRARY"] = ":".join([
        str(ANSIBLE / "library"), str(ANSIBLE / "roles/vm_set/library"),
        environment.get("ANSIBLE_LIBRARY", ""),
    ])
    completed = subprocess.run(command, cwd=ANSIBLE, env=environment)
    if completed.returncode != 0:
        raise ValueError("{} failed (exit {})".format(name, completed.returncode))


def device_stage(args, artifacts, testbed, hostname, phase):
    artifacts = deepcopy(artifacts)
    manifest = artifacts["manifest.json"]
    prepared = artifacts.get("preparation_report.json")
    exclude_managed_acls = (manifest.get("policy", {}).get("exclude_managed_acls", False) if prepared
                            else getattr(args, "exclude_managed_acls", False))
    destination = Path(args.output_dir).resolve()
    if destination.exists():
        raise ValueError("Scenario stage directory already exists")
    facts = artifacts["resolved_facts.json"]
    if (facts.get("hostname") != hostname or manifest["hostname"] != hostname
            or facts.get("peer_hostname") != manifest["peer_hostname"]):
        raise ValueError("Resolved connection identities do not match the scenario manifest; replan the scenario")
    if facts.get("forwarding") is None:
        raise ValueError("A valid routed/access allocation is required before rendering")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".generic-render-", dir=str(destination.parent)) as temporary:
        local = Path(temporary)
        for role in ("dut", "peer"):
            write_private(local / (role + "-request.json"), {
                "role": role, "facts": facts,
                "layouts": manifest["selected_layouts"],
                "settings": artifacts["topology.yml"]["generic_topology"],
                "exclude_managed_acls": exclude_managed_acls,
                **({"buffer_wrapper": (ANSIBLE / "templates/generic_buffers.j2").read_text()}
                   if phase == "render" else {}),
            })
        variables = {"generic_action": phase, "generic_dut": hostname,
                     "generic_peer": facts["peer_hostname"], "generic_hosts": [hostname, facts["peer_hostname"]],
                     "generic_local_dir": str(local)}
        run_playbook(args, "generic_devices.yml", variables, local)
        report = {}
        for role in ("dut", "peer"):
            response = json.loads((local / (role + "-response.json")).read_text())
            if phase == "prepare":
                report[role] = response
                continue
            if exclude_managed_acls and response["report"].get("exclude_managed_acls") is not True:
                raise ValueError("{} renderer did not confirm managed ACL exclusion".format(role))
            artifacts[("dut" if role == "dut" else "leaf") + "_config.json"] = response["config"]
            report[role] = response["report"]
        artifacts["preparation_report.json" if phase == "prepare" else "render_report.json"] = report
        order = (report["dut"]["port_order"] if phase == "prepare" else
                 sorted(artifacts["dut_config.json"]["PORT"], key=lambda name: (int(name[8:]), name)))
        if phase == "render" and prepared:
            if order != facts["dut_port_order"] or report["peer"]["transport"] != prepared["peer"]["transport"]:
                raise ValueError("Rendered PORT order or transport differs from the prepared PTF mapping; "
                                 "retire the old topology and prepare a fresh scenario")
        indices = {name: index for index, name in enumerate(order)}
        facts["dut_port_order"] = order
        artifacts["topology.yml"]["dut_port_order"] = order
        for link in facts["connections"]:
            link["dut_port_index"] = indices[link["dut"]["port"]]
        artifacts["topology.yml"]["topology"]["host_interfaces"] = [
            "0.{}@{}".format(link["dut_port_index"], link["ptf_index"])
            for link in traffic_connections(facts["connections"])]
        artifacts["topology.yml"]["generic_transport"] = report["peer"]["transport"]
        manifest.setdefault("plan_id", manifest["scenario_id"])
        manifest["status"] = "prepared_not_rendered" if phase == "prepare" else "rendered_pending_operator_preflight"
        manifest["transport_prepared"] = phase == "prepare" or bool(prepared)
        manifest["deployable"] = phase == "render"
        manifest["testbed"] = testbed
        manifest.pop("requires_explicit_apply", None)
        manifest.setdefault("policy", {})["exclude_managed_acls"] = exclude_managed_acls
        manifest["policy"].pop("enable_lossless_adapter", None)
        manifest["limitations"] = [
            "single-ASIC traditional buffers and a verified shared QoS-template direction contract",
            "transport VLANs must already be reserved and provisioned through leaf/root/host",
            "full DUT/leaf reloads may flap protected ports; reserve a maintenance window",
        ]
        if len(traffic_connections(facts["connections"])) != len(facts["connections"]):
            manifest["limitations"].append(
                "physical-only children lack CSV transport VLANs: no PTF/forwarding traffic qualification")
        if artifacts["coverage.json"]["status"] != "complete":
            manifest["limitations"].append(
                "best-effort coverage: uncovered mode/operating combinations and buffer cases remain unqualified")
        if exclude_managed_acls:
            manifest["limitations"].append(
                "DATAACL/EVERFLOW bindings on managed ports are excluded from qualification; "
                "protected bindings and ACL rules are preserved")
        manifest["artifact_sha256"] = {
            name: hashlib.sha256(artifact_text(name, value).encode()).hexdigest()
            for name, value in artifacts.items() if name != "manifest.json"}
        if not prepared:
            manifest["scenario_id"] = scenario_id(manifest)
        write_artifacts(destination, artifacts)
    if phase == "prepare":
        print("Prepared canonical PORT/PTF mappings: {}. Device configurations are rendered by deploy-mg.".format(
            destination))
    else:
        print("Rendered private scenario: {}. Contains complete configs, potentially including credentials.".format(
            destination))


def prepare(args, artifacts, testbed, hostname):
    device_stage(args, artifacts, testbed, hostname, "prepare")


def render(args, artifacts, testbed, hostname):
    device_stage(args, artifacts, testbed, hostname, "render")


def print_changes(args, artifacts, hostname):
    """Print only approved summary fields, never inherited configuration values."""
    manifest, facts = artifacts["manifest.json"], artifacts["resolved_facts.json"]
    report = artifacts.get("preparation_report.json") or artifacts["render_report.json"]
    summary = {
        "action": args.action, "dut": hostname, "peer": facts["peer_hostname"],
        "scenario_id": manifest["scenario_id"], "status": manifest.get("status"),
        "coverage": artifacts["coverage.json"]["status"],
        "operations": {
            "add-topo": ["attach scenario-owned host/PTF endpoints"],
            "remove-topo": ["remove scenario-owned host/PTF endpoints"],
            "deploy-mg": (["already deployed; no reload"] if manifest.get("status") == "deployed" else
                          ["verify host/PTF endpoints", "stage both devices", "reload both devices",
                           "save both devices", "clean disposable local artifacts"]),
            "recover": ["restore on-device running/startup backups"],
        }[args.action],
        "transport": [{field: item[field] for field in ("vlan_id", "dut_port", "peer_port", "ptf_index")
                       if field in item} for item in report["peer"]["transport"]],
        "links": [{
            "dut_port": link["dut"]["port"], "peer_port": link["peer"]["port"],
            "role": link["role"], "speed": link["dut"].get("speed"),
            "transport_vlan_id": link.get("transport_vlan_id"), "ptf_index": link.get("ptf_index"),
            "dut_port_index": link.get("dut_port_index"),
        } for link in facts.get("connections", [])],
        "configuration_table_counts": manifest.get("configuration_table_counts", {
            role: {table: len(rows) for table, rows in artifacts.get(name, {}).items()}
            for role, name in (("dut", "dut_config.json"), ("peer", "leaf_config.json"))}),
    }
    print("PRINT DATA: no host provisioning or device configuration applied.")
    print(json.dumps(summary, indent=2))


def cleanup_scenario(directory, artifacts):
    """Discard only known local artifacts; retain the active scenario and remote recovery bundle."""
    directory = Path(directory)
    if directory.name != "rendered" or directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError("Cleanup requires the automatic rendered scenario directory")
    manifest = deepcopy(artifacts["manifest.json"])
    root = directory.parent
    files = [directory / name for name in ("dut_config.json", "leaf_config.json")]
    directories = []
    for stage in ("plan", "prepared"):
        path = root / stage
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_dir():
            raise ValueError("Refusing cleanup of an invalid scenario stage")
        if not any(path.iterdir()):
            directories.append(path)
            continue
        previous = json.loads((path / "manifest.json").read_text())
        expected = manifest.get("plan_id") if stage == "plan" else manifest["scenario_id"]
        if previous.get("scenario_id") != expected:
            raise ValueError("Refusing cleanup of a different scenario")
        names = ("coverage.json", "topology.yml", "resolved_facts.json",
                 "preparation_report.json", "render_report.json", "dut_config.json", "leaf_config.json")
        files.extend(path / name for name in names)
        if all(child.name in (*names, "manifest.json") for child in path.iterdir()):
            files.append(path / "manifest.json")
        directories.append(path)
    snapshots = root / "plan.inputs"
    if str(snapshots / "collection.json") in manifest.get("source_sha256", {}):
        files.append(snapshots / "collection.json")
        for role, names in (("dut", ("platform.json", "pg_profile_lookup.ini")), ("peer", ("platform.json",))):
            path = snapshots / role
            files.extend(path / name for name in names)
            directories.append(path)
        directories.append(snapshots)
    for path in [directory, *directories]:
        if path.is_symlink() or path.exists() and (
                not path.is_dir() or path.stat().st_uid != os.getuid()):
            raise ValueError("Refusing cleanup of an unowned or invalid artifact directory")
    for path in files:
        if path.is_symlink() or path.exists() and (
                not path.is_file() or path.stat().st_uid != os.getuid()):
            raise ValueError("Refusing cleanup of an invalid artifact file")
    manifest["status"] = "deployed"
    manifest.pop("requires_explicit_apply", None)
    if "dut_config.json" in artifacts:
        manifest["configuration_table_counts"] = {
            role: {table: len(rows) for table, rows in artifacts[name].items()}
            for role, name in (("dut", "dut_config.json"), ("peer", "leaf_config.json"))}
    for name in ("dut_config.json", "leaf_config.json"):
        manifest["artifact_sha256"].pop(name, None)
    with tempfile.TemporaryDirectory(prefix=".generic-cleanup-", dir=str(root)) as temporary:
        replacement = Path(temporary) / "manifest.json"
        write_private(replacement, manifest)
        os.replace(str(replacement), str(directory / "manifest.json"))
    for path in files:
        if path.exists():
            path.unlink()
    for path in directories:
        if path.exists() and not any(path.iterdir()):
            path.rmdir()
    print("Removed disposable local configurations, planning artifacts, and default snapshots. "
          "Lifecycle metadata retained in {}; on-device recovery backups are unchanged.".format(directory))


def deploy(args, artifacts, testbed, hostname):
    manifest, facts = artifacts["manifest.json"], artifacts["resolved_facts.json"]
    if manifest["hostname"] != hostname:
        raise ValueError("Scenario DUT does not match the selected testbed")
    host_action = args.action in ("add-topo", "remove-topo")
    ready = manifest.get("deployable") or (host_action and manifest.get("transport_prepared"))
    if not ready:
        raise ValueError("A {} generic scenario is required; run add-topo first".format(
            "prepared" if host_action else "rendered"))
    if artifacts["coverage.json"]["status"] != "complete":
        print("PARTIAL COVERAGE: deployment requirements satisfied; uncovered combinations remain unqualified.")
    physical_only = sum(link.get("transport_vlan_id", -1) is None for link in facts.get("connections", []))
    if physical_only:
        print("PHYSICAL-ONLY COVERAGE: {} children have no CSV VLAN/PTF transport; "
              "their traffic behavior is unqualified.".format(physical_only))
    if manifest.get("testbed") != testbed:
        raise ValueError("Testbed host/PTF settings changed since rendering; render a new scenario")
    report = artifacts.get("preparation_report.json") or artifacts["render_report.json"]
    if args.print_data:
        print_changes(args, artifacts, hostname)
        return
    if args.action == "deploy-mg" and manifest.get("status") == "deployed":
        print("Scenario is already deployed; retained metadata cannot be used to repeat a reload.")
        return
    with tempfile.TemporaryDirectory(prefix="generic-deploy-") as temporary:
        local = Path(temporary)
        variables = {
            "generic_dut": hostname, "generic_peer": facts["peer_hostname"],
            "generic_hosts": [hostname, facts["peer_hostname"]],
            "generic_scenario_id": manifest["scenario_id"], "generic_local_dir": str(local),
            "generic_testbed": testbed, "generic_transport": report["peer"]["transport"],
        }
        if host_action:
            variables["generic_host_action"] = args.action
            run_playbook(args, "generic_host.yml", variables, local, host=True)
            return
        if args.action == "recover":
            variables["generic_action"] = "rollback"
            run_playbook(args, "generic_devices.yml", variables, local)
            return
        report = artifacts["render_report.json"]
        for role in ("dut", "peer"):
            write_private(local / (role + "-request.json"), {
                "config": artifacts[("dut" if role == "dut" else "leaf") + "_config.json"], "report": report[role],
            })
        variables["generic_host_action"] = "verify"
        run_playbook(args, "generic_host.yml", variables, local, host=True)
        variables["generic_action"] = "stage"
        run_playbook(args, "generic_devices.yml", variables, local)
        try:
            for phase in ("apply", "save"):
                variables["generic_action"] = phase
                run_playbook(args, "generic_devices.yml", variables, local)
        except (ValueError, KeyboardInterrupt) as error:
            failure = str(error) or "Deployment interrupted; asynchronous reloads may still be running"
            variables["generic_action"] = "rollback"
            try:
                run_playbook(args, "generic_devices.yml", variables, local)
            except ValueError as recovery:
                raise ValueError("{}; BOTH-DEVICE RECOVERY FAILED: {}. Backups: /var/lib/sonic-generic/{}/ "
                                 "on each device; manual recovery is required".format(
                                     failure, recovery, manifest["scenario_id"])) from recovery
            raise ValueError("{}; both-device configuration rollback completed".format(failure)) from error
    print("Generic deployment reloaded and saved on both devices (link state not checked)")


def automatic_prepare(args, testbed, hostname):
    root = resolve_workspace(testbed["conf-name"])
    prepared = root / "prepared"
    cached = root / "rendered" if (root / "rendered").exists() else prepared
    if cached.exists():
        artifacts = load_scenario(cached)
        if (getattr(args, "exclude_managed_acls", False)
                and not artifacts["manifest.json"].get("policy", {}).get("exclude_managed_acls")):
            raise ValueError("Existing scenario has a different ACL policy; use a fresh workspace")
        deploy(args, artifacts, testbed, hostname)
        return
    plan = root / "plan"
    stage_args = deepcopy(args)
    if not plan.exists():
        if not args.links_csv or not args.peer_hostname:
            raise ValueError("Initial automatic preparation requires --links-csv and --peer-hostname")
        stage_args.hostname, stage_args.output_dir = None, str(plan)
        try:
            artifacts = plan_from_args(stage_args)
        except PlanningError as error:
            write_artifacts(plan, {"coverage.json": error.coverage})
            raise
    else:
        artifacts = load_scenario(plan)
    manifest = artifacts["manifest.json"]
    if manifest.get("testbed") != testbed or manifest["hostname"] != hostname:
        raise ValueError("Automatic preparation workspace belongs to a different testbed")
    stage_args.output_dir = str(prepared)
    prepare(stage_args, artifacts, testbed, hostname)
    deploy(args, load_scenario(prepared), testbed, hostname)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for action in ("add-topo", "remove-topo", "deploy-mg", "recover"):
        command = actions.add_parser(action)
        command.add_argument("--testbed", required=True)
        command.add_argument("--testbed-file", required=True)
        command.add_argument("--vm-inventory", default="veos")
        command.add_argument("--print-data", action="store_true",
                             help="Show a credential-safe change summary without provisioning, reloading, or saving")
        if action == "add-topo":
            command.add_argument("--exclude-managed-acls", action="store_true",
                                 help="Omit inherited DATAACL/EVERFLOW bindings on managed ports; "
                                      "preserve protected bindings and all ACL rules")
            add_planning_arguments(command, required=False)
        else:
            add_connection_arguments(command)
            if action in ("remove-topo", "recover"):
                command.add_argument("--scenario-dir",
                                     help="Select an older rendered scenario instead of automatic storage")
    args = parser.parse_args()
    try:
        hostname, testbed = resolve_testbed(args.testbed_file, args.testbed)
        if args.action == "add-topo":
            automatic_prepare(args, testbed, hostname)
            return
        scenario_dir = getattr(args, "scenario_dir", None)
        if not scenario_dir:
            root = resolve_workspace(args.testbed)
            stage = "rendered" if args.action == "recover" or (root / "rendered").exists() else "prepared"
            scenario_dir = root / stage
        if not (Path(scenario_dir) / "manifest.json").is_file():
            raise ValueError("Required scenario stage is missing: {}".format(scenario_dir))
        artifacts = load_scenario(scenario_dir)
        if artifacts["manifest.json"]["hostname"] != hostname:
            raise ValueError("Scenario DUT does not match the selected testbed")
        planned_testbed = artifacts["manifest.json"].get("testbed", {})
        if planned_testbed.get("conf-name", args.testbed) != args.testbed:
            raise ValueError("Scenario belongs to a different testbed")
        if args.action == "deploy-mg" and not artifacts["manifest.json"].get("deployable"):
            if artifacts["manifest.json"].get("testbed") != testbed:
                raise ValueError("Testbed host/PTF settings changed since preparation; prepare a fresh scenario")
            stage_args = deepcopy(args)
            stage_args.output_dir = str(root / "rendered")
            render(stage_args, artifacts, testbed, hostname)
            scenario_dir = root / "rendered"
            artifacts = load_scenario(scenario_dir)
        deploy(args, artifacts, testbed, hostname)
        if args.action == "deploy-mg" and not args.print_data:
            try:
                cleanup_scenario(scenario_dir, artifacts)
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise ValueError("Both devices are saved, but local artifact cleanup failed; "
                                 "recovery data is retained: {}".format(error)) from error
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        parser.exit(1, "Generic operation failed: {}\n".format(error))


if __name__ == "__main__":
    main()
