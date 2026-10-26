#!/usr/bin/env python3
"""Generic add-topo preparation and explicit deployment, separate from legacy minigraph workflows."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

from generic_config import reconcile_neighbors, validate_vlan_scope, write_private
from plan_generic_topology import (AllocationCapacityError, PlanningError, add_planning_arguments,
                                   allocate_forwarding, artifact_text, load_recipe, plan_from_args, port_assignments,
                                   port_declarations, port_key, resolve_testbed, resolve_workspace, seal_artifacts,
                                   source_digests, validate_breakout_diversity, validate_uplink_repetition,
                                   write_artifacts)


ANSIBLE = Path(__file__).resolve().parents[1]


def scenario_id(manifest):
    value = dict(manifest)
    value.pop("scenario_id", None)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_scenario(directory):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["scenario_id"] != scenario_id(manifest):
        raise ValueError("Scenario manifest digest mismatch")
    for name, expected in manifest["artifact_sha256"].items():
        if Path(name).name != name:
            raise ValueError("Artifact names must not contain paths")
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Scenario artifact changed: {}".format(name))
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


def coverage_ready(artifacts):
    manifest, coverage = artifacts["manifest.json"], artifacts.get("coverage.json", {})
    policy = manifest.get("policy", {})
    if policy.get("coverage_requirement") != "best_effort":
        return coverage.get("status") == "complete"
    facts = artifacts["resolved_facts.json"]
    if not policy.get("vlan_scope") or facts.get("vlan_scope") != policy["vlan_scope"]:
        raise ValueError("CSV VLAN eligibility differs from the frozen policy; replan")
    validate_vlan_scope(facts, policy["vlan_scope"])
    assignments = port_assignments(
        artifacts["topology.yml"]["generic_topology"], [link["dut"]["port"] for link in facts["connections"]])
    if (assignments != policy["port_assignments"]
            or assignments != {link["dut"]["port"]: link["role"] for link in facts["connections"]}):
        raise ValueError("Frozen uplink/downlink assignments differ from the generated YAML; replan")
    if policy.get("role_assignment") == "first_eight_selected":
        first = set(sorted(assignments, key=lambda port: int(port[8:]))[:8])
        if {port for port, role in assignments.items() if role == "uplink"} != first:
            raise ValueError("Automatic uplinks must be the first eight selected DUT ports")
    repetition = validate_uplink_repetition(
        manifest["selected_layouts"]["dut"], policy["port_assignments"],
        policy["min_same_breakout_uplinks"], policy["required_mode_speeds"],
        scope=policy["uplink_repetition_scope"])
    return (coverage.get("status") in ("complete", "incomplete")
            and coverage.get("deployment_eligible") is True
            and "allocation_error" not in coverage and facts.get("forwarding") is not None
            and repetition["complete"])


def validate_forwarding_cleanup(artifacts):
    manifest = artifacts["manifest.json"]
    frozen = manifest.get("policy", {}).get("dut_forwarding_cleanup", {})
    if (not isinstance(frozen, dict) or frozen != artifacts["resolved_facts.json"].get("dut_forwarding_cleanup", {})
            or not set(frozen).issubset(manifest.get("protected_dut_cages", []))):
        raise ValueError("DUT forwarding cleanup differs from the frozen fixed-breakout scope; replan")


def render(args, artifacts, testbed, hostname):
    exclude_managed_acls = getattr(args, "exclude_managed_acls", False)
    destination = Path(args.output_dir).resolve()
    if destination.exists():
        raise ValueError("Rendered scenario directory already exists")
    facts = artifacts["resolved_facts.json"]
    assignments = port_assignments(artifacts["topology.yml"]["generic_topology"],
                                   [link["dut"]["port"] for link in facts["connections"]])
    resolved = {link["dut"]["port"]: link["role"] for link in facts["connections"]}
    if len(resolved) != len(facts["connections"]) or resolved != assignments:
        raise ValueError("Resolved DUT child roles do not match interface selectors/defaults; replan the scenario")
    manifest = artifacts["manifest.json"]
    validate_forwarding_cleanup(artifacts)
    if (facts.get("hostname") != hostname or manifest["hostname"] != hostname
            or facts.get("peer_hostname") != manifest["peer_hostname"]):
        raise ValueError("Resolved connection identities do not match the scenario manifest; replan the scenario")
    reconcile_neighbors(facts, manifest["selected_layouts"])
    repetition = validate_uplink_repetition(
        manifest["selected_layouts"]["dut"], assignments,
        manifest.get("policy", {}).get("min_same_breakout_uplinks", 4),
        manifest.get("policy", {}).get("required_mode_speeds"),
        scope=manifest.get("policy", {}).get("uplink_repetition_scope", "all"))
    if not repetition["complete"]:
        if manifest.get("policy", {}).get("uplink_repetition_scope") == "one":
            raise ValueError("One DUT operating combination needs at least {} matching physical uplinks; "
                             "incomplete plans are review-only".format(repetition["minimum"]))
        raise ValueError("Every required DUT mode/speed needs at least {} physical uplinks; "
                         "incomplete plans are review-only".format(repetition["minimum"]))
    if (repetition.get("scope") == "one" and repetition["selected_target"]
            != manifest["policy"].get("uplink_repetition_target")):
        raise ValueError("Selected uplink combination differs from the frozen repetition target")
    diversity = validate_breakout_diversity(
        manifest["selected_layouts"]["dut"], manifest.get("policy", {}).get("required_mode_speeds"))
    if not diversity["complete"] and manifest.get("policy", {}).get("coverage_requirement") != "best_effort":
        raise ValueError("Every required DUT operating combination needs a physical cage; "
                         "incomplete plans are review-only")
    if not manifest.get("roles_finalized") or not coverage_ready(artifacts):
        raise ValueError("Only finalized plans satisfying deployment requirements can be rendered; "
                         "invalid or legacy incomplete plans are review-only")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".generic-render-", dir=str(destination.parent)) as temporary:
        local = Path(temporary)
        for role in ("dut", "peer"):
            write_private(local / (role + "-request.json"), {
                "role": role, "facts": facts,
                "layouts": manifest["selected_layouts"],
                "settings": artifacts["topology.yml"]["generic_topology"],
                "exclude_managed_acls": exclude_managed_acls,
                "buffer_wrapper": (ANSIBLE / "templates/generic_buffers.j2").read_text(),
            })
        variables = {"generic_action": "render", "generic_dut": hostname,
                     "generic_peer": facts["peer_hostname"], "generic_hosts": [hostname, facts["peer_hostname"]],
                     "generic_local_dir": str(local)}
        run_playbook(args, "generic_devices.yml", variables, local)
        report = {}
        for role in ("dut", "peer"):
            response = json.loads((local / (role + "-response.json")).read_text())
            if exclude_managed_acls and response["report"].get("exclude_managed_acls") is not True:
                raise ValueError("{} renderer did not confirm managed ACL exclusion".format(role))
            artifacts[("dut" if role == "dut" else "leaf") + "_config.json"] = response["config"]
            report[role] = response["report"]
        artifacts["render_report.json"] = report
        order = sorted(artifacts["dut_config.json"]["PORT"],
                       key=lambda name: (int(name[8:]), name))
        indices = {name: index for index, name in enumerate(order)}
        facts["dut_port_order"] = order
        artifacts["topology.yml"]["dut_port_order"] = order
        for link in facts["connections"]:
            link["dut_port_index"] = indices[link["dut"]["port"]]
        artifacts["topology.yml"]["topology"]["host_interfaces"] = [
            "0.{}@{}".format(link["dut_port_index"], link["ptf_index"]) for link in facts["connections"]]
        artifacts["topology.yml"]["generic_transport"] = report["peer"]["transport"]
        manifest = artifacts["manifest.json"]
        manifest["plan_id"] = manifest["scenario_id"]
        manifest["status"] = "rendered_pending_operator_preflight"
        manifest["deployable"] = True
        manifest["testbed"] = testbed
        manifest["requires_explicit_apply"] = True
        manifest.setdefault("policy", {})["exclude_managed_acls"] = exclude_managed_acls
        manifest["policy"].pop("enable_lossless_adapter", None)
        manifest["limitations"] = [
            "single-ASIC traditional buffers and a verified shared QoS-template direction contract",
            "transport VLANs must already be reserved and provisioned through leaf/root/host",
            "full DUT/leaf reloads may flap protected ports; reserve a maintenance window",
        ]
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
        manifest["scenario_id"] = scenario_id(manifest)
        staging = local / "scenario"
        staging.mkdir(mode=0o700)
        for name, value in artifacts.items():
            if name.endswith(".yml"):
                descriptor = os.open(str(staging / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as handle:
                    handle.write(artifact_text(name, value))
            else:
                write_private(staging / name, value)
        os.rename(str(staging), str(destination))
    print("Rendered private scenario: {}. Contains complete configs, potentially including credentials.".format(
        destination))


def deploy(args, artifacts, testbed, hostname):
    manifest, facts = artifacts["manifest.json"], artifacts["resolved_facts.json"]
    validate_forwarding_cleanup(artifacts)
    if manifest["hostname"] != hostname:
        raise ValueError("Scenario DUT does not match the selected testbed")
    if not manifest.get("deployable") or not manifest.get("requires_explicit_apply"):
        raise ValueError("A rendered generic scenario is required; run add-topo first")
    if not manifest.get("roles_finalized") or not coverage_ready(artifacts):
        raise ValueError("Invalid, legacy incomplete, or unfinalized plans are review-only and cannot be deployed")
    if artifacts["coverage.json"]["status"] != "complete":
        print("PARTIAL COVERAGE: deployment requirements satisfied; uncovered combinations remain unqualified.")
    if manifest.get("testbed") != testbed:
        raise ValueError("Testbed host/PTF settings changed since rendering; render a new scenario")
    report = artifacts["render_report.json"]
    if args.action == "deploy-mg" and (
            manifest.get("policy", {}).get("enable_lossless_adapter")
            or any(report[role].get("enable_lossless_adapter") for role in ("dut", "peer"))):
        raise ValueError("Scenario contains a removed lossless override; render a new scenario using installed "
                         "QoS policy through a fresh add-topo workspace. "
                         "Original artifacts remain available for recovery")
    if not args.apply:
        print("DRY RUN: {} for {} / {}; scenario {}".format(
            args.action, hostname, facts["peer_hostname"], manifest["scenario_id"]))
        print("No host provisioning or device configuration applied. "
              "Re-run with --apply only in a reserved maintenance window.")
        print("Transport VLANs: {}".format([item["vlan_id"] for item in report["peer"]["transport"]]))
        return
    with tempfile.TemporaryDirectory(prefix="generic-deploy-") as temporary:
        local = Path(temporary)
        variables = {
            "generic_dut": hostname, "generic_peer": facts["peer_hostname"],
            "generic_hosts": [hostname, facts["peer_hostname"]],
            "generic_scenario_id": manifest["scenario_id"], "generic_local_dir": str(local),
            "generic_testbed": testbed, "generic_transport": report["peer"]["transport"],
            "generic_owned_ports": {role: report[role]["owned_ports"] for role in ("dut", "peer")},
        }
        if args.action in ("add-topo", "remove-topo"):
            variables["generic_host_action"] = args.action
            run_playbook(args, "generic_host.yml", variables, local, host=True)
            if args.action == "add-topo":
                variables.update(dut=hostname, clean_before_add="n")
                run_playbook(args, "fanout_connect.yml", variables, local, host=True)
            return
        for role in ("dut", "peer"):
            write_private(local / (role + "-request.json"), {
                "config": artifacts[("dut" if role == "dut" else "leaf") + "_config.json"], "report": report[role],
            })
        if args.action == "recover":
            variables["generic_action"] = "rollback"
            run_playbook(args, "generic_devices.yml", variables, local)
            return
        variables["generic_host_action"] = "verify"
        run_playbook(args, "generic_host.yml", variables, local, host=True)
        variables["generic_action"] = "stage"
        run_playbook(args, "generic_devices.yml", variables, local)
        try:
            for phase in ("apply", "verify", "save"):
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
    print("Generic deployment verified and saved on both devices")


def finalize(args, artifacts, testbed, hostname):
    """Finalize edited scenario settings without calling the breakout solver."""
    manifest = artifacts["manifest.json"]
    if manifest.get("roles_finalized") or manifest["hostname"] != hostname:
        raise ValueError("Finalize requires an unfinalized breakout plan for this DUT")
    paths = manifest.get("recipe_paths")
    if not isinstance(paths, list) or not paths or any(not isinstance(path, str) for path in paths):
        raise ValueError("Plan lacks topology recipe paths; generate a new plan")
    digests = source_digests(paths)
    settings = load_recipe(paths)
    artifacts["topology.yml"]["generic_topology"] = deepcopy(settings)
    declarations = port_declarations(settings)
    facts = artifacts["resolved_facts.json"]
    assignments = port_assignments(settings, [link["dut"]["port"] for link in facts["connections"]])
    coverage = artifacts["coverage.json"]
    coverage.pop("allocation_error", None)
    try:
        facts["forwarding"] = allocate_forwarding(settings, facts["connections"])
    except AllocationCapacityError as error:
        facts["forwarding"] = None
        coverage["allocation_error"] = str(error)
        for link in facts["connections"]:
            link["role"] = assignments[link["dut"]["port"]]
    facts["role_resolution"] = {
        "ignored_ports": {role: sorted(ports - set(assignments), key=port_key)
                          for role, ports in declarations.items()},
        "defaulted_downlinks": sorted(set(assignments) - declarations["uplink"] - declarations["downlink"],
                                      key=port_key),
    }
    if not declarations["uplink"]:
        artifacts["topology.yml"]["generic_topology"]["physical_links"].update({
            field: sorted((port for port, value in assignments.items() if value == role), key=port_key)
            for field, role in (("uplinks", "uplink"), ("downlinks", "downlink"))
        })
        facts["role_resolution"]["uplink_selection"] = "first_eight_selected"
        facts["role_resolution"]["defaulted_downlinks"] = sorted(
            {port for port, role in assignments.items() if role == "downlink"} - declarations["downlink"],
            key=port_key)
        manifest["policy"].update(role_assignment="first_eight_selected", automatic_uplink_count=8)
    else:
        manifest["policy"]["role_assignment"] = "explicit_uplinks_default_downlinks"
        manifest["policy"].pop("automatic_uplink_count", None)
    repetition = validate_uplink_repetition(
        manifest["selected_layouts"]["dut"], assignments, manifest["policy"]["min_same_breakout_uplinks"],
        manifest["policy"]["required_mode_speeds"], scope=manifest["policy"].get("uplink_repetition_scope", "all"))
    diversity = validate_breakout_diversity(
        manifest["selected_layouts"]["dut"], manifest["policy"]["required_mode_speeds"])
    coverage["uplink_repetition"] = repetition
    coverage["breakout_diversity"] = diversity
    coverage["uncovered_mode_speeds"] = [
        {"mode": row["mode"], "speed": row["speed"]} for row in diversity["groups"] if not row["cage_count"]]
    coverage["status"] = ("complete" if diversity["complete"] and repetition["complete"]
                          and "allocation_error" not in coverage
                          and coverage["covered_buffer_cases"] == sorted(
                              coverage["required_buffer_cases"], key=lambda row: (int(row["speed"]), row["cable"]))
                          else "incomplete")
    if manifest.get("policy", {}).get("coverage_requirement") == "best_effort":
        coverage["deployment_eligible"] = (
            repetition["complete"] and "allocation_error" not in coverage and facts["forwarding"] is not None)
    reconcile_neighbors(facts, manifest["selected_layouts"])
    manifest.update(breakout_plan_id=manifest["scenario_id"], roles_finalized=True, deployable=False,
                    status="finalized_not_rendered" if coverage["status"] == "complete" else "finalized_review_only")
    manifest["policy"]["port_assignments"] = assignments
    if repetition.get("scope") == "one":
        manifest["policy"]["uplink_repetition_target"] = repetition["selected_target"]
    if coverage["status"] != "complete" and coverage_ready(artifacts):
        manifest["status"] = "finalized_partial_coverage"
    if source_digests(paths) != digests:
        raise ValueError("A topology recipe changed during finalization; retry with stable inputs")
    manifest["finalized_recipe_sha256"] = digests
    seal_artifacts(artifacts)
    write_artifacts(args.output_dir, artifacts)
    print("Finalized frozen layout: {} (coverage: {}); no device access.".format(
        args.output_dir, coverage["status"]))
    return artifacts


def automatic_prepare(args, testbed, hostname):
    root = resolve_workspace(testbed["conf-name"], args.output_dir or getattr(args, "workspace", None))
    rendered = root / "rendered"
    if rendered.exists():
        artifacts = load_scenario(rendered)
        if (getattr(args, "exclude_managed_acls", False)
                and not artifacts["manifest.json"].get("policy", {}).get("exclude_managed_acls")):
            raise ValueError("Existing scenario has a different ACL policy; use a fresh workspace")
        deploy(args, artifacts, testbed, hostname)
        return
    plan = root / "plan"
    stage_args = deepcopy(args)
    stage_args.workspace = None
    stage_args.apply = False
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
    finalized = root / "finalized"
    if finalized.exists():
        sealed = load_scenario(finalized)
        if sealed["manifest.json"].get("breakout_plan_id") != manifest["scenario_id"]:
            raise ValueError("Finalized stage belongs to a different breakout plan")
        if (sealed["manifest.json"].get("testbed") != testbed
                or sealed["manifest.json"]["hostname"] != hostname):
            raise ValueError("Finalized stage belongs to a different testbed")
        artifacts = sealed
    else:
        stage_args.scenario_dir, stage_args.output_dir = str(plan), str(finalized)
        artifacts = finalize(stage_args, artifacts, testbed, hostname)
    stage_args.scenario_dir, stage_args.output_dir = str(finalized), str(rendered)
    render(stage_args, artifacts, testbed, hostname)
    deploy(args, load_scenario(rendered), testbed, hostname)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("add-topo", "remove-topo", "deploy-mg", "recover"))
    parser.add_argument("--testbed", required=True)
    parser.add_argument("--testbed-file", required=True)
    parser.add_argument("--vm-inventory", default="veos")
    parser.add_argument("--scenario-dir", help="Explicit rendered stage; otherwise inferred from --workspace")
    parser.add_argument("--output-dir", help="Explicit add-topo preparation workspace")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--exclude-managed-acls", action="store_true",
                        help="Add-topo preparation only: omit inherited DATAACL/EVERFLOW bindings on managed ports; "
                             "preserve protected bindings and all ACL rules")
    add_planning_arguments(parser, required=False)
    args = parser.parse_args()
    try:
        if args.exclude_managed_acls and args.action != "add-topo":
            raise ValueError("--exclude-managed-acls is an add-topo preparation option; "
                             "deployment uses its sealed policy")
        hostname, testbed = resolve_testbed(args.testbed_file, args.testbed)
        if args.workspace and (args.scenario_dir or args.output_dir):
            raise ValueError("Use --workspace or legacy --scenario-dir/--output-dir, not both")
        if args.action == "add-topo" and not args.scenario_dir:
            automatic_prepare(args, testbed, hostname)
            return
        if args.output_dir:
            raise ValueError("--output-dir is only valid for add-topo preparation without --scenario-dir")
        if not args.scenario_dir:
            args.scenario_dir = str(resolve_workspace(args.testbed, args.workspace) / "rendered")
        if not (Path(args.scenario_dir) / "manifest.json").is_file():
            raise ValueError("Required scenario stage is missing: {}".format(args.scenario_dir))
        artifacts = load_scenario(args.scenario_dir)
        if artifacts["manifest.json"]["hostname"] != hostname:
            raise ValueError("Scenario DUT does not match the selected testbed")
        planned_testbed = artifacts["manifest.json"].get("testbed", {})
        if planned_testbed.get("conf-name", args.testbed) != args.testbed:
            raise ValueError("Scenario belongs to a different testbed")
        if (args.exclude_managed_acls
                and not artifacts["manifest.json"].get("policy", {}).get("exclude_managed_acls")):
            raise ValueError("Existing scenario has a different ACL policy; use a fresh workspace")
        deploy(args, artifacts, testbed, hostname)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        parser.exit(1, "Generic operation failed: {}\n".format(error))


if __name__ == "__main__":
    main()
