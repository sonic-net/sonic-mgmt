#!/usr/bin/env python3
"""Plan one DUT/SONiC-leaf layout from local or read-only collected inputs; never configure devices."""

import argparse
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import yaml

from map_breakout_links import (build_mapping, expand_mode, load_device, load_lookup, mode_variants,
                                selected_speeds, speed_key, supported_speeds)
from generic_config import reconcile_neighbors, traffic_connections


class PlanningError(ValueError):
    def __init__(self, message, coverage):
        super().__init__(message)
        self.coverage = dict(coverage, status="infeasible", reason=message)


class AllocationCapacityError(ValueError):
    pass


def port_key(name):
    match = re.fullmatch(r"Ethernet(\d+)", name)
    if match is None:
        raise ValueError("Unsupported port identity: {}".format(name))
    return int(match.group(1))


def merge_settings(base, override):
    """Merge fields explicitly in caller-supplied defaults/group/host order."""
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_settings(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def load_recipe(paths):
    settings = {}
    for path in paths:
        with open(path) as handle:
            document = yaml.safe_load(handle)
        if not isinstance(document, dict) or not isinstance(document.get("generic_topology"), dict):
            raise ValueError("{}: expected generic_topology mapping".format(path))
        settings = merge_settings(settings, document["generic_topology"])
    schema = {
        "physical_links": {"uplinks", "downlinks"},
        "routed_interfaces": {"address_pool", "prefix_length"},
        "access_vlan": {"vlan_id", "subnet"},
        "external_destinations": {"address_pool", "prefix_length"},
        "constraints": {"reserved_networks", "reserved_vlan_ids"},
        "transport": {"vlan_ids"},
    }
    if set(settings) - set(schema):
        raise ValueError("Unknown generic_topology fields: {}".format(sorted(set(settings) - set(schema))))
    for name, fields in schema.items():
        value = settings.get(name, {})
        if not isinstance(value, dict) or set(value) - fields:
            raise ValueError("Invalid generic_topology.{} settings".format(name))
    required = [("routed_interfaces", "address_pool"), ("access_vlan", "subnet"), ("access_vlan", "vlan_id")]
    if "external_destinations" in settings:
        required.append(("external_destinations", "address_pool"))
    for name, field in required:
        if field not in settings.get(name, {}):
            raise ValueError("Missing generic_topology.{}.{}".format(name, field))
    port_declarations(settings)
    return settings


def port_declarations(settings):
    """Validate interface selectors without requiring them to survive the selected breakout."""
    declarations = {}
    for field, role in (("uplinks", "uplink"), ("downlinks", "downlink")):
        ports = settings.get("physical_links", {}).get(field)
        if role == "downlink" and ports is None:
            ports = []
        if (not isinstance(ports, list) or any(
                not isinstance(port, str) or re.fullmatch(r"Ethernet(?:0|[1-9]\d*)", port) is None
                for port in ports)):
            raise ValueError("generic_topology.physical_links.{} must be a list of canonical DUT child "
                             "ports (Ethernet<number>); cage selectors and PortChannels are not supported".format(
                                 field))
        if len(ports) != len(set(ports)):
            raise ValueError("Duplicate {} interface selectors".format(role))
        declarations[role] = set(ports)
    return declarations


def port_assignments(settings, ports):
    """Match roles per realized link; unmatched names are ignored and other children are downlinks."""
    declarations = port_declarations(settings)
    actual = set(ports)
    uplinks = declarations["uplink"] or set(sorted(actual, key=port_key)[:8])
    conflicts = actual & uplinks & declarations["downlink"]
    if conflicts:
        raise ValueError("Selected interfaces have conflicting uplink/downlink roles: {}".format(
            sorted(conflicts, key=port_key)))
    return {port: "uplink" if port in uplinks else "downlink"
            for port in sorted(actual, key=port_key)}


def validate_uplink_minimum(minimum):
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise ValueError("--min-same-breakout-uplinks must be a positive integer")


def uplink_counts(choices, uplink_ports):
    """Count children sharing a full mode/operating combination, including mixed child speeds."""
    counts = Counter()
    for choice in choices:
        counts[(choice["mode"], speed_key(choice["speed"]))] += sum(
            child["port"] in uplink_ports for child in choice["children"])
    return counts


def target_fields(mode, speed):
    return {"mode": mode, "speed": list(speed) if isinstance(speed, tuple) else speed}


def validate_breakout_diversity(layout, targets=None):
    counts = Counter((choice["mode"], speed_key(choice["speed"])) for choice in layout.values())
    targets = (set(counts) if targets is None else {(row["mode"], speed_key(row["speed"])) for row in targets})
    groups = [dict(target_fields(mode, speed), cage_count=counts[(mode, speed)])
              for mode, speed in sorted(targets)]
    return {"groups": groups, "complete": bool(groups) and all(row["cage_count"] for row in groups)}


def validate_uplink_repetition(layout, assignments, minimum=4, targets=None, scope="all"):
    if scope == "none":
        if type(minimum) is not int or minimum != 0:
            raise ValueError("Disabled matching-uplink policy requires minimum zero")
    else:
        validate_uplink_minimum(minimum)
    if scope not in ("all", "one", "none"):
        raise ValueError("Unsupported uplink repetition scope: {}".format(scope))
    ports = {port for port, role in assignments.items() if role == "uplink"}
    counts = uplink_counts(layout.values(), ports)
    targets = (set(counts) if targets is None else {(row["mode"], speed_key(row["speed"])) for row in targets})
    groups = [dict(target_fields(mode, speed), uplink_count=counts[(mode, speed)],
                   shortfall=max(0, minimum - counts[(mode, speed)])) for mode, speed in sorted(targets)]
    if scope == "none":
        for row in groups:
            row["required"] = False
        return {"minimum": 0, "scope": "none", "groups": groups, "selected_target": None, "complete": True}
    if scope == "one":
        matching = [target for target in targets if counts[target] > 0]
        selected = min(matching, key=lambda target: (-counts[target], target)) if matching else None
        for row in groups:
            row["required"] = (row["mode"], speed_key(row["speed"])) == selected
            if not row["required"]:
                row["shortfall"] = 0
        return {"minimum": minimum, "scope": scope, "groups": groups,
                "selected_target": target_fields(*selected) if selected else None,
                "complete": selected is not None and counts[selected] >= minimum}
    return {"minimum": minimum, "groups": groups, "complete": bool(groups) and all(
        row["shortfall"] == 0 for row in groups)}


def read_testbed_entry(path, name):
    """Read one testbed entry without generic-specific DUT restrictions or side effects."""
    with open(path) as handle:
        if Path(path).suffix.lower() == ".csv":
            entries = [{key.lstrip("#").strip(): value for key, value in row.items() if key is not None}
                       for row in csv.DictReader(handle)]
        else:
            entries = yaml.safe_load(handle)
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("{}: expected a list of testbed entries".format(path))
    matches = [entry for entry in entries if entry.get("conf-name") == name]
    if len(matches) != 1:
        raise ValueError("{}: expected exactly one testbed named {!r}, found {}".format(path, name, len(matches)))
    return matches[0]


def generic_topology_recipe(path, name, vars_dir):
    """Return the named generic recipe, or None for a valid traditional topology."""
    topology = read_testbed_entry(path, name).get("topo")
    if not isinstance(topology, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", topology) is None:
        raise ValueError("{}: invalid topology name {!r}".format(name, topology))
    recipe = Path(vars_dir) / ("topo_" + topology + ".yml")
    document = yaml.safe_load(recipe.read_text())
    if not isinstance(document, dict):
        raise ValueError("{}: expected a topology mapping".format(recipe))
    if "generic_topology" not in document:
        return None
    load_recipe([recipe])
    return str(recipe.resolve())


def resolve_testbed(path, name):
    """Read generic testbed identity without topology mutation, inventory access, or eval."""
    entry = read_testbed_entry(path, name)
    duts = entry.get("dut")
    if isinstance(duts, str):
        duts = [dut.strip() for dut in re.split(r"[;,]", duts.strip("[] ")) if dut.strip()]
    if (not isinstance(duts, list) or len(duts) != 1
            or not isinstance(duts[0], str) or not duts[0].strip()):
        raise ValueError("{}: offline generic planning requires exactly one DUT".format(name))
    fields = ("conf-name", "topo", "ptf", "ptf_ip", "ptf_ipv6", "server", "inv_name",
              "group-name", "ptf_image_name", "ptf_imagetag", "vm_base")
    return duts[0].strip(), {field: entry[field] for field in fields if field in entry}


def collect_inputs(args, hostname, testbed):
    """Collect only missing snapshots with inventory-managed authentication."""
    targets = [
        ("platform_json", hostname, "dut", "platform.json"),
        ("pg_profile_lookup", hostname, "dut", "pg_profile_lookup.ini"),
        ("peer_platform_json", args.peer_hostname, "peer", "platform.json"),
    ]
    missing = [target for target in targets if getattr(args, target[0]) is None]
    if not missing:
        return None
    if hostname == args.peer_hostname:
        raise ValueError("DUT and leaf must be distinct inventory hosts")
    requests = {}
    for _, host, _, name in missing:
        if re.fullmatch(r"[A-Za-z0-9_.-]+", host) is None:
            raise ValueError("Collection requires a literal inventory hostname: {!r}".format(host))
        requests.setdefault(host, []).append(name)
    sources = args.inventory
    if not sources and testbed and testbed.get("inv_name"):
        sources = [str(Path(args.testbed_file).resolve().parent / testbed["inv_name"])]
    if not sources:
        raise ValueError("Missing device snapshots require --inventory or a testbed inv_name")
    sources = [str(Path(source).resolve(strict=True)) for source in sources]
    destination = Path(args.snapshot_dir or (args.output_dir + ".inputs")).resolve()
    output = Path(args.output_dir).resolve()
    if destination == output or output in destination.parents:
        raise ValueError("Snapshot directory must be separate from and outside the scenario output directory")
    if destination.exists():
        raise ValueError("Snapshot directory already exists: {}".format(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".generic-inputs-", dir=str(destination.parent)) as temporary:
        staging = Path(temporary) / "snapshots"
        staging.mkdir()
        variables = Path(temporary) / "request.json"
        variables.write_text(json.dumps({
            "generic_requests": requests, "generic_peer": args.peer_hostname,
            "generic_collection_dir": temporary,
        }), encoding="utf-8")
        ansible_dir = Path(__file__).resolve().parents[1]
        command = ["ansible-playbook", str(ansible_dir / "collect_generic_inputs.yml")]
        for source in sources:
            command.extend(["-i", source])
        command.extend(["--extra-vars", "@" + str(variables)])
        if args.vault_password_file:
            command.extend(["--vault-password-file", str(Path(args.vault_password_file).resolve(strict=True))])
        completed = subprocess.run(command, cwd=ansible_dir, timeout=300)
        if completed.returncode != 0:
            raise ValueError("Read-only Ansible collection failed (exit {})".format(completed.returncode))
        provenance = {}
        for attribute, host, role, name in missing:
            document = json.loads((Path(temporary) / (host + ".json")).read_text(encoding="utf-8"))
            item = document["files"][name]
            if not isinstance(item["remote_path"], str) or not isinstance(item["content"], str):
                raise ValueError("Invalid collected asset from {}".format(host))
            directory = staging / role
            directory.mkdir(exist_ok=True)
            (directory / name).write_text(item["content"], encoding="utf-8")
            provenance.setdefault(role, {
                "hostname": host, "platform": document["platform"], "hwsku": document["hwsku"], "files": {},
            })["files"][name] = item["remote_path"]
            setattr(args, attribute, str(destination / role / name))
        (staging / "collection.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        os.rename(str(staging), str(destination))
    return str(destination / "collection.json")


def child_atoms(child, links, side):
    """Treat each maximum-breakout CSV connection as an indivisible channel."""
    lanes = set(child["lanes"])
    atoms = []
    for link in links:
        endpoint = link[side]
        overlap = lanes.intersection(endpoint["lanes"]) if endpoint["cage"] == child["cage"] else set()
        if overlap:
            if overlap != set(endpoint["lanes"]):
                return None
            atoms.append(link["dut"]["port"])
    covered = {lane for link in links if link["dut"]["port"] in atoms for lane in link[side]["lanes"]}
    return tuple(sorted(atoms, key=port_key)) if covered == lanes else None


def candidates(device, links, side, lookup_speeds):
    domains = {}
    rejected = []
    opposite = "peer" if side == "dut" else "dut"
    atom_links = {link["dut"]["port"]: link for link in links}
    for cage_name in sorted({link[side]["cage"] for link in links}, key=port_key):
        cage = device["cages"][cage_name]
        choices = []
        for mode in sorted(cage["breakout_modes"]):
            for variant in mode_variants(mode):
                speed = list(variant) if isinstance(variant, tuple) else variant
                if not set(selected_speeds(mode, variant)).issubset(lookup_speeds):
                    rejected.append({"side": side, "cage": cage_name, "mode": mode, "speed": speed,
                                     "reason": "a component speed has no DUT buffer lookup entry"})
                    continue
                children = expand_mode(cage_name, cage, mode, speed)
                signatures = {}
                reason = None
                for child in children:
                    atoms = child_atoms(child, links, side)
                    if not atoms:
                        reason = "child cannot be formed from complete wired maximum-breakout channels"
                        break
                    neighbors = {atom_links[atom][opposite]["cage"] for atom in atoms}
                    if len(neighbors) != 1:
                        reason = "one child would span multiple peer cages"
                        break
                    settings = {}
                    for column in ("AutoNeg", "LinkTraining", "FEC"):
                        values = {atom_links[atom]["csv_attributes"].get(column, "").strip().lower()
                                  for atom in atoms if atom_links[atom]["csv_attributes"].get(column)}
                        values.discard("")
                        if len(values) > 1:
                            reason = "aggregated channels have conflicting {}".format(column)
                            break
                        if values:
                            settings[column] = values.pop()
                    if reason:
                        break
                    neighbor = neighbors.pop()
                    child["atoms"] = atoms
                    child["link_settings"] = settings
                    signatures.setdefault(neighbor, []).append((atoms, child["speed"]))
                if reason:
                    rejected.append({"side": side, "cage": cage_name, "mode": mode,
                                     "speed": speed, "reason": reason})
                    continue
                choices.append({"mode": mode, "speed": speed, "children": children,
                                "signatures": {name: tuple(sorted(value)) for name, value in signatures.items()}})
        domains[(side, cage_name)] = choices
    return domains, rejected


def compatible(first, first_key, second, second_key):
    if first_key[0] == second_key[0]:
        return True
    return first["signatures"].get(second_key[1]) == second["signatures"].get(first_key[1])


def solve_layout(inventory, dut, peer, lookup, max_states=100000, accept_layout=None, uplink_ports=None,
                 min_same_breakout_uplinks=4, vlan_scope=None, required_dut_ports=()):
    """Maximize attainable coverage, then minimize the number of selected DUT cages."""
    if vlan_scope is None or min_same_breakout_uplinks != 0:
        validate_uplink_minimum(min_same_breakout_uplinks)
    links = [link for link in inventory["links"] if link["eligible"]]
    speeds = {int(row["speed"]) for row in lookup}
    dut_domains, rejected_dut = candidates(dut, links, "dut", speeds)
    peer_domains, rejected_peer = candidates(peer, links, "peer", speeds)
    targets = sorted({(mode, variant) for key in dut_domains for mode in dut["cages"][key[1]]["breakout_modes"]
                      for variant in mode_variants(mode) if set(selected_speeds(mode, variant)).issubset(speeds)})
    required_modes = sorted({mode for mode, _ in targets})
    excluded_modes = [dict(row, device=side) for side, device in (("dut", dut), ("peer", peer))
                      for row in device.get("excluded_modes", [])] + [
        {"cage": key[1], "mode": mode, "reason": "no full operating combination has buffer lookup entries"}
        for key in dut_domains for mode in sorted(dut["cages"][key[1]]["breakout_modes"])
        if not any(set(selected_speeds(mode, variant)).issubset(speeds) for variant in mode_variants(mode))
    ]
    coverage = {"required_modes": required_modes,
                "required_mode_speeds": [target_fields(mode, speed) for mode, speed in targets],
                "required_same_breakout_uplinks": min_same_breakout_uplinks,
                "required_buffer_cases": lookup,
                "excluded_modes": excluded_modes, "rejected_candidates": rejected_dut + rejected_peer,
                "covered_modes": [], "covered_buffer_cases": [], "search_states": 0}
    if not dut_domains:
        raise PlanningError("At least one fully eligible DUT cage is required", coverage)
    domains = dict(dut_domains)
    domains.update(peer_domains)
    neighbors = {key: set() for key in domains}
    for link in links:
        left, right = ("dut", link["dut"]["cage"]), ("peer", link["peer"]["cage"])
        neighbors[left].add(right)
        neighbors[right].add(left)
    for key, choices in domains.items():
        ports = {child["port"] for choice in choices for child in choice["children"]}
        if key[0] != "dut" or not ports.intersection(required_dut_ports):
            choices.append({"mode": None, "speed": 0, "children": [], "signatures": {}})
    changed = True
    while changed:
        changed = False
        for key, choices in domains.items():
            retained = [choice for choice in choices if all(
                any(compatible(choice, key, other, neighbor) for other in domains[neighbor])
                for neighbor in neighbors[key])]
            if len(retained) != len(choices):
                domains[key] = retained
                changed = True
    empty = [key for key in domains if not any(choice["children"] for choice in domains[key])]
    if any(not choices for choices in domains.values()) or all(key in empty for key in dut_domains):
        coverage["empty_domains"] = [list(key) for key in sorted(empty)]
        raise PlanningError("No compatible full-cage layouts for {}".format(empty), coverage)
    if uplink_ports is None:
        uplink_ports = {child["port"] for key, choices in domains.items() if key[0] == "dut"
                        for choice in choices for child in choice["children"]}
    needs = Counter(int(row["speed"]) for row in lookup)
    exhausted = False
    best, best_score, best_allocation_error = None, None, None

    def capacities(assigned):
        choices = [choice for key, choice in assigned.items() if key[0] == "dut" and choice["children"]]
        groups = uplink_counts(choices, uplink_ports)
        children = Counter()
        for choice in choices:
            children.update(child["speed"] for child in choice["children"])
        represented = Counter((choice["mode"], speed_key(choice["speed"])) for choice in choices)
        return groups, children, represented

    def score(groups, children, represented, forwardable=True, cage_count=None):
        largest = max((groups[target] for target in targets), default=0)
        cost = sum(represented.values()) if cage_count is None else cage_count
        if vlan_scope is not None:
            return (int(forwardable), int(largest >= min_same_breakout_uplinks),
                    min(largest, min_same_breakout_uplinks),
                    sum(represented[target] > 0 for target in targets),
                    sum(min(children[speed], count) for speed, count in needs.items()), -cost)
        return (int(forwardable), sum(represented[target] > 0 for target in targets),
                int(largest >= min_same_breakout_uplinks), min(largest, min_same_breakout_uplinks),
                sum(min(children[speed], count) for speed, count in needs.items()), -cost)

    def search(assigned):
        nonlocal exhausted, best, best_score, best_allocation_error
        if coverage["search_states"] >= max_states:
            exhausted = True
            return
        coverage["search_states"] += 1
        groups, capacity, represented = capacities(assigned)
        available = {}
        for key in domains:
            if key not in assigned:
                available[key] = [choice for choice in domains[key] if all(
                    neighbor not in assigned or compatible(choice, key, assigned[neighbor], neighbor)
                    for neighbor in neighbors[key])]
                if not available[key]:
                    return
        upper_groups, upper_children = groups.copy(), capacity.copy()
        upper_represented = represented.copy()
        missing_mode_capacity = {}
        max_children = Counter()
        for key, choices in available.items():
            if key[0] == "dut":
                cage_groups, cage_children = Counter(), Counter()
                cage_targets = set()
                for choice in choices:
                    if not choice["children"]:
                        continue
                    cage_groups |= uplink_counts([choice], uplink_ports)
                    children = Counter(child["speed"] for child in choice["children"])
                    cage_children |= children
                    target = (choice["mode"], speed_key(choice["speed"]))
                    cage_targets.add(target)
                    if not represented[target]:
                        missing_mode_capacity[target] = missing_mode_capacity.get(target, Counter()) | children
                upper_groups.update(cage_groups)
                upper_children.update(cage_children)
                upper_represented.update(cage_targets)
                max_children |= cage_children
        # A cage supplies one mode target. Optimistically credit every missing target's
        # maximum child capacity before bounding any additional cable-case cages.
        missing_capacity = Counter()
        for children in missing_mode_capacity.values():
            missing_capacity.update(children)
        extra_cages = max((
            max(0, min(upper_children[speed], count) - capacity[speed] - missing_capacity[speed]
                + max_children[speed] - 1) // max_children[speed]
            for speed, count in needs.items() if max_children[speed]), default=0)
        minimum_cages = sum(represented.values()) + len(missing_mode_capacity) + extra_cages
        upper_score = score(upper_groups, upper_children, upper_represented, cage_count=minimum_cages)
        if best_score is not None and upper_score <= best_score:
            return
        if not available:
            reason = accept_layout(assigned) if accept_layout is not None else None
            candidate_score = score(groups, capacity, represented, reason is None)
            if best_score is None or candidate_score > best_score:
                best = {key: choice for key, choice in assigned.items() if choice["children"]}
                best_score, best_allocation_error = candidate_score, reason
            return
        key = min(available, key=lambda item: (len(available[item]), item[0] != "dut", port_key(item[1])))
        largest = max((groups[target] for target in targets), default=0)

        def choice_order(choice):
            if not choice["children"]:
                return (0, 0, 0, 0, ("", 0))
            target = (choice["mode"], speed_key(choice["speed"]))
            uplinks = sum(child["port"] in uplink_ports for child in choice["children"])
            children = Counter(child["speed"] for child in choice["children"])
            matching = max(largest, groups[target] + uplinks)
            return (
                -int(not represented[target]) if key[0] == "dut" else 0,
                -int(largest < min_same_breakout_uplinks <= matching)
                if key[0] == "dut" else 0,
                -(min(matching, min_same_breakout_uplinks) - min(largest, min_same_breakout_uplinks))
                if key[0] == "dut" else 0,
                -sum(min(max(0, needs[speed] - capacity[speed]), count) for speed, count in children.items()),
                target,
            )

        choices = sorted(available[key], key=choice_order)
        for choice in choices:
            assigned[key] = choice
            search(assigned)
            del assigned[key]
            if exhausted or best_score == upper_score:
                break

    search({})
    if best is None:
        if exhausted:
            coverage["status"] = "search_limit_reached"
            error = PlanningError("Search limit reached; feasibility is unknown, not proven impossible", coverage)
            error.coverage["status"] = "search_limit_reached"
            raise error
        raise PlanningError("No physically compatible complete DUT/peer layout", coverage)
    groups, capacity, represented = capacities(best)
    repetition = validate_uplink_repetition(
        {key[1]: choice for key, choice in best.items() if key[0] == "dut"},
        {port: "uplink" for port in uplink_ports}, min_same_breakout_uplinks,
        coverage["required_mode_speeds"], scope="none" if min_same_breakout_uplinks == 0 else "one")
    diversity = validate_breakout_diversity(
        {key[1]: choice for key, choice in best.items() if key[0] == "dut"}, coverage["required_mode_speeds"])
    covered_cases = []
    for row in sorted(lookup, key=lambda row: (int(row["speed"]), row["cable"])):
        speed = int(row["speed"])
        if capacity[speed]:
            covered_cases.append(row)
            capacity[speed] -= 1
    coverage.update(status="complete" if diversity["complete"] and repetition["complete"]
                    and len(covered_cases) == len(lookup)
                    and best_allocation_error is None else "incomplete",
                    covered_modes=sorted({choice["mode"] for key, choice in best.items() if key[0] == "dut"}),
                    covered_buffer_cases=covered_cases, uplink_repetition=repetition,
                    breakout_diversity=diversity,
                    uncovered_buffer_cases=[row for row in lookup if row not in covered_cases],
                    search_limit_reached=exhausted, optimality_proven=not exhausted,
                    selected_dut_cage_count=sum(key[0] == "dut" for key in best),
                    unused_cages={
                        side: sorted((key[1] for key in domains if key[0] == side and key not in best), key=port_key)
                        for side in ("dut", "peer")})
    coverage["uncovered_mode_speeds"] = [
        target_fields(row["mode"], row["speed"]) for row in diversity["groups"] if not row["cage_count"]]
    if best_allocation_error:
        coverage["allocation_error"] = best_allocation_error
    return best, coverage


def allocate_forwarding(settings, connections):
    """Allocate addresses for matched routed links and default-access children."""
    actual = [link["dut"]["port"] for link in connections]
    if len(actual) != len(set(actual)):
        raise ValueError("Resolved DUT child interfaces must be unique")
    assignments = port_assignments(settings, actual)
    for link in connections:
        for field in ("role", "interface_mode", "dut_address", "endpoint_address",
                      "destination_prefix", "vlan_id", "gateway"):
            link.pop(field, None)
        link["role"] = assignments[link["dut"]["port"]]
        if link.get("transport_vlan_id", -1) is None:
            link["interface_mode"] = "physical_only"
    eligible = traffic_connections(connections)
    if not any(assignments[link["dut"]["port"]] == "uplink" for link in eligible):
        raise AllocationCapacityError("The routed/access scenario requires at least one matching selected uplink")
    if not any(assignments[link["dut"]["port"]] == "downlink" for link in eligible):
        raise AllocationCapacityError("The routed/access scenario requires at least one selected downlink")
    routed = settings["routed_interfaces"]
    access = settings["access_vlan"]
    external = settings.get("external_destinations")
    pools = [ipaddress.ip_network(value, strict=True)
             for value in (routed["address_pool"], access["subnet"])]
    if external is not None:
        pools.append(ipaddress.ip_network(external["address_pool"], strict=True))
    if len({pool.version for pool in pools}) != 1:
        raise ValueError("All scenario address pools must use one address family")
    if any(first.overlaps(second) for index, first in enumerate(pools) for second in pools[index + 1:]):
        raise ValueError("Scenario address pools overlap")
    reserved = settings.get("constraints", {})
    for value in reserved.get("reserved_networks", []):
        network = ipaddress.ip_network(value, strict=True)
        if any(pool.version == network.version and pool.overlaps(network) for pool in pools):
            raise ValueError("Scenario pool conflicts with reserved network {}".format(value))
    vlan = access["vlan_id"]
    if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
        raise ValueError("access_vlan.vlan_id must be an integer from 1 through 4094")
    if vlan in reserved.get("reserved_vlan_ids", []):
        raise ValueError("DUT VLAN conflicts with a reserved VLAN")
    bits = pools[0].max_prefixlen
    routed_prefix = routed.get("prefix_length", bits - 1)
    prefixes = [("routed", pools[0], routed_prefix, bits - 1)]
    if external is not None:
        external_prefix = external.get("prefix_length", bits)
        prefixes.append(("external", pools[2], external_prefix, bits))
    for name, pool, prefix, maximum in prefixes:
        if isinstance(prefix, bool) or not isinstance(prefix, int) or not pool.prefixlen <= prefix <= maximum:
            raise ValueError("Invalid {} allocation prefix length".format(name))
    ordered = sorted(eligible, key=lambda link: port_key(link["dut"]["port"]))
    uplinks = [link for link in ordered if assignments[link["dut"]["port"]] == "uplink"]
    downlinks = [link for link in ordered if assignments[link["dut"]["port"]] == "downlink"]
    if len(uplinks) > 2 ** (routed_prefix - pools[0].prefixlen):
        raise AllocationCapacityError("Insufficient routed-interface address capacity")
    if external is not None and len(uplinks) > 2 ** (external_prefix - pools[2].prefixlen):
        raise AllocationCapacityError("Insufficient static-route destination capacity")
    subnet = pools[1]
    usable = subnet.num_addresses - (2 if subnet.version == 4 else 1)
    if usable < len(downlinks) + 1 or subnet.prefixlen >= bits - 1:
        raise AllocationCapacityError("Insufficient access subnet address capacity")
    gateway = subnet.network_address + 1
    routes = {}
    routed_subnets = pools[0].subnets(new_prefix=routed_prefix)
    destinations = pools[2].subnets(new_prefix=external_prefix) if external is not None else None
    for link in uplinks:
        interface_subnet = next(routed_subnets)
        hosts = interface_subnet.hosts()
        dut_ip, peer_ip = next(hosts), next(hosts)
        link.update(role="uplink", interface_mode="routed",
                    dut_address="{}/{}".format(dut_ip, routed_prefix), endpoint_address=str(peer_ip))
        if destinations is not None:
            destination = str(next(destinations))
            link["destination_prefix"] = destination
            routes[destination] = {"nexthop": str(peer_ip), "ifname": link["dut"]["port"], "advertise": "false"}
    routes["0.0.0.0/0" if subnet.version == 4 else "::/0"] = {
        "nexthop": uplinks[0]["endpoint_address"], "ifname": uplinks[0]["dut"]["port"], "advertise": "false"}
    for index, link in enumerate(downlinks, 2):
        link.update(role="downlink", interface_mode="access", vlan_id=vlan,
                    endpoint_address=str(subnet.network_address + index), gateway=str(gateway))
    return {"vlan_id": vlan, "svi": "{}/{}".format(gateway, subnet.prefixlen), "static_routes": routes}


def scope_buffer_cases(inventory, dut, lookup):
    """Keep unsupported lookup speeds visible; exclude only speeds confined to protected DUT cages."""
    required, excluded = [], []
    protected = set(inventory["protected_dut_cages"])
    for row in lookup:
        cages = {name for name, cage in dut["cages"].items() if any(
            int(row["speed"]) in supported_speeds(mode) for mode in cage["breakout_modes"])}
        if cages and cages.issubset(protected):
            excluded.append(dict(row, reason="speed is advertised only by protected DUT cages",
                                 dut_cages=sorted(cages, key=port_key)))
        else:
            required.append(row)
    return required, excluded


def scope_vlan_ports(inventory, vlan_ids=None):
    """Freeze allowed traffic endpoints while retaining every physical wiring channel."""
    if vlan_ids is not None and (
            not isinstance(vlan_ids, list) or any(type(vlan) is not int or not 1 <= vlan <= 4094 for vlan in vlan_ids)
            or len(set(vlan_ids)) != len(vlan_ids)):
        raise ValueError("transport.vlan_ids must be a unique list of VLAN IDs")
    inventory = deepcopy(inventory)
    backed = {"dut": {}, "peer": {}}
    for link in inventory["links"]:
        if not link["eligible"]:
            continue
        value = link["csv_attributes"].get("VlanID") or ""
        if not isinstance(value, str):
            raise ValueError("CSV transport VLAN must be a string")
        value = value.strip()
        if not value:
            continue
        if not value.isdigit() or not 1 <= int(value) <= 4094:
            raise ValueError("CSV transport VLAN must be a single ID from 1 through 4094")
        if vlan_ids is not None and int(value) not in vlan_ids:
            continue
        for side in backed:
            backed[side][link[side]["port"]] = int(value)
    for side in backed:
        eligible_ports = {link[side]["port"] for link in inventory["links"] if link["eligible"]}
        backed[side] = {port: vlan for port, vlan in backed[side].items() if port in eligible_ports}
        if len(set(backed[side].values())) != len(backed[side]):
            raise ValueError("CSV transport VLANs must be isolated: duplicate VLAN on {} endpoints".format(side))
    return inventory, dict(source="csv", granularity="realized_port_name",
                           dut_ports=backed["dut"], peer_ports=backed["peer"],
                           unmapped_children="physical_only")


def build_scenario(inventory, dut, peer, lookup, settings, max_states=100000, min_same_breakout_uplinks=4,
                   vlan_backed_only=False):
    declarations = port_declarations(settings)
    if not vlan_backed_only or min_same_breakout_uplinks != 0:
        validate_uplink_minimum(min_same_breakout_uplinks)
    if not declarations["uplink"] and min_same_breakout_uplinks:
        raise ValueError("Automatic first-eight uplinks require omitting --min-same-breakout-uplinks")
    vlan_scope = None
    if vlan_backed_only:
        inventory, vlan_scope = scope_vlan_ports(inventory, settings.get("transport", {}).get("vlan_ids"))
    lookup, excluded_buffer_cases = scope_buffer_cases(inventory, dut, lookup)
    if any(row["cable"] == "0m" for row in lookup):
        raise ValueError("Traditional daemon-owned buffers cannot assign lookup cable case 0m; "
                         "supply a planning snapshot containing supported nonzero cable cases")

    atom_links = {link["dut"]["port"]: link for link in inventory["links"] if link["eligible"]}

    def layout_connections(layout):
        peer_children = {(tuple(child["atoms"]), child["speed"]): child
                         for key, choice in layout.items() if key[0] == "peer" for child in choice["children"]}
        result = []
        for key in sorted(layout, key=lambda item: (item[0], port_key(item[1]))):
            if key[0] != "dut":
                continue
            for child in layout[key]["children"]:
                matched = peer_children[(tuple(child["atoms"]), child["speed"])]
                link = {"dut": deepcopy(child), "peer": deepcopy(matched),
                        "source_links": [atom_links[atom]["csv_attributes"] for atom in child["atoms"]],
                        "connectivity_verified": False}
                if vlan_scope is not None:
                    link["transport_vlan_id"] = (vlan_scope["dut_ports"].get(child["port"])
                                                 if matched["port"] in vlan_scope["peer_ports"] else None)
                result.append(link)
        return result

    def accepts_allocations(layout):
        try:
            allocate_forwarding(settings, layout_connections(layout))
        except AllocationCapacityError as error:
            return str(error)
        return None

    try:
        solution, coverage = solve_layout(
            inventory, dut, peer, lookup, max_states, accepts_allocations, uplink_ports=declarations["uplink"],
            min_same_breakout_uplinks=min_same_breakout_uplinks, vlan_scope=vlan_scope,
            required_dut_ports=declarations["uplink"] | declarations["downlink"])
    except PlanningError as error:
        error.coverage["excluded_buffer_cases"] = excluded_buffer_cases
        raise
    coverage["excluded_buffer_cases"] = excluded_buffer_cases
    selected = {"dut": {}, "peer": {}}
    for (side, cage), choice in sorted(solution.items(), key=lambda item: (item[0][0], port_key(item[0][1]))):
        selected[side][cage] = {"mode": choice["mode"], "speed": choice["speed"],
                                "children": deepcopy(choice["children"])}
    case_indices = Counter()
    cases = {}
    for row in sorted(lookup, key=lambda row: (int(row["speed"]), row["cable"])):
        cases.setdefault(int(row["speed"]), []).append(row)
    connections = layout_connections(solution)
    for link in connections:
        speed = link["dut"]["speed"]
        link["buffer_case"] = dict(cases[speed][case_indices[speed] % len(cases[speed])])
        case_indices[speed] += 1
    selected_atoms = {atom for link in connections for atom in link["dut"]["atoms"]}
    port_order = sorted(({name for name in dut["ports"] if name not in selected_atoms}
                         | {link["dut"]["port"] for link in connections}), key=port_key)
    assignments = port_assignments(settings, [link["dut"]["port"] for link in connections])
    try:
        forwarding = allocate_forwarding(settings, connections)
    except AllocationCapacityError as error:
        forwarding = None
        coverage.update(status="incomplete", allocation_error=str(error))
        for link in connections:
            link["role"] = assignments[link["dut"]["port"]]
    role_resolution = {
        "ignored_ports": {role: sorted(ports - set(assignments), key=port_key)
                          for role, ports in declarations.items()},
        "defaulted_downlinks": sorted(
            {port for port, role in assignments.items() if role == "downlink"} - declarations["downlink"],
            key=port_key),
    }
    indices = {name: index for index, name in enumerate(port_order)}
    for link in connections:
        link["dut_port_index"] = indices[link["dut"]["port"]]
        link["ptf_index"] = None
        link["transport_status"] = "physical_only_no_csv_vlan"
    traffic = traffic_connections(connections)
    for ptf_index, link in enumerate(traffic):
        link["ptf_index"] = ptf_index
        link["transport_status"] = "requires_provisioning_and_independent_verification"
    bindings = ["0.{}@{}".format(link["dut_port_index"], link["ptf_index"]) for link in traffic]
    topology = {"topology": {"host_interfaces": bindings},
                "generic_topology": deepcopy(settings), "dut_port_order": port_order}
    if not declarations["uplink"]:
        topology["generic_topology"]["physical_links"].update({
            field: sorted((port for port, value in assignments.items() if value == role), key=port_key)
            for field, role in (("uplinks", "uplink"), ("downlinks", "downlink"))
        })
        role_resolution["uplink_selection"] = "first_eight_selected"
    facts = {"hostname": inventory["hostname"], "peer_hostname": inventory["peer_hostname"],
             "status": "planned_not_deployed", "connections": connections, "forwarding": forwarding,
             "dut_port_order": port_order, "role_resolution": role_resolution}
    cleanup = {cage: list(dut["cages"][cage]["lanes"])
               for cage in inventory.get("dut_forwarding_cleanup_cages", [])}
    facts["dut_forwarding_cleanup"] = deepcopy(cleanup)
    if vlan_scope is not None:
        facts["vlan_scope"] = deepcopy(vlan_scope)
    reconcile_neighbors(facts, selected)
    manifest = {
        "schema_version": 3, "status": "planned_not_rendered", "deployable": False,
        "hostname": inventory["hostname"], "peer_hostname": inventory["peer_hostname"],
        "selected_layouts": selected,
        "protected_dut_cages": inventory["protected_dut_cages"],
        "protected_peer_cages": inventory["protected_peer_cages"],
        "unused_cages": deepcopy(coverage["unused_cages"]),
        "policy": {"role_assignment": "explicit_uplinks_default_downlinks",
                   "cage_selection": "minimum_dut_cages_after_coverage",
                   "dut_forwarding_cleanup": cleanup,
                   "coverage_unit": "mode_operating_combination",
                   "coverage_priority": ["physical_cage_diversity", "uplink_repetition", "buffer_cases"],
                   "required_mode_speeds": coverage["required_mode_speeds"],
                   "min_same_breakout_uplinks": min_same_breakout_uplinks,
                   "uplink_repetition_scope": "none" if min_same_breakout_uplinks == 0 else "one",
                   "uplink_repetition_target": coverage["uplink_repetition"]["selected_target"],
                   "role_granularity": "child_port", "active_children": "all",
                   "port_assignments": assignments, "portchannels": "not_generated",
                   "downlink_vlan_grouping": "shared", "routing": "static"},
        "pending_validation": [
            "canonical SONiC parser and installed-image/platform capability validation",
            "electrical connectivity, FEC/AN/link-training and hardware shared-resource constraints",
            "live configuration conflicts and allocation/resource ownership",
            "leaf/root/PTF isolated transport channel provisioning and read-back",
            "QoS/buffer backend policy rendering and complete device configuration generation",
        ],
    }
    if vlan_scope is not None:
        manifest["policy"].update(coverage_requirement="best_effort", vlan_scope=vlan_scope,
                                  coverage_priority=["forwarding", "uplink_repetition",
                                                     "physical_cage_diversity", "buffer_cases"])
        coverage["deployment_eligible"] = (
            forwarding is not None and "allocation_error" not in coverage)
        coverage["vlan_scope"] = {"available_endpoints": len(vlan_scope["dut_ports"]),
                                  "selected_endpoints": len(traffic),
                                  "physical_endpoints": len(connections)}
        coverage["traffic_coverage"] = {
            "status": "partial" if len(traffic) != len(connections) else "planned_not_verified",
            "traffic_links": len(traffic),
            "physical_only_links": [{"dut_port": link["dut"]["port"], "peer_port": link["peer"]["port"],
                                     "reason": "no CSV-backed transport VLAN"}
                                    for link in connections if link["transport_vlan_id"] is None]}
    if not declarations["uplink"]:
        manifest["policy"]["role_assignment"] = "first_eight_selected"
        manifest["policy"]["automatic_uplink_count"] = 8
    if min_same_breakout_uplinks == 0:
        manifest["policy"]["coverage_priority"] = ["forwarding", "physical_cage_diversity", "buffer_cases"]
        coverage["uplink_repetition"] = validate_uplink_repetition(
            selected["dut"], assignments, 0, coverage["required_mode_speeds"], scope="none")
    return {"manifest.json": manifest, "coverage.json": coverage,
            "topology.yml": topology, "resolved_facts.json": facts}


def source_digests(paths):
    return {str(Path(path).resolve()): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}


def resolve_workspace(testbed):
    """Use one private workspace per user/testbed without following workspace or stage symlinks."""
    def require_private(path, create=False):
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Workspace directory must be owned by this user, private, and not a symlink: {}".format(
                path))

    if not isinstance(testbed, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", testbed) is None:
        raise ValueError("Default workspace requires a safe testbed name")
    parent = Path(tempfile.gettempdir()) / "sonic-generic-{}".format(os.getuid())
    require_private(parent, create=True)
    root = parent / testbed
    require_private(root, create=True)
    for stage in ("plan", "prepared", "rendered"):
        path = root / stage
        if path.exists() or path.is_symlink():
            require_private(path)
    print("Generic workspace: {} (retained after exit; system cleanup may remove temporary files).".format(root),
          flush=True)
    return root


def artifact_text(name, value):
    if name.endswith(".yml"):
        return yaml.safe_dump(value, sort_keys=False)
    return json.dumps(value, indent=2) + "\n"


def write_artifacts(output, artifacts):
    """Publish a new directory atomically; never overwrite an earlier scenario."""
    output = Path(output)
    if output.exists():
        raise ValueError("Output directory already exists: {}".format(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".generic-scenario-", dir=str(output.parent)) as temporary:
        staging = Path(temporary) / "scenario"
        staging.mkdir(mode=0o700)
        for name, value in artifacts.items():
            descriptor = os.open(str(staging / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(artifact_text(name, value))
        os.rename(str(staging), str(output))


def seal_artifacts(artifacts):
    manifest = artifacts["manifest.json"]
    manifest.pop("scenario_id", None)
    manifest["artifact_sha256"] = {
        name: hashlib.sha256(artifact_text(name, value).encode()).hexdigest()
        for name, value in artifacts.items()
        if name != "manifest.json"}
    manifest["scenario_id"] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def add_connection_arguments(parser):
    parser.add_argument("--inventory", action="append", default=[],
                        help="Ansible inventory path; repeat to combine sources; defaults to testbed inv_name")
    parser.add_argument("--vault-password-file", help="Ansible vault password file")


def add_planning_arguments(parser, required=True):
    add_connection_arguments(parser)
    for option in ("links-csv", "peer-hostname"):
        parser.add_argument("--" + option, required=required)
    parser.add_argument("--recipe", default=str(Path(__file__).resolve().parents[1] / "vars/topo_generic.yml"))
    for option in ("platform-json", "peer-platform-json", "pg-profile-lookup"):
        parser.add_argument("--" + option, help="Local snapshot; collect from inventory when omitted")
    parser.add_argument("--snapshot-dir", help="New collection directory; defaults to OUTPUT_DIR.inputs")
    parser.add_argument("--overrides", action="append", default=[],
                        help="Recipe overrides in explicit low-to-high precedence order; repeat for group then host")
    parser.add_argument("--exclude-port", action="append", default=[])
    parser.add_argument("--max-search-states", type=int, default=100000)
    parser.add_argument("--min-same-breakout-uplinks", type=int,
                        help="Optional legacy matching-mode uplink constraint; disabled by default. "
                             "Requires explicit nonempty uplink selectors.")


def plan_from_args(args):
    if args.max_search_states <= 0:
        raise ValueError("--max-search-states must be positive")
    if args.min_same_breakout_uplinks is not None:
        validate_uplink_minimum(args.min_same_breakout_uplinks)
    if not args.output_dir:
        root = resolve_workspace(args.testbed or args.hostname)
        args.output_dir = str(root / "plan")
    if Path(args.output_dir).exists():
        raise ValueError("Output directory already exists: {}".format(args.output_dir))
    testbed = None
    hostname = args.hostname
    if args.testbed is not None:
        hostname, testbed = resolve_testbed(args.testbed_file, args.testbed)
    settings = load_recipe([args.recipe] + args.overrides)
    if args.min_same_breakout_uplinks is not None and not port_declarations(settings)["uplink"]:
        raise ValueError("Automatic first-eight uplinks require omitting --min-same-breakout-uplinks")
    collection = collect_inputs(args, hostname, testbed)
    paths = [args.links_csv, args.platform_json, args.peer_platform_json,
             args.pg_profile_lookup, args.recipe] + args.overrides
    if args.testbed is not None:
        paths.append(args.testbed_file)
    if collection is not None:
        paths.append(collection)
    digests = source_digests(paths)
    dut, peer = load_device(args.platform_json), load_device(args.peer_platform_json)
    lookup = load_lookup(args.pg_profile_lookup)
    inventory = build_mapping(
        args.links_csv, hostname, args.peer_hostname, dut, peer, lookup, args.exclude_port)
    artifacts = build_scenario(
        inventory, dut, peer, lookup, settings, args.max_search_states,
        args.min_same_breakout_uplinks if args.min_same_breakout_uplinks is not None else 0,
        vlan_backed_only=True)
    manifest = artifacts["manifest.json"]
    if testbed is not None:
        manifest["testbed"] = testbed
    if collection is not None:
        manifest["collection"] = json.loads(Path(collection).read_text(encoding="utf-8"))
    manifest["source_sha256"] = digests
    manifest["recipe_paths"] = [str(Path(path).resolve()) for path in [args.recipe] + args.overrides]
    seal_artifacts(artifacts)
    write_artifacts(args.output_dir, artifacts)
    excluded = artifacts["coverage.json"]["excluded_buffer_cases"]
    if excluded:
        print("Out-of-scope buffer cases: {} (speeds confined to protected DUT cages; not counted as covered).".format(
            len(excluded)))
    coverage = artifacts["coverage.json"]
    print("CSV VLAN-backed endpoints: {} available, {} selected. Deployment requirements: {}.".format(
        coverage["vlan_scope"]["available_endpoints"], coverage["vlan_scope"]["selected_endpoints"],
        "satisfied" if coverage["deployment_eligible"] else "NOT satisfied (review-only)"))
    physical_only = coverage["traffic_coverage"]["physical_only_links"]
    if physical_only:
        print("Physical-only links: {} (no CSV transport VLAN, forwarding, or PTF traffic qualification).".format(
            len(physical_only)))
    if coverage["status"] != "complete":
        print("Best-effort coverage: {} uncovered mode/operating combinations and {} uncovered buffer cases. "
              "These cases remain unqualified.".format(
                  len(coverage["uncovered_mode_speeds"]), len(coverage["uncovered_buffer_cases"])))
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--hostname", help="Explicit DUT hostname for standalone planning")
    identity.add_argument("--testbed", help="Resolve the single DUT from the selected testbed definition")
    parser.add_argument("--testbed-file", default="testbed.yaml")
    parser.add_argument("--output-dir",
                        help="Developer plan destination; otherwise use the automatic testbed directory")
    add_planning_arguments(parser)
    args = parser.parse_args()
    try:
        artifacts = plan_from_args(args)
    except PlanningError as error:
        try:
            write_artifacts(args.output_dir, {"coverage.json": error.coverage})
        except (OSError, ValueError) as write_error:
            parser.exit(1, "Error: {}; could not write coverage: {}\n".format(error, write_error))
        parser.exit(2, "Planning failed: {}. See {}/coverage.json\n".format(error, args.output_dir))
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, subprocess.TimeoutExpired) as error:
        parser.exit(1, "Error: {}\n".format(error))
    ignored = artifacts["resolved_facts.json"]["role_resolution"]["ignored_ports"]
    for role, ports in ignored.items():
        if ports:
            print("Ignored unmatched {} interface selectors: {}".format(role, ", ".join(ports)))
    print("Sealed scenario plan written to {} (coverage: {}). Use add-topo to render this snapshot; "
          "changed inputs require a fresh workspace; "
          "no deployment performed.".format(args.output_dir, artifacts["coverage.json"]["status"]))


if __name__ == "__main__":
    main()
