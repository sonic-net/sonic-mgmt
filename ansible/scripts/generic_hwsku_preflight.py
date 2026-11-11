#!/usr/bin/env python3
"""Bind installed device/host facts, unchanged wiring and optional settings to planner inputs."""

import ast
import copy
import csv
import hashlib
import json
from pathlib import Path
import posixpath
import re
import sys

import yaml


ANSIBLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANSIBLE / "module_utils"))
from generic_hwsku import (  # noqa: E402
    PrerequisiteError, canonical_json, plan_scenario, protected_cages, validate_manifest)
sys.path.insert(0, str(ANSIBLE / "library"))
from generic_hwsku_health import reference, selectors  # noqa: E402


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read_testbed(path, name):
    with open(path, encoding="utf-8") as handle:
        matches = [row for row in yaml.safe_load(handle) if row["conf-name"] == name]
    if len(matches) != 1 or len(matches[0].get("dut", [])) != 1:
        raise PrerequisiteError("The exact testbed must identify one DUT")
    return matches[0]


def connection_rows(path, dut):
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = []
    for row in rows:
        if row["StartDevice"] == dut:
            result.append({"dut_port": row["StartPort"], "leaf": row["EndDevice"], "leaf_port": row["EndPort"],
                           "speed": int(row["BandWidth"]), "vlan": row["VlanID"].strip(),
                           "autoneg": row.get("AutoNeg", "").strip()})
        elif row["EndDevice"] == dut:
            result.append({"dut_port": row["EndPort"], "leaf": row["StartDevice"], "leaf_port": row["StartPort"],
                           "speed": int(row["BandWidth"]), "vlan": row["VlanID"].strip(),
                           "autoneg": row.get("AutoNeg", "").strip()})
    if not result:
        raise PrerequisiteError("No exact DUT connections in the unchanged baseline CSV")
    return sorted(result, key=canonical_json)


def physical_endpoint(facts, name, speed):
    """Resolve a CSV endpoint from canonical output, never from Ethernet-number arithmetic."""
    baseline_lanes = None
    if "baseline_ports" in facts:
        baseline = facts["baseline_ports"]
        if not isinstance(baseline, dict) or name not in baseline:
            raise PrerequisiteError("CSV endpoint " + name + " is absent from the installed base-HWSKU mapping")
        baseline_lanes = _lanes(baseline[name])
    matches = set()
    for cage, variants in facts["expansions"].items():
        for variant in variants:
            row = variant["ports"].get(name)
            if (row is not None and int(row["speed"]) == speed
                    and (baseline_lanes is None or _lanes(row) == baseline_lanes)):
                lanes = baseline[name]["lanes"] if baseline_lanes is not None else row["lanes"]
                matches.add((cage, tuple(int(lane) for lane in lanes.split(","))))
    if len(matches) != 1:
        raise PrerequisiteError(
            "CSV endpoint {} at speed {} has no unique canonical channel binding".format(name, speed))
    return next(iter(matches))


def readiness_report(scope, facts, host, rows, errors=()):
    devices = {}
    for name in [scope["dut"]] + scope["leaves"]:
        value = facts.get(name)
        if value is None:
            devices[name] = {"collected": False}
            continue
        image = yaml.safe_load(value["image"])
        devices[name] = {
            "collected": True, "hostname": value["hostname"], "metadata": value["metadata"],
            "image": {key: image.get(key) for key in ("build_version", "commit_id", "build_date", "asic_type")},
            "cages": len(value["expansions"]),
            "canonical_expansions": sum(len(variants) for variants in value["expansions"].values()),
            "sources": value["sources"], "lookup_sources": [
                {"path": row["path"], "sha256": row["sha256"]} for row in value["lookup_candidates"]],
        }
    protected = set(scope.get("protected_peers", []))
    report = {
        "status": "NOT_READY", "testbed": scope["testbed"], "devices": devices,
        "controlled_leaves": scope["leaves"], "protected_peers": sorted(protected),
        "connection_counts": {
            peer: {"physical_rows": sum(row["leaf"] == peer for row in rows),
                   "csv_transport_rows": sum(row["leaf"] == peer and bool(row["vlan"]) for row in rows)}
            for peer in sorted({row["leaf"] for row in rows})},
        "host_facts_collected": host is not None,
        "ptf_running": host.get("container", {}).get("running") if host is not None else None,
        "blocking_errors": list(errors),
        "configuration_writes_attempted": False,
        "meaning": "Read-only preflight, not a deployment or qualification pass",
    }
    return report


def _lookup_rows(name, raw):
    candidates = raw["lookup_candidates"]
    if not candidates or len({row["sha256"] for row in candidates}) != 1:
        raise PrerequisiteError("Effective pg_profile_lookup.ini is absent or ambiguous on " + name)
    result = {}
    for line in candidates[0]["content"].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or not all(value.isdigit() for value in fields[2:3]):
            raise PrerequisiteError("Malformed speed/cable/size in installed lookup on " + name)
        pair = (int(fields[0]), fields[1])
        if pair in result:
            raise PrerequisiteError("Duplicate installed lookup pair on " + name)
        result[pair] = {"size": int(fields[2])}
        if len(fields) >= 5:
            if not fields[3].isdigit() or not fields[4].isdigit():
                raise PrerequisiteError("Malformed installed lookup xon/xoff on " + name)
            result[pair].update(xon=int(fields[3]), xoff=int(fields[4]))
    if not result:
        raise PrerequisiteError("Installed lookup contains no supported rows on " + name)
    return result


def _lanes(row):
    value = row.get("lanes", "")
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+(?:,[0-9]+)*", value) is None:
        raise PrerequisiteError("Recorded PORT requires explicit canonical ASIC lanes")
    return {int(lane) for lane in value.split(",")}


def _buffer_budget(name, raw):
    applied = raw.get("applied_buffers")
    if not isinstance(applied, dict) or not all(
            isinstance(applied.get(key), dict) for key in ("pg", "profiles", "pools")):
        raise PrerequisiteError("Applied BUFFER_PG/PROFILE/POOL facts are missing on " + name)
    usage, counts, lossless, pool_names, observed = {}, {}, [], set(), {}
    lossy_zero = bool(applied["pg"])
    for key, binding in applied["pg"].items():
        port, separator, indices = key.partition(":")
        if not separator or port not in raw["running"]["PORT"]:
            raise PrerequisiteError("Applied PG binding has no exact running PORT on " + name)
        indices = set(selectors(indices))
        if observed.setdefault(port, set()) & indices:
            raise PrerequisiteError("Overlapping applied PG reservations are ambiguous on " + name)
        observed[port].update(indices)
        profile = applied["profiles"].get(reference(binding.get("profile", ""), "BUFFER_PROFILE"), {})
        if not profile:
            raise PrerequisiteError("An applied buffer profile is missing or unconverged on " + name)
        lossless_fields = {"xon", "xoff"} & set(profile)
        if lossless_fields and lossless_fields != {"xon", "xoff"}:
            raise PrerequisiteError("An applied lossless profile is incomplete on " + name)
        if not lossless_fields:
            pool = applied["pools"].get(reference(profile.get("pool", ""), "BUFFER_POOL"), {})
            lossy_zero = lossy_zero and str(profile.get("size")) == "0" and pool.get("type") == "ingress"
            continue
        pool = reference(profile.get("pool", ""), "BUFFER_POOL")
        if pool not in applied["pools"]:
            raise PrerequisiteError("An applied lossless buffer pool is missing on " + name)
        pool_names.add(pool)
        size = profile.get("size", "")
        if not str(size).isdigit():
            raise PrerequisiteError("Applied lossless profile size is not resolved on " + name)
        count = len(indices)
        usage[port] = usage.get(port, 0) + int(size) * count
        counts[port] = counts.get(port, 0) + count
        lossless.append(profile)
    if not lossless:
        qos = raw["running"].get("PORT_QOS_MAP")
        if (lossy_zero and set(observed) == set(raw["running"]["PORT"])
                and isinstance(qos, dict) and qos
                and all(isinstance(row, dict) and row.get("pfc_enable") == ""
                        and row.get("pfcwd_sw_enable", "") == "" for row in qos.values())):
            return {}, 0, "size"
        raise PrerequisiteError(
            "No converged lossless PG reservations were collected on {}; a lossy baseline requires "
            "complete zero-sized applied ingress PGs and explicitly disabled PFC".format(name))
    shared = all(str(applied["pools"][pool].get("xoff", "0")).isdigit()
                 and int(applied["pools"][pool].get("xoff", "0")) > 0 for pool in pool_names)
    private_xon = shared and all(str(profile["size"]) == str(profile["xon"]) for profile in lossless)
    return usage, max(counts.values()), "xon" if private_xon else "size"


def _service_cages(raw):
    """Recognize the installed SN5640-C512S2 service-port contract, not port-number patterns."""
    metadata = raw["metadata"]
    if (metadata["platform"], metadata["hwsku"]) != (
            "x86_64-nvidia_sn5640-r0", "Mellanox-SN5640-C512S2"):
        return set()
    result = set()
    for cage, variants in raw["expansions"].items():
        if ({variant["name"] for variant in variants} == {"1x25G[10G]"}
                and all(len(variant["ports"]) == 1 for variant in variants)
                and all(len(_lanes(row)) == 1 for variant in variants for row in variant["ports"].values())
                and {int(row["speed"]) for variant in variants for row in variant["ports"].values()}
                == {10000, 25000}):
            result.add(cage)
    if len(result) != 2:
        raise PrerequisiteError(
            "Installed SN5640-C512S2 service capabilities differ from the verified two-port contract")
    return result


def _service_media_speeds(record):
    if not record or record.get("type") != "SFP/SFP+/SFP28" or str(record.get("nominal_bit_rate")) != "103":
        return None
    try:
        compliance = ast.literal_eval(record["specification_compliance"])
    except (KeyError, SyntaxError, ValueError, TypeError) as error:
        raise PrerequisiteError("The recorded 10G service-module compliance is not interpretable") from error
    if not isinstance(compliance, dict):
        raise PrerequisiteError("The recorded service-module compliance must identify Ethernet capabilities")
    if compliance.get("10G Ethernet Compliance") in ("10GBASE-SR", "10GBASE-LR", "10GBASE-ER", "10GBASE-LRM"):
        return [10000]
    return None


def _device_input(name, raw, lookup, reserved):
    if raw["hostname"].lower() != name.lower():
        raise PrerequisiteError("Collected hostname differs from the requested device")
    image = yaml.safe_load(raw["image"])
    if not isinstance(image, dict) or not isinstance(image.get("build_version"), str) or not image["build_version"]:
        raise PrerequisiteError("Actual installed image identity was not collected")
    metadata = raw["metadata"]
    properties = raw["platform"]["interfaces"]
    groups = {cage: str(properties.get(cage, {}).get("port_group", cage)) for cage in raw["expansions"]}
    running = raw.get("running", {}).get("PORT")
    if not isinstance(running, dict) or not running:
        raise PrerequisiteError("Original running PORT allocation is missing on " + name)
    usage, pg_count, size_field = _buffer_budget(name, raw)
    service_cages = _service_cages(raw)
    cages = []
    port_credits, headroom_credits = {}, {}
    for cage, variants in sorted(raw["expansions"].items()):
        if not isinstance(variants, list) or not variants:
            raise PrerequisiteError("Installed canonical expansions are missing for " + name + " " + cage)
        cage_lanes = set().union(*(_lanes(row) for row in variants[0]["ports"].values()))
        owners = {port: row for port, row in running.items() if _lanes(row) & cage_lanes}
        if not owners or any(not _lanes(row) <= cage_lanes for row in owners.values()):
            raise PrerequisiteError("Running PORT allocation crosses or omits canonical cage " + cage)
        port_credits[cage] = len(owners)
        headroom_credits[cage] = sum(usage.get(port, 0) for port in owners)
        group = groups[cage]
        shared = sum(value == group for value in groups.values()) > 1
        choices = []
        for variant in variants:
            group_mode = ("independent" if not shared else properties[cage].get(
                "group_modes", {}).get(variant["name"]))
            if not group_mode:
                raise PrerequisiteError("Installed shared port group lacks mode compatibility for " + cage)
            ports = []
            for port, row in sorted(variant["ports"].items()):
                lanes = [int(value) for value in row["lanes"].split(",")]
                speed = int(row["speed"])
                cables = sorted(cable for candidate_speed, cable in lookup if candidate_speed == speed)
                if not cables:
                    raise PrerequisiteError("Installed lookup lacks canonical speed {} on {}".format(speed, name))
                attributes = {}
                for field in ("fec", "autoneg"):
                    baseline = {value[field] for value in owners.values()
                                if _lanes(value) & set(lanes) and field in value}
                    if field in row:
                        attributes[field] = row[field]
                    elif len(baseline) <= 1:
                        attributes[field] = next(iter(baseline), None)
                    else:
                        raise PrerequisiteError("Ambiguous baseline {} on {} {}".format(field, name, port))
                ports.append({"name": port, "alias": row["alias"], "index": int(row["index"]),
                              "lanes": lanes, "channels": sorted(lanes), "speed": speed,
                              "fec": attributes["fec"], "autoneg": attributes["autoneg"],
                              "cables": cables})
            choices.append({"id": variant["id"], "name": variant["name"], "group_mode": group_mode, "ports": ports})
        entry = {"name": cage, "group": group, "protected_reason": "", "modes": choices,
                 "role": "service" if cage in service_cages else "data"}
        if cage in service_cages:
            media = _service_media_speeds(raw.get("transceivers", {}).get(cage))
            if media is not None:
                entry["media_speeds"] = media
        cages.append(entry)
    maximum_ports = sum(max(len(mode["ports"]) for mode in cage["modes"]) for cage in cages)
    allocated_ports = sum(port_credits.values())
    if allocated_ports != len(running):
        raise PrerequisiteError(
            "Running PORTs outside installed canonical cages prevent resource accounting on " + name)
    if allocated_ports > maximum_ports:
        raise PrerequisiteError("Running port allocation exceeds installed canonical capability on " + name)
    result = {
        "name": name, "platform": metadata["platform"], "base_hwsku": metadata["hwsku"],
        "realized_hwsku": metadata["hwsku"], "image": image["build_version"],
        "asic_count": int(metadata["num_asic"]), "dedicated": reserved,
        "port_capacity": maximum_ports - allocated_ports, "headroom_capacity": 0,
        "port_credits": port_credits, "headroom_credits": headroom_credits, "cages": cages,
    }
    return result, pg_count, size_field


def _templates(name, raw):
    assets = raw.get("template_sha256", {})
    filename = ("buffers_dynamic.json.j2" if raw["metadata"].get("buffer_model") == "dynamic"
                else "buffers.json.j2")
    selected = []
    for basename in (filename, "qos.json.j2"):
        candidates = [posixpath.join(raw[key], basename) for key in ("hwsku_directory", "platform_directory")]
        candidates = [raw.get("template_paths", {}).get(path, path) for path in candidates]
        path = next((path for path in candidates if path in assets), None)
        if path is None:
            raise PrerequisiteError("Installed {} is missing on {}".format(basename, name))
        selected.append(path)
    return {"add": selected, "deploy": list(selected)}


def _channel_groups(devices, baseline, protected):
    for name, device in devices.items():
        for cage in device["cages"]:
            lanes = {lane for port in cage["modes"][0]["ports"] for lane in port["lanes"]}
            groups, covered = [], set()
            rows = [] if (name, cage["name"]) in protected else baseline.get((name, cage["name"]), [])
            for value in rows:
                group = set(value)
                if group in groups:
                    continue
                if not group or covered & group or not group <= lanes:
                    raise PrerequisiteError("Baseline CSV has overlapping or unknown channel groups on " + name)
                groups.append(group)
                covered.update(group)
            groups.extend({lane} for lane in sorted(lanes - covered))
            for mode in cage["modes"]:
                for port in mode["ports"]:
                    port_lanes = set(port["lanes"])
                    units = [group for group in groups if group <= port_lanes]
                    if set().union(*units) != port_lanes:
                        raise PrerequisiteError(
                            "Baseline CSV is not fine-grained enough for {} {}".format(name, mode["name"]))
                    port["channels"] = sorted(min(group) for group in units)


def build_inputs(scope, facts, host, rows, policy=None, execution_context=None):
    """Derive inputs from installed assets and unchanged wiring, never invented transport."""
    overrides = {} if policy is None else policy
    if not isinstance(overrides, dict) or set(overrides) - {"settings"}:
        raise PrerequisiteError("Only optional settings overrides are accepted; device facts must be collected")
    settings = copy.deepcopy(overrides.get("settings", {}))
    if not isinstance(settings, dict):
        raise PrerequisiteError("Generic settings overrides must be a dictionary")
    if not host:
        raise PrerequisiteError("The original host/PTF state is unavailable")
    names = [scope["dut"]] + scope["leaves"]
    if any(name not in facts for name in names):
        raise PrerequisiteError("One or more exact controlled-device collections failed")
    installed = {name: _lookup_rows(name, facts[name]) for name in names}
    pairs = set(installed[scope["dut"]])
    if any(set(value) != pairs for value in installed.values()):
        raise PrerequisiteError("Controlled devices have different effective lookup coverage")
    devices, costs, profiles = {}, {}, {}
    for name in names:
        devices[name], pg_count, size_field = _device_input(
            name, facts[name], installed[name], name in names)
        if any(size_field not in row for row in installed[name].values()):
            raise PrerequisiteError("Installed lookup lacks the applied reservation field " + size_field)
        costs[name] = {pair: row[size_field] * pg_count for pair, row in installed[name].items()}
        profiles[name] = {"profile": "lossless" if pg_count else "lossy", "lossless_pg_count": pg_count}
    profile_names = {value["profile"] for value in profiles.values()}
    if len(profile_names) != 1:
        raise PrerequisiteError("Mixed installed lossy/lossless policies require per-device cost accounting")
    speeds = {port["speed"] for cage in devices[scope["dut"]]["cages"]
              for mode in cage["modes"] for port in mode["ports"]}
    lookup = [{"speed": speed, "cable": cable, "headroom": max(costs[name][speed, cable] for name in names)}
              for speed, cable in sorted(pairs) if speed in speeds]
    excluded = [{"speed": speed, "cable": cable, "reason": "Not advertised by installed DUT canonical expansions",
                 "evidence_sha256": digest(facts[scope["dut"]]["platform"])}
                for speed, cable in sorted(pairs) if speed not in speeds]
    links, endpoints, baseline_groups = [], [], {}
    protected = set(scope.get("protected_peers", []))
    parent = host["external_interface"]
    parents = [row for row in host["host_links"] if row["ifname"] == parent]
    if len(parents) != 1 or "UP" not in parents[0].get("flags", []):
        raise PrerequisiteError("The exact baseline transport parent is unavailable")
    mtu = parents[0].get("mtu")
    if type(mtu) is not int or not 576 <= mtu <= 65535:
        raise PrerequisiteError("The existing transport parent has no valid observed MTU")
    prefix = "gg" + digest([scope["testbed"], rows])[:6]
    existing_names = {row["ifname"] for row in host["host_links"]}
    for row in rows:
        dut_cage, dut_channels = physical_endpoint(facts[scope["dut"]], row["dut_port"], row["speed"])
        baseline_groups.setdefault((scope["dut"], dut_cage), []).append(dut_channels)
        if row["leaf"] in protected:
            next(cage for cage in devices[scope["dut"]]["cages"] if cage["name"] == dut_cage)["protected_reason"] = (
                "Uncontrolled baseline peer: " + row["leaf"])
            continue
        if row["leaf"] not in scope["leaves"]:
            raise PrerequisiteError("An unclassified connected peer cannot be reconfigured")
        leaf_cage, leaf_channels = physical_endpoint(facts[row["leaf"]], row["leaf_port"], row["speed"])
        baseline_groups.setdefault((row["leaf"], leaf_cage), []).append(leaf_channels)
        links.append({"dut_cage": dut_cage, "dut_channel": min(dut_channels), "leaf": row["leaf"],
                      "leaf_cage": leaf_cage, "leaf_channel": min(leaf_channels), "excluded_reason": ""})
        if row["vlan"]:
            if re.fullmatch(r"[1-9][0-9]*", row["vlan"]) is None:
                raise PrerequisiteError("Transport rows must identify one exact reserved VLAN")
            index = len(endpoints)
            interface = prefix + str(index)
            if interface in existing_names:
                raise PrerequisiteError("A proposed scenario host interface already exists")
            endpoints.append({"id": "reserved-vlan-" + row["vlan"], "leaf": row["leaf"], "cage": leaf_cage,
                              "channels": [min(leaf_channels)], "ptf_index": index, "trunk": parent,
                              "vlan": int(row["vlan"]), "host_interface": interface, "roles": ["routed", "access"]})
    _channel_groups(devices, baseline_groups, protected_cages(scope["dut"], list(devices.values()), links))
    used_vlans = {int(row["vlanid"]) for row in facts[scope["dut"]]["running"].get("VLAN", {}).values()}
    used_vlans.update(endpoint["vlan"] for endpoint in endpoints)
    if "access_vlan" not in settings:
        settings["access_vlan"] = next((vlan for vlan in range(1000, 4095) if vlan not in used_vlans), None)
        if settings["access_vlan"] is None:
            raise PrerequisiteError("No unused DUT access VLAN is available")
    source_facts = {name: facts[name]["sources"] for name in names}
    runtime = {
        "templates": {name: _templates(name, facts[name]) for name in names},
        "buffer_profiles": profiles,
        "transport": {"mtu": mtu},
        "resource_basis": ("Installed canonical port capacity; only reclaimed applied PG reservations, "
                           "no assumed MMU spare. Verified PFC-disabled zero-sized ingress PGs consume "
                           "no lossless headroom; lossy deployment is not lossless/MMU qualification."),
    }
    media_sources = {
        name: {cage["name"]: facts[name]["transceivers"][cage["name"]] for cage in devices[name]["cages"]
               if "media_speeds" in cage}
        for name in names}
    if any(media_sources.values()):
        runtime["media_sources"] = {name: rows for name, rows in media_sources.items() if rows}
    snapshot = {
        "schema_version": 1, "dut": scope["dut"], "devices": list(devices.values()), "links": links,
        "endpoints": endpoints, "lookup": lookup, "excluded_lookup": excluded,
        "supported_profiles": sorted(profile_names),
        "sources": {"capabilities": digest({name: facts[name]["platform"] for name in names}),
                    "parser": digest({name: facts[name]["sources"]["parser"] for name in names}),
                    "links": digest(rows), "lookup": digest({name: facts[name]["lookup_candidates"] for name in names}),
                    "policy": digest([settings, runtime, devices, source_facts])},
    }
    if execution_context is not None:
        if (not isinstance(execution_context, dict) or set(execution_context) != {"source_sha", "owner_plan_id"}
                or not isinstance(execution_context["source_sha"], str)
                or re.fullmatch(r"[0-9a-f]{40}", execution_context["source_sha"]) is None
                or not isinstance(execution_context["owner_plan_id"], str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", execution_context["owner_plan_id"]) is None):
            raise PrerequisiteError("Runtime namespace requires the actual source SHA and platform plan identity")
        snapshot["sources"]["policy"] = digest([snapshot["sources"]["policy"], execution_context])
    return snapshot, settings, runtime


def plan_collected(scope, facts, host, rows, policy=None, execution_context=None):
    snapshot, settings, runtime = build_inputs(scope, facts, host, rows, policy, execution_context)
    manifest = plan_scenario(snapshot, settings)
    validate_manifest(manifest, snapshot, settings)
    canonical = {}
    for entry in manifest["layout"]:
        name, cage = entry["device"], entry["cage"]
        variant = next(value for value in facts[name]["expansions"][cage] if value["id"] == entry["expansion"]["id"])
        rows_by_name = copy.deepcopy(variant["ports"])
        for port in entry["expansion"]["ports"]:
            for key in ("fec", "autoneg"):
                if port[key] is not None:
                    rows_by_name[port["name"]][key] = port[key]
                else:
                    rows_by_name[port["name"]].pop(key, None)
        canonical.setdefault(name, {}).update(rows_by_name)
    return snapshot, settings, manifest, canonical, runtime
