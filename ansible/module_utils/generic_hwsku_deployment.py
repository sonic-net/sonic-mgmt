"""Offline ConfigDB rendering and a verified, recoverable deployment transaction.

``render_bundle(snapshot, manifest, baselines, canonical_ports, template_tables,
transport_uplinks=None)`` never discovers hardware or runs the planner. Baselines
are ``{device: {"running": ConfigDB, "startup": {"data": bytes, "metadata": dict}}}``.
Canonical ports are complete raw PORT rows, keyed by selected device and name.
Templates are ``{device: {"add": tables, "deploy": tables}}``; only the DUT needs
deploy tables. Uplink overrides are ``{endpoint_id: {"ports": [baseline_port],
"evidence_sha256": digest}}``. Without an override, existing tagged members of
the reserved baseline VLAN are required. A transport's ``trunk`` is opaque.

``render_contexts(snapshot, manifest, baselines, canonical_ports,
transport_uplinks=None)`` supplies full baseline-derived inputs for installed
sonic-cfggen templates before template_tables exist. Its JSON-compatible result
is ``{device: {"add": ConfigDB, "deploy": ConfigDB}}``, with deploy on the DUT
only. PORT, manifest cable lengths, realized HWSKU metadata and phase-specific
forwarding are rendered through the same validated layout logic as the bundle.
Each active candidate's baseline lane owners must belong to exactly one common
existing CABLE_LENGTH group; missing/ambiguous groups fail without an AZURE
default. Protected rows and existing policy globals survive. Selected buffer/
QoS associations are intentionally absent until installed templates generate
them; no threshold, profile, pool sizing or template-specific variable is
fabricated. These contexts are template inputs, NOT deployable configurations.
Feed the complete installed outputs back to render_bundle for independent
coverage, reference, cable and protected-global validation.

The returned JSON-compatible bundle includes complete add/deploy ConfigDBs,
ownership, transport intents, the frozen manifest, and integrity digests.
Original startup data is represented by ``data_b64`` without reserialization.
Startup metadata must include integer mode, uid and gid; extra metadata survives.

``DeploymentTransaction(workspace, bundle, backend, host_resources, aliases)``
exposes add(), deploy(), remove(), and status(). ``DeploymentTransaction.open(
workspace, backend)`` recovers entirely from durable artifacts, without
recollecting or replanning. Mutation methods return state, scenario_id, changed,
and journal; changed includes independently verified interrupted mutations
reconciled by this call, not only new writes. Host resources are
``{target: {"baseline": dict_or_None, "candidate": dict}}``. Alias resources add
``device`` and ``name`` to that record, and their candidate must contain the same
``name``. Existing aliases must be unchanged. Every selected realized HWSKU
different from the baseline HWSKU needs an alias record. Host snapshots must
cover *all* owned host/PTF state; the adapter is responsible for binding these
snapshots to the bundle's exact transport intents, not a newly planned layout.

The backend has precisely two methods:

* perform(op): conditionally replace the named resource with read_artifact(
  op["after"]). It MUST compare live state with op["before"] immediately before
  writing, use op["id"] as its idempotency/ownership identity, and reject drift.
  Its return value is deliberately ignored.
* verify(op): independently read live state and return
  {"operation_id": op["id"], "target": op["target"], "kind": op["kind"],
   "value": native_snapshot, "owned_by": optional_operation_id}.
  Kinds are running, startup, host, alias. Running values are full ConfigDBs;
  startup values contain exact ``data`` bytes and original ``metadata``;
  host/alias values are dictionaries or None for absence. A Boolean success
  is never verification. ``owned_by`` may identify a *proven* partial write by
  a recorded operation, never merely an assumed lease or desired scenario.

Operations contain id, phase, kind, target, before/after artifact references
({path, sha256, kind}), and context (scenario_id, plus alias identity or exact
transport intents where applicable). Artifacts are durable before intent.
Each intent is durable before perform; only matching readback completes it.
Unknown partial state without operation-specific ownership evidence blocks
restoration instead of overwriting unexplained external changes. Backend
exceptions cause compensation; process interruption leaves resumable intent.
No lock acquisition, device executor, config-save, release, or health claim is
implemented here. Offline verification is not physical validation.
"""

import base64
import copy
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager

if __package__:
    from .generic_hwsku import canonical_json, validate_manifest
else:
    from generic_hwsku import canonical_json, validate_manifest


class DeploymentError(ValueError):
    """A missing prerequisite or unsafe deployment input."""


class ConflictError(DeploymentError):
    """The workspace, operation identity, or live configuration has drifted."""


class TransactionError(RuntimeError):
    """An operation failed, including when compensation succeeded."""


class RestorationError(TransactionError):
    """Restoration is incomplete; retain the workspace and its snapshots."""


_PORT_TABLES = {
    "PORT_QOS_MAP", "BUFFER_PG", "BUFFER_QUEUE", "QUEUE",
    "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST",
}
_GLOBAL_QOS = {
    "BUFFER_POOL", "BUFFER_PROFILE", "TC_TO_QUEUE_MAP", "TC_TO_PRIORITY_GROUP_MAP",
    "DSCP_TO_TC_MAP", "TC_TO_DSCP_MAP", "DOT1P_TO_TC_MAP", "MAP_PFC_PRIORITY_TO_QUEUE",
    "PFC_PRIORITY_TO_PRIORITY_GROUP_MAP", "SCHEDULER", "WRED_PROFILE",
}
_TEMPLATE_TABLES = _PORT_TABLES | _GLOBAL_QOS | {"CABLE_LENGTH"}
_QOS_REFERENCES = {
    "BUFFER_PG": {"profile": "BUFFER_PROFILE"},
    "BUFFER_QUEUE": {"profile": "BUFFER_PROFILE"},
    "BUFFER_PROFILE": {"pool": "BUFFER_POOL"},
    "BUFFER_PORT_INGRESS_PROFILE_LIST": {"profile_list": "BUFFER_PROFILE"},
    "BUFFER_PORT_EGRESS_PROFILE_LIST": {"profile_list": "BUFFER_PROFILE"},
    "QUEUE": {"scheduler": "SCHEDULER", "wred_profile": "WRED_PROFILE"},
    "PORT_QOS_MAP": {
        "tc_to_queue_map": "TC_TO_QUEUE_MAP", "tc_to_pg_map": "TC_TO_PRIORITY_GROUP_MAP",
        "dscp_to_tc_map": "DSCP_TO_TC_MAP", "dot1p_to_tc_map": "DOT1P_TO_TC_MAP",
        "tc_to_dscp_map": "TC_TO_DSCP_MAP",
        "pfc_to_queue_map": "MAP_PFC_PRIORITY_TO_QUEUE",
        "pfc_to_pg_map": "PFC_PRIORITY_TO_PRIORITY_GROUP_MAP",
    },
}


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require(condition, message):
    if not condition:
        raise DeploymentError(message)


def _record(value, required, optional=()):
    _require(isinstance(value, dict), "Expected a dictionary")
    _require(set(required) <= set(value) <= set(required) | set(optional),
             "Unexpected record fields; required {}".format(sorted(required)))


def _json_copy(value):
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as error:
        raise DeploymentError("Input is not canonical JSON ({})".format(type(error).__name__)) from None


def _text(value):
    _require(isinstance(value, str) and value and value == value.strip(), "Expected non-padded text")
    return value


def _config(value, require_port=True):
    _require(isinstance(value, dict), "ConfigDB must be a dictionary")
    _require(not require_port or isinstance(value.get("PORT"), dict), "A full ConfigDB PORT table is required")
    for table, rows in value.items():
        _text(table)
        _require(isinstance(rows, dict), "ConfigDB table {} is not a dictionary".format(table))
        for key, row in rows.items():
            _text(key)
            _require(isinstance(row, dict), "ConfigDB row {}|{} is not a dictionary".format(table, key))
            for field in row:
                _text(field)
    return _json_copy(value)


def _number(value):
    _require(type(value) is int or (isinstance(value, str) and re.fullmatch(r"[0-9]+", value)),
             "Expected an unsigned canonical integer")
    return int(value)


def _lanes(row):
    value = row.get("lanes")
    if isinstance(value, str):
        value = value.split(",")
    _require(isinstance(value, list) and value, "PORT lanes must be explicit and ordered")
    lanes = [_number(lane) for lane in value]
    _require(len(set(lanes)) == len(lanes), "PORT lanes overlap within a port")
    return lanes


def _strings(value):
    if isinstance(value, str):
        value = value.split(",")
    _require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
             "Expected an explicit name list")
    _require(len(set(value)) == len(value), "Duplicate names in a reference list")
    return value


def _references(value, names):
    """Find explicit identities, including bracketed DB references and subinterfaces."""
    strings = []

    def collect(item):
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                collect(key)
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)

    collect(value)
    return {name for name in names if any(re.search(
        r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])", text) for text in strings)}


def _startup(value, encoded=False, reloadable=True):
    _record(value, ("data_b64" if encoded else "data", "metadata"))
    _require(isinstance(value["metadata"], dict), "Startup metadata must be explicit")
    _require(all(type(value["metadata"].get(key)) is int and value["metadata"][key] >= 0
                 for key in ("mode", "uid", "gid")) and value["metadata"]["mode"] <= 0o7777,
             "Startup metadata requires original integer mode, uid and gid")
    if encoded:
        _require(isinstance(value["data_b64"], str), "Startup data_b64 must be text")
        try:
            data = base64.b64decode(value["data_b64"], validate=True)
        except (ValueError, TypeError):
            raise DeploymentError("Invalid startup base64") from None
    else:
        data = value["data"]
        _require(isinstance(data, bytes), "Startup data must be exact bytes")
    if reloadable:
        try:
            _config(json.loads(data.decode("utf-8")))
        except (ValueError, UnicodeError):
            raise DeploymentError("Startup must contain a reloadable ConfigDB JSON document") from None
    return {"data_b64": base64.b64encode(data).decode("ascii"), "metadata": _json_copy(value["metadata"])}


def _native(kind, value):
    if kind == "startup":
        return {"data": base64.b64decode(value["data_b64"]), "metadata": copy.deepcopy(value["metadata"])}
    return copy.deepcopy(value)


def _wire(kind, value):
    if kind == "running":
        return _config(value, require_port=False)
    if kind == "startup":
        return _startup(value, reloadable=False)
    _require(kind in {"host", "alias"} and (value is None or isinstance(value, dict)),
             "Host/alias verification must be a snapshot dictionary or None")
    return _json_copy(value)


def _managed_ports(baseline, entries):
    lane_sets = {entry["cage"]: {lane for port in entry["expansion"]["ports"] for lane in port["lanes"]}
                 for entry in entries}
    covered = {cage: set() for cage in lane_sets}
    managed = set()
    all_lanes = set().union(*lane_sets.values())
    for name, row in baseline["PORT"].items():
        lanes = set(_lanes(row))
        if not lanes & all_lanes:
            continue
        cages = [cage for cage, physical in lane_sets.items() if lanes <= physical]
        _require(len(cages) == 1, "Baseline PORT crosses selected/protected cages: " + name)
        cage = cages[0]
        _require(not covered[cage] & lanes, "Baseline PORT lane ownership overlaps")
        covered[cage].update(lanes)
        managed.add(name)
    _require(covered == lane_sets, "Baseline PORT does not completely describe selected physical cages")
    return managed


def _strip_ports(baseline, old_ports, identities, reserved_vlans):
    """Remove only unambiguously port-owned rows; never guess shared ownership."""
    result = copy.deepcopy(baseline)
    removed = set(identities)
    removed_networks = []
    for key in list(result.get("INTERFACE", {})):
        if key.split("|", 1)[0] in old_ports:
            if "|" in key:
                try:
                    address = ipaddress.ip_interface(key.split("|", 1)[1])
                except ValueError:
                    raise DeploymentError("Malformed baseline INTERFACE address") from None
                removed.add(str(address.ip))
                removed_networks.append(address.network)
            del result["INTERFACE"][key]
    memberships = {}
    for vlan, row in result.get("VLAN", {}).items():
        memberships[vlan] = set(_strings(row["members"])) if "members" in row else set()
    for key in result.get("VLAN_MEMBER", {}):
        parts = key.split("|")
        _require(len(parts) == 2 and parts[0] in memberships, "Malformed baseline VLAN_MEMBER")
        memberships[parts[0]].add(parts[1])
    for vlan, members in memberships.items():
        if not members & old_ports:
            continue
        interface_keys = [key for key in result.get("VLAN_INTERFACE", {}) if key.split("|", 1)[0] == vlan]
        if members <= old_ports and vlan not in reserved_vlans:
            del result["VLAN"][vlan]
            removed.add(vlan)
            for key in interface_keys:
                if "|" in key:
                    try:
                        address = ipaddress.ip_interface(key.split("|", 1)[1])
                    except ValueError:
                        raise DeploymentError("Malformed baseline VLAN_INTERFACE address") from None
                    removed.add(str(address.ip))
                    removed_networks.append(address.network)
                del result["VLAN_INTERFACE"][key]
        elif "members" in result["VLAN"][vlan]:
            result["VLAN"][vlan]["members"] = sorted(members - old_ports)
    for key in list(result.get("VLAN_MEMBER", {})):
        if key.split("|")[1] in old_ports:
            del result["VLAN_MEMBER"][key]
    for name in old_ports:
        del result["PORT"][name]
    for table in _PORT_TABLES | {"DEVICE_NEIGHBOR", "NEIGH", "PFC_WD"}:
        for key in list(result.get(table, {})):
            selector = set(key.split("|", 1)[0].split(","))
            if selector & old_ports:
                _require(selector <= old_ports, "Ambiguous shared port group: {}|{}".format(table, key))
                del result[table][key]
    for row in result.get("CABLE_LENGTH", {}).values():
        for name in old_ports & set(row):
            del row[name]
    for row in result.get("ACL_TABLE", {}).values():
        if "ports" in row:
            ports = _strings(row["ports"])
            if old_ports & set(ports):
                row["ports"] = [port for port in ports if port not in old_ports]
    for key, row in list(result.get("BGP_NEIGHBOR", {}).items()):
        if row.get("local_addr") in removed:
            del result["BGP_NEIGHBOR"][key]
    for key, row in list(result.get("STATIC_ROUTE", {}).items()):
        interfaces = set(_strings(row["ifname"])) if row.get("ifname") else set()
        if interfaces & removed:
            _require(interfaces <= removed, "Ambiguous shared static route: " + key)
            del result["STATIC_ROUTE"][key]
        elif row.get("nexthop") and not interfaces:
            for hop in _strings(row["nexthop"]):
                try:
                    address = ipaddress.ip_address(hop)
                except ValueError:
                    raise DeploymentError("Malformed static route next hop") from None
                _require(not any(address.version == network.version and address in network
                                 for network in removed_networks),
                         "Static route has an ambiguous removed-interface next hop: " + key)
    for table, rows in result.items():
        # Peer PORT names and descriptive attributes are not local bindings.
        dependencies = list(rows) if table in {"PORT", "DEVICE_NEIGHBOR"} else rows
        _require(not _references(dependencies, removed),
                 "Unknown or safety-sensitive dependency on managed identities in " + table)
    return result


def _transport(manifest, baselines, managed, overrides):
    overrides = {} if overrides is None else _json_copy(overrides)
    endpoint_ids = {endpoint["transport"]["id"] for endpoint in manifest["endpoints"]}
    _require(set(overrides) <= endpoint_ids, "Uplink metadata names an unselected endpoint")
    used = set()
    result = []
    for endpoint in manifest["endpoints"]:
        transport = endpoint["transport"]
        leaf, vlan = endpoint["leaf"], "Vlan{}".format(transport["vlan"])
        baseline = baselines[leaf]["running"]
        _require((leaf, vlan) not in used, "Transport endpoints share a leaf VLAN")
        used.add((leaf, vlan))
        _require(vlan in baseline.get("VLAN", {})
                 and _number(baseline["VLAN"][vlan].get("vlanid")) == transport["vlan"],
                 "Transport VLAN is not reserved in the leaf baseline: " + vlan)
        _require(not any(key.split("|", 1)[0] == vlan for key in baseline.get("VLAN_INTERFACE", {})),
                 "Reserved transport VLAN has a logical L3 interface: " + vlan)
        members = {key.split("|")[1]: row for key, row in baseline.get("VLAN_MEMBER", {}).items()
                   if key.split("|", 1)[0] == vlan and len(key.split("|")) == 2}
        override = overrides.get(transport["id"])
        if override is not None:
            _record(override, ("ports", "evidence_sha256"))
            _require(isinstance(override["evidence_sha256"], str)
                     and re.fullmatch(r"[0-9a-f]{64}", override["evidence_sha256"]),
                     "Explicit uplinks require verified source evidence")
            uplinks = _strings(override["ports"])
        else:
            uplinks = sorted(name for name, row in members.items()
                             if row.get("tagging_mode") == "tagged" and name not in managed[leaf])
        _require(bool(uplinks), "Missing verified physical uplink for " + transport["id"])
        _require(set(uplinks) <= set(baseline["PORT"]) - managed[leaf],
                 "Transport uplinks must be unselected baseline physical PORTs")
        if override is None:
            _require(all(members[name].get("tagging_mode") == "tagged" for name in uplinks),
                     "Baseline uplink is not tagged")
        else:
            _require(all(name not in members or members[name].get("tagging_mode") == "tagged"
                         for name in uplinks), "Explicit uplink conflicts with baseline untagged membership")
        declared = set(_strings(baseline["VLAN"][vlan]["members"])) if "members" in baseline["VLAN"][vlan] else set()
        _require((set(members) | declared) <= managed[leaf] | set(uplinks),
                 "Reserved VLAN has protected or unexplained transport members")
        result.append({
            "endpoint_id": transport["id"], "leaf": leaf, "leaf_port": endpoint["leaf_port"],
            "vlan": transport["vlan"], "uplink_ports": sorted(uplinks), "trunk": transport["trunk"],
            "host_interface": transport["host_interface"], "ptf_index": transport["ptf_index"],
            "role": endpoint["role"], "dut_port": endpoint["dut_port"],
            "dut_address": endpoint["dut_address"], "ptf_address": endpoint["ptf_address"],
            "gateway": str(ipaddress.ip_interface(endpoint["dut_address"]).ip),
            "cable": endpoint["cable"], "speed": endpoint["speed"],
        })
    return result


def _profile_names(value, table):
    names = _strings(value)
    result = []
    for name in names:
        if name.startswith("["):
            _require(name.startswith("[" + table + "|") and name.endswith("]"), "Ambiguous QoS reference")
            name = name[len(table) + 2:-1]
        result.append(name)
    return result


def _scope_buffer_profiles(tables, baseline):
    profiles = tables.get("BUFFER_PROFILE", {})
    aliases = {}
    for name, row in list(profiles.items()):
        original = baseline.get("BUFFER_PROFILE", {}).get(name)
        if original is None or original == row:
            continue
        alias = "generic_buffer_" + _digest([name, row])[:12]
        _require(alias not in profiles or profiles[alias] == row, "Generated buffer profile name collision")
        previous = baseline.get("BUFFER_PROFILE", {}).get(alias)
        _require(previous is None or previous == row, "Generated buffer profile collides with protected policy")
        profiles[alias] = profiles.pop(name)
        aliases[name] = alias
    for table in ("BUFFER_PG", "BUFFER_QUEUE", "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST"):
        field = "profile_list" if table.endswith("_LIST") else "profile"
        for row in tables.get(table, {}).values():
            if field not in row:
                continue
            values = _strings(row[field])
            names = _profile_names(row[field], "BUFFER_PROFILE")
            replaced = ["[BUFFER_PROFILE|" + aliases.get(name, name) + "]" if value.startswith("[")
                        else aliases.get(name, name) for value, name in zip(values, names)]
            row[field] = ",".join(replaced) if isinstance(row[field], str) else replaced


def _zero_headroom_policy(tables, baseline, ports, active):
    qos = {port: {} for port in active}
    for names, row in tables.get("PORT_QOS_MAP", {}).items():
        for port in set(names.split(",")) & set(active):
            qos[port].update(row)
    if any(row.get("pfc_enable") != "" or row.get("pfcwd_sw_enable", "") != "" for row in qos.values()):
        return False
    covered = {"BUFFER_PG": set(), "BUFFER_QUEUE": set()}
    profiles = dict(baseline.get("BUFFER_PROFILE", {}), **tables.get("BUFFER_PROFILE", {}))
    for table in ("BUFFER_PG", "BUFFER_QUEUE"):
        field = "profile"
        for key, row in tables.get(table, {}).items():
            selected = set(key.split("|", 1)[0].split(",")) & ports
            if not selected:
                continue
            if table in covered:
                covered[table].update(selected)
            names = _profile_names(row.get(field, []), "BUFFER_PROFILE")
            if table in covered and not names:
                return False
            for name in names:
                profile = profiles.get(name, {})
                if str(profile.get("size")) != "0" or {"xon", "xoff"} & set(profile) or not profile.get("pool"):
                    return False
    return bool(active) and all(set(active) <= names for names in covered.values())


def _buffer_reservations(config):
    allocations, totals = {}, {}
    for table in ("BUFFER_PG", "BUFFER_QUEUE", "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST"):
        field = "profile_list" if table.endswith("_LIST") else "profile"
        for key, row in config.get(table, {}).items():
            ports, separator, bounds = key.partition("|")
            names = _profile_names(row.get(field, []), "BUFFER_PROFILE")
            indices = [None]
            if field == "profile":
                if not separator or re.fullmatch(r"[0-9]+(?:-[0-9]+)?", bounds) is None or not names:
                    return None
                first, last = _number(bounds.split("-")[0]), _number(bounds.split("-")[-1])
                if not 0 <= first <= last <= 255:
                    return None
                indices = range(first, last + 1)
            for name in names:
                profile = config.get("BUFFER_PROFILE", {}).get(name, {})
                if {"xon", "xoff"} & set(profile) or "size" not in profile or "pool" not in profile:
                    return None
                pools = _profile_names(profile["pool"], "BUFFER_POOL")
                if len(pools) != 1:
                    return None
                size = _number(profile["size"])
                for port in ports.split(","):
                    for index in indices:
                        identity = (table, port, index if field == "profile" else name)
                        if identity in allocations:
                            if allocations[identity] != name:
                                return None
                            continue
                        allocations[identity] = name
                        totals[pools[0]] = totals.get(pools[0], 0) + size
    return totals


def _apply_templates(config, baseline, tables, ports, cables, protected):
    _require(isinstance(tables, dict) and set(tables) <= _TEMPLATE_TABLES, "Unknown installed QoS/buffer table")
    tables = _json_copy(tables)
    for rows in tables.values():
        _require(isinstance(rows, dict), "Installed template table must contain rows")
        _require(all(isinstance(row, dict) for row in rows.values()), "Installed template row must be a dictionary")
    if protected:
        _scope_buffer_profiles(tables, baseline)
    preserve_pools = bool(protected) and _zero_headroom_policy(tables, baseline, ports, cables)
    factory_reservations = _buffer_reservations(tables) if preserve_pools else None
    for table in _PORT_TABLES:
        for key in list(config.get(table, {})):
            selector = set(key.split("|", 1)[0].split(","))
            if selector & ports:
                _require(selector <= ports, "Template replacement crosses a protected port group")
                del config[table][key]
    for row in config.get("CABLE_LENGTH", {}).values():
        for port in ports & set(row):
            del row[port]
    coverage = {table: set() for table in ("BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP")}
    actual_cables = {}
    for table in sorted(tables, key=lambda name: name == "BUFFER_POOL"):
        rows = tables[table]
        _require(isinstance(rows, dict), "Installed template table must contain rows")
        for key, row in rows.items():
            _text(key)
            _require(isinstance(row, dict), "Installed template row must be a dictionary")
            original = baseline.get(table, {}).get(key)
            if table in _PORT_TABLES:
                selector = set(key.split("|", 1)[0].split(","))
                if selector & ports:
                    _require(selector <= ports, "Installed template mixes selected and protected ports")
                    parts = key.split("|")
                    if table in {"BUFFER_PG", "BUFFER_QUEUE", "QUEUE"}:
                        _require(len(parts) == 2 and re.fullmatch(r"[0-9]+(?:-[0-9]+)?", parts[1]),
                                 "Malformed installed buffer/queue selector")
                    else:
                        _require(len(parts) == 1, "Malformed installed per-port QoS selector")
                    if table in coverage:
                        coverage[table].update(selector)
                else:
                    if selector <= set(protected):
                        continue
                    _require(original == row, "Installed template targets an unknown/protected port: " + key)
            elif table == "CABLE_LENGTH":
                previous = config.setdefault(table, {}).setdefault(key, {})
                for port, cable in row.items():
                    if port in ports:
                        _require(port in cables and cable == cables[port],
                                 "Installed cable assignment disagrees with plan")
                        _require(port not in actual_cables, "Duplicate installed cable assignment")
                        actual_cables[port] = cable
                    else:
                        if port in protected:
                            continue
                        _require(baseline.get(table, {}).get(key, {}).get(port) == cable,
                                 "Installed cable table changes a protected/unknown port")
                    previous[port] = copy.deepcopy(cable)
                continue
            elif protected:
                if table == "BUFFER_POOL" and original is not None and preserve_pools:
                    candidate_reservations = _buffer_reservations(config)
                    _require({field: value for field, value in original.items() if field not in {"size", "xoff"}}
                             == {field: value for field, value in row.items() if field not in {"size", "xoff"}}
                             and candidate_reservations is not None and factory_reservations is not None
                             and set(candidate_reservations) <= set(tables.get("BUFFER_POOL", {}))
                             and set(factory_reservations) <= set(tables.get("BUFFER_POOL", {}))
                             and _number(original.get("size")) + _number(original.get("xoff", "0"))
                             + candidate_reservations.get(key, 0)
                             <= _number(row.get("size")) + _number(row.get("xoff", "0"))
                             + factory_reservations.get(key, 0),
                             "Installed template requires incompatible protected buffer pool policy: " + key)
                    continue
                _require(original == row or (original is None and table != "BUFFER_POOL"),
                         "Installed template changes a shared protected buffer/QoS global: " + table + "|" + key)
            config.setdefault(table, {})[key] = copy.deepcopy(row)
    _require(all(set(cables) <= covered for covered in coverage.values()),
             "Installed templates lack complete candidate PORT QoS/buffer coverage")
    _require(actual_cables == cables, "Installed templates lack exact planned cable lengths")
    for table, fields in _QOS_REFERENCES.items():
        for row in config.get(table, {}).values():
            for field, referenced_table in fields.items():
                if field in row:
                    for name in _profile_names(row[field], referenced_table):
                        _require(name in config.get(referenced_table, {}),
                                 "Unresolved installed QoS/buffer reference: " + referenced_table + "|" + name)


def _insert(config, table, key, row):
    previous = config.setdefault(table, {}).get(key)
    _require(previous is None or previous == row, "Candidate conflicts with protected {}|{}".format(table, key))
    config[table][key] = copy.deepcopy(row)


def _forwarding(config, manifest):
    if not manifest["endpoints"]:
        _require(not manifest["traffic_cases"] and manifest["requirements"]["routed_ports"] == 0,
                 "Traffic requirements disagree with the empty endpoint set")
        return
    vlan = "Vlan{}".format(manifest["settings"]["access_vlan"])
    networks = {ipaddress.ip_interface(endpoint["dut_address"]).network for endpoint in manifest["endpoints"]}
    for table in ("INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE", "LOOPBACK_INTERFACE", "VLAN_SUB_INTERFACE"):
        for key in config.get(table, {}):
            if "|" not in key:
                continue
            try:
                protected_network = ipaddress.ip_interface(key.split("|", 1)[1]).network
            except ValueError:
                raise DeploymentError("Unrecognized protected L3 interface address") from None
            _require(not any(network.version == protected_network.version and network.overlaps(protected_network)
                             for network in networks), "Scenario addressing overlaps a protected logical interface")
    _require(not any(key.split("|", 1)[0] == vlan for key in config.get("VLAN_INTERFACE", {})),
             "Access VLAN has a protected logical interface")
    _require(not any(key.split("|", 1)[0] == vlan for key in config.get("VLAN_MEMBER", {})),
             "Access VLAN has protected members")
    existing = config.get("VLAN", {}).get(vlan, {})
    _require(not existing.get("members"), "Access VLAN has protected declared members")
    if existing:
        _require(_number(existing.get("vlanid")) == manifest["settings"]["access_vlan"],
                 "Access VLAN identity conflicts with the baseline")
    for table, rows in config.items():
        if table != "VLAN":
            _require(not _references(rows, {vlan}), "Access VLAN has protected dependencies in " + table)
    _insert(config, "VLAN", vlan, existing or {"vlanid": str(manifest["settings"]["access_vlan"])})
    next_hops, interfaces = [], []
    for endpoint in manifest["endpoints"]:
        port = endpoint["dut_port"]
        address = endpoint["dut_address"]
        peer = str(ipaddress.ip_interface(endpoint["ptf_address"]).ip)
        if endpoint["role"] == "routed":
            interface = port
            _insert(config, "INTERFACE", port, {})
            _insert(config, "INTERFACE", port + "|" + address, {})
            next_hops.append(peer)
            interfaces.append(port)
        else:
            interface = vlan
            _insert(config, "VLAN_INTERFACE", vlan, {})
            _insert(config, "VLAN_INTERFACE", vlan + "|" + address, {})
            _insert(config, "VLAN_MEMBER", vlan + "|" + port, {"tagging_mode": "untagged"})
        _insert(config, "STATIC_ROUTE", peer + "/32", {"nexthop": peer, "ifname": interface})
    _require(len(interfaces) == manifest["requirements"]["routed_ports"],
             "Routed port count disagrees with frozen settings")
    _insert(config, "STATIC_ROUTE", "0.0.0.0/0", {"nexthop": ",".join(next_hops), "ifname": ",".join(interfaces)})


def _render_base(snapshot, manifest, baselines, canonical_ports, transport_uplinks):
    """Validate the frozen witness and render non-template add state once."""
    _require(isinstance(snapshot, dict) and isinstance(manifest, dict),
             "Snapshot and frozen manifest must be dictionaries")
    validate_manifest(manifest, snapshot, manifest.get("settings"))
    manifest = _json_copy(manifest)
    dut = snapshot["dut"]
    selected = {entry["device"] for entry in manifest["layout"]}
    _require(all(isinstance(value, dict) and set(value) == selected
                 for value in (baselines, canonical_ports)),
             "Baselines and canonical PORTs must cover exactly the selected devices")
    normalized, ownership, configs, managed = {}, {}, {}, {}
    by_device = {device["name"]: device for device in manifest["devices"]}
    for device in sorted(selected):
        _record(baselines[device], ("running", "startup"))
        running = _config(baselines[device]["running"])
        startup = _startup(baselines[device]["startup"])
        metadata = running.get("DEVICE_METADATA", {}).get("localhost")
        _require(isinstance(metadata, dict) and metadata.get("hwsku") == by_device[device]["base_hwsku"],
                 "Baseline DEVICE_METADATA must identify the verified base HWSKU")
        _require(metadata.get("hostname", device) == device
                 and metadata.get("platform", by_device[device]["platform"]) == by_device[device]["platform"],
                 "Baseline device identity disagrees with recorded source")
        normalized[device] = {"running": running, "startup": startup}
        entries = [entry for entry in manifest["layout"] if entry["device"] == device]
        expected = {port["name"]: port for entry in entries for port in entry["expansion"]["ports"]}
        _require(isinstance(canonical_ports[device], dict) and set(canonical_ports[device]) == set(expected),
                 "Canonical PORT rows must exactly cover realized expansion children")
        for name, port in expected.items():
            row = canonical_ports[device][name]
            _require(isinstance(row, dict), "Canonical PORT row is not a dictionary")
            _require(row.get("name", name) == name and row.get("alias") == port["alias"]
                     and _number(row.get("index")) == port["index"] and _lanes(row) == port["lanes"]
                     and _number(row.get("speed")) == port["speed"]
                     and row.get("fec") == port["fec"] and row.get("autoneg") == port["autoneg"],
                     "Canonical PORT row disagrees with frozen manifest: " + name)
        old_ports = _managed_ports(running, entries)
        managed[device] = old_ports
        protected = set(running["PORT"]) - old_ports
        aliases = {row["alias"] for row in canonical_ports[device].values()}
        _require(not aliases & {row.get("alias") for name, row in running["PORT"].items() if name in protected},
                 "Canonical alias collides with protected PORT")
        _require(not set(expected) & protected, "Canonical name collides with protected PORT")
        identities = (old_ports | set(expected) | aliases
                      | {_text(running["PORT"][name].get("alias", name)) for name in old_ports})
        reserved = {"Vlan{}".format(endpoint["transport"]["vlan"]) for endpoint in manifest["endpoints"]
                    if endpoint["leaf"] == device}
        candidate = _strip_ports(running, old_ports, identities, reserved)
        inactive = {port for entry in entries for port in entry["inactive_ports"]}
        candidate["PORT"].update(copy.deepcopy(canonical_ports[device]))
        for name in expected:
            candidate["PORT"][name]["admin_status"] = "down" if name in inactive else "up"
        candidate["DEVICE_METADATA"]["localhost"]["hwsku"] = by_device[device]["realized_hwsku"]
        configs[device] = candidate
        ownership[device] = {
            "cages": sorted(entry["cage"] for entry in entries), "old_ports": sorted(old_ports),
            "ports": sorted(expected), "protected_ports": sorted(protected),
            "inactive_ports": sorted(inactive), "transport_vlans": sorted(reserved),
        }
    transport = _transport(manifest, normalized, managed, transport_uplinks)
    for item in transport:
        config, vlan = configs[item["leaf"]], "Vlan{}".format(item["vlan"])
        for uplink in item["uplink_ports"]:
            key = vlan + "|" + uplink
            _insert(config, "VLAN_MEMBER", key, config.get("VLAN_MEMBER", {}).get(key, {"tagging_mode": "tagged"}))
        _insert(config, "VLAN_MEMBER", vlan + "|" + item["leaf_port"], {"tagging_mode": "untagged"})
        if "members" in config["VLAN"][vlan]:
            members = set(config["VLAN"][vlan]["members"]) | set(item["uplink_ports"]) | {item["leaf_port"]}
            config["VLAN"][vlan]["members"] = sorted(members)
    cable_maps = {device: {} for device in selected}
    for endpoint in manifest["port_bindings"]:
        cable_maps[dut][endpoint["dut_port"]] = endpoint["cable"]
        cable_maps[endpoint["leaf"]][endpoint["leaf_port"]] = endpoint["cable"]
        _insert(configs[dut], "DEVICE_NEIGHBOR", endpoint["dut_port"],
                {"name": endpoint["leaf"], "port": endpoint["leaf_port"]})
        _insert(configs[endpoint["leaf"]], "DEVICE_NEIGHBOR", endpoint["leaf_port"],
                {"name": dut, "port": endpoint["dut_port"]})
    return manifest, dut, normalized, configs, ownership, transport, cable_maps


def _context_cables(config, baseline, old_ports, cables):
    owners = {
        port: (set(_lanes(baseline["PORT"][port])),
               [group for group, row in baseline.get("CABLE_LENGTH", {}).items() if port in row])
        for port in old_ports
    }
    for port, cable in cables.items():
        lanes = set(_lanes(config["PORT"][port]))
        matches = [groups for previous_lanes, groups in owners.values() if previous_lanes & lanes]
        _require(matches and all(len(groups) == 1 for groups in matches),
                 "Missing or ambiguous baseline CABLE_LENGTH group for " + port)
        groups = {match[0] for match in matches}
        _require(len(groups) == 1, "Ambiguous baseline CABLE_LENGTH groups across candidate lanes: " + port)
        group = next(iter(groups))
        config.setdefault("CABLE_LENGTH", {}).setdefault(group, {})[port] = cable


def render_contexts(snapshot, manifest, baselines, canonical_ports, transport_uplinks=None):
    """Return full add/DUT-deploy template inputs, never fabricated buffer policy.

    The baseline's CABLE_LENGTH table must give every old port intersecting an
    active candidate exactly one group, shared across that candidate's lanes.
    Lengths come only from the frozen manifest. Inactive children have no cable
    entry. All other policy inputs come unchanged from the supplied baseline;
    installed-template-specific prerequisites remain the caller's responsibility.
    """
    manifest, dut, normalized, configs, ownership, unused_transport, cables = _render_base(
        snapshot, manifest, baselines, canonical_ports, transport_uplinks)
    for device, config in configs.items():
        _context_cables(config, normalized[device]["running"], ownership[device]["old_ports"], cables[device])
    contexts = {device: {"add": config} for device, config in configs.items()}
    deployed = copy.deepcopy(configs[dut])
    _forwarding(deployed, manifest)
    contexts[dut]["deploy"] = deployed
    for stages in contexts.values():
        for context in stages.values():
            _config(context)
    return _json_copy(contexts)


def render_bundle(snapshot, manifest, baselines, canonical_ports, template_tables, transport_uplinks=None):
    """Render complete candidates, failing closed on missing policy or ambiguous ownership."""
    manifest, dut, normalized, configs, ownership, transport, cable_maps = _render_base(
        snapshot, manifest, baselines, canonical_ports, transport_uplinks)
    selected = set(configs)
    _require(isinstance(template_tables, dict) and set(template_tables) == selected,
             "Installed templates must cover exactly the selected devices")
    for device in sorted(selected):
        _record(template_tables[device], ("add", "deploy") if device == dut else ("add",), ("deploy",))
        if device != dut and "deploy" in template_tables[device]:
            _require(template_tables[device]["deploy"] == template_tables[device]["add"],
                     "Deploy cannot change leaf buffer/QoS configuration")
        _apply_templates(configs[device], normalized[device]["running"], template_tables[device]["add"],
                         set(ownership[device]["ports"]), cable_maps[device], ownership[device]["protected_ports"])
    deployed = copy.deepcopy(configs[dut])
    _apply_templates(deployed, normalized[dut]["running"], template_tables[dut]["deploy"],
                     set(ownership[dut]["ports"]), cable_maps[dut], ownership[dut]["protected_ports"])
    _forwarding(deployed, manifest)
    _require(configs[dut]["PORT"] == deployed["PORT"]
             and configs[dut].get("CABLE_LENGTH") == deployed.get("CABLE_LENGTH"),
             "Deploy attempted to change frozen PORT layout or cables")
    for candidate in list(configs.values()) + [deployed]:
        _config(candidate)
    bundle = {
        "schema_version": 1, "scenario_id": manifest["scenario_id"], "dut": dut,
        "manifest": manifest, "baselines": normalized, "add_configs": configs,
        "deploy_configs": {dut: deployed}, "ownership": ownership, "transport": transport,
        "digests": {
            "baseline": {device: {kind: _digest(value) for kind, value in baseline.items()}
                         for device, baseline in normalized.items()},
            "add": {device: _digest(config) for device, config in configs.items()},
            "deploy": {dut: _digest(deployed)},
            "layout": manifest["integrity"]["layout_sha256"], "mapping": manifest["integrity"]["mapping_sha256"],
            "inputs": _digest({
                "snapshot": snapshot, "manifest": manifest, "baselines": normalized,
                "canonical_ports": canonical_ports, "template_tables": template_tables,
                "transport_uplinks": transport_uplinks,
            }),
        },
    }
    bundle["bundle_sha256"] = _digest(bundle)
    return _json_copy(bundle)


def _windows_security(path, create=False):
    """Create/check an owner-and-SYSTEM-only DACL, without starting a console."""
    import ctypes.wintypes as wintypes

    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(pointer),
        pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)]
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [pointer]
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, pointer]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    security = owner = dacl = None

    def sid_text(sid):
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(text)

    try:
        length = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not advapi.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = sid_text(ctypes.cast(buffer, ctypes.POINTER(pointer))[0])
        if create:
            descriptor = pointer()
            sddl = "D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)".format(user)
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, ctypes.byref(descriptor), None):
                raise ctypes.WinError(ctypes.get_last_error())

            class SecurityAttributes(ctypes.Structure):
                _fields_ = [("length", wintypes.DWORD), ("descriptor", pointer), ("inherit", wintypes.BOOL)]

            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            try:
                if not kernel.CreateDirectoryW(path, ctypes.byref(attributes)):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel.LocalFree(descriptor)
        security, owner, dacl = pointer(), pointer(), pointer()
        result = advapi.GetNamedSecurityInfoW(
            path, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(security))
        if result:
            raise ctypes.WinError(result)
        _require(owner and sid_text(owner) == user and dacl, "Workspace/file owner or DACL is not private")
        ace_count = ctypes.c_ushort.from_address(dacl.value + 4).value
        _require(ace_count > 0, "Empty private workspace DACL")
        for number in range(ace_count):
            ace = pointer()
            if not advapi.GetAce(dacl, number, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            _require(ctypes.c_ubyte.from_address(ace.value).value == 0
                     and sid_text(pointer(ace.value + 8)) in {user, "S-1-5-18"},
                     "Workspace/file grants access outside its owner and SYSTEM")
    finally:
        if security:
            kernel.LocalFree(security)
        kernel.CloseHandle(token)


def _private(path, directory=False, create=False):
    if create:
        if os.name == "nt":
            _windows_security(path, create=True)
        else:
            os.mkdir(path, 0o700)
    info = os.lstat(path)
    _require(not stat.S_ISLNK(info.st_mode)
             and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
             "Workspace entries must be ordinary private files/directories")
    if os.name == "nt":
        _require(not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT, "Workspace reparse points are unsafe")
        _windows_security(path)
    else:
        _require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "Workspace/file permissions are not private")


def _atomic_json(path, value):
    parent = os.path.dirname(path)
    _private(parent, directory=True)
    pending = os.path.join(parent, ".pending-" + uuid.uuid4().hex)
    descriptor = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((canonical_json(value) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        _private(pending)
        if os.name == "nt":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
            if not kernel.MoveFileExW(pending, path, 0x1 | 0x8):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(pending, path)
            descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def _read_json(path):
    _private(path)
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except (ValueError, UnicodeError):
        raise ConflictError("Corrupt durable JSON artifact") from None


def read_artifact(reference):
    """Read and authenticate an operation artifact, returning its native snapshot."""
    _record(reference, ("path", "sha256", "kind"))
    envelope = _read_json(reference["path"])
    _require(isinstance(envelope, dict) and set(envelope) == {"kind", "value"}
             and envelope["kind"] == reference["kind"] and _digest(envelope) == reference["sha256"],
             "Operation artifact integrity mismatch")
    return _native(reference["kind"], envelope["value"])


class DeploymentTransaction:
    """One frozen scenario's durable attempts; reuse its workspace to recover."""

    def __init__(self, workspace, bundle, backend, host_resources=None, aliases=None):
        bundle = _json_copy(bundle)
        digest = bundle.pop("bundle_sha256", None)
        _require(digest == _digest(bundle), "Bundle integrity mismatch")
        bundle["bundle_sha256"] = digest
        _require(bundle.get("schema_version") == 1 and bundle.get("scenario_id") == bundle["manifest"]["scenario_id"],
                 "Unknown bundle schema or scenario identity")
        _require(set(bundle["deploy_configs"]) == {bundle["dut"]}, "Deploy must target only the DUT")
        _require(isinstance(host_resources, dict) and host_resources,
                 "Owned host/PTF baseline and candidate snapshots required")
        _require(aliases is None or isinstance(aliases, dict), "Alias resources must be a dictionary")
        _require(callable(getattr(backend, "perform", None)) and callable(getattr(backend, "verify", None)),
                 "Backend must implement perform and independent verify")
        self.bundle, self.backend = bundle, backend
        self.workspace = os.path.abspath(os.fspath(workspace))
        self.journal_path = os.path.join(self.workspace, "journal.json")
        self.artifact_dir = os.path.join(self.workspace, "artifacts")
        self.hosts, self.aliases = _json_copy(host_resources), _json_copy(aliases or {})
        self._validate_resources()
        if not os.path.lexists(self.workspace):
            _private(self.workspace, directory=True, create=True)
        else:
            _private(self.workspace, directory=True)
        with self._lock():
            if not os.path.lexists(self.artifact_dir):
                _private(self.artifact_dir, directory=True, create=True)
            else:
                _private(self.artifact_dir, directory=True)
            identity = _digest({"bundle": bundle, "hosts": self.hosts, "aliases": self.aliases})
            self.identity = identity
            if os.path.lexists(self.journal_path):
                self.journal = self._load()
                self._authenticate_references()
            else:
                self.journal = {
                    "schema_version": 1, "scenario_id": bundle["scenario_id"], "identity_sha256": identity,
                    "bundle": self._artifact("bundle", bundle), "state": "PREPARED", "operations": [],
                    "resources": self._resources(), "last_error": None, "attempt": 0, "previous_attempts": [],
                }
                self._save()

    def _validate_resources(self):
        for target, resource in self.hosts.items():
            _text(target)
            _record(resource, ("baseline", "candidate"))
            _require(isinstance(resource["candidate"], dict), "Host candidate snapshot must be explicit")
            _wire("host", resource["baseline"])
        required = {
            (device["name"], device["realized_hwsku"]) for device in self.bundle["manifest"]["devices"]
            if device["name"] in self.bundle["add_configs"] and device["realized_hwsku"] != device["base_hwsku"]
        }
        supplied = set()
        for target, resource in self.aliases.items():
            _text(target)
            _record(resource, ("baseline", "candidate", "device", "name"))
            pair = (resource["device"], resource["name"])
            _require(pair in required and pair not in supplied,
                     "Alias identity is not a unique selected realized HWSKU")
            supplied.add(pair)
            _require(isinstance(resource["candidate"], dict) and resource["candidate"].get("name") == resource["name"],
                     "Alias candidate must identify its exact name")
            _require(resource["baseline"] is None or resource["baseline"] == resource["candidate"],
                     "An existing alias cannot be overwritten by this scenario")
            if resource["baseline"] is None:
                for baseline in self.bundle["baselines"].values():
                    startup = json.loads(base64.b64decode(baseline["startup"]["data_b64"]).decode("utf-8"))
                    _require(not _references([baseline["running"], startup], {resource["name"]}),
                             "A supposedly new alias is referenced by an original running/startup snapshot")
        _require(required == supplied, "Missing baseline/candidate snapshots for selected HWSKU aliases")

    @classmethod
    def open(cls, workspace, backend):
        """Recover the immutable inputs and owned resources from the private journal."""
        workspace = os.path.abspath(os.fspath(workspace))
        _private(workspace, directory=True)
        journal = _read_json(os.path.join(workspace, "journal.json"))
        digest = journal.pop("journal_sha256", None)
        if journal.get("schema_version") != 1 or digest != _digest(journal):
            raise ConflictError("Journal integrity/schema mismatch")
        hosts, aliases = {}, {}
        artifact_dir = os.path.join(workspace, "artifacts")
        _private(artifact_dir, directory=True)

        def artifact(reference):
            if os.path.dirname(os.path.abspath(reference["path"])) != artifact_dir:
                raise ConflictError("Journal artifact escaped the private workspace")
            return read_artifact(reference)

        bundle = artifact(journal["bundle"])
        for resource in journal["resources"]:
            if resource["kind"] not in {"host", "alias"}:
                continue
            record = {"baseline": artifact(resource["baseline"]), "candidate": artifact(resource["add"])}
            if resource["kind"] == "alias":
                record.update({field: resource["context"][field] for field in ("device", "name")})
                aliases[resource["target"]] = record
            else:
                hosts[resource["target"]] = record
        return cls(workspace, bundle, backend, hosts, aliases)

    @contextmanager
    def _lock(self):
        _private(self.workspace, directory=True)
        path = os.path.join(self.workspace, ".lock")
        if os.path.lexists(path):
            _private(path)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            _private(path)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise ConflictError("Workspace is in use; no lock was stolen") from None
            else:
                import fcntl
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise ConflictError("Workspace is in use; no lock was stolen") from None
            locked = True
            yield
        finally:
            if locked and os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            os.close(descriptor)

    def _artifact(self, kind, value):
        envelope = {"kind": kind, "value": value}
        digest = _digest(envelope)
        reference = {"path": os.path.join(self.artifact_dir, digest + ".json"), "sha256": digest, "kind": kind}
        if os.path.lexists(reference["path"]):
            _require(_read_json(reference["path"]) == envelope, "Conflicting immutable artifact")
        else:
            _atomic_json(reference["path"], envelope)
        return reference

    def _resources(self):
        resources = []
        for target, record in sorted(self.aliases.items()):
            resources.append(self._resource("alias", target, record["baseline"], record["candidate"],
                                            {"device": record["device"], "name": record["name"]}))
        for target, record in sorted(self.hosts.items()):
            resources.append(self._resource("host", target, record["baseline"], record["candidate"],
                                            {"transport": self.bundle["transport"]}))
        devices = sorted(self.bundle["add_configs"], key=lambda device: (device == self.bundle["dut"], device))
        for device in devices:
            baseline = self.bundle["baselines"][device]
            config = self.bundle["add_configs"][device]
            resources.append(self._resource("running", device, baseline["running"], config))
            startup = {"data_b64": base64.b64encode((canonical_json(config) + "\n").encode("utf-8")).decode("ascii"),
                       "metadata": baseline["startup"]["metadata"]}
            resources.append(self._resource("startup", device, baseline["startup"], startup))
        return resources

    def _resource(self, kind, target, baseline, candidate, context=None):
        return {
            "key": _digest([kind, target]), "kind": kind, "target": target,
            "baseline": self._artifact(kind, baseline), "add": self._artifact(kind, candidate),
            "context": dict(context or {}, scenario_id=self.bundle["scenario_id"]),
        }

    def _save(self):
        value = copy.deepcopy(self.journal)
        value["journal_sha256"] = _digest(value)
        _atomic_json(self.journal_path, value)

    def _load(self):
        if self.identity != _digest({"bundle": self.bundle, "hosts": self.hosts, "aliases": self.aliases}):
            raise ConflictError("Frozen transaction inputs changed")
        value = _read_json(self.journal_path)
        digest = value.pop("journal_sha256", None)
        if value.get("schema_version") != 1 or digest != _digest(value):
            raise ConflictError("Journal integrity/schema mismatch")
        if value.get("identity_sha256") != self.identity:
            raise ConflictError("Workspace belongs to conflicting scenario or changed inputs")
        attempt, previous = value.get("attempt", 0), value.get("previous_attempts", [])
        if (type(attempt) is not int or attempt < 0 or not isinstance(previous, list)
                or len(previous) != attempt):
            raise ConflictError("Invalid transaction attempt history")
        for index, closed in enumerate(previous):
            if (not isinstance(closed, dict) or type(closed.get("attempt")) is not int
                    or closed["attempt"] != index
                    or closed.get("restoration_verified") is not True
                    or not isinstance(closed.get("last_error"), dict)):
                raise ConflictError("A previous attempt lacks its verified failure/recovery record")
        if value["last_error"] is not None and not isinstance(value["last_error"], dict):
            raise ConflictError("Invalid recorded transaction failure")
        for operation in value["operations"]:
            number = operation.get("attempt", 0)
            if type(number) is not int or not 0 <= number <= attempt:
                raise ConflictError("An operation belongs to an invalid attempt")
        value.update(attempt=attempt, previous_attempts=previous)
        return value

    def _authenticate_references(self):
        _private(self.artifact_dir, directory=True)
        refs = [self.journal["bundle"]]
        for resource in self.journal["resources"]:
            refs.extend([resource["baseline"], resource["add"]])
        for op in self.journal["operations"]:
            refs.extend([op["before"], op["after"]])
        for reference in refs:
            if os.path.dirname(os.path.abspath(reference["path"])) != self.artifact_dir:
                raise ConflictError("Journal artifact escaped the private workspace")
            read_artifact(reference)

    def _operation(self, resource, phase, before, after, suffix=""):
        attempt = self.journal["attempt"]
        namespace = self.bundle["scenario_id"] + (":attempt-" + str(attempt) if attempt else "")
        return {
            "id": "{}:{}:{}{}".format(namespace, phase, resource["key"], suffix), "attempt": attempt,
            "phase": phase, "kind": resource["kind"], "target": resource["target"], "resource": resource["key"],
            "before": copy.deepcopy(before), "after": copy.deepcopy(after),
            "context": copy.deepcopy(resource["context"]),
        }

    def _observe(self, op):
        result = self.backend.verify(copy.deepcopy(op))
        _require(isinstance(result, dict) and result.get("operation_id") == op["id"]
                 and result.get("target") == op["target"] and result.get("kind") == op["kind"]
                 and "value" in result, "Backend did not provide identity-bound independent readback")
        value = _wire(op["kind"], result["value"])
        return value, _digest({"kind": op["kind"], "value": value}), result.get("owned_by")

    def _intent(self, op):
        record = dict(op, status="INTENT")
        self.journal["operations"].append(record)
        self._save()
        return record

    def _perform(self, record):
        self.backend.perform(copy.deepcopy(record))
        unused_value, digest, unused_owner = self._observe(record)
        if digest != record["after"]["sha256"]:
            raise ConflictError("Backend write was not verified: " + record["id"])
        record["status"], record["verified_sha256"] = "VERIFIED", digest
        self._save()

    def _deploy_ref(self, resource):
        config = self.bundle["deploy_configs"][self.bundle["dut"]]
        if resource["kind"] == "running":
            value = config
        else:
            value = {"data_b64": base64.b64encode((canonical_json(config) + "\n").encode("utf-8")).decode("ascii"),
                     "metadata": self.bundle["baselines"][resource["target"]]["startup"]["metadata"]}
        return self._artifact(resource["kind"], value)

    def _expected(self, resource):
        reference = resource["baseline"]
        for op in self._current_operations(resource["key"]):
            if op["status"] == "VERIFIED":
                reference = op["after"]
        return reference

    def _current_operations(self, resource=None):
        return [operation for operation in self.journal["operations"]
                if operation.get("attempt", 0) == self.journal["attempt"]
                and (resource is None or operation["resource"] == resource)]

    def _verify_all(self, originals=False, pending=False):
        for resource in self.journal["resources"]:
            expected = resource["baseline"] if originals else self._expected(resource)
            probe = self._operation(resource, "probe", expected, expected)
            unused_value, digest, unused_owner = self._observe(probe)
            permitted = {expected["sha256"]}
            records = self._current_operations(resource["key"])
            if pending and records and records[-1]["status"] == "INTENT":
                permitted.update([records[-1]["before"]["sha256"], records[-1]["after"]["sha256"]])
            if digest not in permitted:
                raise ConflictError("Live state drifted for {} {}".format(resource["kind"], resource["target"]))

    def _run_phase(self, phase):
        changed = False
        for resource in self.journal["resources"]:
            is_dut_config = resource["target"] == self.bundle["dut"] and resource["kind"] in {"running", "startup"}
            if phase == "deploy" and not is_dut_config:
                continue
            before = resource["baseline"] if phase == "add" else resource["add"]
            after = resource["add"] if phase == "add" else self._deploy_ref(resource)
            op = self._operation(resource, phase, before, after)
            previous = next((record for record in self._current_operations() if record["id"] == op["id"]), None)
            if previous is not None and previous["status"] == "VERIFIED":
                continue
            unused_value, digest, unused_owner = self._observe(op)
            if previous is not None and digest == after["sha256"]:
                previous["status"], previous["verified_sha256"] = "VERIFIED", digest
                self._save()
                changed = True
                continue
            if digest != before["sha256"]:
                raise ConflictError("Unexplained live state before " + op["id"])
            if before["sha256"] == after["sha256"]:
                continue
            record = previous if previous is not None else self._intent(op)
            self._perform(record)
            changed = True
        self._verify_all()
        return changed

    def _result(self, changed):
        return {"state": self.journal["state"], "scenario_id": self.bundle["scenario_id"],
                "changed": changed, "journal": self.journal_path, "attempt": self.journal["attempt"]}

    def _record_failure(self, phase, error, stage):
        if self.journal["last_error"] is None:
            self.journal["last_error"] = {
                "attempt": self.journal["attempt"], "stage": stage,
                "phase": {"add": "add-topo", "deploy": "deploy-mg"}.get(phase, phase),
                "type": type(error).__name__, "message": str(error),
            }
            self._save()
        return copy.deepcopy(self.journal["last_error"])

    def record_failure(self, phase, error, stage):
        """Retain the first causal failure before external readiness compensation."""
        with self._lock():
            self.journal = self._load()
            self._authenticate_references()
            if self.journal["state"] == "RESTORED" and self.journal["last_error"] is None:
                raise ConflictError("A completed teardown has no failed attempt to retry")
            return self._record_failure(phase, error, stage)

    def _verify_restored(self):
        try:
            self._verify_all(originals=True)
        except Exception as error:
            self.journal["state"] = "RESTORE_FAILED"
            self.journal["restore_errors"] = [{
                "kind": "verification", "type": type(error).__name__, "message": str(error)}]
            self._save()
            raise RestorationError(
                "Previously restored state has drifted; retain the journal: " + str(error)) from error

    def _phase(self, phase):
        with self._lock():
            self.journal = self._load()
            self._authenticate_references()
            state = self.journal["state"]
            repeated = ((phase == "add" and state in {"ADDED", "DEPLOYED"})
                        or (phase == "deploy" and state == "DEPLOYED"))
            allowed = {"PREPARED", "ADDING"} if phase == "add" else {"ADDED", "DEPLOYING"}
            retrying = phase == "add" and state == "RESTORED" and self.journal["last_error"] is not None
            if not repeated and state not in allowed and not retrying:
                raise ConflictError("Cannot {} a transaction in state {}".format(phase, state))
            if retrying:
                self._verify_restored()
                self.journal["previous_attempts"].append({
                    "attempt": self.journal["attempt"], "restoration_verified": True,
                    "last_error": copy.deepcopy(self.journal["last_error"]),
                })
                self.journal["attempt"] += 1
                self.journal["last_error"] = None
                self.journal["state"] = "ADDING"
                self._save()
            try:
                if not retrying:
                    self._verify_all(pending=state in {"ADDING", "DEPLOYING"})
                if repeated:
                    return self._result(False)
                self.journal["state"] = "ADDING" if phase == "add" else "DEPLOYING"
                self._save()
                changed = self._run_phase(phase)
                self.journal["state"] = "ADDED" if phase == "add" else "DEPLOYED"
                self._save()
                return self._result(changed)
            except Exception as error:
                self._record_failure(phase, error, "configuration-apply")
                try:
                    self._restore()
                except Exception as restore_error:
                    raise RestorationError(
                        "Deployment failed; restoration is incomplete; retain journal; "
                        "first failure {}: {}; restore: {}"
                        .format(type(error).__name__, error, restore_error)) from restore_error
                raise TransactionError("Deployment failed ({}: {}); original state verified restored".format(
                    type(error).__name__, error)) from error

    def add(self):
        """Apply aliases, owned host transport, leaf/DUT layouts and initial templates."""
        return self._phase("add")

    def deploy(self):
        """Apply only DUT forwarding and final buffers to the frozen add layout."""
        return self._phase("deploy")

    def _restore_resource(self, resource):
        expected = resource["baseline"]
        records = self._current_operations(resource["key"])
        probe = self._operation(resource, "probe", expected, expected)
        value, digest, owner = self._observe(probe)
        if digest == expected["sha256"]:
            if records and records[-1]["phase"] == "restore" and records[-1]["status"] == "INTENT":
                records[-1]["status"], records[-1]["verified_sha256"] = "VERIFIED", digest
                self._save()
                return True
            return False
        latest = records[-1] if records else None
        allowed = {latest["after"]["sha256"]} if latest else set()
        if latest and latest["status"] == "INTENT":
            allowed.add(latest["before"]["sha256"])
        partial_owner = latest and latest["status"] == "INTENT" and owner == latest["id"]
        if digest not in allowed and not partial_owner:
            raise ConflictError("Unexplained external drift blocks restoration of " + resource["target"])
        pending = next((record for record in reversed(records) if record["phase"] == "restore"
                        and record["status"] == "INTENT" and record["before"]["sha256"] == digest), None)
        if pending is None:
            before = self._artifact(resource["kind"], value)
            op = self._operation(resource, "restore", before, expected, ":" + str(len(records)))
            pending = self._intent(op)
        self._perform(pending)
        return True

    def _alias_barrier(self):
        for resource in self.journal["resources"]:
            if resource["kind"] not in {"running", "startup"}:
                continue
            baseline = resource["baseline"]
            probe = self._operation(resource, "probe", baseline, baseline)
            value, digest, unused_owner = self._observe(probe)
            if digest != baseline["sha256"]:
                raise ConflictError("Alias cleanup requires verified original running AND startup")
            if resource["kind"] == "startup":
                value = json.loads(base64.b64decode(value["data_b64"]).decode("utf-8"))
            for alias in self.aliases.values():
                if alias["baseline"] is None and _references(value, {alias["name"]}):
                    raise ConflictError("Restored configuration still references a scenario-created alias")

    def _restore(self):
        self.journal["state"] = "RESTORING"
        self._save()
        changed, errors = False, []
        resources = list(reversed(self.journal["resources"]))
        for resource in resources:
            if resource["kind"] == "alias":
                continue
            try:
                changed = self._restore_resource(resource) or changed
            except Exception as error:
                errors.append({"kind": resource["kind"], "target": resource["target"],
                               "type": type(error).__name__, "message": str(error)})
        if not errors:
            try:
                self._alias_barrier()
            except Exception as error:
                errors.append({"kind": "alias-barrier", "type": type(error).__name__, "message": str(error)})
        if not errors:
            for resource in resources:
                if resource["kind"] == "alias":
                    try:
                        changed = self._restore_resource(resource) or changed
                    except Exception as error:
                        errors.append({"kind": "alias", "target": resource["target"],
                                       "type": type(error).__name__, "message": str(error)})
        if not errors:
            try:
                self._verify_all(originals=True)
            except Exception as error:
                errors.append({"kind": "verification/alias", "type": type(error).__name__, "message": str(error)})
        if errors:
            self.journal["state"], self.journal["restore_errors"] = "RESTORE_FAILED", errors
            self._save()
            raise RestorationError("Restoration incomplete; snapshots and pending intents retained")
        self.journal["state"], self.journal["restore_errors"] = "RESTORED", []
        for record in self._current_operations():
            if record["phase"] != "restore":
                record["compensated"] = True
        self._save()
        return changed

    def remove(self):
        """Resume compensation, verify originals, and only then delete owned aliases."""
        with self._lock():
            self.journal = self._load()
            self._authenticate_references()
            if self.journal["state"] == "RESTORED":
                self._verify_restored()
                return self._result(False)
            return self._result(self._restore())

    def status(self):
        """Return a journal snapshot, not an assertion of live device health."""
        with self._lock():
            self.journal = self._load()
            return copy.deepcopy(self.journal)
