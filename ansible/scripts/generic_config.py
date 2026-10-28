#!/usr/bin/env python3
"""Render and validate a generic scenario using installed SONiC assets, without reloading."""

import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

from map_breakout_links import mode_components, selected_speeds


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_running():
    return json.loads(subprocess.check_output(["sonic-cfggen", "-d", "--print-data"], text=True))


def write_private(path, value):
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def numbers(value):
    result = set()
    for part in value.split(","):
        bounds = part.split("-")
        if len(bounds) not in (1, 2) or not all(bound.isdigit() for bound in bounds):
            raise ValueError("Unsupported queue/PG index expression: {}".format(value))
        start, end = int(bounds[0]), int(bounds[-1])
        if not 0 <= start <= end <= 7:
            raise ValueError("Queue/PG index must be between 0 and 7")
        result.update(range(start, end + 1))
    return result


def scoped_port(key):
    return key.split("|", 1)[0]


def parse_buffer_lookup(text):
    rows = []
    columns = None
    for line in text.splitlines():
        values = line.strip().lstrip("#").split()
        if "speed" in values and "cable" in values:
            columns = values
        elif line.strip() and not line.lstrip().startswith("#"):
            if columns is None or len(columns) != len(values):
                raise ValueError("Malformed installed buffer lookup")
            rows.append(dict(zip(columns, values)))
    return rows


def reconcile_neighbors(facts, layouts):
    """Validate frozen child connections and derive reciprocal physical neighbor entries."""
    hosts = {"dut": facts.get("hostname"), "peer": facts.get("peer_hostname")}
    if (any(not isinstance(host, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", host) is None
            for host in hosts.values()) or hosts["dut"] == hosts["peer"]):
        raise ValueError("Resolved connections require two distinct device identities")
    expected = {}
    for side in hosts:
        expected[side] = {}
        for choice in layouts[side].values():
            groups = mode_components(choice["mode"])
            speeds = selected_speeds(choice["mode"], choice["speed"])
            child_speeds = [speed for group, speed in zip(groups, speeds) for _ in range(group["count"])]
            if len(child_speeds) != len(choice["children"]):
                raise ValueError("Invalid {} child count in frozen breakout layout".format(side))
            for child, speed in zip(choice["children"], child_speeds):
                port = child["port"]
                if (port in expected[side] or re.fullmatch(r"Ethernet(?:0|[1-9]\d*)", port) is None
                        or type(child["speed"]) is not int or child["speed"] != speed):
                    raise ValueError("Invalid or duplicate {} child in frozen breakout layout".format(side))
                expected[side][port] = child
    neighbors = {side: {} for side in hosts}
    for link in facts["connections"]:
        if link.get("role") not in ("uplink", "downlink"):
            raise ValueError("Resolved child connection requires an explicit uplink/downlink role")
        for side, remote in (("dut", "peer"), ("peer", "dut")):
            child = link[side]
            port = child["port"]
            if port in neighbors[side]:
                raise ValueError("Duplicate resolved {} child connection: {}".format(side, port))
            if expected[side].get(port) != child:
                raise ValueError("Resolved {} child {} does not match frozen breakout layout; "
                                 "replan the scenario".format(side, port))
            neighbors[side][port] = {"name": hosts[remote], "port": link[remote]["port"]}
        if (link["dut"]["speed"] != link["peer"]["speed"]
                or str(link["buffer_case"]["speed"]) != str(link["dut"]["speed"])):
            raise ValueError("Resolved child connection has incompatible endpoint or buffer-case speeds")
        if not link["dut"]["atoms"] or tuple(link["dut"]["atoms"]) != tuple(link["peer"]["atoms"]):
            raise ValueError("Resolved DUT and peer children do not represent the same physical wiring channels")
    if any(not rows or set(rows) != set(expected[side]) for side, rows in neighbors.items()):
        raise ValueError("Resolved connections do not cover every frozen DUT and peer child")
    return neighbors


def remove_owned(config, owned):
    """Remove only understood port-scoped entries; reject unknown retired-port references later."""
    tables = ("INTERFACE", "DEVICE_NEIGHBOR", "PORT_QOS_MAP", "QUEUE", "BUFFER_PG",
              "BUFFER_QUEUE", "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST",
              "PFC_WD", "PORTCHANNEL_MEMBER", "VLAN_MEMBER")
    for table in tables:
        result = {}
        for key, value in config.get(table, {}).items():
            parts = key.split("|")
            if table in ("PORTCHANNEL_MEMBER", "VLAN_MEMBER"):
                if len(parts) != 2:
                    raise ValueError("Unsupported {} key {}".format(table, key))
                if parts[1] not in owned:
                    result[key] = value
            else:
                ports = [port for port in parts[0].split(",") if port not in owned]
                if ports:
                    result["|".join([",".join(ports)] + parts[1:])] = value
        if table in config:
            config[table] = result
    for values in config.get("CABLE_LENGTH", {}).values():
        for port in owned:
            values.pop(port, None)
    for acl in config.get("ACL_TABLE", {}).values():
        if "ports" in acl:
            ports = acl["ports"]
            if not isinstance(ports, list):
                raise ValueError("ACL_TABLE.ports must be a list for generic rendering")
            acl["ports"] = [port for port in ports if port not in owned]
    for row in config.get("VLAN", {}).values():
        if "members" in row:
            row["members"] = [port for port in row["members"] if port not in owned]


def retire_static_routes(config, affected):
    """Resolve route ownership against connected subnets before retiring their interfaces."""
    if not config.get("STATIC_ROUTE"):
        return
    connected = []
    for table in ("INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE",
                  "LOOPBACK_INTERFACE", "MGMT_INTERFACE", "VLAN_SUB_INTERFACE"):
        rows = config.get(table, {})
        default_vrf = "default"
        if (table == "MGMT_INTERFACE"
                and config.get("MGMT_VRF_CONFIG", {}).get("vrf_global", {}).get("mgmtVrfEnabled") == "true"):
            default_vrf = "mgmt"
        for key in rows:
            if "|" in key:
                interface, address = key.split("|")
                binding = rows.get(interface, {})
                if binding.get("vnet_name"):
                    continue
                vrf = binding.get("vrf_name", default_vrf)
                connected.append((vrf, ipaddress.ip_interface(address).network, interface))
    for prefix, row in list(config.get("STATIC_ROUTE", {}).items()):
        route_vrf = prefix.split("|")[0] if "|" in prefix else "default"
        fields = {}
        for field in ("ifname", "nexthop", "nexthop-vrf", "blackhole"):
            value = row.get(field, "")
            if not isinstance(value, str):
                raise ValueError("Static route next-hop fields must be strings")
            fields[field] = value.split(",") if value.strip() else None
        sizes = {len(values) for values in fields.values() if values is not None}
        if len(sizes) > 1:
            raise ValueError("Static route next-hop fields have different lengths")
        dependencies = []
        for index in range(next(iter(sizes), 0)):
            values = {field: entries[index] if entries is not None else "" for field, entries in fields.items()}
            owners = set()
            if values["blackhole"] == "true":
                pass
            elif values["ifname"]:
                owners.add(values["ifname"])
            elif values["nexthop"].startswith("PortChannel"):
                owners.add(values["nexthop"])
            elif values["nexthop"]:
                nexthop = ipaddress.ip_address(values["nexthop"])
                vrf = values["nexthop-vrf"] or route_vrf
                owners = {interface for context, network, interface in connected
                          if context == vrf and nexthop in network}
                if owners.intersection(affected) and len(owners) > 1:
                    raise ValueError("Cannot change a static route with ambiguous next-hop interfaces: {}".format(
                        prefix))
            dependencies.append(owners)
        if any(owners.intersection(affected) for owners in dependencies):
            if any(not owners or not owners.issubset(affected) for owners in dependencies):
                raise ValueError(
                    "Cannot change a static route shared with protected interfaces or unresolved next hops: {}".format(
                        prefix))
            del config["STATIC_ROUTE"][prefix]


def retire_logical_interfaces(config, owned):
    affected = set(owned)
    for channel in list(config.get("PORTCHANNEL", {})):
        members = {key.split("|")[1] for key in config.get("PORTCHANNEL_MEMBER", {})
                   if key.split("|")[0] == channel}
        if members.intersection(owned):
            if not members.issubset(owned):
                raise ValueError("Cannot change a PortChannel shared with protected ports")
            affected.add(channel)
            del config["PORTCHANNEL"][channel]
    for vlan in list(config.get("VLAN", {})):
        members = {key.split("|")[1] for key in config.get("VLAN_MEMBER", {})
                   if key.split("|")[0] == vlan}
        members.update(config["VLAN"][vlan].get("members", []))
        if members and members.issubset(affected):
            affected.add(vlan)
            del config["VLAN"][vlan]
            config.get("DHCP_RELAY", {}).pop(vlan, None)
    retire_static_routes(config, affected)
    addresses = set()
    for table in ("INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE"):
        for key in list(config.get(table, {})):
            if scoped_port(key) in affected:
                if "|" in key:
                    addresses.add(str(ipaddress.ip_interface(key.split("|")[1]).ip))
                del config[table][key]
    for table in ("BGP_NEIGHBOR", "BGP_INTERNAL_NEIGHBOR", "BGP_VOQ_CHASSIS_NEIGHBOR"):
        for key, row in list(config.get(table, {}).items()):
            if row.get("local_addr") in addresses:
                del config[table][key]
    for key in list(config.get("PORTCHANNEL_MEMBER", {})):
        if key.split("|")[0] in affected:
            del config["PORTCHANNEL_MEMBER"][key]
    for key in list(config.get("VLAN_MEMBER", {})):
        if set(key.split("|")).intersection(affected):
            del config["VLAN_MEMBER"][key]
    return affected - owned


def validate_references(config, retired=()):
    ports = set(config["PORT"])
    for table in ("PORT_QOS_MAP", "QUEUE", "BUFFER_PG", "BUFFER_QUEUE", "PFC_WD",
                  "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST"):
        for key in config.get(table, {}):
            if table == "PFC_WD" and key == "GLOBAL":
                continue
            for port in scoped_port(key).split(","):
                if port not in ports:
                    raise ValueError("{} references absent port {}".format(table, port))
    for table in ("VLAN_MEMBER", "PORTCHANNEL_MEMBER"):
        for key in config.get(table, {}):
            parent, member = key.split("|")
            if member not in ports and member not in config.get("PORTCHANNEL", {}):
                raise ValueError("{} references absent member {}".format(table, member))
            if parent not in config.get("VLAN" if table == "VLAN_MEMBER" else "PORTCHANNEL", {}):
                raise ValueError("{} references absent parent {}".format(table, parent))
    for table in ("BUFFER_PG", "BUFFER_QUEUE"):
        for row in config.get(table, {}).values():
            if row["profile"] not in config.get("BUFFER_PROFILE", {}):
                raise ValueError("{} references absent buffer profile".format(table))
    for row in config.get("BUFFER_PROFILE", {}).values():
        if row.get("pool") not in config.get("BUFFER_POOL", {}):
            raise ValueError("BUFFER_PROFILE references absent pool")
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?:{})(?![A-Za-z0-9_])".format(
        "|".join(re.escape(port) for port in retired))) if retired else None
    references = dict(config)
    # Descriptions are free text and may name remote interfaces, not local bindings.
    references["PORT"] = {
        port: {field: value for field, value in row.items() if field != "description"}
        for port, row in config["PORT"].items()}
    if "DEVICE_NEIGHBOR" in references:
        # Remote interface names belong to another device, not the retired local namespace.
        references["DEVICE_NEIGHBOR"] = list(references["DEVICE_NEIGHBOR"])
    if pattern:
        def reference_locations(value, path):
            if isinstance(value, dict):
                for index, (key, row) in enumerate(value.items()):
                    match = pattern.search(json.dumps(key))
                    if match:
                        yield "{}[key #{}] references {}".format(path, index, match.group())
                        location = "{}[entry #{}]".format(path, index)
                    else:
                        location = "{}[{}]".format(path, json.dumps(key))
                    yield from reference_locations(row, location)
            elif isinstance(value, list):
                for index, row in enumerate(value):
                    yield from reference_locations(row, "{}[{}]".format(path, index))
            else:
                match = pattern.search(json.dumps(value))
                if match:
                    yield "{} (value references {})".format(path, match.group())

        locations = []
        for location in reference_locations(references, "CONFIG_DB"):
            locations.append(location)
            if len(locations) == 8:
                break
        if locations:
            raise ValueError(
                "Unsupported configuration still references a retired port: {}; explicit migration is required. "
                "Showing at most 8 locations, not field values.".format("; ".join(locations)))


def forwarding_cleanup_ports(base, platform, layouts, cages):
    """Resolve frozen fixed-breakout cages without treating them as replacement PORTs."""
    if not isinstance(cages, dict):
        raise ValueError("DUT forwarding cleanup must map cages to frozen lanes")
    ports = set()
    for cage, frozen in cages.items():
        if (cage in layouts or not isinstance(frozen, list) or not frozen
                or any(type(lane) is not int for lane in frozen) or len(set(frozen)) != len(frozen)):
            raise ValueError("DUT forwarding cleanup must use unselected cages with valid frozen lanes")
        installed = platform["interfaces"].get(cage, {}).get("lanes", "")
        if installed.split(",") != list(map(str, frozen)):
            raise ValueError("DUT forwarding cleanup cage lanes differ from installed platform")
        lanes = set(map(str, frozen))
        current = {name for name, row in base["PORT"].items() if lanes.intersection(row["lanes"].split(","))}
        if not current or any(not set(base["PORT"][name]["lanes"].split(",")).issubset(lanes) for name in current):
            raise ValueError("DUT forwarding cleanup cage is absent or shares another running port's lanes")
        ports.update(current)
    return ports


def realize_ports(base, platform, layouts, canonical):
    """Resolve canonical PORT entries without rendering or retiring dependent configuration."""
    owned = set()
    selected = {}
    for cage, choice in layouts.items():
        lanes = set(platform["interfaces"][cage]["lanes"].split(","))
        old = {name for name, row in base["PORT"].items() if lanes.intersection(row["lanes"].split(","))}
        if not old:
            raise ValueError("Selected cage {} is absent from running PORT".format(cage))
        if any(not set(base["PORT"][name]["lanes"].split(",")).issubset(lanes) for name in old):
            raise ValueError("Selected cage intersects another running port's lanes")
        owned.update(old)
        parents = [base["PORT"][name] for name in sorted(old)]
        common = {key: value for key, value in parents[0].items()
                  if key not in {"alias", "lanes", "speed", "index", "subport", "fec", "autoneg", "link_training"}
                  and all(row.get(key) == value for row in parents)}
        children = canonical(cage, choice, platform["interfaces"][cage])
        if set(children) != {child["port"] for child in choice["children"]}:
            raise ValueError("Installed canonical breakout parser disagrees with planned child names")
        for child in choice["children"]:
            row = children[child["port"]]
            if (row["lanes"].split(",") != list(map(str, child["lanes"]))
                    or row["alias"] != child["alias"]
                    or int(row["speed"]) != child.get("speed", choice["speed"])):
                raise ValueError("Installed canonical breakout parser disagrees with planned lanes/alias/speed")
            selected[child["port"]] = dict(common, **row, admin_status="up")
            selected[child["port"]]["adv_speeds"] = [str(child.get("speed", choice["speed"]))]
    if set(selected).intersection(set(base["PORT"]) - owned):
        raise ValueError("Selected child name conflicts with a protected port")
    return owned, selected


def build_ports(base, platform, layouts, canonical, exclude_managed_acls=False, forwarding_cleanup=()):
    if not isinstance(exclude_managed_acls, bool):
        raise ValueError("exclude_managed_acls must be a boolean")
    config = deepcopy(base)
    config.pop("BREAKOUT_CFG", None)
    owned, selected = realize_ports(base, platform, layouts, canonical)
    acl_members = {}
    channels = {port: {key.split("|")[0] for key in base.get("PORTCHANNEL_MEMBER", {})
                       if key.split("|")[1] == port} for port in owned}
    for name, acl in base.get("ACL_TABLE", {}).items():
        if name not in {"DATAACL", "EVERFLOW"} or "ports" not in acl:
            continue
        if exclude_managed_acls:
            continue
        if not isinstance(acl["ports"], list):
            raise ValueError("ACL_TABLE.ports must be a list for generic rendering")
        acl_members[name] = set(acl["ports"])
    inherited_acls = {}
    for port, row in selected.items():
        lanes = set(row["lanes"].split(","))
        parents = [name for name in owned if lanes.intersection(base["PORT"][name]["lanes"].split(","))]
        memberships = {
            parent: frozenset(name for name, members in acl_members.items()
                              if parent in members or channels[parent].intersection(members))
            for parent in sorted(parents)}
        if len(set(memberships.values())) != 1:
            details = "; ".join("{}=[{}]".format(parent, ", ".join(sorted(names)) or "none")
                                for parent, names in memberships.items())
            raise ValueError("Overlapping old ports disagree on DATAACL/EVERFLOW membership for {}: {}. "
                             "Explicit ACL migration is required; bindings were not broadened or dropped.".format(
                                 port, details or "no overlapping old ports"))
        inherited_acls[port] = next(iter(memberships.values()))
    cleanup = set(forwarding_cleanup)
    if not cleanup.issubset(base["PORT"]) or cleanup.intersection(owned):
        raise ValueError("Forwarding-only cleanup must use existing fixed-breakout ports")
    retired_logical = retire_logical_interfaces(config, owned | cleanup)
    inheritable = owned | {channel for memberships in channels.values() for channel in memberships}
    for name, acl in config.get("ACL_TABLE", {}).items():
        if "ports" not in acl:
            continue
        if not isinstance(acl["ports"], list):
            raise ValueError("ACL_TABLE.ports must be a list for generic rendering")
        removed = set(acl["ports"]).intersection(owned | retired_logical)
        if removed and (name not in {"DATAACL", "EVERFLOW"}
                        or not exclude_managed_acls and not removed.issubset(inheritable)):
            raise ValueError("Unsupported ACL_TABLE {} bindings on {}; explicit ACL migration is required".format(
                name, ", ".join(sorted(removed))))
    remove_owned(config, owned | retired_logical)
    for row in config.get("VLAN", {}).values():
        if "members" in row:
            row["members"] = [port for port in row["members"] if port not in cleanup]
    for port in owned:
        del config["PORT"][port]
    validate_references(config, owned | retired_logical)
    config["PORT"].update(selected)
    for port, names in inherited_acls.items():
        for name in names:
            config["ACL_TABLE"][name]["ports"].append(port)
    for name, acl in config.get("ACL_TABLE", {}).items():
        if acl.get("ports") == [] and base["ACL_TABLE"][name].get("ports"):
            del acl["ports"]
    return config, owned, set(selected)


def source_link_attribute(source, field):
    value = source.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("Source-link {} must be a string or null".format(field))
    return value.strip()


def traffic_connections(connections):
    return [link for link in connections if link.get("transport_vlan_id", -1) is not None]


def validate_vlan_scope(facts, scope):
    """Keep traffic inside the frozen CSV scope, with explicitly unprovisioned physical-only children."""
    if scope is None:
        if any(link.get("transport_vlan_id", -1) is None for link in facts["connections"]):
            raise ValueError("Physical-only children require a frozen CSV transport policy")
        return
    if scope.get("source") != "csv" or scope.get("granularity") != "realized_port_name":
        raise ValueError("Unsupported frozen VLAN eligibility policy; replan")
    physical_only = scope.get("unmapped_children") == "physical_only"
    if scope.get("unmapped_children") not in (None, "physical_only"):
        raise ValueError("Unsupported unmapped-child policy; replan")
    connections = facts["connections"]
    if not connections:
        raise ValueError("CSV VLAN scope has no selected physical links")
    for side in ("dut", "peer"):
        permitted = scope.get(side + "_ports")
        if (not isinstance(permitted, dict) or any(
                type(vlan) is not int or not 1 <= vlan <= 4094 for vlan in permitted.values())
                or len(set(permitted.values())) != len(permitted)):
            raise ValueError("Invalid frozen CSV VLAN endpoints")
        ports = [link[side]["port"] for link in connections]
        if len(set(ports)) != len(ports) or (not physical_only and not set(ports).issubset(permitted)):
            raise ValueError("Realized {} port has no CSV-backed transport VLAN; replan".format(side))
    for link in connections:
        expected = scope["dut_ports"].get(link["dut"]["port"])
        if link["peer"]["port"] not in scope["peer_ports"]:
            expected = None
        vlan = link.get("transport_vlan_id")
        if expected is None and physical_only:
            if ("transport_vlan_id" not in link or vlan is not None or link.get("ptf_index") is not None
                    or link.get("interface_mode") != "physical_only"
                    or any(field in link for field in (
                        "dut_address", "endpoint_address", "destination_prefix", "vlan_id", "gateway"))):
                raise ValueError("Physical-only child cannot have forwarding, a transport VLAN, or a PTF index")
            continue
        if type(vlan) is not int or vlan != expected:
            raise ValueError("Selected transport VLAN differs from its frozen CSV endpoint")
        if str(vlan) not in {source_link_attribute(source, "VlanID") for source in link["source_links"]}:
            raise ValueError("Selected transport VLAN is absent from the child's physical CSV wiring")
    if physical_only and [link.get("ptf_index") for link in traffic_connections(connections)] != list(
            range(len(traffic_connections(connections)))):
        raise ValueError("CSV-backed traffic children require contiguous PTF indices")


def transport_plan(facts, leaf, owned, settings):
    connections = traffic_connections(facts["connections"])
    explicit = settings.get("transport", {}).get("vlan_ids")
    scoped = facts.get("vlan_scope") is not None
    if scoped:
        validate_vlan_scope(facts, facts["vlan_scope"])
        candidates = [link["transport_vlan_id"] for link in connections]
        if explicit is not None and (
                not isinstance(explicit, list) or any(
                    type(vlan) is not int or not 1 <= vlan <= 4094 for vlan in explicit)
                or len(set(explicit)) != len(explicit) or not set(candidates).issubset(explicit)):
            raise ValueError("Configured transport VLAN allowlist excludes or invalidates CSV-backed endpoints")
    elif explicit is None:
        candidates = set()
        for link in connections:
            for source in link["source_links"]:
                value = source_link_attribute(source, "VlanID")
                if value:
                    if not value.isdigit():
                        raise ValueError("Transport requires explicit single VLAN IDs, not ranges in CSV rows")
                    candidates.add(int(value))
        candidates = sorted(candidates)
    else:
        candidates = explicit
    if (not isinstance(candidates, list) or any(
            isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094 for vlan in candidates)
            or len(set(candidates)) != len(candidates)):
        raise ValueError("transport.vlan_ids must be a unique list of VLAN IDs")
    if len(candidates) < len(connections):
        raise ValueError("Only {} candidate transport VLAN IDs for {} active children (shortfall: {}); "
                         "ownership and provisioning are not yet validated. Reserve and pre-provision "
                         "additional isolated leaf/root/host transport, then supply transport.vlan_ids".format(
                             len(candidates), len(connections),
                             len(connections) - len(candidates)))
    result = []
    for link, vlan_id in zip(connections, candidates):
        vlan = "Vlan{}".format(vlan_id)
        members = {key.split("|")[1]: row for key, row in leaf.get("VLAN_MEMBER", {}).items()
                   if key.split("|")[0] == vlan}
        access = {port for port, row in members.items() if row.get("tagging_mode") == "untagged"}
        trunks = {port for port, row in members.items() if row.get("tagging_mode") == "tagged"}
        if (vlan not in leaf.get("VLAN", {}) or (not access and (scoped or explicit is None))
                or not access.issubset(owned)
                or not trunks or trunks.intersection(owned)
                or str(leaf["VLAN"][vlan].get("vlanid")) != str(vlan_id)
                or any(scoped_port(key) == vlan for key in leaf.get("VLAN_INTERFACE", {}))):
            raise ValueError("{} is not demonstrably owned, isolated, and pre-provisioned on the leaf".format(vlan))
        result.append({"vlan_id": vlan_id, "peer_port": link["peer"]["port"],
                       "dut_port": link["dut"]["port"], "ptf_index": link["ptf_index"],
                       "trunk_ports": sorted(trunks)})
    return result


def apply_forwarding(config, facts, owned, role, transport=None):
    for link in facts["connections"]:
        port = link[role]["port"]
        policies = (("AutoNeg", "autoneg", {"on", "off"}),
                    ("LinkTraining", "link_training", {"on", "off"}),
                    ("FEC", "fec", {"rs", "fc", "none", "auto"}))
        for source_field, field, allowed in policies:
            values = {source_link_attribute(source, source_field).lower() for source in link["source_links"]}
            values.discard("")
            if values:
                if len(values) != 1 or not values.issubset(allowed):
                    raise ValueError("Unsupported or conflicting explicit {}".format(source_field))
                config["PORT"][port][field] = values.pop()
    for row in config.get("VLAN", {}).values():
        if "members" in row:
            row["members"] = [port for port in row["members"] if port not in owned]
    if role == "peer":
        for item in transport:
            vlan = "Vlan{}".format(item["vlan_id"])
            config.setdefault("VLAN_MEMBER", {})[vlan + "|" + item["peer_port"]] = {"tagging_mode": "untagged"}
            if "members" in config["VLAN"][vlan]:
                config["VLAN"][vlan]["members"].append(item["peer_port"])
        return
    forwarding = facts["forwarding"]
    addresses = [link["dut_address"] for link in facts["connections"] if link["interface_mode"] == "routed"]
    addresses.append(forwarding["svi"])
    networks = [ipaddress.ip_interface(address).network for address in addresses]
    for table in ("INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE", "MGMT_INTERFACE"):
        for key in config.get(table, {}):
            if "|" in key:
                existing = ipaddress.ip_interface(key.split("|", 1)[1]).network
                for address, network in zip(addresses, networks):
                    if network.version == existing.version and network.overlaps(existing):
                        raise ValueError(
                            "Approved forwarding addresses overlap preserved {}: planned {} ({}) conflicts with "
                            "{} ({}). Choose approved non-overlapping allocations or explicitly migrate the "
                            "preserved interface.".format(table, address, network, key, existing))
    for link in facts["connections"]:
        port = link["dut"]["port"]
        if link["interface_mode"] == "routed":
            config.setdefault("INTERFACE", {})[port] = {}
            config["INTERFACE"][port + "|" + link["dut_address"]] = {}
    vlan = "Vlan{}".format(forwarding["vlan_id"])
    if vlan in config.get("VLAN", {}):
        raise ValueError("DUT forwarding VLAN already exists: {}; choose an approved unused VLAN ID or "
                         "explicitly retire the old allocation first".format(vlan))
    downlinks = [link["dut"]["port"] for link in facts["connections"] if link["interface_mode"] == "access"]
    config.setdefault("VLAN", {})[vlan] = {"vlanid": str(forwarding["vlan_id"])}
    config.setdefault("VLAN_INTERFACE", {})[vlan] = {}
    config["VLAN_INTERFACE"][vlan + "|" + forwarding["svi"]] = {}
    for port in downlinks:
        config.setdefault("VLAN_MEMBER", {})[vlan + "|" + port] = {"tagging_mode": "untagged"}
    routes = config.setdefault("STATIC_ROUTE", {})
    for prefix, row in forwarding["static_routes"].items():
        if prefix in routes:
            raise ValueError("Planned static route conflicts with baseline: {}".format(prefix))
        routes[prefix] = deepcopy(row)


def pfc_priorities(value):
    if value == "":
        return []
    if (not isinstance(value, str)
            or any(not item.isdigit() or not 0 <= int(item) <= 7 for item in value.split(","))):
        raise ValueError("PFC policy must enable explicit lossless priorities from 0 through 7")
    priorities = [int(item) for item in value.split(",")]
    if len(set(priorities)) != len(priorities):
        raise ValueError("PFC policy contains duplicate lossless priorities")
    return sorted(priorities)


def inherited_pfc_policy(base, config, port, fields):
    """Inherit omitted PFC fields only from unambiguous lane-overlapping running ports."""
    lanes = set(config["PORT"][port].get("lanes", "").split(",")) - {""}
    parents = {name: set(row.get("lanes", "").split(",")) for name, row in base.get("PORT", {}).items()
               if lanes.intersection(row.get("lanes", "").split(","))}
    if not lanes or not parents or not lanes.issubset(set().union(*parents.values())):
        raise ValueError("Cannot inherit missing PFC policy for {} without running lane coverage".format(port))
    inherited = {}
    for field in fields:
        values = set()
        for parent in parents:
            rows = [row for key, row in base.get("PORT_QOS_MAP", {}).items()
                    if parent in scoped_port(key).split(",")]
            if not rows or any(field not in row for row in rows):
                raise ValueError("Running port {} lacks {} required by {}".format(parent, field, port))
            for row in rows:
                value = row[field]
                if field == "pfc_enable":
                    value = ",".join(map(str, pfc_priorities(value)))
                if not isinstance(value, str) or (not value and field != "pfc_enable"):
                    raise ValueError("Running port {} has invalid {}".format(parent, field))
                values.add(value)
        if len(values) != 1:
            raise ValueError("Conflicting running {} policies overlap {}; cannot inherit".format(field, port))
        inherited[field] = values.pop()
    return inherited


def scope_buffer_policy(config, generated, daemon_profiles=()):
    """Bind installed static profiles without replacing shared protected buffer policy."""
    report = {"preserved_pools": {}, "profile_aliases": {}}
    pools = generated.get("BUFFER_POOL", {})
    for name, row in pools.items():
        current = config.get("BUFFER_POOL", {}).get(name)
        if current is None or current == row:
            continue
        comparable = deepcopy(current)
        if "xoff" not in row:
            comparable.pop("xoff", None)
        comparable.pop("size", None)
        if (comparable != {key: value for key, value in row.items() if key != "size"}
                or any(not isinstance(values.get("size"), str) or not values["size"].isdigit()
                       for values in (current, row))):
            raise ValueError("Installed buffer policy cannot change shared BUFFER_POOL {} policy".format(name))
        report["preserved_pools"][name] = {"running": deepcopy(current), "template": deepcopy(row)}
        pools[name] = deepcopy(current)
    profiles = generated.get("BUFFER_PROFILE", {})
    for name, row in list(profiles.items()):
        if name in daemon_profiles:
            continue
        current = config.get("BUFFER_PROFILE", {}).get(name)
        if current is not None and current != row:
            if name.startswith("pg_lossless_"):
                raise ValueError("Installed buffer policy cannot replace a daemon-owned headroom profile")
            alias = "generic_buffer_" + digest({"name": name, "profile": row})[:12]
            if (alias in profiles and profiles[alias] != row
                    or alias in config.get("BUFFER_PROFILE", {}) and config["BUFFER_PROFILE"][alias] != row):
                raise ValueError("Installed buffer-profile alias conflicts with existing policy")
            profiles[alias] = profiles.pop(name)
            report["profile_aliases"][name] = alias
    for table in ("BUFFER_PG", "BUFFER_QUEUE"):
        for row in generated.get(table, {}).values():
            row["profile"] = report["profile_aliases"].get(row["profile"], row["profile"])
    for table in ("BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST"):
        for row in generated.get(table, {}).values():
            values = row["profile_list"]
            names = values.split(",") if isinstance(values, str) else values
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise ValueError("Installed buffer policy requires explicit buffer profile-list references")
            names = [report["profile_aliases"].get(name, name) for name in names]
            row["profile_list"] = ",".join(names) if isinstance(values, str) else names
    return report


def apply_qos(config, generated, facts, role, lookup, base, owned, selected,
              egress_profile="egress_lossless_profile"):
    cases = {(row["speed"], row["cable"]): row for row in lookup}
    if len(cases) != len(lookup):
        raise ValueError("Installed buffer lookup has duplicate speed/cable cases")
    expected = {"profiles": {}, "pgs": {}, "unused_profiles": {}}
    lossy_profiles = set()
    daemon_profiles = {"pg_lossless_{}_{}_profile".format(link[role]["speed"], link["buffer_case"]["cable"])
                       for link in facts["connections"]}
    protected = set(config["PORT"]) - selected
    port_tables = {"PORT_QOS_MAP", "QUEUE", "BUFFER_PG", "BUFFER_QUEUE",
                   "BUFFER_PORT_INGRESS_PROFILE_LIST", "BUFFER_PORT_EGRESS_PROFILE_LIST"}
    for table, rows in generated.items():
        if table == "CABLE_LENGTH":
            continue
        if table in port_tables:
            for key, row in rows.items():
                ports = scoped_port(key).split(",")
                for port in ports:
                    if port in selected:
                        config.setdefault(table, {})["|".join([port] + key.split("|")[1:])] = deepcopy(row)
        else:
            current = config.setdefault(table, {})
            for name, row in rows.items():
                if table == "BUFFER_PROFILE" and name in daemon_profiles:
                    continue
                if protected and name in current and current[name] != row:
                    raise ValueError("Rendered shared {} {} changes protected-port policy".format(table, name))
                current[name] = deepcopy(row)
    profiles = config.get("BUFFER_PROFILE", {})
    for link in facts["connections"]:
        port = link[role]["port"]
        case = link["buffer_case"]
        row = cases.get((str(link[role]["speed"]), case["cable"]))
        if row is None:
            raise ValueError("Installed lookup has no {} / {} case".format(link[role]["speed"], case["cable"]))
        qos = config.setdefault("PORT_QOS_MAP", {}).setdefault(port, {})
        if "pfc_enable" not in qos:
            qos.update(inherited_pfc_policy(base, config, port, ["pfc_enable"]))
        priorities = pfc_priorities(qos["pfc_enable"])
        qos["pfc_enable"] = ",".join(map(str, sorted(priorities)))
        config.setdefault("CABLE_LENGTH", {}).setdefault("AZURE", {})[port] = row["cable"]
        for values in config["CABLE_LENGTH"].values():
            if port in values:
                values[port] = row["cable"]
        name = "pg_lossless_{}_{}_profile".format(row["speed"], row["cable"])
        pool = config.get("BUFFER_POOL", {}).get("ingress_lossless_pool")
        profile = None
        if priorities or (row["cable"] != "0m" and pool is not None):
            if pool is None:
                raise ValueError("Installed templates lack the supported traditional lossless buffer objects")
            pool_mode = pool.get("mode")
            if pool_mode not in ("dynamic", "static"):
                raise ValueError("Installed ingress lossless pool must define its threshold mode")
            profile = {"pool": "ingress_lossless_pool", "size": row["size"], "xon": row["xon"],
                       "xoff": row["xoff"], pool_mode + "_th": row["threshold"]}
            if "xon_offset" in row:
                profile["xon_offset"] = row["xon_offset"]
        if not priorities:
            lossy_profiles.add(name)
            if profile is not None:
                expected["unused_profiles"][name] = profile
            continue
        if egress_profile not in profiles:
            raise ValueError("Installed templates lack the supported traditional lossless buffer objects")
        if case["cable"] == "0m":
            raise ValueError("Traditional daemon ownership does not generate lossless PGs for cable length 0m")
        missing = [field for field in ("pfc_to_pg_map", "pfc_to_queue_map") if field not in qos]
        if missing:
            qos.update(inherited_pfc_policy(base, config, port, missing))
        pg_map = config.get("PFC_PRIORITY_TO_PRIORITY_GROUP_MAP", {}).get(qos.get("pfc_to_pg_map"))
        queue_map = config.get("MAP_PFC_PRIORITY_TO_QUEUE", {}).get(qos.get("pfc_to_queue_map"))
        if pg_map is None or queue_map is None:
            raise ValueError("Installed QoS policy must provide explicit PFC-to-PG and PFC-to-queue maps")
        if any(int(pg_map[str(priority)]) != priority for priority in priorities):
            raise ValueError("Traditional daemon ownership requires identity PFC-priority-to-PG mappings")
        pgs = {int(pg_map[str(priority)]) for priority in priorities}
        queues = {int(queue_map[str(priority)]) for priority in priorities}
        if any(not 0 <= index <= 7 for index in pgs | queues):
            raise ValueError("Unsupported lossless PG/queue index")
        tc_pg = config.get("TC_TO_PRIORITY_GROUP_MAP", {}).get(qos.get("tc_to_pg_map"))
        tc_queue = config.get("TC_TO_QUEUE_MAP", {}).get(qos.get("tc_to_queue_map"))
        if tc_pg is None or tc_queue is None:
            raise ValueError("Installed port policy lacks TC-to-PG or TC-to-queue classification")
        queue_to_pg = {}
        for priority in priorities:
            queue, pg = int(queue_map[str(priority)]), int(pg_map[str(priority)])
            if queue in queue_to_pg and queue_to_pg[queue] != pg:
                raise ValueError("PFC maps associate one queue with different lossless PGs")
            queue_to_pg[queue] = pg
        classified = deepcopy(tc_pg)
        used_queues = set()
        for tc, queue in tc_queue.items():
            queue = int(queue)
            if queue in queue_to_pg:
                classified[tc] = str(queue_to_pg[queue])
                used_queues.add(queue)
        if used_queues != queues:
            raise ValueError("Lossless queues are not reachable through the installed TC-to-queue map")
        map_name = "generic_tc_pg_" + digest(classified)[:12]
        maps = config["TC_TO_PRIORITY_GROUP_MAP"]
        if map_name in maps and maps[map_name] != classified:
            raise ValueError("Generic TC-to-PG map name conflicts with an existing policy")
        maps[map_name] = classified
        qos["tc_to_pg_map"] = map_name
        if name in profiles and profiles[name] != profile:
            raise ValueError("Existing daemon profile differs from the selected lookup case: {}".format(name))
        expected["profiles"][name] = profile
        expected["pgs"].update({port + "|" + str(pg): name for pg in pgs})
        for table, indices, profile in (("BUFFER_PG", pgs, name),
                                        ("BUFFER_QUEUE", queues, egress_profile)):
            expanded = {}
            for key, value in config.get(table, {}).items():
                if scoped_port(key) == port:
                    for index in numbers(key.split("|")[1]) - indices:
                        expanded[port + "|" + str(index)] = value
                else:
                    expanded[key] = value
            if table == "BUFFER_QUEUE":
                expanded.update({port + "|" + str(index): {"profile": profile} for index in indices})
            config[table] = expanded
    if lossy_profiles:
        expected["omitted_profiles"] = {}
        references = json.dumps(dict(config, BUFFER_PROFILE=list(profiles.values())), sort_keys=True)
        for name in sorted(lossy_profiles - set(expected["profiles"])):
            if name not in profiles:
                continue
            if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", references):
                expected["omitted_profiles"][name] = profiles.pop(name)
    expected["unused_profiles"] = {
        name: row for name, row in expected["unused_profiles"].items()
        if name not in profiles and name not in expected["profiles"]}
    validate_references(config, owned - selected)
    reservations = {}
    for table in ("BUFFER_PG", "BUFFER_QUEUE"):
        for key, binding in config.get(table, {}).items():
            profile = config["BUFFER_PROFILE"][binding["profile"]]
            count = len(scoped_port(key).split(",")) * len(numbers(key.split("|")[1]))
            pool = profile["pool"]
            reservations[pool] = reservations.get(pool, 0) + int(profile.get("size", "0")) * count
    for name in expected["pgs"].values():
        profile = expected["profiles"][name]
        pool = profile["pool"]
        reservations[pool] = reservations.get(pool, 0) + int(profile["size"])
    for pool, reserved in reservations.items():
        if reserved > int(config["BUFFER_POOL"][pool]["size"]):
            raise ValueError("Buffer reservations exceed installed pool size: {}".format(pool))
    return expected


def canonical_ports(cage, choice, properties):
    import portconfig

    if choice["mode"] not in properties["breakout_modes"]:
        raise ValueError("Selected breakout mode is not advertised by the installed platform")
    groups = mode_components(choice["mode"])
    speeds = selected_speeds(choice["mode"], choice["speed"])

    def label(speed):
        return "{}G".format(speed // 1000) if speed % 1000 == 0 else str(speed)

    parts = []
    for group, speed in zip(groups, speeds):
        others = [label(value) for value in group["speeds"] if value != speed]
        suffix = "[" + ",".join(others) + "]" if others else ""
        lanes = "({})".format(group["lanes"]) if group["lanes"] is not None else ""
        parts.append("{}x{}{}{}".format(group["count"], label(speed), suffix, lanes))
    mode = "+".join(parts)
    return portconfig.BreakoutCfg(cage, mode, properties).get_config()


def template_json(directory, context, template, template_dir=None):
    source = directory / (str(len(list(directory.iterdir()))) + ".json")
    write_private(source, context)
    command = ["sonic-cfggen", "-j", str(source), "-t", str(template)]
    if template_dir is not None:
        command.extend(["-T", str(template_dir)])
    return json.loads(subprocess.check_output(command, text=True))


def direction_template(source, buffer_policy=False):
    """Adapt inspected role-list contracts without changing installed policy values."""
    from jinja2 import Environment, nodes

    # AST inspection only; configuration rendering remains owned by sonic-cfggen.
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    tree = Environment(autoescape=True).parse(source)
    template_name = "buffers_defaults_objects.j2" if buffer_policy else "qos_config.j2"
    roles = {"PORT_UPLINK": "GENERIC_UPLINK_PORTS", "PORT_DOWNLINK": "GENERIC_DOWNLINK_PORTS"}
    initializers = {name: [node for node in tree.body if isinstance(node, nodes.Assign)
                           and isinstance(node.target, nodes.Name) and node.target.name == name
                           and isinstance(node.node, nodes.List) and not node.node.items]
                    for name in roles}
    classifiers = []
    for index, node in enumerate(tree.body):
        if not isinstance(node, nodes.If):
            continue
        appended = {call.node.node.name for call in node.find_all(nodes.Call)
                    if isinstance(call.node, nodes.Getattr) and call.node.attr == "append"
                    and isinstance(call.node.node, nodes.Name)}
        if appended == set(roles):
            following = index + 1
            while following < len(tree.body) and isinstance(tree.body[following], nodes.Output):
                if any(not isinstance(child, nodes.TemplateData) or child.data.strip()
                       for child in tree.body[following].nodes):
                    break
                following += 1
            boundary = nodes.Macro if buffer_policy else nodes.Assign
            if following < len(tree.body) and isinstance(tree.body[following], boundary):
                classifiers.append((node.lineno - 1, tree.body[following].lineno - 1))
    if any(len(values) != 1 for values in initializers.values()) or len(classifiers) != 1:
        raise ValueError("Installed {} has an unrecognized direction contract; ".format(template_name) +
                         "provide a reviewed adapter rather than guessing port policy")
    lines = source.splitlines(keepends=True)
    start, end = classifiers[0]
    if any(values[0].lineno - 1 >= start for values in initializers.values()):
        raise ValueError("Template role-list initializers must precede neighbor classification")
    for name, values in initializers.items():
        index = values[0].lineno - 1
        if re.fullmatch(r"{%-?\s*set\s+" + name + r"\s*=\s*\[\s*\]\s*-?%}", lines[index].strip()) is None:
            raise ValueError("Template role-list initializers must be standalone empty-list assignments")
        if not buffer_policy:
            lines[index] = "{%- set " + name + " = " + roles[name] + " %}\n"
    if buffer_policy:
        if not re.match(r"^\s*{%-?\s*macro\b", lines[end]):
            raise ValueError("Unrecognized buffer classification boundaries")
        lines[end:end] = [
            "{%- set " + name + " = (" + name +
            " | reject('in', GENERIC_UPLINK_PORTS + GENERIC_DOWNLINK_PORTS) | list) + " + explicit + " %}\n"
            for name, explicit in roles.items()]
        result = "".join(lines)
        # Syntax validation only; this environment never renders output.
        # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
        Environment(autoescape=True).parse(result)
        return result
    if (not re.match(r"^\s*{%-?\s*if\b", lines[start])
            or not re.match(r"^\s*{%-?\s*set\b", lines[end])):
        raise ValueError("Unrecognized QoS classification boundaries")
    lines[start:end] = ["{%- if GENERIC_UPLINK_PORTS is not defined %}\n"] + lines[start:end] + ["{% endif %}\n"]
    result = "".join(lines)
    # Syntax validation only; this environment never renders output.
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    Environment(autoescape=True).parse(result)
    return result


def installed_asset(platform_dir, sku_dir, name, platform_first=False):
    first, second = (platform_dir, sku_dir) if platform_first else (sku_dir, platform_dir)
    path = first / name
    return path if path.exists() or path.is_symlink() else second / name


def prepare_qos_template(directory, platform_dir, sku_dir):
    from jinja2 import Environment, nodes

    assets = directory / "templates"
    assets.mkdir(mode=0o700)
    for root in (sku_dir, platform_dir):
        for asset in root.glob("*.j2"):
            destination = assets / asset.name
            if not destination.exists():
                destination.symlink_to(asset)
    source = installed_asset(platform_dir, sku_dir, "qos.json.j2").read_text()
    # AST inspection only; configuration rendering remains owned by sonic-cfggen.
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    includes = [node for node in Environment(autoescape=True).parse(source).find_all(nodes.Include)
                if isinstance(node.template, nodes.Const) and node.template.value == "qos_config.j2"]
    if len(includes) != 1:
        raise ValueError("Installed qos.json.j2 must have one static shared qos_config.j2 include")
    shared = directory / "generic_qos_config.j2"
    shared.write_text(direction_template(Path("/usr/share/sonic/templates/qos_config.j2").read_text()))
    lines = source.splitlines(keepends=True)
    index = includes[0].lineno - 1
    if lines[index].count("qos_config.j2") != 1:
        raise ValueError("Unrecognized shared QoS include; a reviewed adapter is required")
    # cfggen searches system templates before -T; an absolute include selects only our temporary adapter.
    lines[index] = lines[index].replace("qos_config.j2", str(shared))
    template = directory / "generic_qos.json.j2"
    template.write_text("".join(lines))
    return template, assets


def prepare_buffer_template(directory, template_dir, wrapper_source):
    """Redirect the inspected buffer include chain to private direction-aware copies."""
    from jinja2 import Environment, nodes

    def redirect(source, name, target):
        # AST inspection only; configuration rendering remains owned by sonic-cfggen.
        # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
        tree = Environment(autoescape=True).parse(source)
        references = []
        for node in tree.find_all((nodes.Import, nodes.Include)):
            expression = node.template.left if isinstance(node.template, nodes.Mod) else node.template
            if isinstance(expression, nodes.Const) and expression.value == name:
                references.append(node)
        pattern = r"(['\"])" + re.escape(name) + r"\1"
        result, count = re.subn(pattern, lambda match: repr(str(target)), source)
        if len(references) != 1 or count != 1:
            raise ValueError("Installed buffer template has an unrecognized include contract for " + name)
        return result

    objects = template_dir / "buffers_defaults_objects.j2"
    if not objects.is_file():
        raise ValueError("Installed buffers_defaults_objects.j2 is required for the reviewed direction adapter")
    adapted_objects = directory / "generic_buffers_defaults_objects.j2"
    adapted_objects.write_text(direction_template(objects.read_text(), buffer_policy=True))
    defaults = directory / "buffer_templates"
    defaults.mkdir(mode=0o700)
    for path in template_dir.glob("buffers_defaults_*.j2"):
        if path.name != objects.name:
            (defaults / path.name).write_text(redirect(
                path.read_text(), objects.name, adapted_objects))
    shared = directory / "generic_buffers_config.j2"
    shared.write_text(redirect(
        Path("/usr/share/sonic/templates/buffers_config.j2").read_text(),
        "buffers_defaults_%s.j2", defaults / "buffers_defaults_%s.j2"))
    template = directory / "generic_buffers.json.j2"
    template.write_text(redirect(
        (template_dir / "buffers.json.j2").read_text(), "buffers_config.j2", shared))
    wrapper = directory / "buffers.j2"
    wrapper.write_text(redirect(wrapper_source, "buffers.json.j2", template))
    return wrapper


def generic_identity(platform_dir, hwsku):
    """Resolve only our exact sibling alias; never create device paths during rendering."""
    current = platform_dir / hwsku
    if (not hwsku or Path(hwsku).name != hwsku or hwsku in (".", "..")):
        raise ValueError("Invalid HwSKU identity")
    base = hwsku
    if hwsku.endswith("_generic"):
        base = hwsku[:-len("_generic")]
        if not current.is_symlink() or current.resolve(strict=True) != (platform_dir / base).resolve(strict=True):
            raise ValueError("Existing generic HwSKU must be a symlink to its exact base HwSKU")
    target = platform_dir / base
    if not target.is_dir() or target.is_symlink():
        raise ValueError("Generic HwSKU requires an existing, non-symlink base HwSKU directory")
    alias = platform_dir / (base + "_generic")
    if (alias.exists() or alias.is_symlink()) and (
            not alias.is_symlink() or alias.resolve(strict=True) != target.resolve(strict=True)):
        raise ValueError("Generic HwSKU alias conflicts with an existing path")
    return {"original_hwsku": hwsku, "hwsku": base + "_generic",
            "alias": str(alias), "target": str(target)}


def device_assets(base, role):
    metadata = base["DEVICE_METADATA"]["localhost"]
    if metadata.get("buffer_model") != "traditional" or int(metadata.get("num_asic", "1")) != 1:
        raise ValueError("Initial generic rendering requires a single-ASIC traditional-buffer device")
    platform_dir = Path("/usr/share/sonic/device") / metadata["platform"]
    if Path(metadata["platform"]).name != metadata["platform"] or metadata["platform"] in (".", ".."):
        raise ValueError("Invalid installed platform identity")
    identity = generic_identity(platform_dir, metadata["hwsku"]) if role == "dut" else None
    sku_dir = Path(identity["target"]) if identity else platform_dir / metadata["hwsku"]
    return platform_dir, sku_dir, identity


def prepare_device(request):
    """Read only the canonical port order and existing transport needed to attach PTF."""
    role, facts = request["role"], request["facts"]
    reconcile_neighbors(facts, request["layouts"])
    validate_vlan_scope(facts, facts.get("vlan_scope"))
    base = read_running()
    platform_dir, sku_dir, _ = device_assets(base, role)
    platform = json.loads(installed_asset(platform_dir, sku_dir, "platform.json", platform_first=True).read_text())
    owned, selected = realize_ports(base, platform, request["layouts"][role], canonical_ports)
    transport = transport_plan(facts, base, owned, request["settings"]) if role == "peer" else None
    order = sorted((set(base["PORT"]) - owned) | set(selected), key=lambda name: (int(name[8:]), name))
    return {"port_order": order, "owned_ports": sorted(selected), "transport": transport}


def render_device(request):
    role, facts, settings = request["role"], request["facts"], request["settings"]
    neighbors = reconcile_neighbors(facts, request["layouts"])
    validate_vlan_scope(facts, facts.get("vlan_scope"))
    base = read_running()
    metadata = base["DEVICE_METADATA"]["localhost"]
    platform_dir, sku_dir, identity = device_assets(base, role)
    lookup_path = installed_asset(platform_dir, sku_dir, "pg_profile_lookup.ini", platform_first=True)
    platform_path = installed_asset(platform_dir, sku_dir, "platform.json", platform_first=True)
    platform = json.loads(platform_path.read_text())
    exclude_managed_acls = request.get("exclude_managed_acls", False)
    if "enable_lossless_adapter" in request:
        raise ValueError("Lossless overrides are no longer supported; render installed QoS policy without an adapter")
    cleanup = (forwarding_cleanup_ports(
        base, platform, request["layouts"]["dut"], facts.get("dut_forwarding_cleanup", {}))
        if role == "dut" else set())
    config, owned, selected = build_ports(
        base, platform, request["layouts"][role], canonical_ports, exclude_managed_acls,
        **({"forwarding_cleanup": cleanup} if cleanup else {}))
    config.setdefault("DEVICE_NEIGHBOR", {}).update(neighbors[role])
    transport = transport_plan(facts, base, owned, settings) if role == "peer" else None
    apply_forwarding(config, facts, owned, role, transport)
    context = deepcopy(config)
    version_path = Path("/etc/sonic/sonic_version.yml")
    version = yaml.safe_load(version_path.read_text())
    if not isinstance(version.get("asic_type"), str) or not version["asic_type"]:
        raise ValueError("Installed image does not identify its ASIC type")
    context.update(asic_type=version["asic_type"], hwsku=sku_dir.name, platform=metadata["platform"])
    context["DEVICE_METADATA"]["localhost"]["hwsku"] = sku_dir.name
    context["GENERIC_UPLINK_PORTS"] = [
        link[role]["port"] for link in facts["connections"] if role == "dut" and link["role"] == "uplink"]
    context["GENERIC_DOWNLINK_PORTS"] = sorted(selected - set(context["GENERIC_UPLINK_PORTS"]))
    assets = [platform_path, lookup_path, version_path]
    assets += (list(sku_dir.glob("*.j2")) + list(platform_dir.glob("*.j2"))
               + list(Path("/usr/share/sonic/templates").glob("*.j2")))
    assets = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in assets}
    with tempfile.TemporaryDirectory(prefix="generic-render-") as temporary:
        directory = Path(temporary)
        template, template_dir = prepare_qos_template(directory, platform_dir, sku_dir)
        generated = template_json(directory, context, template, template_dir)
        wrapper = prepare_buffer_template(directory, template_dir, request["buffer_wrapper"])
        context["GENERIC_CABLES"] = {link[role]["port"]: link["buffer_case"]["cable"]
                                     for link in facts["connections"]}
        for values in base.get("CABLE_LENGTH", {}).values():
            for port, cable in values.items():
                if port not in owned:
                    context["GENERIC_CABLES"][port] = cable
        buffers = template_json(directory, context, wrapper, template_dir)
        if set(generated).intersection(buffers) - {"CABLE_LENGTH"}:
            raise ValueError("Installed QoS and buffer templates generate overlapping tables")
        generated.update(buffers)
    buffer_policy = scope_buffer_policy(
        config, generated,
        daemon_profiles={"pg_lossless_{}_{}_profile".format(link[role]["speed"], link["buffer_case"]["cable"])
                         for link in facts["connections"]})
    lookup = parse_buffer_lookup(lookup_path.read_text())
    lossless = apply_qos(
        config, generated, facts, role, lookup, base, owned, selected,
        egress_profile=buffer_policy["profile_aliases"].get("egress_lossless_profile", "egress_lossless_profile"))
    buffer_policy["omitted_profiles"] = lossless.get("omitted_profiles", {})
    buffer_policy["lossy_cable_cases"] = {
        link[role]["port"]: {"speed": str(link[role]["speed"]), "cable": link["buffer_case"]["cable"]}
        for link in facts["connections"] if not config["PORT_QOS_MAP"][link[role]["port"]]["pfc_enable"]}
    if identity:
        config["DEVICE_METADATA"]["localhost"]["hwsku"] = identity["hwsku"]
    from sonic_yang import SonicYang

    validator = SonicYang("/usr/local/yang-models", False, False)
    validator.loadYangModel()
    validator.loadData(configdbJson=deepcopy(config))
    if set(validator.tablesWithOutYang).intersection(
            table for table in config if config.get(table) != base.get(table)):
        raise ValueError("An altered table has no installed YANG model")
    validator.validate_data_tree()
    report = {"baseline_sha256": digest(base), "config_sha256": digest(config), "assets": assets,
              "buffer_policy": buffer_policy,
              "unused_buffer_profiles": lossless["unused_profiles"],
              "qos_policy": "installed_lossless" if lossless["profiles"] else "installed_lossy",
              "owned_ports": sorted(selected), "protected_ports": sorted(set(base["PORT"]) - owned),
              "physical_only_ports": sorted(link[role]["port"] for link in facts["connections"]
                                            if link.get("transport_vlan_id", -1) is None),
              "forwarding_cleanup_ports": sorted(cleanup),
              "retired_ports": sorted(owned - selected), "transport": transport,
              "lookup_path": str(lookup_path.resolve(strict=True)),
              "platform": metadata["platform"], "hwsku": metadata["hwsku"], "yang_validated": True}
    report["exclude_managed_acls"] = exclude_managed_acls
    if lossless["profiles"]:
        report["lossless_buffers"] = lossless
    report["excluded_acl_bindings"] = {
        name: sorted(set(acl.get("ports", [])) - set(config.get("ACL_TABLE", {}).get(name, {}).get("ports", [])))
        for name, acl in base.get("ACL_TABLE", {}).items()
        if exclude_managed_acls and name in {"DATAACL", "EVERFLOW"}}
    if identity:
        report["hwsku_alias"] = identity
    return {"config": config, "report": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("prepare", "render"), default="render")
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        request = json.loads(Path(args.request).read_text())
        result = prepare_device(request) if args.action == "prepare" else render_device(request)
        write_private(Path(args.output), result)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Generic rendering failed: {}\n".format(error))


if __name__ == "__main__":
    main()
