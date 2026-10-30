#!/usr/bin/env python3
"""Read-only inventory of maximum-breakout links and supported buffer inputs."""

import argparse
import csv
from itertools import product
import json
import re
import sys
from pathlib import Path


def read_table(path, required):
    """Read a whitespace table whose column header starts with '#'."""
    header = None
    rows = []
    with open(path) as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                columns = line.lstrip("#").split()
                if set(required).issubset(columns):
                    if header is not None:
                        raise ValueError("{}:{}: duplicate table header".format(path, number))
                    header = columns
                continue
            if header is None:
                raise ValueError("{}:{}: missing table header".format(path, number))
            values = line.split()
            if len(values) != len(header):
                raise ValueError("{}:{}: expected {} columns".format(path, number, len(header)))
            rows.append(dict(zip(header, values)))
    if not rows:
        raise ValueError("{}: no table entries".format(path))
    return rows


def lane_list(value):
    lanes = value.split(",")
    if not lanes or any(not lane.strip().isdigit() for lane in lanes):
        raise ValueError("Invalid lanes: {!r}".format(value))
    lanes = [int(lane) for lane in lanes]
    if len(lanes) != len(set(lanes)):
        raise ValueError("Duplicate lanes: {}".format(value))
    return lanes


def mode_components(mode):
    """Parse ordered SONiC breakout groups; parenthesized widths are total group lanes."""
    groups = []
    for component in mode.split("+"):
        match = re.fullmatch(r"([1-9]\d*)x([1-9]\d*)([GM])(?:\[([\dGM,]+)\])?(?:\(([1-9]\d*)\))?",
                             component)
        if match is None:
            raise ValueError("Unsupported breakout mode syntax: {}".format(mode))
        count, value, unit, alternates, lanes = match.groups()
        values = [value + unit] + (alternates.split(",") if alternates else [])
        speeds = set()
        for value in values:
            speed = re.fullmatch(r"([1-9]\d*)([GM])", value)
            if speed is None:
                raise ValueError("Invalid alternate speed in mode {}".format(mode))
            speeds.add(int(speed.group(1)) * (1000 if speed.group(2) == "G" else 1))
        groups.append({"count": int(count), "speeds": sorted(speeds), "lanes": int(lanes) if lanes else None})
    if len(groups) > 1 and any(group["lanes"] is None for group in groups):
        raise ValueError("Mixed breakout groups require explicit lane counts: {}".format(mode))
    return groups


def mode_variants(mode):
    """Uniform variants are scalar speeds; mixed variants contain one speed per ordered group."""
    groups = mode_components(mode)
    return [speeds[0] if len(groups) == 1 else tuple(speeds)
            for speeds in product(*(group["speeds"] for group in groups))]


def speed_key(speed):
    return tuple(speed) if isinstance(speed, (list, tuple)) else speed


def selected_speeds(mode, speed):
    groups = mode_components(mode)
    speeds = [speed] if len(groups) == 1 else speed
    if (not isinstance(speeds, (list, tuple)) or len(speeds) != len(groups)
            or any(type(value) is not int or value not in group["speeds"]
                   for group, value in zip(groups, speeds))):
        raise ValueError("Unsupported mode/speed {}/{}".format(mode, speed))
    return list(speeds)


def expand_mode(cage_name, cage, mode, speed):
    """Expand an advertised mode using ordered group partitions, aliases and child speeds."""
    if mode not in cage["breakout_modes"]:
        raise ValueError("{}: unsupported mode/speed {}/{}".format(cage_name, mode, speed))
    parent = re.fullmatch(r"Ethernet(\d+)", cage_name)
    if parent is None:
        raise ValueError("{}: unsupported parent naming".format(cage_name))
    groups = mode_components(mode)
    speeds = selected_speeds(mode, speed)
    lanes = cage["lanes"]
    aliases = cage["breakout_modes"][mode]
    counts = [group["count"] for group in groups]
    widths = [group["lanes"] if group["lanes"] is not None else len(lanes) for group in groups]
    if (sum(widths) != len(lanes) or any(width % count for width, count in zip(widths, counts))
            or len(aliases) != sum(counts)):
        raise ValueError("{}: invalid lane or alias count for {}".format(cage_name, mode))
    children = []
    offset = 0
    for group, total, operating_speed in zip(groups, widths, speeds):
        width = total // group["count"]
        for _ in range(group["count"]):
            children.append({
                "port": "Ethernet{}".format(int(parent.group(1)) + offset),
                "alias": aliases[len(children)], "cage": cage_name, "lanes": lanes[offset:offset + width],
                "speed": operating_speed,
            })
            offset += width
    return children


def load_device(platform_path):
    """Derive maximum-breakout children using ordered platform lanes and aliases."""
    with open(platform_path) as handle:
        platform = json.load(handle)
    interfaces = platform.get("interfaces")
    if not isinstance(interfaces, dict) or not interfaces:
        raise ValueError("{}: missing interfaces".format(platform_path))
    cages = {}
    lane_owner = {}
    ports = {}
    aliases = {}
    for name, data in interfaces.items():
        parent = re.fullmatch(r"Ethernet(\d+)", name)
        if parent is None:
            raise ValueError("{}: unsupported parent naming; expected Ethernet<number>".format(name))
        lanes = lane_list(data["lanes"])
        modes = data.get("breakout_modes")
        if not isinstance(modes, dict) or not modes:
            raise ValueError("{}: missing breakout_modes".format(name))
        parsed_modes = {}
        for mode, mode_aliases in modes.items():
            groups = mode_components(mode)
            count = sum(group["count"] for group in groups)
            if (not isinstance(mode_aliases, list) or len(mode_aliases) != count
                    or any(not isinstance(alias, str) or not alias for alias in mode_aliases)):
                raise ValueError("{}: invalid aliases for {}".format(name, mode))
            widths = [group["lanes"] if group["lanes"] is not None else len(lanes) for group in groups]
            if sum(widths) != len(lanes):
                raise ValueError("{}: assigned lane count differs from cage for {}".format(name, mode))
            if any(width % group["count"] for width, group in zip(widths, groups)):
                raise ValueError("{}: lane count is not divisible by {}".format(name, mode))
            parsed_modes[mode] = count
        for lane in lanes:
            if lane in lane_owner:
                raise ValueError("Lane {} belongs to multiple cages".format(lane))
            lane_owner[lane] = name
        maximum_children = max(parsed_modes.values())
        maximum_modes = [mode for mode, count in parsed_modes.items() if count == maximum_children]
        cages[name] = {"lanes": lanes, "breakout_modes": modes, "maximum_breakout_modes": maximum_modes}
        maximum = [expand_mode(name, cages[name], mode, mode_variants(mode)[0]) for mode in maximum_modes]
        geometries = [[(row["port"], row["alias"], row["lanes"]) for row in rows] for rows in maximum]
        if any(geometry != geometries[0] for geometry in geometries[1:]):
            raise ValueError("{}: maximum-breakout modes have ambiguous child aliases or lanes".format(name))
        supported = [set() for _ in range(maximum_children)]
        for mode in maximum_modes:
            for variant in mode_variants(mode):
                for index, child in enumerate(expand_mode(name, cages[name], mode, variant)):
                    supported[index].add(child["speed"])
        for index, entry in enumerate(maximum[0]):
            child, alias = entry["port"], entry["alias"]
            if child in ports or alias in aliases:
                raise ValueError("Duplicate derived port name or alias: {}".format(child))
            entry.pop("speed")
            ports[child] = dict(entry, supported_speeds=sorted(supported[index]))
            aliases[alias] = child
    for alias, child in aliases.items():
        if alias in ports and alias != child:
            raise ValueError("Ambiguous port alias: {}".format(alias))
    return {"cages": cages, "ports": ports, "aliases": aliases}


def resolve_port(device, name):
    canonical = name if name in device["ports"] else device["aliases"].get(name)
    if canonical is None:
        raise ValueError("CSV endpoint {!r} absent from platform-derived maximum breakout".format(name))
    return device["ports"][canonical]


def load_lookup(path):
    """Keep supplied lookup parameters unchanged; never calculate profiles."""
    entries = {}
    for row in read_table(path, ("speed", "cable", "size", "xon", "xoff", "threshold")):
        if not row["speed"].isdigit() or int(row["speed"]) <= 0:
            raise ValueError("{}: invalid speed".format(path))
        key = (row["speed"], row["cable"])
        if key in entries:
            raise ValueError("{}: duplicate speed/cable case {}".format(path, key))
        entries[key] = row
    return list(entries.values())


def supported_speeds(mode):
    return sorted({speed for group in mode_components(mode) for speed in group["speeds"]})


def build_mapping(links_path, hostname, peer_hostname, dut, peer, lookup, excluded_ports=()):
    """Annotate physical CSV links, protecting cages touched by excluded wiring."""
    if hostname == peer_hostname:
        raise ValueError("DUT and peer must be different devices")
    excluded = {resolve_port(dut, name)["port"] for name in excluded_ports}
    links = []
    protected_dut = set()
    protected_peer = set()
    seen = set()
    seen_peer = set()
    with open(links_path, newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"StartDevice", "StartPort", "EndDevice", "EndPort", "BandWidth"}
        if not required.issubset(reader.fieldnames or ()):
            raise ValueError("{}: missing required CSV columns".format(links_path))
        for number, row in enumerate(reader, 2):
            endpoints = [(row["StartDevice"], row["StartPort"]), (row["EndDevice"], row["EndPort"])]
            relevant = any(device in (hostname, peer_hostname) for device, _ in endpoints)
            if not relevant:
                continue
            if None in row or any(not row[column] for column in required):
                raise ValueError("{}:{}: malformed CSV row".format(links_path, number))
            for device, port in endpoints:
                if device == peer_hostname:
                    canonical = resolve_port(peer, port)["port"]
                    if canonical in seen_peer:
                        raise ValueError("Duplicate peer endpoint: {}".format(canonical))
                    seen_peer.add(canonical)
            if hostname not in [device for device, _ in endpoints]:
                for device, port in endpoints:
                    if device == peer_hostname:
                        protected_peer.add(resolve_port(peer, port)["cage"])
                continue
            if endpoints[0][0] == endpoints[1][0]:
                raise ValueError("{}:{}: DUT self-link is unsupported".format(links_path, number))
            dut_index = 0 if endpoints[0][0] == hostname else 1
            dut_port = dict(resolve_port(dut, endpoints[dut_index][1]))
            remote_host, remote_name = endpoints[1 - dut_index]
            remote = dict(resolve_port(peer, remote_name)) if remote_host == peer_hostname else {"port": remote_name}
            if dut_port["port"] in seen:
                raise ValueError("Duplicate DUT endpoint: {}".format(dut_port["port"]))
            seen.add(dut_port["port"])
            if not row["BandWidth"].isdigit() or int(row["BandWidth"]) not in dut_port["supported_speeds"]:
                raise ValueError("{}: CSV bandwidth is unsupported by maximum-breakout modes".format(dut_port["port"]))
            dut_port["speed"] = int(row["BandWidth"])
            if remote_host == peer_hostname:
                if dut_port["speed"] not in remote["supported_speeds"]:
                    raise ValueError(
                        "{}: peer does not support CSV bandwidth at maximum breakout".format(remote["port"]))
                remote["speed"] = dut_port["speed"]
            if remote_host != peer_hostname or dut_port["port"] in excluded:
                protected_dut.add(dut_port["cage"])
                if remote_host == peer_hostname:
                    protected_peer.add(remote["cage"])
            links.append({"csv_line": number, "csv_attributes": row, "dut": dut_port,
                          "peer_hostname": remote_host, "peer": remote})
    if not links:
        raise ValueError("{}: no links for {}".format(links_path, hostname))
    for device, connected, protected in ((dut, seen, protected_dut), (peer, seen_peer, protected_peer)):
        protected.update(set(device["cages"]) - {port["cage"] for port in device["ports"].values()})
        for name, port in device["ports"].items():
            if name not in connected:
                protected.add(port["cage"])
    changed = True
    while changed:
        previous = (len(protected_dut), len(protected_peer))
        for link in links:
            if link["peer_hostname"] != peer_hostname:
                continue
            dut_cage, peer_cage = link["dut"]["cage"], link["peer"]["cage"]
            if dut_cage in protected_dut or peer_cage in protected_peer:
                protected_dut.add(dut_cage)
                protected_peer.add(peer_cage)
        changed = previous != (len(protected_dut), len(protected_peer))
    for link in links:
        reasons = []
        if link["peer_hostname"] != peer_hostname:
            reasons.append("peer is outside selected scope")
        if link["dut"]["cage"] in protected_dut:
            reasons.append("DUT cage contains or shares resources with protected connections")
        if link["peer_hostname"] == peer_hostname and link["peer"]["cage"] in protected_peer:
            reasons.append("peer cage contains or shares resources with protected connections")
        link["eligible"] = not reasons
        link["protection_reasons"] = reasons
    modes = {}
    for name, cage in dut["cages"].items():
        modes[name] = {}
        for mode, aliases in cage["breakout_modes"].items():
            speeds = supported_speeds(mode)
            modes[name][mode] = {
                "aliases": aliases,
                "speeds": speeds,
                "operating_combinations": [list(value) if isinstance(value, tuple) else value
                                           for value in mode_variants(mode)],
                "buffer_cases": [entry for entry in lookup if int(entry["speed"]) in speeds],
                "speeds_without_lookup": [speed for speed in speeds
                                          if not any(int(entry["speed"]) == speed for entry in lookup)],
            }
    excluded_cages = {resolve_port(dut, name)["cage"] for name in excluded}
    cleanup_cages = {link["dut"]["cage"] for link in links if link["peer_hostname"] != peer_hostname}
    cleanup_cages = {cage for cage in cleanup_cages - excluded_cages
                     if all(name in seen for name, port in dut["ports"].items() if port["cage"] == cage)}
    return {"hostname": hostname, "peer_hostname": peer_hostname, "links": links,
            "dut_cages": dut["cages"], "peer_cages": peer["cages"], "dut_mode_buffer_inputs": modes,
            "excluded_dut_modes": dut.get("excluded_modes", []),
            "excluded_peer_modes": peer.get("excluded_modes", []),
            "dut_forwarding_cleanup_cages": sorted(cleanup_cages),
            "protected_dut_cages": sorted(protected_dut), "protected_peer_cages": sorted(protected_peer)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("links-csv", "hostname", "peer-hostname", "platform-json",
                   "pg-profile-lookup", "peer-platform-json"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--exclude-port", action="append", default=[],
                        help="Protect this DUT port's entire cage; repeat for additional ports")
    args = parser.parse_args()
    try:
        dut = load_device(args.platform_json)
        peer = load_device(args.peer_platform_json)
        result = build_mapping(args.links_csv, args.hostname, args.peer_hostname, dut, peer,
                               load_lookup(args.pg_profile_lookup), args.exclude_port)
        paths = ("links_csv", "platform_json", "pg_profile_lookup", "peer_platform_json")
        result["sources"] = {name: str(Path(getattr(args, name)).resolve()) for name in paths}
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
