#!/usr/bin/env python3

import argparse
import copy
import json
import os
import re
import sys

PORT_NAME_RE = re.compile(r"^Ethernet(\d+)$")
ALIAS_RE = re.compile(r"^(?P<prefix>[^0-9]+)(?P<number>\d+)(?P<suffix>[a-zA-Z]+)?$")


def _log(message):
    print(message, file=sys.stderr)


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4, sort_keys=False)
        handle.write("\n")


def parse_csv(value):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_port_index(name):
    match = PORT_NAME_RE.match(name)
    if not match:
        return None
    return int(match.group(1))


def sort_ports(ports):
    def sort_key(name):
        idx = parse_port_index(name)
        return (idx is None, idx if idx is not None else name, name)

    return sorted(ports, key=sort_key)


def sort_group_ports(port_table, ports):
    items = []
    for port in ports:
        entry = port_table.get(port, {})
        alias_info = parse_alias(entry.get("alias"))
        suffix = alias_info[2] if alias_info else None
        subport = entry.get("subport")
        try:
            subport_value = int(subport)
        except (TypeError, ValueError):
            subport_value = None
        items.append({
            "port": port,
            "subport": subport_value,
            "suffix": suffix,
            "port_index": parse_port_index(port),
        })

    def sort_key(item):
        if item["subport"] is not None:
            return (0, item["subport"], item["port_index"] or 0, item["port"])
        if item["suffix"]:
            return (1, item["suffix"].lower(), item["port_index"] or 0, item["port"])
        return (2, item["port_index"] or 0, item["port"])

    return [item["port"] for item in sorted(items, key=sort_key)]


def parse_alias(alias):
    if not alias:
        return None
    match = ALIAS_RE.match(alias)
    if not match:
        return None
    return match.group("prefix"), match.group("number"), match.group("suffix")


def letters_for_index(index):
    if index < 0:
        raise ValueError("Alias index cannot be negative")
    letters = []
    while True:
        letters.append(chr(ord("a") + (index % 26)))
        index = index // 26 - 1
        if index < 0:
            break
    return "".join(reversed(letters))


def parse_speed_list(value, breakout_count):
    speeds = parse_csv(value)
    if not speeds:
        return []
    if len(speeds) == 1:
        return [speeds[0]] * breakout_count
    if len(speeds) != breakout_count:
        raise ValueError(
            "breakout-speed must be a single value or match breakout-count"
        )
    return speeds


def select_base_ports(port_table, ports_arg, breakout_total, breakout_count, base_speed):
    if ports_arg:
        ports = parse_csv(ports_arg)
        missing = [p for p in ports if p not in port_table]
        if missing:
            _log("Warning: ports not found in PORT table: {}".format(", ".join(missing)))
        return [p for p in ports if p in port_table]

    if breakout_total is None:
        raise ValueError("breakout-total is required when ports are not specified")
    if breakout_total % breakout_count != 0:
        raise ValueError("breakout-total must be a multiple of breakout-count")

    base_ports_needed = breakout_total // breakout_count
    candidates = [
        name for name, entry in port_table.items()
        if entry.get("speed") == str(base_speed)
    ]
    return sort_ports(candidates)[:base_ports_needed]


def build_new_port_names(base_port, breakout_count):
    base_index = parse_port_index(base_port)
    if base_index is None:
        raise ValueError("Unsupported port name: {}".format(base_port))
    return ["Ethernet{}".format(base_index + offset) for offset in range(breakout_count)]


def split_lanes(lanes_value, breakout_count):
    lanes = [lane.strip() for lane in lanes_value.split(",") if lane.strip()]
    if not lanes:
        raise ValueError("No lanes defined")
    if len(lanes) % breakout_count != 0:
        raise ValueError("Lane count {} not divisible by breakout-count {}".format(
            len(lanes), breakout_count
        ))
    group_size = len(lanes) // breakout_count
    return [lanes[i:i + group_size] for i in range(0, len(lanes), group_size)]


def build_alias_plan(port_table):
    group_ports = {}
    for port_name, entry in port_table.items():
        alias_info = parse_alias(entry.get("alias"))
        if not alias_info:
            continue
        prefix, number, suffix = alias_info
        group_ports.setdefault((prefix, number), []).append({
            "port": port_name,
            "suffix": suffix,
        })

    alias_plan = {}
    for key, ports in group_ports.items():
        port_names = [item["port"] for item in ports]
        for position, port_name in enumerate(sort_group_ports(port_table, port_names)):
            alias_plan[port_name] = {
                "prefix": key[0],
                "number": key[1],
                "position": position,
            }

    return alias_plan


def ensure_unique_aliases(port_table):
    groups = {}
    for port_name, entry in port_table.items():
        alias_info = parse_alias(entry.get("alias"))
        if not alias_info:
            continue
        prefix, number, _ = alias_info
        groups.setdefault((prefix, number), []).append(port_name)

    for (prefix, number), ports in groups.items():
        aliases = [port_table[p].get("alias") for p in ports]
        if len(aliases) == len(set(aliases)):
            continue

        ordered_ports = sort_group_ports(port_table, ports)
        for position, port_name in enumerate(ordered_ports):
            entry = port_table[port_name]
            entry["alias"] = "{}{}{}".format(
                prefix,
                number,
                letters_for_index(position),
            )
            entry["subport"] = str(position + 1)


def update_port_table(port_table, base_ports, breakout_count, speed_list, collision_mode, alias_plan):
    breakout_map = {}
    added_ports = 0

    for base_port in base_ports:
        if base_port not in port_table:
            _log("Warning: base port {} not found, skipping".format(base_port))
            continue

        try:
            new_ports = build_new_port_names(base_port, breakout_count)
        except ValueError as exc:
            _log("Warning: {} (skipping {})".format(exc, base_port))
            continue

        conflicts = [
            name for name in new_ports
            if name in port_table and name != base_port
        ]
        if conflicts:
            if collision_mode == "skip":
                _log("Warning: conflicts for {} ({}), skipping breakout".format(
                    base_port, ", ".join(conflicts)
                ))
                continue
            raise ValueError("Port name conflicts for {}: {}".format(
                base_port, ", ".join(conflicts)
            ))

        base_entry = port_table[base_port]
        lanes_value = base_entry.get("lanes")
        if not lanes_value:
            _log("Warning: base port {} has no lanes, skipping".format(base_port))
            continue

        try:
            lane_groups = split_lanes(lanes_value, breakout_count)
        except ValueError as exc:
            _log("Warning: {} for {}, skipping".format(exc, base_port))
            continue

        alias_info = alias_plan.get(base_port)
        if alias_info:
            alias_prefix = alias_info["prefix"]
            alias_number = alias_info["number"]
            alias_offset = alias_info["position"] * breakout_count
        else:
            alias_prefix = None
            alias_number = None
            alias_offset = 0
            if base_entry.get("alias"):
                _log("Warning: unable to parse alias for {}, leaving aliases unchanged".format(base_port))

        new_entries = []
        for idx, port_name in enumerate(new_ports):
            entry = copy.deepcopy(base_entry)
            entry["lanes"] = ",".join(lane_groups[idx])
            entry["speed"] = speed_list[idx]
            if alias_prefix and alias_number:
                entry["alias"] = "{}{}{}".format(
                    alias_prefix,
                    alias_number,
                    letters_for_index(alias_offset + idx),
                )
                entry["subport"] = str(alias_offset + idx + 1)
            else:
                entry["subport"] = str(idx + 1)
            new_entries.append((port_name, entry))

        for port_name, entry in new_entries:
            port_table[port_name] = entry

        breakout_map[base_port] = {
            "new_ports": new_ports,
            "speeds": speed_list,
        }
        added_ports += max(len(new_ports) - 1, 0)

    return breakout_map, added_ports


def _get_cable_length_tables(cable_length_data):
    if not isinstance(cable_length_data, dict):
        return []
    if any(isinstance(value, dict) for value in cable_length_data.values()):
        return [value for value in cable_length_data.values() if isinstance(value, dict)]
    return [cable_length_data]


def find_cable_length(cable_length_data, port):
    for table in _get_cable_length_tables(cable_length_data):
        if port in table:
            return table[port]
    return None


def get_device_metadata(config):
    metadata = config.get("DEVICE_METADATA", {}).get("localhost", {})
    return (
        metadata.get("platform"),
        metadata.get("hwsku"),
        metadata.get("type"),
    )


def infer_topo(device_type):
    if not device_type:
        return None
    if "ToRRouter" in device_type:
        return "t0"
    if "LeafRouter" in device_type:
        return "t1"
    if "SpineRouter" in device_type:
        return "t2"
    return None


def resolve_device_dir(platform, hwsku, buffers_root):
    if not platform or not hwsku:
        return None
    return os.path.join(buffers_root, platform, hwsku)


def read_default_cable_length(buffers_defaults_path):
    if not buffers_defaults_path or not os.path.exists(buffers_defaults_path):
        return None
    pattern = re.compile(r"default_cable\s*=\s*['\"]([^'\"]+)['\"]")
    with open(buffers_defaults_path, "r", encoding="utf-8") as handle:
        for line in handle:
            match = pattern.search(line)
            if match:
                return match.group(1)
    return None


def get_buffer_threshold_field(config):
    pool = config.get("BUFFER_POOL", {}).get("ingress_lossless_pool", {})
    mode = pool.get("mode", "dynamic")
    return "dynamic_th" if mode == "dynamic" else "static_th"


def load_pg_profile_lookup(path, threshold_field):
    if not path or not os.path.exists(path):
        return {}
    profiles = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = stripped.split()
            if len(tokens) < 6:
                continue
            speed, cable = tokens[0], tokens[1]
            size, xon, xoff, threshold = tokens[2:6]
            profile_data = {
                "pool": "ingress_lossless_pool",
                "size": size,
                "xon": xon,
                "xoff": xoff,
                threshold_field: threshold,
            }
            if len(tokens) > 6:
                profile_data["xon_offset"] = tokens[6]
            profiles[(speed, cable)] = profile_data
    return profiles


def ensure_lossless_profile(buffer_profiles, profile_lookup, speed, cable_length):
    if not profile_lookup:
        return None
    profile_key = (speed, cable_length)
    if profile_key not in profile_lookup:
        return None
    profile_name = "pg_lossless_{}_{}_profile".format(speed, cable_length)
    if profile_name not in buffer_profiles:
        buffer_profiles[profile_name] = profile_lookup[profile_key]
    return profile_name


def update_cable_length(config, breakout_map, default_length, new_port_length=None):
    cable_length_data = config.get("CABLE_LENGTH")
    if not cable_length_data:
        return

    for base_port, info in breakout_map.items():
        base_length = find_cable_length(cable_length_data, base_port) or default_length
        target_length = new_port_length or base_length
        if not target_length:
            _log("Warning: no cable length for {}".format(base_port))
            continue
        for table in _get_cable_length_tables(cable_length_data):
            for new_port in info["new_ports"][1:]:
                if new_port not in table:
                    table[new_port] = target_length


def update_port_qos_map(config, breakout_map):
    qos_map = config.get("PORT_QOS_MAP")
    if not isinstance(qos_map, dict):
        return

    for base_port, info in breakout_map.items():
        if base_port not in qos_map:
            continue
        for new_port in info["new_ports"][1:]:
            if new_port not in qos_map:
                qos_map[new_port] = copy.deepcopy(qos_map[base_port])


def update_queue_table(config, breakout_map):
    queue_table = config.get("QUEUE")
    if not isinstance(queue_table, dict):
        return

    items = list(queue_table.items())
    for key, value in items:
        base_port, suffix = _split_port_key(key)
        if not base_port or base_port not in breakout_map:
            continue
        for new_port in breakout_map[base_port]["new_ports"][1:]:
            new_key = "{}|{}".format(new_port, suffix)
            if new_key not in queue_table:
                queue_table[new_key] = copy.deepcopy(value)


def update_vlan_member(config, breakout_map):
    vlan_member = config.get("VLAN_MEMBER")
    if not isinstance(vlan_member, dict):
        return

    items = list(vlan_member.items())
    for key, value in items:
        vlan_name, port = _split_port_key(key)
        if not port or port not in breakout_map:
            continue
        for new_port in breakout_map[port]["new_ports"][1:]:
            new_key = "{}|{}".format(vlan_name, new_port)
            if new_key not in vlan_member:
                vlan_member[new_key] = copy.deepcopy(value)


def update_acl_table(config, breakout_map):
    acl_table = config.get("ACL_TABLE")
    if not isinstance(acl_table, dict):
        return

    for acl_entry in acl_table.values():
        ports = acl_entry.get("ports")
        if not isinstance(ports, list):
            continue
        port_set = set(ports)
        for base_port, info in breakout_map.items():
            if base_port in port_set:
                for new_port in info["new_ports"][1:]:
                    if new_port not in port_set:
                        ports.append(new_port)
                        port_set.add(new_port)


def map_lossless_profile(profile, speed, cable_length, buffer_profiles, profile_lookup):
    if not profile or not profile.startswith("pg_lossless_"):
        return profile
    if not cable_length:
        return profile
    new_name = ensure_lossless_profile(buffer_profiles, profile_lookup, speed, cable_length)
    if new_name:
        return new_name
    return profile


def update_buffer_pg(config, breakout_map, default_length, profile_lookup):
    buffer_pg = config.get("BUFFER_PG")
    buffer_profiles = config.get("BUFFER_PROFILE")
    if not isinstance(buffer_profiles, dict):
        buffer_profiles = {}
        config["BUFFER_PROFILE"] = buffer_profiles
    if not isinstance(buffer_pg, dict):
        return

    cable_length_data = config.get("CABLE_LENGTH", {})
    items = list(buffer_pg.items())
    for key, value in items:
        base_port, suffix = _split_port_key(key)
        if not base_port or base_port not in breakout_map:
            continue

        base_speed = breakout_map[base_port]["speeds"][0]
        cable_length = find_cable_length(cable_length_data, base_port) or default_length
        if "profile" in value:
            value["profile"] = map_lossless_profile(
                value.get("profile"), base_speed, cable_length, buffer_profiles, profile_lookup
            )

        for idx, new_port in enumerate(breakout_map[base_port]["new_ports"][1:], start=1):
            new_speed = breakout_map[base_port]["speeds"][idx]
            new_key = "{}|{}".format(new_port, suffix)
            if new_key in buffer_pg:
                continue
            new_value = copy.deepcopy(value)
            if "profile" in new_value:
                new_value["profile"] = map_lossless_profile(
                    new_value.get("profile"), new_speed, cable_length, buffer_profiles, profile_lookup
                )
            buffer_pg[new_key] = new_value


def update_buffer_queue(config, breakout_map):
    buffer_queue = config.get("BUFFER_QUEUE")
    if not isinstance(buffer_queue, dict):
        return

    items = list(buffer_queue.items())
    for key, value in items:
        base_port, suffix = _split_port_key(key)
        if not base_port or base_port not in breakout_map:
            continue
        for new_port in breakout_map[base_port]["new_ports"][1:]:
            new_key = "{}|{}".format(new_port, suffix)
            if new_key not in buffer_queue:
                buffer_queue[new_key] = copy.deepcopy(value)


def update_buffer_pool(config, override_value):
    if not override_value:
        return
    try:
        overrides = json.loads(override_value)
    except json.JSONDecodeError:
        if os.path.exists(override_value):
            overrides = load_json(override_value)
        else:
            raise

    buffer_pool = config.get("BUFFER_POOL")
    if not isinstance(buffer_pool, dict):
        config["BUFFER_POOL"] = overrides
        return
    for key, value in overrides.items():
        buffer_pool[key] = value


def order_port_table(config):
    port_table = config.get("PORT")
    if not isinstance(port_table, dict):
        return
    ordered = {}
    for port_name in sort_ports(port_table.keys()):
        ordered[port_name] = port_table[port_name]
    config["PORT"] = ordered


def _split_port_key(key):
    if "|" not in key:
        return None, None
    left, right = key.split("|", 1)
    return left, right


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a breakout config_db.json from an existing config_db.json"
    )
    parser.add_argument(
        "--in", dest="input_path", default="/etc/sonic/config_db.json",
        help="Path to the existing config_db.json (default: /etc/sonic/config_db.json)"
    )
    parser.add_argument(
        "--out", dest="output_path", default="/etc/sonic/config_db.breakout.json",
        help="Path to write the updated config_db.json"
    )
    parser.add_argument(
        "--ports", dest="ports", default=None,
        help="Comma-separated list of base ports to break out (e.g., Ethernet0,Ethernet4)"
    )
    parser.add_argument(
        "--breakout-total", dest="breakout_total", type=int, default=None,
        help="Total breakout ports to create (e.g., 64)"
    )
    parser.add_argument(
        "--breakout-count", dest="breakout_count", type=int, required=True,
        help="Number of breakout ports per base port (e.g., 4)"
    )
    parser.add_argument(
        "--breakout-speed", dest="breakout_speed", required=True,
        help="Breakout port speed(s). Single value or comma-separated list"
    )
    parser.add_argument(
        "--base-speed", dest="base_speed", default="400000",
        help="Base port speed to match when selecting ports (default: 400000)"
    )
    parser.add_argument(
        "--default-cable-length", dest="default_cable_length", default=None,
        help="Fallback cable length when base port has none (e.g., 40m)"
    )
    parser.add_argument(
        "--topo", dest="topo", default=None,
        help="Override device topology type (t0, t1, t2) for buffer defaults"
    )
    parser.add_argument(
        "--platform", dest="platform", default=None,
        help="Override platform name for device directory lookup"
    )
    parser.add_argument(
        "--hwsku", dest="hwsku", default=None,
        help="Override HwSKU for device directory lookup"
    )
    parser.add_argument(
        "--device-type", dest="device_type", default=None,
        help="Override DEVICE_METADATA.localhost.type for topology inference"
    )
    parser.add_argument(
        "--buffers-root", dest="buffers_root", default="/usr/share/sonic/device",
        help="Root directory for platform buffer files"
    )
    parser.add_argument(
        "--buffer-pool-override", dest="buffer_pool_override", default=None,
        help="JSON string or file path to apply to BUFFER_POOL"
    )
    parser.add_argument(
        "--collision-mode", dest="collision_mode", default="skip",
        choices=["skip", "fail"],
        help="Behavior when new port names already exist (default: skip)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        speed_list = parse_speed_list(args.breakout_speed, args.breakout_count)
    except ValueError as exc:
        _log("Error: {}".format(exc))
        return 1

    config = load_json(args.input_path)
    port_table = config.get("PORT")
    if not isinstance(port_table, dict):
        _log("Error: PORT table not found")
        return 1

    platform, hwsku, device_type = get_device_metadata(config)
    if args.platform:
        platform = args.platform
    if args.hwsku:
        hwsku = args.hwsku
    if args.device_type:
        device_type = args.device_type

    topo = args.topo or infer_topo(device_type)
    if not topo:
        _log("Warning: unable to infer topology type; buffer defaults may be skipped")

    device_dir = resolve_device_dir(platform, hwsku, args.buffers_root)
    if device_dir and not os.path.isdir(device_dir):
        _log("Warning: device directory not found: {}".format(device_dir))
        device_dir = None

    default_cable_length = args.default_cable_length
    if not default_cable_length and device_dir and topo:
        buffers_defaults_path = os.path.join(device_dir, "buffers_defaults_{}.j2".format(topo))
        default_cable_length = read_default_cable_length(buffers_defaults_path)
        if default_cable_length:
            _log("Detected default cable length: {}".format(default_cable_length))

    threshold_field = get_buffer_threshold_field(config)
    profile_lookup = {}
    if device_dir:
        pg_profile_path = os.path.join(device_dir, "pg_profile_lookup.ini")
        profile_lookup = load_pg_profile_lookup(pg_profile_path, threshold_field)
        if profile_lookup:
            _log("Loaded pg_profile_lookup entries: {}".format(len(profile_lookup)))
        else:
            _log("Warning: pg_profile_lookup.ini not found or empty")

    try:
        base_ports = select_base_ports(
            port_table,
            args.ports,
            args.breakout_total,
            args.breakout_count,
            args.base_speed,
        )
    except ValueError as exc:
        _log("Error: {}".format(exc))
        return 1

    alias_plan = build_alias_plan(port_table)

    breakout_map, added_ports = update_port_table(
        port_table,
        base_ports,
        args.breakout_count,
        speed_list,
        args.collision_mode,
        alias_plan,
    )

    ensure_unique_aliases(port_table)

    if not breakout_map:
        _log("No ports were broken out. Nothing to write.")
        return 1

    update_cable_length(config, breakout_map, default_cable_length, default_cable_length)
    update_queue_table(config, breakout_map)
    update_port_qos_map(config, breakout_map)
    update_acl_table(config, breakout_map)
    update_buffer_pg(config, breakout_map, default_cable_length, profile_lookup)
    update_buffer_queue(config, breakout_map)
    update_vlan_member(config, breakout_map)
    update_buffer_pool(config, args.buffer_pool_override)
    order_port_table(config)

    write_json(args.output_path, config)

    _log("Breakout complete. Base ports updated: {}".format(len(breakout_map)))
    _log("Additional ports created: {}".format(added_ports))
    _log("Wrote: {}".format(args.output_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
