"""Calculate DUT port configuration and PTF indices from canonical breakout data."""

import copy
import itertools
import re
from collections import Counter, defaultdict


def natural_key(name):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", name)]


def expand_modes(platform, breakout_parser):
    """Leave names, aliases, lane ordering and speed variants to SONiC's parser."""
    cages = {}
    for cage, properties in sorted(platform["interfaces"].items(), key=lambda item: natural_key(item[0])):
        choices = []
        for mode in sorted(properties["breakout_modes"]):
            parsed = breakout_parser(cage, mode, properties)
            entries = parsed._breakout_mode_entry
            for speeds in itertools.product(*(sorted(entry.supported_speed) for entry in entries)):
                variant = breakout_parser(cage, mode, properties)
                for entry, speed in zip(variant._breakout_mode_entry, speeds):
                    entry.default_speed = speed
                choices.append({"mode": mode, "ports": variant.get_config()})
        if not choices:
            raise ValueError("No breakout configuration for " + cage)
        cages[cage] = choices
    if not cages:
        raise ValueError("platform.json contains no interface capabilities")
    return cages


def read_lookup(text):
    cables = defaultdict(set)
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) < 2 or not fields[0].isdigit() or int(fields[0]) <= 0:
            raise ValueError("Invalid pg_profile_lookup row {}".format(number))
        cables[int(fields[0])].add(fields[1])
    if not cables:
        raise ValueError("pg_profile_lookup contains no speed/cable entries")
    return {speed: sorted(lengths, key=natural_key) for speed, lengths in cables.items()}


def _lanes(row):
    return frozenset(row["lanes"].split(","))


def _connected(name, row, connections, base_ports, base_indices, vlans):
    return (name in base_indices and base_indices[name] in vlans and name in connections
            and bool(base_ports[name].get("lanes"))
            and row["lanes"].split(",") == base_ports[name]["lanes"].split(",")
            and str(connections[name]["speed"]) == str(row["speed"]))


def select_modes(cages, cables, connections, base_ports, vlans, min_subports=0, max_nodes=100000):
    """Cover data-port mode/speed counts without changing the existing peer setup.

    Single-lane auxiliary cages keep a compatible baseline mode. On an entirely
    single-lane platform they are the data cages and participate in coverage.
    """
    if min_subports < 0:
        raise ValueError("min_subports must not be negative")
    base_indices = {name: index for index, name in enumerate(sorted(base_ports, key=natural_key))}
    widths = {cage: len(set().union(*(_lanes(row) for row in choices[0]["ports"].values())))
              for cage, choices in cages.items()}
    data_cages = {cage for cage, width in widths.items() if width > 1 or max(widths.values()) == 1}
    required = Counter()
    options = {}
    for cage, choices in cages.items():
        options[cage] = []
        for choice in choices:
            counts = Counter(int(row["speed"]) for row in choice["ports"].values())
            if cage in data_cages:
                for speed, count in counts.items():
                    if speed not in cables:
                        raise ValueError("No buffer lookup for advertised speed {}".format(speed))
                    demand = (choice["mode"], speed)
                    required[demand] = max(required[demand], count, len(cables[speed]), min_subports)
            contribution = Counter(
                (choice["mode"], int(row["speed"])) for name, row in choice["ports"].items()
                if _connected(name, row, connections, base_ports, base_indices, vlans))
            options[cage].append((choice, contribution))

    nodes = 0

    def search(selected, covered):
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            raise ValueError("Port layout search budget exceeded; no configuration was generated")
        unmet = [demand for demand, count in required.items() if covered[demand] < count]
        if not unmet:
            return selected
        remaining = {cage: choices for cage, choices in options.items()
                     if cage not in selected and cage in data_cages}
        candidates = {}
        for demand in unmet:
            upper = covered[demand] + sum(
                max(counts[demand] for _, counts in choices) for choices in remaining.values())
            if upper < required[demand]:
                return None
            candidates[demand] = [
                (cage, choice, counts) for cage, choices in remaining.items()
                for choice, counts in choices if counts[demand]]
        demand = min(unmet, key=lambda item: (len(candidates[item]), item))
        for cage, choice, counts in candidates[demand]:
            result = search(dict(selected, **{cage: choice}), covered + counts)
            if result is not None:
                return result
        return None

    selected = search({}, Counter())
    if selected is None:
        raise ValueError("DUT mode/speed counts cannot fit the existing wiring and port speeds")

    for cage, choices in options.items():
        if cage in selected:
            continue

        def preference(option):
            choice, counts = option
            baseline = all(name in base_ports
                           and all(str(row[key]) == str(base_ports[name][key]) for key in ("lanes", "speed"))
                           for name, row in choice["ports"].items())
            return (-sum(counts.values()), not baseline, len(choice["ports"]))

        selected[cage] = min(choices, key=preference)[0]
    return selected


def render_port_config(ports):
    """The full PORT attributes are also merged into the normal init_cfg.json."""
    columns = ["name", "lanes", "alias", "index", "speed"]
    if any("role" in row for row in ports.values()):
        columns.append("role")
    lines = ["# " + " ".join(columns)]
    for name in sorted(ports, key=natural_key):
        row = dict(ports[name], name=name)
        lines.append(" ".join(str(row.get(column, "Ext") if column == "role" else row[column])
                              for column in columns))
    return "\n".join(lines) + "\n"


def generate_port_config(cages, lookup, base_ports, connections, vlan_map, min_subports=0):
    """Return ordinary PORT/CABLE_LENGTH/BREAKOUT_CFG data and PTF VLAN indices."""
    cables = read_lookup(lookup)
    vlans = {int(index): vlan for index, vlan in vlan_map.items()}
    base_indices = {name: index for index, name in enumerate(sorted(base_ports, key=natural_key))}
    selected = select_modes(cages, cables, connections, base_ports, vlans, min_subports)
    ports = {}
    port_modes = {}
    for choice in selected.values():
        for name, row in choice["ports"].items():
            if name in ports:
                raise ValueError("Breakout configurations share port " + name)
            ports[name] = copy.deepcopy(row)
            port_modes[name] = choice["mode"]

    port_vlans = {}
    by_mode_speed = defaultdict(list)
    for index, name in enumerate(sorted(ports, key=natural_key)):
        row = ports[name]
        connected = _connected(name, row, connections, base_ports, base_indices, vlans)
        row["admin_status"] = "up" if connected else "down"
        if connected:
            port_vlans[index] = vlans[base_indices[name]]
        by_mode_speed[(port_modes[name], int(row["speed"]))].append((not connected, name))
    lengths = {}
    for (_, speed), names in by_mode_speed.items():
        if speed not in cables:
            raise ValueError("No buffer lookup for selected speed {}".format(speed))
        for index, (_, name) in enumerate(sorted(names, key=lambda item: (item[0], natural_key(item[1])))):
            lengths[name] = cables[speed][index % len(cables[speed])]

    return {
        "config": {
            "PORT": ports,
            "CABLE_LENGTH": {"AZURE": lengths},
            "BREAKOUT_CFG": {cage: {"brkout_mode": choice["mode"]} for cage, choice in selected.items()},
        },
        "port_config_ini": render_port_config(ports),
        "port_vlan_map": port_vlans,
    }
