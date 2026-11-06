"""Offline Generic HWSKU coverage planning over recorded canonical expansions."""

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field, replace


SCHEMA_VERSION = 1
PLANNER_VERSION = "1"


class PlanningError(ValueError):
    """Base class for explicit planning failures."""


class InvalidInput(PlanningError):
    """The recorded input does not satisfy the planner contract."""


class PrerequisiteError(PlanningError):
    """The recorded platform or reservation cannot support this workflow."""


class InfeasiblePlan(PlanningError):
    """The complete search proved that the required layout cannot fit."""


class SearchBudgetExceeded(PlanningError):
    """Search stopped without proving feasibility or infeasibility."""


class InvalidManifest(PlanningError):
    """A manifest disagrees with its inputs, witnesses or integrity digests."""


def canonical_json(value):
    """Serialize a snapshot or manifest without incidental ordering/whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _record(value, required, optional=()):
    if not isinstance(value, dict):
        raise InvalidInput("Expected a record with fields {}".format(required))
    missing, unknown = set(required) - set(value), set(value) - set(required) - set(optional)
    if missing or unknown:
        raise InvalidInput("Missing fields {}; unknown fields {}".format(
            sorted(missing), sorted(str(key) for key in unknown)))
    return value


def _text(value, empty=False):
    if not isinstance(value, str) or (not value and not empty) or value != value.strip():
        raise InvalidInput("Expected a non-padded string; got {!r}".format(value))
    return value


def _integer(value, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise InvalidInput("Integer outside [{}, {}]: {!r}".format(minimum, maximum, value))
    return value


def _items(value, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value):
        raise InvalidInput("Expected {}list".format("a nonempty " if nonempty else "a "))
    return value


def _unique(values, label):
    if len(set(values)) != len(values):
        raise InvalidInput("Duplicate {}".format(label))


def _sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise InvalidInput("Expected a lowercase SHA256 digest")
    return value


def _normalize_port(port):
    _record(port, ("name", "alias", "index", "lanes", "channels", "speed", "fec", "autoneg", "cables"))
    result = copy.deepcopy(port)
    for key in ("name", "alias", "fec", "autoneg"):
        _text(result[key])
    _integer(result["index"])
    _integer(result["speed"], 1)
    for key in ("lanes", "channels"):
        result[key] = [_integer(item) for item in _items(result[key])]
        _unique(result[key], key)
    # ASIC lane order is canonical parser output, not an unordered input set.
    result["channels"].sort()
    result["cables"] = sorted(_text(item) for item in _items(result["cables"]))
    _unique(result["cables"], "cable lengths")
    return result


def _normalize_devices(devices):
    result = []
    for device in _items(devices):
        _record(device, ("name", "platform", "base_hwsku", "realized_hwsku", "image", "asic_count",
                         "dedicated", "port_capacity", "headroom_capacity", "cages"))
        item = copy.deepcopy(device)
        for key in ("name", "platform", "base_hwsku", "realized_hwsku", "image"):
            _text(item[key])
        _integer(item["asic_count"], 1)
        _integer(item["port_capacity"], 1)
        _integer(item["headroom_capacity"])
        if type(item["dedicated"]) is not bool:
            raise InvalidInput("dedicated must be a boolean")
        if item["asic_count"] != 1 or not item["dedicated"]:
            raise PrerequisiteError("Only reserved single-ASIC devices are supported: " + item["name"])
        cages = []
        device_lanes = set()
        device_names = set()
        device_aliases = set()
        device_indices = set()
        for cage in _items(item["cages"]):
            _record(cage, ("name", "group", "protected_reason", "modes"))
            cage = copy.deepcopy(cage)
            for key in ("name", "group"):
                _text(cage[key])
            _text(cage["protected_reason"], empty=True)
            modes = []
            physical_lanes = None
            physical_channels = None
            names, aliases, indices = set(), set(), set()
            for mode in _items(cage["modes"]):
                _record(mode, ("id", "name", "group_mode", "ports"))
                mode = copy.deepcopy(mode)
                for key in ("id", "name", "group_mode"):
                    _text(mode[key])
                mode["ports"] = sorted((_normalize_port(port) for port in _items(mode["ports"])),
                                       key=lambda port: port["name"])
                for key in ("name", "alias", "index"):
                    _unique([port[key] for port in mode["ports"]], "port " + key)
                lanes = [lane for port in mode["ports"] for lane in port["lanes"]]
                channels = [channel for port in mode["ports"] for channel in port["channels"]]
                _unique(lanes, "lanes within an expansion")
                _unique(channels, "channels within an expansion")
                if physical_lanes is not None and (set(lanes) != physical_lanes
                                                   or set(channels) != physical_channels):
                    raise InvalidInput("Expansions must describe the same complete cage")
                physical_lanes, physical_channels = set(lanes), set(channels)
                names.update(port["name"] for port in mode["ports"])
                aliases.update(port["alias"] for port in mode["ports"])
                indices.update(port["index"] for port in mode["ports"])
                modes.append(mode)
            _unique([mode["id"] for mode in modes], "expansion IDs")
            if (device_lanes & physical_lanes or device_names & names
                    or device_aliases & aliases or device_indices & indices):
                raise InvalidInput("Different cages share ASIC lanes or port identities")
            device_lanes.update(physical_lanes)
            device_names.update(names)
            device_aliases.update(aliases)
            device_indices.update(indices)
            cage["modes"] = sorted(modes, key=lambda mode: (mode["name"], mode["id"]))
            cages.append(cage)
        _unique([cage["name"] for cage in cages], "cage names")
        item["cages"] = sorted(cages, key=lambda cage: cage["name"])
        result.append(item)
    _unique([device["name"] for device in result], "device names")
    return sorted(result, key=lambda device: device["name"])


def normalize_inputs(snapshot, defaults=None, group_settings=None, host_settings=None):
    """Validate recorded facts and merge settings DUT > group > shared defaults.

    All expansions must already have been produced by SONiC's canonical parser.
    This function does not read platform files, discover devices or infer lanes.
    """
    _record(snapshot, ("schema_version", "dut", "devices", "links", "endpoints", "lookup",
                       "supported_profiles", "sources"), ("excluded_lookup",))
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != SCHEMA_VERSION:
        raise InvalidInput("Unsupported snapshot schema version")
    result = copy.deepcopy(snapshot)
    result["dut"] = _text(result["dut"])
    result["devices"] = _normalize_devices(result["devices"])
    devices = {device["name"]: device for device in result["devices"]}
    if result["dut"] not in devices or len(devices) < 2:
        raise PrerequisiteError("A DUT and at least one dedicated leaf are required")
    if any(device["platform"] != devices[result["dut"]]["platform"] for device in devices.values()):
        raise PrerequisiteError("DUT and leaves must use the same verified platform")
    cages = {(device["name"], cage["name"]): cage
             for device in result["devices"] for cage in device["cages"]}
    channels = {key: set(channel for port in cage["modes"][0]["ports"] for channel in port["channels"])
                for key, cage in cages.items()}
    links = []
    for link in _items(result["links"], nonempty=False):
        _record(link, ("dut_cage", "dut_channel", "leaf", "leaf_cage", "leaf_channel", "excluded_reason"))
        link = copy.deepcopy(link)
        for key in ("dut_cage", "leaf", "leaf_cage"):
            _text(link[key])
        _text(link["excluded_reason"], empty=True)
        for key in ("dut_channel", "leaf_channel"):
            _integer(link[key])
        dut_key = (result["dut"], link["dut_cage"])
        leaf_key = (link["leaf"], link["leaf_cage"])
        if (link["leaf"] == result["dut"] or dut_key not in cages or leaf_key not in cages
                or link["dut_channel"] not in channels[dut_key] or link["leaf_channel"] not in channels[leaf_key]):
            raise InvalidInput("Link references an unknown physical channel")
        links.append(link)
    _unique([(link["dut_cage"], link["dut_channel"]) for link in links], "DUT channel connections")
    _unique([(link["leaf"], link["leaf_cage"], link["leaf_channel"]) for link in links],
            "leaf channel connections")
    result["links"] = sorted(links, key=canonical_json)
    endpoints = []
    for endpoint in _items(result["endpoints"], nonempty=False):
        _record(endpoint, ("id", "leaf", "cage", "channels", "ptf_index", "trunk", "vlan",
                           "host_interface", "roles"))
        endpoint = copy.deepcopy(endpoint)
        for key in ("id", "leaf", "cage", "trunk", "host_interface"):
            _text(endpoint[key])
        _integer(endpoint["ptf_index"])
        _integer(endpoint["vlan"], 1, 4094)
        endpoint["channels"] = sorted(_integer(channel) for channel in _items(endpoint["channels"]))
        _unique(endpoint["channels"], "transport channels")
        key = (endpoint["leaf"], endpoint["cage"])
        if (endpoint["leaf"] == result["dut"] or key not in channels
                or not set(endpoint["channels"]) <= channels[key]):
            raise InvalidInput("Endpoint references an unknown leaf channel")
        endpoint["roles"] = sorted(_text(role) for role in _items(endpoint["roles"]))
        _unique(endpoint["roles"], "endpoint roles")
        if not set(endpoint["roles"]) <= {"routed", "access"}:
            raise InvalidInput("Endpoint roles must be routed or access")
        endpoints.append(endpoint)
    _unique([endpoint["id"] for endpoint in endpoints], "endpoint IDs")
    result["endpoints"] = sorted(endpoints, key=lambda endpoint: endpoint["id"])
    lookup = []
    for row in _items(result["lookup"]):
        _record(row, ("speed", "cable", "headroom"))
        lookup.append({"speed": _integer(row["speed"], 1), "cable": _text(row["cable"]),
                       "headroom": _integer(row["headroom"])})
    _unique([(row["speed"], row["cable"]) for row in lookup], "lookup rows")
    result["lookup"] = sorted(lookup, key=lambda row: (row["speed"], row["cable"]))
    excluded = []
    for row in _items(result.get("excluded_lookup", []), nonempty=False):
        _record(row, ("speed", "cable", "reason", "evidence_sha256"))
        excluded.append({"speed": _integer(row["speed"], 1), "cable": _text(row["cable"]),
                         "reason": _text(row["reason"]), "evidence_sha256": _sha256(row["evidence_sha256"])})
    _unique([(row["speed"], row["cable"]) for row in lookup + excluded], "supported/excluded lookup rows")
    result["excluded_lookup"] = sorted(excluded, key=canonical_json)
    result["supported_profiles"] = sorted(_text(profile) for profile in _items(result["supported_profiles"]))
    _unique(result["supported_profiles"], "supported profiles")
    _record(result["sources"], ("capabilities", "parser", "links", "lookup", "policy"))
    result["sources"] = {key: _sha256(value) for key, value in result["sources"].items()}
    settings = {}
    for layer in (defaults, group_settings, host_settings):
        if layer is not None:
            if not isinstance(layer, dict):
                raise InvalidInput("Settings layers must be dictionaries")
            settings.update(copy.deepcopy(layer))
    _record(settings, ("min_subports", "routed_ports", "access_vlan", "routed_network",
                       "access_network", "profile", "max_search_nodes"))
    for key in ("min_subports", "routed_ports", "max_search_nodes"):
        _integer(settings[key], 1)
    _integer(settings["access_vlan"], 1, 4094)
    if _text(settings["profile"]) not in result["supported_profiles"]:
        raise PrerequisiteError("The selected buffer/QoS profile is not supported")
    networks = []
    for key in ("routed_network", "access_network"):
        try:
            network = ipaddress.IPv4Network(_text(settings[key]))
        except ValueError as error:
            raise InvalidInput("Invalid {}: {}".format(key, error)) from error
        settings[key] = str(network)
        networks.append(network)
    routed, access = networks
    if routed.overlaps(access) or access.prefixlen > 30 or routed.num_addresses < 2 * settings["routed_ports"]:
        raise InvalidInput("Address pools overlap or cannot supply routed pairs and an access gateway")
    result["settings"] = settings
    return result


@dataclass(frozen=True)
class _Selection:
    modes: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    bindings: tuple = ()
    resources: frozenset = frozenset()
    headroom: dict = field(default_factory=dict)
    mode_counts: dict = field(default_factory=dict)
    lookup_pairs: frozenset = frozenset()
    routed: int = 0


class _Planner:
    def __init__(self, inputs):
        self.inputs = inputs
        self.dut = inputs["dut"]
        self.settings = inputs["settings"]
        self.devices = {device["name"]: device for device in inputs["devices"]}
        self.cages = {(device["name"], cage["name"]): cage
                      for device in inputs["devices"] for cage in device["cages"]}
        self.modes = {(key, mode["id"]): mode for key, cage in self.cages.items() for mode in cage["modes"]}
        self.links = {(link["dut_cage"], link["dut_channel"]):
                      (link["leaf"], link["leaf_cage"], link["leaf_channel"]) for link in inputs["links"]}
        self.lookup = {(row["speed"], row["cable"]): row for row in inputs["lookup"]}
        self.protected = self._protected_cages()
        self.required_modes = sorted({(mode["name"], port["speed"])
                                      for key, cage in self.cages.items()
                                      if key[0] == self.dut and key not in self.protected
                                      for mode in cage["modes"] for port in mode["ports"]})
        eligible_speeds = {speed for _, speed in self.required_modes}
        all_speeds = {port["speed"] for cage in self.devices[self.dut]["cages"]
                      for mode in cage["modes"] for port in mode["ports"]}
        if any(speed not in all_speeds for speed, _ in self.lookup):
            raise PrerequisiteError("Unsupported lookup speeds require explicit evidence-backed exclusions")
        if any(speed not in {row["speed"] for row in inputs["lookup"]} for speed in eligible_speeds):
            raise PrerequisiteError("An eligible operating speed has no supported lookup row")
        self.required_lookup = sorted(pair for pair in self.lookup if pair[0] in eligible_speeds)
        self.options = [(key, mode) for key, cage in sorted(self.cages.items())
                        if key[0] == self.dut and key not in self.protected for mode in cage["modes"]]
        self.peers = {(key, mode["id"], port["name"]): self._peer_candidates(key, port)
                      for key, mode in self.options for port in mode["ports"]}
        self.nodes = 0

    def _protected_cages(self):
        protected = {key: {cage["protected_reason"]} for key, cage in self.cages.items() if cage["protected_reason"]}
        for link in self.inputs["links"]:
            if link["excluded_reason"]:
                for key in ((self.dut, link["dut_cage"]), (link["leaf"], link["leaf_cage"])):
                    protected.setdefault(key, set()).add(link["excluded_reason"])
        changed = True
        while changed:
            before = {key: frozenset(reasons) for key, reasons in protected.items()}
            for key, cage in self.cages.items():
                reasons = set().union(*(value for other, value in before.items()
                                        if other[0] == key[0] and self.cages[other]["group"] == cage["group"]))
                if reasons:
                    protected.setdefault(key, set()).update(reasons)
            for link in self.inputs["links"]:
                keys = ((self.dut, link["dut_cage"]), (link["leaf"], link["leaf_cage"]))
                reasons = set().union(*(protected.get(key, set()) for key in keys))
                if reasons:
                    for key in keys:
                        protected.setdefault(key, set()).update(reasons)
            changed = before != {key: frozenset(reasons) for key, reasons in protected.items()}
        return {key: sorted(reasons) for key, reasons in sorted(protected.items())}

    def _peer_candidates(self, dut_key, port):
        wires = [self.links.get((dut_key[1], channel)) for channel in port["channels"]]
        if any(wire is None for wire in wires) or len({wire[:2] for wire in wires}) != 1:
            return []
        leaf_key = wires[0][:2]
        if leaf_key in self.protected:
            return []
        mapped = {wire[2] for wire in wires}
        candidates = []
        for mode in self.cages[leaf_key]["modes"]:
            for peer in mode["ports"]:
                if set(peer["channels"]) != mapped or any(
                        peer[key] != port[key] for key in ("speed", "fec", "autoneg")):
                    continue
                cables = sorted(set(port["cables"]) & set(peer["cables"]))
                endpoints = [endpoint for endpoint in self.inputs["endpoints"]
                             if (endpoint["leaf"], endpoint["cage"]) == leaf_key
                             and set(endpoint["channels"]) <= mapped]
                for cable in cables:
                    if (port["speed"], cable) in self.lookup:
                        candidates.extend((leaf_key, mode["id"], peer, cable, endpoint) for endpoint in endpoints)
        return sorted(candidates, key=lambda item: (item[0], item[1], item[2]["name"], item[3], item[4]["id"]))

    def _tick(self):
        self.nodes += 1
        if self.nodes > self.settings["max_search_nodes"]:
            raise SearchBudgetExceeded("Search exhausted {} nodes; feasibility is unknown".format(self.nodes - 1))

    def _add_mode(self, state, key, mode):
        if key in self.protected:
            return None
        if key in state.modes:
            return state if state.modes[key] == mode["id"] else None
        group = (key[0], self.cages[key]["group"])
        if group in state.groups and state.groups[group] != mode["group_mode"]:
            return None
        port_count = sum(len(self.modes[(other, value)]["ports"]) for other, value in state.modes.items()
                         if other[0] == key[0])
        if port_count + len(mode["ports"]) > self.devices[key[0]]["port_capacity"]:
            return None
        modes, groups = dict(state.modes), dict(state.groups)
        modes[key], groups[group] = mode["id"], mode["group_mode"]
        return replace(state, modes=modes, groups=groups)

    def _add_binding(self, state, dut_key, mode, port, candidate, role):
        leaf_key, leaf_mode, peer, cable, endpoint = candidate
        if role not in endpoint["roles"] or (role == "routed" and state.routed == self.settings["routed_ports"]):
            return None
        access_count = len(state.bindings) - state.routed + (role == "access")
        if access_count > ipaddress.IPv4Network(self.settings["access_network"]).num_addresses - 3:
            return None
        resources = {("dut", port["name"]), ("peer", leaf_key[0], peer["name"]), ("endpoint", endpoint["id"]),
                     ("ptf", endpoint["ptf_index"]), ("vlan", endpoint["trunk"], endpoint["vlan"]),
                     ("host", endpoint["host_interface"])}
        if state.resources & resources:
            return None
        state = self._add_mode(state, leaf_key, self.modes[(leaf_key, leaf_mode)])
        if state is None:
            return None
        cost = self.lookup[(port["speed"], cable)]["headroom"]
        headroom = dict(state.headroom)
        for device in (self.dut, leaf_key[0]):
            headroom[device] = headroom.get(device, 0) + cost
            if headroom[device] > self.devices[device]["headroom_capacity"]:
                return None
        binding = {"dut_cage": dut_key[1], "dut_port": port["name"], "dut_index": port["index"],
                   "leaf": leaf_key[0], "leaf_cage": leaf_key[1], "leaf_port": peer["name"],
                   "speed": port["speed"], "cable": cable, "role": role, "transport": endpoint}
        counts = dict(state.mode_counts)
        coverage = (mode["name"], port["speed"])
        counts[coverage] = counts.get(coverage, 0) + 1
        return replace(state, bindings=state.bindings + (binding,), resources=state.resources | resources,
                       headroom=headroom, mode_counts=counts,
                       lookup_pairs=state.lookup_pairs | {(port["speed"], cable)},
                       routed=state.routed + (role == "routed"))

    def _assign_ports(self, state, key, mode, index=0):
        if index == len(mode["ports"]):
            yield state
            return
        port = mode["ports"][index]
        for candidate in self.peers[(key, mode["id"], port["name"])]:
            for role in ("routed", "access"):
                self._tick()
                next_state = self._add_binding(state, key, mode, port, candidate, role)
                if next_state is not None:
                    yield from self._assign_ports(next_state, key, mode, index + 1)

    def _demands(self, state):
        demands = [(("mode", name, speed), self.settings["min_subports"] - state.mode_counts.get((name, speed), 0))
                   for name, speed in self.required_modes]
        demands.extend((("lookup", speed, cable), 1) for speed, cable in self.required_lookup
                       if (speed, cable) not in state.lookup_pairs)
        demands.extend([(("routed",), self.settings["routed_ports"] - state.routed),
                        (("access",), 1 - (len(state.bindings) - state.routed))])
        return [(demand, count) for demand, count in demands if count > 0]

    def _contribution(self, key, mode, demand):
        peers = [(port, self.peers[(key, mode["id"], port["name"])]) for port in mode["ports"]]
        if any(not candidates for _, candidates in peers):
            return 0
        if demand[0] == "mode":
            return sum(mode["name"] == demand[1] and port["speed"] == demand[2] for port, _ in peers)
        if demand[0] == "lookup":
            return int(any(port["speed"] == demand[1] and any(candidate[3] == demand[2] for candidate in candidates)
                           for port, candidates in peers))
        return sum(any(demand[0] in candidate[4]["roles"] for candidate in candidates) for _, candidates in peers)

    def search(self, state=None):
        state = _Selection() if state is None else state
        self._tick()
        demands = self._demands(state)
        if not demands:
            return state
        ranked = []
        for demand, count in demands:
            options, capacity = [], {}
            for key, mode in self.options:
                if key in state.modes:
                    continue
                contribution = self._contribution(key, mode, demand)
                if contribution and self._add_mode(state, key, mode) is not None:
                    options.append((key, mode))
                    capacity[key] = max(capacity.get(key, 0), contribution)
            if sum(capacity.values()) < count:
                return None
            ranked.append((len(options), demand, options))
        _, _, options = min(ranked, key=lambda item: (item[0], item[1]))
        for key, mode in options:
            next_state = self._add_mode(state, key, mode)
            for assigned in self._assign_ports(next_state, key, mode):
                found = self.search(assigned)
                if found is not None:
                    return found
        return None

    def _exclusions(self):
        result = [{"kind": "cage", "device": key[0], "cage": key[1], "reasons": reasons}
                  for key, reasons in self.protected.items()]
        all_modes = {(mode["name"], port["speed"]) for cage in self.devices[self.dut]["cages"]
                     for mode in cage["modes"] for port in mode["ports"]}
        result.extend({"kind": "mode", "mode": name, "speed": speed, "reason": "protected cages only"}
                      for name, speed in sorted(all_modes - set(self.required_modes)))
        result.extend(dict(row, kind="lookup") for row in self.inputs["excluded_lookup"])
        result.extend({"kind": "lookup", "speed": speed, "cable": cable, "reason": "protected cages only"}
                      for speed, cable in sorted(set(self.lookup) - set(self.required_lookup)))
        return result

    def manifest(self, state):
        bindings = copy.deepcopy(sorted(state.bindings, key=lambda item: item["dut_port"]))
        routed_network = ipaddress.IPv4Network(self.settings["routed_network"])
        access_network = ipaddress.IPv4Network(self.settings["access_network"])
        routed_index, access_index = 0, 0
        for binding in bindings:
            if binding["role"] == "routed":
                address = int(routed_network.network_address) + 2 * routed_index
                binding["dut_address"] = str(ipaddress.IPv4Address(address)) + "/31"
                binding["ptf_address"] = str(ipaddress.IPv4Address(address + 1)) + "/31"
                routed_index += 1
            else:
                binding["dut_address"] = str(access_network.network_address + 1) + "/" + str(access_network.prefixlen)
                binding["ptf_address"] = str(access_network.network_address + 2 + access_index)
                binding["ptf_address"] += "/" + str(access_network.prefixlen)
                access_index += 1
        layout = []
        for key, mode_id in sorted(state.modes.items()):
            if key[0] == self.dut:
                active = {binding["dut_port"] for binding in bindings if binding["dut_cage"] == key[1]}
            else:
                active = {binding["leaf_port"] for binding in bindings
                          if (binding["leaf"], binding["leaf_cage"]) == key}
            mode = self.modes[(key, mode_id)]
            inactive = sorted(port["name"] for port in mode["ports"] if port["name"] not in active)
            layout.append({"device": key[0], "cage": key[1], "expansion": copy.deepcopy(mode),
                           "inactive_ports": inactive})
        dut_modes = {key[1]: self.modes[(key, mode_id)]["name"]
                     for key, mode_id in state.modes.items() if key[0] == self.dut}
        coverage = {
            "modes": [{"mode": name, "speed": speed,
                       "ports": sorted(binding["dut_port"] for binding in bindings if binding["speed"] == speed
                                       and dut_modes[binding["dut_cage"]] == name)}
                      for name, speed in self.required_modes],
            "lookup": [{"speed": speed, "cable": cable,
                        "ports": sorted(binding["dut_port"] for binding in bindings
                                        if (binding["speed"], binding["cable"]) == (speed, cable))}
                       for speed, cable in self.required_lookup],
        }
        anchor = next(binding["dut_port"] for binding in bindings if binding["role"] == "routed")
        paths = sorted({path for binding in bindings if binding["dut_port"] != anchor
                        for path in ((anchor, binding["dut_port"]), (binding["dut_port"], anchor))})
        manifest = {
            "schema_version": SCHEMA_VERSION, "planner_version": PLANNER_VERSION,
            "inputs_sha256": _digest(self.inputs), "sources": copy.deepcopy(self.inputs["sources"]),
            "devices": [{key: value for key, value in device.items() if key != "cages"}
                        for device in self.inputs["devices"]],
            "settings": copy.deepcopy(self.settings),
            "requirements": {"modes": [{"mode": name, "speed": speed, "count": self.settings["min_subports"]}
                                       for name, speed in self.required_modes],
                             "lookup": [{"speed": speed, "cable": cable} for speed, cable in self.required_lookup],
                             "routed_ports": self.settings["routed_ports"]},
            "exclusions": self._exclusions(), "layout": layout, "endpoints": bindings, "coverage": coverage,
            "traffic_cases": [{"id": "traffic-{}".format(index), "ingress": ingress, "egress": egress}
                              for index, (ingress, egress) in enumerate(paths)],
            "resources": {"headroom": dict(sorted(state.headroom.items()))},
            "integrity": {"layout_sha256": _digest(layout), "mapping_sha256": _digest(bindings)},
        }
        manifest["scenario_id"] = manifest["inputs_sha256"][:16] + "-" + manifest["integrity"]["layout_sha256"][:16]
        manifest["integrity"]["manifest_sha256"] = _digest(manifest)
        return manifest


def plan_scenario(snapshot, defaults=None, group_settings=None, host_settings=None):
    """Return one complete manifest, or raise a typed failure; never write devices."""
    inputs = normalize_inputs(snapshot, defaults, group_settings, host_settings)
    planner = _Planner(inputs)
    selected = planner.search()
    if selected is None:
        raise InfeasiblePlan("No complete layout satisfies mode/lookup coverage, peers and reserved resources")
    manifest = planner.manifest(selected)
    _validate_manifest(manifest, planner)
    return manifest


def _validate_manifest(manifest, planner):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("layout"), list):
        raise InvalidManifest("Missing manifest layout")
    if not isinstance(manifest.get("endpoints"), list):
        raise InvalidManifest("Missing manifest endpoints")
    state = _Selection()
    for entry in manifest["layout"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("expansion"), dict):
            raise InvalidManifest("Malformed layout entry")
        device, cage, mode_id = entry.get("device"), entry.get("cage"), entry["expansion"].get("id")
        if not all(isinstance(value, str) for value in (device, cage, mode_id)):
            raise InvalidManifest("Malformed layout identity")
        key = (device, cage)
        if key in state.modes or (key, mode_id) not in planner.modes:
            raise InvalidManifest("Duplicate or unknown layout selection")
        state = planner._add_mode(state, key, planner.modes[(key, mode_id)])
        if state is None:
            raise InvalidManifest("Protected, incompatible or over-capacity layout")
    declared_modes = dict(state.modes)
    for binding in manifest["endpoints"]:
        if (not isinstance(binding, dict) or not isinstance(binding.get("transport"), dict)
                or not all(isinstance(binding.get(key), str) for key in
                           ("dut_cage", "dut_port", "leaf", "leaf_cage", "leaf_port", "cable", "role"))
                or not isinstance(binding["transport"].get("id"), str)):
            raise InvalidManifest("Malformed endpoint binding")
        dut_key = (planner.dut, binding["dut_cage"])
        if dut_key not in declared_modes:
            raise InvalidManifest("Endpoint has no declared DUT expansion")
        mode_id = declared_modes[dut_key]
        mode = planner.modes[(dut_key, mode_id)]
        ports = {port["name"]: port for port in mode["ports"]}
        if binding["dut_port"] not in ports:
            raise InvalidManifest("Endpoint has no declared DUT child")
        candidates = planner.peers.get((dut_key, mode_id, binding["dut_port"]), [])
        candidate = next((item for item in candidates
                          if item[0] == (binding["leaf"], binding["leaf_cage"])
                          and declared_modes.get(item[0]) == item[1] and item[2]["name"] == binding["leaf_port"]
                          and item[3] == binding["cable"] and item[4]["id"] == binding["transport"]["id"]), None)
        if candidate is None:
            raise InvalidManifest("Endpoint disagrees with canonical ports, physical channels or lookup")
        state = planner._add_binding(state, dut_key, mode, ports[binding["dut_port"]], candidate, binding["role"])
        if state is None:
            raise InvalidManifest("Duplicate or over-capacity endpoint/resource assignment")
    for key, mode_id in declared_modes.items():
        if key[0] == planner.dut:
            actual = {binding["dut_port"] for binding in state.bindings if binding["dut_cage"] == key[1]}
            if actual != {port["name"] for port in planner.modes[(key, mode_id)]["ports"]}:
                raise InvalidManifest("A selected DUT child is unconnected")
        elif not any((binding["leaf"], binding["leaf_cage"]) == key for binding in state.bindings):
            raise InvalidManifest("Unused leaf expansion")
    try:
        serialized = canonical_json(manifest)
    except (TypeError, ValueError) as error:
        raise InvalidManifest("Manifest is not canonical JSON: {}".format(error)) from error
    if planner._demands(state) or serialized != canonical_json(planner.manifest(state)):
        raise InvalidManifest("Coverage, identity, addresses, witnesses or integrity digests disagree")


def validate_manifest(manifest, snapshot, defaults=None, group_settings=None, host_settings=None):
    """Independently replay constraints/witnesses without repeating the search."""
    planner = _Planner(normalize_inputs(snapshot, defaults, group_settings, host_settings))
    _validate_manifest(manifest, planner)
