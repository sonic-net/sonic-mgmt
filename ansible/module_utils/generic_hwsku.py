"""Offline Generic HWSKU coverage planning over recorded canonical expansions."""

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field, replace


SCHEMA_VERSION = 1
PLANNER_VERSION = "4"


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
    for key in ("name", "alias"):
        _text(result[key])
    for key in ("fec", "autoneg"):
        if result[key] is not None:
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
                         "dedicated", "port_capacity", "headroom_capacity", "cages"),
                ("port_credits", "headroom_credits"))
        item = copy.deepcopy(device)
        for key in ("name", "platform", "base_hwsku", "realized_hwsku", "image"):
            _text(item[key])
        _integer(item["asic_count"], 1)
        _integer(item["port_capacity"])
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
            _record(cage, ("name", "group", "protected_reason", "modes"), ("role", "media_speeds"))
            cage = copy.deepcopy(cage)
            cage["role"] = cage.get("role", "data")
            if cage["role"] not in ("data", "service"):
                raise InvalidInput("Cage role must be data or service")
            if "media_speeds" in cage:
                cage["media_speeds"] = sorted(_integer(speed, 1) for speed in _items(cage["media_speeds"], False))
                _unique(cage["media_speeds"], "media operating speeds")
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
                for key in ("name", "alias"):
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
            if cage["role"] == "service" and any(
                    len(mode["ports"]) != 1 or len(mode["ports"][0]["lanes"]) != 1 for mode in modes):
                raise InvalidInput("Service coverage requires single-lane, single-child cages")
            cages.append(cage)
        _unique([cage["name"] for cage in cages], "cage names")
        item["cages"] = sorted(cages, key=lambda cage: cage["name"])
        for credit_field in ("port_credits", "headroom_credits"):
            if credit_field in item:
                credits = item[credit_field]
                if not isinstance(credits, dict) or not set(credits) <= {cage["name"] for cage in cages}:
                    raise InvalidInput("Resource credits must name recorded cages")
                item[credit_field] = {name: _integer(value) for name, value in sorted(credits.items())}
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
    settings = {"access_vlan": 100, "routed_network": "198.18.0.0/16",
                "access_network": "198.19.0.0/16", "max_search_nodes": 100000}
    if len(result["supported_profiles"]) == 1:
        settings["profile"] = result["supported_profiles"][0]
    for layer in (defaults, group_settings, host_settings):
        if layer is not None:
            if not isinstance(layer, dict):
                raise InvalidInput("Settings layers must be dictionaries")
            settings.update(copy.deepcopy(layer))
    _record(settings, ("access_vlan", "routed_network", "access_network", "profile", "max_search_nodes"),
            ("min_subports", "routed_ports"))
    for key in ("min_subports", "routed_ports", "max_search_nodes"):
        if key in settings:
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
    if (routed.overlaps(access) or access.prefixlen > 30
            or routed.num_addresses < 2 * settings.get("routed_ports", 1)):
        raise InvalidInput("Address pools overlap or cannot supply routed pairs and an access gateway")
    result["settings"] = settings
    return result


def protected_cages(dut, devices, links):
    """Close declared exclusions over whole cages, shared groups and connected peers."""
    cages = {(device["name"], cage["name"]): cage for device in devices for cage in device["cages"]}
    protected = {key: {cage["protected_reason"]} for key, cage in cages.items() if cage["protected_reason"]}
    for link in links:
        if link["excluded_reason"]:
            for key in ((dut, link["dut_cage"]), (link["leaf"], link["leaf_cage"])):
                protected.setdefault(key, set()).add(link["excluded_reason"])
    changed = True
    while changed:
        before = {key: frozenset(reasons) for key, reasons in protected.items()}
        for key, cage in cages.items():
            reasons = set().union(*(value for other, value in before.items()
                                    if other[0] == key[0] and cages[other]["group"] == cage["group"]))
            if reasons:
                protected.setdefault(key, set()).update(reasons)
        for link in links:
            keys = ((dut, link["dut_cage"]), (link["leaf"], link["leaf_cage"]))
            reasons = set().union(*(protected.get(key, set()) for key in keys))
            if reasons:
                for key in keys:
                    protected.setdefault(key, set()).update(reasons)
        changed = before != {key: frozenset(reasons) for key, reasons in protected.items()}
    return {key: sorted(reasons) for key, reasons in sorted(protected.items())}


@dataclass(frozen=True)
class _Selection:
    modes: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    bindings: tuple = ()
    resources: frozenset = frozenset()
    headroom: dict = field(default_factory=dict)
    mode_counts: dict = field(default_factory=dict)
    lookup_pairs: frozenset = frozenset()
    service_mode_counts: dict = field(default_factory=dict)
    service_lookup_pairs: frozenset = frozenset()
    routed: int = 0
    access: int = 0


class _Planner:
    def __init__(self, inputs):
        self.inputs = inputs
        self.dut = inputs["dut"]
        self.settings = inputs["settings"]
        self.traffic_required = True
        self.devices = {device["name"]: device for device in inputs["devices"]}
        self.cages = {(device["name"], cage["name"]): cage
                      for device in inputs["devices"] for cage in device["cages"]}
        self.modes = {(key, mode["id"]): mode for key, cage in self.cages.items() for mode in cage["modes"]}
        self.links = {(link["dut_cage"], link["dut_channel"]):
                      (link["leaf"], link["leaf_cage"], link["leaf_channel"]) for link in inputs["links"]}
        self.lookup = {(row["speed"], row["cable"]): row for row in inputs["lookup"]}
        self.protected = self._protected_cages()
        self.service_cages = {key for key, cage in self.cages.items()
                              if key[0] == self.dut and key not in self.protected and cage["role"] == "service"}
        self.eligible_modes = sorted({(mode["name"], port["speed"])
                                      for key, cage in self.cages.items()
                                      if key[0] == self.dut and key not in self.protected
                                      for mode in cage["modes"] for port in mode["ports"]})
        if not self.eligible_modes:
            raise PrerequisiteError("No eligible controlled DUT modes remain after cage/group protection")
        eligible_speeds = {speed for _, speed in self.eligible_modes}
        all_speeds = {port["speed"] for cage in self.devices[self.dut]["cages"]
                      for mode in cage["modes"] for port in mode["ports"]}
        if any(speed not in all_speeds for speed, _ in self.lookup):
            raise PrerequisiteError("Unsupported lookup speeds require explicit evidence-backed exclusions")
        if any(speed not in {row["speed"] for row in inputs["lookup"]} for speed in eligible_speeds):
            raise PrerequisiteError("An eligible operating speed has no supported lookup row")
        self.eligible_lookup = sorted(pair for pair in self.lookup if pair[0] in eligible_speeds)
        self.options = [(key, mode) for key, cage in sorted(self.cages.items())
                        if key[0] == self.dut and key not in self.protected for mode in cage["modes"]]
        self.required_modes = sorted({(mode["name"], port["speed"]) for key, mode in self.options
                                      if key not in self.service_cages for port in mode["ports"]})
        if not self.required_modes:
            raise PrerequisiteError("No primary data-port modes remain")
        self.service_modes = sorted({(mode["name"], port["speed"]) for key, mode in self.options
                                     if key in self.service_cages for port in mode["ports"]})
        primary_speeds = {speed for _, speed in self.required_modes}
        service_speeds = {speed for _, speed in self.service_modes}
        self.required_lookup = [pair for pair in self.eligible_lookup if pair[0] in primary_speeds]
        self.service_lookup = [pair for pair in self.eligible_lookup if pair[0] in service_speeds]
        counts = {
            (name, speed): max(
                self.settings.get("min_subports", 1),
                sum(pair[0] == speed for pair in self.eligible_lookup),
                max(sum(port["speed"] == speed for port in mode["ports"])
                    for _, mode in self.options if mode["name"] == name))
            for name, speed in self.eligible_modes
        }
        self.required_counts = {pair: counts[pair] for pair in self.required_modes}
        self.service_counts = {pair: counts[pair] for pair in self.service_modes}
        self.peers = {(key, mode["id"], port["name"]): self._peer_candidates(key, port)
                      for key, mode in self.options for port in mode["ports"]}
        endpoints = inputs["endpoints"]
        self.traffic_capacity = min(
            len({endpoint["id"] for endpoint in endpoints}),
            len({endpoint["ptf_index"] for endpoint in endpoints}),
            len({endpoint["host_interface"] for endpoint in endpoints}),
            len({(endpoint["trunk"], endpoint["vlan"]) for endpoint in endpoints}))
        self.nodes = 0

    def _protected_cages(self):
        return protected_cages(self.dut, self.inputs["devices"], self.inputs["links"])

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
                        candidates.append((leaf_key, mode["id"], peer, cable, None))
        return sorted(candidates, key=lambda item: (
            item[0], item[1], item[2]["name"], item[4] is None,
            item[4]["ptf_index"] if item[4] else -1, item[3], item[4]["id"] if item[4] else ""))

    def _tick(self):
        self.nodes += 1
        if self.nodes > self.settings["max_search_nodes"]:
            raise SearchBudgetExceeded("Search exhausted {} nodes; feasibility is unknown".format(self.nodes - 1))

    def _budget(self, state, device, resource, optimistic=False):
        field = "port_credits" if resource == "port_capacity" else "headroom_credits"
        credits = self.devices[device].get(field, {})
        return self.devices[device][resource] + sum(
            value for cage, value in credits.items()
            if ((device, cage) not in self.protected if optimistic else (device, cage) in state.modes))

    def _port_count(self, state, device):
        return sum(len(self.modes[(key, value)]["ports"]) for key, value in state.modes.items()
                   if key[0] == device)

    def _add_mode(self, state, key, mode):
        media = self.cages[key].get("media_speeds")
        if key in self.protected or media is not None and any(port["speed"] not in media for port in mode["ports"]):
            return None
        if key in state.modes:
            return state if state.modes[key] == mode["id"] else None
        group = (key[0], self.cages[key]["group"])
        if group in state.groups and state.groups[group] != mode["group_mode"]:
            return None
        if self._port_count(state, key[0]) + len(mode["ports"]) > self._budget(
                state, key[0], "port_capacity", optimistic=True):
            return None
        modes, groups = dict(state.modes), dict(state.groups)
        modes[key], groups[group] = mode["id"], mode["group_mode"]
        return replace(state, modes=modes, groups=groups)

    def _add_binding(self, state, dut_key, mode, port, candidate, role):
        leaf_key, leaf_mode, peer, cable, endpoint = candidate
        if endpoint is None:
            if role != "l1":
                return None
        elif role not in endpoint["roles"] or endpoint["vlan"] == self.settings["access_vlan"]:
            return None
        if role == "routed" and (state.routed == self.settings.get(
                "routed_ports", ipaddress.IPv4Network(self.settings["routed_network"]).num_addresses // 2)):
            return None
        access_count = state.access + (role == "access")
        if access_count > ipaddress.IPv4Network(self.settings["access_network"]).num_addresses - 3:
            return None
        resources = {("dut", port["name"]), ("peer", leaf_key[0], peer["name"])}
        if endpoint is not None:
            resources.update({("endpoint", endpoint["id"]), ("ptf", endpoint["ptf_index"]),
                              ("vlan", endpoint["trunk"], endpoint["vlan"]),
                              ("host", endpoint["host_interface"])})
        if state.resources & resources:
            return None
        state = self._add_mode(state, leaf_key, self.modes[(leaf_key, leaf_mode)])
        if state is None:
            return None
        cost = self.lookup[(port["speed"], cable)]["headroom"]
        headroom = dict(state.headroom)
        for device in (self.dut, leaf_key[0]):
            headroom[device] = headroom.get(device, 0) + cost
            if headroom[device] > self._budget(state, device, "headroom_capacity", optimistic=True):
                return None
        binding = {"dut_cage": dut_key[1], "dut_port": port["name"], "dut_index": port["index"],
                   "leaf": leaf_key[0], "leaf_cage": leaf_key[1], "leaf_port": peer["name"],
                   "speed": port["speed"], "cable": cable, "role": role, "transport": endpoint}
        service = dut_key in self.service_cages
        counts = dict(state.service_mode_counts if service else state.mode_counts)
        coverage = (mode["name"], port["speed"])
        counts[coverage] = counts.get(coverage, 0) + 1
        return replace(state, bindings=state.bindings + (binding,), resources=state.resources | resources,
                       headroom=headroom,
                       mode_counts=state.mode_counts if service else counts,
                       service_mode_counts=counts if service else state.service_mode_counts,
                       lookup_pairs=state.lookup_pairs if service else state.lookup_pairs | {(port["speed"], cable)},
                       service_lookup_pairs=(state.service_lookup_pairs | {(port["speed"], cable)}
                                             if service else state.service_lookup_pairs),
                       routed=state.routed + (role == "routed"), access=access_count)

    def _assign_ports(self, state, key, mode, index=0):
        if index == len(mode["ports"]):
            yield state
            return
        port = mode["ports"][index]
        candidates = sorted(self.peers[(key, mode["id"], port["name"])], key=lambda item: (
            item[4] is None, (port["speed"], item[3]) in state.lookup_pairs,
            item[4]["ptf_index"] if item[4] else -1, item[0], item[1], item[2]["name"], item[3]))
        for candidate in candidates:
            if not self.traffic_required and candidate[4] is not None:
                continue
            roles = ("access", "routed") if state.routed and not state.access else ("routed", "access")
            for role in (("l1",) if candidate[4] is None else roles):
                self._tick()
                next_state = self._add_binding(state, key, mode, port, candidate, role)
                if next_state is not None:
                    yield from self._assign_ports(next_state, key, mode, index + 1)

    def _demands(self, state, require_traffic=None):
        demands = [(("mode", name, speed),
                    self.required_counts[(name, speed)] - state.mode_counts.get((name, speed), 0))
                   for name, speed in self.required_modes]
        demands.extend((("lookup", speed, cable), 1) for speed, cable in self.required_lookup
                       if (speed, cable) not in state.lookup_pairs)
        if self.traffic_required if require_traffic is None else require_traffic:
            demands.extend([(("routed",), self.settings.get("routed_ports", 1) - state.routed),
                            (("access",), 1 - state.access)])
        for device in self.devices:
            demands.extend([
                (("budget", device, "port_capacity"),
                 self._port_count(state, device) - self._budget(state, device, "port_capacity")),
                (("budget", device, "headroom_capacity"),
                 state.headroom.get(device, 0) - self._budget(state, device, "headroom_capacity")),
            ])
        return [(demand, count) for demand, count in demands if count > 0]

    def _contribution(self, key, mode, demand, state):
        if key in self.service_cages and demand[0] in ("mode", "lookup"):
            return 0
        peers = [(port, self.peers[(key, mode["id"], port["name"])]) for port in mode["ports"]]
        if any(not candidates for _, candidates in peers):
            return 0
        if demand[0] == "budget":
            device, resource = demand[1:]
            field = "port_credits" if resource == "port_capacity" else "headroom_credits"
            candidates = {key} if device == self.dut else {
                candidate[0] for _, options in peers for candidate in options
                if candidate[0][0] == device and candidate[0] not in state.modes}
            return sum(self.devices[device].get(field, {}).get(cage[1], 0) for cage in candidates)
        if demand[0] == "mode":
            return sum(mode["name"] == demand[1] and port["speed"] == demand[2] for port, _ in peers)
        if demand[0] == "lookup":
            return int(any(port["speed"] == demand[1] and any(candidate[3] == demand[2] for candidate in candidates)
                           for port, candidates in peers))
        return sum(any(candidate[4] is not None and demand[0] in candidate[4]["roles"] for candidate in candidates)
                   for _, candidates in peers)

    def search(self, state=None):
        state = _Selection() if state is None else state
        self._tick()
        if self.traffic_required and self.traffic_capacity < self.settings.get("routed_ports", 1) + 1:
            return None
        demands = self._demands(state)
        if not demands:
            return state
        ranked = []
        for demand, count in demands:
            options, capacity = [], {}
            for key, mode in self.options:
                if key in state.modes:
                    continue
                contribution = self._contribution(key, mode, demand, state)
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

    def complete_services(self, selected):
        """Maximize service coverage around the first feasible primary layout."""
        if not self.service_cages:
            return selected
        state = _Selection()
        for key, mode_id in sorted(selected.modes.items()):
            if key[0] == self.dut and key not in self.service_cages:
                state = self._add_mode(state, key, self.modes[(key, mode_id)])
        for binding in selected.bindings:
            key = (self.dut, binding["dut_cage"])
            if key in self.service_cages:
                continue
            mode = self.modes[(key, selected.modes[key])]
            port = next(port for port in mode["ports"] if port["name"] == binding["dut_port"])
            candidate = next(item for item in self.peers[(key, mode["id"], port["name"])]
                             if item[0] == (binding["leaf"], binding["leaf_cage"])
                             and item[1] == selected.modes[item[0]] and item[2]["name"] == binding["leaf_port"]
                             and item[3] == binding["cable"] and item[4] == binding["transport"])
            state = self._add_binding(state, key, mode, port, candidate, binding["role"])
            if state is None:
                raise PlanningError("Primary witness could not be replayed for service allocation")
        keys = sorted(self.service_cages)
        best, best_score = None, None

        def visit(index, candidate):
            nonlocal best, best_score
            self._tick()
            if index == len(keys):
                if self._demands(candidate):
                    return
                score = (sum(candidate.service_mode_counts.get(pair, 0) > 0 for pair in self.service_modes),
                         len(candidate.service_lookup_pairs & set(self.service_lookup)),
                         sum(min(candidate.service_mode_counts.get(pair, 0), count)
                             for pair, count in self.service_counts.items()),
                         sum(binding["transport"] is not None for binding in candidate.bindings
                             if (self.dut, binding["dut_cage"]) in self.service_cages))
                if best_score is None or score > best_score:
                    best, best_score = candidate, score
                return
            visit(index + 1, candidate)
            key = keys[index]
            for option_key, mode in self.options:
                if option_key != key:
                    continue
                added = self._add_mode(candidate, key, mode)
                if added is not None:
                    for assigned in self._assign_ports(added, key, mode):
                        visit(index + 1, assigned)

        visit(0, state)
        if best is None:
            raise PlanningError("Service allocation lost the existing primary/traffic witness")
        return best

    def _service_coverage(self, bindings, dut_modes):
        bindings = [row for row in bindings if (self.dut, row["dut_cage"]) in self.service_cages]
        modes = []
        for name, speed in self.service_modes:
            ports = sorted(row["dut_port"] for row in bindings
                           if row["speed"] == speed and dut_modes[row["dut_cage"]] == name)
            modes.append({"mode": name, "speed": speed, "requested_count": self.service_counts[name, speed],
                          "actual_count": len(ports), "ports": ports})
        lookup = [{"speed": speed, "cable": cable,
                   "ports": sorted(row["dut_port"] for row in bindings
                                   if (row["speed"], row["cable"]) == (speed, cable))}
                  for speed, cable in self.service_lookup]
        missing_modes = [row for row in modes if row["actual_count"] < row["requested_count"]]
        missing_lookup = [row for row in lookup if not row["ports"]]
        warnings = ([{"code": "SERVICE_COVERAGE_INCOMPLETE", "missing_modes": missing_modes,
                      "missing_lookup": missing_lookup}] if missing_modes or missing_lookup else [])
        return {"policy": "best_effort", "complete": not warnings, "modes": modes, "lookup": lookup,
                "warnings": warnings}

    def _exclusions(self):
        result = [{"kind": "cage", "device": key[0], "cage": key[1], "reasons": reasons}
                  for key, reasons in self.protected.items()]
        all_modes = {(mode["name"], port["speed"]) for cage in self.devices[self.dut]["cages"]
                     for mode in cage["modes"] for port in mode["ports"]}
        result.extend({"kind": "mode", "mode": name, "speed": speed, "reason": "protected cages only"}
                      for name, speed in sorted(all_modes - set(self.eligible_modes)))
        result.extend(dict(row, kind="lookup") for row in self.inputs["excluded_lookup"])
        result.extend({"kind": "lookup", "speed": speed, "cable": cable, "reason": "protected cages only"}
                      for speed, cable in sorted(set(self.lookup) - set(self.eligible_lookup)))
        return result

    def manifest(self, state):
        bindings = copy.deepcopy(sorted(state.bindings, key=lambda item: item["dut_port"]))
        routed_network = ipaddress.IPv4Network(self.settings["routed_network"])
        access_network = ipaddress.IPv4Network(self.settings["access_network"])
        routed_index, access_index = 0, 0
        for binding in bindings:
            if binding["role"] == "l1":
                continue
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
                                       and (self.dut, binding["dut_cage"]) not in self.service_cages
                                       and dut_modes[binding["dut_cage"]] == name)}
                      for name, speed in self.required_modes],
            "lookup": [{"speed": speed, "cable": cable,
                        "ports": sorted(binding["dut_port"] for binding in bindings
                                        if (binding["speed"], binding["cable"]) == (speed, cable)
                                        and (self.dut, binding["dut_cage"]) not in self.service_cages)}
                       for speed, cable in self.required_lookup],
        }
        coverage["service"] = self._service_coverage(bindings, dut_modes)
        coverage["complete"] = coverage["service"]["complete"]
        endpoints = [binding for binding in bindings if binding["transport"] is not None]
        paths = []
        if endpoints:
            anchor = next(binding["dut_port"] for binding in endpoints if binding["role"] == "routed")
            paths = sorted({path for binding in endpoints if binding["dut_port"] != anchor
                            for path in ((anchor, binding["dut_port"]), (binding["dut_port"], anchor))})
        coverage["unselected"] = {
            "modes": [{"mode": name, "speed": speed} for name, speed in
                      sorted(set(self.eligible_modes) - set(self.required_modes) - set(self.service_modes))],
            "lookup": [{"speed": speed, "cable": cable} for speed, cable in
                       sorted(set(self.eligible_lookup) - set(self.required_lookup) - set(self.service_lookup))],
        }
        coverage["traffic"] = {
            "ports": [binding["dut_port"] for binding in endpoints],
            "unavailable": [{"dut_port": binding["dut_port"],
                             "reason": "No independent routed/access transport assigned in the frozen layout"}
                            for binding in bindings if binding["transport"] is None],
            "complete": bool(bindings) and len(endpoints) == len(bindings),
        }
        manifest = {
            "schema_version": SCHEMA_VERSION, "planner_version": PLANNER_VERSION,
            "inputs_sha256": _digest(self.inputs), "sources": copy.deepcopy(self.inputs["sources"]),
            "devices": [{key: value for key, value in device.items() if key != "cages"}
                        for device in self.inputs["devices"]],
            "settings": copy.deepcopy(self.settings),
            "requirements": {"modes": [{"mode": name, "speed": speed, "count": self.required_counts[(name, speed)]}
                                       for name, speed in self.required_modes],
                             "lookup": [{"speed": speed, "cable": cable} for speed, cable in self.required_lookup],
                             "service": {
                                 "policy": "best_effort",
                                 "modes": [{"mode": name, "speed": speed,
                                            "requested_count": self.service_counts[name, speed]}
                                           for name, speed in self.service_modes],
                                 "lookup": [{"speed": speed, "cable": cable}
                                            for speed, cable in self.service_lookup]},
                             "routed_ports": state.routed,
                             "routed_ports_override": self.settings.get("routed_ports")},
            "exclusions": self._exclusions(), "layout": layout, "port_bindings": bindings,
            "endpoints": endpoints, "coverage": coverage,
            "traffic_cases": [{"id": "traffic-{}".format(index), "ingress": ingress, "egress": egress}
                              for index, (ingress, egress) in enumerate(paths)],
            "resources": {"headroom": dict(sorted(state.headroom.items())),
                          "available": {device: {
                              "ports": self._budget(state, device, "port_capacity"),
                              "headroom": self._budget(state, device, "headroom_capacity")}
                              for device in sorted(self.devices)}},
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
    if selected is None and "routed_ports" not in planner.settings:
        planner.traffic_required = False
        selected = planner.search()
    if selected is None:
        raise InfeasiblePlan("No complete layout satisfies mode/lookup coverage, peers and reserved resources")
    selected = planner.complete_services(selected)
    manifest = planner.manifest(selected)
    _validate_manifest(manifest, planner)
    return manifest


def _validate_manifest(manifest, planner):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("layout"), list):
        raise InvalidManifest("Missing manifest layout")
    if not isinstance(manifest.get("endpoints"), list):
        raise InvalidManifest("Missing manifest endpoints")
    if not isinstance(manifest.get("port_bindings"), list):
        raise InvalidManifest("Missing manifest physical port bindings")
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
            raise InvalidManifest("Protected, incompatible, media-limited or over-capacity layout")
    declared_modes = dict(state.modes)
    for binding in manifest["port_bindings"]:
        if (not isinstance(binding, dict) or "transport" not in binding
                or (binding["transport"] is not None and not isinstance(binding["transport"], dict))
                or not all(isinstance(binding.get(key), str) for key in
                           ("dut_cage", "dut_port", "leaf", "leaf_cage", "leaf_port", "cable", "role"))
                or (binding["transport"] is not None and not isinstance(binding["transport"].get("id"), str))):
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
                          and item[3] == binding["cable"]
                          and ((item[4] is None and binding["transport"] is None)
                               or (item[4] is not None and binding["transport"] is not None
                                   and item[4]["id"] == binding["transport"]["id"]))), None)
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
    require_traffic = bool(state.routed or state.access) or "routed_ports" in planner.settings
    if planner._demands(state, require_traffic) or serialized != canonical_json(planner.manifest(state)):
        raise InvalidManifest("Coverage, identity, addresses, witnesses or integrity digests disagree")


def validate_manifest(manifest, snapshot, defaults=None, group_settings=None, host_settings=None):
    """Independently replay constraints/witnesses without repeating the search."""
    planner = _Planner(normalize_inputs(snapshot, defaults, group_settings, host_settings))
    _validate_manifest(manifest, planner)
