"""FRR JSON helpers used by EVPN-MH tests."""

import ipaddress
import json
import re


class CommandJsonError(RuntimeError):
    """Base class for a failed FRR JSON query."""


class CommandUnavailableError(CommandJsonError):
    """The image does not implement a required FRR JSON command."""


class CommandExecutionError(CommandJsonError):
    """A supported FRR command failed at runtime."""


class InvalidCommandJsonError(CommandJsonError):
    """A command succeeded but returned malformed/non-JSON output."""


def command_json(duthost, command):
    result = duthost.shell("vtysh -c '{}'".format(command), module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        detail = "\n".join(str(result.get(field, ""))
                           for field in ("stderr", "stdout", "msg"))
        error_type = (CommandUnavailableError
                      if any(marker in detail.lower() for marker in (
                          "unknown command", "invalid input", "not found",
                          "unrecognized command"))
                      else CommandExecutionError)
        raise error_type("{} failed on {}: {}".format(
            command, duthost.hostname, detail.strip()))
    try:
        return json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise InvalidCommandJsonError(
            "{} returned invalid JSON on {}".format(
                command, duthost.hostname)) from error


def route_nexthop_count(routes):
    """Return the first installed route's active next-hop count.

    FRR has emitted both ``nexthops`` and ``paths[].nexthops`` layouts across
    releases, so walk the response rather than binding the test to one JSON
    nesting shape.  Inactive/dead entries never count toward the 3->2->1
    underlay contract.
    """
    for item in walk_json(routes):
        if not isinstance(item, dict) or not isinstance(item.get("nexthops"), list):
            continue
        nexthops = [
            nexthop for nexthop in item["nexthops"]
            if isinstance(nexthop, dict)
            and not nexthop.get("inactive", False)
            and not nexthop.get("dead", False)
            and str(nexthop.get("active", "true")).lower() not in ("false", "0")
        ]
        if nexthops:
            return len(nexthops)
    return 0


def walk_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


def scalar_strings(value):
    """Yield scalar JSON values and mapping keys as strings.

    FRR has represented EVPN NLRI both as ordinary fields and as route keys
    such as ``[3]:[0]:[32]:[10.1.0.3]``.  Looking at keys as well as values
    keeps the assertions schema-tolerant without falling back to a substring
    search over an entire JSON document.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from scalar_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_strings(child)
    elif value is not None:
        yield str(value)


def json_contains_value(value, expected):
    """Return whether an exact scalar or bracketed FRR route-key value exists."""
    expected = str(expected)
    return any(
        candidate == expected or "[{}]".format(expected) in candidate
        for candidate in scalar_strings(value)
    )


def _normalized_peer_address(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def peer_states(summary):
    """Return unique peer-address state, failing closed on disagreement."""
    observed = {}

    def state_from(details):
        for field in ("state", "peerState", "bgpState"):
            if field in details:
                return details[field]
        if "pfxRcd" in details:
            return "Established"
        return None

    def record(address, state):
        address = _normalized_peer_address(address)
        if address is None or state is None:
            return
        state = str(state).strip().lower()
        previous = observed.get(address)
        observed[address] = (
            state if previous is None or previous == state else "ambiguous"
        )

    for item in walk_json(summary):
        if not isinstance(item, dict):
            continue

        state = state_from(item)
        for field in (
                "peerAddress", "peer", "neighborAddress", "neighbor"):
            if field in item:
                record(item[field], state)
                break

        # Common FRR form: {"peers": {"10.1.0.32": {"state": ...}}}
        for address, details in item.items():
            if not isinstance(details, dict):
                continue
            record(
                address,
                state_from(details),
            )

    return observed


def established_peers(summary):
    return {
        address
        for address, state in peer_states(summary).items()
        if state == "established"
    }


def contains_prefix(routes, prefix):
    network, prefix_length = str(prefix).rsplit("/", 1)
    route_key_fragment = "[{}]:[{}]".format(prefix_length, network)
    for candidate in scalar_strings(routes):
        if candidate == str(prefix) or route_key_fragment in candidate:
            return True
    for item in walk_json(routes):
        if not isinstance(item, dict):
            continue
        if prefix in {str(value) for value in item.values()
                      if not isinstance(value, (dict, list))}:
            return True
        # FRR route JSON commonly splits a prefix into ip and ipLen instead
        # of returning the canonical address/prefix-length string.
        if "ip" in item and "ipLen" in item:
            if "{}/{}".format(item["ip"], item["ipLen"]) == prefix:
                return True
    return False


def vni_is_present(vnis, vni):
    """Match a VNI in the common list, keyed-map and detail JSON layouts."""
    expected = str(vni)
    for item in walk_json(vnis):
        if not isinstance(item, dict):
            continue
        for key in ("vni", "vniId", "vni_id"):
            if key in item and str(item[key]) == expected:
                return True
        if expected in {str(key) for key in item}:
            return True
    return False


def _shell_stdout(duthost, command):
    result = duthost.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise CommandExecutionError("{} failed on {}: {}".format(
            command, duthost.hostname,
            result.get("stderr", result.get("stdout", ""))))
    return result.get("stdout", "").strip()


def app_db_key_exists(duthost, key):
    return _shell_stdout(
        duthost, "sonic-db-cli APPL_DB EXISTS '{}'".format(key)) == "1"


def app_db_hget(duthost, key, field):
    return _shell_stdout(
        duthost,
        "sonic-db-cli APPL_DB HGET '{}' '{}'".format(key, field))


def app_db_route_nexthops(duthost, vrf, prefix):
    """Return exact APPL_DB next hops for a VRF route.

    Both the VRF-qualified and historical default-VRF key shapes are
    understood.  An absent route deliberately returns an empty set so callers
    can poll for convergence and then fail with the expected prefix in their
    assertion.
    """
    keys = ["ROUTE_TABLE:{}:{}".format(vrf, prefix)]
    if str(vrf).lower() in ("default", "default-vrf"):
        keys.append("ROUTE_TABLE:{}".format(prefix))
    for key in keys:
        if not app_db_key_exists(duthost, key):
            continue
        value = app_db_hget(duthost, key, "nexthop")
        return {part.strip() for part in value.split(",") if part.strip()}
    return set()


def neighbor_matches(duthost, vlan, ip, mac):
    """Require an exact IP-to-MAC neighbor on a tenant SVI."""
    output = _shell_stdout(
        duthost,
        "ip -j neigh show to {} dev Vlan{}".format(ip, vlan))
    try:
        entries = json.loads(output or "[]")
    except (TypeError, ValueError) as error:
        raise InvalidCommandJsonError(
            "ip neighbor returned invalid JSON on {}".format(
                duthost.hostname)) from error
    normalized = str(mac).lower().replace("-", ":")
    return any(
        str(entry.get("dst", "")) == str(ip)
        and str(entry.get("lladdr", "")).lower().replace("-", ":") == normalized
        and str(entry.get("state", "")).upper() not in ("FAILED", "INCOMPLETE")
        for entry in entries if isinstance(entry, dict)
    )


def ethernet_segment(segments, esi):
    normalized = esi.lower()
    for item in walk_json(segments):
        if not isinstance(item, dict):
            continue
        candidate = item.get("esi", item.get("ESI", ""))
        if str(candidate).lower() == normalized:
            return item
    return None


def segment_vteps(segment):
    values = []
    for key in ("vteps", "vtep", "remoteVteps", "remoteVtep"):
        value = segment.get(key)
        if isinstance(value, str):
            values.extend(part.strip() for part in value.split(",") if part.strip())
        elif isinstance(value, list):
            for part in value:
                if isinstance(part, dict):
                    address = part.get("vtep", part.get("address"))
                    if address is not None:
                        values.append(str(address))
                else:
                    values.append(str(part))
        elif isinstance(value, dict):
            if "vtep" in value:
                values.append(str(value["vtep"]))
            else:
                values.extend(str(part) for part in value.keys())
    return set(values)


def _segment_flags(segment):
    flags = segment.get("flags", [])
    if isinstance(flags, str):
        return {part.strip().lower() for part in re.split(r"[,\s]+", flags) if part.strip()}
    if isinstance(flags, dict):
        return {str(key).strip().lower() for key, enabled in flags.items() if enabled}
    if isinstance(flags, (list, tuple, set)):
        return {str(part).strip().lower() for part in flags}
    return set()


def _segment_locality(segment):
    """Return True for local, False for remote, or None when unproven."""
    flags = _segment_flags(segment)
    if flags:
        local = "local" in flags
        remote = "remote" in flags
        return local if local != remote else None

    if "local" in segment:
        value = segment["local"]
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in ("true", "yes", "1", "local"):
            return True
        if normalized in ("false", "no", "0", "remote"):
            return False
        return None

    value = str(segment.get("type", "")).strip()
    compact = value.upper()
    if re.fullmatch(r"[LRN]+", compact):
        local = "L" in compact
        remote = "R" in compact
        return local if local != remote else None
    tokens = {
        part for part in re.split(r"[,\s]+", value.lower()) if part
    }
    local = "local" in tokens
    remote = "remote" in tokens
    return local if local != remote else None


def segment_is_remote(segment):
    return _segment_locality(segment) is False


def segment_is_local(segment):
    return _segment_locality(segment) is True


def segment_is_df(segment):
    for key in ("dfStatus", "dfRole", "role", "isDf", "isDF"):
        if key not in segment:
            continue
        value = segment[key]
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("df", "true", "yes", "1")
    flags = _segment_flags(segment)
    if flags:
        return "local" in flags and "nondf" not in flags and "non-df" not in flags
    # FRR's summary type is a flag string: L=local, R=remote and N=non-DF.
    value = str(segment.get("type", "")).strip()
    compact = value.upper()
    if re.fullmatch(r"[LRN]+", compact) and "L" in compact:
        return "R" not in compact and "N" not in compact
    tokens = {
        part for part in re.split(r"[,\s]+", value.lower()) if part
    }
    if "local" in tokens:
        return "nondf" not in tokens and "non-df" not in tokens
    return False


def json_contains_host(routes, mac=None, ip=None):
    """Match a MAC/IP host in one FRR route object, not across unrelated routes."""
    normalized_mac = str(mac or "").lower().replace("-", ":")
    for item in walk_json(routes):
        if not isinstance(item, dict):
            continue
        values = {str(value).lower().replace("-", ":") for value in item.values()
                  if not isinstance(value, (dict, list))}
        if normalized_mac and normalized_mac not in values:
            continue
        if ip and str(ip).lower() not in values:
            continue
        return True
    return False
