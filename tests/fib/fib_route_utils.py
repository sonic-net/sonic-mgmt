import re
from collections import namedtuple


DEFAULT_ROUTE_READ_ERROR = "READ_ERROR"
DEFAULT_ROUTE_MALFORMED = "MALFORMED"
DEFAULT_ROUTE_MISSING = "MISSING"
DEFAULT_ROUTE_SINGLE = "SINGLE"
DEFAULT_ROUTE_ECMP = "ECMP"

DEFAULT_ROUTE_PREFIXES = {
    "ipv4": "0.0.0.0/0",
    "ipv6": "::/0",
}

DefaultRouteInfo = namedtuple("DefaultRouteInfo", ["state", "nexthops", "detail"])


def classify_default_route_output(command_result, ipver):
    """Classify one address family's default route from a generated FIB file."""
    if ipver not in DEFAULT_ROUTE_PREFIXES:
        raise ValueError("Unsupported address family: {}".format(ipver))

    if command_result.get("rc", 0) != 0:
        detail = command_result.get("stderr") or command_result.get("stdout") or "unknown read error"
        return DefaultRouteInfo(DEFAULT_ROUTE_READ_ERROR, [], detail)

    lines = command_result.get("stdout_lines")
    if lines is None:
        lines = command_result.get("stdout", "").splitlines()

    prefix = DEFAULT_ROUTE_PREFIXES[ipver]
    route_lines = [
        line.strip()
        for line in lines
        if line.strip() and line.strip().split(None, 1)[0] == prefix
    ]
    if not route_lines:
        return DefaultRouteInfo(
            DEFAULT_ROUTE_MISSING,
            [],
            "{} is absent".format(prefix),
        )
    if len(route_lines) != 1:
        return DefaultRouteInfo(
            DEFAULT_ROUTE_MALFORMED,
            [],
            "{} appears {} times".format(prefix, len(route_lines)),
        )

    route_line = route_lines[0]
    suffix = route_line[len(prefix):].strip()
    groups = re.findall(r"\[([^\]]*)\]", suffix)
    normalized_suffix = " ".join("[{}]".format(group) for group in groups)
    if not suffix or normalized_suffix != suffix:
        return DefaultRouteInfo(
            DEFAULT_ROUTE_MALFORMED,
            [],
            "invalid route line: {}".format(route_line),
        )

    nexthops = []
    for group in groups:
        ports = group.split()
        if not ports or any(not port.isdigit() for port in ports):
            return DefaultRouteInfo(
                DEFAULT_ROUTE_MALFORMED,
                [],
                "invalid nexthop group in route line: {}".format(route_line),
            )
        nexthops.append([int(port) for port in ports])

    if len(nexthops) == 1:
        return DefaultRouteInfo(DEFAULT_ROUTE_SINGLE, nexthops, route_line)
    if len(nexthops) > 1:
        return DefaultRouteInfo(DEFAULT_ROUTE_ECMP, nexthops, route_line)

    return DefaultRouteInfo(
        DEFAULT_ROUTE_MALFORMED,
        [],
        "default route has no usable nexthops: {}".format(route_line),
    )
