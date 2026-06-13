import random
import re
import logging

logger = logging.getLogger(__name__)

# Placeholder values that show/portstat counter columns may report when a
# counter has not been initialized yet (e.g. an interface that has not seen
# traffic). These are not numbers and must be treated as zero instead of being
# passed to int(), which would raise ValueError: invalid literal for int().
NON_NUMERIC_COUNTER_VALUES = ("N/A", "n/a", "-", "")


def safe_int_counter(value):
    """Convert a counter cell from show/portstat output into an int.

    Counter columns occasionally report non-numeric placeholders such as
    'N/A' for uninitialized counters. Treat those as 0 so callers do not crash
    with a ValueError when parsing the value.
    """
    if value is None:
        return 0
    cleaned = str(value).strip().replace(",", "")
    if cleaned in NON_NUMERIC_COUNTER_VALUES:
        return 0
    try:
        return int(cleaned)
    except ValueError:
        logger.warning("Unexpected non-numeric counter value %r, treating as 0", value)
        return 0


def sum_ifaces_counts(counter_out, ifaces, column):
    if len(ifaces) == 0:
        return 0
    if len(ifaces) == 1:
        return safe_int_counter(counter_out[ifaces[0]][column])
    return sum([safe_int_counter(counter_out[iface][column]) for iface in ifaces])


def parse_interfaces(output_lines, pc_ports_map):
    """
    Parse the interfaces from 'show ip route' into an array
    """
    route_targets = []
    ifaces = []
    output_lines = output_lines[3:]

    for item in output_lines:
        match = re.search(r"(Ethernet\d+|PortChannel\d+)", item)
        if match:
            route_targets.append(match.group(0))

    for route_target in route_targets:
        if route_target.startswith("Ethernet"):
            ifaces.append(route_target)
        elif route_target.startswith("PortChannel") and route_target in pc_ports_map:
            ifaces.extend(pc_ports_map[route_target])

    return route_targets, ifaces


def random_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                        random.randint(0, 255),
                                        random.randint(0, 255))
