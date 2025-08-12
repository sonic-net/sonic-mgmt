import random
import re
import logging

logger = logging.getLogger(__name__)


def sum_ifaces_counts(counter_out, ifaces, column):
    if len(ifaces) == 0:
        return 0
    if len(ifaces) == 1:
        return int(counter_out[ifaces[0]][column].replace(",", ""))
    return sum([int(counter_out[iface][column].replace(",", "")) for iface in ifaces])


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
