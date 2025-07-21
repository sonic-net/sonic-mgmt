import random
import re
import logging
from tests.common.portstat_utilities import parse_column_positions

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


def parse_rif_counters(output_lines):
    """Parse the output of "show interfaces counters rif" command
    Args:
        output_lines (list): The output lines of "show interfaces counters rif" command
    Returns:
        list: A dictionary, key is interface name, value is a dictionary of fields/values
    """

    header_line = ''
    separation_line = ''
    separation_line_number = 0
    for idx, line in enumerate(output_lines):
        if line.find('----') >= 0:
            header_line = output_lines[idx - 1]
            separation_line = output_lines[idx]
            separation_line_number = idx
            break

    try:
        positions = parse_column_positions(separation_line)
    except Exception:
        logger.error('Possibly bad command output')
        return {}

    headers = []
    for pos in positions:
        header = header_line[pos[0]:pos[1]].strip().lower()
        headers.append(header)

    if not headers:
        return {}

    results = {}
    for line in output_lines[separation_line_number + 1:]:
        portstats = []
        for pos in positions:
            portstat = line[pos[0]:pos[1]].strip()
            portstats.append(portstat)

        intf = portstats[0]
        results[intf] = {}
        for idx in range(1, len(portstats)):  # Skip the first column interface name
            results[intf][headers[idx]] = portstats[idx].replace(',', '')

    return results


def random_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                        random.randint(0, 255),
                                        random.randint(0, 255))
