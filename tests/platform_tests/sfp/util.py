import re
import logging
from tests.common.platform.interface_utils import get_port_map


def parse_output(output_lines):
    """
    @summary: For parsing command output. The output lines should have format 'key value'.
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        fields = line.split()
        if len(fields) != 2:
            continue
        res[fields[0]] = fields[1]
    return res


def parse_eeprom(output_lines):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        if re.match(r"^Ethernet\d+: .*", line):
            fields = line.split(":")
            res[fields[0]] = fields[1].strip()
    return res


def get_dev_conn(duthost, conn_graph_facts, asic_index):
    dev_conn = conn_graph_facts["device_conn"][duthost.hostname]

    # Get the interface pertaining to that asic
    portmap = get_port_map(duthost, asic_index)
    logging.info("Got portmap {}".format(portmap))

    if asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        dev_conn = {k: v for k, v in portmap.items() if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(asic_index, dev_conn))

    return portmap, dev_conn