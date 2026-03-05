import re
import logging

logger = logging.getLogger(__name__)


def get_flow_array(flow_table):
    flow_array = []
    for records in flow_table.values():
        flow_array.extend(records)
    return flow_array


def parse_pdsctl_show_flow_output(output):
    keys = [
        "Session", "LookupId", "Dir", "SIP", "DIP",
        "Proto", "Sport", "Dport", "Role", "Action"
    ]

    lines = output.strip().splitlines()

    flow_tables = {}
    current_table_id = None
    current_table_data = []

    for line in lines:
        if line.startswith('Flow-table-'):
            if current_table_id is not None and current_table_data:
                flow_tables[current_table_id] = current_table_data
            current_table_id = line.strip()
            current_table_data = []
        elif re.match(r'^\d+', line):
            elements = list(filter(None, line.split()))
            if len(elements) != len(keys):
                logger.warning("Column lenght mismatch")
                continue
            entry = dict(zip(keys, elements))
            current_table_data.append(entry)

    if current_table_id is not None and current_table_data:
        flow_tables[current_table_id] = current_table_data

    flow_array = get_flow_array(flow_tables)
    sorted_flow_array = sorted(flow_array, key=lambda x: int(x['Session']))

    return sorted_flow_array


def compare_flow_tables_pdsctl(dpuhost1, dpuhost2):
    if 'pensando' not in dpuhost1.facts['asic_type'] or 'pensando' not in dpuhost2.facts['asic_type']:
        logger.warning("Only Pensando is supported for this function")
        return False

    output1 = dpuhost1.shell("pdsctl show flow")["stdout"]
    output2 = dpuhost2.shell("pdsctl show flow")["stdout"]
    flow_table1 = parse_pdsctl_show_flow_output(output1)
    if (flow_table1 is None):
        logger.warning(f" flows table for {dpuhost1.hostname} is empty")
        return False

    flow_table2 = parse_pdsctl_show_flow_output(output2)
    if (flow_table2 is None):
        logger.warning(f" flows table for {dpuhost2.hostname} is empty")
        return False

    logger.debug(f"flows on primary: {flow_table1}")
    logger.debug(f"flows on standby: {flow_table2}")

    if flow_table1 == flow_table2:
        logger.info(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are identical")
        return True
    else:
        logger.warning(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are different")
        return False
