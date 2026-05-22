import re
import logging
import json
from pprint import pformat

logger = logging.getLogger(__name__)


def get_flow_array(flow_table):
    flow_array = []
    for records in flow_table.values():
        flow_array.extend(records)
    return flow_array


def parse_pdsctl_show_flow_output(output):
    keys = [
        "Session", "LookupId", "Dir", "SIP", "DIP",
        "Proto", "Sport", "Dport", "Role", "Action", "Vni", "RegionId"
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
                logger.warning(f"Column length mismatch: elements {len(elements)}, keys {len(keys)}")
                continue
            entry = dict(zip(keys, elements))
            current_table_data.append(entry)

    if current_table_id is not None and current_table_data:
        flow_tables[current_table_id] = current_table_data

    flow_array = get_flow_array(flow_tables)
    sorted_flow_array = sorted(flow_array, key=lambda x: int(x['Session']))

    return sorted_flow_array


FLOW_KEY_FIELDS = (
    "ENI_MAC", "VNET_ID", "SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "IP_PROTO"
)
IGNORE_FIELDS = {
    "EPOCH",
    "SAI_FLOW_ENTRY_ATTR_UNDERLAY0_SMAC",
    "SAI_FLOW_ENTRY_ATTR_UNDERLAY0_DMAC",
    # TODO: currently ignore version because it has bug waiting for fix
    "SAI_FLOW_ENTRY_ATTR_VERSION",
}

SONIC_DPU_FLOW_DUMP_MAX_FLOWS_DEFAULT = 1024


def flow_key(flow):
    return tuple(flow[field] for field in FLOW_KEY_FIELDS)


def format_flow_key(key):
    return dict(zip(FLOW_KEY_FIELDS, key))


def comparable_flow(flow):
    return {
        k: v
        for k, v in flow.items()
        if k not in IGNORE_FIELDS
    }


def parse_sonic_dpu_flow_dump_output(output):
    """
    Return dict of flows, None if failed to parse
    """
    result = {}
    if not output:
        return result
    try:
        flows = json.loads(output)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse sonic-dpu-flow-dump output: {output}")
        return None

    for flow in flows:
        key = flow_key(flow)
        result[key] = comparable_flow(flow)
    return result


def log_flow_map_diff(flow_map1, flow_map2, host1, host2):
    only_on_1 = [format_flow_key(k) for k in flow_map1.keys() - flow_map2.keys()]
    only_on_2 = [format_flow_key(k) for k in flow_map2.keys() - flow_map1.keys()]
    attr_diffs = []
    for k in flow_map1.keys() & flow_map2.keys():
        if flow_map1[k] == flow_map2[k]:
            continue
        differing_fields = {
            field: (flow_map1[k].get(field), flow_map2[k].get(field))
            for field in flow_map1[k].keys() | flow_map2[k].keys()
            if flow_map1[k].get(field) != flow_map2[k].get(field)
        }
        attr_diffs.append({
            "flow": format_flow_key(k),
            "differing_fields": differing_fields,
        })
    logger.warning(f" flows only on {host1}:\n{pformat(only_on_1, sort_dicts=False, width=120)}")
    logger.warning(f" flows only on {host2}:\n{pformat(only_on_2, sort_dicts=False, width=120)}")
    logger.warning(f" flows with attribute differences:\n{pformat(attr_diffs, sort_dicts=False, width=120)}")


def compare_flow_tables_sonic_dpu_flow_dump(
    dpuhost1, dpuhost2, max_flows, verbose=True, include_flow_state=False,
    min_expected_flows=None,
):
    parts = ["sudo", "sonic-dpu-flow-dump.py"]
    if not include_flow_state:
        parts.append("--no-flow-state")
    parts.append("-m")
    parts.append(str(int(max_flows)))
    dump_cmd = " ".join(parts)
    output1 = dpuhost1.shell(dump_cmd)["stdout"]
    output2 = dpuhost2.shell(dump_cmd)["stdout"]

    if verbose:
        logger.info(f"dump on {dpuhost1.hostname}:\n{output1}")
        logger.info(f"dump on {dpuhost2.hostname}:\n{output2}")

    flow_map1 = parse_sonic_dpu_flow_dump_output(output1)
    if flow_map1 is None:
        logger.warning(f" flows table for {dpuhost1.hostname} is None")
        return False

    flow_map2 = parse_sonic_dpu_flow_dump_output(output2)
    if flow_map2 is None:
        logger.warning(f" flows table for {dpuhost2.hostname} is None")
        return False

    if min_expected_flows is not None and min_expected_flows > 0:

        if len(flow_map1) < min_expected_flows:
            logger.warning(
                "%s: parsed flow count %s < min_expected_flows %s",
                dpuhost1.hostname,
                len(flow_map1),
                min_expected_flows,
            )
            return False

        if len(flow_map2) < min_expected_flows:
            logger.warning(
                "%s: parsed flow count %s < min_expected_flows %s",
                dpuhost2.hostname,
                len(flow_map2),
                min_expected_flows,
            )
            return False

    if flow_map1 == flow_map2:
        logger.info(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are identical")
        return True
    else:
        logger.warning(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are different")
        log_flow_map_diff(flow_map1, flow_map2, dpuhost1.hostname, dpuhost2.hostname)
        return False


def compare_flow_tables_pdsctl(dpuhost1, dpuhost2, verbose=True):
    output1 = dpuhost1.shell("pdsctl show flow")["stdout"]
    output2 = dpuhost2.shell("pdsctl show flow")["stdout"]
    flow_table1 = parse_pdsctl_show_flow_output(output1)
    if (flow_table1 is None or len(flow_table1) == 0):
        logger.warning(f" flows table for {dpuhost1.hostname} is empty")
        return False

    flow_table2 = parse_pdsctl_show_flow_output(output2)
    if (flow_table2 is None or len(flow_table2) == 0):
        logger.warning(f" flows table for {dpuhost2.hostname} is empty")
        return False

    if verbose:
        logger.info(f"flows on primary: {flow_table1}")
        logger.info(f"flows on standby: {flow_table2}")

    def without_session(flow_list):
        return [{k: v for k, v in entry.items() if k != 'Session'} for entry in flow_list]

    if without_session(flow_table1) == without_session(flow_table2):
        logger.info(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are identical (ignoring Session id)")
        return True
    else:
        logger.warning(f" flows for {dpuhost1.hostname} and {dpuhost2.hostname} are different")
        return False


def compare_flow_tables(dpuhost1, dpuhost2, verbose=True, **kwargs):
    """
    Compare flow tables between two DPU hosts (sonic-dpu-flow-dump on non-Pensando).

    Optional kwargs: max_flows (int, default SONIC_DPU_FLOW_DUMP_MAX_FLOWS_DEFAULT),
    flow_state (bool, default False — False adds --no-flow-state to the dump command).
    min_expected_flows (int, optional) — for sonic-dpu-flow-dump only: require at least this
    many flows on each DPU after parse (and non-empty stdout) before treating equality as success.
    """
    max_flows = kwargs.pop("max_flows", None)
    flow_state = kwargs.pop("flow_state", None)
    min_expected_flows = kwargs.pop("min_expected_flows", None)
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError("compare_flow_tables() got unexpected keyword arguments: %s" % unexpected)

    if max_flows is None:
        max_flows = SONIC_DPU_FLOW_DUMP_MAX_FLOWS_DEFAULT
    if flow_state is None:
        flow_state = False

    include_flow_state = bool(flow_state)

    if 'pensando' not in dpuhost1.facts['asic_type'] or 'pensando' not in dpuhost2.facts['asic_type']:
        logger.info("not pensando, using sonic-dpu-flow-dump.py")
        return compare_flow_tables_sonic_dpu_flow_dump(
            dpuhost1,
            dpuhost2,
            verbose=verbose,
            max_flows=max_flows,
            include_flow_state=include_flow_state,
            min_expected_flows=min_expected_flows,
        )
    else:
        return compare_flow_tables_pdsctl(dpuhost1, dpuhost2, verbose=verbose)
