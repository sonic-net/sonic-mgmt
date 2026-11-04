"""Read and clear SONiC WRED/ECN queue counters.

CLI reference:
    show queue wredcounters --json [-n <asic>] [<port>] [--nonzero] [--voq]
    sonic-clear queue wredcounters

Counterpoll for wredqueue/wredport must be enabled before these counters
report data. For snappi ECN tests that is handled by the
``enable_wred_ecn_counterpoll`` fixture in ``tests/snappi_tests/ecn/``.
"""

import json

import pytest

from tests.common.helpers.assertions import pytest_assert


def _parse_int_counter(value):
    s = str(value).strip().replace(',', '')
    if s == '' or s.upper() == 'N/A':
        return 0
    return int(s)


def _txq_from_priority(priority, voq=False):
    """
    Map priority argument to TxQ label used by 'show queue wredcounters --json'.
    Args:
        priority (int/str/None): e.g. 3 -> 'UC3' or 'VOQ3', 'UC3' -> 'UC3'
        voq (bool): when True, numeric priority maps to VOQ<n>
    Returns:
        TxQ label string or None
    """
    if priority is None:
        return None
    priority_str = str(priority).upper()
    if priority_str.startswith(("UC", "MC", "VOQ", "ALL")):
        return priority_str
    prefix = "VOQ" if voq else "UC"
    return "{}{}".format(prefix, priority_str)


def _normalize_wred_counter_entry(entry):
    return {
        "wred_drop_pkts": _parse_int_counter(entry.get("wreddroppacket", 0)),
        "wred_drop_bytes": _parse_int_counter(entry.get("wreddropbytes", 0)),
        "ecn_marked_pkts": _parse_int_counter(entry.get("ecnmarkedpacket", 0)),
        "ecn_marked_bytes": _parse_int_counter(entry.get("ecnmarkedbytes", 0)),
    }


def _parse_wred_counters_json(data):
    """
    Parse 'show queue wredcounters --json' output.

    Returns:
        {
            'Ethernet0': {
                'UC3': {
                    'wred_drop_pkts': 0,
                    'wred_drop_bytes': 0,
                    'ecn_marked_pkts': 7820381,
                    'ecn_marked_bytes': 7976788620,
                },
                ...
            },
            ...
        }
    """
    counters = {}
    if not isinstance(data, dict):
        return counters

    for port, port_blob in data.items():
        if not isinstance(port_blob, dict):
            continue
        port_counters = {}
        for txq, entry in port_blob.items():
            if txq in ("time", "cached_time") or not isinstance(entry, dict):
                continue
            port_counters[txq] = _normalize_wred_counter_entry(entry)
        if port_counters:
            counters[port] = port_counters
    return counters


def _asics_for_read(duthost, interface=None, asic=None):
    """
    Resolve the SonicAsic instances a read should be issued against.

    Args:
        duthost: SONiC host under test
        interface (str/None): port name; its owning ASIC is used when asic is None
        asic (SonicAsic/int/str/None): explicit target as an instance, an ASIC
            index, or a namespace string such as a snappi port's 'asic_value'
    Returns:
        list of SonicAsic. duthost.asics holds one instance on a single-ASIC
        DUT, and cli_ns_option is '' there, so callers need no is_multi_asic
        branch.
    """
    if asic is not None:
        if hasattr(asic, "asic_index"):
            return [asic]
        if isinstance(asic, str):
            asic_inst = duthost.asic_instance_from_namespace(asic)
            pytest_assert(
                asic_inst is not None,
                "No ASIC with namespace '{}' on {}".format(asic, duthost.hostname))
            return [asic_inst]
        return [duthost.asic_instance(asic)]
    if interface and duthost.is_multi_asic:
        return [duthost.get_port_asic_instance(interface)]
    return list(duthost.asics)


def _run_wred_counter_cli(duthost, cmd):
    """
    Run a WRED counter CLI command and return its stripped stdout.

    Skips the test when the command fails, which is how an image without WRED
    counter support surfaces.
    """
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        pytest.skip(
            "'{}' failed on {} with rc={} ({}); image may not support WRED counters".format(
                cmd, duthost.hostname, result["rc"],
                (result.get("stderr") or result.get("stdout") or "").strip()))
    return result["stdout"].strip()


def _build_show_queue_wredcounters_cmd(
        cli_ns_option="", interface=None, nonzero=False, voq=False):
    cmd = "show queue wredcounters --json"
    if cli_ns_option:
        cmd += " {}".format(cli_ns_option)
    if interface:
        cmd += " {}".format(interface)
    if nonzero:
        cmd += " --nonzero"
    if voq:
        cmd += " --voq"
    return cmd


def _run_show_queue_wredcounters_json(
        duthost, cli_ns_option="", interface=None, nonzero=False, voq=False):
    cmd = _build_show_queue_wredcounters_cmd(
        cli_ns_option=cli_ns_option,
        interface=interface,
        nonzero=nonzero,
        voq=voq,
    )
    stdout = _run_wred_counter_cli(duthost, cmd)
    if not stdout:
        return {}

    try:
        data = json.loads(stdout)
    except ValueError:
        pytest.skip(
            "'{}' on {} did not return JSON; image may not support --json".format(
                cmd, duthost.hostname))
    else:
        return _parse_wred_counters_json(data)


def _filter_wred_counters_by_priority(counters, txq_filter):
    if txq_filter is None:
        return counters
    filtered = {}
    for port, prio_map in counters.items():
        if txq_filter in prio_map:
            filtered[port] = {txq_filter: prio_map[txq_filter]}
    return filtered


def get_ecn_wred_counters(
        duthost, interface=None, asic=None, priority=None, nonzero=False, voq=False):
    """
    Get ECN/WRED queue counters from SONiC CLI.
    CLI:
        show queue wredcounters --json [-n <asic>] [<port>] [--nonzero] [--voq]

    Each ASIC is read separately because 'show queue wredcounters --json'
    prints one JSON document per namespace, so a namespace-less read on a
    multi-ASIC DUT emits several concatenated documents.

    Args:
        duthost: SONiC host under test
        interface (str/None): port name, e.g. 'Ethernet0'. None = all interfaces.
        asic (SonicAsic/int/str/None): target ASIC for read, as an instance, an
            index, or a namespace string. If None with interface set, the ASIC
            is inferred from the port. If both None, reads every ASIC.
        priority (int/str/None): queue priority / TxQ, e.g. 3 or 'UC3'. None = all TxQs.
        nonzero (bool): pass --nonzero to CLI when True
        voq (bool): pass --voq to CLI when True
    Returns:
        {
            'Ethernet0': {
                'UC3': {
                    'wred_drop_pkts': 0,
                    'wred_drop_bytes': 0,
                    'ecn_marked_pkts': 7820381,
                    'ecn_marked_bytes': 7976788620,
                },
                ...
            },
            ...
        }
    Skips the test when the image does not support the WRED counter CLI.
    """
    txq_filter = _txq_from_priority(priority, voq=voq)
    result = {}

    for asic_inst in _asics_for_read(duthost, interface=interface, asic=asic):
        parsed = _run_show_queue_wredcounters_json(
            duthost,
            cli_ns_option=asic_inst.cli_ns_option,
            interface=interface,
            nonzero=nonzero,
            voq=voq,
        )
        for port, prio_map in _filter_wred_counters_by_priority(parsed, txq_filter).items():
            result.setdefault(port, {}).update(prio_map)
    return result


def clear_ecn_wred_counters(duthost):
    """
    Clear WRED queue counters on every ASIC of duthost.
    CLI:
        sonic-clear queue wredcounters

    The CLI takes no -n/--namespace option, and the wredstat script behind it
    already runs against every namespace, so one invocation covers all ASICs.

    Args:
        duthost: SONiC host under test
    Skips the test when the image does not support the WRED counter CLI.
    """
    _run_wred_counter_cli(duthost, "sonic-clear queue wredcounters")
