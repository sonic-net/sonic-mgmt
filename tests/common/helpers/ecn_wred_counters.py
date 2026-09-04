"""Read and clear SONiC WRED/ECN queue counters.

CLI reference:
    show queue wredcounters --json [-n <asic>] [<port>] [--nonzero] [--voq]
    sonic-clear queue wredcounters [-n <asic>]

Counterpoll for wredqueue/wredport must be enabled before these counters
report data. For snappi ECN tests that is handled by the
``enable_wred_ecn_counterpoll`` fixture in ``tests/snappi_tests/ecn/``.
"""

import json

import pytest


def _resolve_asic_instance(duthost, asic=None):
    """
    Resolve asic argument to a SonicAsic instance.
    Args:
        duthost: SONiC host under test
        asic: SonicAsic instance, asic index (int), or None
    Returns:
        SonicAsic instance
    """
    if asic is None:
        return duthost.asic_instance()
    if hasattr(asic, "asic_index"):
        return asic
    return duthost.asic_instance(asic)


def _namespace_arg(asic_namespace=None):
    """Return the ' -n <namespace>' CLI fragment, or '' when not namespaced."""
    if not asic_namespace:
        return ""
    return " -n {}".format(asic_namespace)


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


def _build_show_queue_wredcounters_cmd(
        duthost, asic_namespace=None, interface=None, nonzero=False, voq=False):
    cmd = "show queue wredcounters --json"
    if duthost.is_multi_asic:
        cmd += _namespace_arg(asic_namespace)
    if interface:
        cmd += " {}".format(interface)
    if nonzero:
        cmd += " --nonzero"
    if voq:
        cmd += " --voq"
    return cmd


def _run_show_queue_wredcounters_json(
        duthost, asic_namespace=None, interface=None, nonzero=False, voq=False):
    cmd = _build_show_queue_wredcounters_cmd(
        duthost,
        asic_namespace=asic_namespace,
        interface=interface,
        nonzero=nonzero,
        voq=voq,
    )
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        pytest.skip(
            "'{}' failed on {} with rc={}; image may not support WRED counters".format(
                cmd, duthost.hostname, result["rc"]))

    stdout = result["stdout"].strip()
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


def _run_sonic_clear_wredcounters(duthost, asic_namespace=None):
    cmd = "sonic-clear queue wredcounters" + _namespace_arg(asic_namespace)
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        pytest.skip(
            "'{}' failed on {} with rc={}; image may not support WRED counters".format(
                cmd, duthost.hostname, result["rc"]))


def _filter_wred_counters_by_priority(counters, txq_filter):
    if txq_filter is None:
        return counters
    filtered = {}
    for port, prio_map in counters.items():
        if txq_filter in prio_map:
            filtered[port] = {txq_filter: prio_map[txq_filter]}
    return filtered


def _asic_namespace_for_read(duthost, interface=None, asic=None):
    if asic is not None:
        return _resolve_asic_instance(duthost, asic).get_asic_namespace()
    if interface and duthost.is_multi_asic:
        return duthost.get_port_asic_instance(interface).get_asic_namespace()
    return None


def get_ecn_wred_counters(
        duthost, interface=None, asic=None, priority=None, nonzero=False, voq=False):
    """
    Get ECN/WRED queue counters from SONiC CLI.
    CLI:
        show queue wredcounters --json [-n <asic>] [<port>] [--nonzero] [--voq]
    Args:
        duthost: SONiC host under test
        interface (str/None): port name, e.g. 'Ethernet0'. None = all interfaces.
        asic (SonicAsic/int/None): target ASIC for read. If None with interface set,
            ASIC is inferred from the port. If both None on multi-ASIC, reads all ASICs.
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

    if interface or asic is not None:
        asic_namespace = _asic_namespace_for_read(duthost, interface=interface, asic=asic)
        parsed = _run_show_queue_wredcounters_json(
            duthost,
            asic_namespace=asic_namespace,
            interface=interface,
            nonzero=nonzero,
            voq=voq,
        )
        result.update(_filter_wred_counters_by_priority(parsed, txq_filter))
        return result

    if duthost.is_multi_asic:
        for asic_inst in duthost.asics:
            parsed = _run_show_queue_wredcounters_json(
                duthost,
                asic_namespace=asic_inst.get_asic_namespace(),
                interface=None,
                nonzero=nonzero,
                voq=voq,
            )
            for port, prio_map in _filter_wred_counters_by_priority(parsed, txq_filter).items():
                result.setdefault(port, {}).update(prio_map)
    else:
        parsed = _run_show_queue_wredcounters_json(
            duthost,
            asic_namespace=None,
            interface=None,
            nonzero=nonzero,
            voq=voq,
        )
        result.update(_filter_wred_counters_by_priority(parsed, txq_filter))
    return result


def clear_ecn_wred_counters(duthost, asic=None):
    """
    Clear WRED queue counters.
    CLI:
        sonic-clear queue wredcounters [-n <asic>]
    Args:
        duthost: SONiC host under test
        asic (SonicAsic/int/None): target ASIC. If None on multi-ASIC, clears all ASICs.
    Skips the test when the image does not support the WRED counter CLI.
    """
    if asic is not None:
        asic_inst = _resolve_asic_instance(duthost, asic)
        namespace = asic_inst.get_asic_namespace() if duthost.is_multi_asic else None
        _run_sonic_clear_wredcounters(duthost, asic_namespace=namespace)
        return

    if duthost.is_multi_asic:
        for asic_inst in duthost.asics:
            _run_sonic_clear_wredcounters(
                duthost, asic_namespace=asic_inst.get_asic_namespace())
    else:
        _run_sonic_clear_wredcounters(duthost)
