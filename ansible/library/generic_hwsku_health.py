#!/usr/bin/python
"""Verify selected links and applied PG/queue/QoS objects without configuring services."""

import json
from pathlib import Path
import socket
import time


QOS_MAPS = {
    "dscp_to_tc_map": {
        "table": "DSCP_TO_TC_MAP", "attribute": "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP",
        "type": "DSCP_TO_TC", "key": "dscp", "value": "tc"},
    "tc_to_dscp_map": {
        "table": "TC_TO_DSCP_MAP", "attribute": "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP",
        "type": "TC_AND_COLOR_TO_DSCP", "key": "tc", "value": "dscp"},
    "dot1p_to_tc_map": {
        "table": "DOT1P_TO_TC_MAP", "attribute": "SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP",
        "type": "DOT1P_TO_TC", "key": "dot1p", "value": "tc"},
    "tc_to_pg_map": {
        "table": "TC_TO_PRIORITY_GROUP_MAP", "attribute": "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP",
        "type": "TC_TO_PRIORITY_GROUP", "key": "tc", "value": "pg"},
    "tc_to_queue_map": {
        "table": "TC_TO_QUEUE_MAP", "attribute": "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
        "type": "TC_TO_QUEUE", "key": "tc", "value": "qidx"},
    "pfc_to_pg_map": {
        "table": "PFC_PRIORITY_TO_PRIORITY_GROUP_MAP",
        "attribute": "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP",
        "type": "PFC_PRIORITY_TO_PRIORITY_GROUP", "key": "prio", "value": "pg"},
    "pfc_to_queue_map": {
        "table": "MAP_PFC_PRIORITY_TO_QUEUE", "attribute": "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
        "type": "PFC_PRIORITY_TO_QUEUE", "key": "prio", "value": "qidx"},
}


def selectors(value):
    indices = set()
    for token in value.split(","):
        bounds = token.split("-")
        first, last = int(bounds[0]), int(bounds[-1])
        if len(bounds) > 2 or not 0 <= first <= last <= 255:
            raise ValueError("Invalid PG/queue selector")
        indices.update(range(first, last + 1))
    return sorted(indices)


def port_bindings(config, table, port):
    result = {}
    for key, attributes in config.get(table, {}).items():
        names, separator, indices = key.partition("|")
        if separator and port in names.split(","):
            for index in selectors(indices):
                entry = {"selector": indices, "profile": attributes["profile"]}
                if str(index) in result and result[str(index)]["profile"] != entry["profile"]:
                    raise ValueError("Overlapping PG/queue selectors disagree on their profile")
                result[str(index)] = entry
    return result


def reference(value, table):
    for prefix in ("[" + table + "|", "[" + table + "_TABLE:"):
        if value.startswith(prefix) and value.endswith("]"):
            return value[len(prefix):-1]
    return value


def profile_matches(database, request, port, index, binding, kind, asic_profile):
    table = "BUFFER_PG_TABLE" if kind == "INGRESS_PRIORITY_GROUP" else "BUFFER_QUEUE_TABLE"
    application = database.get_all("APPL_DB", "{}:{}:{}".format(table, port, binding["selector"])) or {}
    name = reference(application.get("profile", ""), "BUFFER_PROFILE")
    configured = reference(binding["profile"], "BUFFER_PROFILE")
    if not name or name == "NULL" or (configured != "NULL" and name != configured):
        return False
    profile = database.get_all("APPL_DB", "BUFFER_PROFILE_TABLE:" + name) or {}
    if (not {"pool", "size"} <= set(profile) or not {"dynamic_th", "static_th"}.intersection(profile)
            or kind == "INGRESS_PRIORITY_GROUP" and configured == "NULL" and not {"xon", "xoff"} <= set(profile)):
        return False
    fields = {"size": "RESERVED_BUFFER_SIZE", "xon": "XON_TH", "xoff": "XOFF_TH",
              "xon_offset": "XON_OFFSET_TH", "dynamic_th": "SHARED_DYNAMIC_TH", "static_th": "SHARED_STATIC_TH"}
    configured_profile = request["profiles"].get(configured, {}) if configured != "NULL" else {}
    for field, attribute in fields.items():
        if field in configured_profile and str(configured_profile[field]) != str(profile.get(field)):
            return False
        if field in profile and str(profile[field]) != asic_profile.get("SAI_BUFFER_PROFILE_ATTR_" + attribute):
            return False
    pool_name = reference(profile.get("pool", ""), "BUFFER_POOL")
    if not pool_name:
        return False
    if "pool" in configured_profile and reference(configured_profile["pool"], "BUFFER_POOL") != pool_name:
        return False
    pool = database.get_all("APPL_DB", "BUFFER_POOL_TABLE:" + pool_name) or {}
    if not {"size", "type", "mode"} <= set(pool):
        return False
    configured_pool = request["pools"].get(pool_name, {})
    if any(field in configured_pool and str(configured_pool[field]) != str(pool.get(field))
           for field in ("size", "type", "mode", "xoff")):
        return False
    pool_id = asic_profile.get("SAI_BUFFER_PROFILE_ATTR_POOL_ID")
    asic_pool = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:" + str(pool_id)) or {}
    for field, attribute in (("size", "SIZE"), ("xoff", "XOFF_SIZE")):
        if field in pool and str(pool[field]) != asic_pool.get("SAI_BUFFER_POOL_ATTR_" + attribute):
            return False
    for field, attribute in (("type", "TYPE"), ("mode", "THRESHOLD_MODE")):
        if (field in pool
                and not asic_pool.get("SAI_BUFFER_POOL_ATTR_" + attribute, "").endswith("_" + pool[field].upper())):
            return False
    return bool(profile and pool and asic_pool)


def qos_map_matches(database, request, field, name, oid):
    spec = QOS_MAPS[field]
    expected = request.get("qos_maps", {}).get(spec["table"], {}).get(reference(name, spec["table"]))
    if not isinstance(expected, dict) or not expected or not isinstance(oid, str) or oid == "oid:0x0":
        return False
    row = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:" + oid) or {}
    if row.get("SAI_QOS_MAP_ATTR_TYPE") != "SAI_QOS_MAP_TYPE_" + spec["type"]:
        return False
    try:
        entries = json.loads(row["SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"])
        if (type(entries["count"]) is not int or not isinstance(entries["list"], list)
                or entries["count"] != len(entries["list"])):
            return False
        # SWSS initializes TC_TO_DSCP keys with the default green packet color.
        color = ("SAI_PACKET_COLOR_GREEN",) if field == "tc_to_dscp_map" else ()
        expected_entries = {(int(key),) + color: int(value) for key, value in expected.items()}
        if len(expected_entries) != len(expected):
            return False
        actual = {}
        for entry in entries["list"]:
            key, value = entry["key"][spec["key"]], entry["value"][spec["value"]]
            if type(key) is not int or type(value) is not int:
                return False
            key = (key,) + ((entry["key"]["color"],) if color else ())
            if key in actual:
                return False
            actual[key] = value
        return actual == expected_entries
    except (KeyError, TypeError, ValueError):
        return False


def pfc_matches(request, port, asic_port):
    configured = request["qos"][port]["pfc_enable"]
    if not isinstance(configured, str):
        raise ValueError("Frozen PFC priorities must be a comma-separated string")
    bitmap = 0
    for priority in configured.split(",") if configured else []:
        if not priority.isdigit() or int(priority) > 7:
            raise ValueError("Frozen PFC priorities must be in the range 0-7")
        bitmap |= 1 << int(priority)
    asymmetric = request.get("pfc_asym", {}).get(port, "off")
    if asymmetric not in ("on", "off"):
        raise ValueError("Frozen PFC asymmetric mode must be on or off")
    # SAI defaults unwritten PFC attributes to zero and combined mode.
    prefix = "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"
    mode = "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_"
    if asic_port.get(prefix + "_MODE", mode + "COMBINED") != mode + (
            "SEPARATE" if asymmetric == "on" else "COMBINED"):
        return False
    expected = {"_TX": bitmap, "_RX": 255} if asymmetric == "on" else {"": bitmap}
    try:
        return all(int(asic_port.get(prefix + suffix, "0")) == value for suffix, value in expected.items())
    except (TypeError, ValueError):
        return False


def check(request, database, interface_root=Path("/sys/class/net")):
    problems, checked = [], 0
    reservations = {}
    headroom_ports = set(request.get("headroom_ports", request["ports"]))
    for key in database.keys("APPL_DB", "BUFFER_PG_TABLE:*") or []:
        port, separator, indices = key[len("BUFFER_PG_TABLE:"):].partition(":")
        if port not in headroom_ports:
            continue
        binding = database.get_all("APPL_DB", key) or {}
        name = reference(binding.get("profile", ""), "BUFFER_PROFILE")
        profile = database.get_all("APPL_DB", "BUFFER_PROFILE_TABLE:" + name) or {}
        if not separator or not profile:
            problems.append(port + ": reclaimed PG reservation is unresolved")
            continue
        thresholds = {"xon", "xoff"}
        if not thresholds.intersection(profile):
            continue
        if (not thresholds <= set(profile) or not profile.get("pool")
                or any(not str(profile.get(field, "")).isdigit() for field in ("size", "xon", "xoff"))):
            problems.append(port + ": applied lossless PG reservation is unresolved")
            continue
        for index in selectors(indices):
            identity = (port, index)
            if identity in reservations:
                problems.append(port + ": overlapping applied PG reservation")
            reservations[identity] = int(profile["size"])
    reserved_headroom = sum(reservations.values())
    names = database.get_all("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP") or {}
    objects = {}
    for kind, prefix in (("INGRESS_PRIORITY_GROUP", "PG"), ("QUEUE", "QUEUE")):
        objects[kind] = {
            field: database.get_all("COUNTERS_DB", "COUNTERS_{}_{}_MAP".format(prefix, field)) or {}
            for field in ("NAME", "PORT", "INDEX")}
    for port in request["ports"]:
        carrier = interface_root / port / "carrier"
        try:
            linked = carrier.read_text().strip() == "1"
        except OSError:
            linked = False
        if not linked:
            problems.append(port + ": selected physical link is not up")
        oid = names.get(port)
        if not oid or oid == "oid:0x0":
            problems.append(port + ": actual ASIC port mapping is absent")
            continue
        asic_port = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + oid) or {}
        if not asic_port:
            problems.append(port + ": actual ASIC port object is absent")
            continue
        for kind, prefix, bindings in (
                ("INGRESS_PRIORITY_GROUP", "SAI_INGRESS_PRIORITY_GROUP_ATTR_", request["pg"][port]),
                ("QUEUE", "SAI_QUEUE_ATTR_", request["queues"][port])):
            if not bindings:
                problems.append(port + ": no required " + kind + " bindings")
            for index, binding in bindings.items():
                identity = objects[kind]
                object_id = identity["NAME"].get("{}:{}".format(port, index))
                if (object_id in (None, "oid:0x0") or identity["PORT"].get(object_id) != oid
                        or identity["INDEX"].get(object_id) != str(index)):
                    problems.append("{}: {} {} has no consistent counter port/index identity".format(
                        port, kind, index))
                    continue
                row = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_" + kind + ":" + object_id) or {}
                attribute = prefix + ("BUFFER_PROFILE" if kind == "INGRESS_PRIORITY_GROUP" else "BUFFER_PROFILE_ID")
                if not row:
                    problems.append("{}: {} {} has no ASIC object".format(port, kind, index))
                    continue
                profile = row.get(attribute)
                if not profile or profile == "oid:0x0":
                    problems.append("{}: {} {} has no applied buffer profile".format(port, kind, index))
                    continue
                profile_row = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:" + profile)
                if not profile_row or profile_row.get("SAI_BUFFER_PROFILE_ATTR_POOL_ID") in (None, "oid:0x0"):
                    problems.append("{}: applied buffer profile/pool is absent".format(port))
                elif not profile_matches(database, request, port, index, binding, kind, profile_row):
                    problems.append("{}: {} {} disagrees between CONFIG/APPL/ASIC buffer state".format(
                        port, kind, index))
                else:
                    checked += 1
        for field, name in request["qos"][port].items():
            if field in QOS_MAPS and not qos_map_matches(
                    database, request, field, name, asic_port.get(QOS_MAPS[field]["attribute"])):
                problems.append(port + ": applied QoS map is absent or disagrees with frozen type/entries: " + field)
        if "pfc_enable" in request["qos"][port] and not pfc_matches(request, port, asic_port):
            problems.append(port + ": applied PFC bitmap/mode disagrees with frozen policy")
    if "headroom_limit" in request:
        limit = request["headroom_limit"]
        if type(limit) is not int or limit < 0:
            raise ValueError("Frozen headroom reservation limit must be a nonnegative integer")
        if reserved_headroom > limit:
            problems.append("Applied lossless reservations exceed the frozen reclaimed headroom budget")
    return {"ready": not problems, "ports": len(request["ports"]), "applied_buffer_bindings": checked,
            "reserved_headroom": reserved_headroom,
            "blocking_errors": problems}


def wait_ready(request, database, timeout=180, interval=2):
    deadline = time.monotonic() + timeout
    while True:
        result = check(request, database)
        if result["ready"] or time.monotonic() >= deadline:
            return result
        time.sleep(min(interval, max(0, deadline - time.monotonic())))


def main():
    from ansible.module_utils.basic import AnsibleModule
    from ansible.module_utils.multi_asic_utils import load_db_config
    from sonic_py_common import multi_asic
    from swsscommon.swsscommon import SonicV2Connector

    module = AnsibleModule(argument_spec={
        "request": {"type": "dict", "required": True, "no_log": True},
        "destination": {"type": "path", "required": True},
    })
    try:
        request = module.params["request"]
        if socket.gethostname().lower() != request["device"].lower() or multi_asic.get_num_asics() != 1:
            raise ValueError("Readiness device identity or ASIC scope changed")
        load_db_config()
        database = SonicV2Connector(namespace=multi_asic.get_namespace_list()[0])
        for name in ("COUNTERS_DB", "ASIC_DB", "APPL_DB"):
            database.connect(name)
        result = wait_ready(request, database)
        from generic_hwsku_device_action import write_result
        write_result(module.params["destination"], result)
        module.exit_json(changed=False, ready=result["ready"], artifact_written=True)
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError) as error:
        module.fail_json(msg="Generic link/buffer/QoS readiness read failed: {}".format(error))


if __name__ == "__main__":
    main()
