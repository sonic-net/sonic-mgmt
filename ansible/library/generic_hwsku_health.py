#!/usr/bin/python
"""Verify selected links and applied PG/queue/QoS objects without configuring services."""

from pathlib import Path
import socket
import time


QOS_ATTRIBUTES = {
    "dscp_to_tc_map": "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP",
    "tc_to_dscp_map": "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP",
    "dot1p_to_tc_map": "SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP",
    "tc_to_pg_map": "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP",
    "tc_to_queue_map": "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
    "pfc_to_pg_map": "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP",
    "pfc_to_queue_map": "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
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
        if not {"xon", "xoff"} <= set(profile):
            continue
        if not str(profile.get("size", "")).isdigit():
            problems.append(port + ": applied lossless reservation size is unresolved")
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
        if not oid:
            problems.append(port + ": actual ASIC port mapping is absent")
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
        asic_port = database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + oid) or {}
        for field in request["qos"][port]:
            attribute = QOS_ATTRIBUTES.get(field)
            if attribute is not None:
                mapping = asic_port.get(attribute)
                if (mapping in (None, "oid:0x0")
                        or not database.get_all("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:" + mapping)):
                    problems.append(port + ": applied QoS map is absent: " + field)
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
