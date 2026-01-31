import json
import re
import ipaddress
from tests.common.reboot import reboot


def get_json_from_gnmi_output(stdout):
    marker = "The GetResponse is below"
    marker_pos = stdout.find(marker)
    assert marker_pos != -1, "GetResponse marker not found"

    # Support both object and array JSON roots
    obj_pos = stdout.find("{", marker_pos)
    arr_pos = stdout.find("[", marker_pos)

    if obj_pos == -1 and arr_pos == -1:
        raise AssertionError("JSON not found in GetResponse")

    start_pos = obj_pos if arr_pos == -1 else arr_pos if obj_pos == -1 else min(obj_pos, arr_pos)

    decoder = json.JSONDecoder()
    payload = stdout[start_pos:].lstrip()
    obj, _ = decoder.raw_decode(payload)
    return obj


def reboot_device(duthost, localhost):
    reboot(duthost, localhost)


def transform_reboot_cause_output(reboot_cause_dict):
    reboot_cause_str = ""

    reboot_cause = reboot_cause_dict.get("cause", "Unknown")
    reboot_user = reboot_cause_dict.get("user", "N/A")
    reboot_time = reboot_cause_dict.get("time", "N/A")

    if reboot_user != "N/A":
        reboot_cause_str = "User issued '{}' command".format(reboot_cause)
    else:
        reboot_cause_str = reboot_cause

    if reboot_user != "N/A" or reboot_time != "N/A":
        reboot_cause_str += " ["

        if reboot_user != "N/A":
            reboot_cause_str += "User: {}".format(reboot_user)
            if reboot_time != "N/A":
                reboot_cause_str += ", "

        if reboot_time != "N/A":
            reboot_cause_str += "Time: {}".format(reboot_time)

        reboot_cause_str += "]"
    return reboot_cause_str


def check_reboot_cause(duthost, output):
    cmd = "show reboot-cause"
    result = duthost.shell(cmd)["stdout"]

    reboot_cause_str = transform_reboot_cause_output(output)

    failure_message = "{} no match parsed gnmi output {} for SHOW/reboot-cause path".format(result, reboot_cause_str)
    assert result == reboot_cause_str, failure_message


def check_reboot_cause_history(duthost, output):
    cmd = "show reboot-cause history"
    result = duthost.show_and_parse(cmd)

    result_map = {entry["name"]: {k: entry[k] for k in entry if k != "name"} for entry in result}

    failure_message = "show result {} != output {} for SHOW/reboot-cause/history path".format(result_map, output)
    assert result_map == output, failure_message


def get_valid_interface(duthost):
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet\d+$')
    for name, st in interfaces.items():
        if pattern.match(name) and st.get("oper") == "up" and st.get("admin") == "up":
            return [name]
    return None


def get_period_value(duthost):
    return ["5"]


def get_group_value(duthost):
    return ["BAD"]


def get_counter_type_value(duthost):
    return ["PORT_INGRESS_DROPS"]


def get_ipv6_neighbor(duthost):
    output = duthost.shell("redis-cli -n 6 keys 'NEIGH_STATE_TABLE|*'", module_ignore_errors=True)["stdout"]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return None
    for line in lines:
        if ":" in line:
            return [line.split("|", 1)[-1]]
    return None

def get_ipv6_prefix(duthost):
    return ["::\/0"]


def get_ipv6_bgp_neighbor_arguments(duthost):
    return ["routes", "advertised-routes", "received-routes"]


def get_ipv6_prefix_family(duthost):
    return ["LOCAL_VLAN_IPV6_PREFIX", "PL_LoopbackV6"]


def get_ipv6_bgp_network_arguments(duthost):
    return ["bestpath", "longer-prefixes", "multipath"]


def get_ipv6_route_arguments(duthost):
    return ["bgp", "nexthop-group", "::\/0"]


def get_interface_vlan(duthost):
    vlan_intfs = duthost.get_vlan_intfs()
    if len(vlan_intfs) == 0:
        return None
    return [vlan_intfs[0]]


def get_rif_interface(duthost):
    output = duthost.shell("redis-cli -n 2 hgetall COUNTERS_RIF_NAME_MAP", module_ignore_errors=True)["stdout"]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) >= 2:
        return [lines[0]]
    return None


def get_device_neighbor(duthost):
    output = duthost.shell("redis-cli -n 4 keys 'DEVICE_NEIGHBOR|*'", module_ignore_errors=True)["stdout"]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return None
    return [lines[0].split("|", 1)[-1]]

def get_device_arp_ip(duthost):
    output = duthost.shell("/usr/sbin/arp -n", module_ignore_errors=True)["stdout"]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) >= 2:
        first_entry = lines[1].split()
        return [first_entry[0]]
    return None


def get_feature_name(duthost):
    output = duthost.shell("redis-cli -n 4 keys 'FEATURE|*'", module_ignore_errors=True)["stdout"]
    features = [l.split("|", 1)[-1].strip('"') for l in output.splitlines() if l.strip()]
    if not features:
        return None
    return features