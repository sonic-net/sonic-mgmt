import os
import json
import logging
import itertools
import shlex
import pytest
import time
import re

import cli_helpers as helper
from telemetry_utils import generate_client_cli
from show_cli_to_gnmi_path import ShowCliToGnmiPathConverter, OptionException

pytestmark = [pytest.mark.topology('any')]

logger = logging.getLogger(__name__)

METHOD_GET = "get"
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SHOW_CMD_FILE = os.path.join(BASE_DIR, "show_cmd.json")
RESOURCE_EXHAUSTION = "ResourceExhausted"
CLIENT_LARGER_MESSAGE_ERROR = "Received message larger than max"

# Removing ipv6/route (changes pending in client) and ndp (known issue with ipv6 parsing)

argumentMap = {
    "INTERFACE_NAME":            helper.get_valid_interface,
    "DEVICE_NEIGHBOR":           helper.get_device_neighbor,
    "RIF_INTERFACE":             helper.get_rif_interface,
    "IPV6NEIGHBOR":              helper.get_ipv6_neighbor,
    "IPV6_BGP_NETWORK_ARG":      helper.get_ipv6_bgp_network_arguments,
    "IPV6ADDRESS_PREFIX":        helper.get_ipv6_prefix,
    "IPV6_BGP_NEIGHBOR_ARG":     helper.get_ipv6_bgp_neighbor_arguments,
    "IPV6ADDRESS_PREFIX_FAMILY": helper.get_ipv6_prefix_family,
    "IPV6_ROUTE_ARG":            helper.get_ipv6_route_arguments,
    "ARP_IPV4_ADDRESS":          helper.get_device_arp_ip,
    "FEATURE_NAME":              helper.get_feature_name
}

# Options (lowercase keys) -> (type, cli-name, getter)
# type: "flag" => --name ; "kv" => --name=value
optionMap = {
    "period":               ("kv",   "period",   helper.get_period_value),
    "printall":             ("flag", "printall", None),
    "group":                ("kv",   "group",    helper.get_group_value),
    "counter_type":         ("kv", "counter_type", helper.get_counter_type_value),
    "interface":            ("kv", "interface", helper.get_valid_interface),
    "SONIC_CLI_IFACE_MODE": ("kv", "SONIC_CLI_IFACE_MODE", None),
    "nonzero":              ("flag", "nonzero", None),
    "all":                  ("flag", "all", None),
    "trim":                 ("flag", "trim", None),
    "dom":                  ("flag", "dom", None),
    "interface_vlan":       ("kv", "iface", helper.get_interface_vlan),
}

def powerset(iterable):
    items = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(items, r) for r in range(len(items) + 1))

def generate_option_combinations(nested):
    result = [[]]  # empty set (no options)
    for subset in powerset(nested):
        if not subset:
            continue
        for combo in itertools.product(*subset):
            result.append(list(combo))
    return result

def generate_required_argument_combinations(nested):
    if not nested:
        return []
    return [list(t) for t in itertools.product(*nested)]

def generate_optional_argument_combinations(nested):
    result = [[]]
    for i in range(len(nested)):
        result.extend([list(t) for t in itertools.product(*nested[:i+1])])
    return result

def build_show_cli_tokens(base_path, positional_args, option_tokens):
    parts = [base_path]
    parts.extend(str(arg) for arg in positional_args)
    parts.extend(option_tokens)
    return " ".join(parts)

def option_value_lists(option_keys, duthost, arguments):
    lists = []
    last_arg = arguments[-1] if arguments else None
    for key in option_keys:

        otype, oname, getter = optionMap[key]
        if otype == "flag":
            lists.append([f"--{oname}"])
        else:  # kv
            if key == "SONIC_CLI_IFACE_MODE":
                iface_flag = any(
                    re.match(r"--iface=Ethernet\d+$", v)
                    for sub in lists for v in sub
                )
                if ((last_arg and re.match(r"^Ethernet\d+$", last_arg)) or iface_flag):
                    lists.append([f"--{oname}=default"])
                else:
                    lists.append([f"--{oname}=alias"])
                continue
            vals = getter(duthost) if getter else []
            if not vals:
                continue
            lists.append([f"--{oname}={v}" for v in vals])
    return lists

def convert_show_cli_to_xpath(cli_str):
    tokens = shlex.split(cli_str)
    return ShowCliToGnmiPathConverter(tokens).convert()


def validate_schema(shape, required_keys, required_map_keys, payload):
    """
    payload can be in multiple shapes:

    1) array: [{"interface": "Ethernet0", "alias": "etp0"}]
    2) object(keys): {"fdb_aging_time": "600s"}
    3) object(map): {"Ethernet0": {"alias": "etp0"}}
    """
    if shape == "array":
        if not isinstance(payload, list):
            return False, f"expected array, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None
        for i, elem in enumerate(payload):
            if not isinstance(elem, dict):
                return False, f"array element {i} not an object (got {type(elem).__name__})"
            missing = [k for k in required_keys if k not in elem]
            if missing:
                return False, f"array element {i} missing keys: {missing}"
        return True, None

    # object_keys
    if shape == "object_keys":
        if not isinstance(payload, dict):
            return False, f"expected object, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None
        missing = [k for k in required_keys if k not in payload]
        if missing:
            return False, f"object missing keys: {missing}"
        return True, None

    # object_map
    if shape == "object_map":
        if not isinstance(payload, dict):
            return False, f"expected object, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None

        missing_top = [k for k in required_map_keys if k not in payload]
        if missing_top:
            return False, f"object_map missing top-level keys: {missing_top}"

        for k, v in payload.items():
            if not isinstance(v, dict):
                return False, f"value at key '{k}' is not an object (got {type(v).__name__})"
            missing = [rk for rk in required_keys if rk not in v]
            if missing:
                return False, f"value at key '{k}' missing keys: {missing}"
        return True, None

    return False, f"unknown shape '{shape}'"

def gnmi_get_with_retry(ptfhost, cmd, retries=3):
    res = {"rc": 1, "stdout": "", "stderr": ""}
    for i in range(max(1, retries)):
        res = ptfhost.shell(cmd, module_ignore_errors=True)
        if res.get("rc", 1) == 0:
            return res
        logger.info(f"Retrying gNMI Get (attempt {i+1}/{retries}) for: {cmd}")
        time.sleep(1)
    return res


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_show_cli_schema_and_safeguard(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    ptfhost,
    setup_streaming_telemetry,
    gnxi_path,
    request,
    skip_non_container_test
):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    with open(SHOW_CMD_FILE, "r", encoding="utf-8") as f:
        show_cmds = json.load(f)

    failures = []
    commands_tested = []

    for show_cmd in show_cmds:
        path = show_cmd["path"]
        required_args = show_cmd.get("required_args", [])
        optional_args = show_cmd.get("optional_args", [])
        options = show_cmd.get("options", [])
        schema = show_cmd["schema"]
        shape = schema["shape"]
        required_keys = schema.get("required_keys", [])
        required_map_keys = schema.get("required_map_keys", [])
        should_validate = show_cmd.get("validateSchema", False)

        required_arg_values = []
        if required_args:
            invalid_arg = None
            for arg in required_args:
                getter = argumentMap.get(arg)
                if not getter:
                    invalid_arg = arg
                    break
                value = getter(duthost)
                if not value:
                    invalid_arg = arg
                    break
                required_arg_values.append(value)
            if invalid_arg:
                failures.append({
                    "cli": path,
                    "xpath": "",
                    "reason": f"unknown required arg '{invalid_arg}'"
                })
                continue

        argument_combinations = []
        if required_args:
            argument_combinations = generate_required_argument_combinations(required_arg_values)
        elif optional_args:
            arg_values = []
            for arg in optional_args:
                getter = argumentMap.get(arg)
                if not getter:
                    failures.append({
                        "cli": path,
                        "xpath": "",
                        "reason": f"unknown optional arg '{arg}'"
                    })
                    continue
                arg_value = getter(duthost)
                if not arg_value:
                    failures.append({
                        "cli": path,
                        "xpath": "",
                        "reason": f"optional arg: '{arg}' getter failed"
                    })
                    continue
                arg_values.append(arg_value)
            argument_combinations = generate_optional_argument_combinations(arg_values)
        else:
            argument_combinations = [[]]

        for argument_combination in argument_combinations:
            try:
                per_option_lists = option_value_lists(options, duthost, argument_combination) if options else []
            except (KeyError, ValueError) as e:
                failures.append({"cli": path, "xpath": "", "reason": str(e)})
                continue
            for opt_tokens in (generate_option_combinations(per_option_lists) if per_option_lists else [[]]):
                    cli = build_show_cli_tokens(path, argument_combination, opt_tokens)
                    commands_tested.append(cli)
                    try:
                        xpath = convert_show_cli_to_xpath(cli)
                        prefix = "SHOW/"
                        if xpath.startswith(prefix):
                            xpath = xpath[len(prefix):]
                    except (OptionException, ValueError) as e:
                        failures.append({
                            "cli": cli,
                            "xpath": "",
                            "reason": f"{e}"
                        })
                        continue

                    logger.info("CLI: %s, XPATH: %s", cli, xpath)
                    xpath_to_query = shlex.quote(xpath)

                    before_status = duthost.all_critical_process_status()

                    cmd = generate_client_cli(
                        duthost=duthost,
                        gnxi_path=gnxi_path,
                        method=METHOD_GET,
                        xpath=xpath_to_query,
                        target="SHOW"
                    )
                    ptf_result = gnmi_get_with_retry(ptfhost, cmd)
                    rc = ptf_result.get("rc", 1)
                    stdout = ptf_result.get("stdout", "")
                    stderr = ptf_result.get("stderr", "")

                    if rc != 0:
                        if RESOURCE_EXHAUSTION in stdout or CLIENT_LARGER_MESSAGE_ERROR in stdout:
                            continue
                        failures.append({
                            "cli": cli,
                            "xpath": xpath,
                            "reason": f"ptf rc={rc}, stderr={stderr}"
                        })
                        continue

                    after_status = duthost.all_critical_process_status()
                    if before_status != after_status:
                        failures.append({
                            "cli": cli,
                            "xpath": xpath,
                            "reason": "Critical process status changed after GET"
                        })

                    try:
                        payload = helper.get_json_from_gnmi_output(stdout)
                    except (json.JSONDecodeError, TypeError, AssertionError) as e:
                        failures.append({
                            "cli": cli,
                            "xpath": xpath,
                            "reason": f"JSON parse error: {e}. Raw: {stdout}"
                        })
                        continue

                    if not should_validate:
                        continue

                    ok, reason = validate_schema(shape, required_keys, required_map_keys, payload)
                    if not ok:
                        failures.append({
                            "cli": cli,
                            "xpath": xpath,
                            "reason": reason
                        })
    commands_tested_lines = ["Commands tested: ({} total):".format(len(commands_tested))]
    for commands in commands_tested:
        commands_tested_lines.append(commands)
    logger.info(f"{commands_tested_lines}")

    if failures:
        lines = ["Failures summary ({} total):".format(len(failures))]
        for f in failures:
            lines.append(f"cli='{f['cli']}' xpath='{f['xpath']}' reason={f['reason']}")
        logger.info("\n".join(lines))
        pytest.fail("\n".join(lines))
