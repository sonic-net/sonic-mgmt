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
CLIENT_LARGER_MESSAGE_ERROR_ALT = "trying to send message larger than max"

# Keys for which substituting a dummy value is expected to produce a
# server-side error because the resource truly cannot exist on the device.
# Keep this set narrow to avoid masking regressions in normal CLI handling.
TOLERATE_DUMMY_FAILURE_KEYS = {"FILENAME", "DEVICE", "dpu", "psu_index"}

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
    "FEATURE_NAME":              helper.get_feature_name,
    "FILENAME":                  helper.get_kdump_filename,
    "MIRROR_SESSION_NAME":       helper.get_mirror_session_name,
    "DEVICE":                    helper.get_ssd_device
    # "SID":                       helper.get_sid, (TODO: Since lab devices wont have SRV6 data we cannot provide SID)
}


def resolve_arg_value(arg, duthost):
    """
    Resolve a positional argument key to its value list.

    Substitutes a dummy from helper.DUMMY_VALUES when the device-derived getter
    returns nothing, so the gNMI path is still exercised.

    Returns (values, used_dummy, error):
      - values:     list of values, or None when unresolved
      - used_dummy: True when the value list came from helper.DUMMY_VALUES
      - error:      reason string when the key has neither getter nor dummy
    """
    getter = argumentMap.get(arg)
    value = getter(duthost) if getter else None
    if value:
        return value, False, None
    dummy = helper.DUMMY_VALUES.get(arg)
    if dummy:
        return dummy, True, None
    if not getter:
        return None, False, f"unknown arg '{arg}'"
    return None, False, f"arg '{arg}' getter returned no value and no dummy defined"


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
    "lines":                ("kv", "lines", helper.get_lines_value),
    "dpu":                  ("kv", "dpu", helper.get_dpu_name),
    "psu_index":            ("kv", "index", helper.get_psu_index),
    "history":              ("flag", "history", None),
    "vendor":               ("flag", "vendor", None),
    "check":                ("flag", "check", None),
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
    dummy_option_tokens = set()
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
            used_dummy = False
            if not vals:
                vals = helper.DUMMY_VALUES.get(key)
                if not vals:
                    continue
                used_dummy = True
            tokens = [f"--{oname}={v}" for v in vals]
            if used_dummy and key in TOLERATE_DUMMY_FAILURE_KEYS:
                dummy_option_tokens.update(tokens)
            lists.append(tokens)
    return lists, dummy_option_tokens


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

        # Only validate required_keys for keys specified in required_map_keys
        keys_to_validate = required_map_keys if required_map_keys else payload.keys()
        for k in keys_to_validate:
            if k not in payload:
                continue
            v = payload[k]
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


def is_large_message_error(stdout, stderr):
    output = "{}\n{}".format(stdout or "", stderr or "")
    return (
        RESOURCE_EXHAUSTION in output or
        CLIENT_LARGER_MESSAGE_ERROR in output or
        CLIENT_LARGER_MESSAGE_ERROR_ALT in output
    )


def is_vs_kvm_environment(duthost):
    """Detect VS/KVM-like environments without relying on one exact platform string."""
    asic_type = duthost.facts.get("asic_type", "")
    platform = duthost.facts.get("platform", "")
    return asic_type == "vs" or "kvm" in platform


def is_kvm_limitation(duthost, cli, stdout, stderr):
    """
    Returns True for known VS/KVM platform limitations where SHOW command
    behavior is expected to fail due to missing hardware/services/files.
    """
    if not is_vs_kvm_environment(duthost):
        return False

    output = "{}\n{}".format(stdout or "", stderr or "")

    kvm_limitations = [
        {
            "cli_prefix": "show interfaces transceiver lpmode",
            "errors": ["exit status 2"],
        },
        {
            "cli_prefix": "show environment",
            "errors": ["exit status 1"],
        },
        {
            "cli_prefix": "show platform psustatus",
            "errors": ["no PSUs detected"],
        },
        {
            "cli_prefix": "show system-health summary",
            "errors": ["System health configuration file not found"],
        },
        {
            "cli_prefix": "show system-health detail",
            "errors": ["System health configuration file not found"],
        },
        {
            "cli_prefix": "show system-health monitor-list",
            "errors": ["System health configuration file not found"],
        },
        {
            "cli_prefix": "show boot",
            "errors": ["No supported bootloader detected"],
        },
        {
            "cli_prefix": "show system-health sysready-status",
            "errors": [
                "No system ready status data available",
                "system-health service might be down",
            ],
        },
        {
            "cli_prefix": "show platform pcieinfo",
            "errors": ["pcie.yaml", "Not found config file"],
        },
        {
            "cli_prefix": "show platform syseeprom",
            "errors": ["does not support EEPROM"],
        },
    ]

    for rule in kvm_limitations:
        if cli.startswith(rule["cli_prefix"]) and any(err in output for err in rule["errors"]):
            return True
    return False


def is_smartswitch_device(duthost):
    """Return True when the DUT is a SmartSwitch (has DPU modules)."""
    return bool(duthost.facts.get("is_smartswitch"))


def is_non_smartswitch_limitation(duthost, cli, stdout, stderr):
    """
    Returns True for commands that are only relevant on SmartSwitch platforms
    and are expected to fail on any non-SmartSwitch device.
    """
    if is_smartswitch_device(duthost):
        return False

    output = "{}\n{}".format(stdout or "", stderr or "")

    non_smartswitch_limitations = [
        {
            "cli_prefix": "show system-health dpu",
            "errors": ["module all not found", "module", "not found"],
        },
    ]

    for rule in non_smartswitch_limitations:
        if cli.startswith(rule["cli_prefix"]) and any(err in output for err in rule["errors"]):
            return True
    return False


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_show_cli_schema_and_safeguard(
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
        dummy_arg_keys = set()
        if required_args:
            arg_error = None
            for arg in required_args:
                value, used_dummy, err = resolve_arg_value(arg, duthost)
                if err:
                    arg_error = err
                    break
                required_arg_values.append(value)
                if used_dummy:
                    dummy_arg_keys.add(arg)
            if arg_error:
                failures.append({
                    "cli": path,
                    "xpath": "",
                    "reason": arg_error
                })
                continue

        argument_combinations = []
        if required_args:
            argument_combinations = generate_required_argument_combinations(required_arg_values)
        elif optional_args:
            arg_values = []
            optional_arg_failed = False
            for arg in optional_args:
                value, used_dummy, err = resolve_arg_value(arg, duthost)
                if err:
                    failures.append({
                        "cli": path,
                        "xpath": "",
                        "reason": err
                    })
                    optional_arg_failed = True
                    break
                arg_values.append(value)
                if used_dummy:
                    dummy_arg_keys.add(arg)
            if optional_arg_failed:
                continue
            argument_combinations = generate_optional_argument_combinations(arg_values)
        else:
            argument_combinations = [[]]

        tolerate_failure = bool(dummy_arg_keys & TOLERATE_DUMMY_FAILURE_KEYS)

        for argument_combination in argument_combinations:
            try:
                per_option_lists, dummy_option_tokens = (
                    option_value_lists(options, duthost, argument_combination) if options else ([], set())
                )
            except (KeyError, ValueError) as e:
                failures.append({"cli": path, "xpath": "", "reason": str(e)})
                continue
            for opt_tokens in (generate_option_combinations(per_option_lists) if per_option_lists else [[]]):
                combo_tolerate_failure = tolerate_failure or any(t in dummy_option_tokens for t in opt_tokens)
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

                # Check critical-process status BEFORE the rc-driven `continue`
                # paths below - otherwise a request that kills a critical process
                # AND returns nonzero would be reported as a plain rc failure
                # (or tolerated silently if combo_tolerate_failure), and the
                # far-worse "critical process died" signal would be dropped.
                after_status = duthost.all_critical_process_status()
                if before_status != after_status:
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": "Critical process status changed after GET"
                    })

                if rc != 0:
                    if is_large_message_error(stdout, stderr):
                        continue
                    if is_kvm_limitation(duthost, cli, stdout, stderr):
                        logger.info(
                            "Tolerating expected VS/KVM limitation for CLI '%s'",
                            cli,
                        )
                        continue
                    if is_non_smartswitch_limitation(duthost, cli, stdout, stderr):
                        logger.info(
                            "Tolerating expected non-SmartSwitch limitation for CLI '%s'",
                            cli,
                        )
                        continue
                    if combo_tolerate_failure:
                        logger.info(
                            "Tolerating expected gNMI failure for dummy-value CLI '%s' "
                            "(dummy arg keys: %s)", cli, sorted(dummy_arg_keys)
                        )
                        continue
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": f"ptf rc={rc}, stderr={stderr!r}, stdout={stdout!r}"
                    })
                    continue

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
        logger.info(f"{lines}")
        pytest.fail("\n".join(lines))
