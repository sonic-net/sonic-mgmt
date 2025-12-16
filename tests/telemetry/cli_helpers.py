import json
from tests.common.reboot import reboot


def get_json_from_gnmi_output(stdout):
    marker_pos = stdout.find("The GetResponse is below")
    start_pos = stdout.find("{", marker_pos)

    assert start_pos > 0, "JSON not found in GetResponse"

    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(stdout[start_pos:])
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
