#!/usr/bin/python
"""Script to modify a COPP configuration to follow a specified rate limit.

This is used by the COPP tests to reduce the rate limit below that of the
PTF host's sending rate.

Example:
    python update_copp_config.py <rate limit in pps> <input file> <output file> <config_format>
    python update_copp_config.py 600 /tmp/copp_config.json /tmp/new_copp_config.json app_db

Note:
    Historically, there was a 00-copp.config.json file in the SWSS docker that specified
    the parameters for each trap group like so:

    [
        "COPP_TABLE:default": {
            "cir": "600",
            "cbs": "600",
            ...
        },
        "COPP_TABLE:trap.group.bgp.lacp": {
            ...
        },
        ...
    ]

    This is the "app_db" format used for 202006 images and earlier.

    In newer SONiC versions, there is a copp_cfg.json file on the host that specifies the parameters
    for each trap group like so:

    {
        "COPP_GROUP": {
            "default": {
                "cir":"600",
                "cbs":"600",
                ...
            },
            "queue4_group1": {
                ...
            },
            ...
        },
        ...
    }

    This is the "config_db" format used for 202012 images and later (including the master branch).
"""
import json
import sys


def generate_limited_pps_config(pps_limit, input_config_file, output_config_file, config_format="app_db"):
    """Modifies a COPP config to use the specified rate limit.

    Notes:
        This only affects COPP policies that enforce a rate limit. Other
        policies are left alone.

    Args:
        pps_limit (int): The rate limit to enforce expressed in PPS (packets-per-second)
        input_config_file (str): The name of the file containing the initial config
        output_config_file (str): The name of the file to output the modified config
        config_format (str): The format of the input COPP config file

    """
    with open(input_config_file) as input_stream:
        copp_config = json.load(input_stream)

    if config_format == "app_db":
        trap_groups = copp_config
    elif config_format == "config_db":
        trap_groups = [{x: y} for x, y in copp_config["COPP_GROUP"].items()]
    else:
        raise ValueError("Invalid config format specified")

    for trap_group in trap_groups:
        for _, group_config in trap_group.items():
            # Notes:
            # CIR (committed information rate) - bandwidth limit set by the policer
            # CBS (committed burst size) - largest burst of packets allowed by the policer
            #
            # Setting these two values to pps_limit restricts the policer to allowing exactly
            # that number of packets per second, which is what we want for our tests.

            if "cir" in group_config:
                group_config["cir"] = pps_limit

            if "cbs" in group_config:
                group_config["cbs"] = pps_limit

    with open(output_config_file, "w+") as output_stream:
        json.dump(copp_config, output_stream)


if __name__ == "__main__":
    ARGS = sys.argv[1:]

    if len(ARGS) < 4:
        config_format = "app_db"
    else:
        config_format = ARGS[3]

    generate_limited_pps_config(ARGS[0], ARGS[1], ARGS[2], config_format)
