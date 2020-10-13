#!/usr/bin/python
"""
    Script to modify a COPP configuration to follow a specified rate limit.

    This is used by the COPP tests to reduce the rate limit below that of the
    PTF host's sending rate.

    Example::

        $ python update_copp_config.py <rate limit in pps> <input file> <output file>
        $ python update_copp_config.py 600 /tmp/copp_config.json /tmp/new_copp_config.json
"""
import json
import sys

def generate_limited_pps_config(pps_limit, input_config_file, output_config_file):
    """
        Modifies a COPP config to use the specified rate limit.

        Notes:
            This only affects COPP policies that enforce a rate limit. Other
            policies are left alone.

        Args:
            pps_limit (int): The rate limit to enforce expressed in PPS (packets-per-second)
            input_config_file (str): The name of the file containing the initial config
            output_config_file (str): The name of the file to output the modified config
    """

    with open(input_config_file) as input_stream:
        copp_config = json.load(input_stream)

    for trap_group in copp_config:
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
    generate_limited_pps_config(ARGS[0], ARGS[1], ARGS[2])
