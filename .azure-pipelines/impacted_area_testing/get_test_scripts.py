#!/usr/bin/env python3

"""
    Scripts for getting test scripts in impacted area
    Example:
        python impacted_area_testing/get_test_scripts.py vrf,gnmi ../tests

    It will get all test scripts in specific impacted area.
"""
import os
import re
import logging
import json
import argparse
from natsort import natsorted
from constant import PR_TOPOLOGY_TYPE, EXCLUDE_TEST_SCRIPTS


def topo_name_to_topo_checker(topo_name):
    pattern = re.compile(r'^(ciscovs-7nodes|ciscovs-5nodes|wan|wan-pub-isis|wan-com|wan-pub|wan-pub-cisco|wan-3link-tg|'
                         r't0|t0-52|t0-mclag|mgmttor|m0|mc0|mx|'
                         r't1|t1-lag|t1-56-lag|t1-64-lag|'
                         r'ptf|fullmesh|dualtor|t2|tgen|multidut-tgen|dpu|any|snappi|util|'
                         r't0-2vlans|t0-sonic|t1-multi-asic)$')
    match = pattern.match(topo_name)
    if match is None:
        logging.warning("Unsupported testbed type - {}".format(topo_name))
        return topo_name

    topo_type = match.group()
    if topo_type in ['mgmttor', 'm0', 'mc0', 'mx', 't0-52', 't0-mclag']:
        # certain testbed types are in 't0' category with different names.
        topo_type = 't0'
    elif topo_type in ['t1-lag', 't1-56-lag', 't1-64-lag']:
        topo_type = 't1'

    topology_checker = topo_type + "_checker"

    return topology_checker


def distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker):
    for topology in match.group(1).split(","):
        topology_mark = topology.strip().strip('"').strip("'")
        if topology_mark == "any":
            for key in ["t0_checker", "t1_checker"]:
                if script_name not in test_scripts_per_topology_checker[key]:
                    test_scripts_per_topology_checker[key].append(script_name)
        else:
            topology_checker = topo_name_to_topo_checker(topology_mark)
            if topology_checker in test_scripts_per_topology_checker \
                    and script_name not in test_scripts_per_topology_checker[topology_checker]:
                test_scripts_per_topology_checker[topology_checker].append(script_name)


def collect_scripts_by_topology_type(features: str, location: str) -> dict:
    """
    This function collects all test scripts under the impacted area and category them by topology type.

    Args:
        Features: The impacted area defined by features
        Location: The location of test scripts

    Returns:
        Dict: A dict of test scripts categorized by topology type.
    """
    # Recursively find all files starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "files"
    scripts = []

    for feature in features.split(","):
        feature_path = os.path.join(location, feature)
        for root, dirs, script in os.walk(feature_path):
            for s in script:
                if s.startswith("test_") and s.endswith(".py"):
                    scripts.append(os.path.join(root, s))
    scripts = natsorted(scripts)

    # Open each file and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    # Init the dict to record the mapping of topology type and test scripts
    test_scripts_per_topology_checker = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_checker[topology_type] = []

    for s in scripts:
        # Remove prefix from file name:
        script_name = s[len(location) + 1:]
        if script_name in EXCLUDE_TEST_SCRIPTS:
            continue

        try:
            with open(s, 'r') as script:
                for line in script:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker)
                        break
        except Exception as e:
            raise Exception('Exception occurred while trying to get topology in {}, error {}'.format(s, e))

    return {k: v for k, v in test_scripts_per_topology_checker.items() if v}


def main(features, location):
    scripts_list = collect_scripts_by_topology_type(features, location)
    print(json.dumps(scripts_list))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", help="Impacted area", nargs='?', const="", type=str, default="")
    parser.add_argument("--location", help="The location of folder `tests`", type=str, default="")
    args = parser.parse_args()

    features = args.features
    location = args.location
    main(features, location)
