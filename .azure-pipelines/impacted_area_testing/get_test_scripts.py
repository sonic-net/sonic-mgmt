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


def topo_name_to_type(topo_name):
    pattern = re.compile(r'^(wan|t0|t1|ptf|fullmesh|dualtor|t2|tgen|multidut-tgen|mgmttor'
                         r'|m0|mc0|mx|dpu|any|snappi|util|t0-2vlans|t0-sonic|t1-multi-asic)')
    match = pattern.match(topo_name)
    if match is None:
        logging.warning("Unsupported testbed type - {}".format(topo_name))
        return topo_name

    topo_type = match.group()
    if topo_type in ['mgmttor', 'm0', 'mc0', 'mx']:
        # certain testbed types are in 't0' category with different names.
        topo_type = 't0'
    if topo_type in ['multidut-tgen']:
        topo_type = 'tgen'
    return topo_type


def collect_all_scripts(features, location):
    '''
    This function collects all test scripts under the impacted area
    and distribute all test scripts to corresponding PR checkers
    '''
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
    test_scripts_per_topology_type = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_type[topology_type] = []

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
                        for topology in match.group(1).split(","):
                            topology_mark = topology.strip().strip('"').strip("'")
                            if topology_mark == "any":
                                for key in ["t0", "t1"]:
                                    if script_name not in test_scripts_per_topology_type[key]:
                                        test_scripts_per_topology_type[key].append(script_name)
                            else:
                                topology_type = topo_name_to_type(topology_mark)
                                if topology_type in test_scripts_per_topology_type \
                                        and script_name not in test_scripts_per_topology_type[topology_type]:
                                    test_scripts_per_topology_type[topology_type].append(script_name)
        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(s, e))

    return {k: v for k, v in test_scripts_per_topology_type.items() if v}


def main(features, location):
    scripts_list = collect_all_scripts(features, location)
    print(json.dumps(scripts_list))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", help="Impacted area", type=str, default="")
    parser.add_argument("--location", help="The location of folder `tests`", type=str, default="")
    args = parser.parse_args()

    features = args.features
    location = args.location
    main(features, location)
