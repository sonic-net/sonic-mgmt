#!/usr/bin/env python3

"""
    Scripts for getting test scripts according to topology type and feature folders
    Example:
        python validate_diff_folders/get_test_scripts.py dpu vrf,gnmi ../tests

    It will get all test scripts that can run on the testbeds of specific topology type in specific feature folder.
"""
import os
import sys
import re
import logging
from natsort import natsorted
from constant import PR_TOPOLOGY_TYPE


def topo_name_to_type(topo_name):
    pattern = re.compile(r'^(wan|t0|t1|ptf|fullmesh|dualtor|t2|tgen|multidut-tgen|mgmttor|m0|mc0|mx|dpu|any|snappi)')
    match = pattern.match(topo_name)
    if match is None:
        logging.warning("Unsupported testbed type - {}".format(topo_name))
        return topo_name

    topo_type = match.group()
    if topo_type in ['mgmttor', 'dualtor', 'm0', 'mc0', 'mx']:
        # certain testbed types are in 't0' category with different names.
        topo_type = 't0'
    if topo_type in ['multidut-tgen']:
        topo_type = 'tgen'
    return topo_type


def collect_all_scripts(topo_type, features):
    '''
    This function collects all test scripts under the folder 'tests/'
    and get all test scripts that can run on the testbeds of this topology type in specific feature folders
    '''
    location = sys.argv[3]

    # Recursively find all files starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "files"
    files = []
    for feature in features.split(","):
        feature_path = os.path.join(location, feature)
        for root, dirs, file in os.walk(feature_path):
            for f in file:
                if f.startswith("test_") and f.endswith(".py"):
                    files.append(os.path.join(root, f))
    files = natsorted(files)

    # Open each file and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    # Init the dict to record the mapping of topology type and test scripts
    test_scripts_per_topology_type = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_type[topology_type] = []

    for f in files:
        # Remove prefix from file name:
        filename = os.path.join(f.split('/')[-2], f.split('/')[-1])
        try:
            with open(f, 'r') as file:
                for line in file:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        for topology in match.group(1).split(","):
                            topology_mark = topology.strip().strip('"').strip('\'')
                            if topology_mark == "any":
                                for key in test_scripts_per_topology_type:
                                    test_scripts_per_topology_type[key].append(filename)
                            else:
                                topology_type = topo_name_to_type(topology_mark)
                                if topology_type in test_scripts_per_topology_type:
                                    test_scripts_per_topology_type[topology_type].append(filename)
        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(f, e))
    return test_scripts_per_topology_type[topo_type]


def main(topo_type, features):
    scripts_list = collect_all_scripts(topo_type, features)
    print(','.join(scripts_list))
    return ','.join(scripts_list)


if __name__ == '__main__':
    topo_type = sys.argv[1]
    features = sys.argv[2]
    main(topo_type, features)
