#!/usr/bin/env python3

"""
    Scripts for getting test scripts in impacted area
    Example:
        python impacted_area_testing/get_test_scripts.py --files file1.py file2.py

    It will get all test scripts in specific impacted area.
"""
import re
import logging
import json
import argparse
from constant import PR_TOPOLOGY_TYPE, EXCLUDE_TEST_SCRIPTS
from pathlib import Path


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
    elif 't2' in topo_type:
        topo_type = 't2'

    topology_checker = topo_type + "_checker"

    return topology_checker


def distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker):
    for topology in match.group(1).split(","):
        topology_mark = topology.strip().strip('"').strip("'")
        if topology_mark == "any":
            for key in ["t0_checker", "t1_checker", "t2_checker"]:
                if script_name not in test_scripts_per_topology_checker[key]:
                    test_scripts_per_topology_checker[key].append(script_name)
        else:
            topology_checker = topo_name_to_topo_checker(topology_mark)
            if topology_checker in test_scripts_per_topology_checker \
                    and script_name not in test_scripts_per_topology_checker[topology_checker]:
                test_scripts_per_topology_checker[topology_checker].append(script_name)


def collect_scripts_by_topology_type_from_files(files: list) -> dict:
    """
    This function collects test scripts from the provided list of files and categorizes them by topology type.

    Args:
        files: List of file paths to analyze.

    Returns:
        Dict: A dict of test scripts categorized by topology type.
    """
    # Regex pattern to find pytest topology markers
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    # Init the dict to record the mapping of topology type and test scripts
    test_scripts_per_topology_checker = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_checker[topology_type] = []

    for file_path in files:
        # Remove the top-level 'tests' directory from the file path
        script_name = str(Path(file_path).relative_to("tests"))
        if script_name in EXCLUDE_TEST_SCRIPTS:
            continue

        try:
            with open(file_path, 'r') as script:
                for line in script:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker)
                        break
        except Exception as e:
            raise Exception(f'Exception occurred while trying to get topology in {file_path}, error {e}')

    return {k: v for k, v in test_scripts_per_topology_checker.items() if v}


def main(files):
    scripts_list = collect_scripts_by_topology_type_from_files(files)
    print(json.dumps(scripts_list))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", help="List of files to analyze", nargs='+', type=str, required=True)
    args = parser.parse_args()

    files = args.files
    main(files)
