"""
To ensure that a test script is included in the PR checker for the corresponding topology type
and if the script is skipped in PR checker, this script will perform a validation check.
Additionally, the return value will be enhanced to include more detailed information, such as the category of the test.
Post-execution, the script will also append the scan time and track ID to the results.

The return value is formatted as below:
[
    {
        'testscript': 'acl/custom_acl_table/test_custom_acl_table.py',
        'topology': 't0',
        'trackid': '3aa57f0f-8f18-4cf7-ae1e-0a18973a0b86',
        'scantime': '2024-05-31 06:53:40.826349',
        'category': 'data',
        'covered': False,
        'skipped': False
    },
    {
        'testscript': 'bgp/test_bgp_allow_list.py',
        'topology': 't1',
        'trackid': '3aa57f0f-8f18-4cf7-ae1e-0a18973a0b86',
        'scantime': '2024-05-31 06:53:40.826349',
        'category': 'control',
        'covered': False,
        'skipped': False
    }
]
And finally, we will upload the results to Kusto table `TestScripts`
"""

import yaml
import re
import os
import sys
import uuid
import logging

from natsort import natsorted
from datetime import datetime
from constant import DATAPLANE_FEATURES, PR_TOPOLOGY_TYPE, PR_TOPOLOGY_MAPPING
from report_data_storage import KustoConnector


def topo_name_to_type(topo_name):
    pattern = re.compile(r'^(wan|t0|t1|ptf|fullmesh|dualtor|t2|tgen|multidut-tgen|mgmttor|m0|mc0|mx|dpu|any|snappi)')
    match = pattern.match(topo_name)
    if match is None:
        logging.warning("Unsupported testbed type - {}".format(topo_name))
        return topo_name

    topo_type = match.group()
    if topo_type in ['mgmttor', 'dualtor']:
        # certain testbed types are in 't0' category with different names.
        topo_type = 't0'
    if topo_type in ['mc0']:
        topo_type = 'm0'
    if topo_type in ['multidut-tgen']:
        topo_type = 'tgen'
    return topo_type


def collect_all_scripts():
    '''
    This function collects all test scripts under the folder 'tests/'
    and get the topology type marked in the script

    The return value is a dict contains the script name and topology type
    [{
        'testscript': 'acl/custom_acl_table/test_custom_acl_table.py',
        'topology': 't0'
    }]
    '''
    location = sys.argv[1]

    # Recursively find all files starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "files"
    files = []
    for root, dirs, file in os.walk(location):
        for f in file:
            if f.startswith("test_") and f.endswith(".py"):
                files.append(os.path.join(root, f))
    files = natsorted(files)

    # Open each file and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")
    test_scripts = []

    for f in files:
        # Remove prefix from file name:
        filename = f[len(location) + 1:]
        try:
            with open(f, 'r') as file:
                for line in file:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        for topology in match.group(1).split(","):
                            topology_mark = topology.strip().strip('"').strip('\'')
                            result = {
                                "testscript": filename,
                                "topology": topo_name_to_type(topology_mark)
                            }
                            test_scripts.append(result)
        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(f, e))

    return test_scripts


def get_pr_checker_scripts():
    '''
    Check if a script is included in the PR checker for the corresponding topology type
    '''
    pr_test_scripts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../", "pr_test_scripts.yaml")

    # Get all the scripts included in different PR checker
    pr_test_scripts = {}
    try:
        with open(pr_test_scripts_file) as f:
            pr_test_scripts = yaml.safe_load(f)
    except Exception as e:
        logging.error('Failed to load file {}, error {}'.format(f, e))

    # Get all the skip scripts
    pr_test_skip_scripts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../",
                                             "pr_test_skip_scripts.yaml")
    pr_test_skip_scripts = {}
    try:
        with open(pr_test_skip_scripts_file) as f:
            pr_test_skip_scripts = yaml.safe_load(f)
    except Exception as e:
        logging.error('Failed to load file {}, error {}'.format(f, e))

    test_scripts_per_topology_type = {}
    skipped_scripts_per_topology_type = {}

    for key, value in pr_test_skip_scripts.items():
        topology_type = PR_TOPOLOGY_MAPPING.get(key, "")
        if topology_type:
            if skipped_scripts_per_topology_type.get(topology_type, ""):
                skipped_scripts_per_topology_type[topology_type].update(value)
            else:
                skipped_scripts_per_topology_type[topology_type] = set(value)

        if key in pr_test_scripts:
            pr_test_scripts[key].extend(value)
        else:
            pr_test_scripts[key] = value

    for key, value in pr_test_scripts.items():
        topology_type = PR_TOPOLOGY_MAPPING.get(key, "")
        if topology_type:
            if test_scripts_per_topology_type.get(topology_type, ""):
                test_scripts_per_topology_type[topology_type].update(value)
            else:
                test_scripts_per_topology_type[topology_type] = set(value)

    return test_scripts_per_topology_type, skipped_scripts_per_topology_type


def expand_test_scripts(test_scripts, test_scripts_per_topology_type, skipped_scripts_per_topology_type):
    # Expand the test scripts list here.
    # If the topology mark is "any", we will add all topology types in PR checker on this script.
    expanded_test_scripts = []
    for test_script in test_scripts:
        topology_mark = test_script["topology"]

        if topology_mark == "any":
            for topology in PR_TOPOLOGY_TYPE:
                expanded_test_scripts.append({
                    "testscript": test_script["testscript"],
                    "topology": topology
                })
        else:
            expanded_test_scripts.append(test_script)

    # Check if a script is included in the PR checker for the corresponding topology type
    # And if this script is skipped in PR checker
    for test_script in expanded_test_scripts:
        topology_type = topo_name_to_type(test_script["topology"])

        test_script["skipped"] = test_script["testscript"] in skipped_scripts_per_topology_type.get(topology_type, "")

        if test_script["testscript"] == "test_posttest.py" or test_script["testscript"] == "test_pretest.py":
            test_script["covered"] = True
        else:
            test_script["covered"] = test_script["testscript"] in test_scripts_per_topology_type.get(topology_type, "")
    return expanded_test_scripts


def upload_results(test_scripts):
    database = sys.argv[2]
    kusto_db = KustoConnector(database)
    kusto_db.upload_testscripts(test_scripts)


def main():
    test_scripts = collect_all_scripts()
    test_scripts_per_topology_type, skipped_scripts_per_topology_type = get_pr_checker_scripts()
    expanded_test_scripts = expand_test_scripts(test_scripts, test_scripts_per_topology_type,
                                                skipped_scripts_per_topology_type)

    # Add additionally field to mark one running
    trackid = str(uuid.uuid4())
    scantime = str(datetime.now())
    print(trackid)

    # Also, we will specify if the script belongs to data plane or control plane
    for script in expanded_test_scripts:
        script["trackid"] = trackid
        script["scantime"] = scantime
        if script["testscript"].split("/")[0] in DATAPLANE_FEATURES:
            script["category"] = "data"
        else:
            script["category"] = "control"
    upload_results(expanded_test_scripts)


if __name__ == '__main__':
    main()
