"""
To ensure that a test script is included in the PR checker for the corresponding topology type,
this script will perform a validation check.
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
        'covered': False
    },
    {
        'testscript': 'bgp/test_bgp_allow_list.py',
        'topology': 't1',
        'trackid': '3aa57f0f-8f18-4cf7-ae1e-0a18973a0b86',
        'scantime': '2024-05-31 06:53:40.826349',
        'category': 'control',
        'covered': False
    }
]
"""

import yaml
import re
import os
import sys
import uuid
import logging

from natsort import natsorted
from datetime import datetime
from constant import DATAPLANE_FEATURES, PR_TOPOLOGY_TYPE


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
                            result = {
                                "testscript": filename,
                                "topology": topology.strip().strip('"').strip('\'')
                            }
                            test_scripts.append(result)
        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(f, e))

    return test_scripts


def check_PRChecker_coverd(test_scripts):
    '''
    Check if a script is included in the PR checker for the corresponding topology type
    '''
    pr_test_scripts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../", "pr_test_scripts.yaml")

    # Get all the scripts included in different PR checker
    try:
        with open(pr_test_scripts_file) as f:
            pr_test_scripts = yaml.safe_load(f)
    except Exception as e:
        logging.error('Failed to load file {}, error {}'.format(f, e))

    # Check if a script is included in the PR checker for the corresponding topology type
    # If the topology mark is "any", we will check if it is included in all topology types of PR checker.
    i = 0
    while i < len(test_scripts):
        topo_type = test_scripts[i]["topology"]

        if topo_type == "any":
            for topology in PR_TOPOLOGY_TYPE:
                test_scripts.append({
                    "testscript": test_scripts[i]["testscript"],
                    "topology": topology
                })
            test_scripts.remove(test_scripts[i])
            continue

        if test_scripts[i]["testscript"] in pr_test_scripts.get(topo_type, ""):
            test_scripts[i]["covered"] = True
        else:
            test_scripts[i]["covered"] = False
        i += 1


def main():
    test_scripts = collect_all_scripts()
    check_PRChecker_coverd(test_scripts)

    # Add additionally field to mark one running
    trackid = str(uuid.uuid4())
    scantime = str(datetime.now())

    # Also, we will specify if the script belongs to data plane or control plane
    for script in test_scripts:
        script["trackid"] = trackid
        script["scantime"] = scantime
        if script["testscript"].split("/")[0] in DATAPLANE_FEATURES:
            script["category"] = "data"
        else:
            script["category"] = "control"


if __name__ == '__main__':
    main()
