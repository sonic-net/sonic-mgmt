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
    pr_test_scripts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../", "pr_test_scripts.yaml")

    try:
        with open(pr_test_scripts_file) as f:
            pr_test_scripts = yaml.safe_load(f)
    except Exception as e:
        logging.error('Failed to load file {}, error {}'.format(f, e))

    for test_script in test_scripts:
        topo_type = test_script["topology"]

        if topo_type == "any":
            for topology in PR_TOPOLOGY_TYPE:
                test_scripts.append({
                    "testscript": test_script["testscript"],
                    "topology": topology
                })
            test_scripts.remove(test_script)
            continue

        if test_script["testscript"] in pr_test_scripts.get(topo_type, ""):
            test_script["covered"] = True
        else:
            test_script["covered"] = False


def main():
    test_scripts = collect_all_scripts()
    check_PRChecker_coverd(test_scripts)

    trackid = str(uuid.uuid4())
    scantime = str(datetime.now())

    for script in test_scripts:
        script["trackid"] = trackid
        script["scantime"] = scantime
        if script["testscript"].split("/")[0] in DATAPLANE_FEATURES:
            script["category"] = "data"
        else:
            script["category"] = "control"

    return test_scripts


if __name__ == '__main__':
    main()
