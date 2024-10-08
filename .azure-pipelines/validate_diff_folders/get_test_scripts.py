'''
args: topology
Filter out the scripts which has the same topology

We need a dict to record the topology and test scripts
'''
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


def collect_all_scripts():
    '''
    This function collects all test scripts under the folder 'tests/'
    and get the topology type marked in the script

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

    # Init the dict to record the mapping of topology type and test scripts
    test_scripts_per_topology_type = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_type[topology_type] = []

    # Add test scripts into above dict
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
                            if topology_mark == "any":
                                for key in test_scripts_per_topology_type:
                                    test_scripts_per_topology_type[key].append(filename)
                            else:
                                test_scripts_per_topology_type[topology_mark].append(filename)
        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(f, e))

    return test_scripts


def main():
    pass


if __name__ == '__main__':
    main()
