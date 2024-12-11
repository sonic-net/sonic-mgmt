import re
import os
import sys
import logging

from natsort import natsorted


def collect_scripts_and_markers():
    '''
    This function collects all test scripts under the folder 'tests/' and get the topology type marked in the script.
    If there is no such marker, we will exit with status code 1.
    If there are some exceptions occurred, we will exit with status code 2.
    Otherwise, we will exit with status code 0.
    '''
    location = sys.argv[1]

    # Recursively find all files starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "files"
    scripts = []
    for root, dirs, script in os.walk(location):
        for s in script:
            if s.startswith("test_") and s.endswith(".py"):
                scripts.append(os.path.join(root, s))
    scripts = natsorted(scripts)

    # Open each file and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    scripts_without_marker = []

    for s in scripts:
        has_markers = False
        # Remove prefix from file name:
        script_name = s[len(location) + 1:]
        try:
            with open(s, 'r') as script:
                for line in script:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        has_markers = True
                        break

            if not has_markers:
                print("\033[31mPlease add mark `pytest.mark.topology` in script {}\033[0m".format(script_name))
                scripts_without_marker.append(script_name)

        except Exception as e:
            logging.error('Exception occurred while trying to get marker in {}, error {}'.format(s, e))
            sys.exit(2)

    if scripts_without_marker:
        sys.exit(1)

    sys.exit(0)


def main():
    collect_scripts_and_markers()


if __name__ == '__main__':
    main()
