import re
import os
import sys
import logging

from natsort import natsorted


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

    for f in files:
        has_markers = False
        # Remove prefix from file name:
        filename = f[len(location) + 1:]
        try:
            with open(f, 'r') as file:
                for line in file:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        has_markers = True
                        break

            if not has_markers:
                print("\033[31mPlease add mark `pytest.mark.topology` in script {}\033[0m".format(filename))
                sys.exit(1)

        except Exception as e:
            logging.error('Failed to load file {}, error {}'.format(f, e))

    sys.exit(0)


def main():
    collect_all_scripts()


if __name__ == '__main__':
    main()
