import re
import os
import sys
import logging

from natsort import natsorted


def collect_scripts_without_topology_markers():
    """
    This function collects all test scripts under the folder 'tests/' and check the topology type marked in the script.

    Returns:
        List: A list of test scripts without the topology type marker.
    """
    location = sys.argv[1]

    # Recursively find all scripts starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "scripts"
    scripts = []
    for root, dirs, script in os.walk(location):
        for s in script:
            if s.startswith("test_") and s.endswith(".py"):
                scripts.append(os.path.join(root, s))
    scripts = natsorted(scripts)

    # Open each script and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    scripts_without_marker = []

    for s in scripts:
        has_markers = False
        # Remove prefix from file name:
        script_name = s[len(location) + 1:]
        try:
            with open(s, 'r') as script:
                match = pattern.search(script.read())
                if match:
                    has_markers = True
                    break

            if not has_markers:
                scripts_without_marker.append(script_name)

        except Exception as e:
            raise Exception('Exception occurred while trying to get marker in {}, error {}'.format(s, e))

    return scripts_without_marker


def main():
    try:
        scripts_without_marker = collect_scripts_without_topology_markers()

        if scripts_without_marker:
            for script in scripts_without_marker:
                print("\033[31mPlease add mark `pytest.mark.topology` in script {}\033[0m".format(script))
            sys.exit(1)

        sys.exit(0)
    except Exception as e:
        logging.error(e)
        sys.exit(2)


if __name__ == '__main__':
    main()
