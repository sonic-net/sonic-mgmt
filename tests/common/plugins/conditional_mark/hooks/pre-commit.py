import os
import re
from ruamel import yaml
import sys

def main():
    with os.popen("git diff --cached --name-only", "r") as p:
        stage_files = p.read().split()

    for file in stage_files:
        if not re.match(r'(.*)tests_mark_conditions(.*).yaml', file):
            stage_files.remove(file)

    for file in stage_files:
        with open(file) as f:
            if not f.read():
                sys.exit(0)
            conditions = list(yaml.round_trip_load(f).keys())
            pre = conditions[0]
            for condition in conditions[1:]:
                if condition < pre:
                    sys.exit(-1)
                else:
                    pre = condition
    sys.exit(0)

if __name__ == "__main__":
    main()
