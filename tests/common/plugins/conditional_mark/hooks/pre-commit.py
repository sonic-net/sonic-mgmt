import os
import re
import sys
import logging

def main():
    stage_files = sys.argv[1:]
    print("YT test stage_files {}".format(stage_files))
    for file in stage_files:
        conditions = []
        with open(file, 'r') as f:
            file_contents = f.readlines()
            if not file_contents:
                continue
            for line in file_contents:
                if re.match('[a-zA-Z]', line):
                    conditions.append(line.splitlines()[0])

            pre = conditions[0]
            for condition in conditions[1:]:
                if condition < pre:
                    logging.info(condition)
                    sys.exit(-1)
                else:
                    pre = condition
    sys.exit(0)

if __name__ == "__main__":
    main()
