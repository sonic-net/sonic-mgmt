import re
import sys


def main():
    stage_files = sys.argv[1:]
    for stage_file in stage_files:
        conditions = []
        with open(stage_file, 'r') as f:
            file_contents = f.readlines()
            if not file_contents:
                continue
            for line in file_contents:
                if re.match('^[a-zA-Z]', line):
                    conditions.append(line.strip().rstrip(":"))
            sorted_conditions = conditions[:]
            sorted_conditions.sort()
            if conditions != sorted_conditions:
                sys.exit(-1)
    sys.exit(0)


if __name__ == "__main__":
    main()
