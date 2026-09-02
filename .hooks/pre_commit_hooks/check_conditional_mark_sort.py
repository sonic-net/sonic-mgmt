import re
import sys


def main():
    stage_files = sys.argv[1:]
    for stage_file in stage_files:
        if "tests_mark_conditions" in stage_file:
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
                for i in range(len(conditions)):
                    if conditions[i] != sorted_conditions[i]:
                        print("The entries in tests/common/plugins/conditional_mark/tests_mark_conditions*.yaml "
                              "are not sorted in alphabetic order, please adjust the order before commit")
                        print("===========================================================================")
                        print("File: {}".format(stage_file))
                        print("===========================================================================")
                        print("Conditional marks before sort: {}".format(conditions))
                        print("Conditional marks after sort: {}".format(sorted_conditions))
                        print("===========================================================================")
                        print("Mismatch item, before sort: {}, after sort: {}".format(conditions[i],
                                                                                      sorted_conditions[i]))
                        print("===========================================================================")
                        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
