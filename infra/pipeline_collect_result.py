#!/usr/bin/python

import json

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

try:
    full_report = open("./full_report.txt", "r")
except:
    print("error: full_report.txt file not exit!")
    exit(-1)

sum = {"passx": 0, "total": 0, "failed": 0, "passed": 0, "aborted": 0, "blocked": 0, "errored": 0, "skipped": 0, "success_rate": 0.0}

lines = full_report.readlines()
total_line = lines[-1]

for item in total_line.split(",")[1:]:
    num, cat = item.strip().split(" ")
    #print("num %s, cat %s, sum %s" %(num, cat, sum))
    if cat == "Total":
        sum["total"] += int(num)
    elif cat == "Passed":
        sum["passed"] += int(num)
    elif cat == "Failed":
        sum["failed"] += int(num)
    elif cat == "SKip":
        sum["skipped"] += int(num)
    elif cat == "Error":
        sum["errored"] += int(num)

    if sum["total"] > 0:
        sum["success_rate"] = sum["passed"] / sum["total"]

sum_f = open("../../" + SUMMARY_REPORT_FILENAME, "w")
com_f = open("../../" + COMMON_REPORT_FILENAME, "w")

json.dump(sum, sum_f)
com_f.writelines(lines)

sum_f.close()
com_f.close()
