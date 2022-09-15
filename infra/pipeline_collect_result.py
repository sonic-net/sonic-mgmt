#!/usr/bin/python

import json

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

sum_f = open("../../" + SUMMARY_REPORT_FILENAME, "w")
com_f = open("../../" + COMMON_REPORT_FILENAME, "w")

sum = {"passx": 0, "total": 0, "failed": 0, "passed": 0, "aborted": 0, "blocked": 0, "errored": 0, "skipped": 0, "success_rate": 0.0}

try:
    full_report = open("./full_report.txt", "r")
    lines = full_report.readlines()
    total_line = lines[-1]
    for line in lines:
        if line.startswith("Total"):
            total_line = line

    print(total_line)
    if total_line:
        for item in total_line.split(","):
            if item.startswith("Total TCs"):
                cat, num = item.strip().split(":")
            else:
                num, cat = item.strip().split(" ")
            if cat == "Total TCs":
                sum["total"] += int(num)
            elif cat == "Pass":
                sum["passed"] += int(num)
            elif cat == "Fail":
                sum["failed"] += int(num)
            elif cat == "Skipped":
                sum["skipped"] += int(num)
            elif cat == "Error":
                sum["errored"] += int(num)

            if sum["total"] > 0:
                sum["success_rate"] = sum["passed"] / sum["total"]

            print("num %s, cat %s, sum %s" %(num, cat, sum))
    com_f.writelines(lines)
except:
    print("error: full_report.txt file not exit!")
    com_f.write("full_report.txt file was not found, did something go wrong?")

json.dump(sum, sum_f)

sum_f.close()
com_f.close()

