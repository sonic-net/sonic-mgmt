#!/usr/bin/python

import os
import json
import re

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

# VXR SIM failure detected, don't overwrite file contents
bgp_failure = False
if (os.path.isfile(SUMMARY_REPORT_PATH)):
    with open(SUMMARY_REPORT_PATH, "r") as summary_file:
        contents = json.load(summary_file)
        if ("status" in contents and contents["status"] == "sim_failure"):
            print("VXR SIM failure detected!")
            exit(1)
        if ("status" in contents and contents["status"] == "bgp_failure"):
            bgp_failure = True

sum_f = open(SUMMARY_REPORT_PATH, "w")
com_f = open(COMMON_REPORT_PATH, "w") 

sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : "sim_success"}

if bgp_failure:
    print("BGP Test Failure Detected")
    sum["total"] = 1
    sum["failed"] = 1
    sum["status"] = "bgp_failure"
    json.dump(sum, sum_f)
    json.dump(sum, com_f)
    sum_f.close()
    com_f.close()
    exit(0)

resultpattern = r'<th class="(passed|skipped|failed)">'
numberpattern = r'<td>(\d+)</td>'

try:
    report = open("./report.html", "r")
except:
    print("error: report.html file not exit!")
    com_f.write("report.html file was not found, did something go wrong?")
    json.dump(sum, sum_f)
    sum_f.close()
    com_f.close()
    exit(1)

resultclass = ""
lines = report.readlines()
for line in lines:
    result = re.findall(resultpattern, line)
    if result:
        print(result[0])
        resultclass = result[0]
    n = re.findall(numberpattern, line)
    if n:
        print(n[0])
        sum[resultclass] = int(n[0])
        sum["total"] += int(n[0])
if sum["total"] > 0:
    sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2)
print(sum)

json.dump(sum, sum_f)
json.dump(sum, com_f)
sum_f.close()
com_f.close()

