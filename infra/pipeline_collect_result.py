#!/usr/bin/python

import json
import re

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

sum_f = open("../../" + SUMMARY_REPORT_FILENAME, "w")
com_f = open("../../" + COMMON_REPORT_FILENAME, "w")

sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0}

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
    sum["success_rate"] = sum["passed"] / (sum["total"] - sum["skipped"]) * 100
print(sum)

json.dump(sum, sum_f)
sum_f.close()
com_f.close()

