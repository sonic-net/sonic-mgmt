import csv
import datetime
import json
import os
import pprint
import re
import subprocess
import sys

import yaml

import generate_spytest_html_report as html_report

VXR_PORTS_FILENAME = "vxr_ports.yaml"
RESULT_FOLDER_PATH = "/home/vxr/sonic-test/sonic-mgmt/spytest/spytest_results"

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
TOPO_PLATFORM_FILE_MAP = "topo_and_platform_to_filename_map.json"
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)
PARALLEL_LOG = "/tmp/spytest_parallel.log"

def extract_test_start_time(spytest_results_files):
    test_start_time = []

    for file in spytest_results_files:
        if "summary.txt" in file:
            test_start_time.append("_".join(file.split("_")[1:-1]))

    return test_start_time

def collect_result(sim_dir):

    from pathlib import Path

    directory_path = Path(f"{sim_dir}/spytest_result")

    # Get the list of file names
    spytest_results_files = [f.name for f in directory_path.iterdir() if f.is_file()]

    test_start_time = extract_test_start_time(spytest_results_files)
    if not test_start_time:
        print(f"Summary file doesn't exists for {sim_dir}, probably skipped because of sim errors")

    ret = 0
    try:
        summary = dict()
        for test_time in test_start_time:
            summary = {
                "SIM_ID": "sim_0",
                "TEST_SUITE": "",
                "SCRIPT_NAME": "",
                "EXEC_START_TIME": "0",
                "EXEC_COMPLETION_TIME": 0,
                "EXECUTION_TIME": 0,
                "TOTAL_TEST": 0,
                "FAILED_TEST": 0,
                "PASSED_TEST": 0,
                "SKIPPED_TEST": 0,
                "SUCCESS_RATE": 0.0,
                "LOG_REPORT": ""
            }
            failed_test_list = []
            spytest_result_summary_file = open(
                f"{sim_dir}/spytest_result/results_{test_time}_summary.txt", "r"
            )
            spytest_result_summary = spytest_result_summary_file.readlines()
            spytest_result_summary_file.close()
            #print(f"{spytest_result_summary=}")

            # SPYTEST_SUITE_NAME_ARG
            export_file = open(
                f"{sim_dir}/spytest_result/results_{test_time}_export.txt", "r"
            )
            export_summary_data = export_file.readlines()
            export_file.close()

            for line in export_summary_data:
                if 'SPYTEST_SUITE_NAME_ARG' in line:
                    suite_name = line.split('/')[-1]
                    summary['TEST_SUITE'] = suite_name.strip()
                    #print(f"{summary['TEST_SUITE']=}")

            test_file = open(
                f"{sim_dir}/spytest_result/results_{test_time}_testcases.csv", "r"
            )
            test_file_cont = csv.DictReader(test_file, skipinitialspace=True)

            summary["SIM_ID"] = sim_dir.split("/")[-1]
            for line in spytest_result_summary:
                if "=" not in line:
                    continue

                key, value = line.split("=")
                key = key.strip()
                value = value.strip()

                if key == "PASS":
                    summary["PASSED_TEST"] = int(value)
                elif key in [
                    "UNSUPPORTED",
                    "SCRIPTERROR",
                    "DEPFAIL",
                    "ENVFAIL",
                    "TIMEOUT",
                    "FAIL",
                ]:
                    summary["FAILED_TEST"] = int(value)
                elif key == "SKIPPED":
                    summary["SKIPPED_TEST"] = int(value)
                elif key == "Test Count":
                    summary["TOTAL_TEST"] = int(value)
                elif key == "Execution Started":
                    summary["EXEC_START_TIME"] = value
                elif key == "Execution Completed":
                    summary["EXEC_COMPLETION_TIME"] = value
                elif key == "Execution Time":
                    summary["EXECUTION_TIME"] = value
                elif key == "Software Versions":
                    summary["SOFTWARE_VERSION"] = value
                elif key == "DUT_FAIL":
                    summary["DUT_FAIL"] = value
                elif key == "CMDFAIL":
                    summary["CMD_FAIL"] = value
                elif key == "CONFIGFAIL":
                    summary["CONFIG_FAIL"] = value
                elif key == "TGENFAIL":
                    summary["TGEN_FAIL"] = value


            tmp_sim = sim_dir.split("/")[-1]
            if tmp_sim not in failed_test_dict:
                failed_test_dict[tmp_sim] = []

            for row in test_file_cont:
                script_name = os.path.basename(row["Module"])
                script_name = script_name.strip()
                summary["SCRIPT_NAME"] = script_name
                script_name = os.path.basename(script_name)
                script_name = os.path.splitext(script_name)[0]
                if row["Result"] != "Pass":
                    failed_log = ""
                    for report_file in spytest_results_files:
                        if f"{script_name}.log" in report_file:
                            #print(f"{report_file=}")
                            failed_log = report_file
                    failed_test_list.append((row['Module'], row['TestCase'], failed_log))

            failed_test_dict[tmp_sim].extend(failed_test_list)

            try:
                summary["SUCCESS_RATE"] = round(
                    summary["PASSED_TEST"]
                    / (summary["TOTAL_TEST"] - summary["SKIPPED_TEST"])
                    * 100,
                    2,
                )
            except ZeroDivisionError as e:
                print("Test script seems to have skipped")
                summary["SUCCESS_RATE"] = 0.00

            log_report = f"dashboard_{summary['TEST_SUITE']}.html"
            summary['LOG_REPORT'] = log_report
            all_results.append(summary)

    except BaseException as e:
        print("Exception! Failed to open result file!", e.with_traceback())
        ret = 1

    return ret, ""

def init(result_dir=None):
    cur_dir = result_dir or os.getcwd()
    global NUM_OF_SIM
    NUM_OF_SIM = 8

    for i in range(1, NUM_OF_SIM + 1):
        sim_dir = f"{cur_dir}/sim_{i}"
        rc, msg = collect_result(sim_dir)
        if rc != 0:
            print(f"error at collect_result! msg: {msg}")

    test_data = {'script_data': all_results, 'failed_tc_data': failed_test_dict}
    with open(SUMMARY_REPORT_PATH, 'w') as file:
        json.dump(test_data, file, indent=2)

    print(f"{test_data}")
    print(f"{os.path.abspath(SUMMARY_REPORT_PATH)=}")
    parallel_log = os.path.basename(PARALLEL_LOG)
    html_report.generate_test_report(all_results, failed_test_dict, dest=cur_dir, log=parallel_log)

def main():
    RESULT_FOLDER_PATH = sys.argv[1]
    results_dir = RESULT_FOLDER_PATH or os.getcwd()
    #results_dirs = os.listdir(results_dir)
    #results_dirs = [f"{RESULT_FOLDER_PATH}/{item}" for item in results_dirs if os.path.isdir(f"{RESULT_FOLDER_PATH}/{item}/")]
    if not(os.path.exists(results_dir) and os.path.isdir(results_dir)):
        print("The directory {results_dir} does not exists")
        sys.exit(0)

    global failed_test_dict, all_results
    results_dirs = []
    results_dirs.append(results_dir)

    for idx, res_dir in enumerate(results_dirs):
        failed_test_dict = {}
        all_results = []
        init(result_dir=res_dir)


if __name__ == "__main__":
    main()

