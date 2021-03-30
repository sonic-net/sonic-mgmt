#!/router/bin/python3.8.2_mcpre-v1

import argparse
import json
import logging
import os
import subprocess
import time

def _create_parser():
    parser = argparse.ArgumentParser(description='Execute scripts and parse result.')
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=True,default='t1_scripts.txt')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default=None)
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default=None)
    parser.add_argument('-p', '--only_parse', action='store_true', help='Just Parse results',
                      default=False)
    return parser

def run_scripts(script_file,drop_version,log_dir):
    if drop_version is not None:
        filename = "ongoing_result_{}.txt".format(drop_version)
    else:
        filename = 'ongoing_result.txt'
    if log_dir is not None:
        log_dir = '/data/tests/{}'.format(log_dir)
    else:
        log_dir = '/data/tests/run_logs'
    current_result_file = open(filename, 'w')
    tcs_file = open(script_file, 'r')
    tcs = tcs_file.readlines()
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_error = 0
    final_total = 0
    for tc in tcs:
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]
        if drop_version is not None:
            tc_name = tc_name + "_" + drop_version

        print("Executing: {}".format(tc))
        
        cmd = "./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p {} -c {} |& tee {}.log".format(log_dir,tc,tc_name)
        subprocess.Popen("bash -c '{}'".format(cmd),shell=True)
        total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(tc_name), shell=True).strip()
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(tc_name), shell=True).strip()
        failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(tc_name), shell=True).strip()
        skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(tc_name), shell=True).strip()
        errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(tc_name), shell=True).strip()
        time.sleep(10)
        final_total += total_tests
        total_passed += passed
        total_failed += failed
        total_skipped += skipped
        total_error += errored

        print("{}     : {} : {} : {} : {} : {}".format(tc_name,total_tests,passed,failed,skipped,errored))

        current_result_file.write("{}     , {} , {} , {} , {} , {} \n".format(tc_name,total_tests,passed,failed,skipped,errored))
        current_result_file.flush()

    current_result_file.write("Total     , {} , {} , {} , {} , {} \n".format(final_total,total_passed,total_failed,total_skipped,total_error))
    current_result_file.close()

def parse_results():
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_error = 0
    final_total = 0

    log_list = list()
    for filename in os.listdir('/data/tests'):
        if filename.endswith(".log") or filename.endswith(".txt"):
            log_list.append(filename)
        else:
            continue

    result_file = open('final_result.txt', 'w')
    if len(log_list) > 0:
        for log_file in log_list:
            os.system("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g'  >> all_result.txt".format(log_file))

            total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(log_file), shell=True).strip()
            passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(log_file), shell=True).strip()
            failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(log_file), shell=True).strip()
            skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(log_file), shell=True).strip()
            errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(log_file), shell=True).strip()

            final_total += total_tests
            total_passed += passed
            total_failed += failed
            total_skipped += skipped
            total_error += errored
            print("{}     : {} : {} : {} : {} : {} \n".format(log_file,total_tests,passed,failed,skipped,errored))

            result_file.write("{}     , {} , {} , {} , {} , {} \n".format(log_file,total_tests,passed,failed,skipped,errored))

    result_file.write("Total     , {} , {} , {} , {} , {} \n".format(final_total,total_passed,total_failed,total_skipped,total_error))
    result_file.close()


def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    script_file = args['script_file']
    drop_version = args['drop_version']
    log_dir = args['log_dir']
    only_parse = args['only_parse']

    if only_parse:
        parse_results()
    else:
        run_scripts(script_file,drop_version,log_dir)

if __name__ == '__main__':
  main()



