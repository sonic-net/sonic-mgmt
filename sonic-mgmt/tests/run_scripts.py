#!/usr/bin/python

import argparse
import json
import logging
import os
import subprocess
import time
import datetime

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
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32',
                      required=False,default="mth32")
    parser.add_argument('-t', '--tstamp', type=str, help='Time stamp',
                      required=False,default=None)
    return parser

def run_scripts(dut_name,script_file,drop_version,log_dir,tstamp):
    if drop_version is not None:
        filename = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    else:
        filename = 'ongoing_result_{}.csv'.format(tstamp)
    if log_dir is not None:
        log_dir = '/data/tests/{}'.format(log_dir)
    else:
        log_dir = '/data/tests/run_logs'
    current_result_file = open(filename, 'w')
    current_result_file.write("Sno,Feature,T,P,F,S\n")
    tcs_file = open(script_file, 'r')
    tcs = tcs_file.readlines()
    sno = 0
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    final_total = 0
    for tc in tcs:
        if '#' in tc:
            continue
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]
        if drop_version is not None:
            tc_name = tc_name + "_" + drop_version

        print("Executing: {}".format(tc))
        print("./run_tests.sh -n docker-ptf -d {} -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p {} -c {} |& tee {}.log".format(dut_name,log_dir,tc,tc_name))
        cmd = "./run_tests.sh -n docker-ptf -d {} -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p {} -c {} |& tee {}.log".format(dut_name,log_dir,tc,tc_name)
        os.system("bash -c '{}'".format(cmd))
        total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(tc_name), shell=True).strip()
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(tc_name), shell=True).strip()
        failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(tc_name), shell=True).strip()
        skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(tc_name), shell=True).strip()
        errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(tc_name), shell=True).strip()
        time.sleep(10)
        sno += 1
        final_total += int(total_tests)
        total_passed += int(passed)
        total_failed += int(failed)
        total_skipped += int(skipped)
        total_skipped += int(errored)

        print("{}:{}     : {} : {} : {} : {} : {}".format(sno, tc_name,total_tests,passed,failed,skipped,errored))

        current_result_file.write("{}, {}     , {} , {} , {} , {} \n".format(sno, tc_name,total_tests,passed,failed,skipped))
        current_result_file.flush()

    current_result_file.write("Total     , {} , {} , {} , {} \n".format(final_total,total_passed,total_failed,total_skipped))
    current_result_file.close()
    os.system("cat {}".format(filename))

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

    result_file = open('final_result.csv', 'w')
    if len(log_list) > 0:
        for log_file in log_list:
            os.system("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g'  >> all_result.txt".format(log_file))

            total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(log_file), shell=True).strip()
            passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(log_file), shell=True).strip()
            failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(log_file), shell=True).strip()
            skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(log_file), shell=True).strip()
            errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(log_file), shell=True).strip()

            final_total += int(total_tests)
            total_passed += int(passed)
            total_failed += int(failed)
            total_skipped += int(skipped)
            total_error += int(errored)
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
    device_type = args['device_type']
    tstamp = args['tstamp']
    if device_type == 'sherman':
        dut_name = 'sherman-01'
    else:
        dut_name = 'mathilda-01'

    if tstamp is None:        
        tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")

    if only_parse:
        parse_results()
    else:
        run_scripts(dut_name,script_file,drop_version,log_dir,tstamp)

if __name__ == '__main__':
  main()



