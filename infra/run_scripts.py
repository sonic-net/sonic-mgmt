#!/usr/bin/python

import argparse
import json
import logging
import os
import subprocess
import time
import datetime
import sys
import requests
import base64
from allure_server import AllureServer
import paramiko

ALLURE_SERVER_IP, ALLURE_SERVER_PORT, ALLURE_DIR = '10.22.183.173', 5050, '/tmp/allure_results'

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
    parser.add_argument('-c', '--collect_logs', action='store_true', help='Just Parse results',
                      default=False)
    parser.add_argument('-a', '--dut_address', type=str, help='specify dut address',
                      required=False,default=None)
    parser.add_argument('-n', '--dut_name', type=str, help='DUT name specified to run tests',
                      required=False,default='mathilda-01')
    parser.add_argument('-g', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
    parser.add_argument('-b', '--build_id', type=str, help='Jenkins Build ID associated with the test',
                      required=False, default=None)
    parser.add_argument('--create_allure_report', action='store_true', help='When testing, specify if allure report to be created at the end of test',
                      default=False)  
    parser.add_argument('--additional_tests', type=str, help='Additional Sanity Test to run',
                      required=False, default="")
    return parser

def run_exec_cmds(host,port,user,passwd,cmd_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for cmd in cmd_list:
        ssh.connect(host, port, user, passwd)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()
        out = stdout.read().decode("ascii").strip()
        error = stderr.read()
        print(out)
        if error:
            print('There was an error pulling the runtime: {}'.format(error))
        ssh.close()

# Generate allure report using data in ALLURE_DIR
def generate_allure_report(build_id, current_result_file):
    try:
        allure_server_obj = AllureServer(ALLURE_SERVER_IP, ALLURE_SERVER_PORT, ALLURE_DIR, build_id)
        report_url = allure_server_obj.generate_allure_report()
        print("Allure report generated, url is: ", report_url)
        current_result_file.write("Allure report generated, url is: {}\n".format(report_url))
        current_result_file.flush()
    except Exception as e:
        print("Error while generating allure report! Error: ", e)
        current_result_file.write("Error while generating allure report! Error: {}\n".format(e))
        current_result_file.flush()

def get_testcases(script_file, additional_tests=''):
    #adding all testcases from all files into one list, ordered
    tcs_dict = {}
    tcs = []

    for filename in script_file.split(","):
        tcs_file = open(filename, 'r')
        for tc in tcs_file.readlines():
            if tc not in tcs_dict:
                tcs.append(tc)
                tcs_dict[tc] = ""
        tcs_file.close()
    
    if additional_tests:
        for tc in additional_tests.split(","):
            if tc not in tcs_dict:
                tcs.append(tc)
                tcs_dict[tc] = ""

    
    print("script files are '{}', additional testscases are: '{}'".format(script_file, additional_tests))
    print("\nTestcases are:")
    print("".join(tcs))
    
    return tcs

def run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,tstamp,build_id,create_allure_report,collect_logs=False,dut_address=None, additional_tests=''):
    if drop_version is not None:
        filename = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    else:
        filename = 'ongoing_result_{}.csv'.format(tstamp)
    if log_dir is not None:
        log_dir = '/data/tests/{}'.format(log_dir)
    else:
        log_dir = '/data/tests/run_logs'
    if build_id is None:
        build_id = 99999
    print("BUILD ID IS {}".format(build_id))
    current_result_file = open(filename, 'w')
    report_file = open('full_report.txt', 'w')
    tcs = get_testcases(script_file, additional_tests)
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_error = 0
    final_total = 0
    ssh_port = 22
    dut_uname = 'cisco'
    dut_passwd = 'cisco123'
    if collect_logs and dut_address is not None:
        cmd_list = list()
        cmd_list.append('mkdir swss_logs_{}\n'.format(drop_version))
        cmd_list.append('sudo rm /var/log/swss/*.gz\n')
        cmd_list.append('sudo rm /var/log/syslog*.gz\n')
        cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}\n'.format(drop_version))
        cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}\n'.format(drop_version))
        run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

    delta1 = datetime.datetime.now()
    tc_name = "bgp_fact"
    cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name,log_dir)
    os.system("bash -c '{}'".format(cmd))
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    if not int(passed):
        print("Iteration1: Rerunning the script, making sure that DUT is up\n")
        current_result_file.write("Iteration1: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
        current_result_file.flush()
        time.sleep(60)
        cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name,log_dir)
        os.system("bash -c '{}'".format(cmd))
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
        if not int(passed):
            print("Iteration2: Rerunning the script, making sure that DUT is up\n")
            current_result_file.write("Iteration2: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
            current_result_file.flush()
            time.sleep(60)
            cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name,log_dir)
            os.system("bash -c '{}'".format(cmd))

    total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l", shell=True).strip()
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l", shell=True).strip()
    skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l", shell=True).strip()
    errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l", shell=True).strip()
    time.sleep(10)
    final_total += int(total_tests)
    total_passed += int(passed)
    total_failed += int(failed)
    total_skipped += int(skipped)
    total_error += int(errored)

    print("{}     : {} : {} : {} : {} : {}".format(tc_name,total_tests,passed,failed,skipped,errored))

    current_result_file.write("{}, {} total, {} Pass, {} Fail, {} Skip, {} Error \n".format(tc_name,total_tests,passed,failed,skipped,errored))
    current_result_file.flush()
    report_file.write("{}     , {} total, {} Pass, {} Fail, {} Skip, {} Error\n".format(tc_name,total_tests,passed,failed,skipped,errored))
    report_file.flush()

    if collect_logs and dut_address is not None:
        cmd_list = list()
        cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
        cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
        run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)
    
    if not int(passed):
        current_result_file.write("{}, {} total, {} Pass, {} Fail, {} Skip, {} Error \n".format(tc_name,total_tests,passed,failed,skipped,errored))
        current_result_file.flush()
        report_file.write("{}     , {} total, {} Pass, {} Fail, {} Skip, {} Error\n".format(tc_name,total_tests,passed,failed,skipped,errored))
        report_file.flush()    
        current_result_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now\n")
        current_result_file.flush()
        report_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now\n")
        report_file.flush()
        # Use previous test results to generate Allure report
        if create_allure_report:
            generate_allure_report(build_id, current_result_file)
        sys.exit("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now")

    current_result_file.write(" -------------- Running Sanity File(s) {}, additional tests: {} ------------- \n".format(script_file, additional_tests)) 
    current_result_file.flush()
    for tc in tcs:
        if '#' in tc:
            continue
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]
        if drop_version is not None:
            tc_name = tc_name + "_" + drop_version

        print("Executing: {}".format(tc))

        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo rm /var/log/swss/sairedis.rec.*\n')
            cmd_list.append('sudo rm /var/log/swss/swss.rec.*\n')
            cmd_list.append('sudo rm /var/log/syslog*.gz\n')
            cmd_list.append('sudo rm /var/log/syslog.*\n')
            cmd_list.append("sudo sh -c '> /var/log/swss/sairedis.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/swss/swss.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/syslog'\n")
            cmd_list.append('mkdir swss_logs_{}/{}\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

        cmd = "./run_tests.sh -n {} -d {} -e --alluredir=/tmp/allure_results -e -rapP -O -u -e --skip_sanity -m individual -p {} -c {} |& tee {}.log".format(topo_name,dut_name,log_dir,tc,tc_name)
        os.system("bash -c '{}'".format(cmd))

        total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(tc_name), shell=True).strip()
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(tc_name), shell=True).strip()
        failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(tc_name), shell=True).strip()
        skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(tc_name), shell=True).strip()
        errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(tc_name), shell=True).strip()
        time.sleep(10)
        final_total += int(total_tests)
        total_passed += int(passed)
        total_failed += int(failed)
        total_skipped += int(skipped)
        total_error += int(errored)

        print("{}     : {} : {} : {} : {} : {}".format(tc_name,total_tests,passed,failed,skipped,errored))

        current_result_file.write("{}:           {} total, {} Pass, {} Fail, {} Skip, {} Error \n".format(tc_name,total_tests,passed,failed,skipped,errored))
        current_result_file.flush()
        report_file.write("{}     , {} total, {} Pass, {} Fail, {} Skip, {} Error\n".format(tc_name,total_tests,passed,failed,skipped,errored))
        report_file.flush()

        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

    if create_allure_report:
        generate_allure_report(build_id, current_result_file)

    current_result_file.write("Total TCs: {},          {} Pass, {} Fail, {} Skipped, {} Error\n".format(final_total,total_passed,total_failed,total_skipped,total_error))
    current_result_file.close()
    report_file.write("Total     , {} Total, {} Passed, {} Failed, {} Skip, {} Error\n".format(final_total,total_passed,total_failed,total_skipped,total_error))
    report_file.close()

    delta2 = datetime.datetime.now()
    print(delta2)
    time_delta = (delta2 - delta1)
    print(time_delta)
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60

    print("Total time : {} mins".format(minutes))

def new_run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,tstamp,build_id,create_allure_report,collect_logs=False,dut_address=None,additional_tests=''):
    if drop_version is not None:
        filename = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    else:
        filename = 'ongoing_result_{}.csv'.format(tstamp)
    if log_dir is not None:
        log_dir = '/data/tests/{}'.format(log_dir)
    else:
        log_dir = '/data/tests/run_logs'
    if build_id is None:
        build_id = 99999
    print("BUILD ID IS {}".format(build_id))
    current_result_file = open(filename, 'w')
    report_file = open('full_report.txt', 'w')
    tcs = get_testcases(script_file, additional_tests)
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_error = 0
    final_total = 0
    ssh_port = 22
    dut_uname = 'cisco'
    dut_passwd = 'cisco123'
    if collect_logs and dut_address is not None:
        cmd_list = list()
        cmd_list.append('mkdir swss_logs_{}\n'.format(drop_version))
        cmd_list.append('sudo rm /var/log/swss/*.gz\n')
        cmd_list.append('sudo rm /var/log/syslog*.gz\n')
        cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}\n'.format(drop_version))
        cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}\n'.format(drop_version))
        run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

    delta1 = datetime.datetime.now()
    tc_name = "bgp_fact"
    cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name)
    os.system("bash -c '{}'".format(cmd))
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    if not int(passed):
        print("Iteration1: Rerunning the script, making sure that DUT is up\n")
        current_result_file.write("Iteration1: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
        current_result_file.flush()
        time.sleep(60)
        cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name)
        os.system("bash -c '{}'".format(cmd))
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
        if not int(passed):
            print("Iteration2: Rerunning the script, making sure that DUT is up\n")
            current_result_file.write("Iteration2: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
            current_result_file.flush()
            time.sleep(60)
            cmd = "./run_tests.sh -n {} -d {} -O -u -e --alluredir=/tmp/allure_results -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name)
            os.system("bash -c '{}'".format(cmd))

    total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l", shell=True).strip()
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l", shell=True).strip()
    skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l", shell=True).strip()
    errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l", shell=True).strip()
    time.sleep(10)
    final_total += int(total_tests)
    total_passed += int(passed)
    total_failed += int(failed)
    total_skipped += int(skipped)
    total_error += int(errored)

    print("{}     : {} : {} : {} : {} : {}".format(tc_name,total_tests,passed,failed,skipped,errored))

    if collect_logs and dut_address is not None:
        cmd_list = list()
        cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
        cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
        run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

    if not int(passed):
        current_result_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now\n")
        current_result_file.flush()
        report_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now\n")
        report_file.flush()
        # Use previous test results to generate Allure report
        if create_allure_report:
            generate_allure_report(build_id, current_result_file)
        sys.exit("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now")

    current_result_file.write(" -------------- Running Sanity File(s) {}, additional tests: {} ------------- \n".format(script_file, additional_tests))
    current_result_file.flush()
    for tc in tcs:
        if '#' in tc:
            continue
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]
        if drop_version is not None:
            tc_name = tc_name + "_" + drop_version

        print("Executing: {}\n".format(tc))
        current_result_file.write("Executing: {}\n".format(tc));current_result_file.flush()

        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo rm /var/log/swss/sairedis.rec.*\n')
            cmd_list.append('sudo rm /var/log/swss/swss.rec.*\n')
            cmd_list.append('sudo rm /var/log/syslog*.gz\n')
            cmd_list.append('sudo rm /var/log/syslog.*\n')
            cmd_list.append("sudo sh -c '> /var/log/swss/sairedis.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/swss/swss.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/syslog'\n")
            cmd_list.append('mkdir swss_logs_{}/{}\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

        cmd = "./run_tests.sh -n {} -d {} -e --alluredir=/tmp/allure_results -e -rapP -O -u -e --skip_sanity -m individual -p {} -c {} |& tee {}.log".format(topo_name,dut_name,log_dir,tc,tc_name)
        os.system("bash -c '{}'".format(cmd))

        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

    if create_allure_report:
        generate_allure_report(build_id, current_result_file)

    current_result_file.close()
    report_file.close()

    delta2 = datetime.datetime.now()
    print(delta2)
    time_delta = (delta2 - delta1)
    print(time_delta)
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60

    print("Total time : {} mins".format(minutes))

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
            os.system("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g'  >> all_result.txt".format(log_file))

            total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(log_file), shell=True).strip()
            passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(log_file), shell=True).strip()
            failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(log_file), shell=True).strip()
            skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(log_file), shell=True).strip()
            errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(log_file), shell=True).strip()

            final_total += int(total_tests)
            total_passed += int(passed)
            total_failed += int(failed)
            total_skipped += int(skipped)
            total_error += int(errored)
            print("{}     : {} : {} : {} : {} : {} \n".format(log_file,total_tests,passed,failed,skipped,errored))

            result_file.write("{}, {} Total , {} Pass, {} Failed, {} Skipped, {} Error\n".format(log_file,total_tests,passed,failed,skipped,errored))

    result_file.write("Total     , {} Total, {} Passed, {} Failed, {} Skip, {} Error\n".format(final_total,total_passed,total_failed,total_skipped,total_error))
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
    collect_logs = args['collect_logs']
    dut_address = args.get('dut_address')
    dut_name = args['dut_name']
    topo_name = args['topo_name']
    build_id = args['build_id']
    create_allure_report = args['create_allure_report']
    additional_tests = args['additional_tests']

    if device_type == 'sherman':
        dut_name = 'sherman-01'
    elif device_type == 'churchill-mono':
        dut_name = 'churchill-mono-01'
    else:
        dut_name = 'mathilda-01'

    if tstamp is None:
        tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")

    if only_parse:
        parse_results()
    else:
        if not collect_logs:
            new_run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,tstamp,build_id,create_allure_report,additional_tests=additional_tests)
        else:
            if dut_address is None:
                print('Missing DUT Address, specify DUT address for collecting logs')
                exit
            run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,tstamp,build_id,create_allure_report,collect_logs,dut_address,additional_tests=additional_tests)

        #run_scripts(dut_name,script_file,drop_version,log_dir,tstamp)

if __name__ == '__main__':
  main()


