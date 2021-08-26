#!/usr/bin/python

import argparse
import json
import logging
import os
import subprocess
import time
import paramiko
import sys

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
    parser.add_argument('-c', '--collect_logs', action='store_true', help='Just Parse results',
                      default=False)                  
    parser.add_argument('-a', '--dut_address', type=str, help='specify dut address',
                      required=False,default=None)
    parser.add_argument('-d', '--dut_name', type=str, help='DUT name specified to run tests',
                      required=False,default='mathilda-01')
    parser.add_argument('-t', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
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


def run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,collect_logs=False,dut_address=None):
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

    cmd = "./run_tests.sh -n {} -d {} -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name,dut_name,log_dir)
    os.system("bash -c '{}'".format(cmd))
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    if not int(passed):
        sys.exit("BGP Fact testcase failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now")        

    for tc in tcs:
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


        cmd = "./run_tests.sh -n {} -d {} -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p {} -c {} |& tee {}.log".format(topo_name,dut_name,log_dir,tc,tc_name)
        os.system("bash -c '{}'".format(cmd))
        total_tests = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l".format(tc_name), shell=True).strip()
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l".format(tc_name), shell=True).strip()
        failed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l".format(tc_name), shell=True).strip()
        skipped = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l".format(tc_name), shell=True).strip()
        errored = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {}.log | grep -i teardown  |sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l".format(tc_name), shell=True).strip()
        time.sleep(10)
        final_total += int(total_tests)
        total_passed += int(passed)
        total_failed += int(failed)
        total_skipped += int(skipped)
        total_error += int(errored)

        print("{}     : {} : {} : {} : {} : {}".format(tc_name,total_tests,passed,failed,skipped,errored))

        current_result_file.write("{}     , {} , {} , {} , {} , {} \n".format(tc_name,total_tests,passed,failed,skipped,errored))
        current_result_file.flush()
        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo cp /var/log/swss/* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            cmd_list.append('sudo cp /var/log/syslog* swss_logs_{}/{}/.\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)


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
    collect_logs = args['collect_logs']
    dut_address = args.get('dut_address')
    dut_name = args['dut_name']
    topo_name = args['topo_name']

    if only_parse:
        parse_results()
    else:
        if not collect_logs:
            run_scripts(script_file,drop_version,log_dir,dut_name,topo_name)
        else:
            if dut_address is None:
                print('Missing DUT Address, specify DUT address for collecting logs')
                exit     
            run_scripts(script_file,drop_version,log_dir,dut_name,topo_name,collect_logs,dut_address)

if __name__ == '__main__':
  main()



