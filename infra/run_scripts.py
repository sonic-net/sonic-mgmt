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
import subprocess
import paramiko
import yaml


# Load config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

# Load Allure config values
ALLURE_DIR = allure_config['allure']['local-report-dir']
ALLURE_REPORT_URL_FILE = allure_config['allure']['report-url-file-path']


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
    parser.add_argument('-d', '--device_type', type=str, help='the device type of the DUT',
                      required=False,default="mth32")
    parser.add_argument('-tt', '--topo_type', type=str, help='topo type',
                      required=True,default='t1-64-lag')
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
    parser.add_argument('-k', '--skip_sanity', action='store_true', help='Skip sanity check',
                      default=False)
    parser.add_argument('-dd', '--dut_data_file', type=str, help='path to file containing DUT acess info',
                      required=False,default=None)
    parser.add_argument('--mark-conditions-files', type=str,
                        help='mark files to skip tests conditionaly, use comma seperated file names when specifying more than one file',
                        required=False, default='common/plugins/conditional_mark/tests_mark_conditions.yaml')
    parser.add_argument('-y', '--test_tag', type=str, help='tag to get tests to run from sanity file. Comma seperated \
        For e.g.fwd,plt', required=False,default=None)
    return parser

def run_exec_cmds(host,port,user,passwd,cmd_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(host, port, user, passwd)
    ssh.connect(host, port, user, passwd)
    for cmd in cmd_list:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()
        try:
            out = stdout.read().decode("ascii").strip()
            error = stderr.read()
            print(out)
            if error:
                print('There was an error pulling the runtime: {}'.format(error))
        except:
            print("Problem decoding output of ssh command")
    ssh.close()

# Generate allure report using data in ALLURE_DIR
def generate_allure_report(build_id, current_result_file):
    report_folder_name = "allure-report-{}".format(build_id)
    report_dir_path = "/tmp/{}".format(report_folder_name)
    report_tar_path = "{}.tar.gz".format(report_dir_path)

    result = subprocess.run(["allure", "generate", "--name", build_id, "-o", report_dir_path, ALLURE_DIR])
    if result.returncode != 0:
        print("Error while generating allure report! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.write("Error while generating allure report! Error: {} {}\n".format(result.stderr, result.stdout))
        current_result_file.flush()
        return

    result = subprocess.run(["ls", report_dir_path])
    if result.returncode != 0:
        print("Error while verifying allure report! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.write("Error while verifying allure report! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.flush()
        return

    print("Allure report generated successfully at /tmp/{}".format(report_folder_name))
    current_result_file.write("Allure report generated successfully at /tmp/{}\n".format(report_folder_name))
    current_result_file.flush()

    result = subprocess.run(["tar", "-cvzf", report_tar_path, "-C", "/tmp/", report_folder_name])
    if result.returncode != 0:
        print("Error while generating allure report tarball! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.write("Error while generating allure report tarball! Error: {} {}\n".format(result.stderr, result.stdout))
        current_result_file.flush()
        return

    result = subprocess.run(["ls", report_tar_path])
    if result.returncode != 0:
        print("Error while verifying allure report tarball! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.write("Error while verifying allure report tarball! Error: {} {}".format(result.stderr, result.stdout))
        current_result_file.flush()
        return

    print("Allure report tarball created successfully!")
    current_result_file.write("Allure report tarball created successfully!\n")
    current_result_file.flush()

def convert_keys_to_strings_and_lower(d):
    """Recursively convert all keys in a dictionary to lowercase strings."""
    if isinstance(d, dict):
        return {str(key).lower(): convert_keys_to_strings_and_lower(value) for key, value in d.items()}
    elif isinstance(d, list):
        return [convert_keys_to_strings_and_lower(item) for item in d]
    else:
        return d

def get_testcases_yaml(yaml_file, test_categories_str, topology=None, device_type=None):
    """
    Loads a test case YAML and returns a subset of test cases, determined by these rules:

    1. For each TEST_CATEGORY:
    1a. Tests in TEST_CATEGORY/all_topo are included
    1b. If TOPOLOGY is specified and TEST_CATEGORY/TOPOLOGY exists, tests in TEST_CATEGORY/TOPOLOGY are included

    2. Any duplicate test entries are removed.

    :param yaml_file: path of YAML file with test cases and its categorization.
    :param test_categories_str: comma separeted string, containing test categories (e.g. 'FWD', 'PLT', etc.).
    :param topology: string indicating the topology (e.g. 't1-64-lag').
    :return: List of test file paths (strings) in the final test list.
    """
    with open(yaml_file, 'r') as f:
        data = yaml.safe_load(f)

    data = convert_keys_to_strings_and_lower(data)

    final_tests = []

    if not test_categories_str:
        raise ValueError("test_category must be specified!")

    category_list = []
    if test_categories_str:
        category_list = [cat.strip().lower() for cat in test_categories_str.split(',') if cat.strip()]

    # 2. If we have categories, add all_topo/<category> if it exists
    for category in category_list:
        if category not in data:
            logging.error(f"Could not find category '{category}' in yaml file '{yaml_file}'! Skipping...")
            continue

        if 'all_topo' in data[category]:
            if 'all_pids' in data[category]['all_topo']:
                final_tests.extend(data[category]['all_topo']['all_pids'])

            if device_type is not None and device_type in data[category]['all_topo']:
                final_tests.extend(data[category]['all_topo'][device_type])

        if topology and topology in data[category]:
            if 'all_pids' in data[category][topology]:
                final_tests.extend(data[category][topology]['all_pids'])
            if device_type is not None and device_type in data[category][topology]:
                final_tests.extend(data[category][topology][device_type])

    # 5. Remove duplicates while preserving the order
    seen = set()
    unique_tests = []
    for test in final_tests:
        if test not in seen:
            seen.add(test)
            unique_tests.append(test)

    return unique_tests

def get_testcases(script_file, test_tag, topo_type, additional_tests='', device_type=None):
    #adding all testcases from all files into one list, ordered
    tcs_dict = {}
    tcs = []
    tc_list = []

    if script_file.endswith(('.yaml', '.yml')):
        tcs = get_testcases_yaml(script_file, test_tag, topo_type, device_type)

    elif script_file.endswith(('.txt')):
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
    if script_file.endswith(('.yaml', '.yml')):
        for tc in tcs:
            print(tc)
    else:
        print("".join(tcs))

    return tcs

def run_scripts(script_file,drop_version,log_dir,dut_name,topo_type,topo_name,tstamp,build_id,create_allure_report,collect_logs=False,dut_address=None, additional_tests='', run_options='',mark_conditions_files='',test_tag=None, device_type=None):
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
    mark_conditions_file_opt = process_conditions_files(mark_conditions_files)
    current_result_file = open(filename, 'w')
    report_file = open('full_report.txt', 'w')
    tcs = get_testcases(script_file,test_tag,topo_type,additional_tests, device_type)
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
    cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR, log_dir)
    os.system("bash -c '{}'".format(cmd))
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    if not int(passed):
        print("Iteration1: Rerunning the script, making sure that DUT is up\n")
        current_result_file.write("Iteration1: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
        current_result_file.flush()
        time.sleep(60)
        cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR, log_dir)
        os.system("bash -c '{}'".format(cmd))
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
        if not int(passed):
            print("Iteration2: Rerunning the script, making sure that DUT is up\n")
            current_result_file.write("Iteration2: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
            current_result_file.flush()
            time.sleep(60)
            cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -p {} -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR, log_dir)
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

        cmd = "./run_tests.sh -n {} {} -e --alluredir={} -e -rapP -O -u -e --skip_sanity -m individual -p {} {} -c {} |& tee {}.log".format(topo_name, run_options, ALLURE_DIR, log_dir, mark_conditions_file_opt, tc, tc_name)
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

def get_techsupport(dut_address, tc_name, dut_name, log_dir):
    ssh_port = 22
    dut_uname = 'cisco'
    dut_passwd = 'cisco123'
    ts_dir='/var/dump'

    try:
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(dut_address, port=ssh_port, username=dut_uname, password=dut_passwd)

        # Open an SFTP session
        sftp = ssh.open_sftp()

        # List all files in the remote directory
        files = sftp.listdir_attr(ts_dir)

        if not files:
            print("No files found in the directory.")
            return None

        # Find the latest file by modification time
        latest_file = max(files, key=lambda x: x.st_mtime)
        latest_file_path = os.path.join(ts_dir, latest_file.filename)
        print(latest_file_path)
        sftp.get(latest_file_path, f'{log_dir}/{dut_name}_{tc_name}_{latest_file.filename}')

        # Close the SFTP session and SSH connection
        sftp.close()
        ssh.close()

        return latest_file_path

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def process_conditions_files(mark_conditions_files):
    mark_conditions_file_opt = ""
    for file in mark_conditions_files.split(","):
        mark_conditions_file_opt+=' -e "--mark-conditions-files {}" '.format(file)

    return mark_conditions_file_opt

def new_run_scripts(script_file,drop_version,log_dir,dut_name,topo_type,topo_name,tstamp,build_id,create_allure_report,collect_logs=False,dut_address=None,additional_tests='', run_options='',dut_data_file=None, mark_conditions_files='',test_tag=None, device_type=None):
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
    mark_conditions_file_opt=process_conditions_files(mark_conditions_files)
    current_result_file = open(filename, 'w')
    report_file = open('full_report.txt', 'w')
    tcs = get_testcases(script_file,test_tag,topo_type,additional_tests, device_type)
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
    cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR)
    os.system("bash -c '{}'".format(cmd))
    passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    if not int(passed):
        print("Iteration1: Rerunning the script, making sure that DUT is up\n")
        current_result_file.write("Iteration1: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
        current_result_file.flush()
        time.sleep(60)
        cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR)
        os.system("bash -c '{}'".format(cmd))
        passed = subprocess.check_output("egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' bgp_fact.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
        if not int(passed):
            print("Iteration2: Rerunning the script, making sure that DUT is up\n")
            current_result_file.write("Iteration2: Sleeping for a minute and then rerunning the script, making sure that DUT is up\n")
            current_result_file.flush()
            time.sleep(60)
            cmd = "./run_tests.sh -n {} {} -O -u -e --alluredir={} -e -rapP -m individual -c bgp/test_bgp_fact.py |& tee bgp_fact.log".format(topo_name, run_options, ALLURE_DIR)
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
    def get_dut_names(data):
        return [key for key in data if key.startswith('sonic_dut')]

    with open(dut_data_file) as f:
        dut_data = yaml.load(f, Loader=yaml.FullLoader)

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

        for dname in get_dut_names(dut_data):
            device = dut_data[dname]
            cmd_list = list()
            cmd_list.append('sudo rm /var/log/swss/sairedis.rec.*\n')
            cmd_list.append('sudo rm /var/log/swss/swss.rec.*\n')
            cmd_list.append('sudo rm /var/log/syslog*.gz\n')
            cmd_list.append('sudo rm /var/log/syslog.*\n')
            cmd_list.append('sudo rm /var/dump/*\n')
            cmd_list.append("sudo sh -c '> /var/log/swss/sairedis.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/swss/swss.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/syslog'\n")
            run_exec_cmds(device['xr_mgmt_ip'], ssh_port, dut_uname, dut_passwd, cmd_list)

        if collect_logs and dut_address is not None:
            cmd_list = list()
            cmd_list.append('sudo rm /var/log/swss/sairedis.rec.*\n')
            cmd_list.append('sudo rm /var/log/swss/swss.rec.*\n')
            cmd_list.append('sudo rm /var/log/syslog*.gz\n')
            cmd_list.append('sudo rm /var/log/syslog.*\n')
            cmd_list.append('sudo rm /var/dump/*\n')
            cmd_list.append("sudo sh -c '> /var/log/swss/sairedis.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/swss/swss.rec'\n")
            cmd_list.append("sudo sh -c '> /var/log/syslog'\n")
            cmd_list.append('mkdir swss_logs_{}/{}\n'.format(drop_version,tc_name))
            run_exec_cmds(dut_address, ssh_port, dut_uname, dut_passwd, cmd_list)

        cmd = "./run_tests.sh -n {} {} -e --alluredir={} -e -rapP -O -u -e --skip_sanity -m individual -p {} {} -c {} |& tee {}.log".format(topo_name, run_options, ALLURE_DIR, log_dir, mark_conditions_file_opt, tc, tc_name)
        os.system("bash -c '{}'".format(cmd))
        failed = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {tc_name}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l", shell=True).strip()
        error = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {tc_name}.log | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l", shell=True).strip()

        if int(failed) or int(error):
            for dname in get_dut_names(dut_data):
                device = dut_data[dname]
                cmd_list = list()
                cmd_list.append("show techsupport")
                run_exec_cmds(device['xr_mgmt_ip'], ssh_port, dut_uname, dut_passwd, cmd_list)
                get_techsupport(device['xr_mgmt_ip'], tc_name, dut_name, log_dir)

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
    topo_type = args['topo_type']
    tstamp = args['tstamp']
    collect_logs = args['collect_logs']
    dut_address = args.get('dut_address')
    dut_name = args['dut_name']
    topo_name = args['topo_name']
    build_id = args['build_id']
    create_allure_report = args['create_allure_report']
    additional_tests = args['additional_tests']
    skip_sanity = args['skip_sanity']
    dut_data_file = args['dut_data_file']
    mark_conditions_files = args['mark_conditions_files']
    test_tag = args['test_tag']
    run_options = ''
    if device_type == 'sherman':
        dut_name = 'sherman-01'
    elif device_type == 'churchill-mono':
        dut_name = 'churchill-mono-01'
    elif device_type == 'm64-zz-2':
        dut_name = 'm64-zz-2'
    elif device_type == 'mth-t0-64':
        dut_name = 'mth-t0-64'
    elif device_type == 'sfd':
        dut_name = 'sfd'
    elif device_type == 'aaa14-t2':
        dut_name = 'aaa14-t2'
    elif device_type == 'lightening':
        dut_name = 'lightening-01'
    elif device_type == 'siren':
        dut_name = 'siren-01'
    else:
        dut_name = 'mathilda-01'

    if dut_name != 'sfd' and dut_name != 'aaa14-t2':
        run_options += '-d {} '.format(dut_name)

    if dut_name == 'aaa14-t2':
        run_options += '-t t2,any'.format(dut_name)

    if skip_sanity:
        run_options += '-e --skip_sanity '

    if tstamp is None:
        tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")

    if only_parse:
        parse_results()
    else:
        if not collect_logs:
            if dut_address is None:
                print('Missing DUT Address, specify DUT address for collecting logs')
                exit
            new_run_scripts(script_file,drop_version,log_dir,dut_name,topo_type,topo_name,tstamp,build_id,create_allure_report,dut_data_file=dut_data_file,run_options=run_options,additional_tests=additional_tests,mark_conditions_files=mark_conditions_files,test_tag=test_tag, device_type=device_type)
        else:
            if dut_address is None:
                print('Missing DUT Address, specify DUT address for collecting logs')
                exit
            run_scripts(script_file,drop_version,log_dir,dut_name,topo_type,topo_name,tstamp,build_id,create_allure_report,collect_logs,dut_address,run_options=run_options,additional_tests=additional_tests,mark_conditions_files=mark_conditions_files,test_tag=test_tag, device_type=device_type)

        #run_scripts(dut_name,script_file,drop_version,log_dir,tstamp)

if __name__ == '__main__':
  main()
