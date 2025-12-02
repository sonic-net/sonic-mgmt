#!/usr/bin/python

import argparse
import logging
import os
import subprocess
import time
import datetime
import sys
import paramiko
import yaml
from utils import log

# Load config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

# Load Allure config values
ALLURE_DIR = allure_config['allure']['local-report-dir']
ALLURE_REPORT_URL_FILE = allure_config['allure']['report-url-file-path']

# Map device types to actual device names
# KEY: Device Type
# VALUE: Actual DUT name
DEVICE_TYPE_TO_DUT_NAME_MAP = {
    'sherman':          'sherman-01',
    'churchill-mono':   'churchill-mono-01',
    'm64-zz-2':         'm64-zz-2',
    'mth-t0-64':        'mth-t0-64',
    'sfd':              'sfd',
    'aaa14-t2':         'aaa14-t2',
    'lightning':        'lightning-01',
    'superbolt':        'superbolt-01',
    'siren':            'siren-01',
    'crocodile':        'crocodile-01',
    'mustang':          'mustang-01',
    'mth64':            'mathilda-01'
}

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
    log.info(f"Connecting to {host}:{port} as {user}")
    ssh.connect(host, port, user, passwd)
    for cmd in cmd_list:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()
        try:
            out = stdout.read().decode("ascii").strip()
            error = stderr.read()
            log.info(out)
            if error:
                log.error(f'There was an error pulling the runtime: {error}')
        except Exception as e:
            log.error(f"Problem decoding output of ssh command: {e}")
    ssh.close()

# Generate allure report using data in ALLURE_DIR
def generate_allure_report(build_id, current_result_file):
    report_folder_name = f"allure-report-{build_id}"
    report_dir_path = f"/tmp/{report_folder_name}"
    report_tar_path = f"{report_dir_path}.tar.gz"

    result = subprocess.run(["allure", "generate", "--name", build_id, "-o", report_dir_path, ALLURE_DIR])
    if result.returncode != 0:
        log.error(f"Error while generating allure report! Error: {result.stderr} {result.stdout}")
        current_result_file.write(f"Error while generating allure report! Error: {result.stderr} {result.stdout}\n")
        current_result_file.flush()
        return

    result = subprocess.run(["ls", report_dir_path])
    if result.returncode != 0:
        log.error(f"Error while verifying allure report! Error: {result.stderr} {result.stdout}")
        current_result_file.write(f"Error while verifying allure report! Error: {result.stderr} {result.stdout}")
        current_result_file.flush()
        return

    log.info(f"Allure report generated successfully at /tmp/{report_folder_name}")
    current_result_file.write(f"Allure report generated successfully at /tmp/{report_folder_name}\n")
    current_result_file.flush()

    result = subprocess.run(["tar", "-cvzf", report_tar_path, "-C", "/tmp/", report_folder_name])
    if result.returncode != 0:
        log.error(f"Error while generating allure report tarball! Error: {result.stderr} {result.stdout}")
        current_result_file.write(f"Error while generating allure report tarball! Error: {result.stderr} {result.stdout}\n")
        current_result_file.flush()
        return

    result = subprocess.run(["ls", report_tar_path])
    if result.returncode != 0:
        log.error(f"Error while verifying allure report tarball! Error: {result.stderr} {result.stdout}")
        current_result_file.write(f"Error while verifying allure report tarball! Error: {result.stderr} {result.stdout}")
        current_result_file.flush()
        return

    log.info("Allure report tarball created successfully!")
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

def get_testcases_yaml(yaml_file, test_categories_str, topology=None, device_type=None, hw_or_sim='sim'):
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
    if hw_or_sim not in ['hw', 'sim']:
        err_msg = f"ERROR! Invalid choice for parameter hw_or_sim. choices are 'sim' or 'hw', given: '{hw_or_sim}'"
        print(err_msg)
        raise ValueError(err_msg)

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
            log.error(f"Could not find category '{category}' in yaml file '{yaml_file}'! Skipping...")
            continue

        if 'all_topo' in data[category]:
            if 'all_pids' in data[category]['all_topo']:
                if hw_or_sim in data[category]['all_topo']['all_pids']:
                    final_tests.extend(data[category]['all_topo']['all_pids'][hw_or_sim])

            if device_type is not None and device_type in data[category]['all_topo']:
                if hw_or_sim in data[category]['all_topo'][device_type]:
                    final_tests.extend(data[category]['all_topo'][device_type][hw_or_sim])

        if topology and topology in data[category]:
            if 'all_pids' in data[category][topology]:
                if hw_or_sim in data[category][topology]['all_pids']:
                    final_tests.extend(data[category][topology]['all_pids'][hw_or_sim])
            for pid_list in data[category][topology].keys():
                if isinstance(pid_list, str):
                    # Split the string by commas and strip whitespace
                    pids_list = [item.strip() for item in pid_list.split(",")]
                if device_type is not None and device_type in pids_list:
                    if hw_or_sim in data[category][topology][pid_list]:
                        final_tests.extend(data[category][topology][pid_list][hw_or_sim])

    # 5. Remove duplicates while preserving the order
    seen = set()
    unique_tests = []
    for test in final_tests:
        if test not in seen:
            seen.add(test)
            unique_tests.append(test)

    return unique_tests

def get_testcases(script_file, test_tag, topo_type, additional_tests='', device_type=None, hw_or_sim='sim'):
    #adding all testcases from all files into one list, ordered
    tcs_dict = {}
    tcs = []
    tc_list = []

    if script_file.endswith(('.yaml', '.yml')):
        tcs = get_testcases_yaml(script_file, test_tag, topo_type, device_type, hw_or_sim)

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


    log.info(f"script files are '{script_file}', additional testscases are: '{additional_tests}'")
    log.info("Testcases are:")
    if script_file.endswith(('.yaml', '.yml')):
        for tc in tcs:
            log.info(tc)
    else:
        log.info("".join(tcs))
    return tcs
def get_techsupport(dut_address, tc_name, dut_name, log_dir):
    ssh_port = 22
    dut_uname = 'admin'
    dut_passwd = 'password'
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
            log.warning("No files found in the directory.")
            return None

        # Find the latest file by modification time
        latest_file = max(files, key=lambda x: x.st_mtime)
        latest_file_path = os.path.join(ts_dir, latest_file.filename)
        log.info(latest_file_path)
        sftp.get(latest_file_path, f'{log_dir}/{dut_name}_{tc_name}_{latest_file.filename}')

        # Close the SFTP session and SSH connection
        sftp.close()
        ssh.close()

        return latest_file_path

    except Exception as e:
        log.error(f"An error occurred: {e}")
        return None

def process_conditions_files(mark_conditions_files):
    mark_conditions_file_opt = ""
    for file in mark_conditions_files.split(","):
        mark_conditions_file_opt+=f' -e "--mark-conditions-files {file}" '

    return mark_conditions_file_opt

def parse_log_file_for_results(log_file_name):
    total = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file_name} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | wc -l", shell=True).strip()
    passed = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file_name} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i passed | wc -l", shell=True).strip()
    failed = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file_name} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i failed | wc -l", shell=True).strip()
    skipped = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file_name} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i skipped | wc -l", shell=True).strip()
    errored = subprocess.check_output(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file_name} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g' | grep -i error | wc -l", shell=True).strip()

    return int(total), int(passed), int(failed), int(skipped), int(errored)

def run_scripts(
        script_file,
        drop_version,
        log_dir,
        dut_name,
        topo_type,
        topo_name,
        tstamp,
        build_id,
        create_allure_report,
        additional_tests='',
        run_options='',
        dut_data_file=None,
        mark_conditions_files='',
        test_tag=None,
        device_type=None
    ):
    log.info("running run_scripts")
    log.info(f"""
                 params:
                 script_file: {script_file}
                 drop_version: {drop_version}
                 log_dir: {log_dir}
                 dut_name: {dut_name}
                 topo_type: {topo_type}
                 topo_name: {topo_name}
                 tstamp: {tstamp}
                 build_id: {build_id}
                 create_allure_report: {create_allure_report}
                 additional_tests: {additional_tests}
                 run_options: {run_options}
                 dut_data_file: {dut_data_file}
                 mark_conditions_files: {mark_conditions_files}
                 test_tag: {test_tag}
                 device_type: {device_type}
    """)
    
    if drop_version is not None:
        filename = f"ongoing_result_{drop_version}_{tstamp}.csv"
    else:
        filename = f'ongoing_result_{tstamp}.csv'

    if log_dir is not None:
        log_dir = f"/data/tests/{log_dir}"
    else:
        log_dir = '/data/tests/run_logs'

    if build_id is None:
        build_id = 99999

    log.info(f"BUILD ID IS {build_id}")

    mark_conditions_file_opt=process_conditions_files(mark_conditions_files)
    current_result_file = open(filename, 'w')
    report_file = open('full_report.txt', 'w')
    test_cases_list = get_testcases(script_file,test_tag,topo_type,additional_tests, device_type)
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_error = 0
    final_total = 0
    ssh_port = 22
    dut_uname = 'admin'
    dut_passwd = 'password'
    
    delta1 = datetime.datetime.now()


    # First run bgp_facts.py to ensure DUT is up and BGP is established
    # This will be somewhat of a pre-check before running rest of the tests
    passed = 0
    iteration = 0
    max_iterations = 3
    
    tc_name = "bgp_fact"
    log.info("-------------- START: Running bgp_facts.py to check DUT Health -------------")
    while iteration < max_iterations and int(passed) == 0:
        iteration += 1
        msg = f"Iteration {iteration}: Reunning bgp_facts.py, making sure that DUT is up\n"
        log.info(msg)
        current_result_file.write(msg)
        current_result_file.flush()
        time.sleep(60)
        cmd = f"./run_tests.sh -n {topo_name} {run_options} -O -u -e --recover_method=config_reload -e --alluredir={ALLURE_DIR} -e -rapP -m individual -p {log_dir} -c bgp/test_bgp_fact.py |& tee bgp_fact.log"
        os.system(f"bash -c '{cmd}'")
        total, passed, failed, skipped, errored = parse_log_file_for_results("bgp_fact.log")

    time.sleep(10)
    final_total += int(total)
    total_passed += int(passed)
    total_failed += int(failed)
    total_skipped += int(skipped)
    total_error += int(errored)

    log.info(f"{tc_name}     : {total} : {passed} : {failed} : {skipped} : {errored}")

    if not int(passed):
        msg = "Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. Check BGP neighbors on DUT. Exiting now"
        current_result_file.write(msg+"\n")
        current_result_file.flush()
        report_file.write(msg+"\n")
        report_file.flush()
        # Use previous test results to generate Allure report
        if create_allure_report:
            generate_allure_report(build_id, current_result_file)
        sys.exit(msg)

    log.info("-------------- END: Running bgp_facts.py to check DUT Health -------------")


    # Proceeding with rest of the tests
    current_result_file.write(f" -------------- Running Sanity File(s) {script_file}, additional tests: {additional_tests} ------------- \n")
    current_result_file.flush()
    def get_dut_names(data):
        return [key for key in data if key.startswith('sonic_dut')]

    with open(dut_data_file) as f:
        dut_data = yaml.load(f, Loader=yaml.FullLoader)

    for tc in test_cases_list:
        if '#' in tc:
            continue
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]
        if drop_version is not None:
            tc_name = tc_name + "_" + drop_version

        log.info(f"Executing: {tc}")
        current_result_file.write(f"Executing: {tc}\n");current_result_file.flush()

        cmd = f"./run_tests.sh -n {topo_name} {run_options} -e --alluredir={ALLURE_DIR} -e -rapP -O -u -e --recover_method=config_reload -m individual -p {log_dir} {mark_conditions_file_opt} -c {tc} |& tee {tc_name}.log"
        os.system(f"bash -c '{cmd}'")
        total, passed, failed, skipped, errored = parse_log_file_for_results(f"{tc_name}.log")

        if int(failed) or int(errored):
            for dname in get_dut_names(dut_data):
                device = dut_data[dname]
                cmd_list = list()
                cmd_list.append("show techsupport")
                run_exec_cmds(device['xr_mgmt_ip'], ssh_port, dut_uname, dut_passwd, cmd_list)
                get_techsupport(device['xr_mgmt_ip'], tc_name, dut_name, log_dir)

    if create_allure_report:
        generate_allure_report(build_id, current_result_file)

    current_result_file.close()
    report_file.close()

    delta2 = datetime.datetime.now()
    log.info(f"End time: {delta2}")
    time_delta = (delta2 - delta1)
    log.info(f"Time delta: {time_delta}")
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60
    log.info(f"Total time : {minutes} mins")

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
            os.system(f"egrep '^FAILED|^PASSED|^SKIPPED|^ERROR' {log_file} | sed 's/INFO:SectionStartLogger:====================/ /g' | sed 's/ teardown ====================/ /g'  >> all_result.txt")

            total, passed, failed, skipped, errored = parse_log_file_for_results(log_file)
            final_total += int(total)
            total_passed += int(passed)
            total_failed += int(failed)
            total_skipped += int(skipped)
            total_error += int(errored)
            log.info(f"{log_file}     : {total} : {passed} : {failed} : {skipped} : {errored}")

            result_file.write(f"{log_file}, {total} Total , {passed} Pass, {failed} Failed, {skipped} Skipped, {errored} Error\n")

    result_file.write(f"Total     , {final_total} Total, {total_passed} Passed, {total_failed} Failed, {total_skipped} Skip, {total_error} Error\n")
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
    dut_name = args['dut_name']
    topo_name = args['topo_name']
    build_id = args['build_id']
    create_allure_report = args['create_allure_report']
    additional_tests = args['additional_tests']
    skip_sanity = args['skip_sanity']
    dut_data_file = args['dut_data_file']
    mark_conditions_files = args['mark_conditions_files']
    test_tag = args['test_tag']

    if not dut_name and device_type not in DEVICE_TYPE_TO_DUT_NAME_MAP:
        print(f"ERROR: dut_name not specified and could not determine from device_type '{device_type}'.")
        sys.exit(1)

    dut_name = DEVICE_TYPE_TO_DUT_NAME_MAP[device_type]

    run_options = ''
    if dut_name != 'sfd' and dut_name != 'aaa14-t2':
        run_options += f'-d {dut_name} '

    if dut_name == 'aaa14-t2':
        run_options += f'-t t2,any'

    if skip_sanity:
        run_options += '-e --skip_sanity '

    if tstamp is None:
        tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")

    if only_parse:
        parse_results()
        sys.exit(0)

    run_scripts(
        script_file,
        drop_version,
        log_dir,
        dut_name,
        topo_type,
        topo_name,
        tstamp,
        build_id,
        create_allure_report,
        additional_tests=additional_tests,
        run_options=run_options,
        dut_data_file=dut_data_file,
        mark_conditions_files=mark_conditions_files,
        test_tag=test_tag,
        device_type=device_type
    )

if __name__ == '__main__':
  main()
