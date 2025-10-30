#!/usr/bin/python3
import sys
import time
import argparse
from run_scripts_remote import FAILURE_RESONS, SUCCESS_STATUS, FAILURE_STATUS
from run_scripts import get_testcases
import yaml
import os
import json
import paramiko
from hw_setup_utils import log, extractFromImageName, getTestbedInfoDict, getDockerExecCommand, prep_special_run_commands, \
    run_scripts, sshUtil, allure_directory, UNSET_PROXY, runIndividualTests, getLatestValidAllureReport, \
    checkForExistingRuns, SSH_PORT, collect_spytest_results, upload_result, ALLURE_CONFIG_FILE_NAME, getSonicMgmtContainterName, getTechSupport, \
    nested_ssh_connection, DUT_USERNAME, DUT_PASSWORD, WORKSPACE, SANITY_LOGS_PATH, getLogsPath
from utils import _run_cmd_in_ssh, _run_cmd_in_ssh_container, upload_log_files_to_log_server, create_sanity_log_tarball, SANITY_LOG_TARBALL, print_folder_contents


# Parse config file
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

def cleanup_logs_on_dut(p1, prompt):
    """
    Removes old logs and compressed files from /var/log and /var/log/swss.
    """
    commands = [
        "sudo rm -rf /var/log/faulthandler.log",
        "sudo rm -rf /var/log/*.gz",
        "sudo rm -rf /var/log/swss/*.gz"
    ]
    
    for cmd in commands:
        try:
            p1.sendline(cmd)
            p1.expect(prompt, timeout=60)
        except Exception as e:
            log.error(f"Error executing {cmd}: {e}")

def parse_show_boot(output):
    """
    Parse the output of 'show boot' to extract current, next, and available images.
    """
    current_image = None
    next_image = None
    available_images = []

    capture_available = False

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('$') or line.startswith('show boot'):
            continue

        if line.startswith("Current:"):
            current_image = line.replace("Current:", "").strip()
        elif line.startswith("Next:"):
            next_image = line.replace("Next:", "").strip()
        elif line.startswith("Available:"):
            capture_available = True
        elif capture_available and line:
            available_images.append(line)

    return current_image, next_image, available_images

def cleanup_old_images_on_dut(p1, prompt):
    """
    Identifies and removes unused SONiC images, preserving the current and next boot images.
    """
    # Get current and next boot images
    try:
        p1.sendline("show boot")
        p1.expect(prompt, timeout=60)
        output = p1.before

        current_image, next_image, available_images = parse_show_boot(output)
        if not current_image or not next_image:
            log.error("Failed to retrieve boot images. Skipping cleanup.")
            return

        log.info(f"Current Image: {current_image}")
        log.info(f"Next Image: {next_image}")
        log.info(f"Available Images: {available_images}")

        # Identify images to remove (preserve current only)
        images_to_remove = [img for img in available_images if img != current_image]
        log.info(f"Images to be removed: {images_to_remove}")

        for image in images_to_remove:
            remove_cmd = f"sudo sonic-installer remove -y {image}"
            try:
                log.info(f"Executing: {remove_cmd}")
                p1.sendline(remove_cmd)
                p1.expect(prompt, timeout=300)
            except Exception as e:
                log.error(f"Error removing {image}: {e}")
    except Exception as e:
        log.error(f"Error during image cleanup: {e}")

def run_test(args):
    log.info("run_test")
    full_link = args.full_link
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed = args.testbed
    test_suites_arg = args.test_suites
    build_id = args.build_id
    skip_folders = args.skip_folders
    skip_tests = args.skip_tests
    testfile = args.testfile
    test_tag = args.test_tag
    topology = args.topology
    platform = args.platform
    if skip_folders=="null" or skip_folders==None:
        skip_folders = ""
    if skip_tests=="null" or skip_tests==None:
        skip_tests = ""
    rerun = args.rerun
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']
    local_log_dir = os.path.join(WORKSPACE, 'sanity/infra/', SANITY_LOGS_PATH)
    os.makedirs(local_log_dir, exist_ok=True)

    ucs_ssh = testbed_info_dict["ucs_username"]+"@"+testbed_info_dict['ucs_host_name']
    container_name = getSonicMgmtContainterName(stream, testbed)
    docker_exec_cmd = getDockerExecCommand(stream, testbed)

    if testfile:
        testfile_full_path = os.path.dirname(os.path.abspath(__file__))
        testfile_full_path = os.path.join(testfile_full_path, testfile)

    exit_code = None
    docker_prompt = testbed_info_dict['docker_prompt']
    log.info("start running tests")
    # p2 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    # p2.expect(local_ucs)
    # for ssh in testbed_info_dict['dut_ssh']:
    #     [p1, prompt] = sshDUTUtil(p2, ssh)
    #     p1.expect(prompt)
    #     log.info("Starting pre-run cleanup on DUT")
    #     cleanup_logs_on_dut(p1, prompt)
    #     cleanup_old_images_on_dut(p1, prompt)
    #     log.info("Pre-run cleanup completed on DUT")
    #     p1.close()
    # p2.close()

    if 'special_run_commands' in testbed_info_dict or 'special_imfs_run_commands' in testbed_info_dict:
        testbed_info_dict = getTestbedInfoDict(testbed)
        if testfile and test_tag:
            test_suites_array = get_testcases(testfile_full_path, test_tag, topo_type=topology, additional_tests='', device_type=platform, hw_or_sim='hw')
        elif test_suites_arg == 'All' and "tests_list" in testbed_info_dict:
            test_suites_array = testbed_info_dict["tests_list"]
        elif test_suites_arg:
            test_suites_array = [test_suites_arg]
        else:
            log.error(f"No tests fund! TEST_SUITES: {test_suites_arg}, TESTFILE: {testfile}, TEST_TAG: {test_tag}")
            return -1

        log.debug(test_suites_array)
        for test_suites in test_suites_array:
            log.debug(f' Running tests for {test_suites}')
            prompt = docker_prompt
            if "image_mgmt_test.py" in test_suites and 'special_imfs_run_commands' in testbed_info_dict:
                run_commands = testbed_info_dict['special_imfs_run_commands']
                docker = 'False'
                prompt = testbed_info_dict['ucs_ssh_prompt']
            elif "image_mgmt_test.py" in test_suites and 'special_imfs_run_commands' not in testbed_info_dict:
                log.error("IMFS run commands not available")
                return -1
            else:
                run_commands = testbed_info_dict['special_run_commands']
                docker = 'True'
            cmd_list = prep_special_run_commands(testbed, test_suites_arg, test_suites, image_id, build_id, docker_exec_cmd, run_commands, docker)
            log.debug(cmd_list)
            update_flag = ('git_update_flag' in testbed_info_dict and testbed_info_dict['git_update_flag']=="true")
            rc = run_scripts(testbed_info_dict['ucs_host'], testbed_info_dict['ucs_username'], testbed_info_dict['ucs_password'], cmd_list, prompt, SSH_PORT, update_flag)
            if rc!=0:
                return -1
            log.debug("time to close all threads after running scripts")
            time.sleep(100)
        return exit_code
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=testbed_info_dict['ucs_host'],
        username=testbed_info_dict['ucs_username'],
        password=testbed_info_dict['ucs_password']
    )
    stdout, stderr, status_code= _run_cmd_in_ssh(client, "docker ps -a")
    log.debug(f"'docker ps -a' output:\n{stdout}")
    log.debug(rerun)
    # Clean up allure results directory if not a rerun
    if rerun == False or rerun == "false":
        stdout, stderr, status_code = _run_cmd_in_ssh_container(client, container_name, f"cd {allure_directory} && find . -mindepth 1 -delete")

    dut_run_log_folder = f'{image_id}_jenkins_logs_{build_id}_{testbed}'
    dut_log_dir = f'/run_logs/{dut_run_log_folder}'
    if testfile and test_tag:
        sftp = client.open_sftp()
        remote_file_path = f"/home/sonic/ring3-time-{build_id}.txt"
        test_suites_array = get_testcases(testfile_full_path, test_tag, topo_type=topology, additional_tests='', device_type=platform, hw_or_sim='hw')
        with sftp.file(remote_file_path, mode='a') as remote_file:
            for test_suite in test_suites_array:
                exit_code = runIndividualTests(image_id, build_id, testbed, dut_log_dir, client, container_name, test_suite, test_suite, skip_folders, skip_tests, local_log_dir, remote_file)
                if exit_code!=0:
                    time.sleep(30)
                    client.close()
                    return exit_code
        # Output contents of the file
        log.debug(f"Output contents of the file - {remote_file_path}")
        with sftp.file(remote_file_path, mode='r') as remote_file:
            content = remote_file.read().decode()  # decode bytes to string
            log.debug(content)
        
        sftp.close()

    elif test_suites_arg and "," in test_suites_arg:
        test_suites_array = test_suites_arg.split(",")
        for test_suite in test_suites_array:
            exit_code = runIndividualTests(image_id, build_id, testbed, dut_log_dir, client, container_name, test_suite, test_suite, skip_folders, skip_tests, local_log_dir)
            if exit_code!=0:
                time.sleep(30)
                client.close()
                return exit_code
    elif test_suites_arg:
        exit_code = runIndividualTests(image_id, build_id, testbed, dut_log_dir, client, container_name, test_suites_arg, test_suites_arg, skip_folders, skip_tests, local_log_dir)
    else:
        log.error(f"No tests found! TEST_SUITES: {test_suites_arg}, TESTFILE: {testfile}, TEST_TAG: {test_tag}")
        return -1
    log.debug("Timeout for 2 minutes to let the run finish")
    time.sleep(120)
    client.close()

    for dut in testbed_info_dict['dut_ssh']:
        log.debug(f"Collect show tech logs for dut: {dut}")
        target_client, bastion_client = nested_ssh_connection(testbed_info_dict["ucs_host_name"], testbed_info_dict["ucs_username"], testbed_info_dict["ucs_password"], dut, DUT_USERNAME, DUT_PASSWORD, True)
        rc = getTechSupport(target_client, local_log_dir)
        if rc!=0:
            log.error(f"Tech support failure")
        target_client.close()
        bastion_client.close()

    # Bundle the log files into one location
    os.chdir(local_log_dir)
    log.debug("Bundle the log files into one location")
    create_sanity_log_tarball(local_log_dir)
    print_folder_contents(local_log_dir)
    return exit_code

def collect_results(args):
    full_link = args.full_link
    build_id = args.build_id
    testbed = args.testbed
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)
    rc = 0
    #default results json
    result = {
        "total" : 0,
        "failed" : 0,
        "passed" : 0,
        "aborted" : 0,
        "errored" : 0,
        "skipped" : 0,
        "success_rate" : 0,
        "status": FAILURE_STATUS
    }

    SUMMARY_REPORT_FILENAME = "results.json"

    WORKSPACE = os.getenv("WORKSPACE")
    test_suites_arg = os.getenv("TEST_SUITES")
    results_path = os.path.join(WORKSPACE, SUMMARY_REPORT_FILENAME)
    dut_run_log_folder = f'{image_id}_jenkins_logs_{build_id}_{testbed}'
    logs_path = getLogsPath(stream, testbed)
    log.debug(f"Entered collect_results, dut_run_log_folder: {dut_run_log_folder}, results_path: {results_path}, logs_path: {logs_path}")

    if 'custom_result_url' in testbed_info_dict:
        testbed_type = testbed.split("-")[-1]
        image_folder = 'ring4'+'-'+image_id+'-'+build_id+'-'+testbed_type
        result_url = testbed_info_dict["custom_result_url"]+image_folder+"/dashboard.html"
        # target_url = extract_file_contents_url(result_url)
        # target_url = "http://172.27.146.35/run_logs/cicd_runs/ring4-17467-3293/results_2024_10_25_15_49_40_summary.txt"
        # result_sum = extract_result_sum(urllib.request.urlopen(target_url), True
        result["report_link"] = result_url
    elif 'collect_spytest_flag' in testbed_info_dict and testbed_info_dict['collect_spytest_flag']:
        testbed_info_dict = getTestbedInfoDict(testbed)
        if test_suites_arg == 'cisco/tortuga/image_mgmt/image_mgmt_test.py':
            result["report_link"] = f'http://10.29.158.30/imfs_results/{image_id}/imfs_result.txt'
        else:
            test_suites_array = testbed_info_dict["tests_list"] if (test_suites_arg == 'All' and "tests_list" in testbed_info_dict) else [test_suites_arg]
            for test_suite in test_suites_array:
                log.debug(f"Collect results for test: {test_suite}")
                rc, msg, test_start_time, result_sum = collect_spytest_results(testbed, test_suite, image_id, build_id)
                if rc!=0:
                    print(f"error at collect_result! msg: {msg}")

                log.debug(f"Upload results for test: {test_suite}")
                rc, msg, result_url, log_tarball_link = upload_result(testbed, test_start_time)
                if rc != 0:
                    print(f"error at upload_result! msg: {msg}")

                result_sum["report_link"] = result_url
                result_sum["log_tarball_link"] = log_tarball_link
                result = result_sum
                log.debug(f"result sum for test_suites: '{test_suite}', {result}")
    else:
        [report_data, allure_link] = getLatestValidAllureReport(build_id, image_id, testbed, stream)
        if not report_data:
            log.error("Report Data not found!")
            return -1

        if not allure_link:
            log.error("Allure link not found!")
            return -1

        log.debug(f"report_data:{report_data}")
        log.debug(f"allure_link: {allure_link}")
        
        stats = report_data["statistic"]
        if stats["total"] == 0:
            result["report_link"] = None
            result["status"] = FAILURE_STATUS
        else:
            if (stats["total"] - stats["skipped"]) == 0:
                percent = 0
            else:
                percent = 100 * (stats["passed"] / float(stats["total"]-stats["skipped"]))
            result = {
                "passx" : 0,
                "total" : stats["total"],
                "failed" : stats["failed"],
                "passed" : stats["passed"],
                "aborted" : stats["unknown"],
                "errored" : stats["broken"],
                "skipped" : stats["skipped"],
                "success_rate" : round(percent, 2),
                "report_link": allure_link,
                "status": SUCCESS_STATUS if round(percent, 2) == 100.0 else FAILURE_STATUS,
                "log_path": f"{logs_path}{dut_run_log_folder}",
                "ucs_server": testbed_info_dict["ucs_host_name"]
            }
        
        if result["success_rate"] == 100.0:
            result["status"] = SUCCESS_STATUS
        else:
            result["status"] = FAILURE_STATUS
            result["failure_reason"] = FAILURE_RESONS.TEST_CASES_FAILED
            rc = -1
    files_to_move = [SANITY_LOG_TARBALL]
    log_url = upload_log_files_to_log_server(files_to_move)
    log.debug(log_url)
    result["log_tarball_link"] = log_url
    with open(results_path, "w") as results_file:
        json.dump(result, results_file, indent=2)
    log.info(f"Saved results.json at: {results_path}")   
    return rc

def kill_run(args, test_string="run_tests"):
    testbed = args.testbed
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']

    p = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    p.expect(local_ucs)
    if checkForExistingRuns(p, test_string, local_ucs)>=1:
        log.info("Many runs to kill!")
        return -1
        log.info(f"No of lines: {len(y)}")
        #sample array for y: [<cmd>, <pid>, <pid2>, <local_ucs>]
        pid = y[1]
        pid2 = y[2]
        log.info("Pid: '{0}, Pid2: '{1}".format(pid.strip(), pid2.strip()))
        p.sendline(f"kill -9 {pid}")
        p.expect(local_ucs)
        p.sendline(f"kill -9 {pid2}")
        p.expect(local_ucs)
    else:
        log.info("No runs to kill!")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Management full run.')
    subparser = parser.add_subparsers(help = "available subcommand:")

    run_parser = subparser.add_parser("run", help = "run tests on image")
    run_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    run_parser.add_argument("-b", "--build_id", help = "build id", required=True)
    run_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    run_parser.add_argument("-s", "--test_suites", help = "test suites", default = '', nargs='?')
    run_parser.add_argument("--rerun", help = "rerun", default=False)
    run_parser.add_argument("--skip-folders", help = "skip folders", default = '', nargs='?')
    run_parser.add_argument("--skip-tests", help = "skip tests", default = '', nargs='?')
    run_parser.add_argument("--testfile", help = "test file", default = '', nargs='?')
    run_parser.add_argument("--test-tag", help = "test tag", default = '', nargs='?')
    run_parser.add_argument("--platform", help = "platform of the DUT", default = '', nargs='?')
    run_parser.add_argument("--topology", help = "topology of the DUT", default = '', nargs='?')
    run_parser.set_defaults(func=run_test)

    collect_parser = subparser.add_parser("collect-results", help = "collect data")
    collect_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    collect_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    collect_parser.add_argument("-b", "--build_id", help = "build id", required=True)
    collect_parser.set_defaults(func=collect_results)

    kill_parser = subparser.add_parser("kill", help = "kill runs")
    kill_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    kill_parser.set_defaults(func=kill_run)

    args = parser.parse_args()

    res = args.func(args)
    sys.exit(res)