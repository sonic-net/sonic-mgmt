import datetime
import paramiko
import time
import os
import re
import argparse
import sys
import json
import yaml
import subprocess
import shutil
from enum import Enum

# Path to config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

ALLURE_REPORT_URL_FILE = allure_config['allure']['report-url-file-path']
CICD_LOG_DIR = "/auto/mb/sonic/workspace/sonic-cicd/sanity_logs"
CICD_LOG_URL = "https://allure.cisco.com/auto/mb/sonic/workspace/sonic-cicd/sanity_logs"

SUCCESS_STATUS = "success"
FAILURE_STATUS = "failure"

from utils import upload_log_files_to_log_server 

class FAILURE_RESONS(str, Enum):
    SIM_BAD_STATE = "sim_bad_state"
    TEST_CASES_FAILED = "test_cases_failed"
    NO_REPORT_FILE = "no_report_file"
    CREATE_REPORT_FAIL = "create_report_fail"
    RUN_SCRIPTS_EXCEPTION = "run_scripts_exception"
    LOG_FILES_GET_FAIL = "log_files_get_fail"
    SIM_BRINGUP_FAIL = "sim_bringup_fail"

    def __str__(self):
        return self.value

# VXR sim failed
def handle_sim_failure(error_msg):
    SUMMARY_REPORT_FILENAME = "results.json"
    COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

    SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
    COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

    # Include sim_status field to indicate failure
    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status": FAILURE_STATUS, "failure_reason": error_msg}

    for file_path in [SUMMARY_REPORT_PATH, COMMON_REPORT_PATH]:
        with open(file_path, "w") as output_file:
            json.dump(sum, output_file)

def upload_sanity_file(host, username, password, script_file, sonic_test_dir, ssh_port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("connect", (host, ssh_port, username, password))
    ssh.connect(host, ssh_port, username, password)
    print("connected")
    ftp_client=ssh.open_sftp()
    uploaded_script_files = []
    for script_file_path in script_file.split(","):
        script_filename = script_file_path.rsplit('/', 1)[-1]
        print(f"script_file_path: {script_file_path}, destination: {sonic_test_dir}/sonic-test/sonic-mgmt/tests/{script_filename}")
        ftp_client.put(script_file_path,f"{sonic_test_dir}/sonic-test/sonic-mgmt/tests/{script_filename}")
        uploaded_script_files.append(script_filename)
    ftp_client.close()

    return uploaded_script_files

def upload_dut_data_file(host, username, password, dut_data_file, sonic_test_dir, ssh_port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("connect", (host, ssh_port, username, password))
    ssh.connect(host, ssh_port, username, password)
    print("connected")
    ftp_client=ssh.open_sftp()

    print(f"dut_data_file: {dut_data_file}, destination: {sonic_test_dir}/sonic-test/sonic-mgmt/tests/{dut_data_file}")
    ftp_client.put(dut_data_file,f"{sonic_test_dir}/sonic-test/sonic-mgmt/tests/{dut_data_file}")
    ftp_client.close()

def get_build_project_name():
    if os.getenv("MODE"):
        sanity_mode = os.getenv("MODE").replace("_", "")
    elif os.getenv("SANITY_MODE"):
        sanity_mode = os.getenv("SANITY_MODE").replace("_", "")
    else:
        sanity_mode = "sonic-mgmt"

    if os.getenv("JOB_BASE_NAME"):
        job_base_name = os.getenv("JOB_BASE_NAME").replace("_", "")
    else:
        job_base_name = "manual-sanity"

    if os.getenv("TIMESTAMP"):
        timestamp = re.sub(r'[^a-zA-Z0-9]', '', os.getenv("TIMESTAMP"))
    else:
        timestamp = datetime.datetime.now().strftime("%d%b%Y%H%M%S")

    if os.getenv("BUILD_ID"):
        build_id = os.getenv("BUILD_ID")
    else:
        build_id = 99999

    if os.getenv("PLATFORM"):
        platform = os.getenv("PLATFORM").replace("_", "")
    else:
        platform = "unknownPlatform"

    if os.getenv("TOPOLOGY"):
        topology = os.getenv("TOPOLOGY").replace("_", "")
    else:
        topology = "unknownTopology"


    build_project_name = "sonic-{}-{}-{}-{}-{}-{}".format(job_base_name, build_id, sanity_mode, platform, topology, timestamp)

    build_project_name = build_project_name.lower()

    return build_project_name

def trigger_run_scripts(host, username, password, script_file,drop_version,log_dir,device_type,topo_type,create_allure_report, additional_tests='', ssh_port=22,
            topo_name='docker-ptf', docker_mgmt_container='docker-sonic-mgmt', skip_sanity=False, dut_data_file=None, apply_sim_patches=False, test_tag=None):
    print("starting run_scripts, params: ", host, username, password, script_file,drop_version,log_dir,device_type,create_allure_report,
            ssh_port, topo_name, docker_mgmt_container, skip_sanity, dut_data_file)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    print("connected to host {}".format(host))
    chan = ssh.invoke_shell()
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    print("Going into container '{}' to run tests".format(docker_mgmt_container))
    chan.send('docker exec -it {} /bin/bash \n'.format(docker_mgmt_container))
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    chan.send('unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("utf-8", errors="replace"))
    
    reports_dir = allure_config['allure']['local-report-dir']
    chan.send(f'rm -f {reports_dir}/* \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("utf-8", errors="replace"))

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("utf-8", errors="replace"))

    build_project_name = get_build_project_name()

    print("calling run_scripts.py, the allure report build name is ", build_project_name)

    tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")
    result_file = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    chan.send('rm run_script.log \n')
    time.sleep(3)
    chan.send('rm {} \n'.format(result_file))
    time.sleep(3)
    chan.send('rm -rf DT\n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("utf-8", errors="replace"))

    delta1 = datetime.datetime.now()

    additional_params = ""

    if create_allure_report:
        additional_params += " --create_allure_report "
    if additional_tests:
        additional_params += " --additional_tests={} ".format(additional_tests)
    if skip_sanity:
        additional_params += " -k "

    ## apply patches specefic to sim
    if apply_sim_patches:
        print("applying sim patches by running python add_sim_hooks.py \n")
        chan.send('python add_sim_hooks.py \n')
        time.sleep(60)
        resp = chan.recv(9999)
        print(resp.decode("utf-8", errors="replace"))
        additional_params += " --mark-conditions-files common/plugins/conditional_mark/tests_mark_conditions_cisco_sim.yaml"

    print("Run command:")
    print('./run_scripts.py -s {} -v {} -l {} -d {} -tt {} -t {} -g {} -b {} -dd {} -y \'{}\' {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,topo_type,tstamp,topo_name,build_project_name,dut_data_file,test_tag,additional_params))

    chan.send('./run_scripts.py -s {} -v {} -l {} -d {} -tt {} -t {} -g {} -b {} -dd \'{}\' -y \'{}\' {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,topo_type,tstamp,topo_name,build_project_name,dut_data_file,test_tag,additional_params))

    time.sleep(3)
    resp = chan.recv(9999)

    chan.send('exit\n')
    time.sleep(10)

    chan.send('docker exec -it {} /bin/bash \n'.format(docker_mgmt_container))
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    later = datetime.datetime.now() + datetime.timedelta(hours=30)
    while True:
        chan.send('ps -ef | grep run_scripts.py\n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("utf-8", errors="replace"))
        sys.stdout.flush()

        if script_file in resp.decode("utf-8", errors="replace"):
            time.sleep(150)
            chan.send('cat /data/tests/{} \n'.format(result_file))
            time.sleep(3)
            resp = chan.recv(9999)
            print(resp.decode("utf-8", errors="replace"))
            if datetime.datetime.now() < later:
                time.sleep(150)
            else:
                print("Looks like test is taking longer than 30 hours. Check list of sanity scripts or increase time to wait")
                break
        else:
            break

    chan.send('cat /data/tests/{} \n'.format(result_file))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("utf-8", errors="replace"))
    if "BGP Fact testcase is still failing" in resp.decode("utf-8", errors="replace"):
        status = FAILURE_STATUS
        failure_reason = FAILURE_RESONS.SIM_BAD_STATE
    else:
        status = SUCCESS_STATUS
        failure_reason = None
    
    if create_allure_report:
        copy_allure_report_tar_to_remote_and_generate_url(host=host, username=username, password=password, build_project_name=build_project_name, docker_mgmt_container=docker_mgmt_container, ssh_port=ssh_port)

    ssh.close()
    delta2 = datetime.datetime.now()
    time_delta = (delta2 - delta1)
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60

    print("Total run time for sanity suite: {} mins".format(minutes))
    return status, failure_reason

def create_report_html(host, username, password, log_dir, sonic_test_dir, ssh_port=22):
    print("Creating report html on remote host {}. SSH port {}, username/password: {}/{}".format(host, ssh_port, username, password))
    print("running command: ")
    print('python3 {}/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o {}/sonic-test/sonic-mgmt/tests/results.json \
        --directory {}/sonic-test/sonic-mgmt/tests/{} > {}/sonic-test/sonic-mgmt/tests/report.txt \n'.format(sonic_test_dir, sonic_test_dir, sonic_test_dir, log_dir, sonic_test_dir))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)

    chan = ssh.invoke_shell()
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)
    commands = []

    commands.append('python3 {}/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o {}/sonic-test/sonic-mgmt/tests/results.json \
        --directory {}/sonic-test/sonic-mgmt/tests/{} > {}/sonic-test/sonic-mgmt/tests/report.txt \n'.format(sonic_test_dir, sonic_test_dir, sonic_test_dir, log_dir, sonic_test_dir))
    commands.append('junit2html {}/sonic-test/sonic-mgmt/tests/{} --merge {}/sonic-test/sonic-mgmt/tests/{}/test-results.xml\n'.format(sonic_test_dir, log_dir, sonic_test_dir, log_dir))
    commands.append('junit2html {}/sonic-test/sonic-mgmt/tests/{}/test-results.xml --report-matrix {}/sonic-test/sonic-mgmt/tests/report.html\n'.format(sonic_test_dir, log_dir, sonic_test_dir))
    commands.append('junit2html {}/sonic-test/sonic-mgmt/tests/{}/test-results.xml --summary-matrix\n'.format(sonic_test_dir, log_dir))
    i = 0
    while True:
        if len(commands) == i:
            break

        chan.send(commands[i])
        print(f"Running command '{commands[i]}'")
        resp = ''
        while ':~$' not in resp:
            resp = chan.recv(9999).decode("ascii")
            print(resp)
        time.sleep(3)
        if chan.recv_ready():
            print(chan.recv(9999).decode("ascii"))
        i += 1

    ssh.close()


def parse_report(host, username, password, sonic_test_dir, ssh_port=22):
    print("Parsing report")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    ftp_client=ssh.open_sftp()
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/report.txt'.format(sonic_test_dir),'report.txt')
    ftp_client.close()
    ssh.close()

    read_report = open('report.txt', 'r')
    report_file = open('full_report.txt', 'w')
    out = read_report.read().splitlines()
    total, passed, fail, skip, error, xfail = 0, 0, 0, 0, 0, 0
    for line in out:
        print(line)
        if 'total' not in line.lower():
            continue
        report_file.write(line + "\n")
        report_file.flush()
        tc = line.split(',')
        if 'total' not in tc[1].lower():
            continue
        total += int(tc[1].strip(' ').split(' ')[0])
        passed += int(tc[2].strip(' ').split(' ')[0])
        fail += int(tc[3].strip(' ').split(' ')[0])
        skip += int(tc[4].strip(' ').split(' ')[0])
        error += int(tc[5].strip(' ').split(' ')[0])
        xfail += int(tc[6].strip(' ').split(' ')[0])
    resp = "Total TCs: {}, {} Pass, {} Fail, {} Skipped, {} Error, {} xFail\n".format(total,passed,fail,skip,error,xfail)
    report_file.write("=================================================================\n")
    print("=================================================================\n")
    print(resp)
    report_file.write(resp  + "\n")
    report_file.flush()
    report_file.close()
    return resp

def get_report_file(host, username, password, sonic_test_dir, ssh_port=22):
    print("Getting report file")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    ftp_client=ssh.open_sftp()
    #ftp_client.get('{}/sonic-test/sonic-mgmt/tests/full_report.txt','full_report.txt')
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/test-results.xml.html'.format(sonic_test_dir),'test-results.xml.html')
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/report.html'.format(sonic_test_dir),'report.html')
    ftp_client.close()

def copy_allure_report_tar_to_remote_and_generate_url(host, username, password, build_project_name, docker_mgmt_container, ssh_port=22):
    print("Getting allure report tar file")
    
    report_folder_name = "allure-report-{}".format(build_project_name)
    report_dir_path = "/tmp/{}".format(report_folder_name)
    report_tar_path = "{}.tar.gz".format(report_dir_path)

    remote_path = allure_config['allure']['remote-report-dir'] 
    remote_path = remote_path if remote_path.endswith('/') else remote_path + '/'

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    ftp_client=ssh.open_sftp()

    # copy allure report tar file to the VM
    print("Copying allure report tar file from container {}:{} to the VM:{}".format(docker_mgmt_container, report_tar_path, report_tar_path))
    cmd = 'docker cp {}:{} {}\n'.format(docker_mgmt_container, report_tar_path, report_tar_path)

    _, stdout, stderr = ssh.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print("Error! Could not copy allure report from {}:{} to {}: {}".format(docker_mgmt_container, report_tar_path, report_tar_path, stderr.read().decode("ascii")))
        ssh.close()
        ftp_client.close()
        return
    
    sys.stdout.flush()

    # get allure report tar file from the VM
    print("Getting allure report tar file from the VM:{} to local".format(report_tar_path))
    try:
        ftp_client.get(report_tar_path, report_tar_path)
    except Exception as e:
        print("Error! Could not get allure report tar file!")
    ftp_client.close()

    # extract allure report tar file
    print("Extracting allure report tar file")
    result = subprocess.run(["tar", "-xvzf", report_tar_path, "-C", "/tmp/"])
    if result.returncode != 0:
        print("Error! Could not extract allure report tar file! {} {}".format(result.stderr, result.stdout))
        return

    # copy allure report to remote
    print("Copying allure report to remote path: {}".format(remote_path))
    result = subprocess.run(["cp", "-R", report_dir_path, "{}/".format(remote_path)])
    if result.returncode != 0:
        print("Error! Could not copy allure report to remote! {} {}".format(result.stderr, result.stdout))
        return

    # clean-up allure report tar file and folder
    print("Removing allure report tar file and folder from local")
    result = subprocess.run(["rm", "-rf", report_tar_path])
    if result.returncode != 0:
        print("Error! Could not remove allure report tar file! {} {}".format(result.stderr, result.stdout))
    
    result = subprocess.run(["rm", "-rf", report_dir_path])
    if result.returncode != 0:
        print("Error! Could not remove allure report folder! {} {}".format(result.stderr, result.stdout))

    # create report URL and write to file
    report_url = "{}/{}/{}".format(allure_config['allure']['server-base-url'], allure_config['allure']['remote-report-dir'], report_folder_name)
    with open(ALLURE_REPORT_URL_FILE, 'w') as f:
        f.write(report_url)

    print("Allure report copied to remote successfully and generated URL: {}".format(report_url))


def get_sanity_logs(host, username, password, log_dir, sonic_test_dir, ssh_port=22):
    print("Get sanity log files")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)

    tar_commands = [
        f"cd {sonic_test_dir}/sonic-test/sonic-mgmt/tests",
        f"mkdir sanity_logs; cp -r *.log logs/ {log_dir} sanity_logs",
        "tar -cvf sanity_logs.tar sanity_logs",
        "gzip -f sanity_logs.tar"
    ]

    print(f"Running remote command: {tar_commands}")
    stdin, stdout, stderr = ssh.exec_command(';'.join(tar_commands))
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        error_output = stderr.read().decode()
        print(f"Error creating sanity logs tarball: {error_output}")
        ssh.close()
        return

    ftp_client=ssh.open_sftp()
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/sanity_logs.tar.gz'.format(sonic_test_dir),'sanity_logs.tar.gz')
    ftp_client.close()
    ssh.close()

    # extract syslogs tarball
    print(f"Extracting sanity_logs.tar.gz")
    result = subprocess.run(["tar", "-xvzf", "sanity_logs.tar.gz"])
    if result.returncode != 0:
        print(f"Error! Could not extract sanity_logs.tar.gz! stderr: {result.stderr}, stdout: {result.stdout}")

def get_syslogs(dut_data_file):
    dut_uname = 'cisco'
    dut_passwd = 'cisco123'

    with open(dut_data_file) as f:
        dut_data = yaml.load(f, Loader=yaml.FullLoader)

    #get syslog for each DUT
    for dut_name, dut_config in dut_data.items():
        #only consider DUTs
        if not dut_name.startswith('sonic_dut'):
            continue

        dut_address = dut_config['HostAgent']
        ssh_port = dut_config['xr_redir22']

        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(dut_address, port=ssh_port, username=dut_uname, password=dut_passwd)

        # Create the tar.gz archive on the remote machine.
        # The command changes directory to remote_dir and archives its contents.
        remote_tar_path = f"/tmp/syslogs_{dut_name}.tar.gz"
        local_tar_path = os.path.basename(remote_tar_path)
        tar_commands = [
            f"mkdir -p /tmp/syslogs/{dut_name}",
            f"sudo cp /var/log/syslog* /tmp/syslogs/{dut_name}",
            f"sudo chmod 666 /tmp/syslogs/{dut_name}/syslog*",
            f"tar -czvf {remote_tar_path} -C /tmp syslogs",
            "rm -rf /tmp/syslogs"
        ]
        print(f"Running remote command: {tar_commands}")
        stdin, stdout, stderr = ssh.exec_command(';'.join(tar_commands))
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_output = stderr.read().decode()
            print(f"Error creating tar archive on remote host: {error_output}")
            ssh.close()
            return

        # Open an SFTP session and download the tar file.
        sftp = ssh.open_sftp()
        print(f"Downloading remote archive from {remote_tar_path} to {local_tar_path}")
        sftp.get(remote_tar_path, local_tar_path)

        # Optionally, remove the remote tar.gz file
        print(f"Removing remote archive {remote_tar_path}")
        sftp.remove(remote_tar_path)
        sftp.close()
        ssh.close()
        print("Download complete.")

        # extract syslogs tarball
        print(f"Extracting tarball {local_tar_path}")
        result = subprocess.run(["tar", "-xvzf", local_tar_path])
        if result.returncode != 0:
            print(f"Error! Could not extract {local_tar_path}! stderr: {result.stderr}, stdout: {result.stdout}")
            return

    # re-packaging syslogs directory into a tarball
    print(f"Re-packaging directory syslogs into tarball")
    result = subprocess.run(["tar", "-czvf", "syslogs.tar.gz", "syslogs"])
    if result.returncode != 0:
        print(f"Error! encountered error while creating tarball! stderr: {result.stderr}, stdout: {result.stdout}")
        return

def generate_results_json(run_result, failure_reason):
    # Path to config file
    ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
    allure_config = {}
    with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
        allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
        config_file.close()

    SUMMARY_REPORT_FILENAME = "results.json"

    SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
    ALLURE_REPORT_URL_FILE = allure_config['allure']['report-url-file-path']

    sum = {
        "total": 0, 
        "failed": 0, 
        "passed": 0, 
        "skipped": 0, 
        "success_rate": 0.0, 
        "status" : run_result,
        "failure_reason": failure_reason
    }

    sum_f = open(SUMMARY_REPORT_PATH, "w")
    resultpattern = r'<th class="(passed|skipped|failed)">'
    numberpattern = r'<td>(\d+)</td>'

    try:
        report = open("./report.html", "r")
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
            if sum["success_rate"] != 100:
                sum["status"] = FAILURE_STATUS
                sum["failure_reason"] = sum["failure_reason"] or FAILURE_RESONS.TEST_CASES_FAILED
    except:
        print("error: report.html file does not exist!")
        sum["status"] = FAILURE_STATUS
        sum["failure_reason"] = sum["failure_reason"] or FAILURE_RESONS.NO_REPORT_FILE
    
    try:
        with open(ALLURE_REPORT_URL_FILE, 'r') as f:
            allure_url = f.readline()
            print(f"found allure report url: {allure_url}")
            sum["report_link"] = allure_url
    except FileNotFoundError as e:
        print(f"Error! could not find file {ALLURE_REPORT_URL_FILE}, containing allure report: {e}")

    # List of files to copy into the build directory
    files_to_copy = ["report.html", "test-results.xml.html", "sanity_logs.tar.gz", "sanity_logs", "syslogs", "syslogs.tar.gz"]
    log_url = upload_log_files_to_log_server(files_to_copy)

    sum["log_tarball_link"] = log_url

    print(f"Result summary: {sum}")

    json.dump(sum, sum_f)
    sum_f.close()

    return sum

def run_scripts_remote(host, username, password, script_file,drop_version,log_dir,device_type,topo_type,create_allure_report, ssh_port=22, topo_name='docker-ptf', additional_tests='',
            sonic_test_dir='golden-code', docker_mgmt_container='docker-sonic-mgmt', skip_sanity=False, dut_data_file=None, add_sim_patches=False, test_tag=None):
    sanity_start_time = datetime.datetime.now()

    print('run_scripts_remote, params:')
    print(f"""
host={host},
username={username},
password={password},
script_file={script_file},
drop_version={drop_version},
log_dir={log_dir},
device_type={device_type},
topo_type={topo_type},
create_allure_report={create_allure_report},
ssh_port={ssh_port},
topo_name={topo_name},
additional_tests={additional_tests},
sonic_test_dir={sonic_test_dir},
docker_mgmt_container={docker_mgmt_container},
skip_sanity={skip_sanity},
dut_data_file={dut_data_file},
add_sim_patches={add_sim_patches},
test_tag={test_tag},
          """)

    
    if not os.path.exists(dut_data_file):
        print(f"ERROR! dut data file '{dut_data_file}' does not exist! Exiting")
        return -1

    if not host or not ssh_port:
        with open(dut_data_file) as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
        host = data['sonic_mgmt']['HostAgent']
        ssh_port = data['sonic_mgmt']['xr_redir22']

    run_result = None
    failure_reason = None

    print("Running scripts remotely on host {}. SSH port {}, username/password: {}/{}".format(host, ssh_port, username, password))
    print("Device type: {}, topo_name: {}".format(device_type, topo_name))
    print("Script file: {}, drop version: {}, log_dir {}, sonic-test directory: {}, docker-mgmt container name: '{}', create-allure-report: {}".format(script_file, drop_version, log_dir, sonic_test_dir, docker_mgmt_container, create_allure_report))
    print("Upload Sanity Script file")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    print("connected to host {}".format(host))

    print("determine sonic_test_dir from docker_mgmt_container name")
    cmd = f'docker inspect `docker ps -aqf name={docker_mgmt_container}` | grep sonic-test | head -1\n'

    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()
    out = stdout.read().decode("ascii").strip()

    print(f"resp for docker inspect is {out}")
    sys.stdout.flush()
    out = out.strip('"')
    sonic_test_dir = out.split("/sonic-test")[0]
    print("sonic-test dir is: ", sonic_test_dir)

    #send additional test files to sim
    ftp_client=ssh.open_sftp()
    if additional_tests:
        for additional_test in additional_tests.split(","):
            additional_test = additional_test.strip()
            print(f"uploading additional testcase {additional_test} to sonic-mgmt from '../sonic-mgmt/tests/{additional_test}' to '{sonic_test_dir}/sonic-test/sonic-mgmt/tests/{additional_test}'")

            chan = ssh.invoke_shell()
            chan.send(f"mkdir -p {sonic_test_dir}/sonic-test/sonic-mgmt/tests/{additional_test.rsplit('/',1)[0]} \n")

            try:
                ftp_client.put(f"../sonic-mgmt/tests/{additional_test}",f"{sonic_test_dir}/sonic-test/sonic-mgmt/tests/{additional_test}")
            except Exception as e:
                print(f"caught error while uploading file {additional_test}! e: {e}")
                return 1


    uploaded_script_files = upload_sanity_file(host, username, password, script_file, sonic_test_dir, ssh_port)
    uploaded_script_files_str = ",".join(uploaded_script_files)
    upload_dut_data_file(host, username, password, dut_data_file, sonic_test_dir, ssh_port)

    print("Running Sanity Scripts : '{}', additional tests: '{}'".format(uploaded_script_files_str, additional_tests))
    try:
        run_result, failure_reason = trigger_run_scripts(
            host, 
            username, 
            password, 
            uploaded_script_files_str,
            drop_version,
            log_dir,
            device_type,
            topo_type,
            create_allure_report, 
            additional_tests,
            ssh_port, 
            topo_name, 
            docker_mgmt_container, 
            skip_sanity, 
            dut_data_file, 
            add_sim_patches, 
            test_tag
        )
    except Exception as e:
        print(f"Caught exception while running run_scripts.py! error: {e}")
        run_result = FAILURE_STATUS
        failure_reason = FAILURE_RESONS.RUN_SCRIPTS_EXCEPTION
    
    sanity_end_time = datetime.datetime.now()

    try:
        create_report_html(host, username, password, log_dir, sonic_test_dir, ssh_port)
        parse_report(host, username, password, sonic_test_dir, ssh_port)
        get_report_file(host, username, password, sonic_test_dir, ssh_port)
    except Exception as e:
        print(f"Caught exception while creating report! error: {e}")
        run_result = FAILURE_STATUS
        failure_reason = failure_reason or FAILURE_RESONS.CREATE_REPORT_FAIL
    
    try:
        get_sanity_logs(host, username, password, log_dir, sonic_test_dir, ssh_port)
        get_syslogs(dut_data_file)
    except Exception as e:
        print(f"Caught exception while getting logs! error: {e}")
        run_result = FAILURE_STATUS
        failure_reason = failure_reason or FAILURE_RESONS.LOG_FILES_GET_FAIL

    results_summary = generate_results_json(run_result, failure_reason)

    sanity_time_delta = (sanity_end_time - sanity_start_time).total_seconds()
    print("Time taken for the sanity tests to run : {} mins".format(sanity_time_delta/60))
    if results_summary["status"] != SUCCESS_STATUS:
        print("Sanity run unsuccesful !!!, Check log files for more details")
        return 1

    return 0

def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-a', '--host_address', type=str, help='host address to ssh into',
                      required=False,default=None)
    parser.add_argument('-r', '--ssh_port', type=str, help='port_used for ssh',
                      required=False,default=22)
    parser.add_argument('-u', '--username', type=str, help='username used to ssh into machine running sonic-mgmt',
                      required=False,default="vxr")
    parser.add_argument('-p', '--password', type=str, help='password used to ssh into mechine running sonic-mgmt',
                      required=False,default="cisco123")
    parser.add_argument('-g', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default='DT')
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default='DT')
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='sanity-scripts/sanity_scripts.txt')
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32, crocodile, sfd',
                      required=True,default="mth64")
    parser.add_argument('-tt', '--topo_type', type=str, help='topo type',
                      required=True,default='t1-64-lag')
    parser.add_argument('-c', '--docker_mgmt_container', type=str, help='name of the docker management container',
                      required=False,default='docker-sonic-mgmt')
    parser.add_argument('-t', '--sonic_test_dir', type=str, help='Directory of sonic-test on DUT',
                      required=False, default='golden-code')
    parser.add_argument('--create_allure_report', action='store_true', help='When testing, specify if allure report to be created at the end of test',
                      default=False)
    parser.add_argument('--additional_tests', type=str, help='Additional Testscases to test',
                      required=False, default='')
    parser.add_argument('--add_sim_patches', action='store_true', help='Add patches to SIM to handle eth4 for route_check and shutdown',
                      default=False)
    parser.add_argument('-k', '--skip_sanity', action='store_true', help='skip sanity check',
                      default=False)
    parser.add_argument('-m', '--dut_data_file', type=str, help='path of file containing DUT access info',
                      required=False,default='vxr_ports.yaml')
    parser.add_argument('-y', '--test_tag', type=str, help='tag to get tests to run from sanity file. Comma seperated \
        For e.g.fwd,plt', required=False,default=None)
    return parser


if __name__ == '__main__':
    parser = _create_parser()

    args = vars(parser.parse_args())
    host_address = args['host_address']
    ssh_port = args['ssh_port']
    username = args['username']
    password = args['password']
    topo_name = args['topo_name']
    drop_version = args['drop_version']
    log_dir = args['log_dir']
    script_file = args['script_file']
    device_type = args['device_type']
    topo_type = args['topo_type']
    docker_mgmt_container = args['docker_mgmt_container']
    sonic_test_dir = args['sonic_test_dir']
    create_allure_report = args['create_allure_report']
    additional_tests = args['additional_tests']
    skip_sanity = args['skip_sanity']
    dut_data_file = args['dut_data_file']
    add_sim_patches = args['add_sim_patches']
    test_tag = args['test_tag']
    
    ret = run_scripts_remote(
        host_address,
        username,
        password,
        script_file,
        drop_version,
        log_dir,
        device_type,
        topo_type,
        create_allure_report,
        ssh_port,
        topo_name,
        additional_tests,
        sonic_test_dir,
        docker_mgmt_container,
        skip_sanity,
        dut_data_file,
        add_sim_patches,
        test_tag
    )

    sys.exit(ret)