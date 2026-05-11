import argparse
import json
import logging
import os
import yaml
import telnetlib
import paramiko
import time
import datetime
import subprocess
import sys
import re
from pathlib import Path
import shlex
import tarfile
from db_tool_sonicsol import PostgresDBConnectionSonicSol
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/..")
from run_scripts_remote import SUCCESS_STATUS, FAILURE_STATUS, FAILURE_RESONS
import pexpect
import csv

NODE_NAME = os.getenv("NODE_NAME", "unknown")

VXR_PORTS_FILENAME = "vxr_ports.yaml"
RESULT_FOLDER_PATH = "/home/sonic/solution_test/sonic-test/sonic-mgmt/spytest/spytest_results"
LOG_SERVER_IP = "10.28.109.58" ;# light14 server
LOG_SERVER_USERNAME = "sonic"
LOG_SERVER_PASSWORD = "roZes@123"
LOG_PATH = "/var/www/html/logs/solution_test"
LOG_HTTP_PATH = f"http://{LOG_SERVER_IP}:/logs/solution_test"

SUMMARY_REPORT_FILENAME = "results.json"
NEW_SUMMARY_REPORT_FILENAME = "test_cases_info.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
#TOPO_PLATFORM_FILE_MAP = os.path.dirname(os.path.realpath(__file__)) + '/topo_and_platform_to_filename_map.json'
SERVER_CREDS_MAP = os.path.dirname(os.path.realpath(__file__)) + '/server_creds.json'
SUMMARY_REPORT_PATH = "../../../{}".format(SUMMARY_REPORT_FILENAME)
NEW_SUMMARY_REPORT_PATH = "../../../{}".format(NEW_SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../../{}".format(COMMON_REPORT_FILENAME)


pattern = r'_mh'
flag = False
for item in sys.argv:
    match = re.search(pattern, item)
    if match:
        flag = True
        break
if flag:
    TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING = {
        "spine0": "SD1",
        "leaf0": "SD2",
        "leaf1": "SD3",
        "leaf2": "SD4",
        "leaf3": "SD5"
    }   
else:
    TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING = {
        "spine0": "SD1",
        "spine1": "SD2",
        "leaf0": "SD3",
        "leaf1": "SD4",
        "leaf2": "SD5"
    }

device_ip_and_ports = []

def _create_parser():
    parser = argparse.ArgumentParser(description='Uploading Solution Test run logs to Dashboard.')
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=False)
    parser.add_argument('--curr_server', type=str, help='current server where the run is stored',
                      required=True)
    parser.add_argument('-t', '--topology', type=str, help='location of DUT in topo',
                      required=True)
    parser.add_argument('-p', '--platform', type=str, help='platform type of the DUT',
                      required=True)
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False, default="")
    parser.add_argument('-r', '--run_label', type=str, help='Label for test run. ' 
                                                            'Example: ipv4, ipv6',
                      required=True, default="")
    parser.add_argument('-d', '--run_desc', type=str, help='Description for test run. ' 
                                                            'Example: "rerun tgfailed TCs ',
                      required=False, default="")
    parser.add_argument('-l', '--logs_path', type=str, help='Do data collect and upload for ' 
                      'existing run logs', required=True, default='')
    parser.add_argument('-x', '--dev', action='store_true', 
                        help='Run in dev mode. Data written to dev dir')
    parser.add_argument('-n', '--npu', type=str, help='NPU ID OR Project Name',
                      required=True)
    return parser


def get_ports_config(port_file=VXR_PORTS_FILENAME):
    with open(port_file) as f:
        ports_config = yaml.load(f, Loader=yaml.FullLoader)
    
    return ports_config

def get_spirent_ip():
    ports_config = get_ports_config()

    telnet_host = ports_config["spt"]["HostAgent"]
    telnet_port = ports_config["spt"]["serial0"]

    p = pexpect.spawn(f'telnet {telnet_host} {telnet_port}')
    p.sendline()
    p.expect('login')
    ret = str(p.before)
    ret = ret.split("STCv-")[1].split("/dev")[0].replace("-", ".")

    return ret.strip()

"""
def determine_spt_or_ixia(topology, platform):
    print("determine_spt_or_ixia")
    pyvxr_yaml_file = import_pyvxr_yaml_file(topology, platform)
    with open(pyvxr_yaml_file, "r") as f:
        pyvxr_topo = yaml.load(f, Loader=yaml.BaseLoader)

    if "ixia" in pyvxr_topo["devices"]:
        return "ixia"
    elif "spt" in pyvxr_topo["devices"]:
        return "spt"
    else:
        print("ERROR! Could not find ixia or spt in pyvxr yaml file!")
        return None
"""

def find_devices(topo_file_str):
    regex = r'^([ ]{0}|[ ]{4}|\t)(\w+):'
    keys = re.findall(regex, topo_file_str, re.MULTILINE)

    is_device = False
    devices = []

    for i, reg_match in enumerate(keys):
        #got to devices key
        if reg_match[1] == "devices":
            is_device = True
            continue

        #reached end of devices list
        if is_device and len(reg_match[0]) == 0:
            break

        if is_device:
            devices.append(reg_match[1])

    return devices

# Define a function to perform the replacement
def replace_device_ip_and_port_helper(match):
    global device_ip_and_ports
    curr_device = device_ip_and_ports.pop(0)
    print(curr_device)
    return match.group(1) + curr_device["ip"] + match.group(2) + curr_device["port"] + match.group(3)

def replace_device_ip_and_port(topo_file_str):
    regex = r'(\W+access:\s*\{.*?ip:\s*)\S+(,\s*port:\s*)\S+(}\n)' #match 'access' portion of devices config
    data_replaced = re.sub(regex, replace_device_ip_and_port_helper, topo_file_str, flags=re.DOTALL)
    return data_replaced

def update_device_ip_and_ports(topo_file_str):
    global device_ip_and_ports
    devices = find_devices(topo_file_str)

    ports_config = get_ports_config()

    for device_name in devices:
        device_access_info = {}
        if "SD" in device_name:
            device_access_info["ip"] = ports_config[device_name]["HostAgent"]
            device_access_info["port"] = str(ports_config[device_name]["xr_redir22"])
        elif device_name in TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING:
            device_name_in_pyvxr_topo = TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING[device_name]
            device_access_info["ip"] = ports_config[device_name_in_pyvxr_topo]["HostAgent"]
            device_access_info["port"] = str(ports_config[device_name_in_pyvxr_topo]["xr_redir22"])
        else:
            continue
            
        device_ip_and_ports.append(device_access_info)
    
    new_topo_file_str = replace_device_ip_and_port(topo_file_str)
    return new_topo_file_str

def exec_command_raise_error(client, cmd):
    print(f"executing command: '{cmd}'")
    stdin, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print(f"Encountered error while executing '{cmd}', stdout: {stdout.readlines()}, stderr: {stderr.readlines()}")
        raise Exception(stdout.channel.recv_exit_status(), stderr.readlines())

    return stdin, stdout, stderr
        
def execute_command_on_chan(chan, command='', show_output=False):
    print(f"executing command: {command}")
    termination_command = "\necho \"Command Completed, exit code is: $?\"\n"
    termination_str = "Command Completed, exit code is:"
    chan.send(command+termination_command)
    while True:
        resp = chan.recv(9999).decode('utf-8')
        if show_output:
            print("resp: ", resp)
        if termination_str in resp:
            #the termination command command will show up initially in resp, ignore
            if resp.count(termination_str) == 1 and "$?" in resp.split(termination_str)[1]:
                continue
            exit_code = resp.split(termination_str)[1]
            print(f"Exit code for command {command} is: {exit_code}")
            break

def run_sanity(topology, platform, script_file): 
    print("Starting step: run_sanity")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")

    chan = client.invoke_shell()
    execute_command_on_chan(chan)

    spt_or_ixia = determine_spt_or_ixia(topology, platform)

    if spt_or_ixia == "spt":
        cmd = "docker exec -it docker-sonic-mgmt /bin/bash\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "sudo su\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "cd /data; cp -r projects /; /data/bin/tools_install.sh; export SPIRENTD_LICENSE_FILE=10.22.181.32\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "mkdir spytest_results; chmod 777 spytest_results; cd spytest_results\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"env; /data/bin/spytest --testbed /data/topo --test-suite /data/{script_file}\n"
        execute_command_on_chan(chan, cmd, show_output=True)

    elif spt_or_ixia == "ixia":
        cmd = "docker exec -it ixia_sonic_mgmt bash\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "cd /data; pip install monotonic\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "pip install retry\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "unset https_proxy http_proxy\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "mkdir spytest_results; chmod 777 spytest_results; cd spytest_results\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"env; /data/bin/spytest --testbed /data/topo --test-suite /data/{script_file}\n"
        execute_command_on_chan(chan, cmd, show_output=True)
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"

    time.sleep(120)

    return 0, ""

def extract_test_start_time(spytest_results_files):
    for file in spytest_results_files:
        if "stats.txt" in file:
            return "_".join(file.split("_")[1:-1])

def pull_dir_via_sftp(host, user, password, remote_dir, local_dest, port=22, keep_remote_tar=False):
    print(f"Tarring path {user}@{host}:{remote_dir} and storing to local directory: '{local_dest}'")
    remote_dir = str(remote_dir)
    local_dest = Path(local_dest) / host
    local_dest.mkdir(parents=True, exist_ok=True)

    tarball_name = f"{remote_dir.replace('/', '_')}.tar.gz"
    remote_tar = f"/tmp/{tarball_name}"
    local_tar = local_dest / tarball_name
    tar_cmd = f"set -euo pipefail; tar -czf {shlex.quote(remote_tar)} {remote_dir}"

    if local_tar.exists() and local_tar.is_file():
        msg = f"Tarball '{tarball_name}' already exists in local directory '{local_dest}'! Exit."
        #raise ValueError(msg)
        print(msg)
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=user, password=password, port=port)

    # Tar the directory on the remote host
    print(f"tar cmd: {tar_cmd}")
    _, stdout, stderr = ssh.exec_command(tar_cmd)
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        msg = stderr.read().decode()
        ssh.close()
        raise RuntimeError(f"Remote tar failed (rc={rc}): {msg}")

    # Download the tarball via SFTP
    sftp = ssh.open_sftp()
    try:
        sftp.get(remote_tar, str(local_tar))
    finally:
        sftp.close()
    print(f"From {host}, Downloaded {remote_tar} to local: '{local_tar}'")

    # Optionally remove the tarball on the remote
    if not keep_remote_tar:
        ssh.exec_command(f"rm -f {shlex.quote(remote_tar)}")
    ssh.close()

    # Extract locally
    with tarfile.open(local_tar, mode="r:gz") as tf:
         tf.extractall(path=local_dest)

    # Clean up local tar
    try:
        os.remove(str(local_tar))
    except OSError:
        raise Exception("Unable to clean up local tar file")

    relative_path = Path(remote_dir.lstrip('/'))
    final_path = local_dest / relative_path
    print(f"Destination of directory now! {final_path}")
    return final_path

def open_leaf0_log_file(directory_path, topology):
    """
    Opens the first file ending with 'leaf0.log' found in the specified directory.

    Args:
        directory_path (str): The path to the directory to search.

    Returns:
        str: The content of the file if found, otherwise an error message.
    """
    try:
        # Check if the directory exists
        if not os.path.isdir(directory_path):
            return f"Error: Directory '{directory_path}' does not exist."

        image_id = 0 
        stream = ""
        release = ""

        CONDITIONAL_LOGS = {
            'leaf1.log': 'cnest',
            'T2LC0.log': 't2',
            'SD1.log': 'oci',
            'leaf0_dc1.log': 'dci'
        }

        found = False

        # List all files and directories in the given path
        for filename in os.listdir(directory_path):
            # Check if the item is a file and ends with 'leaf0.log'
            if os.path.isfile(os.path.join(directory_path, filename)):
                if filename.endswith('leaf0.log') or any(filename.endswith(sfx) and key in topology
                                                        for sfx, key in CONDITIONAL_LOGS.items()):
                    found = True
                    file_path = os.path.join(directory_path, filename)
                    print(f"Found and opening file: {file_path}")
                    try:
                        with open(file_path, 'r') as f:
                            lines = f.readlines()
                            i = 0 
                            while "SONiC Software Version" not in lines[i]: 
                                i += 1 
                            
                            if i < len(lines): 
                                sh_ver_img_pattern1 = r"-([0-9]+)-"  #SONiC.202405c.2.1.0-81I-28928-20250807.235033
                                sh_ver_img_pattern2 = r".([0-9]+)-"  #SONiC.202405c.28930-int-20250807.201428 

                                info = lines[i][lines[i].index("Version:"):]
                                match1 = re.search(sh_ver_img_pattern1, info)
                                match2 = re.search(sh_ver_img_pattern2, info)

                                if match1: # Check if match1 is not None
                                    if len(match1.group()) > 4:
                                        image_id = match1.group()[1:-1]
                                elif match2: # Check if match2 is not None
                                    if len(match2.group()) > 4:
                                        image_id = match2.group()[1:-1]
                                else:
                                    print("No Match found!")
                                
                                db_stream = PostgresDBConnectionSonicSol(use_backup=False)
                                stream_tup = db_stream.find_one("pipeline2_build", key_data={"build_id": image_id}, column_list=["stream"])
                                db_stream.close_connection()
                                stream = stream_tup[0]

                                pattern = r"^[^.]+\.((?:\d{6}[a-zA-Z]*)(?:\.(?:\d+|[a-zA-Z]{1,4}))?)"
                                ##if '202405c.2.tortuga.2.2' in stream: 
                                ##   pattern = r"^[^.]+\.(\d{6}[a-z]\.\d+\.[^.]+\.\d+\.\d+)"     
                                    
                                match = re.search(pattern, stream)
                                if match: 
                                    release = match.group(1)

                                if release == "": 
                                    release = stream.split('.', 1)[0] # to look for the correct release in streams like 'c-master.tortuga.....'

                                print("About to be done with function!")
                                return int(image_id), stream, release 

                            else: 
                                print("SONiC Software Version information NOT found!!")

                    except IOError as e:
                        return f"Error opening file '{file_path}': {e}"

        if found == False: 
            print(f'Leaf0.log type file not found for {topology}')

        
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def collect_result(curr_server, logs_path, topology, platform, run_label, run_desc): 
    print("Collecting result")
    # TODO
    #ports_config = get_ports_config()
    final_path = logs_path 

    with open(SERVER_CREDS_MAP) as server_creds:
        SERVER_CREDS_MAP_DICT = json.load(server_creds)

    host = curr_server
    if host not in SERVER_CREDS_MAP_DICT: 
        raise Exception("Do not have information for this particular host in mapping!")

    user = SERVER_CREDS_MAP_DICT[host]["user"]
    password = SERVER_CREDS_MAP_DICT[host]["password"]

    local_dest = "/var/www/html/logs/"

    final_path = pull_dir_via_sftp(host, user, password, logs_path, local_dest)
    
    if os.path.exists(final_path) == False: 
        raise Exception("Log Path is incorrect / Does not exist!!")
        rc, msg = cleanup()
        return None

    logs_path = final_path
     
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # TODO
    #client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    client.connect('10.28.109.58', port=22, username="sonic", password="roZes@123")

    ftp_client=client.open_sftp()
    spytest_results_files = ftp_client.listdir(str(logs_path))

    global test_start_time
    test_start_time = extract_test_start_time(spytest_results_files)
    exec_command_raise_error(client, f"cd {logs_path}; echo cisco123 | sudo -S chmod -R 644 tmp* | true")
    
    exec_command_raise_error(client, f"cd {logs_path}; tar -czvf spytest_result.tar.gz *")
    ftp_client.get(f"{logs_path}/spytest_result.tar.gz","./spytest_result.tar.gz")
    exec_command_raise_error(client, f"cd {logs_path}; rm spytest_result.tar.gz")

    os.system(f"mkdir spytest_result_{test_start_time}")
    os.system(f"tar -xvf spytest_result.tar.gz -C spytest_result_{test_start_time}")
    os.system(f"tar -czvf vxr.out.tar.gz vxr.out")

    #generate report files for pipeline
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    com_f = open(COMMON_REPORT_PATH, "w")
    tc_f = open(NEW_SUMMARY_REPORT_PATH, 'w')

    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "failure_reason": None,
            'build_start' : "", 'build_end' : "", "platform" : platform, "topology" : topology,
            "run_label" : run_label, "run_desc" : run_desc}
    tc_details = {}

    ret = 0 
    msg = ""

    image_id = 0
    stream = ""
    release = ""

    contains_pns = False
    try: 
        scale_json = open(f"./spytest_result_{test_start_time}/perf_and_scale.json", "r")
        scale_json.close()
        contains_pns = True
    except FileNotFoundError:
        contains_pns = False

    try:
        image_id, stream, release = open_leaf0_log_file(f"./spytest_result_{test_start_time}", topology) 

        time_log_file = open(f"./spytest_result_{test_start_time}/results_{test_start_time}_time.log", 'r')
        lines = time_log_file.readlines()
        time_log_file.close()

        first_line = lines[0].strip()
        last_line = lines[-1].strip()
        
        sum['build_start'] = first_line[:first_line.index(".")]
        sum['build_end'] = last_line[:last_line.index(".")]

        stats_txt_file = open(f"./spytest_result_{test_start_time}/results_{test_start_time}_stats.txt", 'r')
        stats_txt = stats_txt_file.readlines()
        stats_txt_file.close()

        sum['total'] = 0 
        sum['passed'] = 0
        sum['failed'] = 0
        sum['skipped'] = 0 

        i = 0 
        while i < len(stats_txt): 
            if "STATS" in stats_txt[i]:
                # Skip module configuration blocks
                #print(f"\n🟢 Found STATS block at line {i}: {stats_txt[i].strip()}")
                lookahead = "".join(stats_txt[i:i+5])
                if "Module Configuration" in lookahead:
                    print("Skipping Module Configuration block — moving to next STATS.\n")
                    i += 1 
                    # Move i forward until the next STATS block or end of file
                    while i < len(stats_txt) and "STATS" not in stats_txt[i]:
                        i += 1   
                
                if i >= len(stats_txt):
                    print("Reached EOF without finding new STATS BLOCK!")
                    break
                
                line = stats_txt[i]
                sum["total"] += 1
                case_summary = {}

                # parse module name
                parts = line.split(":")
                module = parts[1].strip() if len(parts) > 1 else "unknown"
                script_full_name = module
                script_name = os.path.basename(module)
                case_summary["test_script_full_name"] = script_full_name
                case_summary["test_script_name"] = script_name

                dir_name = os.path.dirname(module)
                test_category = os.path.split(dir_name)[1] if dir_name else "unknown"
                case_summary['test_category'] = test_category

                if len(parts) > 4:
                    case_summary['test_case_name'] = parts[-3] + '.' + parts[-1].split(' ')[0] 
                    case_summary['test_case_full_name'] = module.split(".py")[0].replace('/', '.') + "#" + parts[-3] + '.' + parts[-1].split(' ')[0] 
                else: 
                    case_summary['test_case_name'] = parts[-1].split(' ')[0] 
                    case_summary['test_case_full_name'] = module.split(".py")[0].replace('/', '.') + "#" + parts[-1].split(' ')[0]

                # find RESULT line robustly
                state = "Unknown"
                while i + 1 < len(stats_txt):
                    i += 1
                    if "RESULT" in stats_txt[i]:
                        parts = stats_txt[i].split("=")
                        if len(parts) > 1:
                            state = parts[1].strip()
                        break
                case_summary['state'] = state

                if "pass" in state.lower():
                    sum['passed'] += 1
                elif state.lower() in ["TGenFail", "ScriptError"] or "skip" in state.lower():
                    sum['skipped'] += 1
                else:
                    sum['failed'] += 1

                # find TECH SUPPORT line safely
                while i < len(stats_txt) and "TECH SUPPORT" not in stats_txt[i]:
                    i += 1
                if i < len(stats_txt) - 1:
                    i += 1
                
                # extract timestamps if present
                start_time = None
                end_time = None
                if i < len(stats_txt) and "," in stats_txt[i]:
                    start_time = stats_txt[i].split(",")[0]
                    j = i + 1
                    while j < len(stats_txt) and "====" not in stats_txt[j]:
                        j += 1
                    if j - 1 > i and "," in stats_txt[j - 1]:
                        end_time = stats_txt[j - 1].split(",")[0]

                case_summary['start_time'] = start_time
                case_summary['end_time'] = end_time

                if script_name not in tc_details:
                    tc_details[script_name] = {"SCRIPT_NAME": script_name, "TC_INFO": []}
                tc_details[script_name]['TC_INFO'].append(case_summary)

                while i < len(stats_txt) and "STATS" not in stats_txt[i]:
                    i += 1
            else:
                i += 1 # no STATS in this line, move forward

        if sum["total"] > sum["skipped"]: 
            sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2)
        elif sum["total"] == sum["skipped"]: 
            sum["success_rate"] = 0

        if sum["success_rate"] == 100:
            sum["status"] = SUCCESS_STATUS
        else:
            sum["status"] = FAILURE_STATUS
            sum["failure_reason"] = FAILURE_RESONS.TEST_CASES_FAILED 

    except Exception as e:
        msg = "Exception! Failed to open stats.txt file!"
        print(msg)
        sum["status"] = "failure"
        sum["failure_reason"] = FAILURE_RESONS.NO_REPORT_FILE
        ret = 1

    print(f"result summary is: {sum}")

    test_data = {'script_data': list(tc_details.values())}

    json.dump(sum, sum_f)
    json.dump(sum, com_f)
    json.dump(test_data, tc_f, indent=2)

    sum_f.close()
    com_f.close()
    tc_f.close()

    return ret, msg, sum, image_id, stream, release, contains_pns

def upload_result():
    print("Uploading result to server")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(LOG_SERVER_IP, username = LOG_SERVER_USERNAME, password = LOG_SERVER_PASSWORD)
    
    ftp_client=client.open_sftp()
    spytest_results_files = os.listdir(f"spytest_result_{test_start_time}")
    dest_path = f"{LOG_PATH}/spytest_result_{test_start_time}"
    http_path = f"{LOG_HTTP_PATH}/spytest_result_{test_start_time}"
    
    if os.path.exists(dest_path):
        raise Exception(f"Directory spytest_result_{test_start_time} already exists!!")
        return None 

    ftp_client.mkdir(dest_path)
    
    ftp_client.put(f"./spytest_result.tar.gz", f"{dest_path}/spytest_result.tar.gz")
    ftp_client.put(f"./vxr.out.tar.gz", f"{dest_path}/vxr.out.tar.gz")
    ftp_client.put(NEW_SUMMARY_REPORT_PATH, f"{dest_path}/{NEW_SUMMARY_REPORT_FILENAME}")
    exec_command_raise_error(client,f"cd {dest_path}; tar -xvf spytest_result.tar.gz")
    
    with open(SUMMARY_REPORT_PATH, "r") as f:
        sum = json.load(f)

    com_f = open(COMMON_REPORT_PATH, "w") 
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    
    sum["report_link"] = f"{http_path}/results_{test_start_time}_logs.log"
    sum["log_tarball_link"] = f"{http_path}/spytest_result.tar.gz"

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()
    ftp_client.put(SUMMARY_REPORT_PATH, f"{dest_path}/{SUMMARY_REPORT_FILENAME}")

    print(f"Successfully uploaded test result, url is: {sum['report_link']}")
    return 0, "", dest_path

def cleanup():
    os.system(f"rm -rf spytest_result_{test_start_time}")
    os.system(f"rm -rf spytest_result.tar.gz")
    os.system(f"rm -rf vxr.out.tar.gz")
    return 0, ""

def main(curr_server, topo_yaml, topology, platform, script_file, run_label, logs_path, run_desc=None, dev=False):

    global LOG_PATH , LOG_HTTP_PATH , LOG_SERVER_IP, test_start_time

    #### ERROR CHECKS 
    if run_label.strip() == "": 
        raise Exception("Please add run label for this run. It is a REQUIRED Parameter!")
        rc, msg = cleanup()
        return None
    elif logs_path[0] != "/":
        raise Exception("Please put a forward slash at the beginning of the logs path!")
        rc, msg = cleanup()
        return None
    ############

    if dev: 
        LOG_PATH += "_dev"
        LOG_HTTP_PATH += "_dev"

    try:
        if not logs_path:
            # if not logs_path provided then need to run script
            if not script_file:
                print("error! script_file not provided!")
                raise Exception("error! script_file not provided!")

            rc, msg = run_sanity(topology, platform, script_file)
            if rc != 0:
                print(f"error at run_sanity! msg: {msg}")
                raise Exception(msg)
            logs_path = RESULT_FOLDER_PATH

        rc, msg, result_sum, image_id, stream, release, contains_pns = collect_result(curr_server, logs_path, topology, platform, run_label, run_desc)
        if rc != 0:
            raise Exception(f"error at collect_result! msg: {msg}")

        rc, msg, dest_path = upload_result()
        print(f"IN MAIN ---- {dest_path}")
        if rc != 0:
            raise Exception(f"error at upload_result! msg: {msg}")
    
        if result_sum["status"] == FAILURE_STATUS:
            print(f"failures detected in run logs! Please check logs. Result summary: {result_sum}")

        print(f"run_spytest completed successfully : logs @ {LOG_SERVER_IP} : {LOG_PATH} :: spytest_result_{test_start_time}")
        print(f"DIR_PATH ======= {dest_path}")
        return dest_path, image_id, stream, release, contains_pns

    except Exception as e:
        print(f"An error occurred: {e.args}")
        raise
    finally:
        rc, msg = cleanup()

if __name__ == '__main__':

    """ 
    Uncomment these lines when running JUST this script!

    argparser = _create_parser()
    args = vars(argparser.parse_args())
    tar_ball = args['tar_ball']
    topo_yaml = args['topo_yaml']
    topology = args['topology']
    platform = args['platform']
    script_file = args['script_file']
    run_label = args['run_label']
    run_desc = args['run_desc']
    logs_path = args['logs_path']
    dev = False

    if args['dev']:
        dev = True
    """

    main(curr_server, topo_yaml, topology, platform, script_file, run_label, logs_path, run_desc, dev)
