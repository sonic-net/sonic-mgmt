import argparse
import datetime
import getpass
import json
import os
import re
import subprocess
import sys
import telnetlib
import threading
import time

import paramiko
import pexpect
import yaml
import csv
import uuid

import generate_spytest_html_report as html_report
from run_scripts_remote import handle_sim_failure, run_scripts_remote
# import access_pg_db

# Avoid hardcoded python exec through out and have in single place
PYTHON3 = "python3.8"

VXR_PORTS_FILENAME = "vxr_ports.yaml"
RESULT_FOLDER_PATH = "/home/vxr/sonic-test/sonic-mgmt/spytest/spytest_results"

SUMMARY_REPORT_FILENAME = "results.json"
NEW_SUMMARY_REPORT_FILENAME = "test_cases_info.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
TOPO_PLATFORM_FILE_MAP = "topo_and_platform_to_filename_map.json"
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
NEW_SUMMARY_REPORT_PATH = "../../{}".format(NEW_SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)
PARALLEL_LOG = "spytest_parallel.log"

sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : "sim_success"}

pattern = r"_mh"
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
        "leaf3": "SD5",
    }
else:
    TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING = {
        "spine0": "SD1",
        "spine1": "SD2",
        "leaf0": "SD3",
        "leaf1": "SD4",
        "leaf2": "SD5",
    }

device_ip_and_ports = []
failed_test_dict = {}
all_results = []
failure_sims = []
requeue_dict = {}

class SimThread(threading.Thread):
    def __init__(self, topo_yaml, topology, platform, tar_ball, sim_dir):
        super(SimThread, self).__init__()
        self.__sim_error = threading.Event()
        self.topo_yaml = topo_yaml
        self.topology = topology
        self.platform = platform
        self.tar_ball = tar_ball
        self.sim_dir = sim_dir
        self.sim_name = self.sim_dir.split("/")[-1]

    def stop(self):
        self.__sim_error.set()

    def stopped(self):
        return self.__sim_error.is_set()

    def run(self):
        while True:
            try:
                time.sleep(1)
                # Get a task from the queue

                if self.stopped():
                    print(f"Trying to execution test on {self.sim_name}, but it is in error state."
                          f" Retry in 30 secs")
                    time.sleep(30)
                    break
                task = task_queue.get(timeout=1)  # Timeout to exit if no task is available

                print(f"{self.sim_name}: is processing test execution of suit {task}")

                rc, msg = configure_vxr(self.topology, self.platform, self.tar_ball, task, self.sim_dir)
                if rc != 0:
                    print(f"error at configure_vxr! msg: {msg}")
                    sys.exit(rc)

                rc, msg = run_sanity(self.topology, self.platform, task, self.sim_dir)
                if rc != 0:
                    print(f"error at run_sanity! msg: {msg}")
                    sys.exit(rc)

                if sim_error_state(self.sim_dir):
                    print(f"Marking sim {self.sim_name} as not usable")
                    self.stop()
                # Mark task as done
                task_queue.task_done()
                print(f"sim {self.sim_name} has completed test execution of test: {task}")
            except queue.Empty:
                print(f"SIM {self.sim_name} found no task and is exiting.")
                break

def _add_simulator_tags(vxr_yaml_file, args):
    # Parse vxr yaml file
    if not (os.path.exists(vxr_yaml_file) and os.path.isfile(vxr_yaml_file)):
        return False
    with open(vxr_yaml_file, "r") as f:
        data = yaml.safe_load(f)

    if "sim_host" not in data["simulation"]:
        print(f"{args=}")
        if 'sim_host' not in args:
            return
        data["simulation"]['sim_host'] = args['sim_host']

    username = getpass.getuser()

    for item in range(1, args["num_of_threads"] + 1):
        filename = os.path.join("/nobackup", username, f"sim_{item}")
        nf = f"sim_{item}.yaml"
        new_data = data
        new_data["simulation"]["sim_dir"] = filename
        with open(nf, "w") as new_file:
            yaml.dump(new_data, new_file, sort_keys=False)

    return True


def _create_parser():
    parser = argparse.ArgumentParser(description="Reading ports file.")
    parser.add_argument(
        "-b", "--tar_ball", type=str, help="Specify tar ball location", required=False
    )
    parser.add_argument(
        "-f", "--topo_yaml", type=str, help="topo yaml file", required=False
    )
    parser.add_argument(
        "-t", "--topology", type=str, help="location of DUT in topo", required=False
    )
    parser.add_argument(
        "-p", "--platform", type=str, help="platform type of the DUT", required=False
    )
    parser.add_argument(
        "-s",
        "--script_file",
        type=str,
        help="Input test script file",
        required=False,
        default="reporting/suites/tortuga_parallel",
    )
    parser.add_argument(
        "-n",
        "--num_of_threads",
        type=int,
        help="Total number of simulators for parallel suite execution",
        required=False,
        default=4,
    )
    parser.add_argument(
        "-d",
        "--sim_host",
        type=str,
        help="hostname for sim creation",
        required=False,
    )

    return parser


def get_ports_config(port_file=VXR_PORTS_FILENAME):
    with open(port_file) as f:
        ports_config = yaml.load(f, Loader=yaml.FullLoader)

    return ports_config


def get_spirent_ip(sim_dir):
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    telnet_host = ports_config["spt"]["HostAgent"]
    telnet_port = ports_config["spt"]["serial0"]

    p = pexpect.spawn(f"telnet {telnet_host} {telnet_port}")
    p.sendline()
    p.expect("login")
    ret = str(p.before)
    ret = ret.split("STCv-")[1].split("/dev")[0].replace("-", ".")

    return ret.strip()


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


def find_devices(topo_file_str):
    regex = r"^([ ]{0}|[ ]{4}|\t)(\w+):"
    keys = re.findall(regex, topo_file_str, re.MULTILINE)

    is_device = False
    devices = []

    for i, reg_match in enumerate(keys):
        # got to devices key
        if reg_match[1] == "devices":
            is_device = True
            continue

        # reached end of devices list
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
    return (
        match.group(1)
        + curr_device["ip"]
        + match.group(2)
        + curr_device["port"]
        + match.group(3)
    )


def replace_device_ip_and_port(topo_file_str):
    regex = r"(\W+access:\s*\{.*?ip:\s*)\S+(,\s*port:\s*)\S+(}\n)"  # match 'access' portion of devices config
    data_replaced = re.sub(
        regex, replace_device_ip_and_port_helper, topo_file_str, flags=re.DOTALL
    )
    return data_replaced


def update_device_ip_and_ports(topo_file_str, sim_dir):
    global device_ip_and_ports
    devices = find_devices(topo_file_str)

    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    for device_name in devices:
        device_access_info = {}
        if "SD" in device_name:
            device_access_info["ip"] = ports_config[device_name]["HostAgent"]
            device_access_info["port"] = str(ports_config[device_name]["xr_redir22"])
        elif device_name in TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING:
            device_name_in_pyvxr_topo = TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING[
                device_name
            ]
            device_access_info["ip"] = ports_config[device_name_in_pyvxr_topo][
                "HostAgent"
            ]
            device_access_info["port"] = str(
                ports_config[device_name_in_pyvxr_topo]["xr_redir22"]
            )
        else:
            continue

        device_ip_and_ports.append(device_access_info)

    new_topo_file_str = replace_device_ip_and_port(topo_file_str)
    return new_topo_file_str


def update_topo_file(topology, platform, sim_dir):
    print("Updating topo file")
    topo_file = import_topo_file(topology, platform)

    if not topo_file:
        return -1, "error! topo_file does not exist in config file!"

    with open(topo_file, "r") as f:
        topo_file_str = f.read()

    topo_file_str = update_device_ip_and_ports(topo_file_str, sim_dir)

    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    spt_or_ixia = determine_spt_or_ixia(topology, platform)
    if spt_or_ixia == "spt":
        spt_ip = get_spirent_ip(sim_dir)
        regex = r"(\W+properties:\s*\{type: stc.*?ip:\s*)\S+(,.*?\n)"
        topo_file_str = re.sub(regex, rf"\1 {spt_ip}\2", topo_file_str)
        print(f"spirent ip is {spt_ip}")
        # topo_config["devices"]["spt"]["properties"]["ip"] = spt_ip
    elif spt_or_ixia == "ixia":
        ixia_chassis_mgmt_ip = ports_config["ixia_chassis"]["mgmt_ip"]
        ixia_gui_mgmt_ip = ports_config["ixia_gui"]["mgmt_ip"]
        regex = (
            r"(\W+properties:\s*\{type: ixia.*?ip:\s*)\S+(,\s*ix_server:\s*)\S+(}\n)"
        )
        topo_file_str = re.sub(
            regex, rf"\1 {ixia_chassis_mgmt_ip}\2 {ixia_gui_mgmt_ip}\3", topo_file_str
        )
        # topo_config["devices"]["T1"]["properties"]["ip"] = ixia_chassis_mgmt_ip
        # topo_config["devices"]["T1"]["properties"]["ix_server"] = ixia_gui_mgmt_ip
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"

    with open(topo_file, "w") as f:
        f.write(topo_file_str)

    # #BaseLoader does not preserve custom data types. add datatype '!include' back into topo file
    # os.system(f"sed -E -i 's/([^[:space:]]+.yaml)/!include \\1/' {topo_file}")

    return 0, ""


def send_topo_file_to_vxr(topology, platform, sim_dir):
    print("Uploading topo file to vxr sim")
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    topo_file = import_topo_file(topology, platform)
    print(f"{topo_file=}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )
    ftp_client = client.open_sftp()
    ftp_client.put(topo_file, "sonic-test/sonic-mgmt/spytest/topo")
    ftp_client.close()
    client.close()

    return 0, ""


def send_test_files_to_vxr(task, sim_dir):
    print("Sending test files to vxr")
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    ftp_client = client.open_sftp()
    ftp_client.put(f"{task}", f"sonic-test/sonic-mgmt/spytest/{task}")

    for root, subdirs, files in os.walk("../sonic-mgmt/spytest/templates"):
        exec_command_raise_error(client, f"mkdir -p sonic-test/sonic-mgmt/{root}")
        for file in files:
            ftp_client.put(f"{root}/{file}", f"sonic-test/sonic-mgmt/{root}/{file}")

    for root, subdirs, files in os.walk("../sonic-mgmt/spytest/tests"):
        exec_command_raise_error(client, f"mkdir -p sonic-test/sonic-mgmt/{root}")
        for file in files:
            ftp_client.put(f"{root}/{file}", f"sonic-test/sonic-mgmt/{root}/{file}")

    ftp_client.close()
    client.close()

    return 0, ""


def exec_command_raise_error(client, cmd):
    print(f"executing command: '{cmd}'")
    stdin, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print(
            f"Encountered error while executing '{cmd}', stdout: {stdout.readlines()}, stderr: {stderr.readlines()}"
        )
        raise Exception(stdout.channel.recv_exit_status(), stderr.readlines())

    return stdin, stdout, stderr


def configure_vxr_spt(topology, platform, tar_ball, sim_dir):
    print("Configure VXR with Spitfire")
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    try:
        tar_ball_name = tar_ball.split("/")[-1]
        # untar sonic-test golden-code
        exec_command_raise_error(client, f"wget -q {tar_ball}")
        exec_command_raise_error(client, f"tar -xvf {tar_ball_name}")

        # run sonic-mgmt docker
        exec_command_raise_error(
            client,
            "wget -q http://172.29.93.10/sonic-images/golden-code/docker-sonic-mgmt.gz",
        )
        exec_command_raise_error(client, "docker load < docker-sonic-mgmt.gz")
        exec_command_raise_error(
            client,
            "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'docker-sonic-mgmt' -itd docker-sonic-mgmt /bin/bash",
        )

        # install spirent related files
        exec_command_raise_error(
            client,
            "wget -q http://172.29.93.10/sonic-images/spirent_projects_folder.tar.gz",
        )
        exec_command_raise_error(
            client,
            "tar -xvf spirent_projects_folder.tar.gz -C sonic-test/sonic-mgmt/spytest",
        )

    except paramiko.SSHException as e:
        return -1, e
    except BaseException as e:
        return e.args[0], e.args[1]

    client.close()


def configure_vxr_ixia(topology, platform, tar_ball, sim_dir):
    print("Configure VXR with IXIA")
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    try:
        tar_ball_name = tar_ball.split("/")[-1]

        # untar sonic-test golden-code
        exec_command_raise_error(client, f"wget -q {tar_ball}")
        exec_command_raise_error(client, f"tar -xvf {tar_ball_name}")

        # run sonic-mgmt docker
        exec_command_raise_error(
            client,
            "wget -q http://172.29.93.10/sonic-images/spytest/keysight-u18070.tar",
        )
        exec_command_raise_error(client, "docker load -i keysight-u18070.tar")
        exec_command_raise_error(
            client,
            "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'ixia_sonic_mgmt' -itd spytest/keysight-u18:9.20.2201.70 /bin/bash",
        )

    except paramiko.SSHException as e:
        return -1, e
    except BaseException as e:
        return e.args[0], e.args[1]


def configure_vxr(topology, platform, tar_ball, task, sim_dir):
    print("Starting step: configure_vxr")
    rc, msg = send_test_files_to_vxr(task, sim_dir)
    if rc != 0:
        return rc, msg

    return 0, ""


def execute_command_on_chan(chan, command="", show_output=False, sim_name=None):
    print(f"executing command: {command}")
    termination_command = '\necho "Command Completed, exit code is: $?"\n'
    termination_str = "Command Completed, exit code is:"
    chan.send(command + termination_command)
    while True:
        resp = chan.recv(9999).decode("utf-8")
        if show_output:
            print("resp: ", resp)
        if termination_str in resp:
            # the termination command command will show up initially in resp, ignore
            if (
                resp.count(termination_str) == 1
                and "$?" in resp.split(termination_str)[1]
            ):
                continue
            exit_code = resp.split(termination_str)[1]
            print(f"Exit code for command {command} is: {exit_code}")
            break


def run_sanity(topology, platform, task, sim_dir):
    print("Starting step: run_sanity")
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    chan = client.invoke_shell()
    execute_command_on_chan(chan)

    spt_or_ixia = determine_spt_or_ixia(topology, platform)
    sim_name = sim_dir.split("/")[-1]

    if spt_or_ixia == "spt":
        cmd = "docker exec -it docker-sonic-mgmt /bin/bash\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "sudo su\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "cd /data; cp -r projects /; /data/bin/tools_install.sh; export SPIRENTD_LICENSE_FILE=10.22.181.32\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "mkdir spytest_results; chmod 777 spytest_results; cd spytest_results\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"env; /data/bin/spytest --testbed /data/topo --test-suite /data/{task}\n"
        execute_command_on_chan(chan, cmd, show_output=True, sim_name=sim_name)

    elif spt_or_ixia == "ixia":
        cmd = "docker exec -it ixia_sonic_mgmt bash\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "cd /data; pip install monotonic\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "unset https_proxy http_proxy\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "mkdir spytest_results; chmod 777 spytest_results; cd spytest_results\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"env; /data/bin/spytest --testbed /data/topo --test-suite /data/{task}\n"
        execute_command_on_chan(chan, cmd, show_output=True, sim_name=sim_name)
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"

    time.sleep(120)

    cmd = f"mv dashboard.html dashboard_{task}.html\n"
    execute_command_on_chan(chan, cmd, show_output=True)

    cmd = f"mv build.txt build_{task}.txt\n"
    execute_command_on_chan(chan, cmd, show_output=True)
    return 0, ""


def extract_test_start_time(spytest_results_files):
    test_start_time = []

    for file in spytest_results_files:
        if "summary.txt" in file:
            test_start_time.append("_".join(file.split("_")[1:-1]))

    return test_start_time

def task_failed_status(sim_dir, task):
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    ftp_client = client.open_sftp()
    spytest_results_files = ftp_client.listdir(RESULT_FOLDER_PATH)

    exec_command_raise_error(
        client,
        f"cd {RESULT_FOLDER_PATH}; echo cisco123 | sudo -S chmod -R 644 tmp* | true",
    )

    ftp_client.get(
        f"{RESULT_FOLDER_PATH}/build_{task}.txt",
        f"{sim_dir}/build_{task}.txt",
    )

    build_dict = {}
    global requeue_dict
    try:
        with open(f"{sim_dir}/build_{task}.txt", "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    key, value = line.split(':', 1)
                    build_dict[key.strip()] = value.strip()
                    if build_dict["Pass Rate"] != "100.00%":
                        if task in requeue_dict:
                            print(f"This tasked({task}) is already queued more than once")
                            return
                        requeue_dict[task] = sim_dir.split("/")[-1]
                        # Re-queue the task
                        task_queue.put(task)
                        print(f"Pass rate is not 100% for {task}, requeing")
    except FileNotFoundError:
        if task in requeue_dict:
            print(f"This tasked({task}) is already queued more than once")
            return
        requeue_dict[task] = sim_dir.split("/")[-1]
        # Re-queue the task
        task_queue.put(task)


def collect_result(sim_dir):
    global sum
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    ftp_client = client.open_sftp()
    spytest_results_files = ftp_client.listdir(RESULT_FOLDER_PATH)

    # Added to validate locally
    # Specify the directory path
    # from pathlib import Path
    # directory_path = Path(f'{sim_dir}/spytest_result')

    # Get the list of file names
    # spytest_results_files = [f.name for f in directory_path.iterdir() if f.is_file()]

    test_start_time = extract_test_start_time(spytest_results_files)

    exec_command_raise_error(
        client,
        f"cd {RESULT_FOLDER_PATH}; echo cisco123 | sudo -S chmod -R 644 tmp* | true",
    )

    exec_command_raise_error(
        client, f"cd {RESULT_FOLDER_PATH}; tar -czvf spytest_result.tar.gz *"
    )
    ftp_client.get(
        f"{RESULT_FOLDER_PATH}/spytest_result.tar.gz",
        f"{sim_dir}/spytest_result.tar.gz",
    )

    cmd = f"mkdir -p spytest_result"
    subprocess.run(
        [cmd], cwd=sim_dir, shell=True, capture_output=True, text=True, check=True
    )
    cmd = f"tar -xvf spytest_result.tar.gz -C spytest_result"
    subprocess.run(
        [cmd], cwd=sim_dir, shell=True, capture_output=True, text=True, check=True
    )
    cmd = f"tar -czvf vxr.out.tar.gz vxr.out"
    subprocess.run(
        [cmd], cwd=sim_dir, shell=True, capture_output=True, text=True, check=True
    )

    ret = 0
    try:
        summary = dict()
        for time in test_start_time:
            summary = {
                "SIM_ID": "sim_0",
                "TEST_SUITE": "test.txt",
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
                f"{sim_dir}/spytest_result/results_{time}_summary.txt", "r"
            )
            spytest_result_summary = spytest_result_summary_file.readlines()
            spytest_result_summary_file.close()

            # SPYTEST_SUITE_NAME_ARG
            export_file = open(
                f"{sim_dir}/spytest_result/results_{time}_export.txt", "r"
            )
            export_summary_data = export_file.readlines()
            export_file.close()
            for line in export_summary_data:
                if 'SPYTEST_SUITE_NAME_ARG' in line:
                    suite_name = line.split('/')[-1]
                    summary['TEST_SUITE'] = suite_name.strip()
                    #print(f"{summary['TEST_SUITE']=}")

            test_file = open(
                f"{sim_dir}/spytest_result/results_{time}_testcases.csv", "r"
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
                    sum["passed"] += int(value)
                elif key in [
                    "UNSUPPORTED",
                    "SCRIPTERROR",
                    "DEPFAIL",
                    "ENVFAIL",
                    "TIMEOUT",
                    "FAIL",
                ]:
                    summary["FAILED_TEST"] = int(value)
                    sum["failed"] += int(value)
                elif key == "SKIPPED":
                    summary["SKIPPED_TEST"] = int(value)
                    sum["skipped"] += int(value)
                elif key == "Test Count":
                    summary["TOTAL_TEST"] = int(value)
                    sum["total"] += int(value)
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

            summary['TC_INFO'] = []
            for row in test_file_cont:
                case_summary = dict()

                module = row["Module"]
                script_name = os.path.basename(row["Module"])
                test_script = os.path.basename(row["Module"])
                dir_name = os.path.dirname(row['Module'])
                test_category = os.path.split(dir_name)[1]
                case_summary['start_time'] = row['ExecutedOn']
                case_summary['test_case_name'] = row['TestCase']
                case_summary['state'] = row['Result']
                case_summary['test_case_full_name'] = module.split(".py")[0].replace('/', '.') + "#" + row['TestCase']
                case_summary['test_category'] = test_category
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

                summary['TC_INFO'].append(case_summary)


            failed_test_dict[tmp_sim].extend(failed_test_list)
            try:
                summary["SUCCESS_RATE"] = round(
                    summary["PASSED_TEST"]
                    / (summary["TOTAL_TEST"] - summary["SKIPPED_TEST"])
                    * 100,
                    2,
                )
                sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2)
            except ZeroDivisionError as e:
                print("Test script seems to have skipped")
                summary["SUCCESS_RATE"] = 0.00
                sum["success_rate"] = "0.00"

            log_report = f"dashboard_{summary['TEST_SUITE']}.html"
            summary['LOG_REPORT'] = log_report
            all_results.append(summary)

    except BaseException as e:
        print("Exception! Failed to open result file!", e.args)
        sum["status"] = "failure"
        ret = 1

    print(f"After SIM {{sim_dir}} cumulative result summary is: {sum}")

    return ret, ""


def cleanup(sim_dir):
    vxr_path = f"{PYTHON3} /auto/vxr/pyvxr/pyvxr-latest/vxr.py"
    subprocess.run(
        [f"{vxr_path} clean"],
        cwd=sim_dir,
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )

    return 0, ""


def import_pyvxr_yaml_file(topology, platform):
    print(f"get vxr config for topology: {topology}, platform: {platform}")

    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

    print(
        "Topo & platform to filename mapping dict: '{}'".format(TOPO_PLATFORM_FILE_DICT)
    )

    if topology in TOPO_PLATFORM_FILE_DICT:
        if platform in TOPO_PLATFORM_FILE_DICT[topology]:
            pyvxr_yaml_file = TOPO_PLATFORM_FILE_DICT[topology][platform]["pyvxr_yaml_file"]

    return pyvxr_yaml_file


def import_topo_file(topology, platform):
    print(f"get topo config for topology: {topology}, platform: {platform}")

    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

    topo_file = None
    if topology in TOPO_PLATFORM_FILE_DICT:
        if (
            platform in TOPO_PLATFORM_FILE_DICT[topology]
            and "topo_file" in TOPO_PLATFORM_FILE_DICT[topology][platform]
        ):
            topo_file = TOPO_PLATFORM_FILE_DICT[topology][platform]["topo_file"]

    return topo_file

def check_and_ftp_upload_run_cmd(client, ftp_client, local_file_name_f, remote_ftp_dir, remote_file_name_f, optional_cmd=None):
    # Check if the local file exists before attempting to upload it
    if os.path.exists(local_file_name_f):
        # Perform the FTP put operation
        ftp_client.put(local_file_name_f, f"{remote_ftp_dir}/{remote_file_name_f}")
        if optional_cmd is None:
            # nothing to be done in remote
            pass
        else:
            exec_command_raise_error(client, f"{optional_cmd}")
    else:
        # Handle the case where the file does not exist
        print(f"Warn: The local file '{local_file_name_f}' does not exist.")

def upload_result(unique_dir_name, sim_dir):
    print("Uploading result to server")
    sim_name = os.path.basename(sim_dir)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("sonic-ucs-m3-1", username="ringcicd", password="cicd_sonic")

    ftp_client = client.open_sftp()
    spytest_results_files = os.listdir(f"{sim_dir}/")
    ftp_dir = "/auto/vxr1/sonic-images/ringcicd"
    prefix_unique_dir_name = f"spytest_result_{unique_dir_name}"

    dir_list = ftp_client.listdir(ftp_dir)
    if not prefix_unique_dir_name in dir_list:
        ftp_client.mkdir(
            f"{ftp_dir}/{prefix_unique_dir_name}"
        )

    # SIM specific spytest result tar gz file
    # Define the local file path
    remote_exec_cmd = f"cd {ftp_dir}/{prefix_unique_dir_name}; tar -xvf spytest_result_{sim_name}.tar.gz"
    local_sim_spytest_result_tar_f = f"{sim_dir}/spytest_result.tar.gz"
    check_and_ftp_upload_run_cmd(client, ftp_client, local_sim_spytest_result_tar_f,
                                 f"{ftp_dir}/{prefix_unique_dir_name}/",
                                 f"spytest_result_{sim_name}.tar.gz",
                                 remote_exec_cmd)
    # SIM specific vxr.out file
    # Define the local file path
    local_sim_vxr_out_f = f"{sim_dir}/vxr.out.tar.gz"
    check_and_ftp_upload_run_cmd(client, ftp_client, local_sim_vxr_out_f,
                                 f"{ftp_dir}/{prefix_unique_dir_name}/",
                                 f"vxr.out_{sim_name}.tar.gz")

    report_file = 'test_execution_report.html'
    report_abs_path = os.path.abspath(report_file)
    check_and_ftp_upload_run_cmd(client, ftp_client, report_abs_path,
                                 f"{ftp_dir}/{prefix_unique_dir_name}/",
                                 report_file)

    '''
    parallel_log_file = os.path.basename(PARALLEL_LOG)
    if not os.path.exists(PARALLEL_LOG):
        parallel_log_file = None
    ftp_client.put(PARALLEL_LOG, f"{ftp_dir}/{prefix_unique_dir_name}/{parallel_log_file}")
    '''

    # upload the 'new_results.json' file too
    check_and_ftp_upload_run_cmd(client, ftp_client, NEW_SUMMARY_REPORT_PATH,
                                 f"{ftp_dir}/{prefix_unique_dir_name}/",
                                 NEW_SUMMARY_REPORT_FILENAME)

    return 0, ""


def start_vxrs(topo_yaml, topology, platform, tar_ball, sim_dir):
    print(f"{sim_dir}:Starting step: start_vxr")
    vxr_path = f"{PYTHON3} /auto/vxr/pyvxr/pyvxr-latest/vxr.py"

    result = subprocess.run(
        ["pwd"], cwd=sim_dir, capture_output=True, text=True, check=True
    )
    print(result.stdout)
    result = subprocess.run(
        ["ls"], cwd=sim_dir, capture_output=True, text=True, check=True
    )
    print(f"Op={result.stdout}")
    # clean if any topo if already exists
    # sim_output = subprocess.check_output(f'{vxr_path} clean', shell=True, cwd=sim_dir).strip()
    subprocess.run(
        [f"{vxr_path} clean"],
        cwd=sim_dir,
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )

    cmd = "bash -c '{} start {} |& tee sim_op.log'".format(vxr_path, topo_yaml)
    print(f"cmd: {cmd}")
    subprocess.run(
        [cmd], cwd=sim_dir, shell=True, capture_output=True, text=True, check=True
    )

    # Sim up
    sim_output = subprocess.check_output(
        "grep -i 'sim up' sim_op.log | wc -l", shell=True, cwd=sim_dir
    ).strip()
    print(f"SIM OUT={sim_output}")

    global failure_sims
    # Populate results file with failure data
    if not int(sim_output):
        failure_sims.append(sim_dir.split("/")[-1])
        return -1, "Sim is not up. Exiting now"

    time.sleep(300)

    cmd = f"{vxr_path} ports > {VXR_PORTS_FILENAME}"
    subprocess.run(
        [cmd], cwd=sim_dir, shell=True, capture_output=True, text=True, check=True
    )

    # Configure VXR with static files
    spt_or_ixia = determine_spt_or_ixia(topology, platform)

    if spt_or_ixia == "spt":
        configure_vxr_spt(topology, platform, tar_ball, sim_dir)
    elif spt_or_ixia == "ixia":
        configure_vxr_ixia(topology, platform, tar_ball, sim_dir)
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"

    rc, msg = update_topo_file(topology, platform, sim_dir)
    if rc != 0:
        return rc, msg
    rc, msg = send_topo_file_to_vxr(topology, platform, sim_dir)
    if rc != 0:
        return rc, msg

    return 0, ""


import queue

task_queue = queue.Queue()

def create_multiple_suit_file(suit_file):
    try:
        global task_queue
        with open(suit_file, "r") as f:
            lines = f.readlines()

        # Identify the split index for filenames and common arguments
        split_index = lines.index("#Runtime Arguments\n")

        # Extract filenames and common arguments
        filenames = [
            line.strip() for line in lines[:split_index] if line.startswith("+file:")
        ]
        common_args = lines[split_index:]

        # Create separate files for each filename
        for index, filename in enumerate(filenames, start=1):
            output_filename = f"file_{index}"
            with open(output_filename, "w") as out_file:
                out_file.write("# Modules\n")
                out_file.write(filename + "\n\n")
                out_file.writelines(common_args)
            print(f"Created file: {output_filename}")
            task_queue.put(output_filename)

    except FileNotFoundError:
        print(f"The source file '{suit_file}' does not exist.")
    except BaseException as e:
        print(f"An unexpected error occurred: {e}")

def sim_error_state(sim_dir,):
    ports_config = get_ports_config(f"{sim_dir}/vxr_ports.yaml")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ports_config["sonic_mgmt"]["HostAgent"],
        ports_config["sonic_mgmt"]["xr_redir22"],
        "vxr",
        "cisco123",
    )

    latest_time = 0
    latest_result_log = None
    sftp = client.open_sftp()
    sftp.chdir(RESULT_FOLDER_PATH)

    for fileattr in sftp.listdir_attr():
        if (fileattr.filename.endswith('logs.log') and fileattr.filename.startswith('results')
                and fileattr.st_mtime > latest_time):
            latest_time = fileattr.st_mtime
            latest_result_log = fileattr.filename

    if latest_result_log is None:
        return False

    remote_command = f"tail -n10 {RESULT_FOLDER_PATH}/{latest_result_log}"
    stdin, stdout, stderr = exec_command_raise_error(client, remote_command)
    last_lines = stdout.read().decode('utf-8')
    for line in last_lines.split("\n"):
        if "ERROR Failed to connect TGEN" in line:
            return True

    return False

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    tar_ball = args["tar_ball"]
    topo_yaml = args["topo_yaml"]
    topology = args["topology"]
    platform = args["platform"]
    script_file = args["script_file"]
    NUM_OF_SIM = args["num_of_threads"]

    # Get current timestamp and process id
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    process_id = os.getpid()

    # Create a unique name using timestamp, process id, and uuid
    unique_dir_name = f"{timestamp}_{process_id}_{uuid.uuid4().hex[:8]}"
    print(f"unique_dir_name: {unique_dir_name}")

    prefix_unique_dir_name = f"spytest_result_{unique_dir_name}"

    topo_yaml = import_pyvxr_yaml_file(topology, platform)
    cur_dir = os.getcwd()
    threads = []
    exec_threads = []

    # Create multiple vxr topo yaml files for each thread
    _add_simulator_tags(topo_yaml, args)

    # Create multiple suit files based on number of file we have in given suit file
    suit_file = f"../sonic-mgmt/spytest/{script_file}"
    create_multiple_suit_file(suit_file)

    # Stage 1: Spawn all vxr topologies
    for i in range(1, NUM_OF_SIM + 1):
        sim_dir = f"{cur_dir}/sim_{i}"
        sim_yaml = os.path.join(cur_dir, f"sim_{i}.yaml")
        if not os.path.exists(sim_yaml):
            print("Something is wrong")
            # sys.exit(0)
        os.makedirs(sim_dir, exist_ok=True)
        thread = threading.Thread(
            target=start_vxrs, args=(f"../{topo_yaml}", topology, platform, tar_ball, sim_dir)
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    #print("Sim's are UP!!!")

    #Stage 2: Run sanity on the topology spawned
    for i in range(1, NUM_OF_SIM+1):
        if f"sim_{i}" in failure_sims:
            continue
        sim_dir = f"{cur_dir}/sim_{i}"
        sim_yaml = os.path.join(cur_dir, f'sim_{i}.yaml')
        thread = SimThread(f"../{topo_yaml}", topology, platform, tar_ball, sim_dir)
        exec_threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in exec_threads:
        thread.join()

    print("Test runs are completed, collect logs")
    print("\nTest Result:")

    # Stage 3: Collect logs from all topology run
    sim_exception_count = 0
    for i in range(1, NUM_OF_SIM + 1):
        try:
            # Checking for ports file before collecting logs, in case sim never came up we will get exception
            get_ports_config(f"{sim_dir}/vxr_ports.yaml")
            sim_dir = f"{cur_dir}/sim_{i}"
            rc, msg = collect_result(sim_dir)
            if rc != 0:
                print(f"error at collect_result! msg: {msg}")
        except Exception:
            print(f"WARN: exception in SIM #{i}")
            sim_exception_count =+ 1
            continue

    if sim_exception_count == NUM_OF_SIM:
        print(f"None of the SIMs (NUM_OF_SIM:{NUM_OF_SIM}) came up; exiting")
        print(f"Waiting for logs check...")
        return

    test_data = {'script_data': all_results, 'failed_tc_data': failed_test_dict}
    with open(NEW_SUMMARY_REPORT_PATH, 'w') as file:
        json.dump(test_data, file, indent=2)

    print(f"{test_data}")
    parallel_log = os.path.basename(PARALLEL_LOG)
    html_report.generate_test_report(all_results, failed_test_dict, log=parallel_log)

    for i in range(1, NUM_OF_SIM + 1):
        sim_dir = f"{cur_dir}/sim_{i}"
        rc, msg = upload_result(unique_dir_name, sim_dir)
        if rc != 0:
            print(f"error at upload_result! msg: {msg}")

    for i in range(1, NUM_OF_SIM + 1):
        if f"sim_{i}" in failure_sims:
            continue
        sim_dir = f"{cur_dir}/sim_{i}"
        cleanup(sim_dir)

    # TODO:
    # store only sim_1 tarball for now; others needs to be added
    sum["log_tarball_link"] = f"http://172.29.93.10/sonic-images/ringcicd/{prefix_unique_dir_name}/spytest_result_sim_1.tar.gz"
    # store the test execution report html for easier access via results summary
    sum["report_link"] = f"http://172.29.93.10/sonic-images/ringcicd/{prefix_unique_dir_name}/test_execution_report.html"

    #generate report files for pipeline
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    com_f = open(COMMON_REPORT_PATH, "w")

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()

    '''
    ftp_dir = "/auto/vxr1/sonic-images/ringcicd"
    summary_file = os.path.basename(SUMMARY_REPORT_PATH)
    if os.path.exists(SUMMARY_REPORT_PATH):
        ftp_client.put(SUMMARY_REPORT_PATH, f"{ftp_dir}/{prefix_unique_dir_name}/{summary_file}")
    '''

    # commenting out build 18299 specific hardcoded update to grafana
    # access_pg_db.trigger(NEW_SUMMARY_REPORT_PATH, job_base_name=f"pipeline1_sanity_{unique_dir_name}", build_id=18299)
    url = f'url: http://172.29.93.10/sonic-images/ringcicd/spytest_result_{unique_dir_name}/test_execution_report.html'
    print(
        f"Successfully uploaded test result\n{url}"
    )

if __name__ == "__main__":
    main()

