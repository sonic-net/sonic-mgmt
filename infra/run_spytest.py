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
from run_scripts_remote import run_scripts_remote, handle_sim_failure


VXR_PORTS_FILENAME = "vxr_ports.yaml"
TOPO_FILE_PATH = "../spytest_tb_files/tortuga_spytest_topo_4d.yaml"
RESULT_FOLDER_PATH = "/home/vxr/sonic-test/sonic-mgmt/spytest/spytest_results"
test_start_time = ""

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-b', '--tar_ball', type=str, help='Specify tar ball location',
                      required=False)
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=False)
    parser.add_argument('-t', '--topology', type=str, help='location of DUT in topo',
                      required=False)
    parser.add_argument('-p', '--platform', type=str, help='platform type of the DUT',
                      required=False)
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='reporting/suites/tortuga')
    return parser

def start_vxr(topo_yaml):
    print("Starting step: start_vxr")
    vxr_path = "python3.8 /auto/vxr/pyvxr/pyvxr-latest/vxr.py"
    os.system("{} clean".format(vxr_path))

    os.system("bash -c '{} start {} |& tee sim_op.log'".format(vxr_path, topo_yaml))

    sim_output = subprocess.check_output("grep -i 'sim up' sim_op.log | wc -l", shell=True).strip()

    # Populate results file with failure data
    if not int(sim_output):
        return -1, "Sim is not up. Exiting now"

    os.system(f"{vxr_path} ports > {VXR_PORTS_FILENAME}")

    return 0, ""


def get_ports_config(port_file=VXR_PORTS_FILENAME):
    with open(port_file) as f:
        ports_config = yaml.load(f, Loader=yaml.FullLoader)
    
    return ports_config


def update_topo_file():
    print("Updating topo file")
    with open(TOPO_FILE_PATH, "r") as f:
        topo_file = yaml.load(f, Loader=yaml.BaseLoader)
    
    ports_config = get_ports_config()


    for device in topo_file["devices"].keys():
        if "SD" not in device:
            continue
        topo_file["devices"][device]["access"]["ip"] = ports_config[device]["HostAgent"]
        topo_file["devices"][device]["access"]["port"] = ports_config[device]["xr_redir22"]

    with open(TOPO_FILE_PATH, "w") as f:
        yaml.safe_dump(topo_file, f)

    #BaseLoader does not preserve custom data types. add datatype '!include' back into topo file
    os.system(f"sed -E -i 's/([^[:space:]]+.yaml)/!include \\1/' {TOPO_FILE_PATH}")

    return 0, ""

def send_topo_file_to_vxr():
    print("Uploading topo file to vxr sim")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=client.open_sftp()
    ftp_client.put(TOPO_FILE_PATH,'sonic-test/sonic-mgmt/spytest/topo')
    ftp_client.close()
    client.close()

    return 0, ""

def send_test_files_to_vxr(script_file):
    print("Sending test files to vxr")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")

    ftp_client=client.open_sftp()
    ftp_client.put(f"../sonic-mgmt/spytest/{script_file}", f"sonic-test/sonic-mgmt/spytest/{script_file}")
    with open(f"../sonic-mgmt/spytest/{script_file}", 'r') as f:
        for line in f.readlines():
            if "+file:" in line:
                _, test_file = line.split(":")
                test_file = test_file.strip()
                ftp_client.put(f"../sonic-mgmt/spytest/tests/{test_file}", f"sonic-test/sonic-mgmt/spytest/tests/{test_file}")

    ftp_client.close()
    client.close()

    return 0, ""

def exec_command_raise_error(client, cmd):
    print(f"executing command: '{cmd}'")
    stdin, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print(f"Encountered error while executing '{cmd}', stdout: {stdout.readlines()}, stderr: {stderr.readlines()}")
        raise Exception(stdout.channel.recv_exit_status(), stderr.readlines())

def configure_vxr(tar_ball, script_file):
    print("Starting step: configure_vxr")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")


    try:
        exec_command_raise_error(client, f"wget {tar_ball}")
        exec_command_raise_error(client, "tar -xvf golden_code_spytest.tar.gz")
        exec_command_raise_error(client, "wget http://172.29.93.10/sonic-images/golden-code/docker-sonic-mgmt.gz")
        exec_command_raise_error(client, "docker load < docker-sonic-mgmt.gz")
        exec_command_raise_error(client, "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'docker-sonic-mgmt' -itd docker-sonic-mgmt /bin/bash")
    except paramiko.SSHException as e:
        return -1, e
    except Exception as e:
        return e.args[0], e.args[1]
    
    client.close()

    rc, msg = update_topo_file()
    if rc != 0:
        return rc, msg
    rc, msg = send_topo_file_to_vxr()
    if rc != 0:
        return rc, msg
    
    rc,msg = send_test_files_to_vxr(script_file)
    if rc != 0:
        return rc, msg
    
    return 0, ""
        
def wait_for_command_complete(chan, temination_str=":~$ "):
    buff = ''
    while not buff.endswith(temination_str):
        resp = chan.recv(9999)
        buff += resp.decode('utf-8')
        #print("resp: ", buff)

def run_sanity(script_file): 
    print("Starting step: run_sanity")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")

    chan = client.invoke_shell()
    wait_for_command_complete(chan)

    chan.send(f"docker exec -it docker-sonic-mgmt /bin/bash\n")
    wait_for_command_complete(chan)

    chan.send(f"cd /data; sudo mkdir spytest_results; cd spytest_results\n")
    wait_for_command_complete(chan, ":/data/spytest_results$ ")

    chan.send(f"sudo /data/bin/spytest --testbed /data/topo --test-suite /data/{script_file}\n")
    wait_for_command_complete(chan, ":/data/spytest_results$ ")

    return 0, ""

def extract_test_start_time(spytest_results_files):
    for file in spytest_results_files:
        if "summary.txt" in file:
            return "_".join(file.split("_")[1:-1])

def collect_result(): 
    print("Collecting result")
    ports_config = get_ports_config()
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    
    ftp_client=client.open_sftp()
    spytest_results_files = ftp_client.listdir(RESULT_FOLDER_PATH)

    global test_start_time
    test_start_time = extract_test_start_time(spytest_results_files)

    os.system(f"mkdir spytest_result_{test_start_time}")
    
    for result_file in spytest_results_files:
        ftp_client.get(f"{RESULT_FOLDER_PATH}/{result_file}",f"./spytest_result_{test_start_time}/{result_file}")
    
    #generate report files for pipeline
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    com_f = open(COMMON_REPORT_PATH, "w") 

    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : "sim_success"}

    spytest_result_sum_file = open(f"./spytest_result_{test_start_time}/results_{test_start_time}_summary.txt", 'r')
    spytest_result_sum = spytest_result_sum_file.readlines()

    print(f"Result sum file contents: {spytest_result_sum}")

    for line in spytest_result_sum:
        if "=" not in line:
            continue

        key, value = line.split("=")
        key = key.strip()
        value = value.strip()

        if key == "PASS":
            sum["passed"] = int(value)
        elif key == "FAIL":
            sum["failed"] = int(value)
        elif key == "SKIPPED":
            sum["skipped"] = int(value)
        elif key == "Test Count":
            sum["total"] = int(value)
    
    sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2)


    print(f"result summary is: {sum}")

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()
    spytest_result_sum_file.close()


    return 0, ""

def upload_result():
    print("Uploading result to server")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("sonic-ucs-m3-1", username = "ringcicd", password = "cicd_sonic")
    
    ftp_client=client.open_sftp()
    spytest_results_files = os.listdir(f"spytest_result_{test_start_time}")
    ftp_client.mkdir(f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}")
    
    for result_file in spytest_results_files:
        ftp_client.put(f"./spytest_result_{test_start_time}/{result_file}", f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}/{result_file}")
    
    with open(SUMMARY_REPORT_PATH, "r") as f:
        sum = json.load(f)

    com_f = open(COMMON_REPORT_PATH, "w") 
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    
    sum["report_link"] = f"http://172.29.93.10/sonic-images/ringcicd/spytest_result_{test_start_time}/dashboard.html"

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()

    print(f"Successfully uploaded test result, url is: http://172.29.93.10/sonic-images/ringcicd/spytest_result_{test_start_time}/dashboard.html")
    return 0, ""

def cleanup():
    return 0, ""

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    tar_ball = args['tar_ball']
    topo_yaml = args['topo_yaml']
    topology = args['topology']
    platform = args['platform']
    script_file = args['script_file']

    print("using topo & platform to filename mapping in '{}'".format(TOPO_PLATFORM_FILE_MAP))
    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)
    
    print("Topo & platform to filename mapping dict: '{}'".format(TOPO_PLATFORM_FILE_DICT)) 

    #get topo_yaml from topology
    if not topo_yaml and topology in TOPO_PLATFORM_FILE_DICT:
        if platform in TOPO_PLATFORM_FILE_DICT[topology]:
            topo_yaml = TOPO_PLATFORM_FILE_DICT[topology][platform]


    rc, msg = start_vxr(topo_yaml)
    if rc != 0:
        print(f"error at start_vxr! msg: {msg}")
        sys.exit(rc)

    rc, msg = configure_vxr(tar_ball, script_file)
    if rc != 0:
        print(f"error at configure_vxr! msg: {msg}")
        sys.exit(rc)

    rc, msg = run_sanity(script_file)
    if rc != 0:
        print(f"error at run_sanity! msg: {msg}")
        sys.exit(rc)
    
    rc, msg = collect_result()
    if rc != 0:
        print(f"error at collect_result! msg: {msg}")
        sys.exit(rc)
    
    rc, msg = upload_result()
    if rc != 0:
        print(f"error at upload_result! msg: {msg}")
        sys.exit(rc)


if __name__ == '__main__':
  main()
