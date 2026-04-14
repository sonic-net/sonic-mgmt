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
from run_scripts_remote import SUCCESS_STATUS, FAILURE_STATUS, FAILURE_RESONS
import pexpect
import csv

VXR_PORTS_FILENAME = "vxr_ports.yaml"
DEFAULT_RESULT_FOLDER_PATH = "/home/vxr/sonic-test/sonic-mgmt/spytest/spytest_results"
RESULT_FOLDER_PATH = DEFAULT_RESULT_FOLDER_PATH
test_start_time = ""
HW_RUN_TIMESTAMP = ""

SUMMARY_REPORT_FILENAME = "results.json"
NEW_SUMMARY_REPORT_FILENAME = "test_cases_info.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
NEW_SUMMARY_REPORT_PATH = "../../{}".format(NEW_SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

pattern_mh = r'_mh'
pattern_dci = r'-dci'
is_mh = False
is_dci = False
for item in sys.argv:
    if re.search(pattern_mh, item):
        is_mh = True
    if re.search(pattern_dci, item):
        is_dci = True

if is_dci:
    # DCI 3DC 8D topology mapping
    TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING = {
        "DC1GW1": "SD1",
        "DC1GW2": "SD2",
        "DC2GW1": "SD3",
        "DC3GW1": "SD4",
        "Leaf1": "SD5",
        "Leaf2": "SD6",
        "Leaf3": "SD7",
        "Leaf4": "SD8"
    }
elif is_mh:
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

EXECUTION_MODE = 'vxr'  # 'vxr' or 'hw'
UCS_CONFIG = None  # For hw mode: {host, username, password}
HW_CFG_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "config", "hw_cfg.json")


def _load_hw_cfg():
    try:
        with open(HW_CFG_PATH, encoding="utf-8") as cfg_file:
            cfg_text = cfg_file.read().strip()
            return json.loads(cfg_text) if cfg_text else {}
    except Exception as exc:
        print("Failed to load hardware config from {}: {}".format(HW_CFG_PATH, exc))
        return {}

HW_CFG = _load_hw_cfg()


def _get_hw_testbed_defaults(test_bed):
    """Get testbed configuration from hw_cfg.json using test_bed name."""
    testbed_info = HW_CFG.get("testbed-info", {})
    if test_bed and test_bed in testbed_info:
        return testbed_info[test_bed]
    print("WARNING: No hardware defaults found for test_bed='{}' in {}".format(test_bed, HW_CFG_PATH))
    return {}

def _get_hw_testbed_spytest_docker(test_bed):
    """Get docker name from hw_cfg.json using SONIC_VERSION and test_bed name."""
    testbed_info = HW_CFG.get("testbed-info", {})
    if test_bed and test_bed in testbed_info:
        docker_name = testbed_info[test_bed].get(f"spytest_container_{UCS_CONFIG['sonic_version']}", "")
        if docker_name:
            return docker_name
    print("WARNING: No spytest docker found for test_bed='{}' in {}, using just SONIC_VERSION".format(test_bed, HW_CFG_PATH))
    return f"spytest-platform-hardening-{UCS_CONFIG['sonic_version']}"

def _get_hw_testbed_spytest_file_base(test_bed):
    """Get base file path for ftp and results usage from hw_cfg.json using SONIC_VERSION and test_bed name."""
    testbed_info = HW_CFG.get("testbed-info", {})
    if test_bed and test_bed in testbed_info:
        base_path = testbed_info[test_bed].get(f"spytest_file_base_{UCS_CONFIG['sonic_version']}", "")
        if base_path == "":
            pass
        else:
            return base_path
    print("WARNING: No spytest file base found for test_bed='{}' in {}, using just SONIC_VERSION".format(test_bed, HW_CFG_PATH))
    return f"{UCS_CONFIG['sonic_version']}"

def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-b', '--tar_ball', type=str, help='Specify tar ball location',
                      required=False)
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=False)
    parser.add_argument('-t', '--topology', type=str, help='location of DUT in topo',
                      required=False)
    parser.add_argument('-p', '--platform', type=str, help='platform hardware type (lightning, carib, etc.)',
                      required=False)
    parser.add_argument('--test_bed', type=str, 
                      help='testbed name for hw_cfg.json lookup (e.g., lightning-spytest-plat). Required for hw mode unless all UCS configs (--ucs_host, --ucs_username, --ucs_password) are provided',
                      required=False)
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='reporting/suites/tortuga')
    
    # Hardware mode support
    parser.add_argument('-m', '--mode', type=str, 
                      choices=['vxr', 'hw'],
                      default='vxr',
                      help='Test execution mode: vxr (default) or hw (hardware)')
    parser.add_argument('--ucs_host', type=str,
                      help='UCS host IP address (required for hw mode)',
                      required=False)
    parser.add_argument('--ucs_username', type=str,
                      help='UCS host username (default: sonic)',
                      required=False)
    parser.add_argument('--ucs_password', type=str,
                      help='UCS host password (or use UCS_PASSWORD env var for hw mode)',
                      required=False)
    parser.add_argument('--sonic_version', type=str,
                      help='SONiC version identifier used to select UCS resources (required for hw mode)',
                      required=False)

    return parser

def _validate_args(args):
    """Validate argument combinations and requirements."""
    if args.get('mode') == 'hw':
        test_bed = args.get('test_bed')
        
        # Check if UCS config needs to be loaded from hw_cfg.json
        if not all(args.get(k) for k in ('ucs_host', 'ucs_username', 'ucs_password')):
            if not test_bed:
                return False, "ERROR: --test_bed is required when UCS configs (--ucs_host, --ucs_username, --ucs_password) are not provided"
            defaults = _get_hw_testbed_defaults(test_bed)
            if defaults:
                if not args.get('ucs_host') and defaults.get('ucs_host'):
                    args['ucs_host'] = defaults['ucs_host']
                    print("Using UCS host '{}' from hw_cfg.json for testbed '{}'".format(defaults['ucs_host'], test_bed))
                if not args.get('ucs_username') and defaults.get('ucs_username'):
                    args['ucs_username'] = defaults['ucs_username']
                    print("Using UCS username from hw_cfg.json for testbed '{}'".format(test_bed))
                if not args.get('ucs_password') and defaults.get('ucs_password'):
                    args['ucs_password'] = defaults['ucs_password']
                    print("Using UCS password from hw_cfg.json for testbed '{}'".format(test_bed))

        # Hardware mode requires UCS configuration (either from args or from hw_cfg.json via test_bed)
        missing = []
        if not args.get('ucs_host'):
            missing.append('--ucs_host')
        if not args.get('ucs_username'):
            missing.append('--ucs_username')
        if not args.get('ucs_password'):
            missing.append('--ucs_password')
        if missing:
            return False, "ERROR: {} required when using hardware mode. Provide them directly or via --test_bed in hw_cfg.json".format(
                ", ".join(missing))

        if not args.get('sonic_version'):
            return False, "ERROR: --sonic_version is required when using hardware mode (-m hw)"

    return True, ""

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
    """Get ports config for VXR mode. Not used in HW mode."""
    if EXECUTION_MODE == 'hw':
        return {}  # HW mode doesn't need VXR ports
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

def update_topo_file(topology, platform):

    if EXECUTION_MODE == 'hw':
        print("Hardware mode detected; skipping topology modifications")
        return 0, ""

    print("Updating topo file")
    topo_file = import_topo_file(topology, platform)

    if not topo_file:
        return -1, "error! topo_file does not exist in config file!"
    
    with open(topo_file, "r") as f:
        topo_file_str = f.read()

    topo_file_str = update_device_ip_and_ports(topo_file_str)

    ports_config = get_ports_config()


    # for device in topo_config["devices"].keys():
    #     if "SD" in device:
    #         topo_config["devices"][device]["access"]["ip"] = ports_config[device]["HostAgent"]
    #         topo_config["devices"][device]["access"]["port"] = ports_config[device]["xr_redir22"]
    #     if device in TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING:
    #         device_name_in_pyvxr_topo = TOPO_DEVICE_NAME_TO_PYVXR_DEVICE_NAME_MAPPING[device]
    #         topo_config["devices"][device]["access"]["ip"] = ports_config[device_name_in_pyvxr_topo]["HostAgent"]
    #         topo_config["devices"][device]["access"]["port"] = ports_config[device_name_in_pyvxr_topo]["xr_redir22"]
    

    spt_or_ixia = determine_spt_or_ixia(topology, platform)

    if spt_or_ixia == "spt":
        spt_ip = get_spirent_ip()
        regex = r'(\W+properties:\s*\{type: stc.*?ip:\s*)\S+(,.*?\n)'
        topo_file_str = re.sub(regex, fr'\1 {spt_ip}\2', topo_file_str)
        print(f"spirent ip is {spt_ip}")
        # topo_config["devices"]["spt"]["properties"]["ip"] = spt_ip
    elif spt_or_ixia == 'ixia':
        ixia_chassis_mgmt_ip = ports_config["ixia_chassis"]["mgmt_ip"]
        ixia_gui_mgmt_ip = ports_config["ixia_gui"]["mgmt_ip"]
        regex = r'(\W+properties:\s*\{type: ixia.*?ip:\s*)\S+(,\s*ix_server:\s*)\S+(}\n)'
        topo_file_str = re.sub(regex, fr'\1 {ixia_chassis_mgmt_ip}\2 {ixia_gui_mgmt_ip}\3', topo_file_str)
        # topo_config["devices"]["T1"]["properties"]["ip"] = ixia_chassis_mgmt_ip
        # topo_config["devices"]["T1"]["properties"]["ix_server"] = ixia_gui_mgmt_ip
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"

        
    with open(topo_file, "w") as f:
        f.write(topo_file_str)

    # #BaseLoader does not preserve custom data types. add datatype '!include' back into topo file
    # os.system(f"sed -E -i 's/([^[:space:]]+.yaml)/!include \\1/' {topo_file}")

    return 0, ""

def send_topo_file_to_execution_host(topology, platform, test_bed=None):
    print("Uploading topo file to execution host")
    
    topo_file = import_topo_file(topology, platform)

    client = get_execution_host_ssh_client()
    ftp_client=client.open_sftp()
    if EXECUTION_MODE == 'hw':
        ftp_client.put(topo_file, f"{_get_hw_testbed_spytest_file_base(test_bed)}/sonic-test/sonic-mgmt/spytest/topo")
    else:
        ftp_client.put(topo_file,'sonic-test/sonic-mgmt/spytest/topo')
    ftp_client.close()
    client.close()

    return 0, ""

def send_test_files_to_execution_host(script_file, test_bed=None):
    print("Sending test files to execution host")
    
    client = get_execution_host_ssh_client()
    ftp_client = None

    try:
        ftp_client = client.open_sftp()
        if EXECUTION_MODE == 'hw':
            ftp_client.put(
                f"../sonic-mgmt/spytest/{script_file}",
                f"{_get_hw_testbed_spytest_file_base(test_bed)}/sonic-test/sonic-mgmt/spytest/{script_file}"
            )
        else:
            ftp_client.put(
                f"../sonic-mgmt/spytest/{script_file}",
                f"sonic-test/sonic-mgmt/spytest/{script_file}"
            )

            for root, subdirs, files in os.walk("../sonic-mgmt/spytest/templates"):
                exec_command_raise_error(client, f"mkdir -p sonic-test/sonic-mgmt/{root}")
                for file in files:
                    ftp_client.put(f"{root}/{file}", f"sonic-test/sonic-mgmt/{root}/{file}")

            for root, subdirs, files in os.walk("../sonic-mgmt/spytest/tests"):
                exec_command_raise_error(client, f"mkdir -p sonic-test/sonic-mgmt/{root}")
                for file in files:
                    ftp_client.put(f"{root}/{file}", f"sonic-test/sonic-mgmt/{root}/{file}")
    finally:
        if ftp_client:
            try:
                ftp_client.close()
            except Exception:
                pass
        client.close()

    return 0, ""

def exec_command_raise_error(client, cmd):
    print(f"executing command: '{cmd}'")
    stdin, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print(f"Encountered error while executing '{cmd}', stdout: {stdout.readlines()}, stderr: {stderr.readlines()}")
        raise Exception(stdout.channel.recv_exit_status(), stderr.readlines())

    return stdin, stdout, stderr

def get_execution_host_ssh_client():
    """
    Get SSH client to execution host.
    VXR mode: connects to VXR management node
    HW mode: connects to UCS host
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    if EXECUTION_MODE == 'hw':
        # Connect to UCS for hardware mode
        client.connect(
            hostname=UCS_CONFIG['host'],
            username=UCS_CONFIG['username'],
            password=UCS_CONFIG['password']
        )
        print(f"Connected to UCS host: {UCS_CONFIG['host']}")
    else:
        # Connect to VXR management node for VXR mode
        ports_config = get_ports_config()
        client.connect(
            ports_config['sonic_mgmt']['HostAgent'],
            ports_config['sonic_mgmt']['xr_redir22'],
            "vxr",
            "cisco123"
        )
        print(f"Connected to VXR management node: {ports_config['sonic_mgmt']['HostAgent']}")
    
    return client

def configure_vxr_spt(topology, platform, tar_ball, script_file):
    print("Configure VXR with Spitfire")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")


    try:
        tar_ball_name = tar_ball.split("/")[-1]
        #untar sonic-test golden-code
        exec_command_raise_error(client, f"wget -q {tar_ball}")
        exec_command_raise_error(client, f"tar -xvf {tar_ball_name}")

        #run sonic-mgmt docker
        exec_command_raise_error(client, "wget -q http://172.29.93.10/sonic-images/golden-code/docker-sonic-mgmt.gz")
        exec_command_raise_error(client, "docker load < docker-sonic-mgmt.gz")
        exec_command_raise_error(client, "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'docker-sonic-mgmt' -itd docker-sonic-mgmt /bin/bash")

        #install spirent related files
        exec_command_raise_error(client, "wget -q http://172.29.93.10/sonic-images/spirent_projects_folder.tar.gz")
        exec_command_raise_error(client, "tar -xvf spirent_projects_folder.tar.gz -C sonic-test/sonic-mgmt/spytest")

    except paramiko.SSHException as e:
        return -1, e
    except Exception as e:
        return e.args[0], e.args[1]
    
    client.close()

def configure_vxr_ixia(topology, platform, tar_ball, script_file):
    print("Configure VXR with IXIA")
    ports_config = get_ports_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ports_config['sonic_mgmt']['HostAgent'], ports_config['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")

    try:
        tar_ball_name = tar_ball.split("/")[-1]

        #untar sonic-test golden-code
        exec_command_raise_error(client, f"wget -q {tar_ball}")
        exec_command_raise_error(client, f"tar -xvf {tar_ball_name}")

        # run sonic-mgmt docker - use different image based on DCI flag
        if is_dci:
            exec_command_raise_error(
                client,
                "wget -q http://10.29.158.43/builds/keysight-u18070-10-0.tar",
            )
            exec_command_raise_error(client, "docker load -i keysight-u18070-10-0.tar")
            exec_command_raise_error(
                client,
                "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'ixia_sonic_mgmt' -itd spytest/keysight-u18:10.00 /bin/bash",
            )
        else:
            exec_command_raise_error(client, "wget -q http://172.29.93.10/sonic-images/spytest/keysight-u18070.tar")
            exec_command_raise_error(client, "docker load -i keysight-u18070.tar")
            exec_command_raise_error(client, "cd sonic-test/sonic-mgmt/spytest; docker run -v $PWD:/data --name 'ixia_sonic_mgmt' -itd spytest/keysight-u18:9.20.2201.70 /bin/bash")

    except paramiko.SSHException as e:
        return -1, e
    except Exception as e:
        return e.args[0], e.args[1]

def configure_vxr(topology, platform, tar_ball, script_file):
    print("Starting step: configure_vxr")
    spt_or_ixia = determine_spt_or_ixia(topology, platform)

    if spt_or_ixia == "spt":
        configure_vxr_spt(topology, platform, tar_ball, script_file)
    elif spt_or_ixia == "ixia":
        configure_vxr_ixia(topology, platform, tar_ball, script_file)
    else:
        return -1, "ERROR! Could not find ixia or spt in pyvxr yaml file!"
    
    rc, msg = update_topo_file(topology, platform)
    if rc != 0:
        return rc, msg
    rc, msg = send_topo_file_to_execution_host(topology, platform)
    if rc != 0:
        return rc, msg
    
    rc, msg = send_test_files_to_execution_host(script_file)
    if rc != 0:
        return rc, msg
    
    return 0, ""
        
def execute_command_on_chan(chan, command='', show_output=False):
    print(f"executing command: {command}")
    termination_command = "\necho \"Command Completed, exit code is: $?\"\n"
    termination_str = "Command Completed, exit code is:"
    chan.send(command+termination_command)
    start_time = time.time()
    chan_timeout = 60 * 60 * 16  # 16 hours timeout for command execution
    while True:
        resp = chan.recv(9999).decode('utf-8')
        if show_output and resp:
            print(f"resp: '{resp}'")

        if termination_str in resp:
            #the termination command command will show up initially in resp, ignore
            if resp.count(termination_str) == 1 and "$?" in resp.split(termination_str)[1]:
                continue
            exit_code = resp.split(termination_str)[1]
            print(f"Exit code for command {command} is: {exit_code}")
            break
        
        if time.time() - start_time > chan_timeout:
            raise Exception(f"Timeout of {chan_timeout} seconds while waiting for command '{command}' to complete")

        time.sleep(2)

def run_sanity(topology, platform, script_file, test_bed=None): 
    print("Starting step: run_sanity")

    client = get_execution_host_ssh_client()
    chan = client.invoke_shell()
    execute_command_on_chan(chan)

    if EXECUTION_MODE == 'hw':
        # Hardware mode execution
        container_name = _get_hw_testbed_spytest_docker(test_bed)
        print(f"Using spytest container: {container_name}")

        global HW_RUN_TIMESTAMP, RESULT_FOLDER_PATH
        if not HW_RUN_TIMESTAMP:
            HW_RUN_TIMESTAMP = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S-%f")

        base_result_dir = f"{_get_hw_testbed_spytest_file_base(test_bed)}/sonic-test/sonic-mgmt/spytest/spytest_results"
        # Use test_bed if available, otherwise fallback to platform for folder naming
        testbed_identifier = test_bed if test_bed else platform
        run_results_subdir = f"{HW_RUN_TIMESTAMP}_{testbed_identifier}_{topology}"
        RESULT_FOLDER_PATH = os.path.join(base_result_dir, run_results_subdir)

        cmd = f"docker exec -it {container_name} bash\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"cd /data; mkdir -p spytest_results/{run_results_subdir}; " \
              f"chmod 777 spytest_results; chmod 777 spytest_results/{run_results_subdir}\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = "env; ./bin/spytest --testbed /data/topo " \
              f"--logs-path spytest_results/{run_results_subdir} --test-suite /data/{script_file}\n"
        execute_command_on_chan(chan, cmd, show_output=True)

        cmd = f"echo 'Updating permissions of results file to ensure availability.'; cd /data/spytest_results/{run_results_subdir}; chmod -R 644 *\n"
        execute_command_on_chan(chan, cmd, show_output=True)

    else:
        # VXR/sim mode execution
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

            # Install additional packages for DCI if DCI topology is detected
            if is_dci:
                cmd = "pip install retry\n"
                execute_command_on_chan(chan, cmd, show_output=True)

                cmd = "pip install pyopenssl --upgrade\n"
                execute_command_on_chan(chan, cmd, show_output=True)

                cmd = "pip install urllib3 --upgrade\n"
                execute_command_on_chan(chan, cmd, show_output=True)

                cmd = "pip install --upgrade ixnetwork-restpy==1.5.0\n"
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
        if "summary.txt" in file:
            return "_".join(file.split("_")[1:-1])

def collect_result(): 
    print("Collecting result")
    
    client = get_execution_host_ssh_client()
    
    ftp_client=client.open_sftp()
    spytest_results_files = ftp_client.listdir(RESULT_FOLDER_PATH)

    global test_start_time
    test_start_time = extract_test_start_time(spytest_results_files)

    exec_command_raise_error(client, f"cd {RESULT_FOLDER_PATH}; echo cisco123 | sudo -S chmod -R 644 tmp* | true")
    
    exec_command_raise_error(client, f"cd {RESULT_FOLDER_PATH}; tar -czvf spytest_result.tar.gz *")
    ftp_client.get(f"{RESULT_FOLDER_PATH}/spytest_result.tar.gz","./spytest_result.tar.gz")


    os.system(f"mkdir spytest_result_{test_start_time}")
    os.system(f"tar -xvf spytest_result.tar.gz -C spytest_result_{test_start_time}")
    if EXECUTION_MODE != 'hw':
        os.system(f"tar -czvf vxr.out.tar.gz vxr.out")

    #generate report files for pipeline
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    com_f = open(COMMON_REPORT_PATH, "w")
    tc_f = open(NEW_SUMMARY_REPORT_PATH, 'w')

    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "failure_reason": None}
    tc_details = {}

    ret = 0 
    try:
        spytest_result_sum_file = open(f"./spytest_result_{test_start_time}/results_{test_start_time}_summary.txt", 'r')
        spytest_result_sum = spytest_result_sum_file.readlines()
        spytest_result_sum_file.close()

        test_file = open(
            f"./spytest_result_{test_start_time}/results_{test_start_time}_testcases.csv", "r"
        )
        test_file_cont = csv.DictReader(test_file, skipinitialspace=True)

        print(f"Result sum file contents: {spytest_result_sum}")

        for line in spytest_result_sum:
            if "=" not in line:
                continue

            key, value = line.split("=")
            key = key.strip()
            value = value.strip()

            if key == "PASS":
                sum["passed"] = int(value)
            elif key in ["DUTFAIL", "CONFIGFAIL", "CMDFAIL", "TOPOFAIL", "TGENFAIL", "SCRIPTERROR", "DEPFAIL", "ENVFAIL", "TIMEOUT", "FAIL"]:
                sum["failed"] += int(value)
            elif key in ["UNSUPPORTED", "SKIPPED"]:
                sum["skipped"] += int(value)
            elif key == "Test Count":
                sum["total"] = int(value)

        for row in test_file_cont:
            case_summary = dict()
            module = row["Module"]
            script_name = os.path.basename(row["Module"])
            test_script = os.path.basename(row["Module"])
            # print(f'{test_script=}')
            dir_name = os.path.dirname(row['Module'])
            test_category = os.path.split(dir_name)[1]
            case_summary['start_time'] = row['ExecutedOn']
            case_summary['test_case_name'] = row['TestCase']
            case_summary['state'] = row['Result']
            case_summary['test_case_full_name'] = module.split(".py")[0].replace('/', '.') + "#" + row['TestCase']
            case_summary['test_category'] = test_category

            script_name = os.path.basename(script_name)
            if script_name not in tc_details:
                tc_details[script_name] =  {
                    "SCRIPT_NAME": script_name,
                    'TC_INFO': []
                }
            tc_details[script_name]['TC_INFO'].append(case_summary)

        sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2)

        if sum["success_rate"] == 100:
            sum["status"] = SUCCESS_STATUS
        else:
            sum["status"] = FAILURE_STATUS
            sum["failure_reason"] = FAILURE_RESONS.TEST_CASES_FAILED

    except Exception as e:
        print("Exception! Failed to open result file!")
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

    return ret, "", sum

def upload_result():
    print("Uploading result to server")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("sonic-ucs-m3-1", username = "ringcicd", password = "cicd_sonic")
    
    ftp_client=client.open_sftp()
    spytest_results_files = os.listdir(f"spytest_result_{test_start_time}")
    ftp_client.mkdir(f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}")
    
    ftp_client.put(f"./spytest_result.tar.gz", f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}/spytest_result.tar.gz")
    if EXECUTION_MODE != 'hw':
        ftp_client.put(f"./vxr.out.tar.gz", f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}/vxr.out.tar.gz")
    ftp_client.put(NEW_SUMMARY_REPORT_PATH, f"/auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}/{NEW_SUMMARY_REPORT_FILENAME}")
    exec_command_raise_error(client,f"cd /auto/vxr1/sonic-images/ringcicd/spytest_result_{test_start_time}; tar -xvf spytest_result.tar.gz")
    
    with open(SUMMARY_REPORT_PATH, "r") as f:
        sum = json.load(f)

    com_f = open(COMMON_REPORT_PATH, "w") 
    sum_f = open(SUMMARY_REPORT_PATH, "w")
    
    sum["report_link"] = f"http://172.29.93.10/sonic-images/ringcicd/spytest_result_{test_start_time}/dashboard.html"
    sum["log_tarball_link"] = f"http://172.29.93.10/sonic-images/ringcicd/spytest_result_{test_start_time}"

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()

    print(f"Successfully uploaded test result, url is: http://172.29.93.10/sonic-images/ringcicd/spytest_result_{test_start_time}/dashboard.html")
    return 0, ""

def cleanup():
    return 0, ""

def import_pyvxr_yaml_file(topology, platform):
    print(f"get vxr config for topology: {topology}, platform: {platform}")
    
    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

    print("Topo & platform to filename mapping dict: '{}'".format(TOPO_PLATFORM_FILE_DICT)) 

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
        if platform in TOPO_PLATFORM_FILE_DICT[topology] and "topo_file" in TOPO_PLATFORM_FILE_DICT[topology][platform]:
            topo_file = TOPO_PLATFORM_FILE_DICT[topology][platform]["topo_file"]
    
    return topo_file

def main():
    global EXECUTION_MODE, UCS_CONFIG, RESULT_FOLDER_PATH, HW_RUN_TIMESTAMP
    RESULT_FOLDER_PATH = DEFAULT_RESULT_FOLDER_PATH
    HW_RUN_TIMESTAMP = ""

    argparser = _create_parser()
    args = vars(argparser.parse_args())

    # Validate argument combinations
    valid_args, validation_error = _validate_args(args)
    if not valid_args:
        print(validation_error)
        sys.exit(1)
    tar_ball = args['tar_ball']
    topo_yaml = args['topo_yaml']
    topology = args['topology']
    platform = args['platform']
    test_bed = args.get('test_bed')
    script_file = args['script_file']
    
    # Determine execution mode
    EXECUTION_MODE = args.get('mode', 'vxr')
    
    if EXECUTION_MODE == 'hw':
        # Hardware mode: set up UCS connection
        print("="*60)
        print("HARDWARE MODE - Execution on UCS host")
        print("="*60)
        
        UCS_CONFIG = {
            'host': args['ucs_host'],
            'username': args.get('ucs_username', 'sonic'),
            'password': args['ucs_password'],
            'sonic_version': (args['sonic_version'])
        }

        print(f"UCS Host: {UCS_CONFIG['host']}")
        print(f"UCS Username: {UCS_CONFIG['username']}")
        print(f"SONiC Version for Test: {UCS_CONFIG['sonic_version']}")
        print("Note: Topo file is NOT dynamically modified, topo file is assumed setup correctly")
        print("="*60)

        rc, msg = send_topo_file_to_execution_host(topology, platform, test_bed)
        if rc != 0:
            print(f"error at send_topo_file_to_execution_host! msg: {msg}")
            sys.exit(rc)

        rc, msg = send_test_files_to_execution_host(script_file, test_bed)
        if rc != 0:
            print(f"error at send_test_files_to_execution_host! msg: {msg}")
            sys.exit(rc)

    else:
        # VXR mode: normal flow
        print("="*60)
        print("VXR SIMULATION MODE")
        print("="*60)
        topo_yaml = import_pyvxr_yaml_file(topology, platform)
        
        rc, msg = start_vxr(topo_yaml)
        if rc != 0:
            print(f"error at start_vxr! msg: {msg}")
            sys.exit(rc)
        
        rc, msg = configure_vxr(topology, platform, tar_ball, script_file)
        if rc != 0:
            print(f"error at configure_vxr! msg: {msg}")
            sys.exit(rc)
    
    # Common execution path between HW and VXR-sim
    rc, msg = run_sanity(topology, platform, script_file, test_bed=test_bed)
    if rc != 0:
        print(f"error at run_sanity! msg: {msg}")
        sys.exit(rc)
    
    rc, msg, result_sum = collect_result()
    if rc != 0:
        print(f"error at collect_result! msg: {msg}")
    
    rc, msg = upload_result()
    if rc != 0:
        print(f"error at upload_result! msg: {msg}")
        sys.exit(rc)
    
    if result_sum["status"] == FAILURE_STATUS:
        print(f"some failure detected! Please check logs. Result summary: {result_sum}")
        sys.exit(1)
    
    sys.exit(rc)


if __name__ == '__main__':
  main()
