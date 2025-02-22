#!/router/bin/python3.8.2_mcpre-v1

# Creates the t1 topology using vxr.py
# Create admin user in vEOS vm
# Create testbed file based on vxr_ports
# Upload t1 specific files to sonic mgmt container
# Change DUT password and set mgmt ip address
# Start docker container, deploy DUT minigraph
# Replace DUT Mgmt Address
# Reload DUT config
# Add vEOS config
#
# Usage: ./create_sonic_t1_ads.py -t sonic_t1_topo.yaml -c
# -t Topology file for PyVxr
# -c Clean pre-existing sim
#
# After the script is run – you can log into the sonic dut (admin/cisco123 – I change the password to cisco123) and check for bgp summary – both v4 and v6.
#

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
from jinja2 import Environment, FileSystemLoader
import re
from run_scripts_remote import run_scripts_remote, handle_sim_failure

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

# Return a list of device names beginning with "sonic_dut_", for use with the data[] dictionary
# For example: ['sonic_dut_1', 'sonic_dut_2']
def get_dut_names(data):
    return [key for key in data if key.startswith('sonic_dut')]

# Converts a DUT device name from a VXR topology into the proper non-VXR topology name
# For example:
#   - Use legacy "platform-01" format for older VXR toplogies with just a single DUT
#       ('sonic_dut',   'sherman')  -> 'sherman-01'
#
#   - For VXR topologies with multiple DUT, use 0-indexed single digit
#       ('sonic_dut_0', 'mathilda') -> 'mathilda-0'
#       ('sonic_dut_0', 'crocodile') -> 'crocodile-0'
#       ('sonic_dut_1', 'sherman')  -> 'sherman-1'
def get_tdata_dut_name(vxr_dut_name, dut_platform):
    assert vxr_dut_name.startswith('sonic_dut')

    if vxr_dut_name == 'sonic_dut':
        return "{}-01".format(dut_platform)
    else:
        dut_id = vxr_dut_name.split('_')[-1]
        return "{}-{}".format(dut_platform, dut_id)


def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-i', '--input_file', type=str, help='Input port file',
                      required=False,default=None)
    parser.add_argument('-b', '--tar_ball', type=str, help='Specify tar ball location',
                      required=False,default="http://172.29.93.10/sonic-images/golden-code/golden_code_202012.tar.gz")
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=False,default=None)
    parser.add_argument('-t', '--topo_type', type=str, help='topo type',
                      required=False,default='sol-tb-l2vni', choices=['sol-tb-l2vni', 'sol-tb-l3vni', 'tortuga-controller', 'tortuga-controller-2x2', 'tortuga-controller-2x3', 'tortuga-controller-carib-1x3'])
    parser.add_argument('-g', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
    parser.add_argument('-p', '--dut_passwd', type=str, help='Dut password, when it is different from YourPaSsWoRd',
                      required=False,default="cisco123")
    parser.add_argument('-u', '--dut_uname', type=str, help='Dut username, when it is different from admin',
                      required=False,default="cisco")
    parser.add_argument('-c', '--clean_sim', action='store_true', help='Clean simulation',
                      default=False)
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32, crocodile, sfd, churchill-mono, carib',
                      required=False,default="mth64", choices=['sherman', 'mth32', 'mth64', 'crocodile', 'sfd', 'churchill-mono','carib'])
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='sanity-scripts/sanity_scripts.txt')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default='DT')
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default='DT')
    parser.add_argument('-r', '--run_sanity', action='store_true', help='Run Sanity',
                      default=False),
    parser.add_argument('--additional_tests', type=str, help='Additional Testscases to test',
                      required=False, default='')
    parser.add_argument('--cicd', action='store_true', help='Use CICD related parameters',
                      default=False)
    parser.add_argument('--cicd_clean', action='store_true', help='Clean at the end of CICD run',
                      default=False)
    parser.add_argument('--create_allure_report', action='store_true', help='When testing, specify if allure report to be created at the end of test',
                      default=False)
    parser.add_argument('-k', '--skip_sanity', action='store_true', help='Skip sanity test',
                      default=False)
    parser.add_argument('--sim_attach', action='store_true', help='Use the existing SIM',
                      default=False)
    parser.add_argument('--fabric_name', type=str, help='Fabric Name should match the name that is part of your tortuga controller yaml name - it should match your hostname',
                      required=False,default="kindly-1x3")
    return parser

def repo_update(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    chan = ssh.invoke_shell()
    buff = ''

    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("ls \n")
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    if 'golden-code' in buff:
        chan.send("rm -rf golden-code\n")
        buff = ''
        while not buff.endswith(':~$ '):
            resp = chan.recv(9999)
            buff += resp.decode("ascii")
            print(resp.decode("ascii"))
        time.sleep(3)

        chan.send("docker container stop docker-sonic-mgmt\n")
        buff = ''
        while not buff.endswith(':~$ '):
            resp = chan.recv(9999)
            buff += resp.decode("ascii")
            print(resp.decode("ascii"))
        time.sleep(3)

        chan.send("docker container rm docker-sonic-mgmt\n")
        buff = ''
        while not buff.endswith(':~$ '):
            resp = chan.recv(9999)
            buff += resp.decode("ascii")
            print(resp.decode("ascii"))
        time.sleep(3)

    chan.send("mkdir golden-code\n")
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("cd golden-code\n")
    buff = ''
    while not buff.endswith(':~/golden-code$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("wget {}\n".format(data['tar_ball']))
    buff = ''
    while not buff.endswith(':~/golden-code$ '):
        resp = chan.recv(9999)
        buff += resp.decode("utf-8")
    time.sleep(3)

    tar_ball = data['tar_ball'].split('/')[-1]
    chan.send("tar -xvf {}\n".format(tar_ball))
    buff = ''
    while not buff.endswith(':~/golden-code$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("cd sonic-test/sonic-mgmt\n")
    buff = ''
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("mkdir ansible/vars/docker-ptf\n")
    buff = ''
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("docker run -v $PWD:/data --privileged --network host --name 'docker-sonic-mgmt' -itd docker-sonic-mgmt-vxr bash \n")
    buff = ''
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)


    ssh.close()

def create_testbed_file(data,base_topo_file,vEOS_count, dut_platform, device_type):
    input_file = base_topo_file
    with open(input_file) as f:
        tdata = yaml.load(f, Loader=yaml.FullLoader)
        f.close()

    # Find each device listed in the VXR topology that starts with "sonic_dut_"
    for vxr_device_name in get_dut_names(data):
        tdata_dut_name = get_tdata_dut_name(vxr_device_name, dut_platform)
        tdata['devices'][tdata_dut_name]['ansible']['ansible_host'] = data[vxr_device_name]['xr_mgmt_ip']
        tdata['devices'][tdata_dut_name]['ansible']['ansible_ssh_user'] = data[vxr_device_name]['uname']

    tdata['testbed']['docker-ptf']['ansible']['ansible_host'] = data['docker_ptf']['xr_mgmt_ip'] + '/24'
    tdata['testbed']['docker-ptf']['ptf_ip'] = data['docker_ptf']['xr_mgmt_ip'] + '/24'
    tdata['devices']['docker-ptf']['ansible']['ansible_host'] = data['docker_ptf']['xr_mgmt_ip'] + '/24'

    if 'dualtor' in device_type:
        tdata['devices']['str-acs-serv-01']['ansible']['ansible_host'] = data['mux_sim']['xr_mgmt_ip'] + '/24'
        tdata['host_vars']['str-acs-serv-01']['mgmt_gw'] = data['mux_sim']['xr_mgmt_ip']
        tdata['testbed']['docker-ptf']['group-name'] = 'vms_1'

    base = 100
    tdata['veos']['vm_host_1']['STR-ACS-SERV-01']['ansible_host'] = data['sonic_mgmt']['HostAgent']
    for i in range (1,vEOS_count+1):
        tdata['veos']['vms_1']['VM0' + str(base)]['ansible_host'] = data['veos'+str(i)]['xr_mgmt_ip']
        base +=1

    with open(input_file,'w') as f:
        yaml.dump(tdata,f)
        f.close()

def run_python_script(host,port,user,passwd,cmd_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, user, passwd)
    chan = ssh.invoke_shell()
    for cmd in cmd_list:
        chan.send(cmd)
        time.sleep(3)
        resp = chan.recv(9999)
        print("Response : %s" % resp.decode("ascii"))

    ssh.close()

def apply_config(host,port,user,passwd,filepath):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, user, passwd)
    chan = ssh.invoke_shell()
    cfg_file = open(filepath, 'r')
    configs = cfg_file.readlines()
    for cmd in configs:
        chan.send(cmd)
        time.sleep(3)
        resp = chan.recv(9999)
        print("Response : %s" % resp.decode("ascii"))

    ssh.close()

def run_exec_cmds(host,port,user,passwd,cmd_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    out = ""
    for cmd in cmd_list:
        ssh.connect(host, port, user, passwd)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8")
        print(out)
        if error:
            print('There was an error pulling the runtime: {}'.format(error))
        ssh.close()
    return out

# Write a buffer to a remote file on the sonic-mgmt VM
# Allows us to upload a generated file without creating a local temporary copy of it
def upload_file_stream(data, stream, dest):
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
        with ssh.open_sftp() as ftp_client:
            with ftp_client.file(dest, 'w') as fd:
                fd.write(stream)


def upload_tb_files(data,topo_type,base_topo_file,device_type):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.put('run_scripts.py','golden-code/sonic-test/sonic-mgmt/tests/run_scripts.py')
    ftp_client.put('../sonic-mgmt/tests/allure_server.py','golden-code/sonic-test/sonic-mgmt/tests/allure_server.py')
    #ftp_client.put('sanity_scripts.txt','sonic-test/sonic-mgmt/tests/sanity_scripts.txt')
    ftp_client.put(base_topo_file,'golden-code/sonic-test/sonic-mgmt/ansible/{}'.format(base_topo_file))
    ftp_client.put('testbed_add_vm_topology.yml','golden-code/sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
    ftp_client.put('password.txt','golden-code/sonic-test/sonic-mgmt/ansible/password.txt')
    ftp_client.put('veos.yml','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
    if device_type == 'mth32':
        ftp_client.put('lab_connection_graph_mth32.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'crocodile':
        ftp_client.put('lab_connection_graph_crocodile.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_crocodile.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_crocodile.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'dualtor_mth64':
        ftp_client.put('lab_connection_graph_dualtor_mth64.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
    elif device_type == 'churchill-mono':
        ftp_client.put('lab_connection_graph_churchill_mono.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_churchill_mono.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_churchill_mono.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'carib':
        ftp_client.put('lab_connection_graph_churchill_mono.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_churchill_mono.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_churchill_mono.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'sfd' and topo_type == 't2-min':
        ftp_client.put('lab_connection_graph_t2_2lc_min.xml', 'golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('topo_Cisco-8800-LC-48H-C48.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-8800-LC-48H-C48.yml')
        ftp_client.put('topo_Cisco-8800-RP.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-8800-RP.yml')
        ftp_client.put('topo_t2_2lc_min_ports-masic.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t2_2lc_min_ports-masic.yml')
    if topo_type in ['t0', 'dualtor-56']:
        ftp_client.put('t0-leaf.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t0-leaf.j2')
    elif topo_type == 't1':
        ftp_client.put('t1-spine.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-spine.j2')
        ftp_client.put('t1-tor.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-tor.j2')
        ftp_client.put('topo_t1.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t1.yml')
    elif topo_type == 't1-28-lag':
        ftp_client.put('t1-28-lag-spine.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-28-lag-spine.j2')
        ftp_client.put('t1-28-lag-tor.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-28-lag-tor.j2')
        ftp_client.put('topo_t1-28-lag.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t1-28-lag.yml')
    elif topo_type == 't1-lag-dash-4':
        ftp_client.put('t1-28-lag-spine.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-lag-dash-4-spine.j2')
        ftp_client.put('t1-28-lag-tor.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-lag-dash-4-tor.j2')
        ftp_client.put('topo_t1-lag-dash-4.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t1-lag-dash-4.yml')
    ftp_client.close()

def reload_dut_with_newCFG(data):
    for dut_name in get_dut_names(data):
        cmd_list = list()
        cmd_list.append('sudo cp /tmp/config_db_new.json /etc/sonic/config_db.json\n')
        cmd_list.append('sudo cp /tmp/minigraph.xml /etc/sonic/minigraph.xml\n')
        cmd_list.append('sudo reboot\n')
        run_exec_cmds(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], cmd_list)


def get_dut_platform(device_type):
    if device_type == 'sherman':
        return "sherman"
    elif device_type == 'sfd':
        return 'sfd'
    elif device_type == 'crocodile':
        return 'crocodile'
    elif device_type == 'churchill-mono':
        return 'churchill-mono'
    elif device_type == 'carib':
        return 'carib'
    else:
        return "mathilda"

def start_vxr(input_file, cicd, clean_sim, topo_yaml):
    vxr_path = "/auto/vxr/pyvxr/pyvxr-latest/vxr.py"

    if input_file:
        return vxr_path, input_file

    if cicd:
        vxr_path = "python3.8 /auto/vxr/pyvxr/pyvxr-latest/vxr.py"

    if clean_sim:
        os.system("{} clean".format(vxr_path))

    os.system("bash -c '{} start {} |& tee sim_op.log'".format(vxr_path, topo_yaml))

    sim_output = subprocess.check_output("grep -i 'sim up' sim_op.log | wc -l", shell=True).strip()

    # Populate results file with failure data
    if not int(sim_output):
        handle_sim_failure("sim_failure")
        sys.exit("Sim is not up. Exiting now")

    os.system("{} ports > vxr_ports.yaml".format(vxr_path))
    return vxr_path, "vxr_ports.yaml"

def attach_vxr():
    vxr_path = "/auto/vxr/pyvxr/pyvxr-latest/vxr.py"

    os.system("{} ports > vxr_ports.yaml".format(vxr_path))
    return vxr_path, "vxr_ports.yaml"


def print_env_info(data, device_type):
    if 'tortuga-controller' not in data['topo_type']:
        print("Sonic Mgmt (vxr/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['serial0'], data['sonic_mgmt']['xr_mgmt_ip'], data['sonic_mgmt']['xr_redir22']))
        print("Leaf0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['leaf0']['HostAgent'], data['leaf0']['serial0'], data['leaf0']['xr_mgmt_ip'], data['leaf0']['xr_redir22']))
        print("Leaf1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['leaf1']['HostAgent'], data['leaf1']['serial0'], data['leaf1']['xr_mgmt_ip'], data['leaf1']['xr_redir22']))
        print("Spine0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['spine0']['HostAgent'], data['spine0']['serial0'], data['spine0']['xr_mgmt_ip'], data['spine0']['xr_redir22']))
        print("Spine1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['spine1']['HostAgent'], data['spine1']['serial0'], data['spine1']['xr_mgmt_ip'], data['spine1']['xr_redir22']))
        print("Ixia Chassis (ixia-pc/<>) :  SlurmHost: {}   Tlnt Port: {} ".format(data['ixia_chassis']['HostAgent'], data['ixia_chassis']['serial0']))
        print("Ixia Gui (ixia-pc/<>) :  SlurmHost: {}   Tlnt Port: {}  redir3389: {}".format(data['ixia_gui']['HostAgent'], data['ixia_gui']['serial0'], data['ixia_gui']['redir3389']))
        print("Ixia (ixia-pc/<>) :  SlurmHost: {}   Tlnt Port: {}".format(data['ixia']['HostAgent'], data['ixia']['serial0']))
    elif 'tortuga-controller-2x2' in data['topo_type']:
        leaf_ports = [data['L0']['xr_redir22'],data['L1']['xr_redir22']]
        spine_ports = [data['S0']['xr_redir22'],data['S1']['xr_redir22']]
        host_ports = list()
        print("Leaf0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L0']['HostAgent'], data['L0']['serial0'], data['L0']['xr_mgmt_ip'], data['L0']['xr_redir22']))
        print("Leaf1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L1']['HostAgent'], data['L1']['serial0'], data['L1']['xr_mgmt_ip'], data['L1']['xr_redir22']))
        print("Spine0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['S0']['HostAgent'], data['S0']['serial0'], data['S0']['xr_mgmt_ip'], data['S0']['xr_redir22']))
        print("Spine1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['S1']['HostAgent'], data['S1']['serial0'], data['S1']['xr_mgmt_ip'], data['S1']['xr_redir22']))
        for i in range(1,8):
            print("trex{} (root/root) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(i, data['trex' + str(i)]['HostAgent'], data['trex' + str(i)]['serial0'], data['trex' + str(i)]['xr_mgmt_ip'], data['trex' + str(i)]['xr_redir22']))
            host_ports.append(data['trex' + str(i)]['xr_redir22'])
        return leaf_ports, host_ports
    elif 'tortuga-controller-2x3' in data['topo_type']:
        leaf_ports = [data['L0']['xr_redir22'],data['L1']['xr_redir22'],data['L2']['xr_redir22']]
        spine_ports = [data['S0']['xr_redir22'],data['S1']['xr_redir22']]
        host_ports = list()
        print("Leaf0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L0']['HostAgent'], data['L0']['serial0'], data['L0']['xr_mgmt_ip'], data['L0']['xr_redir22']))
        print("Leaf1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L1']['HostAgent'], data['L1']['serial0'], data['L1']['xr_mgmt_ip'], data['L1']['xr_redir22']))
        print("Leaf2 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L2']['HostAgent'], data['L2']['serial0'], data['L2']['xr_mgmt_ip'], data['L2']['xr_redir22']))
        print("Spine0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['S0']['HostAgent'], data['S0']['serial0'], data['S0']['xr_mgmt_ip'], data['S0']['xr_redir22']))
        print("Spine1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['S1']['HostAgent'], data['S1']['serial0'], data['S1']['xr_mgmt_ip'], data['S1']['xr_redir22']))
        for i in range(1,11):
            print("trex{} (root/root) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(i, data['trex' + str(i)]['HostAgent'], data['trex' + str(i)]['serial0'], data['trex' + str(i)]['xr_mgmt_ip'], data['trex' + str(i)]['xr_redir22']))
            host_ports.append(data['trex' + str(i)]['xr_redir22'])
        return leaf_ports, host_ports
    else:
        leaf_ports = [data['L0']['xr_redir22'],data['L1']['xr_redir22'],data['L2']['xr_redir22']]
        spine_ports = [data['S0']['xr_redir22']]
        host_ports = list()
        print("Leaf0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L0']['HostAgent'], data['L0']['serial0'], data['L0']['xr_mgmt_ip'], data['L0']['xr_redir22']))
        print("Leaf1 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L1']['HostAgent'], data['L1']['serial0'], data['L1']['xr_mgmt_ip'], data['L1']['xr_redir22']))
        print("Leaf2 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['L2']['HostAgent'], data['L2']['serial0'], data['L2']['xr_mgmt_ip'], data['L2']['xr_redir22']))
        print("Spine0 (cisco/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['S0']['HostAgent'], data['S0']['serial0'], data['S0']['xr_mgmt_ip'], data['S0']['xr_redir22']))
        for i in range(1,11):
            print("trex{} (root/root) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(i, data['trex' + str(i)]['HostAgent'], data['trex' + str(i)]['serial0'], data['trex' + str(i)]['xr_mgmt_ip'], data['trex' + str(i)]['xr_redir22']))
            host_ports.append(data['trex' + str(i)]['xr_redir22'])
        return leaf_ports, host_ports, spine_ports

def update_controller_test(data, leaf_ports, host_ports):

    fabric_str = "FABRIC_NAME={}".format(data['fabric_name'])
    pyvxr_str = "PYVXR_HOST={}".format(data['L0']['HostAgent'])
    host_str = "HOST_PORTS={}".format(format(','.join(str(item) for item in host_ports)))
    leaf_str = "LEAF_PORTS={}".format(format(','.join(str(item) for item in leaf_ports)))
    spine_str1 = "SPINE_PORTS=1"
    spine_str2 = "SPINE_PORTS=2"
    print(fabric_str)
    print(pyvxr_str)
    print(host_str)
    print(leaf_str)
    os.system("sed -i 's/.*FABRIC_NAME\=.*/{}/' ./tortuga_controller/test.sh".format(fabric_str))
    os.system("sed -i 's/.*PYVXR_HOST\=.*/{}/' ./tortuga_controller/test.sh".format(pyvxr_str))
    os.system("sed -i 's/.*HOST_PORTS\=.*/{}/' ./tortuga_controller/test.sh".format(host_str))
    os.system("sed -i 's/.*LEAF_PORTS\=.*/{}/' ./tortuga_controller/test.sh".format(leaf_str))
    if 'tortuga-controller-2' in data['topo_type']:
        os.system("sed -i 's/.*SPINE_PORTS\=.*/{}/' ./tortuga_controller/test.sh".format(spine_str2))
    else:
        os.system("sed -i 's/.*SPINE_PORTS\=.*/{}/' ./tortuga_controller/test.sh".format(spine_str1))

def start_controller():
    test_path = "./tortuga_controller/test.sh"
    cwd = os.getcwd()
    os.chdir('./tortuga_controller')
    os.system("bash -c './test.sh |& tee test_op.log'".format(test_path))

    test_output = subprocess.check_output("grep -i 'Completed in' test_op.log | wc -l", shell=True).strip()

    os.chdir(cwd)

    # Populate results file with failure data
    if not int(test_output):
        return False
    else:
        return True

def export_sim_cfg_to_file(data, topo_name, device_type, docker_mgmt_container):
    sim_cfg_filename = "sim_credentials.json"
    sim_cfg = {}

    for dut_name in get_dut_names(data):
        device = data[dut_name]
        dut_host = "{}_HOST".format(dut_name.upper().replace(" ", "_"))
        dut_username = "{}_USERNAME".format(dut_name.upper().replace(" ", "_"))
        dut_pass = "{}_PASSWORD".format(dut_name.upper().replace(" ", "_"))
        dur_ssh_port = "{}_SSH_PORT".format(dut_name.upper().replace(" ", "_"))

        sim_cfg[dut_host] = device['HostAgent']
        sim_cfg[dut_username] = "cisco"
        sim_cfg[dut_pass] = "cisco123"
        sim_cfg[dur_ssh_port] = device['xr_redir22']

    sim_cfg["SONIC_MGMT_HOST"] = data['sonic_mgmt']['HostAgent']
    sim_cfg["SONIC_MGMT_USERNAME"] = "vxr"
    sim_cfg["SONIC_MGMT_PASSWORD"] = "cisco123"
    sim_cfg["SONIC_MGMT_SSH_PORT"] = data['sonic_mgmt']['xr_redir22']

    sim_cfg["PTF_HOST"] = data['docker_ptf']['HostAgent']
    sim_cfg["PTF_USERNAME"] = "root"
    sim_cfg["PTF_PASSWORD"] = "root"
    sim_cfg["PTF_SSH_PORT"] = data['docker_ptf']['xr_redir22']

    sim_cfg['TOPO_NAME'] = topo_name
    sim_cfg['DEVICE_TYPE'] = device_type
    sim_cfg['DOCKER_MGMT_CONTAINER'] = docker_mgmt_container

    print("Exporting sim credentials to file: {}".format(sim_cfg_filename))
    print("Contents: \n{}".format(sim_cfg))

    with open(sim_cfg_filename,'w') as cfg_file:
            json.dump(sim_cfg, cfg_file, indent=4)

def replace_fabric_name(topo_type, topo_yaml,fabric_name):
    if 'tortuga-controller-2x2' in topo_type:
        num_leaf = 2
        num_spine = 2
    elif 'tortuga-controller-2x3' in topo_type:
        num_leaf = 3
        num_spine = 2
    else:
        num_leaf = 3
        num_spine = 1

    with open(topo_yaml) as f:
        vxr_data = yaml.load(f, Loader=yaml.FullLoader)
        for i in range(0, num_leaf):
            for line in vxr_data['devices']['L{}'.format(i)]['cli_commands'].splitlines():
                if 'config hostname' in line:
                    newline = "sudo config hostname {}-leaf{}".format(fabric_name,i)
                    os.system("sed -i 's/{}/{}/' {}".format(line,newline,topo_yaml))
        for i in range(0, num_spine):
            for line in vxr_data['devices']['S{}'.format(i)]['cli_commands'].splitlines():
                if 'config hostname' in line:
                    newline = "sudo config hostname {}-spine{}".format(fabric_name,i)
                    os.system("sed -i 's/{}/{}/' {}".format(line,newline,topo_yaml))

def collect_showtechsupport(data, dut_ports):
    files_downloaded = []
    for port in dut_ports:
        tar_file_output = run_exec_cmds(data['L0']['HostAgent'], port ,"cisco","cisco123",["show techsupport"])
        print(tar_file_output)
        tar_file = [j for j in tar_file_output.split('\n') if j != ''][-1]
        ret = get_showtechsupport(data, port, tar_file)
        if ret == 0:
            files_downloaded.append(os.path.basename(tar_file))

    return files_downloaded

def create_sanity_log_tarball(data, dut_ports):
    showtechsupport_files = collect_showtechsupport(data, dut_ports)
    sanity_logs_dir = 'sanity_logs'
    os.makedirs(sanity_logs_dir, exist_ok=True)
    files_to_move = showtechsupport_files + ["vxr.out"]
    for file_name in files_to_move:
        if os.path.exists(file_name):
            os.rename(file_name, os.path.join(sanity_logs_dir, file_name))
            print(f"Moved {file_name} to {sanity_logs_dir}")
        else:
            print(f"{file_name} does not exist and will not be moved.")
    try:
        subprocess.run(['tar', '-czf', 'sanity_logs.tar.gz', sanity_logs_dir], check=True)
        print("Created tarball sanity_logs.tar.gz")
    except subprocess.CalledProcessError as e:
        print(f"Error creating tarball: {e}")

def get_showtechsupport(data, port, tar_file):
    print(f"Getting report file {tar_file}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(data['L0']['HostAgent'], port,"cisco","cisco123")
        ftp_client=ssh.open_sftp()
        ftp_client.get(tar_file,os.path.basename(tar_file))
    except Exception as e:
        print(f"failed to get file {tar_file}! Error: {e}")
        return -1
    finally:
        ftp_client.close()
    return 0

def create_report_json(sanity_success):
    sum = {"total": 1, "failed": 0, "passed": 0, "status" : "", "success_rate": 0}

    if sanity_success:
        sum["passed"] = 1
        sum["status"] = "success"
        sum["success_rate"] = 100
    else:
        sum["failed"] = 1
        sum["status"] = "failure"
        sum["success_rate"] = 0

    sum_f = open(SUMMARY_REPORT_PATH, "w")
    com_f = open(COMMON_REPORT_PATH, "w")

    print(f"result summary is: {sum}")

    json.dump(sum, sum_f)
    json.dump(sum, com_f)

    sum_f.close()
    com_f.close()

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    topo_yaml = args['topo_yaml']
    clean_sim = args['clean_sim']
    run_sanity = args['run_sanity']
    dut_passwd = args['dut_passwd']
    dut_uname = args['dut_uname']
    topo_type = args['topo_type']
    device_type = args['device_type']
    script_file = args['script_file']
    drop_version = args['drop_version']
    log_dir = args['log_dir']
    tar_ball = args['tar_ball']
    cicd = args['cicd']
    cicd_clean = args['cicd_clean']
    additional_tests = args['additional_tests']
    create_allure_report = args['create_allure_report']
    skip_sanity = args['skip_sanity']
    sim_attach = args['sim_attach']
    fabric_name = args['fabric_name']

    print("using topo & platform to filename mapping in '{}'".format(TOPO_PLATFORM_FILE_MAP))
    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

    #print("Topo & platform to filename mapping dict: '{}'".format(TOPO_PLATFORM_FILE_DICT))

    #get topo_yaml from topo_type
    if not topo_yaml and topo_type in TOPO_PLATFORM_FILE_DICT:
        if device_type in TOPO_PLATFORM_FILE_DICT[topo_type]:
            topo_yaml = TOPO_PLATFORM_FILE_DICT[topo_type][device_type]["pyvxr_yaml_file"]

    if 'tortuga-controller' in topo_type:
        replace_fabric_name(topo_type,topo_yaml,fabric_name)

    dut_platform = get_dut_platform(device_type)

    vxr_start_begin = datetime.datetime.now()

    if sim_attach:
        vxr_path, input_file = attach_vxr()
    else:
        vxr_path, input_file = start_vxr(args['input_file'], cicd, clean_sim, topo_yaml)

    vxr_start_end = datetime.datetime.now()

    with open(input_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    for dut_name in get_dut_names(data):
        data[dut_name]['uname'] = dut_uname
        data[dut_name]['passwd'] = dut_passwd

    data['tar_ball'] = tar_ball
    data['topo_type'] = topo_type
    data['fabric_name'] = fabric_name

    #print_env_info(data, device_type)

    vcr_configure_end = datetime.datetime.now()

    sim_time_delta = (vxr_start_end - vxr_start_begin).total_seconds()

    if topo_type == 'sol-tb-l2vni':
        leaf0_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l2vni/l2vni_leaf0.cfg'
        apply_config(data['leaf0']['HostAgent'],data['leaf0']['xr_redir22'],dut_uname,dut_passwd,leaf0_filepath)
        leaf1_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l2vni/l2vni_leaf1.cfg'
        apply_config(data['leaf1']['HostAgent'],data['leaf1']['xr_redir22'],dut_uname,dut_passwd,leaf1_filepath)
        spine0_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l2vni/spine0.cfg'
        apply_config(data['spine0']['HostAgent'],data['spine0']['xr_redir22'],dut_uname,dut_passwd,spine0_filepath)
        spine1_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l2vni/spine1.cfg'
        apply_config(data['spine1']['HostAgent'],data['spine1']['xr_redir22'],dut_uname,dut_passwd,spine1_filepath)
    elif topo_type == 'sol-tb-l3vni':
        leaf0_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l3vni/l3vni_leaf0.cfg'
        apply_config(data['leaf0']['HostAgent'],data['leaf0']['xr_redir22'],dut_uname,dut_passwd,leaf0_filepath)
        leaf1_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l3vni/l3vni_leaf1.cfg'
        apply_config(data['leaf1']['HostAgent'],data['leaf1']['xr_redir22'],dut_uname,dut_passwd,leaf1_filepath)
        spine0_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l3vni/spine0.cfg'
        apply_config(data['spine0']['HostAgent'],data['spine0']['xr_redir22'],dut_uname,dut_passwd,spine0_filepath)
        spine1_filepath = './../sonic-mgmt/spytest/tests/cisco/tortuga/solution/validated_configs/base_l3vni/spine1.cfg'
        apply_config(data['spine1']['HostAgent'],data['spine1']['xr_redir22'],dut_uname,dut_passwd,spine1_filepath)

    profile_time_delta = (vcr_configure_end - vxr_start_end).total_seconds()

    if 'tortuga-controller' not in data['topo_type']:
        print("******************************************************************************************************************************************************************************\n")
        print("Time taken for the sim to come up: {} mins".format(sim_time_delta/60))
        #print("Time taken for the profile to come up: {} mins".format(profile_time_delta/60))
        print("Ixia (1/1-1/4) ----> Leaf0(Ethernet16..40)")
        print("Ixia (1/5-1/8) ----> Leaf1(Ethernet16..40)")
        print("Leaf0 Ethernet0 ----> Spine0 Ethernet0")
        print("Leaf0 Ethernet8 ----> Spine1 Ethernet8")
        print("Leaf1 Ethernet0 ----> Spine1 Ethernet0")
        print("Leaf1 Ethernet8 ----> Spine0 Ethernet8")
        print("Sonic-Mgmt eth1 ----> Leaf0 Ethernet48")
        print("Sonic-Mgmt eth2 ----> Leaf1 Ethernet48")
        print("******************************************************************************************************************************************************************************\n")
        print_env_info(data, device_type)
    else:
        leaf_ports, host_ports, spine_ports = print_env_info(data, device_type)
        update_controller_test(data, leaf_ports, host_ports)
        sanity_success = start_controller()
        if sanity_success:
            print("Successfully pushed configuration and Traffic Test passed")
        else:
            print("Test Failed. Something went wrong, Please check the test logs")
        create_sanity_log_tarball(data, leaf_ports + spine_ports)
        create_report_json(sanity_success)

    if cicd_clean:
        print("****** Clearing SIM at the end of CICD run ******** ")
        os.system("{} clean".format(vxr_path))


if __name__ == '__main__':
  main()
