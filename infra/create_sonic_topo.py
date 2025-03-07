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
import re
import urllib.parse

from jinja2 import Environment, FileSystemLoader
from run_scripts_remote import run_scripts_remote, handle_sim_failure

TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'

# SFD T2 MIN MAX LC supported for SIM
SFD_SUPPORTED_NUM_LC = 2

# LC combinations supported for SFD T2 min topology
SFD_SUPPORTED_LC_TOPO = {'GG', 'VG', 'VL'}

# LC type and code mapping for SFD LCs
SFD_LC_TOPO_CODE = {
        "vanguard" : "V",
        "gauntlet" : "G",
        "lancer"   : "V"
    }

# Path to config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

# SIM workaround command files for Sonic master bringup.
wa_file_map = { "sfd": "sfd_wa_cmd_list",
                "churchill-mono": "cmono_wa_cmd_list"
              }

def _get_container_ssh_channel(hostname, username, password, container_name, ssh_port=22):
    """
    SSH into the  VM and exec into container
    return: ssh, ssh_channel
    """

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, port=ssh_port, username=username, password=password, timeout=120, banner_timeout=120)
    ssh_channel = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = ssh_channel.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    # Get into the docker-sonic-mgmt container
    ssh_channel.send('docker exec -it {} /bin/bash \n'.format(container_name))
    buff = ''
    while not buff.endswith(':~$ '):
        resp = ssh_channel.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    return ssh, ssh_channel

def _run_cmd_in_channel(ssh_channel, cmd, timeout=180):
    """
    Run a command in the container shell
    """

    stdout_buff = ''
    stderr_buff = ''
    status_code_buff = ''
    
    rcv_timeout = 60
    interval_length = 5

    ssh_channel.send(f'{cmd}\n') 
    ssh_channel.settimeout(timeout)
    try:
        while not ssh_channel.exit_status_ready():
            if ssh_channel.recv_ready():
                resp = ssh_channel.recv(9999)
                stdout_buff += resp.decode("ascii")
            else:
                rcv_timeout -= interval_length

            if rcv_timeout < 0:
                break
            else:
                time.sleep(interval_length)

            if ssh_channel.recv_stderr_ready():
                error_buff = ssh_channel.recv_stderr(9999)
                while error_buff:
                    stderr_buff += error_buff.decode("ascii")
                    error_buff = ssh_channel.recv_stderr(9999)
    except Exception as e:
        raise Exception("exception occurred while running command in ssh_channel '{}': {}".format(cmd, e))
    
    rcv_timeout = 60
    status_code_cmd = "echo $?"
    ssh_channel.send('{}\n'.format(status_code_cmd)) 
    try:
        while not ssh_channel.exit_status_ready():
            if ssh_channel.recv_ready():
                resp = ssh_channel.recv(9999)
                status_code_buff += resp.decode("ascii")
            else:
                rcv_timeout -= interval_length

            if rcv_timeout < 0:
                break
            else:
                time.sleep(interval_length)
    except Exception as e:
        raise Exception("exception occurred while getting status code of command in ssh_channel '{}': {}".format(cmd, e))
    
    # Extract status codes that appear immediately after "echo $?"
    # The output will look something like 'echo $?\r\n0\r\n\x1b]0;vxr@vxr-vm: /tmp\x07vxr@vxr-vm:/tmp$'. 
    # From this, we are only interested in 'echo $?\r\n0' part. Upon splitting by '\r\n', we get ['echo $?', '0'].
    outputs = status_code_buff.strip().split("\r\n") 
    status_code = int(outputs[outputs.index(status_code_cmd) + 1])

    print(f"ssh_channel command output '{cmd}': stdout: {stdout_buff}, stderr: {stderr_buff}, status_code: {status_code}")
    return stdout_buff, stderr_buff, status_code

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
                      required=True,default='t1-64-lag', choices=['dualtor-56', 'dualtor-56-4', 't1-64-lag', 't1-28-lag', 't1-lag-dash-4', 't0-64', "t1-8-lag", "t2-vs", "t2-min", "t2-min-VG", "t0", "t1"])
    parser.add_argument('-g', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
    parser.add_argument('-p', '--dut_passwd', type=str, help='Dut password, when it is different from YourPaSsWoRd',
                      required=False,default="YourPaSsWoRd")
    parser.add_argument('-u', '--dut_uname', type=str, help='Dut username, when it is different from admin',
                      required=False,default="admin")
    parser.add_argument('-c', '--clean_sim', action='store_true', help='Clean simulation',
                      default=False)
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32, crocodile, sfd, churchill-mono, carib',
                      required=False,default="mth64", choices=['sherman', 'mth32', 'mth64', 'crocodile', 'lightening', 'siren','sfd', 'churchill-mono', 'carib'])
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
    parser.add_argument('--test_file', type=str, help='Input test case file',
                      required=False,default=None)
    parser.add_argument('--apply_wa', action='store_true', help='Use workaround command list for SIM',
                      default=False)
    parser.add_argument('--add_sim_patches', action='store_true', help='Add patches to SIM to handle eth4 for route_check and shutdown',
                      default=False)
    parser.add_argument('-y', '--test_tag', type=str, help='tag to get tests to run from sanity file. Comma seperated \
        For e.g.fwd,plt', required=False,default=None)
    return parser

def repo_update(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
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

def deploy_mg(data, topo_type, base_topo_file, lc_topo_code):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('cd /data/ansible \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    if topo_type in ['dualtor-56', 'dualtor-56-4']:
        chan.send('echo "    docker-ptf: 8080">>/data/ansible/group_vars/all/mux_simulator_http_port_map.yml \n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))

    if topo_type == 'dualtor-56-4':
        chan.send('cp /data/ansible/vars/topo_dualtor-56-4.yml /data/ansible/vars/topo_dualtor-56.yml \n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))

    chan.send('python TestbedProcessing.py -i {} \n'.format(base_topo_file))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    if topo_type in ['t2-min', 't2-vs']:
        overwrite_lab_file(data, lc_topo_code)
        print("Overwrote lab file for T2 specific oddities")

    chan.send('./testbed-cli.sh -t testbed.csv deploy-mg docker-ptf lab group_vars/lab/secrets.yml\n')
    chan.settimeout(180)
    buff = ''
    err_buff = ''
    rcv_timeout = 60
    interval_length = 5

    try:
        while not chan.exit_status_ready():
            if chan.recv_ready():
                resp = chan.recv(9999)
                buff += resp.decode("ascii")
            else:
                rcv_timeout -= interval_length
            if rcv_timeout < 0:
                break
            else:
                time.sleep(interval_length)

            if chan.recv_stderr_ready():
                error_buff = chan.recv_stderr(9999)
                while error_buff:
                    err_buff += error_buff.decode("ascii")
                    error_buff = chan.recv_stderr(9999)
                print(err_buff)
    except Exception as e:
        raise Exception("exception occurred while running deploy_mg: {}".format(e))
    finally:
        print(buff)

    ssh.close()

def untar_cisco_dir(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('tar -xvf cisco.tar\n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    ssh.close()

def vEOS_inital_cfg(data,vEOS_count):
    # Specify the connection timeout in seconds for blocking operations, like connection attempt
    connection_timeout = 5

    # Specify a timeout in seconds. Read until the string is found or until the timeout has passed
    reading_timeout = 5
    base = 100

    for i in range (1,vEOS_count+1):
        veos1_host = data['veos'+ str(i)]['HostAgent']
        veos1_port = data['veos'+str(i)]['serial0']

        print('Adding admin password for VM0{}:'.format(str(base)))
        base += 1
        add_vEOS_admin_user(veos1_host,veos1_port, connection_timeout)


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

# Invoked on each DUT device found in topology
def change_dut_passwd(device):
    host = device['HostAgent']
    port = device['xr_redir22']
    user = device['uname']
    passwd = device['passwd']
    #passwd = "cisco123"
    new_passwd = "cisco123"
    mgmt_ip = device['xr_mgmt_ip']

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port, user, passwd, timeout=120, banner_timeout=120)
    except paramiko.ssh_exception.AuthenticationException:
        ssh.connect(host, port, user, new_passwd, timeout=120, banner_timeout=120)

    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp)

    # Ssh and wait for the password prompt.
    chan.send('sudo passwd {}\n'.format(user))
    buff = ''
    while not buff.endswith('password: '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    # Send the password and wait for a prompt.
    time.sleep(3)
    chan.send(new_passwd +'\n')

    buff = ''
    while not buff.endswith('password: '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    # Send the password and wait for a prompt.
    time.sleep(3)
    chan.send(new_passwd +'\n')

    buff = ''
    while buff.find(' successfully') < 0 :
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    if (' successfully') in buff:
        print("Password change successful")
    else:
        print("Password change failed")

    time.sleep(3)
    chan.send('sudo config interface ip add eth0 {}/24 192.168.122.1\n'.format(mgmt_ip))
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    time.sleep(3)
    chan.send('sudo config interface ip add eth0 FC00:2::32/64 fc00:2::1\n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    time.sleep(3)
    chan.send('sudo config save -y\n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))

    time.sleep(3)
    chan.send('sudo cp /etc/sonic/config_db.json /tmp/config_db.json\n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    ssh.close()

def run_python_script(host,port,user,passwd,cmd_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, user, passwd, timeout=120, banner_timeout=120)
    chan = ssh.invoke_shell()
    for cmd in cmd_list:
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
        ssh.connect(host, port, user, passwd, timeout=120, banner_timeout=120)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()
        out = stdout.read().decode("ascii").strip()
        error = stderr.read().decode("ascii")
        print(out)
        if error:
            print('There was an error pulling the runtime: {}'.format(error))
        ssh.close()
    return out

def add_vEOS_admin_user(veos1_host,veos1_port, connection_timeout):
    tn = telnetlib.Telnet(veos1_host,veos1_port, connection_timeout)

    #    tn.read_until(b"Username: ")
    #    tn.write(user.encode('ascii') + b"\n")
    #    if password:
    #        tn.read_until(b"Password: ")
    #        tn.write(password.encode('ascii') + b"\n")

    tn.write(b"enable\n")
    time.sleep(1)
    tn.write(b"conf t\n")
    time.sleep(1)
    tn.write(b"username admin secret 123456\n")
    time.sleep(1)
    tn.write(b"aaa root secret 123456\n")
    time.sleep(1)
    tn.write(b"end\n")
    time.sleep(1)
    tn.write(b"copy running-config startup-config\n")
    time.sleep(1)
    tn.close()

def download_mg(data,topo_type,dut_name):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
    ftp_client=ssh.open_sftp()
    ftp_client.get('/home/vxr/sonic-test/sonic-mgmt/ansible/minigraph/{}.{}.xml'.format(dut_name,topo_type), 'minigraph.xml')
    ftp_client.close()
    ssh.close()

# Write a buffer to a remote file on the sonic-mgmt VM
# Allows us to upload a generated file without creating a local temporary copy of it
def upload_file_stream(data, stream, dest):
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
        with ssh.open_sftp() as ftp_client:
            with ftp_client.file(dest, 'w') as fd:
                fd.write(stream)


def upload_tb_files(data,topo_type,base_topo_file,device_type, lc_topo_code='GG', add_sim_patches=False):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
    ftp_client=ssh.open_sftp()
    ftp_client.put('run_scripts.py','golden-code/sonic-test/sonic-mgmt/tests/run_scripts.py')
    ftp_client.put('../sonic-mgmt/tests/allure_server.py','golden-code/sonic-test/sonic-mgmt/tests/allure_server.py')
    os.system("tar -cvf cisco.tar -C ./../sonic-mgmt/tests cisco")
    ftp_client.put('cisco.tar', 'golden-code/sonic-test/sonic-mgmt/tests/cisco.tar')
    #ftp_client.put('sanity_scripts.txt','sonic-test/sonic-mgmt/tests/sanity_scripts.txt')
    ftp_client.put(base_topo_file,'golden-code/sonic-test/sonic-mgmt/ansible/{}'.format(base_topo_file))
    ftp_client.put('testbed_add_vm_topology.yml','golden-code/sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
    ftp_client.put('password.txt','golden-code/sonic-test/sonic-mgmt/ansible/password.txt')
    ftp_client.put('veos.yml','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')

    ftp_client.mkdir('golden-code/sonic-test/sonic-mgmt/tests/config')
    ftp_client.put(ALLURE_CONFIG_FILE_NAME, 'golden-code/sonic-test/sonic-mgmt/tests/{}'.format(ALLURE_CONFIG_FILE_NAME))

    if add_sim_patches:
        #ftp_client.put('run_scripts_remote.py','golden-code/sonic-test/sonic-mgmt/tests/run_scripts_remote.py')
        ftp_client.put('sim_patches/add_sim_hooks.py','golden-code/sonic-test/sonic-mgmt/tests/add_sim_hooks.py')
        ftp_client.put('sim_patches/tests_mark_conditions_cisco_sim.yaml','golden-code/sonic-test/sonic-mgmt/tests/common/plugins/conditional_mark/tests_mark_conditions_cisco_sim.yaml')
        ftp_client.put('sim_patches/cisco_sim.py','golden-code/sonic-test/sonic-mgmt/tests/common/devices/cisco_sim.py')
        ftp_client.put('sim_patches/cisco_sim_apis_hook.py','golden-code/sonic-test/sonic-mgmt/tests/common/cisco_sim_apis_hook.py')



    if device_type == 'mth32':
        ftp_client.put('lab_connection_graph_mth32.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    if device_type == 'siren':
        ftp_client.put('lab_connection_graph_siren.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_siren.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_siren.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
        ftp_client.put('../sonic-mgmt/ansible/module_utils/port_utils.py','golden-code/sonic-test/sonic-mgmt/ansible/module_utils/port_utils.py')

    elif device_type == 'crocodile':
        ftp_client.put('lab_connection_graph_crocodile.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_crocodile.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_crocodile.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'lightening':
        ftp_client.put('lab_connection_graph_lightening.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_lightening.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv')
        ftp_client.put('sonic_lab_devices_lightening.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
        ftp_client.put('../sonic-mgmt/ansible/module_utils/port_utils.py','golden-code/sonic-test/sonic-mgmt/ansible/module_utils/port_utils.py')
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
        ftp_client.put(f'sonic_t2/topo_8800-LC-{lc_topo_code}.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-8800-LC-48H-C48.yml')
        ftp_client.put(f'sonic_t2/topo_8800-LC-{lc_topo_code}.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-88-LC0-36FH-M-O36.yml')
        ftp_client.put(f'sonic_t2/topo_8800-LC-{lc_topo_code}.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-88-LC0-36FH-O36.yml')
        ftp_client.put(f'sonic_t2/topo_8800-RP-{lc_topo_code}.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/docker-ptf/topo_Cisco-8800-RP.yml')
        ftp_client.put('sonic_t2/topo_t2_2lc_min_ports-masic.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t2_2lc_min_ports-masic.yml')
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

def replace_dut_mgmt_address(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for dut_name in get_dut_names(data):
        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], timeout=120, banner_timeout=120)
        ftp_client=ssh.open_sftp()
        ftp_client.get('/tmp/config_db.json','config_db_current.json')
        ftp_client.close()
        ssh.close()

        with open('config_db_current.json') as cfg_file:
            cfg_data = json.load(cfg_file)
            current_mgm_intf = cfg_data["MGMT_INTERFACE"]
            current_mac = cfg_data["DEVICE_METADATA"]["localhost"]["mac"]
            print(cfg_data["MGMT_INTERFACE"])
            cfg_file.close()

        with open('config_db.json') as cfg_file:
            cfg_data = json.load(cfg_file)
            cfg_file.close()

        with open('config_db.json','w') as cfg_file:
            cfg_data["MGMT_INTERFACE"] = current_mgm_intf
            cfg_data["DEVICE_METADATA"]["localhost"]["mac"] = current_mac
            json.dump(cfg_data, cfg_file, indent=4)
            cfg_file.close()

        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], timeout=120, banner_timeout=120)
        ftp_client=ssh.open_sftp()
        ftp_client.put('config_db.json','/tmp/config_db_new.json')
        ftp_client.put('minigraph.xml', '/tmp/minigraph.xml')
        ftp_client.close()
        ssh.close()

def reload_dut_with_newCFG(data):
    for dut_name in get_dut_names(data):
        cmd_list = list()
        cmd_list.append('sudo cp /tmp/config_db_new.json /etc/sonic/config_db.json\n')
        cmd_list.append('sudo cp /tmp/minigraph.xml /etc/sonic/minigraph.xml\n')
        cmd_list.append('sudo reboot\n')
        run_exec_cmds(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], cmd_list)


# apply sim patches to handle eth4 for route_check and fast and warm reboot.
# note that eth4 is added as the simulation interface, however, in sonic only eth0 is used for mgmt and eth4 is considered as data port that lead to issues.
# these are temporary patches to handle the issues. Evetually, the sonic coode should be updated to treat eth4 as managment interfce.
def add_sim_patches(data):
    for dut_name in get_dut_names(data):
        print(f"****** Applying simulation patches for eth4 on {dut_name} ******")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], timeout=120, banner_timeout=120)

        ftp_client=ssh.open_sftp()
        ftp_client.get('/usr/local/bin/fast-reboot','fast-reboot')
        ftp_client.get('/usr/local/bin/warm-reboot','warm-reboot')
        ftp_client.get('/usr/local/bin/route_check.py','route_check.py')

        route_check_lines = []
        with open('route_check.py', 'r') as file:
            for  line in file.readlines():
                route_check_lines.append(line)
                if re.search(r"\s*local_if_lst\s*=\s*\{.*\}\s*", line):
                    indent_count = len(re.match(r'^(\s*)', line).group(1))
                    route_check_lines.append(' ' * indent_count+"local_if_lst.add('eth4')\n")
        with open('route_check.py', 'w') as file:
            file.writelines(route_check_lines)

        fast_reboot_lines = []
        ## adding -s to orchagent_restart_check command since the orchagent_restart_check check for eth4 which is not the data port for the DUT
        with open('fast-reboot', 'r') as file:
            for  line in file.readlines():
                if re.search(r'\s*docker exec -i swss \/usr\/bin\/orchagent_restart_check -w 2000 -r 5 .*', line):
                    indent_count = len(re.match(r'^(\s*)', line).group(1))
                    fast_reboot_lines.append(' ' *indent_count +"docker exec -i swss /usr/bin/orchagent_restart_check -s -w 2000 -r 5 > /dev/null || RESTARTCHECK_RC=$?\n")
                else:
                    fast_reboot_lines.append(line)
        with open('fast-reboot', 'w') as file:
            file.writelines(fast_reboot_lines)

        warm_reboot_lines = []
        ## adding -s to orchagent_restart_check command since the orchagent_restart_check check for eth4 which is not the data port for the DUT
        with open('warm-reboot', 'r') as file:
            for  line in file.readlines():
                if re.search(r'\s*docker exec -i swss \/usr\/bin\/orchagent_restart_check -w 2000 -r 5 .*', line):
                    indent_count = len(re.match(r'^(\s*)', line).group(1))
                    warm_reboot_lines.append(' ' * indent_count+"docker exec -i swss /usr/bin/orchagent_restart_check -s -w 2000 -r 5 > /dev/null || RESTARTCHECK_RC=$?\n")
                else:
                    warm_reboot_lines.append(line)
        with open('warm-reboot', 'w') as file:
            file.writelines(warm_reboot_lines)

        ftp_client.put('./route_check.py', '/tmp/route_check.py')
        ftp_client.put('./fast-reboot', '/tmp/fast-reboot')
        ftp_client.put('./warm-reboot', '/tmp/warm-reboot')
        ftp_client.close()
        ssh.close()
        cmd_list = list()
        cmd_list.append('sudo cp /tmp/route_check.py /usr/local/bin/route_check.py\n')
        cmd_list.append('sudo cp /tmp/fast-reboot /usr/local/bin/fast-reboot\n')
        cmd_list.append('sudo cp /tmp/warm-reboot /usr/local/bin/warm-reboot\n')
        run_exec_cmds(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], cmd_list)
        print(f"******  Finished applying simulation patches for eth4 on {dut_name} ******")



def run_sim_workaround(data, filename):
    ssh = paramiko.SSHClient()
    for dut_name in get_dut_names(data):
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], timeout=120, banner_timeout=120)
        ftp_client=ssh.open_sftp()
        ftp_client.put(filename, f'/tmp/{filename}')
        ftp_client.close()
        ssh.close()

        cmd_list = list()
        cmd_list.append(f'sudo bash /tmp/{filename} > /tmp/wa.log 2>&1\n')
        run_exec_cmds(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], cmd_list)
        print(f"***** copied {filename} to {dut_name} ******")

def run_config_reload(data):
    ssh = paramiko.SSHClient()
    for dut_name in get_dut_names(data):
        cmd_list = list()
        cmd_list.append(f'sudo config reload -fy\n')
        run_exec_cmds(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'], cmd_list)
        print(f"******  Executed config reload on {dut_name} ******")

def add_ptf_backplane_addr(data):
    cmd_list = list()
    cmd_list.append('ip address add 10.10.246.254/24 dev backplane')
    cmd_list.append('ip -6 address add fc0a::ff/64 dev backplane')
    cmd_list.append('for i in {0..%s}; do /sbin/ifconfig eth$i mtu 9216 up; done' % data['ptf_intf_count'])
    run_exec_cmds(data['docker_ptf']['HostAgent'], data['docker_ptf']['xr_redir22'], 'root', 'root', cmd_list)

def add_vEOS_cfg(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123", timeout=120, banner_timeout=120)
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('cd /data/ansible \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('env \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('./testbed-cli.sh -t testbed.csv -k veos -m veos add-topo docker-ptf password.txt\n')
    chan.settimeout(180)
    buff = ''
    err_buff = ''
    rcv_timeout = 60
    interval_length = 5

    try:
        while not chan.exit_status_ready():
            if chan.recv_ready():
                resp = chan.recv(9999)
                print(resp.decode("ascii"))
                buff += resp.decode("ascii")
            else:
                rcv_timeout -= interval_length
            if rcv_timeout < 0:
                break
            else:
                time.sleep(interval_length)

            if chan.recv_stderr_ready():
                error_buff = chan.recv_stderr(9999)
                while error_buff:
                    err_buff += error_buff.decode("ascii")
                    error_buff = chan.recv_stderr(9999)
                print(err_buff)
    except Exception as e:
        raise Exception("exception while running add-topo: {}".format(e))
    #finally:
    #    print(buff)

    chan.send('./testbed-cli.sh -t testbed.csv -k veos -m veos announce-routes docker-ptf password.txt\n')
    chan.settimeout(180)
    buff = ''
    err_buff = ''
    rcv_timeout = 60
    interval_length = 5

    try:
        while not chan.exit_status_ready():
            if chan.recv_ready():
                resp = chan.recv(9999)
                print(resp.decode("ascii"))
                buff += resp.decode("ascii")
            else:
                rcv_timeout -= interval_length
            if rcv_timeout < 0:
                break
            else:
                time.sleep(interval_length)

            if chan.recv_stderr_ready():
                error_buff = chan.recv_stderr(9999)
                while error_buff:
                    err_buff += error_buff.decode("ascii")
                    error_buff = chan.recv_stderr(9999)
                print(err_buff)
    except Exception as e:
        raise Exception("exception while running announce-routes: {}".format(e))

    ssh.close()

def install_allure(data):
    """
    Install the allure package in the sonic-mgmt container
    """

    # Get the ssh connection to the sonic-mgmt container
    ssh, container_channel = _get_container_ssh_channel(hostname=data['sonic_mgmt']['HostAgent'], username="vxr", password="cisco123", container_name='docker-sonic-mgmt', ssh_port=data['sonic_mgmt']['xr_redir22'])

    # Change to the tmp directory
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, 'cd /tmp')
    if status_code != 0:
        raise Exception(f'Failed to change directory to /tmp: stdout: {stdout}, stderr: {stderr}')

    # Unset the proxy variables
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, 'unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy')
    if status_code != 0:
        raise Exception(f'Failed to unset the proxy variables: stdout: {stdout}, stderr: {stderr}')

    # Fetch the allure package details from config
    allure_package_url = allure_config['allure']['debian-url']
    alure_package_name = os.path.basename(urllib.parse.urlparse(allure_package_url).path)

    # Download the allure package
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, f'wget {allure_package_url} -P /tmp')
    if status_code != 0:
        raise Exception(f'Failed to download the allure package: stdout: {stdout}, stderr: {stderr}')

    # Install the allure package
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, f'sudo dpkg -i /tmp/{alure_package_name}')
    if status_code != 0:
        raise Exception(f'Failed to install the allure package: stdout: {stdout}, stderr: {stderr}')

    # Verify the installation
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, 'allure --version')
    if status_code != 0:
        raise Exception(f'Failed to verify the allure installation: stdout: {stdout}, stderr: {stderr}')

    # Cleanup the downloaded package
    stdout, stderr, status_code = _run_cmd_in_channel(container_channel, f'rm /tmp/{alure_package_name}')
    if status_code != 0:
        raise Exception(f'Failed to cleanup the downloaded package: stdout: {stdout}, stderr: {stderr}')

    container_channel.close()
    ssh.close()
    return 0

# The lab file generated by TestbedProcessing.py does not work well for T2-2lc-min topology
# We still run TestbedProcessing.py to generate other important output files
# But then we overwrite the lab file with our own (in YAML instead of ini, for readability)
def overwrite_lab_file(vxr_ports, lc_topo_code):
    environment = Environment(loader=FileSystemLoader("lab-templates"))
    template = environment.get_template(f"t2-2lc-min-ports-{lc_topo_code}.yaml.j2")
    upload_file_stream(
        vxr_ports,
        template.render(vxr_ports=vxr_ports),
        "/home/vxr/golden-code/sonic-test/sonic-mgmt/ansible/lab"
    )

def get_dut_platform(device_type):
    if device_type == 'sherman':
        return "sherman"
    elif device_type == 'sfd':
        return 'sfd'
    elif device_type == 'crocodile':
        return 'crocodile'
    elif device_type == 'lightening':
        return 'lightening'
    elif device_type == 'siren':
        return 'siren'
    elif device_type == 'churchill-mono':
        return 'churchill-mono'
    elif device_type == 'carib':
        return 'carib'
    else:
        return "mathilda"

def determine_base_topo(topo_type, device_type):
    ptf_intfcount = 32
    if topo_type in ['t2-vs', 't2-min']:
        assert device_type == 'sfd', "Only SF-D is currently supported with T2 topologies"
        os.system("cp sonic_t2/* .")
        if topo_type == 't2-vs':
            base_topo_file = 'testbed-t2-vs.yaml'
            vEOS_count = 4
        elif topo_type == 't2-min':
            base_topo_file = 'testbed-t2-2lc-min-ports.yaml'
            vEOS_count = 8
    elif topo_type == 't0':
        os.system("cp sonic_t0_topo/* .")
        vEOS_count = 4
        ptf_intfcount = 32
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t0.yaml'
        elif device_type == 'lightening':
            base_topo_file = 'testbed-lightening-t0.yaml'
        elif device_type == 'siren':
            base_topo_file = 'testbed-siren-t0.yaml'
        elif device_type in ['churchill-mono','carib']:
            base_topo_file = 'testbed-churchill-mono-t0.yaml'
        else:
            base_topo_file = 'testbed-mth32-t0.yaml'
    elif topo_type == 't1':
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t1.yaml'
        elif device_type in ['churchill-mono','carib']:
            base_topo_file = 'testbed-churchill-mono-t1.yaml'
        elif device_type == 'lightening':
            base_topo_file = 'testbed-lightening-t1.yaml'
        elif device_type == 'siren':
            base_topo_file = 'testbed-siren-t1.yaml'
        else:
            base_topo_file = 'testbed-mth32-t1.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 32
        ptf_intfcount = 32
    elif topo_type == 'dualtor-56':
        os.system("cp sonic_dualtor_56/* .")
        vEOS_count = 4
        base_topo_file = 'testbed-mth64-t0-dualtor.yaml'
    elif topo_type == 'dualtor-56-4':
        os.system("cp sonic_dualtor_56/* .")
        vEOS_count = 4
        base_topo_file = 'testbed-mth64-t0-dualtor-4.yaml'
    elif topo_type == 't1-64-lag':
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t1-64-lag.yaml'
        else:
            base_topo_file = 'testbed-mth64-t1-64-lag.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 24
        ptf_intfcount = 64
    elif topo_type == 't1-28-lag':
        base_topo_file = 'testbed-mth32-t1-28-lag.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 21
        ptf_intfcount = 32
    elif topo_type == 't1-lag-dash-4':
        base_topo_file = 'testbed-mth32-t1-lag-dash-4.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 21
        ptf_intfcount = 32
    elif topo_type == 't1-8-lag':
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t1-8-lag.yaml'
        else:
            base_topo_file = 'testbed-t1-8-lag.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 6
        ptf_intfcount = 8
    elif topo_type == 't0-64':
        os.system("cp sonic_t0_topo/* .")
        vEOS_count = 4
        ptf_intfcount = 64
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t0.yaml'
        elif device_type in ['churchill-mono','carib']:
            ptf_intfcount = 32
            base_topo_file = 'testbed-churchill-mono-t0.yaml'
        else:
            base_topo_file = 'testbed-mth64-t0-64.yaml'

    return base_topo_file, vEOS_count, ptf_intfcount

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

def configure_vxr(data, topo_type, base_topo_file, vEOS_count, dut_platform, device_type, lc_topo_code, apply_wa=False, add_sim_patch=False):
    # Create admin user in vEOS vm
    print("****** Create admin user in vEOS vm *******")
    vEOS_inital_cfg(data,vEOS_count)

    #print("********** Do a Git Update **********")
    repo_update(data)

    # Create testbed file based on vxr_ports
    print("****** Create testbed file based on vxr_ports *******")
    create_testbed_file(data,base_topo_file,vEOS_count,dut_platform,device_type)

    # Upload t1 specific files to sonic mgmt container
    print("********** Upload testbed specific files to sonic mgmt container ***********")
    upload_tb_files(data,topo_type,base_topo_file,device_type, lc_topo_code,add_sim_patches)

    # Untar cisco directory
    print("********** Untar the uploaded cisco directory **********")
    untar_cisco_dir(data)

    # Change DUT password and set mgmt ip address
    for dut_name in get_dut_names(data):
        print("********** Change DUT password for DUT #{} and set mgmt ip address ***********".format(dut_name))
        change_dut_passwd(data[dut_name])

    if add_sim_patch:
        add_sim_patches(data)
    # Start docker container, deploy DUT minigraph
    print("********** Start docker container, deploy DUT minigraph ***********")
    deploy_mg(data,topo_type,base_topo_file, lc_topo_code)

    if apply_wa and device_type in wa_file_map:
        #sleep sometime to let deploy-mg load_minigraph complete
        time.sleep(300)
        run_sim_workaround(data, wa_file_map[device_type])
        run_config_reload(data)

    # Add vEOS config
    print("********** Add vEOS config ***********")
    add_vEOS_cfg(data)

    print("********** Configure PTF backplane ip address **********")
    add_ptf_backplane_addr(data)

    print("********** Install Allure package **********")
    install_allure(data)


def print_env_info(data, device_type, vEOS_count):
    for dut_name in get_dut_names(data):
        device = data[dut_name]
        print("Sonic DUT '{}' (cisco/cisco123):  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(dut_name, device['HostAgent'], device['serial0'], device['xr_mgmt_ip'], device['xr_redir22']))

    print("Sonic Mgmt (vxr/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['serial0'], data['sonic_mgmt']['xr_mgmt_ip'], data['sonic_mgmt']['xr_redir22']))

    print("PTF (root/root) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['docker_ptf']['HostAgent'], data['docker_ptf']['serial0'], data['docker_ptf']['xr_mgmt_ip'], data['docker_ptf']['xr_redir22']))
    if 'dualtor' in device_type:
        print("MUX SIM (vxr/cisco123) :  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['mux_sim']['HostAgent'], data['mux_sim']['serial0'], data['mux_sim']['xr_mgmt_ip'], data['mux_sim']['xr_redir22']))

    print("VEOS (admin/123456): ")
    for i in range (1,vEOS_count+1):
        print("VEOS{}:  SlurmHost: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(str(i-1), data['veos'+ str(i)]['HostAgent'], data['veos'+ str(i)]['serial0'], data['veos'+ str(i)]['xr_mgmt_ip'], data['veos'+ str(i)]['xr_redir22'] ))

    print("******************************************************************************************************************************************************************************\n")
    if device_type == 'sherman':
        print("Device name is sherman. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d sherman-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_fact.py |& tee bgp_fact.log\n")
    elif device_type == 'crocodile':
        print("Device name is crocodile. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d crocodile-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    elif device_type == 'lightening':
        print("Device name is lightening. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d lightening-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    elif device_type == 'siren':
        print("Device name is siren. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d siren-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    elif device_type in ['churchill-mono','carib']:
        print("Device name is churchill-mono. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d churchill-mono-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    elif device_type == 'sfd':
        print("Device name is sfd. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -O -u -l debug -e -s -e --skip_sanity -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    else:
        print("Device name is mth32 or m64. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_fact.py |& tee bgp_fact.log\n")
    print("******************************************************************************************************************************************************************************\n")

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

def get_lc_topo_type(topo_yaml):
    """ Generates LC topology code based on LC types used in Chassis topology.
        V - Vanguard
        G - Gauntlet
        L - Lancer
        e.g.: VG - Vangauard - LC0, Gauntlet - LC1
    """
    with open(topo_yaml) as f:
        topo_data = yaml.load(f, Loader=yaml.FullLoader)
        lc_list = topo_data['devices']['sonic_dut']['linecard_types']
        if len(lc_list) != SFD_SUPPORTED_NUM_LC:
            sys.exit(f"Only {SFD_SUPPORTED_NUM_LC} LC config is supported. Provided list {lc_list}. Exiting now")
        lc_topo_code = ''
        for lc in lc_list:
            lc_topo_code = lc_topo_code + SFD_LC_TOPO_CODE[lc]
        print(f'LC topo code: {lc_topo_code}')
        return lc_topo_code

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
    test_file = args['test_file']
    drop_version = args['drop_version']
    log_dir = args['log_dir']
    tar_ball = args['tar_ball']
    cicd = args['cicd']
    cicd_clean = args['cicd_clean']
    additional_tests = args['additional_tests']
    create_allure_report = args['create_allure_report']
    skip_sanity = args['skip_sanity']
    sim_attach = args['sim_attach']
    apply_wa = args['apply_wa']
    add_sim_patches = args['add_sim_patches']
    test_tag = args['test_tag']
    print("using topo & platform to filename mapping in '{}'".format(TOPO_PLATFORM_FILE_MAP))
    with open(TOPO_PLATFORM_FILE_MAP) as cfg_file:
        TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

    print("Topo & platform to filename mapping dict: '{}'".format(TOPO_PLATFORM_FILE_DICT))

    #get topo_yaml from topo_type
    if not topo_yaml and topo_type in TOPO_PLATFORM_FILE_DICT:
        if device_type in TOPO_PLATFORM_FILE_DICT[topo_type]:
            topo_yaml = TOPO_PLATFORM_FILE_DICT[topo_type][device_type]["pyvxr_yaml_file"]

    ptf_intfcount = 32

    dut_platform = get_dut_platform(device_type)

    if topo_type == 't2-min-VG':
        # All LC combinations for SFD T2 min topology use same Sonic-mgmt SIM topology
        topo_type = 't2-min'

    base_topo_file, vEOS_count, ptf_intfcount = determine_base_topo(topo_type, device_type)

    print("USING BASE TOPO {}".format(base_topo_file))

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
    data['ptf_intf_count'] = ptf_intfcount

    # For SFD, generate the LC topology Code. Topology code is based on
    # LC types used in teh chassis for this topology instance bringup
    if device_type == 'sfd' and topo_type == 't2-min':
        lc_topo_code = get_lc_topo_type(topo_yaml)
    else:
        lc_topo_code = None

    configure_vxr(data, topo_type, base_topo_file, vEOS_count, dut_platform, device_type, lc_topo_code, apply_wa, add_sim_patches)

    print_env_info(data, device_type, vEOS_count)

    vcr_configure_end = datetime.datetime.now()

    export_sim_cfg_to_file(data, "docker-ptf", device_type, "docker-sonic-mgmt")

    if run_sanity:
        run_scripts_remote(
            data['sonic_mgmt']['HostAgent'],
            "vxr",
            "cisco123",
            script_file,
            drop_version,
            log_dir,
            device_type,
            topo_type,
            create_allure_report,
            ssh_port=data['sonic_mgmt']['xr_redir22'],
            additional_tests=additional_tests,
            skip_sanity=skip_sanity,
            dut_data_file=input_file,
            test_tag=test_tag
        )

    sim_time_delta = (vxr_start_end - vxr_start_begin).total_seconds()
    profile_time_delta = (vcr_configure_end - vxr_start_end).total_seconds()

    print("******************************************************************************************************************************************************************************\n")
    print("Time taken for the sim to come up: {} mins".format(sim_time_delta/60))
    print("Time taken for the profile to come up: {} mins".format(profile_time_delta/60))
    print("******************************************************************************************************************************************************************************\n")

    print_env_info(data, device_type, vEOS_count)

    if cicd_clean:
        print("****** Clearing SIM at the end of CICD run ******** ")
        os.system("{} clean".format(vxr_path))


if __name__ == '__main__':
  main()
