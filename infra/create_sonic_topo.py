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
                      required=False,default="http://172.29.93.10/sonic-images/golden-code/golden_code.tar.gz")
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=True,default=None)
    parser.add_argument('-t', '--topo_type', type=str, help='topo type',
                      required=True,default='t1-64-lag', choices=['dualtor-56', 'dualtor-56-4', 't1-64-lag', 't0-64', "t1-8-lag", "t2-vs", "t2-min"])
    parser.add_argument('-p', '--dut_passwd', type=str, help='Dut password, when it is different from YourPaSsWoRd',
                      required=False,default="YourPaSsWoRd")
    parser.add_argument('-u', '--dut_uname', type=str, help='Dut username, when it is different from admin',
                      required=False,default="admin")
    parser.add_argument('-c', '--clean_sim', action='store_true', help='Clean simulation',
                      default=False)
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32, sfd',
                      required=False,default="mth64", choices=['sherman', 'mth32', 'mth64', 'sfd'])
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='sanity-scripts/sanity_scripts.txt')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default='DT')
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default='DT')
    parser.add_argument('-r', '--run_sanity', action='store_true', help='Run Sanity',
                      default=False)
    parser.add_argument('--cicd', action='store_true', help='Use CICD related parameters',
                      default=False)
    parser.add_argument('--cicd_clean', action='store_true', help='Clean at the end of CICD run',
                      default=False)    
    parser.add_argument('--create_allure_report', action='store_true', help='When testing, specify if allure report to be created at the end of test',
                      default=False)            
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

    chan.send("docker run -v $PWD:/data --privileged --network host --name 'docker-sonic-mgmt' -itd docker-sonic-mgmt-vxr bash \n")
    buff = ''
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)


    ssh.close()

def deploy_mg(data,topo_type,base_topo_file):
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
        overwrite_lab_file(data)
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
        print('Hit %s' % e)
    finally:
        print(buff)

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
        ssh.connect(host, port, user, passwd)
    except paramiko.ssh_exception.AuthenticationException:
        ssh.connect(host, port, user, new_passwd)

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
    ssh.connect(host, port, user, passwd)
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
        ssh.connect(host, port, user, passwd)
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
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.get('/home/vxr/sonic-test/sonic-mgmt/ansible/minigraph/{}.{}.xml'.format(dut_name,topo_type), 'minigraph.xml')
    ftp_client.close()
    ssh.close()

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
    #ftp_client.put('run_scripts.py','sonic-test/sonic-mgmt/tests/run_scripts.py')
    #ftp_client.put('sanity_scripts.txt','sonic-test/sonic-mgmt/tests/sanity_scripts.txt')
    ftp_client.put(base_topo_file,'golden-code/sonic-test/sonic-mgmt/ansible/{}'.format(base_topo_file))
    ftp_client.put('testbed_add_vm_topology.yml','golden-code/sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
    ftp_client.put('password.txt','golden-code/sonic-test/sonic-mgmt/ansible/password.txt')
    ftp_client.put('veos.yml','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
    if device_type == 'mth32':
        ftp_client.put('lab_connection_graph_mth32.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv ')
        ftp_client.put('sonic_lab_devices_mth32.csv','golden-code/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    elif device_type == 'dualtor_mth64':
        ftp_client.put('lab_connection_graph_dualtor_mth64.xml','golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
    elif device_type == 'sfd' and topo_type == 't2-min':
        ftp_client.put('lab_connection_graph_t2_2lc_min.xml', 'golden-code/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('topo_8800-LC-48H-O.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_8800-LC-48H-O.yml')
        ftp_client.put('topo_8800-RP-O.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_8800-RP-O.yml')
        ftp_client.put('topo_t2_2lc_min_ports-masic.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t2_2lc_min_ports-masic.yml')
    if topo_type in ['t0', 'dualtor-56']:
        ftp_client.put('t0-leaf.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t0-leaf.j2')
    elif topo_type == 't1':
        ftp_client.put('t1-spine.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-spine.j2')
        ftp_client.put('t1-tor.j2','golden-code/sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-tor.j2')
        ftp_client.put('topo_t1.yml', 'golden-code/sonic-test/sonic-mgmt/ansible/vars/topo_t1.yml')
    ftp_client.close()

def upload_sanity_file(data,script_file):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.put(script_file,'golden-code/sonic-test/sonic-mgmt/tests/{}'.format(script_file.rsplit('/', 1)[-1]))
    ftp_client.close()

def get_report_file(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    #ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/full_report.txt','full_report.txt')
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/test-results.xml.html','test-results.xml.html')
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/report.html','report.html')
    ftp_client.close() 

def replace_dut_mgmt_address(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for dut_name in get_dut_names(data):
        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'])
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

        ssh.connect(data[dut_name]['HostAgent'], data[dut_name]['xr_redir22'], data[dut_name]['uname'], data[dut_name]['passwd'])
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

def add_ptf_backplane_addr(data):
    cmd_list = list()
    cmd_list.append('ip address add 10.10.246.254/24 dev backplane')
    cmd_list.append('ip -6 address add fc0a::ff/64 dev backplane')
    cmd_list.append('for i in {0..%s}; do /sbin/ifconfig eth$i mtu 9216 up; done' % data['ptf_intf_count'])
    run_exec_cmds(data['docker_ptf']['HostAgent'], data['docker_ptf']['xr_redir22'], 'root', 'root', cmd_list)

def add_vEOS_cfg(data):
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

    chan.send('./testbed-cli.sh -t testbed.csv -m veos add-topo docker-ptf password.txt\n')
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
        print('Hit %s' % e)
    #finally:
    #    print(buff)

    chan.send('./testbed-cli.sh -t testbed.csv -m veos announce-routes docker-ptf password.txt\n')
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
        print('Hit %s' % e)

    ssh.close()

def run_scripts(data,script_file,drop_version,log_dir,device_type,create_allure_report):

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

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    if os.getenv("MODE"):
        sanity_mode = os.getenv("MODE").replace("_", "")
    elif os.getenv("SANITY_MODE"):
        sanity_mode = os.getenv("SANITY_MODE").replace("_", "")
    else:
        sanity_mode = ""

    sanity_index = os.getenv("SANITY_INDEX")
    if os.getenv("JOB_BASE_NAME"):
        job_base_name = os.getenv("JOB_BASE_NAME").replace("_", "")
    else:
        job_base_name = ""
    if os.getenv("TIMESTAMP"):
        timestamp = re.sub(r'[^a-zA-Z0-9]', '', os.getenv("TIMESTAMP"))
    else:
        timestamp = ""
    
    build_id = os.getenv("BUILD_ID")
    if build_id is None:
        build_id = 99999

    if sanity_index:
        build_project_name = "sonic-{}-{}-{}-{}-{}".format(job_base_name, build_id, sanity_mode, sanity_index, timestamp)
    else:
        build_project_name = "sonic-{}-{}-{}-{}".format(job_base_name, build_id, sanity_mode, timestamp)

    build_project_name = build_project_name.lower()

    print("calling run_scripts.py, the allure report build name is ", build_project_name)

    delta1 = datetime.datetime.now()
    tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")
    if create_allure_report:
        chan.send('./run_scripts.py  -s {} -v {} -l {} -d {} -t {} -b {} --create_allure_report |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp,build_project_name))
    else:
        chan.send('./run_scripts.py  -s {} -v {} -l {} -d {} -t {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp))
    time.sleep(3)
    resp = chan.recv(9999)

    chan.send('exit\n')
    time.sleep(10)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    result_file = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    later = datetime.datetime.now() + datetime.timedelta(hours=20)
    while True:
        chan.send('ps -ef | grep run_scripts.py\n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))

        if script_file in resp.decode("ascii"):
            time.sleep(150)
            chan.send('cat /data/tests/{} \n'.format(result_file))
            time.sleep(3)
            resp = chan.recv(9999)
            print(resp.decode("ascii"))
            if datetime.datetime.now() < later:
                time.sleep(150)
            else:
                print("Looks like test is taking longer than six hours. Check list of sanity scripts or increase time to wait")
                break
        else:
            break
    
    chan.send('cat /data/tests/{} \n'.format(result_file))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))
    if "Exiting" in resp.decode("ascii"):
        run_status = False
    else:
        run_status = True
    ssh.close()
    delta2 = datetime.datetime.now()
    time_delta = (delta2 - delta1)
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60

    print("Total run time for sanity suite: {} mins".format(minutes))
    return run_status

def parse_report(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/report.txt','report.txt')
    ftp_client.close()
    ssh.close()

    read_report = open('report.txt', 'r')
    report_file = open('full_report.txt', 'w')
    out = read_report.read().splitlines()
    total, passed, fail, skip, error, xfail = 0, 0, 0, 0, 0, 0
    for line in out:
        if 'total' not in line.lower():
            continue
        print(line)
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

def create_report_html(data,log_dir):
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

    chan.send('python3 ~/golden-code/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o ~/golden-code/sonic-test/sonic-mgmt/tests/results.json \
        --directory ~/golden-code/sonic-test/sonic-mgmt/tests/{} > ~/golden-code/sonic-test/sonic-mgmt/tests/report.txt \n'.format(log_dir))
    time.sleep(3)
    
    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{} --merge ~/golden-code/sonic-test/sonic-mgmt/tests/DT/test-results.xml\n'.format(log_dir))
    time.sleep(3)

    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --report-matrix ~/golden-code/sonic-test/sonic-mgmt/tests/report.html\n'.format(log_dir))
    time.sleep(3)

    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --summary-matrix\n'.format(log_dir))
    time.sleep(3)

    ssh.close()

def get_log_files(data,log_dir):

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

    chan.send("cd golden-code/sonic-test/sonic-mgmt/tests/{} \n".format(log_dir))
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("tar -cvf sanity_logs.tar * \n")
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("gzip sanity_logs.tar \n")
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    ftp_client=ssh.open_sftp()
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/{}/sanity_logs.tar.gz'.format(log_dir),'sanity_logs.tar.gz')
    ftp_client.close() 
    ssh.close()

# The lab file generated by TestbedProcessing.py does not work well for T2-2lc-min topology
# We still run TestbedProcessing.py to generate other important output files
# But then we overwrite the lab file with our own (in YAML instead of ini, for readability)
def overwrite_lab_file(vxr_ports):
    environment = Environment(loader=FileSystemLoader("lab-templates"))
    template = environment.get_template("t2-2lc-min-ports.yaml.j2")
    upload_file_stream(
        vxr_ports,
        template.render(vxr_ports=vxr_ports),
        "/home/vxr/golden-code/sonic-test/sonic-mgmt/ansible/lab"
    )

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
    create_allure_report = args['create_allure_report']

    ptf_intfcount = 32
    if device_type == 'sherman':
        dut_platform = "sherman"
    elif device_type == 'sfd':
        dut_platform = 'sfd'
    else:
        dut_platform = "mathilda"

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
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t0.yaml'
        else:
            base_topo_file = 'testbed-mth32-t0.yaml'
    elif topo_type == 't1':
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t1.yaml'
        else:
            base_topo_file = 'testbed-mth32-t1.yaml'
        os.system("cp sonic_t1_topo/* .")
        vEOS_count = 32
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
        else:
            base_topo_file = 'testbed-mth64-t0-64.yaml'

    print("USING BASE TOPO {}".format(base_topo_file))

    input_file = args['input_file']

    delta1 = datetime.datetime.now()
    vxr_path = "/auto/vxr/pyvxr/pyvxr-latest/vxr.py"
    if cicd:
        vxr_path = "python3.8 /auto/vxr/pyvxr/pyvxr-latest/vxr.py" 

    if input_file is None:
        if clean_sim:
            os.system("{} clean".format(vxr_path))

        os.system("bash -c '{} start {} |& tee sim_op.log'".format(vxr_path, topo_yaml))
        
        sim_output = subprocess.check_output("grep -i 'sim up' sim_op.log | wc -l", shell=True).strip()
        if not int(sim_output):
            sys.exit("Sim is not up. Exiting now")
        os.system("{} ports > vxr_ports.yaml".format(vxr_path))
        input_file = "vxr_ports.yaml"
    delta2 = datetime.datetime.now()

    with open(input_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    for dut_name in get_dut_names(data):
        data[dut_name]['uname'] = dut_uname
        data[dut_name]['passwd'] = dut_passwd

    data['tar_ball'] = tar_ball
    data['ptf_intf_count'] = ptf_intfcount

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
    upload_tb_files(data,topo_type,base_topo_file,device_type)

    # Change DUT password and set mgmt ip address
    for dut_name in get_dut_names(data):
            print("********** Change DUT password for DUT #{} and set mgmt ip address ***********".format(dut_name))
            change_dut_passwd(data[dut_name])

    # Start docker container, deploy DUT minigraph
    print("********** Start docker container, deploy DUT minigraph ***********")
    deploy_mg(data,topo_type,base_topo_file)

    # Add vEOS config
    print("********** Add vEOS config ***********")
    add_vEOS_cfg(data)

    print("********** Configure PTF backplane ip address **********")
    add_ptf_backplane_addr(data)

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
        print("./run_tests.sh -n docker-ptf -d sherman-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    else:
        print("Device name is mth32 or m64. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    print("******************************************************************************************************************************************************************************\n")

    delta3 = datetime.datetime.now()

    if run_sanity:
        print("Upload Sanity Script file")
        upload_sanity_file(data,script_file)
        print("Running Sanity Scripts : {}".format(script_file.rsplit('/', 1)[-1]))
        run_result = run_scripts(data,script_file.rsplit('/', 1)[-1],drop_version,log_dir,device_type,create_allure_report)
        delta4 = datetime.datetime.now()
        if run_result:
            create_report_html(data,log_dir)
            parse_report(data)
            get_report_file(data)
            get_log_files(data,log_dir)
        else:
            report_file = open('full_report.txt', 'w')
            report_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")
            report_file.flush()
            report_file.close()
            print("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")

    sim_time_delta = (delta2 - delta1).total_seconds()
    profile_time_delta = (delta3 - delta2).total_seconds()
    if run_sanity:
        sanity_time_delta = (delta4 - delta3).total_seconds()

    print("******************************************************************************************************************************************************************************\n")
    print("Time taken for the sim to come up: {} mins".format(sim_time_delta/60))
    print("Time taken for the profile to come up: {} mins".format(profile_time_delta/60))
    if run_sanity:
        print("Time taken for the sanity tests to run : {} mins".format(sanity_time_delta/60))
        if not run_result:
            print("Sanity run unsuccesful !!!, Check log files for more details")
    print("******************************************************************************************************************************************************************************\n")

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
    else:
        print("Device name is mth32. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_fact.py |& tee bgp_fact.log\n")
    print("******************************************************************************************************************************************************************************\n")

    if cicd_clean:
        print("****** Clearing SIM at the end of CICD run ******** ")
        os.system("{} clean".format(vxr_path))


if __name__ == '__main__':
  main()
