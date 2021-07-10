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

# Return a list that only contains the entries in 'data' whose keys start with 'sonic_dut_'
def get_dut_entries(data):
    # N.B. for some reason tuple expansion with dict.items() does not work here
    return [data[key] for key in data if key.startswith('sonic_dut_')]

def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-i', '--input_file', type=str, help='Input port file',
                      required=False,default=None)
    parser.add_argument('-b', '--branch', type=str, help='Specify git branch',
                      required=False,default="master")
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=True,default=None)
    parser.add_argument('-t', '--topo_type', type=str, help='topo type',
                      required=True,default='t1', choices=['t0', 't1', 'dualtor-56'])
    parser.add_argument('-p', '--dut_passwd', type=str, help='Dut password, when it is different from YourPaSsWoRd',
                      required=False,default="YourPaSsWoRd")
    parser.add_argument('-u', '--dut_uname', type=str, help='Dut username, when it is different from admin',
                      required=False,default="admin")
    parser.add_argument('-c', '--clean_sim', action='store_true', help='Clean simulation',
                      default=False)
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32',
                      required=False,default="mth32")
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='sanity_scripts.txt')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default='DT7')
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default='DT7')
    parser.add_argument('-r', '--run_sanity', action='store_true', help='Run Sanity',
                      default=False)
    return parser

def git_update(data):
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

    chan.send("cd sonic-test \n")
    buff = ''
    while not buff.endswith(':~/sonic-test$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("git config --global user.email 'sonic-test@cisco.com'; git config --global user.name 'Sonic Test'; git stash; git pull; git checkout {}; git stash apply\n".format(data['branch']))
    buff = ''
    while not buff.endswith(':~/sonic-test$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(20)

    ssh.close()

def deploy_mg(data,base_topo_file):
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

    chan.send("docker container start docker-sonic-mgmt \n")
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

    chan.send('python TestbedProcessing.py -i {} \n'.format(base_topo_file))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

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


def create_testbed_file(data,base_topo_file,vEOS_count, dut_name, dut_prefix):
    input_file = base_topo_file
    with open(input_file) as f:
        tdata = yaml.load(f, Loader=yaml.FullLoader)
        f.close()

    # Find each device listed in the VXR topology that starts with "sonic_dut_"
    for vxr_device in data.keys():
        if vxr_device.startswith('sonic_dut_'):
            # 0-indexed id parsed from 'sonic_dut_{}' devices in VXR topo file
            dut_id = vxr_device.split('_')[-1]
            # 'matilda-0', 'matilda-1', etc, from non-VXR topo file
            dut_name = "{}-{}".format(dut_prefix, dut_id)

            tdata['devices'][dut_name]['ansible']['ansible_host'] = data[vxr_device]['xr_mgmt_ip']
            tdata['devices'][dut_name]['ansible']['ansible_ssh_user'] = data[vxr_device]['uname']
            tdata['testbed']['docker-ptf']['ansible']['ansible_host'] = data['docker_ptf']['xr_mgmt_ip'] + '/24'
            tdata['testbed']['docker-ptf']['ptf_ip'] = data['docker_ptf']['xr_mgmt_ip'] + '/24'
    base = 100

    for i in range (1,vEOS_count+1):
        tdata['veos']['vms_1']['VM0' + str(base)]['ansible_host'] = data['veos'+str(i)]['xr_mgmt_ip']
        base +=1

    with open(input_file,'w') as f:
        yaml.dump(tdata,f)
        f.close()

def change_dut_passwd(dut_entry):
    #TODO this needs to be reworked to allow multiple "sonic_dut" entries
    #for (entry_key, entry_value) in data.items():
    #    if entry_key.startswith('sonic_dut_'):
    host = dut_entry['HostAgent']
    port = dut_entry['xr_redir22']
    user = dut_entry['uname']
    passwd = dut_entry['passwd']
    #passwd = "cisco123"
    new_passwd = "cisco123"
    mgmt_ip = dut_entry['xr_mgmt_ip']

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

def upload_tb_files(data,topo_type,base_topo_file,device_type):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    #ftp_client.put('run_scripts.py','sonic-test/sonic-mgmt/tests/run_scripts.py')
    #ftp_client.put('sanity_scripts.txt','sonic-test/sonic-mgmt/tests/sanity_scripts.txt')
    if device_type == 'mth32':
        ftp_client.put('lab_connection_graph_mth32.xml','sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml')
        ftp_client.put('sonic_lab_links_mth32.csv','sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv ')
        ftp_client.put('sonic_lab_devices_mth32.csv','sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv')
    if topo_type in ['t0', 'dualtor-56']:
        ftp_client.put('testbed_add_vm_topology.yml','sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
        ftp_client.put('password.txt','sonic-test/sonic-mgmt/ansible/password.txt')
        ftp_client.put('veos.yml','sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
        ftp_client.put(base_topo_file,'sonic-test/sonic-mgmt/ansible/{}'.format(base_topo_file))
        ftp_client.put('t0-leaf.j2','sonic-test/sonic-mgmt/ansible/roles/eos/templates/t0-leaf.j2')
    else:
        ftp_client.put('testbed_add_vm_topology.yml','sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
        ftp_client.put('password.txt','sonic-test/sonic-mgmt/ansible/password.txt')
        ftp_client.put('t1-spine.j2','sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-spine.j2')
        ftp_client.put('t1-tor.j2','sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-tor.j2')
        ftp_client.put('veos.yml','sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
        ftp_client.put(base_topo_file,'sonic-test/sonic-mgmt/ansible/{}'.format(base_topo_file))
        ftp_client.put('topo_t1.yml', 'sonic-test/sonic-mgmt/ansible/vars/topo_t1.yml')
    ftp_client.close()

def replace_dut_mgmt_address(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(dut_entry['HostAgent'], dut_entry['xr_redir22'], dut_entry['uname'], dut_entry['passwd'])
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

    ssh.connect(dut_entry['HostAgent'], dut_entry['xr_redir22'], dut_entry['uname'], dut_entry['passwd'])
    ftp_client=ssh.open_sftp()
    ftp_client.put('config_db.json','/tmp/config_db_new.json')
    ftp_client.put('minigraph.xml', '/tmp/minigraph.xml')
    ftp_client.close()
    ssh.close()

def reload_dut_with_newCFG(data):
    cmd_list = list()
    cmd_list.append('sudo cp /tmp/config_db_new.json /etc/sonic/config_db.json\n')
    cmd_list.append('sudo cp /tmp/minigraph.xml /etc/sonic/minigraph.xml\n')
    cmd_list.append('sudo reboot\n')
    run_exec_cmds(dut_entry['HostAgent'], dut_entry['xr_redir22'], dut_entry['uname'], dut_entry['passwd'], cmd_list)

def add_ptf_backplane_addr(data):
    cmd_list = list()
    cmd_list.append('ip address add 10.10.246.254/24 dev eth32')
    cmd_list.append('ip -6 address add fc0a::ff/64 dev eth32')
    cmd_list.append('for i in {0..32}; do /sbin/ifconfig eth$i mtu 9216 up; done')
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

    ssh.close()

def run_scripts(data,script_file,drop_version,log_dir,device_type):

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

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")
    chan.send('./run_scripts.py  -s {} -v {} -l {} -d {} -t {} &\n'.format(script_file,drop_version,log_dir,device_type,tstamp))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('exit \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    tcs_file = open(script_file, 'r')
    tcs = tcs_file.readlines()
    for tc in tcs:
        if '#' in tc:
            continue
        tc = tc.strip()
        tc_name = tc.split('/')
        tc_name = tc_name[len(tc_name)-1].split('.')[0]

    result_file = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    later = datetime.datetime.now() + datetime.timedelta(hours=1)
    while True:
        chan.send('cat ~/sonic-test/sonic-mgmt/tests/{} \n'.format(result_file))
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))
        if tc_name in resp.decode("ascii"):
            break
        else:
            if datetime.datetime.now() < later:
                time.sleep(300)
            else:
                print("Looks like test is taking longer than an hour. Check list of sanity scripts or increase time to wait")
                break
    ssh.close()


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
    branch = args['branch']
    if device_type == 'sherman':
        dut_name = 'sherman-01'
        dut_prefix = "sherman"
    else:
        dut_name = 'mathilda-01'
        dut_prefix = "mathilda"

    if topo_type == 't0':
        os.system("cp sonic_t0_topo/* .")
        vEOS_count = 4
        if device_type == 'sherman':
            base_topo_file = 'testbed-sherman-t0.yaml'
        else:
            base_topo_file = 'testbed-mth64-t0.yaml'
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
    print("USING BASE TOPO {}".format(base_topo_file))

    input_file = args['input_file']

    if input_file is None:
        if clean_sim:
            os.system("/auto/vxr/pyvxr/pyvxr-latest/vxr.py clean")
        os.system("/auto/vxr/pyvxr/pyvxr-1.1.1/vxr.py start {}".format(topo_yaml))
        os.system("/auto/vxr/pyvxr/pyvxr-1.1.1/vxr.py ports > vxr_ports.yaml")
        input_file = "vxr_ports.yaml"

    with open(input_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    for (entry_key, entry_value) in data.items():
        if entry_key.startswith('sonic_dut_'):
            data[entry_key]['uname'] = dut_uname
            data[entry_key]['passwd'] = dut_passwd

    data['branch'] = branch

    # Create admin user in vEOS vm
    print("****** Create admin user in vEOS vm *******")
    vEOS_inital_cfg(data,vEOS_count)

    print("********** Do a Git Update **********")
    git_update(data)

    # Create testbed file based on vxr_ports
    print("****** Create testbed file based on vxr_ports *******")
    create_testbed_file(data,base_topo_file,vEOS_count,dut_name,dut_prefix)

    # Upload t1 specific files to sonic mgmt container
    print("********** Upload testbed specific files to sonic mgmt container ***********")
    upload_tb_files(data,topo_type,base_topo_file,device_type)

    # Change DUT password and set mgmt ip address
    for (i, dut_entry) in enumerate(get_dut_entries(data)):
            print("********** Change DUT password for DUT #{} and set mgmt ip address ***********".format(i))
            change_dut_passwd(dut_entry)

    # Start docker container, deploy DUT minigraph
    print("********** Start docker container, deploy DUT minigraph ***********")
    deploy_mg(data,base_topo_file)

    # Start docker container, deploy DUT minigraph
    #print("********** Download DUT minigraph ***********")
    #download_mg(data,topo_type,,dut_name)

    # Replace DUT Mgmt Address
    #print("********** Replace DUT Mgmt Address ***********")
    #replace_dut_mgmt_address(data)

    # Reload DUT config
    #print("********** Reload DUT config ***********")
    #reload_dut_with_newCFG(data)

    # Add vEOS config
    print("********** Add vEOS config ***********")
    add_vEOS_cfg(data)

    print("********** Configure PTF backplane ip address **********")
    add_ptf_backplane_addr(data)

    for (i, dut_entry) in enumerate(get_dut_entries(data)):
        print("Sonic DUT #{} (cisco/cisco123):  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(i, dut_entry['HostAgent'], dut_entry['serial0'], dut_entry['xr_mgmt_ip'], dut_entry['xr_redir22']))

    print("Sonic Mgmt (vxr/cisco123) :  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['serial0'], data['sonic_mgmt']['xr_mgmt_ip'], data['sonic_mgmt']['xr_redir22']))

    print("PTF (root/root) :  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['docker_ptf']['HostAgent'], data['docker_ptf']['serial0'], data['docker_ptf']['xr_mgmt_ip'], data['docker_ptf']['xr_redir22']))

    print("VEOS (admin/123456): ")
    for i in range (1,vEOS_count+1):
        print("VEOS{}:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(str(i-1), data['veos'+ str(i)]['HostAgent'], data['veos'+ str(i)]['serial0'], data['veos'+ str(i)]['xr_mgmt_ip'], data['veos'+ str(i)]['xr_redir22'] ))

    print("******************************************************************************************************************************************************************************\n")
    if device_type == 'sherman':
        print("Device name is sherman. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d sherman-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    else:
        print("Device name is mth32. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    print("******************************************************************************************************************************************************************************\n")

    if run_sanity:
        print("Running Sanity Scripts")
        run_scripts(data,script_file,drop_version,log_dir,device_type)

    print("Sonic DUT (cisco/cisco123):  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(dut_entry['HostAgent'], dut_entry['serial0'], dut_entry['xr_mgmt_ip'], dut_entry['xr_redir22']))

    print("Sonic Mgmt (vxr/cisco123) :  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['serial0'], data['sonic_mgmt']['xr_mgmt_ip'], data['sonic_mgmt']['xr_redir22']))

    print("PTF (root/root) :  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['docker_ptf']['HostAgent'], data['docker_ptf']['serial0'], data['docker_ptf']['xr_mgmt_ip'], data['docker_ptf']['xr_redir22']))

    print("VEOS (admin/123456): ")
    for i in range (1,vEOS_count+1):
        print("VEOS{}:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(str(i-1), data['veos'+ str(i)]['HostAgent'], data['veos'+ str(i)]['serial0'], data['veos'+ str(i)]['xr_mgmt_ip'], data['veos'+ str(i)]['xr_redir22'] ))

    print("******************************************************************************************************************************************************************************\n")
    if device_type == 'sherman':
        print("Device name is sherman. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d sherman-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    else:
        print("Device name is mth32. To execute a pytest script:\n")
        print("./run_tests.sh -n docker-ptf -d mathilda-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\n")
    print("******************************************************************************************************************************************************************************\n")



if __name__ == '__main__':
  main()
