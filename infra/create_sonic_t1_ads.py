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

def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-i', '--input_file', type=str, help='Input port file',
                      required=False,default=None)
    parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file',
                      required=True,default=None)
    parser.add_argument('-t', '--topo_type', type=str, help='topo type',
                      required=True,default='t1')
    parser.add_argument('-p', '--dut_passwd', type=str, help='Dut password, when it is different from YourPaSsWoRd',
                      required=False,default="YourPaSsWoRd")
    parser.add_argument('-u', '--dut_uname', type=str, help='Dut username, when it is different from admin',
                      required=False,default="admin")
    parser.add_argument('-c', '--clean_sim', action='store_true', help='Clean simulation',
                      default=False)
    return parser


def deploy_mg(data):
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

    chan.send('python TestbedProcessing.py -i testbed-sherman-t1.yaml \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('./testbed-cli.sh -t testbed.csv gen-mg docker-ptf lab group_vars/lab/secrets.yml\n')
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


def create_testbed_file(data,base_topo_file,vEOS_count):    
    input_file = base_topo_file
    with open(input_file) as f:
        tdata = yaml.load(f, Loader=yaml.FullLoader)
        f.close()

    tdata['devices']['sherman-01']['ansible']['ansible_host'] = data['sonic_dut']['xr_mgmt_ip']
    tdata['devices']['sherman-01']['ansible']['ansible_ssh_user'] = data['sonic_dut']['uname']
    tdata['testbed']['docker-ptf']['ansible']['ansible_host'] = data['ptf']['xr_mgmt_ip'] + '/24'
    tdata['testbed']['docker-ptf']['ptf_ip'] = data['ptf']['xr_mgmt_ip'] + '/24'
    base = 100

    for i in range (1,vEOS_count+1):
        tdata['veos']['vms_1']['VM0' + str(base)]['ansible_host'] = data['veos'+str(i)]['xr_mgmt_ip']
        base +=1

    with open(input_file,'w') as f:
        yaml.dump(tdata,f)
        f.close()

def change_dut_passwd(data):
    host = data['sonic_dut']['HostAgent']
    port = data['sonic_dut']['xr_redir22']
    user = data['sonic_dut']['uname']
    passwd = data['sonic_dut']['passwd']
    #passwd = "cisco123"
    new_passwd = "cisco123"
    mgmt_ip = data['sonic_dut']['xr_mgmt_ip']

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

def download_mg(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.get('/home/vxr/sonic-test/sonic-mgmt/ansible/minigraph/sherman-01.t1.xml', 'minigraph.xml')
    ftp_client.close()
    ssh.close()

def upload_tb_files(data,topo_type):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    if topo_type == 't0':
        ftp_client.put('testbed_add_vm_topology.yml','sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
        ftp_client.put('password.txt','sonic-test/sonic-mgmt/ansible/password.txt')
        ftp_client.put('veos.yml','sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
        ftp_client.put('testbed-sherman-t0.yaml','sonic-test/sonic-mgmt/ansible/testbed-sherman-t1.yaml')
        ftp_client.put('topo_t0.yml', 'sonic-test/sonic-mgmt/ansible/vars/topo_t1.yml')
    else:
        ftp_client.put('testbed_add_vm_topology.yml','sonic-test/sonic-mgmt/ansible/testbed_add_vm_topology.yml')
        ftp_client.put('password.txt','sonic-test/sonic-mgmt/ansible/password.txt')
        ftp_client.put('t1-spine.j2','sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-spine.j2')
        ftp_client.put('t1-tor.j2','sonic-test/sonic-mgmt/ansible/roles/eos/templates/t1-tor.j2')
        ftp_client.put('veos.yml','sonic-test/sonic-mgmt/ansible/roles/eos/tasks/veos.yml')
        ftp_client.put('testbed-sherman-t1.yaml','sonic-test/sonic-mgmt/ansible/testbed-sherman-t1.yaml')
        ftp_client.put('topo_t1.yml', 'sonic-test/sonic-mgmt/ansible/vars/topo_t1.yml')
    ftp_client.close()

def replace_dut_mgmt_address(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_dut']['HostAgent'], data['sonic_dut']['xr_redir22'], data['sonic_dut']['uname'], data['sonic_dut']['passwd'])
    ftp_client=ssh.open_sftp()
    ftp_client.get('/tmp/config_db.json','config_db_current.json')
    ftp_client.close()
    ssh.close()
    
    with open('config_db_current.json') as cfg_file:
        cfg_data = json.load(cfg_file)
        current_mgm_intf = cfg_data["MGMT_INTERFACE"]
        print(cfg_data["MGMT_INTERFACE"])
        cfg_file.close()

    with open('config_db.json') as cfg_file:
        cfg_data = json.load(cfg_file)
        cfg_file.close()
        
    with open('config_db.json','w') as cfg_file:
        cfg_data["MGMT_INTERFACE"] = current_mgm_intf
        json.dump(cfg_data, cfg_file, indent=4)
        cfg_file.close()

    ssh.connect(data['sonic_dut']['HostAgent'], data['sonic_dut']['xr_redir22'], data['sonic_dut']['uname'], data['sonic_dut']['passwd'])
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
    run_exec_cmds(data['sonic_dut']['HostAgent'], data['sonic_dut']['xr_redir22'], data['sonic_dut']['uname'], data['sonic_dut']['passwd'], cmd_list)

def add_ptf_backplane_addr(data):
    cmd_list = list()
    cmd_list.append('ip address add 10.10.246.254/24 dev eth32')
    cmd_list.append('ip -6 address add fc0a::ff/64 dev eth32')
    cmd_list.append('for i in {0..32}; do /sbin/ifconfig eth$i mtu 9216 up; done')
    run_exec_cmds(data['ptf']['HostAgent'], data['ptf']['xr_redir22'], 'root', 'root', cmd_list)

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


def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    topo_yaml = args['topo_yaml']
    clean_sim = args['clean_sim']
    dut_passwd = args['dut_passwd']
    dut_uname = args['dut_uname']
    topo_type = args['topo_type']
    if topo_type == 't0':
        base_topo_file = 'testbed-sherman-t0.yaml'
        vEOS_count = 4
    else:
        base_topo_file = 'testbed-sherman-t1.yaml'
        vEOS_count = 32

    if clean_sim:
        os.system("/auto/vxr/pyvxr/pyvxr-0.6.2/vxr.py --cmd clean")
    os.system("cp sonic_t1_topo/* .")
    os.system("/auto/vxr/pyvxr/pyvxr-0.6.2/vxr.py --cmd start {}".format(topo_yaml))
    os.system("/auto/vxr/pyvxr/pyvxr-0.6.2/vxr.py --cmd ports > vxr_ports.yaml")
    input_file = args['input_file']
    
    if input_file is None:
        input_file = "vxr_ports.yaml"

    with open(input_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
      
    data['sonic_dut']['uname'] = dut_uname
    data['sonic_dut']['passwd'] = dut_passwd

    # Create admin user in vEOS vm
    print("****** Create admin user in vEOS vm *******")
    vEOS_inital_cfg(data,vEOS_count)

    # Create testbed file based on vxr_ports 
    print("****** Create testbed file based on vxr_ports *******")
    create_testbed_file(data,base_topo_file,vEOS_count)

    # Upload t1 specific files to sonic mgmt container
    print("********** Upload testbed specific files to sonic mgmt container ***********")
    upload_tb_files(data,topo_type)

    # Change DUT password and set mgmt ip address
    print("********** Change DUT password and set mgmt ip address ***********")
    change_dut_passwd(data)

    # Start docker container, deploy DUT minigraph
    print("********** Start docker container, deploy DUT minigraph ***********")
    deploy_mg(data)

    # Start docker container, deploy DUT minigraph
    print("********** Download DUT minigraph ***********")
    download_mg(data)

    # Replace DUT Mgmt Address
    print("********** Replace DUT Mgmt Address ***********")
    replace_dut_mgmt_address(data)

    # Reload DUT config
    print("********** Reload DUT config ***********")
    reload_dut_with_newCFG(data)

    # Add vEOS config
    print("********** Add vEOS config ***********")
    add_vEOS_cfg(data)

    print("********** Configure PTF backplane ip address **********")
    add_ptf_backplane_addr(data)

    print("Sonic DUT:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_dut']['HostAgent'], data['sonic_dut']['serial0'], data['sonic_dut']['xr_mgmt_ip'], data['sonic_dut']['xr_redir22']))

    print("Sonic Mgmt:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['serial0'], data['sonic_mgmt']['xr_mgmt_ip'], data['sonic_mgmt']['xr_redir22']))

    print("PTF:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(data['ptf']['HostAgent'], data['ptf']['serial0'], data['ptf']['xr_mgmt_ip'], data['ptf']['xr_redir22']))

    for i in range (1,vEOS_count+1):
        print("VEOS{}:  Tlnt: {}   Tlnt Port: {}  SSH: {}   SSH Port: {}".format(str(i-1), data['veos'+ str(i)]['HostAgent'], data['veos'+ str(i)]['serial0'], data['veos'+ str(i)]['xr_mgmt_ip'], data['veos'+ str(i)]['xr_redir22'] ))


if __name__ == '__main__':
  main()
