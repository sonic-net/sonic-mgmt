# This file contains the list of API's for operations on Chef
# @author : Chandra B S (chandra.singh@broadcom.com)
from spytest import st

import apis.system.connection as con_obj
import utilities.utils as utils_obj
import apis.system.basic as basic_obj
import apis.system.ntp as ntp_obj

chef_client_file = r"/etc/chef/client.rb"

from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient

#needed
def copy_files_to_server(server_ip,username,password,src_file):
    ssh = SSHClient()
#    ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(server_ip, username=username, password=password)
    ssh.exec_command('sudo -i')
    scp = SCPClient(ssh.get_transport())
    scp.put(src_file)


#needed
def config_chef(chef_conn_obj, **kwargs):
    if not chef_conn_obj or not kwargs.get('action'):
        return False
    cmd = "sudo -i"
    con_obj.execute_command(chef_conn_obj, cmd)
    action = kwargs['action']
    if action == 'copy_files':
        cmd = 'mv {} {}'.format(kwargs['src_file'], kwargs['dst_file'])
        con_obj.execute_command(chef_conn_obj, cmd)

#needed
def run_chef_client(dut, duration=0, args=''):
    """
    :param dut:
    :param duration:
    :return:
    """
    iterations = ""
    if duration:
        iterations = "-i {}".format(duration)
    command = "chef-client -l info {} {}".format(iterations, args).strip()
    st.log("Remote Command: {}".format(command))
    try:
        st.config(dut, command)
    except ValueError as e:
        st.log(e)
        return False
    return True

#needed
def delete_client_pem_files(dut, path, file_name=None):
    """
    :param dut:
    :param files_path:
    :return:
    """
    if file_name:
        command = "sudo rm -rf {}/{}".format(path,file_name)
        result = st.config(dut, command)
        return result
    else:
        command = "sudo rm -rf {}/{}".format(path,"client.pem")
        st.config(dut, command)
        command = "sudo rm -rf {}/{}".format(path,"validation.pem")
        result = st.config(dut, command)
        return result

#needed
def generate_certs(chef_conn_obj, repo_path):
    if not chef_conn_obj:
        return False
    command = "sudo -i"
    con_obj.execute_command(chef_conn_obj, command)
    command = "cd {}".format(repo_path)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "./gencert.sh"
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    st.wait(5)

#needed
def bootstrap_chef_node(chef_conn_obj, repo_path, device_ip, uname, password, node_name):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False

    ssh_obj = con_obj.connect_to_device(device_ip, uname, password)
    if not ssh_obj:
        password = 'YourPaSsWoRd'

    command = "cd {}".format(repo_path)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "sudo knife bootstrap {} -x {} -P {} --sudo --ssh-verify-host-key never --node-ssl-verify-mode none -N {}"\
                        .format(device_ip, uname, password ,node_name)
    st.log("Remote Command: {}".format(command))
    return con_obj.execute_command(chef_conn_obj, command)

#needed
def delete_chef_node(chef_conn_obj, node_name="testsonic", role_name=None):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "knife node delete {} -y".format(node_name)
#    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "knife client delete {} -y".format(node_name)
#    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    if role_name:
        command = "knife role delete {} -y".format(role_name)
        con_obj.execute_command(chef_conn_obj, command)


#needed
def upload_chef_cookbook(chef_conn_obj, path, file_name="sonic.json"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "cd {}; knife upload cookbooks/sonic".format(path)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)


#needed
def upload_role_chef_server(chef_conn_obj, role_dir, file_name="sonic.json"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "cd {}".format(role_dir)
    con_obj.execute_command(chef_conn_obj, command)
    command = "sudo knife role from file {}".format(file_name)
    st.log("Remote Command: {}".format(command))
    out = con_obj.execute_command(chef_conn_obj, command)
    if not out:
        return False
    console_log = utils_obj.remove_last_line_from_string(out)
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        return False
    return True

#needed
def update_node_run_list(chef_conn_obj, node, recipe_role, action='add'):
    """
    :param chef_conn_obj:
    :param client_ip:
    :param recipe_role:
    :return:
    """
    if not chef_conn_obj:
        return False
#    client_ip = client_ip.replace(".", "-")
    command = "knife node run_list {} {} '{}'".format(action, node, recipe_role)
    st.log("Remote Command: {}".format(command))
    out = con_obj.execute_command(chef_conn_obj, command)
    if not out:
        return False
    console_log = utils_obj.remove_last_line_from_string(out)
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        return False
    return True

def show_node_run_list(chef_conn_obj, node_name="sonic"):
    """
    :param chef_conn_obj:
    :param node_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "knife node show {} run_list".format(node_name)
    st.log("Remote Command: {}".format(command))
    out = con_obj.execute_command(chef_conn_obj, command)
    if not out:
        return False
    console_log = utils_obj.remove_last_line_from_string(out)
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        st.log(console_log)
        return False
    return True

#needed
def chef_package_install(dut, url, ip, username='admin', password='broadcom', altpassword='YourPaSsWoRd'):
    """
    Install CHEF package to the DUT with CHEF server url.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param url:
    :param ip:
    :param username:
    :param password:
    :return:
    """
    if basic_obj.verify_package(dut, 'chef'):
        return True
    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if not ssh_obj:
        ssh_obj = con_obj.connect_to_device(ip, username, altpassword, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = "apt-get install chef -y"
        st.log(ssh_obj.send_command(command, expect_string=r"URL of Chef server:\s*"))
        command = "{}".format(url)
        st.log(ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt)))
        con_obj.ssh_disconnect(ssh_obj)
        return True
    else:
        con_obj.ssh_disconnect(ssh_obj)
        st.log("SSH to DUT is failed - Failed to install the chef package ")
        return False

#needed
def sync_with_server_time(dut_list, ip, username, password):
    """
    To Sync DUT with the CHEF server time.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ip:
    :param username:
    :param password:
    :return:
    """
    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = "date"
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        if not output:
            return False
        st.log(output)
        date = utils_obj.remove_last_line_from_string(output)
        con_obj.ssh_disconnect(ssh_obj)
        st.log("Server Time : {}".format(date))
        for dut in dut_list:
            ntp_obj.config_date(dut, date)
        return True
    else:
        con_obj.ssh_disconnect(ssh_obj)
        st.log("SSH to Server is failed - failed to sync time between DUT and CHEF Server")
        return False


