# This file contains the list of API's for operations on ansible
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
import re
import os
from spytest import st
from spytest.utils import filter_and_select
import apis.system.connection as con_obj


def write_ansible_host(connection_obj, host_string, inventory_path):
    """
    Add hosts to /etc/ansible/hosts hostgroup section
    :param connection_obj:
    :param host_string:
    :param inventory_path:
    :return:
    """
    if not connection_obj:
        return False
    command = "echo {} >> {}".format(host_string, inventory_path)
    con_obj.execute_command(connection_obj, command)


def copy_ssh_id(connection_obj, device_ip, username, password, key_path):
    """
    :param connection_obj:
    :param device_ip:
    :param username:
    :param password:
    :param key_path:
    :return:
    """
    if not connection_obj:
        return False
    command = "sshpass -p '{2}' ssh-copy-id -i {0} {1}@{3}".format(key_path, username, password, device_ip)
    con_obj.execute_command(connection_obj, command)

def ansible_ping_host(connection_obj, host_name, debug=False):
    """
    :param connection_obj:
    :param host_name:
    :param debug: True or False
    :return:
    """
    if not connection_obj:
        return False
    verbose=""
    if debug:
        verbose = "-vvvv"
    command = "ansible -m ping {} {}".format(host_name, verbose)
    return con_obj.execute_command(connection_obj, command)

def verify_ansible_ping_host(connection_obj, host_name):
    """
    :param connection_obj:
    :param host_name:
    :return:
    """
    if not connection_obj:
        return False
    result = ansible_ping_host(connection_obj, host_name)

    if result.find("SUCCESS") < 1:
        return False
    return True

def ansible_cmd(connection_obj, host_name, mod_string, cmd_string, option=None):
    """
    :param connection_obj:
    :param host_name:
    :param mod_string:
    :param cmd_string:
    :param option:
    :return:
    """
    if not connection_obj:
        return False
    command = "ansible -m {1} -a \"{2}\" {0}".format(host_name, mod_string, cmd_string)
    if option:
        command = "ansible -m {1} -a \"{2}\" {0} {3}".format(host_name, mod_string, cmd_string,option)
    return con_obj.execute_command(connection_obj, command)

def verify_ansible_cmd(connection_obj, host_name, mod_string, cmd_string, option=None):
    """
    :param connection_obj:
    :param host_name:
    :param mod_string:
    :param cmd_string:
    :param option:
    :return:
    """
    if not connection_obj:
        return False

    result = ansible_cmd(connection_obj, host_name, mod_string, cmd_string, option=None)

    if result.find("SUCCESS") < 1:
        return False
    return True

def copy_ansible_host_bkp(connection_obj, inventory_path, new_inventory_path):
    """
    :param connection_obj:
    :param inventory_path:
    :param new_inventory_path:
    :return:
    """
    if not connection_obj:
        return False
    command = "cp {} {}".format(inventory_path, new_inventory_path)
    con_obj.execute_command(connection_obj, command)
    return True


def ansible_play_book(connection_obj,inventory_path,playbook_name,cmd_string=None):
    """
    :param connection_obj:
    :param inventory_path:
    :param playbook_name:
    :param cmd_string:
    :return:
    """
    if not connection_obj:
        return False
    command = "sudo ansible-playbook {}/{}".format(inventory_path, playbook_name)
    if cmd_string:
        cmd_string_li = list(cmd_string) if isinstance(cmd_string, list) else [cmd_string]
        command = "sudo ansible-playbook {}/{}".format(inventory_path, playbook_name)
        for each_cmd_string in cmd_string_li:
            command += " -e {} ".format(each_cmd_string)
    return con_obj.execute_command(connection_obj, command)


def verify_ansible_playbook(connection_obj,inventory_path,playbook_name,cmd_string=None, **kwargs):
    """
    :param connection_obj:
    :param inventory_path:
    :param playbook_name:
    :param cmd_string:
    :param kwargs:
    :return:
    """
    output = ansible_play_book(connection_obj,inventory_path,playbook_name,cmd_string)
    pattern = r"(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)"
    hedder = ['host','ok','changed','unreach','fail']
    temp_list = re.findall(pattern,output)
    final_output = [{h:v  for h,v in zip(hedder,each)} for each in temp_list]
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(final_output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True



def verify_ansible_playbook_vdi(dut, playbook_name, **kwargs):
    """
    :param connection_obj:
    :param inventory_path:
    :param playbook_name:
    :param cmd_string:
    :param kwargs:
    :return:
    """
    playbook = os.path.join(os.path.dirname(__file__), "..", "..", "ansible", playbook_name)
    playbook = os.path.abspath(playbook)
    try:
        output = st.ansible_dut(dut, playbook)
    except Exception as e:
        st.log("observed exception {}".format(e))
        return False
    pattern = r"(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)"
    hedder = ['host','ok','changed','unreach','fail']
    temp_list = re.findall(pattern,output)
    final_output = [{h:v  for h,v in zip(hedder,each)} for each in temp_list]
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(final_output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True







