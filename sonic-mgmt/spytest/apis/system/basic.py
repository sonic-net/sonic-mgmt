import json
import tempfile
import os
import re
import ast
import datetime
from spytest import st
from spytest.utils import filter_and_select
from spytest.utils import exec_all
from utilities.common import delete_file
import utilities.utils as utils_obj
import apis.system.connection as conn_obj

def ensure_hwsku_config(dut):
    #TODO: call sudo config-hwsku set if present in device params
    pass

def ensure_certificate(dut):
    st.config(dut, "sudo /usr/bin/certgen admin")

def get_system_status(dut, service=None, skip_error_check=False):
    output = "???"
    try:
        output = st.show(dut, "show system status", skip_tmpl=True,
                         skip_error_check=skip_error_check)
        if "Error: Got unexpected extra argument (status)" in output:
            return None

        output = st.parse_show(dut, "show system status", output)
        if not output:
            return False
        if output[0]["status"] == "ready":
            return True
        if service and output[0][service] == "Up":
            return True
    except Exception as exp:
        msg = "Failed to read system online status output='{}' error='{}'"
        st.warn(msg.format(output, exp))
    return False


def get_swver(dut):
    """
    :param dut:
    :return:
    """
    version = show_version(dut)['version']
    return version


def get_sysuptime(dut):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    up_time = show_version(dut)['uptime']
    return up_time


def get_hwsku(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to ge the hwsku of the device.
    :param dut:
    :return:
    """
    output = st.show(dut, "show platform summary")
    if len(output) <= 0 or "hwsku" not in output[0]:
        return None
    hwsku = output[0]["hwsku"]
    return hwsku


def get_platform_summary(dut, value=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform summary")
    if value:
        if len(output) <= 0 or value not in output[0]:
            return None
        out = output[0][value]
        return out
    else:
        if output:
            return output[0]


def get_dut_date_time(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the DUT date and time
    :param dut:
    :return:
    """
    return utils_obj.remove_last_line_from_string(st.config(dut, "date"))


def get_dut_date_time_obj(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the dur date and time object
    :param dut:
    :return:
    """
    date_val = get_dut_date_time(dut)
    try:
        match = re.search('[A-Z]{2,}', date_val)
        if match:
            timezone = match.group(0)
            return datetime.datetime.strptime(date_val, '%a %b  %d %H:%M:%S {} %Y'.format(timezone))
    except Exception as e:
        st.error(e)
        return None


def get_mac_address(base_mac="00:00:00:00:00:00", start=1, end=100):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the mac addressses
    :param base_mac:
    :param start:
    :param end:
    :return:
    """
    mac_address_list = list()
    base_mac = base_mac.replace(":", '').replace(" ", '')
    mac_int = int("0x"+base_mac, 16)
    for i in range(mac_int+start, mac_int+end+1):
        mac_address = "{0:0{1}x}".format(i, 12)
        mac_formated = ":".join([mac_address[i:i+2] for i in range(0, len(mac_address), 2)])
        mac_address_list.append(mac_formated)
    return mac_address_list


def get_ifconfig(dut, interface='eth0'):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig output
    :param dut:
    :param interface:
    :return:
    """
    command = '/sbin/ifconfig'
    if interface:
        command += " {}".format(interface)
    return st.show(dut, command)


def get_ifconfig_inet(dut, interface):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig inet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "inet" not in output[0]:
        return None
    ip_addresses = output[0]['inet']
    return ip_addresses


def get_ifconfig_inet6(dut, interface):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig inet6
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "inet6" not in output[0]:
        return None
    ip_addresses = output[0]['inet6']
    return ip_addresses


def get_ifconfig_ether(dut, interface='eth0'):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig ethernet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "mac" not in output[0]:
        return None
    mac_address = output[0]['mac']
    return mac_address


def ifconfig_operation(connection_obj, interface_name, operation, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to perform operations on ifconfig interface
    :param connection_obj:
    :param interface_name:
    :param operation:
    :param device:
    :return:
    """
    command = "if{} {}".format(operation, interface_name)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_hostname(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the hostname
    :param dut:
    :return:
    """
    cmd = 'hostname'
    hostname = utils_obj.remove_last_line_from_string(st.show(dut, cmd, skip_tmpl=True))
    hostname = hostname.strip()
    if hostname.startswith(cmd+'\n'):
        hostname = hostname[len(cmd+'\n'):]
    return hostname


def whoami(connection_obj):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the whoami
    :param connection_obj:
    :return:
    """
    return utils_obj.remove_last_line_from_string(conn_obj.execute_command(connection_obj, "whoami"))


def service_operations(connection_obj, service, action="start", client="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to do the service operations
    :param connection_obj:
    :param service:
    :param action:
    :param client:
    :return:
    """
    st.log("####### Restarting {} service ########".format(service))
    command = "sudo service {} {}".format(service, action)
    if client == "dut":
        st.config(connection_obj, command)
    else:
        cnt = 1
        iteration = 4
        while True:
            response = conn_obj.execute_command(connection_obj, command)
            if response is None:
                st.log("No response received, hence retrying..")
                conn_obj.execute_command(connection_obj, command)
            if response is not None:
                st.log("Received response after executing command")
                break
            if cnt > iteration:
                st.error("Prompt not found after {} attempts".format(iteration))
                break
            cnt += 1
            st.wait(3)


def verify_service_status(dut, service, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to verify the service status
    :param dut: DUT or server
    :param service:
    :param device :
    :return:
    """
    command = "systemctl is-active {}".format(service)
    if device == "dut":
        result = st.config(dut, command)
    else:
        result = conn_obj.execute_command(dut, command)
    if utils_obj.remove_last_line_from_string(result) != "active":
        if "active" not in result or result != "inactive":
            return False
    return True


def service_operations_by_systemctl(dut, service, operation):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to do the service operations using systemctl
    :param dut:
    :param service:
    :param operation:
    :return:
    """
    command = "systemctl {} {}".format(operation, service)
    st.config(dut, command)


def copy_file_to_local_path(dut, src_path, dst_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy the file to local path
    :param dut:
    :param src_path:
    :param dst_path:
    :return:
    """
    command = "cp {} {}".format(src_path, dst_path)
    st.config(dut, command)


def delete_line_from_file(connection_obj, line_number, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to delete the line from file
    :param connection_obj:
    :param line_number:
    :param file_path:
    :param device:
    :return:
    """
    command = "sed -i -e '{}d' {}".format(line_number, file_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def write_to_file(connection_obj, content, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write to file
    :param connection_obj:
    :param content:
    :param file_path:
    :param device:
    :return:
    """
    command = "sudo echo {} >> {}".format(content, file_path)
    st.log(command)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def create_and_write_to_file_sudo_mode(dut, content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Functcion to creat and write to file
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'sudo bash -c "echo {} > {}" '.format(content, file_path)
    st.config(dut, command)


def write_to_file_sudo_mode(dut, content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write to file using sudo mode
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'sudo bash -c "echo {} >> {}" '.format(content, file_path)
    st.config(dut, command)


def verify_file_on_device(connection_obj, client_path, file_name="client.pem", device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to verify the file on device
    :param connection_obj:
    :param client_path:
    :param file_name:
    :param device:
    :return:
    """
    path = "{}/{}".format(client_path, file_name)
    command = '[ -f {} ] && echo 1 || echo 0'.format(path)
    try:
        if device == "dut":
            files_list = st.config(connection_obj, command)
        else:
            files_list = conn_obj.execute_command(connection_obj, command)
        if int(utils_obj.remove_last_line_from_string(files_list)) != 1:
            return False
        return True
    except Exception as e:
        st.log(e)
        return False


def make_dir(connection_obj, folder_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to make directory
    :param connection_obj:
    :param folder_path:
    :param device:
    :return:
    """
    command = "mkdir -p {}".format(folder_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def change_permissions(connection_obj, folder_path, permission=777, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to change permissions of the file
    :param connection_obj:
    :param folder_path:
    :param permission:
    :param device:
    :return:
    """
    command = "chmod {} {}".format(permission, folder_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def write_to_file_to_line(connection_obj, content, line, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a line in a file.
    :param connection_obj:
    :param content:
    :param line:
    :param file_path:
    :param device:
    :return:
    """
    command = "sudo sed -i '{}i {}' {}".format(line, content, file_path)
    st.log("COMMAND -- {}".format(command))
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_pwd(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Get present working directory on the device
    :param dut:
    :return:
    """
    return utils_obj.remove_last_line_from_string(st.show(dut, "pwd", skip_tmpl=True))


def write_to_file_before_line(connection_obj, content, before_line, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a file before specific line
    :param connection_obj:
    :param content:
    :param before_line:
    :param file_path:
    :param device:
    :return:
    """
    command = "sed -i '/^{}.*/i {}' {}".format(before_line, content, file_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_match_string_line_number(connection_obj, search_string, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the matching string line number
    :param connection_obj:
    :param search_string:
    :param file_path:
    :param device:
    :return:
    """
    command = "grep -hnr --color=never '{}' {}".format(search_string, file_path)
    if device == "dut":
        result = st.config(connection_obj, command)
    else:
        result = conn_obj.execute_command(connection_obj, command)
    result = utils_obj.remove_last_line_from_string(result)
    if result:
        result = str(result)
        match_string = re.search(r"(\d+):", result)
        if match_string:
            line_number = match_string.group(1)
            return line_number
    return -1


def write_update_file(connection_obj, old_string, new_string, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write the file to be updated
    :param connection_obj:
    :param old_string:
    :param new_string:
    :param file_path:
    :return:
    """
    # line_number = get_match_string_line_number(connection_obj, new_string, file_path, "server")
    replace_line_in_file(connection_obj, old_string, new_string, file_path)
    if not find_line_in_file(connection_obj, new_string, file_path):
        new_string = "{}".format(new_string)
        write_to_file_to_line(connection_obj, new_string, 51, file_path, device="server")
        # before_line = "key dhcpupdate {"
        # write_to_file_before_line(connection_obj, new_string, before_line, file_path, "server")
        if not find_line_in_file(connection_obj, new_string, file_path):
            return False
        else:
            return True
    return True


def write_to_text_file(content):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a file
    :param content:
    :return:
    """
    if content:
        src_file = tempfile.mktemp()
        src_fp = open(src_file, "w")
        src_fp.write(content)
        src_fp.close()
        return src_file


def replace_line_in_file(ssh_conn_obj, old_string, new_string, file_path,device = 'server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to replace the content in a file in a specific line
    :param ssh_conn_obj:
    :param old_string:
    :param new_string:
    :param file_path:
    :return:
    """
    command = "sudo sed -i '/^{}/ c {}' {}".format(old_string, new_string, file_path)
    if device == 'server':
        conn_obj.execute_command(ssh_conn_obj, command)
    else:
        st.config(ssh_conn_obj, command, faster_cli=False)


def replace_line_in_file_with_line_number(dut,**kwargs):
    """
    Author:Chaitanya Lohith Bollapragada
    Usage:
    This api take the file path, line number of the text in the file and the new_text to insert in.
    for example to change the ssh port number in " /etc/ssh/sshd_config"
    replace_line_in_file_with_line_number(vars.D1, line_number = 12, text = 'Port 233', file_path = '/etc/ssh/sshd_config')
    User do not have to know about previous line to change it.
    to get line number use api get_match_string_line_number(vars.D1, 'Port ', '/etc/ssh/sshd_config')
    advanced usage:
    replace_line_in_file_with_line_number(vars.D1, line_number = get_match_string_line_number(vars.D1, 'Port ', '/etc/ssh/sshd_config'),
                                          text = 'Port 233', file_path = '/etc/ssh/sshd_config')
    Assuming default device is server.
    :param dut:
    :param line_number:
    :param text:
    :param file_path:
    :return: bool
    """
    if not ('line_number' in kwargs and 'text' in kwargs and 'file_path' in kwargs):
        return False
    command = 'sed -i "{}s/.*/{}/" {}'.format(kwargs['line_number'], kwargs['text'], kwargs['file_path'])
    if 'device' not in kwargs:
        conn_obj.execute_command(dut, command)
    else:
         st.config(dut, command)
    return True


def find_line_in_file(ssh_conn_obj, search_string, file_path, device='server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to file line in  a file
    :param ssh_conn_obj:
    :param search_string:
    :param file_path:
    :return:
    """
    command = "grep -w '{}' {}".format(search_string, file_path)
    result = conn_obj.execute_command(ssh_conn_obj, command) if device == 'server' else st.config(ssh_conn_obj, command)
    if utils_obj.remove_last_line_from_string(result).find(search_string) < 1:
        return False
    return True


def check_service_status(ssh_conn_obj, service_name, status="running", device='server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to check the service status
    :param ssh_conn_obj:
    :param service_name:
    :param status:
    :return:
    """
    st.log("##### Checking {} status for {} service ######".format(status, service_name))
    command = "status {}".format(service_name)
    result = conn_obj.execute_command(ssh_conn_obj, command) if device == 'server' else st.config(ssh_conn_obj, command)
    result = utils_obj.remove_last_line_from_string(result)
    if "command not found" not in result:
        match = "start/running" if status == "running" else "stop/waiting"
        if result.find("{}".format(match)) > 1:
            return True
    else:
        command = "service --status-all | grep {}".format(service_name)
        result = conn_obj.execute_command(ssh_conn_obj, command)
        result = utils_obj.remove_last_line_from_string(result)
        operator = "+" if status == "running" else "-"
        return True if operator in result and service_name in result else False
    return False


def write_to_json_file(json_content):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to  write the json content to a file
    :param json_content:
    :return:
    """
    json_dump = json.dumps(json_content)
    parsed = json.loads(json_dump)
    chef_cookbook_json = json.dumps(parsed, indent=4, sort_keys=True)
    src_file = tempfile.mktemp()
    src_fp = open(src_file, "w")
    src_fp.write(chef_cookbook_json)
    src_fp.close()
    return src_file


def copy_file_from_client_to_server(ssh_con_obj, **kwargs):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy file from client to server
    :param ssh_con_obj:
    :param kwargs:
    :return:
    """
    try:
        import netmiko
        scp_conn = netmiko.SCPConn(ssh_con_obj)
        scp_conn.scp_transfer_file(kwargs["src_path"], kwargs["dst_path"])
        scp_conn.close()
        if "persist" not in kwargs:
            os.remove(kwargs["src_path"])
    except Exception as e:
        st.log(e)
        st.report_fail("scp_file_transfer_failed", kwargs["src_path"], kwargs["dst_path"])


def check_error_log(dut, file_path, error_string, lines=1, file_length=50, match=None):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to check the error log
    :param dut:
    :param file_path:
    :param error_string:
    :param lines:
    :param file_length:
    :return:
    """
    command = 'sudo tail -{} {} | grep "{}" | tail -{}'.format(file_length, file_path, error_string, lines)
    try:
        response = utils_obj.remove_last_line_from_string(st.show(dut, command, skip_tmpl=True, skip_error_check=True))
        result = response.find(error_string) > 1 if not match else response
        if result:
            return True
        else:
            return False
    except ValueError as e:
        st.log(e)
        return False


def poll_for_error_logs(dut, file_path, error_string, lines=1, file_length=50, iteration_cnt=10, delay=1, match=None):
    """
    API to poll for error logs
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_path:
    :param error_string:
    :param lines:
    :param file_length:
    :param iteration_cnt:
    :param delay:
    :return:
    """
    i=1
    while True:
        if check_error_log(dut, file_path, error_string, lines, file_length, match=match):
            st.log("Log found in {} iteration".format(i))
            return True
        if i > iteration_cnt:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i+=delay
        st.wait(delay)


def show_version(dut):
    """
    Get Show Version
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = 'show version'
    output = st.show(dut, command)
    if not output and st.is_dry_run(): return ""
    exclude_keys = ['repository', 'tag', 'image_id', 'size']
    rv = {each_key: output[0][each_key] for each_key in output[0] if each_key not in exclude_keys}
    return rv


def get_docker_info(dut):
    """
    Get the docker infor from the show version output
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = 'show version'
    output = st.show(dut, command)
    include_keys = ['repository', 'tag', 'image_id', 'size']
    rv = [{each_key: each_line[each_key] for each_key in each_line if each_key in include_keys} for each_line in
          output[1:]]
    return rv


def get_docker_ps(dut):
    """
    Get docker ps
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = 'docker ps --no-trunc'
    output = st.show(dut, command)
    return output


def verify_docker_ps(dut, image, **kwargs):
    """
    To verify docker ps info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param image:
    :param container_id:
    :param command:
    :param created:
    :param status:
    :param ports:
    :param names:
    :return:
    """
    output = get_docker_ps(dut)
    rv = filter_and_select(output, None, {'image': image})
    if not rv:
        st.error("No match for {} = {} in table".format('image', image))
        return False
    for each in kwargs.keys():
        if filter_and_select(rv, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True


def docker_operation(dut, docker_name, operation):
    """
    To Perform Docker operations
    Author: kesava-swamy.karedla@broadcom.com
    :param dut:
    :param docker_name:
    :param operation:
    :return:
    """
    command = 'docker {} {}'.format(operation, docker_name)
    return st.config(dut, command)


def get_memory_info(dut):
    """
    Get Memory information form TOP command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = "top -n 1 b | grep 'KiB Mem' "
    output = st.show(dut, command)
    include_keys = ['total', 'used', 'free', 'buff_cache']
    rv = {each_key:  ast.literal_eval(output[0][each_key]) for each_key in output[0] if each_key in include_keys}
    return rv


def get_top_info(dut, proc_name=None):
    """
    Get Process details from the TOP command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param proc_name: process name
    :return:
    """
    exclude_keys = ['total', 'used', 'free', 'buff_cache']
    if proc_name:
        command = "top -n 1 b | grep {}".format(proc_name)
        output = st.show(dut, command)
        rv = [{each_key: each_line[each_key] for each_key in each_line if each_key not in exclude_keys}
              for each_line in output]
        rv = filter_and_select(rv, None, {'command': proc_name})
    else:
        command = "top -n 1 b"
        output = st.show(dut, command)
        rv = [{each_key: each_line[each_key] for each_key in each_line if each_key not in exclude_keys}
              for each_line in output[1:]]
    return rv


def get_overall_cpu_util(dut, exclude_proc_name=None):
    """
    Get Over all CPU Utlization - WIP
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param exclude_proc_name: exclude proc name
    :return:
    """



def get_platform_syseeprom(dut, tlv_name=None, key='value', decode=False):
    """
    Get Platform Syseeprom
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param tlv_name:
    :param key:  value/len/code
    :return:
    """
    if decode:
        command = "sudo decode-syseeprom"
    else:
        command = "show platform syseeprom"
    output = st.show(dut, command)
    if tlv_name:
        output = filter_and_select(output, [key], {"tlv_name": tlv_name})[0][key]
    return output


def get_platform_syseeprom_as_dict(dut, tlv_name=None, key='value', decode=False):
    """
    Get Platform Syseeprom as dict
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param tlv_name:
    :param key:
    :param decode:
    :return:
    """
    rv = {}
    output = get_platform_syseeprom(dut, tlv_name=tlv_name, key=key, decode=decode)
    for each in output:
        rv[each['tlv_name']] = each[key]
    return rv


def copy_config_db_to_temp(dut, source_path, destination_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    This API is to backup config db json.
    :param dut:
    :param source_path:
    :param destination_path:
    :return:
    """
    if not verify_file_on_device(dut, "/etc/sonic", "config_db.json", "dut"):
        command = "config save -y"
        st.config(dut, command)
    copy_file_to_local_path(dut, source_path, destination_path)


def remove_file(dut, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    This API is to remove file from a specifc path
    :param dut:
    :param file_path:
    :return:
    """
    st.log("####### Removing file {} #######".format(file_path))
    command = "rm -f -- {}".format(file_path)
    st.config(dut, command)


def get_from_redis_cli(dut, **kwargs):
    """
    To get the output from redis-cli
    Author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)
    Expected input is dut and table_name/attribute
    :param dut:
    :param kwargs:
    :return:
    """
    pattern = '"(.*?)"'
    cptrn = re.compile(pattern)
    command = "redis-cli {}".format(kwargs["command"])
    output = st.show(dut, command, skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    if "hgetall" not in command:
        return [each for each in cptrn.findall(reg_output)[0]]
    else:
        if 'table_name' not in kwargs and 'attribute' not in kwargs:
            st.error("Mandatory parameter table_name/attribute not found")
            return False
        processed_output = {}
        re_find_output = cptrn.findall(reg_output)
        for each in [i for i in range(len(re_find_output)) if i % 2 == 0]:
            processed_output[re_find_output[each]] = re_find_output[each + 1]
        if kwargs["attribute"] in processed_output.keys():
            return processed_output[kwargs["attribute"]]
        else:
            st.log("attribute not found")
            return None


def verify_package(dut, packane_name):
    """
    To verify package is installed or not
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param packane_name:
    :return:
    """
    command = "dpkg -s {} | grep Status".format(packane_name)
    output = st.config(dut, command, skip_error_check=True)
    if "package '{}' is not installed".format(packane_name) in output:
        st.log("Package '{}' is not installed in DUT".format(packane_name))
        return False
    return True


def deploy_package(dut, packane_name=None, mode='install', skip_verify_package=False):
    """
    To verify package is installed or not
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param packane_name:
    :param mode: install | update | remove | purge
    :return:
    """
    if mode == "install":
        command = "apt-get install {} -y".format(packane_name)
        if not skip_verify_package:
            if verify_package(dut, packane_name):
                st.log("Package is already present in DUT")
                return True
        st.config(dut, command, skip_error_check=True, faster_cli=False)
        if not verify_package(dut, packane_name):
            st.log("Package '{}' is failed to install in DUT".format(packane_name))
            return False

    elif mode in ['remove', 'purge']:
        command = "apt-get {} {} -y".format(mode, packane_name)
        st.config(dut, command, skip_error_check=True, faster_cli=False)
        if verify_package(dut, packane_name):
            st.log("Package '{}' is failed to {} in DUT".format(mode, packane_name))
            return False

    elif mode == "update":
        command = "apt-get update"
        output = st.config(dut, command, skip_error_check=True, faster_cli=False)
        if "Done" not in output:
            st.log("Package 'update' is failed in DUT".format(packane_name))
            return False
    else:
        st.log("invalid mode - {}".format(mode))
        return False
    return True


def download_file_content(dut, file_path, device="dut"):
    """
    This is the API to read the file content and return for further processing
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_path:
    :param device:
    :return:
    """
    file_content = ""
    if device == "dut":
        command = "value=$(<{})".format(file_path)
        st.show(dut, command, skip_tmpl=True)
        command = "echo $value"
        file_content = utils_obj.remove_last_line_from_string(st.show(dut, command, skip_tmpl=True))
    return file_content


def poll_for_system_status(dut, service=None, iteration=150, delay=2):
    i = 1
    while True:
        if get_system_status(dut, service):
            st.log("System is ready in {} iteration".format(i))
            return True
        if i > iteration:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i += delay
        st.wait(delay)


def get_interface_status(conn_obj, interface, device="dut"):
    """
    API to get the linux interface status
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param interface:
    :param device:
    :return:
    """
    command = "cat /sys/class/net/{}/operstate".format(interface)
    if device=="dut":
        return utils_obj.remove_last_line_from_string(st.show(conn_obj, command, skip_tmpl=True))


def check_interface_status(conn_obj, interface, state, device="dut"):
    """
    API to check the interface state
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param interface:
    :param state:
    :param device:
    :return:
    """
    interface_state = get_interface_status(conn_obj, interface, device=device)
    if interface_state != state:
        return False
    return True


def get_ps_aux(connection_obj, search_string, device="dut"):
    """
    API to get the ps aux output
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param search_string:
    :param device:
    :return:
    """
    command = "sudo ps aux"
    if search_string:
        command += " | grep {}".format(search_string)
    if device == "dut":
        return st.show(connection_obj, command)
    else:
        return conn_obj.execute_command(connection_obj, command)


def get_ifconfig_gateway(dut, interface='eth0'):
    """
    API will return Gateway ip address
    :param dut:
    :param interface:
    :return:
    """

    cmd = "sudo route -n"
    output = st.show(dut, cmd)
    gateway_list = [row['gateway'] for row in output if 'G' in row['flags'] and row['iface'] == interface]
    return None if len(gateway_list) == 0 else gateway_list[0]


def get_frr_config(conn_obj, device="dut"):
    """
    API to get frr config from frr.conf file
    Author: Sooriya G (sooriya.gajendrababu@broadcom.com)
    :param conn_obj:
    :param device:
    :return:
    """
    command = " sudo cat /etc/sonic/frr/frr.conf"
    if device=="dut":
        return utils_obj.remove_last_line_from_string(st.show(conn_obj, command, skip_tmpl=True))


def remove_user_log_in_frr(dut,log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    st.config(dut,"docker exec -it bgp rm /var/log/frr/%s"%log_file_name)


def return_user_log_from_frr(dut,log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    return st.config(dut,"docker exec -it bgp cat /var/log/frr/%s"%log_file_name)


def debug_bfdconfig_using_frrlog(dut,config="",log_file_name=""):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param config:
    :param log_file_name:
    :return:
    """
    if config == "yes" or config=="":
        st.config(dut,"debug bfd", type='vtysh')
        st.config(dut,"log syslog warnings", type='vtysh')
        st.config(dut,"log file /var/log/frr/%s"%log_file_name, type='vtysh')
    elif config == "no":
        st.config(dut,"no debug bfd", type='vtysh')
        st.config(dut,"no log syslog warnings", type='vtysh')
        st.config(dut,"no log file /var/log/frr/%s"%log_file_name, type='vtysh')


def set_hostname(dut, host_name):
    """
    this function is used to set hostname in DUT
    :param dut: Device name where the command to be executed
    :type dut: string
    :param host_name: hostname to be set
    :type host_name: string
    :return: None

    usage: set_hostname(dut1, "host1")

    created by: Julius <julius.mariyan@broadcom>
    """
    cmd = "sudo hostname {}".format(host_name)
    st.config(dut, cmd)
    return


def get_attr_from_cfgdbjson(dut, attr):
    """
    this function is used to get some attribute from DUT's config_db.json file
    :param dut: Device name where the command to be executed
    :type dut: string
    :param attr: attribute details to be fetched
    :type host_name: string
    :return: attribute details

    usage: get_attr_from_cfgdbjson(dut1, "fdb_aging_time")

    created by: Julius <julius.mariyan@broadcom>
    """
    cmd = "sudo cat /etc/sonic/config_db.json | grep {}".format(attr)
    return utils_obj.remove_last_line_from_string(st.config(dut, cmd))


def update_config_db_json(dut, attr, val1, val2):
    """
    this function is used to replace val1 of attribute by val2 in DUT's config_db.json file
    :param dut: Device name where the command to be executed
    :type dut: string
    :param attr: attribute name to be modified
    :type attr: string
    :param val1: to be replaced from val1
    :type val1: string
    :param val2: to be changed to val2
    :type val2: string
    :return: None

    usage: update_config_db_json(dut1, "fdb_aging_time", "300", "30")

    created by: Julius <julius.mariyan@broadcom>
    """
    cmd = "sudo sed -i 's/\"{}\": \"{}\"/\"{}\": \"{}\"/g' /etc/sonic/config_db.json"\
                                                        .format(attr,val1,attr,val2)
    st.config(dut, cmd)
    return


def delete_directory_contents(conn_obj, path, device="dut"):
    """
    API to delete contents in the provided directory
    :param conn_obj:
    :param path:
    :param device:
    :return:
    """
    command = "rm -rf {}/*".format(path.rstrip("/"))
    if device == "dut":
        st.config(conn_obj, command)
    else:
        conn_obj.execute_command(conn_obj, command)
    return True


def get_file_number_with_regex(connection_obj, search_pattern, file_path, device="server"):
    #COMMAND :  sed -nE '/^\s*option\s+dhcp6.boot-file-url\s+"\S+";/=' /etc/dhcp/dhcpd6.conf
    '''
    :param connection_obj:
    :param search_pattern:
    :param file_path:
    :param device:
    :return:
    '''
    command = "sed -nE '/^{}/=' {}".format(search_pattern, file_path)
    st.log("######{}##".format(command))
    if device == "server":
        result = conn_obj.execute_command(connection_obj, command)
    else:
        result = st.config(connection_obj, command)
    if utils_obj.remove_last_line_from_string(result):
        line_number = re.findall(r'\d+',utils_obj.remove_last_line_from_string(result))
        if line_number:
            return line_number[0]
    return 0


def delete_line_using_line_number(connection_obj, line_number, file_path, device="server"):
    '''
    COMMAND: sed -i '20d' /etc/dhcp/dhcpd6.conf
    :param connection_obj:
    :param line_number:
    :param file_path:
    :param device:
    :return:
    '''
    st.log("Line number is {}".format(line_number))
    if line_number > 0:
        command = "sed -i '{}d' {}".format(line_number, file_path)
        st.log("COMMAND-- {}".format(command))
        if device == "server":
            return conn_obj.execute_command(connection_obj, command)
        else:
            return st.config(connection_obj, command)


def get_dut_mac_address(dut):
    """
        This is used to get the Duts and its mac addresses mapping
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = {}
    cmd = "show platform syseeprom"
    eeprom_details = st.show(dut, cmd, skip_error_check=True)
    if not eeprom_details:
        iteration=3
        for i in range(1, iteration+1):
            st.wait(2)
            eeprom_details = st.show(dut, cmd, skip_error_check=True)
            if eeprom_details:
                break
            if not eeprom_details and i >= iteration + 1:
                st.log("EEPROM data not found for {}".format(dut))
                st.report_fail("eeprom_data_not_found", dut)
    dut_mac_address = [details for details in eeprom_details if details.get('tlv_name') == "Base MAC Address"][
        0].get("value").replace(':', "")
    duts_mac_addresses[dut] = dut_mac_address
    return duts_mac_addresses


def get_dut_mac_address_thread(dut_list, thread=True):
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    result = dict()
    params = list()
    for dut in dut_li:
        params.append([get_dut_mac_address, dut])
    if params:
        [out, exceptions] = exec_all(thread, params)
        st.log("#########OUTPUT###########")
        st.log(out)
        st.log(exceptions)
        for value in exceptions:
            if value is not None:
                st.log("Exceptions Observed {}, hence returning None".format(value))
                return None
        st.log("Framing required data as no exceptions observed ...")
        for data in out:
            st.log(data)
            result[data.keys()[0]] = data.values()[0]
        return result
    else:
        st.log("Empty Params Observed .... ")
        return None


def get_number_of_lines_in_file(connection_obj, file_path, device="server"):
    line_number=0
    if file_path:
        command = "wc -l {}".format(file_path)
        if device == "server":
            output = conn_obj.execute_command(connection_obj, command)
        else:
            output = st.config(connection_obj, command)
        result = utils_obj.remove_last_line_from_string(output)
        if result:
            match = re.match(r'^\d+', result)
            if match:
                st.log("####### LINE NUMBER- {}".format(match.group(0)))
                return match.group(0)
    return line_number


def is_vsonic_device(dut):
    return st.is_vsonic(dut)

def get_config_profiles(dut):
    """
    Author: Nagappa Chincholi (nagappa.chincholi@broadcom.com)
    Function to get configured profiles (L2/L3).
    :param dut:
    :return:
    """
    if st.is_community_build():
        return "l3"
    command = 'sudo config-profiles get factory'
    output = st.show(dut, command, skip_tmpl=True)
    if len(output) <= 0:
        return None
    return output[:2]

def set_config_profiles(dut, profile, check_system_status=True):
    cur_profile = get_config_profiles(dut)
    if cur_profile == profile.lower():
        st.log('Device is in the desired profile')
    else:
        cmd = 'sudo config-setup factory'
        cmd += '\n sudo config-profiles factory {}'.format(profile.lower())
        st.config(dut, cmd, max_time=300)
    if check_system_status:
        return bool(get_system_status(dut))
    return True

def get_show_command_data(dut, command, type="txt"):
    file_extension = "txt" if type != "json" else "json"
    data = None
    for i in range(1,3):
        actual_cmd = "{} > /tmp/running_config.{}".format(command, file_extension)
        st.config(dut, actual_cmd)
        delete_file("/tmp/running_config.{}".format(file_extension))
        st.download_file_from_dut(dut, "/tmp/running_config.{}".format(file_extension),
                                  "/tmp/running_config.{}".format(file_extension))
        import os
        if not os.stat("/tmp/running_config.{}".format(file_extension)).st_size == 0:
            break
    try:
        if type == "json":
            with open('/tmp/running_config.json') as file:
                data = eval(json.dumps(json.load(file), indent=4, sort_keys=True))
        else:
            with open('/tmp/running_config.txt', 'r') as file:
                data = file.read().replace('\n', '')
    except Exception as e:
        st.error("Exception occured: {}".format(e))
    st.debug(data)
    return data

def check_sonic_branding(build_name):
    """
    Author1: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    Author2: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to verify the build version is in correct format or not
    :param build_name:
    :return:
    """
    result = True
    constants = st.get_datastore(None, "constants", "default")
    st.log("The Given build version string is : {}".format(build_name))

    regex_format = r"^([a-zA-Z]+-[a-zA-Z]+)-((\d+\.\d+\.\d+|\d+\.\d+)_*(\w*))_*(\d+_\d+_\d+)*-*(\S+)*$"
    os_regex = r"^{}".format(constants['NOS_NAME'])
    version_regex = r"(\d+\.\d+\.\d+|\d+\.\d+)"

    if not re.findall(os_regex, build_name):
        st.error('Build OS NAME is not matching with the standard format - {}'.format(constants['NOS_NAME']))
        result = False

    if not re.findall(version_regex, build_name):
        st.error('Build VERSION info is not matching with the standard format')
        result = False

    if not any(ele in build_name for ele in constants['PRODUCT_PACKAGING_OPTIONS']):
        st.error('Build PRODUCT info is not matching with any of the standard Package')
        result = False

    if not re.findall(regex_format, build_name):
        st.error('Build info is not as per the standard Format')
        result = False

    if not result:
        st.log("Output of OS NAME regex : {},  data : {}".format(os_regex, re.findall(os_regex, build_name)))
        st.log("Output of VERSION regex : {}, data : {}".format(version_regex, re.findall(version_regex, build_name)))
        st.log("Output of FORMAT regex : {}, data : {}".format(regex_format, re.findall(regex_format, build_name)))
        st.log("CONSTANTS : {}".format(constants))

    return result


def copy_file_to_docker(dut, file_name, docker_name):
    """
    API to copy file to any docker
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_name:
    :param docker_name:
    :return:
    """
    command = "docker cp {} {}:{}".format(file_name, docker_name, file_name)
    output = st.config(dut, command)
    if "Error response" in utils_obj.remove_last_line_from_string(output):
        st.log(output)
        return False
    return True

def get_user_group_details(connection_obj, device="server"):
    """
    API to execute id command and parse the output
    :param conn_obj:
    :param type:
    :return:
    """
    command = "id"
    if device == "server":
        output = utils_obj.remove_last_line_from_string(conn_obj.execute_command(connection_obj, command))
    else:
        output = utils_obj.remove_last_line_from_string(st.show(connection_obj, command, skip_tmpl=True, type="click"))
    return output

def verify_user_group_details(connection_obj, uid, group, device="server"):
    """
    API to verify the user group details by executing id.
    :param connection_obj:
    :param search_str:
    :param value:
    :param device:
    :return:
    """
    output = get_user_group_details(connection_obj,device=device)
    if not output:
        st.log("Output not found {}".format(output))
        return False
    if uid:
        user_data = re.findall(r"uid=\d+\({}\)".format(uid), output)
        if not user_data:
            st.log("User data not found -- {}".format(uid))
            return False
    if group:
        group_data = re.findall(r"gid=\d+\({}\)".format(group), output)
        if not group_data:
            st.log("Group data not found -- {}".format(group))
            return False
    return True


def delete_line_using_specific_string(connection_obj, specific_string, file_path, device="server"):
    """
    Author: Santosh Votarikari(santosh.votarikari@broadcom.com)
    API to remove line by using specific string

    COMMAND: sed -i "/DELETE THIS TEXT/d" /var/log/messages
    :param connection_obj:
    :param specific_string:
    :param file_path:
    :param device:
    :return:
    """
    st.log("Specific string is {}".format(specific_string))
    if specific_string:
        command = "sed -i '/{}/d' {}".format(specific_string, file_path)
        st.log("COMMAND-- {}".format(command))
        if device == "server":
            return conn_obj.execute_command(connection_obj, command)
        else:
            return st.config(connection_obj, command)


def cmd_validator(dut, commands, cli_type='klish', error_list=[]):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param commands:
    :param cli_type:
    :param error_list:
    :return:
    """
    result = True
    error_list.extend(['%Error'])
    command_list = commands if isinstance(commands, list) else commands.split('\n')
    st.log(command_list)
    out = st.config(dut, command_list, type=cli_type, skip_error_check=True)
    for each in error_list:
        if each in out:
            st.error("Error string '{}' found in command execution.".format(each))
            result = False
    return result


def verify_docker_status(dut, status='Exited'):
    """
     Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param status:
    :return:
    """
    if status in st.config(dut, "docker ps --no-trunc -a"):
        return False
    else:
        return True


def get_and_match_docker_count(dut, count=None):
    """
    Get docker count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param count:
    :return:
    """
    command = 'docker ps --no-trunc | wc -l'
    if not count:
        return utils_obj.get_word_count(dut, command)
    else:
        if int(count) == utils_obj.get_word_count(dut, command):
            return True
    return False

def move_file_to_local_path(dut, src_path, dst_path, sudo=True):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy the file to local path
    :param dut:
    :param src_path:
    :param dst_path:
    :return:
    """
    sucmd = "sudo" if sudo else ""
    command = "{} mv {} {}".format(sucmd, src_path, dst_path)
    st.config(dut, command)