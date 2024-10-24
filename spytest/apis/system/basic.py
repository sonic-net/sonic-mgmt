import os
import re
import sys
import ast
import json
import random
import datetime
import traceback

from spytest import st

import apis.system.connection as conn_obj
from apis.system.rest import get_rest
from apis.system.rest import config_rest, delete_rest

from utilities.common import filter_and_select, kwargs_to_dict_list
from utilities.common import exec_all, str_encode, str_decode
from utilities.common import delete_file, make_list

import utilities.utils as utils_obj


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in utils_obj.get_supported_ui_type_list() else cli_type
    return cli_type


def is_reboot_confirm(dut):
    if not st.is_feature_supported("confirm-reboot", dut):
        return False
    output = st.config(dut, "fast-reboot -h", skip_error_check=True, type="click")
    if "skip the user confirmation" in output:
        return True
    return False


def ensure_hwsku_config(dut):
    # TODO: call sudo config-hwsku set if present in device params
    pass


def ensure_certificate(dut):
    if st.is_feature_supported("certgen-command", dut):
        st.config(dut, "/usr/bin/certgen admin")


def get_system_status(dut, service=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type != 'click':
        cli_type = utils_obj.override_supported_ui("rest-put", "rest-patch", cli_type=cli_type)
    kwargs.setdefault("skip_tmpl", True)
    output = "???"
    if 'cmd' in kwargs:
        if cli_type == 'click':
            return st.show(dut, kwargs['cmd'], skip_tmpl=True, skip_error_check=True, type=cli_type)
        if cli_type == 'klish':
            return st.show(dut, kwargs['cmd'], skip_tmpl=True, skip_error_check=True, type=cli_type)
    try:
        has_status_core = st.is_feature_supported("system-status-core", dut)
        if has_status_core:
            if cli_type == 'klish':
                if 'skip_error_check' not in kwargs:
                    kwargs['skip_error_check'] = True
                output = st.show(dut, "show system status core", type=cli_type, **kwargs)
                if 'Error: Invalid input detected at' in output:
                    st.log('show system status core is not supported in klish. Trying with click')
                    cli_type = 'click'
            if cli_type == 'click':
                output = st.show(dut, "show system status core", type=cli_type, **kwargs)
            if "Error: Got unexpected extra argument (core)" in output:
                has_status_core = False
        if not has_status_core:
            if cli_type == 'klish':
                if 'skip_error_check' not in kwargs:
                    kwargs['skip_error_check'] = True
                output = st.show(dut, "show system status", type=cli_type, **kwargs)
                if 'Error: Invalid input detected at' in output:
                    st.log('show system status is not supported in klish. Trying with click')
                    cli_type = 'click'
            if cli_type == 'click':
                output = st.show(dut, "show system status", type=cli_type, **kwargs)
            if "Error: Got unexpected extra argument (status)" in output:
                return None
        retval = st.parse_show(dut, "show system status", output)
        if not retval:
            return False
        if retval[0]["status"] == "ready":
            return True
        if service and retval[0][service] == "Up":
            return True
    except Exception as exp:
        msg = "Failed to read system online status output='{}' error='{}'"
        st.warn(msg.format(output, exp))
    return False


def get_system_status_all(dut, service=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() + ['rest-patch', 'rest-put'] else cli_type
    failed_services = []
    if cli_type == 'click':
        cmd = "sudo show system status"
    if cli_type == 'klish':
        cmd = "show system status"
    output = st.show(dut, cmd, type=cli_type, **kwargs)
    if not output:
        return False
    if output[0]["status"] == "ready":
        return True
    if output[0]["status"] in ["not ready"]:
        for i in output:
            if i['state'] != 'OK':
                failed_services.append("'{}' service '{}' due to '{}'".format(i['servname'], i['servstatus'], i['reason']))
        st.log("Failed services list : {}".format(failed_services))
        return False


def get_system_status_all_brief(dut, service=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() + ['rest-patch', 'rest-put'] else cli_type
    if cli_type == 'click':
        cmd = "sudo show system status brief"
    if cli_type == 'klish':
        cmd = "show system status brief"
    output = st.show(dut, cmd, type=cli_type, **kwargs)
    if not output:
        return False
    if output[0]["status"] == "System is ready":
        return True
    if output[0]["status"] in ["System is not ready - one or more services are not up"]:
        return False


def get_system_status_all_detail(dut, service=None, **kwargs):
    kwargs.pop('type', None)
    cli_type = st.get_ui_type(dut, **kwargs)
    failed_services = []
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() + ['rest-patch', 'rest-put'] else cli_type
    if cli_type == 'click':
        output = st.show(dut, "sudo show system status detail", type=cli_type, **kwargs)
    if cli_type == 'klish':
        output = st.show(dut, "show system status detail", type=cli_type, **kwargs)
    if 'output' in kwargs:
        return output
    if not output:
        return False
    if output[0]["status"] == "System is ready":
        return True
    if output[0]["status"] in ["System is not ready - one or more services are not up"]:
        for i in output:
            if i['state'] != 'OK':
                failed_services.append("'{}' service '{}' due to '{}'".format(i['servname'], i['servstatus'], i['reason']))
        st.log("Failed services list : {}".format(failed_services))
        return False
    if service:
        st.log("Service list : {}".format(service))
        result = [True for serv in service for service_name in output if service_name['servname'] == serv and service_name['servstatus'] == 'OK']
        if result:
            return True
        else:
            return False


def retry_api(func, args, **kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    if 'retry_count' in kwargs:
        del kwargs['retry_count']
    if 'delay' in kwargs:
        del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" % ((i + 1), retry_count))
        if func(args, **kwargs):
            return True
        if retry_count != (i + 1):
            st.log("waiting for %s seconds before retyring again" % delay)
            st.wait(delay)
    return False


def get_machineconf_platform(dut):
    cmd = "cat /host/machine.conf | grep onie_platform | cut -d '=' -f 2"
    outputs = str_encode(st.config(dut, cmd)).split(str_encode('\n'))
    return str_decode(outputs[0])


def get_cfggen_hwsku(dut):
    cmd = "sonic-cfggen -d -v \'DEVICE_METADATA[\"localhost\"][\"hwsku\"]\'"
    output = st.config(dut, cmd, skip_error_check=True).split('\n')
    return output[0]


def get_hwsku(dut, **kwargs):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to ge the hwsku of the device.
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in utils_obj.get_supported_ui_type_list('klish'):
        hwsku = show_version(dut, cli_type=cli_type)['hwsku']
        return hwsku

    output = st.show(dut, "show platform summary")
    if len(output) <= 0 or "hwsku" not in output[0]:
        return None
    hwsku = output[0]["hwsku"]
    return hwsku


def set_hwsku(dut, hwsku):
    st.config(dut, "config-hwsku set {}".format(hwsku),
              confirm='y', expect_reboot=True)


def get_platform_summary(dut, value=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform summary")
    if not output:
        return None

    return output[0].get(value, None) if value else output[0]


def get_dut_date_time(dut, pattern="", addtl_time=""):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the DUT date and time
    :param dut:
    :return:
    """
    add_time = ' -s "{}"'.format(addtl_time) if addtl_time else ""
    sudo = "sudo " if add_time else ""
    if not pattern:
        return utils_obj.remove_last_line_from_string(st.config(dut, "date{}".format(add_time)))
    else:
        command = 'echo $({}date "+{}"{})'.format(sudo, pattern, add_time)
        return utils_obj.remove_last_line_from_string(st.config(dut, command, skip_error_check=True))


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


def get_ifconfig(dut, interface=None, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig output
    :param dut:
    :param interface:
    :return:
    """
    if not interface:
        interface = st.get_mgmt_ifname(dut)
    else:
        interface = utils_obj.convert_intf_name_to_component(dut, intf_list=interface)
    command = "/sbin/ifconfig {}".format(interface)
    return st.show(dut, command, **kwargs)


def get_ifconfig_inet(dut, interface=None, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig inet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface, **kwargs)
    if len(output) <= 0 or "inet" not in output[0]:
        return "127.0.0.1" if st.is_dry_run() else None
    ip_addresses = output[0]['inet']
    return ip_addresses


def get_ifconfig_inet6(dut, interface=None):
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


def get_ifconfig_ether(dut, interface=None, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig ethernet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface, **kwargs)
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
    hostname = hostname.split('\n')[0].strip()
    if hostname.startswith(cmd + '\n'):
        hostname = hostname[len(cmd + '\n'):]
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
    for line in result.splitlines():
        if line == "inactive":
            return False
        if line == "active":
            return True
    return False


def systemctl_restart_service(dut, name, max_wait=10, skip_error_check=False):
    command = "systemctl restart {}".format(name)
    st.config(dut, command, skip_error_check=skip_error_check)

    i, delay, retval = 1, 1, False
    while True:
        if verify_service_status(dut, name):
            retval = True
            break
        if delay < 0 or i > int(max_wait / delay):
            break
        i += delay
        st.wait(delay)

    return retval


def service_operations_by_systemctl(dut, service, operation, skip_error_check=True, option=None):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to do the service operations using systemctl
    :param dut:
    :param service:
    :param operation:
    :return:
    """
    option = option if operation == "status" else None
    command = "systemctl {} {}".format(operation, service) if option is None else "systemctl {} {} {}".format(operation, option, service)
    return st.config(dut, command, skip_error_check=skip_error_check)


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


def file_create(dut, content, file_path, **kwargs):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Functcion to creat and write to file
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'bash -c "echo {} > {}" '.format(content, file_path)
    st.config(dut, command, **kwargs)
    return True


def file_append(dut, content, file_path, **kwargs):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write to file using sudo mode
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'bash -c "echo {} >> {}" '.format(content, file_path)
    st.config(dut, command, **kwargs)


def file_delete(dut, file_path, **kwargs):
    try:
        command = 'rm {} 2>/dev/null && echo 1 || echo 0'.format(file_path)
        retval = st.config(dut, command, **kwargs)
        if int(utils_obj.remove_last_line_from_string(retval)) == 1:
            return True
    except Exception as e:
        st.exception(str(e))
    return False


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
        src_file = st.mktemp()
        src_fp = open(src_file, "w")
        src_fp.write(content)
        src_fp.close()
        return src_file


def replace_line_in_file(ssh_conn_obj, old_string, new_string, file_path, device='server'):
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


def replace_line_in_file_with_line_number(dut, **kwargs):
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


def find_line_in_file(conn_obj, search_string, file_path, device='server', verify=True):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to file line in  a file
    :param ssh_conn_obj:
    :param search_string:
    :param file_path:
    :return:
    """
    command = "grep -w '{}' {}".format(search_string, file_path)
    result = conn_obj.execute_command(conn_obj, command) if device == 'server' else st.config(conn_obj, command, skip_error_check=True)
    if verify:
        if utils_obj.remove_last_line_from_string(result).find(search_string) < 1:
            return False
        return True
    else:
        return utils_obj.remove_last_line_from_string(result)


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
    json_str = json.dumps(parsed, indent=4, sort_keys=True)
    src_file = st.mktemp()
    src_fp = open(src_file, "w")
    src_fp.write(json_str)
    src_fp.close()
    return src_file


def upload_file(ssh_con_obj, **kwargs):
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
        scp_conn.scp_put_file(kwargs["src_path"], kwargs["dst_path"])
        scp_conn.close()
        if "persist" not in kwargs:
            os.remove(kwargs["src_path"])
    except Exception as e:
        st.log(e)
        st.report_fail("scp_file_transfer_failed", kwargs["src_path"], kwargs["dst_path"])


def download_file(ssh_con_obj, **kwargs):
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
        scp_conn.scp_get_file(kwargs["src_path"], kwargs["dst_path"])
        scp_conn.close()
        if "persist" not in kwargs:
            os.remove(kwargs["src_path"])
    except Exception as e:
        st.log(e)
        st.report_fail("scp_file_transfer_failed", kwargs["src_path"], kwargs["dst_path"])


def check_error_log(dut, file_path, error_string, lines=1, file_length=50, match=None, start_line=0, host_name=''):
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
    if start_line != 0:
        command = 'sudo tail -n +{} {} | grep {} | grep "{}" | grep -Ev "sudo tail"'.format(start_line, file_path, host_name, error_string)
    else:
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
    i = 1
    while True:
        if check_error_log(dut, file_path, error_string, lines, file_length, match=match):
            st.log("Log found in {} iteration".format(i))
            return True
        if i > iteration_cnt:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i += delay
        st.wait(delay)


def show_version(dut, cli_type='', report=True, **kwargs):
    """
    Get Show Version
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in utils_obj.get_supported_ui_type_list():
        import apis.system.system_server as sys_server_api
        kwargs['cli_type'] = cli_type
        kwargs['report'] = report
        return sys_server_api.system_show_version(dut, **kwargs)
    if cli_type in ['rest-put', 'rest-patch']:
        try:
            rest_urls = st.get_datastore(dut, "rest_urls")
            url = rest_urls['get_system_component'].format("software")
            data = st.rest_read(dut, url)
            if data['status'] in [200]:
                version = data['output']['openconfig-platform:component'][0]['software']
                # Version
                ver = {'distribution': "Debian {}".format(version['distribution-version'])}
                ver.update({"kernel": version['kernel-version']})
                ver.update({"product": version['product-description']})
                ver.update({"asic": version['asic-version']})
                ver.update({"version": "SONiC-OS-{}".format(version['software-version'])})
                ver.update({"hw_version": ''})
                ver.update({"db_version": version['config-db-version']})
                ver.update({"serial_number": version['serial-number']})
                ver.update({"platform": version['platform-name']})
                ver.update({"build_commit": version['build-commit']})
                ver.update({"build_date": version['build-date']})
                ver.update({"built_by": version['built-by']})
                ver.update({"hwsku": version['hwsku-version']})
                ver.update({"mfg": ''})
                out = re.findall(r'(.*),\s+(\d+)\s+\S+,\s+load average:\s+(.*)\s*', version['up-time'])
                if out and len(out[0]) == 3:
                    ver.update({"uptime": out[0][0]})
                    ver.update({"load_average": out[0][2]})
                    ver.update({"user": out[0][1]})
                ver2 = {k: v.replace("'", '').strip() for k, v in ver.items()}
                st.debug(ver2)
                return ver2
            else:
                st.error("Failed to read version", dut=dut)
                cli_type = 'click'
        except Exception as e:
            st.error("Failed to read version", dut=dut)
            st.error(e)
            cli_type = 'click'

    if cli_type in ['click', 'klish']:
        command = 'show version'
        output = st.show(dut, command, type=cli_type, **kwargs)
        if not output:
            st.error("Failed to read version", dut=dut)
            if cli_type in ['klish']:
                output = st.show(dut, command, type='click', **kwargs)
                if not output:
                    st.error("Failed to read version even from click", dut=dut)
            if not output:
                if report:
                    st.report_fail("version_data_not_found", dut)
                return {}
        exclude_keys = ['repository', 'tag', 'image_id', 'size']
        rv = {each_key: output[0][each_key] for each_key in output[0] if each_key not in exclude_keys}
        return rv


def compare_image_version(dut, version=[]):
    """
    Compare current image version on DUT with the provided version
    Author: Venkat Moguluri (venkata.moguluri@broadcom.com)
    :param dut: DUT to be comapred
    :param version: Version to be compared
    :return:
    """
    current_version = show_version(dut, report=False)['version']
    st.log("Current Version on {} is {}".format(dut, current_version))
    if current_version in version:
        return True
    return False


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


def get_docker_stats(dut):
    """
    Get docker ps
    :param dut:
    :return:
    """
    command = 'docker stats -a --no-stream'
    output = st.show(dut, command)
    return output


def verify_docker_stats(dut, name, **kwargs):
    """
    To verify docker stats info

    :param dut:
    :param id:
    :param name:
    :param cpu:
    :param memusage:
    :param memlimit:
    :param memperc:
    :param pid:
    :return: True/False
    """
    output = get_docker_stats(dut)
    rv = filter_and_select(output, None, {'name': name})
    if not rv:
        st.error("No match for {} = {} in table".format('name', name))
        return False
    for each in kwargs.keys():
        if not filter_and_select(rv, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in NAME {} ".format(each, kwargs[each], name))
            return False
        else:
            st.log("Match found for {} = {} in NAME {}".format(each, kwargs[each], name))
    return True


def verify_docker_ps(dut, image=None, **kwargs):
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
    if image:
        rv = filter_and_select(output, None, {'image': image})
        if not rv:
            st.error("No match for {} = {} in table".format('image', image))
            return False
    else:
        rv = output
    for each in kwargs.keys():
        if not filter_and_select(rv, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
        else:
            st.log("Match found for {} = {} in table".format(each, kwargs[each]))

    return True


def docker_operation(dut, docker_name, operation, skip_error_check=True, docker_cmd=False, vrf="default"):
    """
    To Perform Docker operations
    Author: kesava-swamy.karedla@broadcom.com
    :param dut:
    :param docker_name:
    :param operation:
    :return:
    """
    util_name = "systemctl" if not docker_cmd else "docker"
    if docker_cmd == "docker":
        if vrf == "default":
            command = 'docker  -H unix:///run/docker-default.socket {} {}'.format(operation, docker_name)
        elif vrf == "mgmt":
            command = 'docker -H unix:///run/docker-mgmt.socket {} {}'.format(operation, docker_name)
    command = '{} {} {}'.format(util_name, operation, docker_name)
    return st.config(dut, command, skip_error_check=skip_error_check)


def get_memory_info(dut):
    """
    Get Memory information form TOP command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = "top -n 1 b | head -n 4 | tail -n 1"
    output = st.show(dut, command)
    rv = {}
    if output:
        include_keys = ['total', 'used', 'free', 'buff_cache']
        rv = {each_key: ast.literal_eval(output[0][each_key]) for each_key in output[0] if each_key in include_keys}
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


def get_platform_syseeprom(dut, tlv_name=None, key='value', decode=False, cli_type=''):
    """
    Get Platform Syseeprom
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param tlv_name:
    :param key:  value/len/code
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type == "click":
        if decode:
            command = "sudo decode-syseeprom"
        else:
            command = "show platform syseeprom"
        result = st.show(dut, command, type=cli_type)
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        result = list()
        if cli_type == "klish":
            command = "show platform syseeprom"
            output = st.show(dut, command, type=cli_type)
        else:
            output = list()
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['get_system_component'].format("System Eeprom")
            try:
                data = get_rest(dut, rest_url=url1)["output"]["openconfig-platform:component"][0]["state"]
            except Exception as e:
                st.error(e)
                return False
            for k in data:
                temp = dict()
                temp["value"] = data[k]
                k = k.split(":").pop()
                temp["ktlv_name"] = k
                output.append(temp)
        st.log(output)
        key_mapping = {"Platform": "Platform Name", "Base Mac Address": "Base MAC Address", "Mfg Date": "Manufacture Date",
                       "Hardware Version": "Label Revision", "Onie Version": "ONIE Version", "Mac Addresses": "MAC Addresses",
                       "Mfg Name": "Manufacturer", "Manufacture Country": "Manufacture Country", "Vendor Name": "Vendor Name",
                       "Diag Version": "Diag Version", "description": "Platform Name", "id": "Product Name",
                       "part-no": "Part Number", "serial-no": "Serial Number", "base-mac-address": "Base MAC Address",
                       "mfg-date": "Manufacture Date", "hardware-version": "Label Revision", "onie-version": "ONIE Version",
                       "mac-addresses": "MAC Addresses", "mfg-name": "Manufacturer",
                       "manufacture-country": "Manufacture Country", "vendor-name": "Vendor Name",
                       "diag-version": "Diag Version"}
        for each in output:
            if each.get("ktlv_name", ""):
                if each["ktlv_name"] in key_mapping.keys():
                    each["tlv_name"] = key_mapping[each["ktlv_name"]]
                else:
                    each["tlv_name"] = each["ktlv_name"]
            each.pop("ktlv_name", None)
            result.append(each)
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    if tlv_name:
        result = filter_and_select(result, [key], {"tlv_name": tlv_name})[0][key]
    return result


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


def remove_file(dut, file_path, con_obj=""):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    This API is to remove file from a specifc path
    :param dut:
    :param file_path:
    :return:
    """
    st.log("####### Removing file {} #######".format(file_path))
    command = "rm -f -- {}".format(file_path)
    if not con_obj:
        st.config(dut, command)
    else:
        prompt = con_obj.find_prompt()
        result = con_obj.send_command(command, expect_string=prompt, max_loops=50, delay_factor=5)
        result = utils_obj.remove_last_line_from_string(result)
        if "denied" in result:
            st.log("{} doesn't have permissions to remove {}".format(con_obj.username, file_path))
            return False
        else:
            st.log("{} successfully removed".format(file_path))
            return True


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


def verify_arp_nd_kernel_tx(dut, key, value, return_output="no"):
    """
    To verify ARP or ND packet forwarding through kernel CPU port
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param key: "tx_packets" OR "tx_bytes"
    :param value: expected value for the key passed
    :return:
    """
    output = get_ifconfig(dut, interface="CPU")
    if return_output == "yes":
        return output
    key_li = list(key) if isinstance(key, list) else [key]
    val_li = list(value) if isinstance(value, list) else [value]
    ret_val = True
    if len(output) > 0:
        for ke, va in zip(key_li, val_li):
            if ke in output[0]:
                if output[0][ke] >= va:
                    st.log("Match {} actual value {} >= expected value {}".format(ke, output[0][ke], va))
                else:
                    st.log("No Match {} actual value {} >= expected value {}".format(ke, output[0][ke], va))
                    ret_val = False
            else:
                st.log("INFO: ARG {} does not exist in the ifconfig CPU output".format(ke))
        return ret_val
    else:
        st.log("INFO: CPU port does not in the DUT kernel so hardware assistance not supported")
        return False


def deploy_package(dut, packane_name=None, mode='install', skip_verify_package=False, options=None):
    """
    To verify package is installed or not
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param packane_name:
    :param mode: install | update | remove | purge
    :return:
    """

    if mode == "install":
        if options:
            command = "apt-get install {} {} -y".format(options, packane_name)
        else:
            command = "apt-get install {} -y".format(packane_name)

        if not skip_verify_package:
            if verify_package(dut, packane_name):
                st.log("Package '{}' is already installed".format(packane_name), dut=dut)
                return True

        for attempt in range(3):
            st.config(dut, command, skip_error_check=True, faster_cli=False, max_time=600)
            if verify_package(dut, packane_name):
                st.log("Successfully installed package '{}'".format(packane_name), dut=dut)
                return True
            if attempt <= 2:
                st.warn("Failed to install package '{}' attempt {}".format(packane_name, attempt), dut=dut)
                st.wait(10, "Wait to retry installation")
        st.error("Failed to install package '{}'".format(packane_name), dut=dut)
        return False

    if mode in ['remove', 'purge']:
        command = "apt-get {} {} -y".format(mode, packane_name)
        st.config(dut, command, skip_error_check=True, faster_cli=False)
        if verify_package(dut, packane_name):
            st.warn("Failed to {} package '{}'".format(mode, packane_name), dut=dut)
            return False
        st.log("Successfully {}d package '{}'".format(mode, packane_name), dut=dut)
        return True

    if mode == "update":
        command = "apt-get update"
        for attempt in range(3):
            output = st.config(dut, command, skip_error_check=True, faster_cli=False, max_time=600)
            if "Done" in output:
                st.log("Successfully {}d packages".format(mode), dut=dut)
                return True
            if attempt <= 2:
                st.warn("Failed to update packages attempt {}".format(attempt), dut=dut)
                st.wait(10, "Wait to retry update")
        st.error("Failed to update packages", dut=dut)
        return False

    st.log("invalid mode - {}".format(mode))
    return False


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


def is_td4_platform(dut):
    platform = get_hwsku(dut)
    common_constants = st.get_datastore(dut, "constants", "default")
    return bool(platform.lower() in common_constants['TD4_PLATFORMS'])


def is_th4_platform(dut):
    platform = get_hwsku(dut)
    common_constants = st.get_datastore(dut, "constants", "default")
    return bool(platform.lower() in common_constants['TH4_PLATFORMS'])


def is_sub_intf_platform(dut):
    '''
    Sub interface is supported only on TD3.X7, TD3.X5 and TD4.X11
    :param dut:
    :return:
    '''
    platform = get_hwsku(dut).lower()
    chip_rev = st.get_device_param(dut, "chip_rev", None)
    st.log("##### DUT:{}, Platform:{}, Chip_Rev:{} #####".format(dut, platform, chip_rev))
    common_constants = st.get_datastore(dut, "constants")
    td3_platforms = common_constants['TD3_PLATFORMS']
    td3_chips = ['X5', 'X7']
    td4_platforms = common_constants['TD4_PLATFORMS']
    td4_chips = ['X11']
    if platform in td3_platforms:
        return bool(chip_rev in td3_chips)
    if platform in td4_platforms:
        return bool(chip_rev in td4_chips)
    return False


def is_warm_boot_support(dut, is_support=False):
    platform = get_hwsku(dut)
    features_support_data = st.get_datastore(dut, "features", "default")
    key = "WARMBOOT_SUPPORTED" if is_support else "WARMBOOT_UNSUPPORTED"
    return bool(platform.lower() in features_support_data[key])


def poll_for_system_status(dut, service=None, iteration=150, delay=2):

    if not st.is_feature_supported("system-status", dut):
        return st.wait_system_status(dut, (iteration * delay))

    i = 1
    is_td4 = is_td4_platform(dut)
    while True:
        if get_system_status(dut, service):
            st.log("System is ready in {} iteration".format(i))

            if is_td4:
                st.wait(30, 'Extra wait for ports to come up')

            return True
        if i > iteration:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i += 1
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
    if device == "dut":
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
    if "No such file or directory" in interface_state:
        return None
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
        first_char = search_string[0]
        rest_chars = search_string[1:]
        command += " | grep [{}]{}".format(first_char, rest_chars)
    if device == "dut":
        return st.show(connection_obj, command)
    else:
        return conn_obj.execute_command(connection_obj, command)


def get_ifconfig_gateway(dut, interface=None):
    """
    API will return Gateway ip address
    :param dut:
    :param interface:
    :return:
    """
    interface = interface or st.get_mgmt_ifname(dut)
    output = st.show(dut, "sudo route -n")
    gateway_list = [row['gateway'] for row in output if 'G' in row['flags'] and row['iface'] == interface]
    return None if len(gateway_list) == 0 else gateway_list[0]


def get_frr_config(conn_obj, device="dut", protocol=None, cli_type=''):
    """
    API to get frr config from frr.conf file
    Author: Sooriya G (sooriya.gajendrababu@broadcom.com)
    :param conn_obj:
    :param device:
    :return:
    """
    cli_type = st.get_ui_type(cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type == 'click':
        command = " sudo cat /etc/sonic/frr/frr.conf"
    elif cli_type in ['klish', 'rest-patch', 'rest-put']:
        if not protocol:
            st.error("Please provide the protocol name to get frr config for cli_type {}".format(cli_type))
            return ''
        command = " sudo cat /etc/sonic/frr/{}d.conf".format(protocol)
    if device == "dut":
        return utils_obj.remove_last_line_from_string(st.show(conn_obj, command, skip_tmpl=True))


def remove_user_log_in_frr(dut, log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    st.config(dut, "docker exec -it bgp rm /var/log/frr/%s" % log_file_name)


def add_user_log_in_frr(dut, log_file_name):
    """
    API to create frr log file in BGP frr docker
    Author: vishnuvardhan talluri (vishnuvardhan.talluri@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    st.config(dut, "docker exec -it bgp touch /var/log/frr/%s" % log_file_name)
    st.config(dut, "docker exec -it bgp chmod 777 /var/log/frr/%s" % log_file_name)


def return_user_log_from_frr(dut, log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    return st.config(dut, "docker exec -it bgp bash -c  \"grep 'state-change'  /var/log/frr/%s | tail -50\"" % log_file_name)


def debug_bfdconfig_using_frrlog(dut, config="", log_file_name=""):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param config:
    :param log_file_name:
    :return:
    """
    if config == "yes" or config == "":
        st.config(dut, "debug bfd network", type='vtysh')
        st.config(dut, "debug bfd peer", type='vtysh')
        st.config(dut, "debug bfd zebra", type='vtysh')
        st.config(dut, "log syslog warnings", type='vtysh')
        st.config(dut, "log file /var/log/frr/%s" % log_file_name, type='vtysh')
    elif config == "no":
        st.config(dut, "no debug bfd zebra", type='vtysh')
        st.config(dut, "no debug bfd peer", type='vtysh')
        st.config(dut, "no debug bfd network", type='vtysh')
        st.config(dut, "no log syslog warnings", type='vtysh')
        st.config(dut, "no log file /var/log/frr/%s" % log_file_name, type='vtysh')


def set_hostname(dut, host_name, **kwargs):
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
    host_name = host_name or "sonic"
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_hostname']
        payload = {"openconfig-system:hostname": host_name}
        response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
        if not response:
            st.banner('FAIL-OCYANG: hostname config Failed')
            return False
        else:
            return True
    elif cli_type == "click":
        cmd = "config hostname {}".format(host_name)
    elif cli_type == "klish":
        cmd = "hostname {}".format(host_name)
    return st.config(dut, cmd, type=cli_type)


def set_resource_stats_polling_interval(dut, interval, **kwargs):
    """
    this function is used to set resource-stats-polling-interval in DUT
    :param dut: Device name where the command to be executed
    :type dut: string
    :param interval: resource-stats-polling-interval to be set
    :type interval: int

    usage: set_resource_stats_polling_interval(dut1, 120)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['rest-put', 'rest-patch', 'rest-delete']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_resource_stats_polling_interval']
        if cli_type == 'rest-delete':
            del_response = delete_rest(dut, rest_url=url, get_response=True)
            st.log("REST delete of resource_stats_polling_interval response: {}".format(del_response))
            if not del_response:
                st.banner('FAIL-OCYANG: resource-stats-polling-interval delete Failed')
                return False
            else:
                return True
        else:
            if interval is None:
                st.log("Resource stats polling interval value not provided")
                return False
            payload = {"openconfig-system-deviation:resource-stats-polling-interval": interval}
            response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
            st.log("REST config of resource_stats_polling_interval response: {}".format(response))
            if not response:
                st.banner('FAIL-OCYANG: resource-stats-polling-interval config Failed')
                return False
            else:
                return True
    elif cli_type == "klish":
        cmd = "system resource-stats-polling-interval {}".format(interval)
        return st.config(dut, cmd, type=cli_type)

    # Return False if cli_type is neither 'rest-put' nor 'rest-patch' nor 'klish'
    st.log("Invalid cli_type: {}".format(cli_type))
    return False


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
    cmd = "sudo sed -i 's/\"{0}\": \"{1}\"/\"{0}\": \"{2}\"/g' /etc/sonic/config_db.json"\
        .format(attr, val1, val2)
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
    # COMMAND :  sed -nE '/^\s*option\s+dhcp6.boot-file-url\s+"\S+";/=' /etc/dhcp/dhcpd6.conf
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
        line_number = re.findall(r'\d+', utils_obj.remove_last_line_from_string(result))
        if line_number:
            return int(line_number[0])
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
        iteration = 3
        for i in range(1, iteration + 1):
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
    line_number = 0
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
                return int(match.group(0))
    return line_number


def get_config_profiles(dut):
    """
    Author: Nagappa Chincholi (nagappa.chincholi@broadcom.com)
    Function to get configured profiles (L2/L3).
    :param dut:
    :return:
    """
    if not st.is_feature_supported("config-profiles-get-factory-command", dut):
        return "l3"
    command = 'sudo config-profiles get factory'
    output = st.show(dut, command, skip_tmpl=True)
    if len(output) <= 0:
        return None
    return output[:2]


def set_config_profiles(dut, profile, check_system_status=True, force=False, **kwargs):
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skiperr = kwargs.pop('skip_error', False)
    # Adding apply_cli_type for backward compatibility.
    apply_cli_type = kwargs.pop('apply_cli_type', False)
    retvar = True

    if apply_cli_type is False:
        new_profile = profile.lower()
        cur_profile = get_config_profiles(dut)
        if cur_profile != new_profile:
            st.log('Device is profile {} but needed profile {}'.format(cur_profile, new_profile), dut=dut)
        elif not force:
            st.log('Device is in the desired profile', dut=dut)
            return True
        else:
            st.log('Device is in the desired profile, but applying again', dut=dut)

        cmds = ['sudo config-setup factory']
        cmds.append('sudo config-profiles factory {}'.format(new_profile))
        st.config(dut, "\n".join(cmds), max_time=900)
    else:
        if cli_type == 'klish':
            my_cmd = 'factory default profile {} confirm \n'.format(profile)
            out = st.config(dut, my_cmd, type=cli_type, skip_error_check=skiperr, expect_reboot=True, max_time=50, min_time=10)
            if '%Error:' in out:
                retvar = False
        else:
            st.log("Unsupported CLI TYPE - {}".format(cli_type))
            retvar = False

    if check_system_status:
        return bool(st.wait_system_status(dut, max_time=300))

    return retvar


def get_show_command_data(dut, command, type="txt"):
    file_extension = "txt" if type != "json" else "json"
    data = None
    remote_file = "/tmp/running_config.{}".format(file_extension)
    local_file = st.mktemp()
    for _ in range(0, 3):
        actual_cmd = "{} > {}".format(command, remote_file)
        st.config(dut, actual_cmd)
        delete_file(local_file)
        st.download_file_from_dut(dut, remote_file, local_file)
        if os.path.exists(local_file):
            if not os.stat(local_file).st_size == 0:
                break
    try:
        with open(local_file) as file:
            if type == "json":
                # nosemgrep-next-line
                data = eval(json.dumps(json.load(file), indent=4, sort_keys=True))
            else:
                data = file.read().replace('\n', '')
        delete_file(local_file)
    except Exception as e:
        st.error("Exception occured: {}".format(e))
    st.debug(data)
    return data


def check_sonic_branding(build_name, cli_type=""):
    """
    Author1: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    Author2: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to verify the build version is in correct format or not
    :param build_name:
    :return:
    """
    cli_type = st.get_ui_type(cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    # rest support is blocked due to SONIC-24371. So falling back to klish
    if cli_type in ['rest-put', 'rest-patch']:
        cli_type = 'klish'
    result = True
    st.log("The Given build version string is : {}".format(build_name))
    constants = st.get_datastore(None, "constants", "default")
    if cli_type == "click":
        regex_format = r"^(\S+)((\d+\.\d+\.\d+|\d+\.\d+)_*(\w*))_*(\d+_\d+_\d+)*-*(\S+)*$"
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
    elif cli_type == "klish":
        regex_format = r"^(\S+)((\d+\.\d+\.\d+|\d+\.\d+)_*(\w*))_*(\d+_\d+_\d+)*-*(\S+)*$"
        version_regex = r"(\d+\.\d+\.\d+|\d+\.\d+)"
        if 'dell_sonic' in build_name:
            regex_format = r'SONiC-OS-rel_dell_sonic'
            version_regex = r'(\d+\.x|\d+\.\d+\.x|sonic_share)'

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
            st.log("Output of VERSION regex : {}, data : {}".format(version_regex, re.findall(version_regex, build_name)))
            st.log("Output of FORMAT regex : {}, data : {}".format(regex_format, re.findall(regex_format, build_name)))
            st.log("CONSTANTS : {}".format(constants))
    else:
        st.log("unsupported cli type")
        return False
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
    command = "docker cp {0} {1}:{0}".format(file_name, docker_name)
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
    output = get_user_group_details(connection_obj, device=device)
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


def move_file_to_local_path(dut, src_path, dst_path, sudo=True, skip_error_check=False):
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
    st.config(dut, command, skip_error_check=skip_error_check)


def killall_process(dut, name, skip_error_check=True):
    command = "killall {}".format(name)
    st.config(dut, command, skip_error_check=skip_error_check)


def dhcp_server_config(dut, dhcp_files=['isc-dhcp-server', 'dhcpd.conf', 'dhcpd6.conf', 'radvd.conf'], **kwargs):
    '''
    1. Install dhcp package
    2. Update dhcp files - dhcpd6.conf  dhcpd.conf  isc-dhcp-server
    3. create vlan, member and configure IPv4 and IPv6.
    4. Add static routes
    5.Restart dhcp process
    '''
    import apis.switching.vlan as vlan_api
    import apis.routing.ip as ip_api
    vlan = kwargs.get("vlan", "50")  # This is hardcoded as 50, because the interface on DHCP server is Vlan50
    server_connected_port = kwargs.get("server_port")
    ipv4_server_ip = kwargs.get("server_ipv4")
    ipv6_server_ip = kwargs.get("server_ipv6")
    ipv4_server_ip_mask = kwargs.get("mask_v4", "24")
    ipv6_server_ip_mask = kwargs.get("mask_v6", "64")
    route_list = kwargs.get("route_list")
    route_list_v6 = kwargs.get("route_list_v6")
    ipv4_relay_agent_ip = kwargs.get("ipv4_relay_agent_ip")
    ipv6_relay_agent_ip = kwargs.get("ipv6_relay_agent_ip")
    dhcp_files_path = kwargs.get("dhcp_files_path")
    apach = kwargs.get("apach", False)
    radv = kwargs.get("radv", False)
    service = "isc-dhcp-server"
    service_apach = "apache2"
    service_radv = "radvd"
    madatory_fields = [server_connected_port]
    if any(elem is None for elem in madatory_fields):
        st.log("Required interfaces are not provided")
        return False
    vlan_int = 'Vlan{}'.format(vlan) if vlan else server_connected_port
    action = kwargs.get("action", "config")
    route_list = make_list(route_list)
    route_list_v6 = make_list(route_list_v6)
    error_msgs = ["Failed", "Error"]
    if action == "config":
        if not dhcp_files_path:
            st.log("DHCP FILES PATH not provided")
            return False
        dhcp_files_path = make_list(dhcp_files_path)
        # service_status = service_operations_by_systemctl(dut, service=service, operation="status")
        # st.debug(service_status)
        # if "Unit isc-dhcp-server.service could not be found" in service_status:
        deploy_package(dut, mode='update')
        deploy_package(dut, packane_name=service, mode='install')
        if apach:
            deploy_package(dut, packane_name=service_apach, mode='install')
            service_operations_by_systemctl(dut, service=service_apach, operation="status", option='--no-pager')
        if radv:
            deploy_package(dut, packane_name=service_radv, mode='install')
            service_operations_by_systemctl(dut, service=service_radv, operation="status", option='--no-pager')

        # else:
        #     st.log("SKIPPING {} installation, as status show it is already available for operations".format(service.upper()))

        utils_obj.copy_files_to_dut(dut, dhcp_files_path[:1], '/etc/default/')
        utils_obj.copy_files_to_dut(dut, dhcp_files_path[1:3], '/etc/dhcp/')
        if radv:
            utils_obj.copy_files_to_dut(dut, dhcp_files_path[3:4], '/etc/')
        if vlan:
            vlan_api.create_vlan(dut, [vlan])
            sub_intf = st.get_args("routed_sub_intf")
            if sub_intf is not True:
                vlan_api.add_vlan_member(dut, vlan, server_connected_port)
            else:
                vlan_api.add_vlan_member(dut, vlan, server_connected_port, True)
        if ipv4_server_ip:
            ip_api.config_ip_addr_interface(dut, vlan_int, ipv4_server_ip, ipv4_server_ip_mask)
        else:
            st.log("IP CONFIGURATION SKIPPED AS V4 SERVER IP NOT PROVIDED")
        if ipv6_server_ip:
            ip_api.config_ip_addr_interface(dut, vlan_int, ipv6_server_ip, ipv6_server_ip_mask, family='ipv6')
        else:
            st.log("IPV6 CONFIGURATION SKIPPED AS V6 SERVER IP NOT PROVIDED")
        if route_list:
            for ip in route_list:
                if ipv4_relay_agent_ip:
                    ip_api.create_static_route(dut, next_hop=ipv4_relay_agent_ip, static_ip=ip)
                else:
                    st.log("STATIC ROUTE CREATION SKIPPED AS RELAY AGENT IP NOT PROVIDED")
        else:
            st.log("ROUTE LIST NOT PROVIDED HENCE SKIPPED")
        if route_list_v6:
            for ip6 in route_list_v6:
                if ipv6_relay_agent_ip:
                    ip_api.create_static_route(dut, next_hop=ipv6_relay_agent_ip, static_ip=ip6, family='ipv6')
                else:
                    st.log("V6 STATIC ROUTE CREATION SKIPPED AS RELAY AGENT IPV6 NOT PROVIDED")
        else:
            st.log("ROUTE LIST V6 NOT PROVIDED HENCE SKIPPED")
        output = service_operations_by_systemctl(dut, service=service, operation="restart", skip_error_check=True)
        for msg in error_msgs:
            if msg in output:
                st.error("Observerd Error while restarting the {} service".format(service))
                return False
        if radv:
            output = service_operations_by_systemctl(dut, service=service_radv, operation="restart", skip_error_check=True)
            for msg in error_msgs:
                if msg in output:
                    st.error("Observerd Error while restarting the {} service".format(service_radv))
                    return False
        # st.banner('Enabling dhcp snooping globally on the server node to install DHCP L2 copp rules')
        # snooping_api.config_dhcp_snooping(dut, addr_family='ip', enable_global='yes')
        st.wait(2)
        ps_aux = get_ps_aux(dut, "dhcpd")
        if len(ps_aux) >= 1 or st.is_dry_run():
            return True
        return False
    else:
        output = service_operations_by_systemctl(dut, service=service, operation="stop")
        for msg in error_msgs:
            if msg in output:
                st.error("Observerd Error while stopping the {} service".format(service))
                return False
        deploy_package(dut, packane_name=service, mode='purge')
        if apach:
            output = service_operations_by_systemctl(dut, service=service_apach, operation="stop")
            for msg in error_msgs:
                if msg in output:
                    st.error("Observerd Error while stopping the {} service".format(service_apach))
                    return False
            deploy_package(dut, packane_name=service_apach, mode='purge')
            if radv:
                output = service_operations_by_systemctl(dut, service=service_radv, operation="stop")
                for msg in error_msgs:
                    if msg in output:
                        st.error("Observerd Error while stopping the {} service".format(service_radv))
                        return False
                deploy_package(dut, packane_name=service_radv, mode='purge')
        if route_list:
            for ip in route_list:
                if ipv4_relay_agent_ip:
                    ip_api.delete_static_route(dut, next_hop=ipv4_relay_agent_ip, static_ip=ip)
        if route_list_v6:
            for ip6 in route_list_v6:
                if ipv6_relay_agent_ip:
                    ip_api.delete_static_route(dut, next_hop=ipv6_relay_agent_ip, static_ip=ip6, family='ipv6')
        if ipv4_server_ip:
            ip_api.delete_ip_interface(dut, vlan_int, ipv4_server_ip, ipv4_server_ip_mask)
        if ipv6_server_ip:
            ip_api.delete_ip_interface(dut, vlan_int, ipv6_server_ip, ipv6_server_ip_mask, family='ipv6')
        if vlan:
            vlan_api.delete_vlan_member(dut, vlan, server_connected_port)
            vlan_api.delete_vlan(dut, [vlan])
        # st.banner('Disable dhcp snooping Globally on Server Node..')
        # snooping_api.config_dhcp_snooping(dut, addr_family='ip', enable_global='yes', config='no')
        st.log("Rebooting the device after purging of {} service to make the purge affect, "
               "without this isc-dhcp-server installation in other feature/module will fail.".format(service))
        st.reboot(dut, method="fast")
        return True


def get_content_file_number(file_path, search_string_pattern):
    try:
        command = "sed -nE '/^{}/=' {}".format(search_string_pattern, file_path)
        st.log("CMD: {}".format(command))
        line_number = os.popen(command).read()
        st.log("LINE NUMBER: {}".format(line_number))
        if line_number:
            return int(line_number)
    except Exception as e:
        st.log(e)
    return 0


def write_content_to_line_number(file_path, content, line_number):
    command = "sed -i '{} i  {}' {}".format(line_number, content, file_path)
    st.log("CMD: {}".format(command))
    os.popen(command).read()
    return True


def delete_content_from_line_number(file_path, line_number):
    command = "sed -i -e '{}d' {}".format(line_number, file_path)
    st.log("CMD: {}".format(command))
    os.popen(command).read()
    return True


def set_mgmt_ip_gw(dut, ipmask, gw, **kwargs):
    interface = st.get_mgmt_ifname(dut)
    cli_type = st.get_ui_type(dut)
    config = kwargs.get('config', 'yes')
    if cli_type in ['rest-put', 'rest-patch']:
        cli_type = 'klish'
    cmd = ""
    if cli_type in ['click']:
        if config.lower() == "yes":
            cmd = ["config interface ip add {} {} {}".format(interface, ipmask, gw)]
        else:
            cmd = ["config interface ip remove {} {} {}".format(interface, ipmask, gw)]
    elif cli_type in ['klish']:
        if interface == 'eth0':
            cmd = "interface Management 0"
            if config.lower() == "yes":
                cmd = cmd + "\n" + "ip address {} gwaddr {}".format(ipmask, gw)
            else:
                cmd = cmd + "\n" + "no ip address {} ".format(ipmask)
    else:
        st.log("UNSUPPORTED CLI TYPE ")
        return False
    if cmd:
        st.config(dut, cmd, type=cli_type, **kwargs)

    return True


def get_ip_route_list(dut, interface, **kwargs):
    # ensure that the interface admin state is up
    command = "/sbin/ip link set dev {} up".format(interface)
    st.config(dut, command, skip_error_check=True, **kwargs)

    # fetch the route list
    command = "/sbin/ip route list dev {}".format(interface)
    output = st.show(dut, command, skip_error_check=True, **kwargs)
    if len(output) <= 0 or "address" not in output[0]:
        return None
    ip_address = output[0]['address']
    return ip_address


def get_mgmt_ip(dut, interface, force=False, **kwargs):
    if not force:
        ip_address = get_ip_route_list(dut, interface, **kwargs)
        if ip_address:
            return ip_address
        msg = "Unable to get the ip address of '{}' from '/sbin/ip route list'. Falling back to 'ifconfig'.."
        st.log(msg.format(interface), dut=dut)
    ipaddr_list = get_ifconfig_inet(dut, interface, **kwargs)
    if ipaddr_list:
        return ipaddr_list[0]
    return None


def renew_mgmt_ip(dut, interface, **kwargs):
    cli_type = st.get_ui_type(dut)

    # There is a issue in click to renew management ip. So, using klish
    if st.is_feature_supported("klish", dut):
        cli_type = "klish"

    if cli_type == "click":
        output_1 = st.config(dut, "/sbin/dhclient -v -r {}".format(interface), skip_error_check=True, expect_ipchange=True, **kwargs)
        output_2 = st.config(dut, "/sbin/dhclient -v {}".format(interface), skip_error_check=True, expect_ipchange=True, **kwargs)
        return "\n".join([output_1, output_2])
    elif cli_type == "klish":
        zero_or_more_space = utils_obj.get_random_space_string()
        command = "renew dhcp-lease interface Management{}{}".format(zero_or_more_space, interface.strip('eth'))
        return st.show(dut, command, type=cli_type, skip_tmpl=True, skip_error_check=True, expect_ipchange=True, **kwargs)


def set_mgmt_vrf(dut, mgmt_vrf):
    import apis.system.management_vrf as mgmt_vrf_api
    if mgmt_vrf == 1:
        return mgmt_vrf_api.config(dut)
    elif mgmt_vrf == 2:
        return mgmt_vrf_api.config(dut, no_form=True)


def is_routed_vlan_subintf_supported(dut):
    """
    CAUTION: Dell specific api. Consider using is_sub_intf_platform()
    purpose:
        This definition is used to check whether DUT supports routed-vlan sub-interface feature or not.
        It is supported only in Broadcom Trident3 based platforms. Hence this proc returns True only for those platforms.
        In future, once other chipsets supports routed-vlan sub-interface, then this proc should have an entry
        in the following dictionary
    """

    platform_to_chipset_family_map = {
        "DellEMC-S5212f-P-25G": "TRIDENT3",
        "DellEMC-S5224f-P-25G": "TRIDENT3",
        "DellEMC-S5232f-C8D48": "TRIDENT3",
        "DellEMC-S5232f-P-10G": "TRIDENT3",
        "DellEMC-S5232f-C32": "TRIDENT3",
        "DellEMC-S5232f-P-100G": "TRIDENT3",
        "DellEMC-S5232f-P-25G": "TRIDENT3",
        "DellEMC-S5248f-P-10G": "TRIDENT3",
        "DellEMC-S5296f-P-10G": "TRIDENT3",
        "DellEMC-S5248f-P-25G": "TRIDENT3",
        "DellEMC-S5296f-P-25G": "TRIDENT3",
        "DellEMC-S5296f-P-25G-DPB": "TRIDENT3",
        "DellEMC-S5248f-P-25G-DPB": "TRIDENT3",
        "DellEMC-Z9432f-O32": "TRIDENT4"
    }

    routed_vlan_subif_supported_chipsets = [
        "TRIDENT3",
        "TRIDENT4"
    ]

    platform = get_hwsku(dut)
    if platform is not None:
        chipset_family = platform_to_chipset_family_map.get(platform)
        if chipset_family is not None:
            for x in routed_vlan_subif_supported_chipsets:
                if x is chipset_family:
                    return True

    return False


def get_free_output(dut):
    command = "free"
    return st.show(dut, command)


def verify_free_memory(dut, mem_diff):
    avail_output = list()
    for i in range(0, 5):
        output = get_free_output(dut)
        avail_output.append(int(output[0]['available']) if output else 0)
        if i < 4:
            st.wait(60)
    st.log("AVAILABLE MEMORY SAMPLES - {}".format(avail_output))
    if (avail_output[4] - avail_output[3]) > int(mem_diff) and (avail_output[3] - avail_output[2]) > int(mem_diff) and (avail_output[2] - avail_output[1]) > int(mem_diff) and (avail_output[1] - avail_output[0]) > int(mem_diff):
        st.log("Observed continous decrement in available memory")
        return False
    return True


def get_techsupport(dut=None, filename='TechSupport'):
    """
    This proc is used for copying the tech support from the DUT.
    :param duts:
    :param file:
    :return:
    """
    st.generate_tech_support(dut, filename)


def config_radius_server(dut, **kwargs):
    """
    API to install / configure free radius server on provided DUT and parameters
    :param dut:
    :param kwargs:
    :return:
    """
    config_files_path = kwargs.get("config_files_path")
    service = kwargs.get("service", "freeradius")
    action = kwargs.get("action", "config")
    require_reboot = kwargs.get("require_reboot", False)
    installed = False
    freeradius_user = "freerad"
    process_id = 0
    if action not in ["config", "unconfig"]:
        st.error("UNSUPPORTED ACTION -- {}".format(action))
        return False
    if action == "config":
        if is_free_radius_installed(dut):
            installed = True
            output = get_ps_aux(dut, search_string="freeradius")
            if output:
                for process in output:
                    if process["user"] == freeradius_user and process["command"] == "freeradius -X":
                        process_id = int(process["pid"])
                        break
        if not installed:
            if not deploy_package(dut, mode='update'):
                st.report_fail("APT failed to get package list.")
            if not deploy_package(dut, packane_name=service, mode='install'):
                st.report_fail("Freeradius installation is failed")
            for config_file in config_files_path:
                st.upload_file_to_dut(dut, config_file, "/tmp/")
                file_name = os.path.basename(config_file)
                st.config(dut, 'sudo mv /tmp/' + file_name + ' /etc/freeradius/3.0/', skip_error_check=True)
                st.config(dut, "sudo cp /etc/freeradius/3.0/users /etc/freeradius/3.0/users1")
                st.config(dut, "sudo rm -rf /etc/freeradius/3.0/users")
                st.config(dut, "sudo ln -s mods-config/files/authorize /etc/freeradius/3.0/users")
                st.config(dut, "sudo cp /etc/freeradius/3.0/users1 /etc/freeradius/3.0/users")
        else:
            if process_id:
                st.config(dut, "kill -9 {}".format(process_id))
        st.config(dut, "sudo service freeradius stop")
        st.config(dut, "freeradius -X > freeradius.log &")
        return True
    else:
        if is_free_radius_installed(dut):
            deploy_package(dut, packane_name=service, mode='purge')
            if require_reboot:
                st.log("Rebooting the device after purging of {} service to make the purge affect, "
                       "without this isc-dhcp-server installation in other feature/module will fail.".format(service))
                st.reboot(dut, method="fast")
        return True


def is_free_radius_installed(dut):
    """API to check whether free radius is installed or not"""
    output = st.config(dut, "freeradius -v", skip_error_check=True)
    if "not found" in output:
        return False
    return True


def swss_config(dut, data):
    if st.get_args("filemode"):
        return
    file_path1 = "/tmp/swss_config.json"
    file_path2 = "/swss_config.json"
    local_file = write_to_text_file(data)
    st.upload_file_to_dut(dut, local_file, file_path1)
    st.config(dut, "docker cp {0} swss:{1}".format(file_path1, file_path2))
    st.config(dut, "docker exec -it swss bash -c 'swssconfig {0}'".format(file_path2))


def flush_iptable(dut):
    st.config(dut, "iptables -F")


def execute_linux_cmd(dut, cmd):
    st.show(dut, cmd, skip_tmpl=True)


def list_file(dut, path, **kwargs):
    """
    Purpose: To list files in a directory. This uses a time format to display date and time as required

    :param dut: Device name
    :param path: Directory path
    :param listing: Enable or Disable '-l' option
    :param search_keyword: Search keywords for grepping
    :param time_style: Time display format
    :return: List containing output
    """
    listing = kwargs.get("listing", True)
    search_keyword = kwargs.get("search_keyword", False)
    time_style = kwargs.get("time_style", "+%Y-%m-%d %T")
    command = "sudo ls"
    option = ""
    if listing:
        option += " -l"
        option += " --time-style='{}'".format(time_style)
    command += option
    command += " " + path
    if search_keyword:
        command += " | grep '{}'".format(search_keyword)
    output = st.show(dut, command, skip_error_check=True, on_cr_recover="retry5")
    if not output:
        st.error("File not found")
    return output


def is_file_in_path(dut, path, file_list, **kwargs):
    """
    Check the files in the provided path , return bool.
    :param dut:
    :param path:
    :param file_list:
    :param kwargs:
    :return:
    """

    output = list_file(dut, path, **kwargs)
    rv = True
    for i in make_list(file_list):
        if not filter_and_select(output, None, {'entry_name': i}):
            rv = False
    return rv


def generate_dummy_file(dut, dest_file_path, **kwargs):
    """

    :param dut:
    :param dest_file_path:
    :param kwargs: block_size=requires file block size in bytes
                   no_of_blocks=requires integer number
                                such that required file size = block size X no of blocks
    :return:
    """
    block_size = kwargs.get("block_size", 1073741824)
    no_of_blocks = kwargs.get("no_of_blocks", 1)
    skip_error_check = kwargs.get("skip_error_check", False)
    cmd = "dd  if=/dev/zero of={} bs={} count={}".format(dest_file_path, block_size, no_of_blocks)
    result = st.config(dut, cmd, skip_tmpl=True, skip_error_check=skip_error_check)
    if result:
        return result
    return False


def show_ram_memory_composition(dut, keyword=None):
    cmd = "cat /proc/iomem"
    if keyword:
        cmd += " | grep -i '{}'".format(keyword)
    output = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    if output:
        return output
    return False


def check_device_mount(dut, path):
    cmd = "mount | grep '{}'".format(path)
    output = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    if output:
        return output
    return False


def kill_process(dut, process_id):
    cmd = "kill -9 {}".format(process_id)
    st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    return True


def set_dut_date(dut, date_string):
    cmd = 'date -s "' + date_string + '"'
    st.config(dut, cmd, skip_error_check=True)


def show_techsupport_file_content(dut, tech_file_name, search_list=None):
    cmd = "tar -tvf /var/dump/" + tech_file_name
    if search_list:
        search_list = make_list(search_list)
        for each in search_list:
            cmd += ' | grep "{}"'.format(each)
    output = st.show(dut, cmd, skip_error_check=True)
    return output


def exec_ssh_remote_dut(dut, ipaddress, username, password, command=None, timeout=30, **kwargs):

    # Check if sshpass exists, if not update and install
    check_cmd = "which sshpass"
    output = st.config(dut, check_cmd, skip_error_check=True)
    st.log("Command '{}' Output: '{}'.".format(check_cmd, output), dut=dut)
    if "sshpass" not in output:
        install_cmd = "sudo apt-get update;sudo apt-get -f install -y sshpass"
        output = st.config(dut, install_cmd, faster_cli=False, skip_error_check=True, max_time=600)
        st.log("Command '{}' Output: '{}'.".format(check_cmd, output), dut=dut)

    # Construct the sshpass command.
    # nosemgrep-next-line
    exec_command = "sshpass -p '{}' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout={} {}@{} {}"
    exec_command = exec_command.format(password, timeout, username, ipaddress, command or "show uptime")

    # Execute the command
    return st.show(dut, exec_command, skip_tmpl=True, **kwargs)

# phase: pre-tryssh, post-tryssh


def verify_device_info(dut, phase):
    method = st.getenv("SPYTEST_VERIFY_DEVICE_INFO_METHOD", "0")
    # method specifies the device info to be used and action to be taken.
    #   1.1 - uses MAC address of management interface and forces node to be dead as action
    #   1.2 - uses MAC address of management interface and forces node to be used in console
    #   2.1 - uses eeprom serial number and forces node to be dead as action
    #   2.2 - uses eeprom serial number and forces node to be used in console
    #   3.1 - creates a random file and deletes it to verify and forces node to be dead as action
    #   3.2 - creates a random file and deletes it to verify and forces node to be used in console
    #   4.1 - creates a random file and forces node to be dead as action to simulate error
    #   4.2 - creates a random file and forces node to be used in console to simulate error
    #   *   - disabled
    api_info = "verify device info:"
    if phase not in ["pre-tryssh", "post-tryssh"]:
        st.abort_run(99, "{} unknown phase {}".format(api_info, phase))
        return True
    if method not in ["1.1", "1.2", "2.1", "2.2", "3.1", "3.2", "4.1", "4.2"]:
        return True

    # read the old value
    name, value = "device-info-key", "device-info-value"
    result, old = True, st.get_cache(name, dut, None)

    # skip reading pre-tryssh if already known based on method
    if phase == "pre-tryssh" and old and method not in ["3.1", "3.2"]:
        return True

    # build the device info based on method
    if method in ["1.1", "1.2"]:
        value = get_ifconfig_ether(dut)
        result = bool(old == value)
    elif method in ["2.1", "2.2"]:
        value = get_platform_syseeprom(dut, 'Serial Number', 'Value')
        result = bool(old == value)
    elif phase == "pre-tryssh":
        value = random.random()
        file_path = "/tmp/device-info.{}".format(value)
        result = file_create(dut, "", file_path, sudo=False)
    elif phase == "post-tryssh":
        file_path = "/tmp/device-info.{}".format(old)
        result = file_delete(dut, file_path, sudo=False)

    # force the error
    result = result and bool(method not in ["4.1", "4.2"])

    # save the value
    if phase == "pre-tryssh":
        st.set_cache(name, value, dut)
        return True

    # compare the new value with saved value
    if not result:
        if method.endswith(".1"):
            st.abort_run(99, "Duplicate IP")
        return False

    # verified the device info
    return True


def get_memory_histogram_info(dut, type, **kwargs):
    """
    Get memory info from Memory histogram CLI
    Author: Nagappa Chincholi
    :param dut:
    :param type: process or docker or system
    :kwargs - stime , etime , filter, analyze
    :return:
    """
    command = "show histogram memory {}".format(type)

    if 'stime' in kwargs.keys():
        command += " stime {}".format(kwargs['stime'])
    if 'etime' in kwargs.keys():
        command += " etime {}".format(kwargs['etime'])
    if 'analyze' in kwargs.keys():
        command += " analyze {}".format(kwargs['analyze'])
    if 'filter' in kwargs.keys():
        command += " filter {}".format(kwargs['filter'])

    output = st.show(dut, command)
    if 'return_field' in kwargs.keys() and 'filter' in kwargs.keys():
        return output[0][kwargs['return_field']]
    else:
        return output[0]


def get_file_output(dut, filename, sudo_user='yes'):
    """
    To return content in specific file
    Author: Jagadish Chatrasi(jagadish.chatrasi@broadcom.com)
    :param dut:
    :param filename:
    :return:
    """
    if sudo_user == 'no':
        command = "cat {}".format(filename)
    else:
        command = "sudo cat {}".format(filename)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    st.debug("Raw output: {}".format(output))
    out_list = output.strip().split('\n') if "\n" in output else output.strip().split()
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return [x for x in out_list if x.strip()]


def is_campus_build(dut):
    if st.is_dry_run():
        return st.getenv("SPYTEST_DRYRUN_FORCE_CAMPUS") != "0"
    if st.get_testbed_vars().get('version'):
        version = st.get_testbed_vars().version[dut]
    else:
        version = show_version(dut, report=False)['version']
    if 'campus' in version.lower():
        return True
    return False


def copy_file_content_to_file(src_file, dst_file=None):
    """
    Wrapper to copy/write the contents for source file to destination file
    :param src_file:
    :param dst_file:
    :return:
    """
    try:
        import shutil
        dst_file_name = os.path.basename(src_file)
        act_dst_file_path = "{}/{}".format(dst_file.rstrip("/"), dst_file_name)
        shutil.copy(src_file, act_dst_file_path)
        return act_dst_file_path
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        message, function_name, line_no = (str(e), traceback.extract_tb(exc_tb)[-1][0], traceback.extract_tb(exc_tb)[-1][1])
        st.error("{} - {} - {}".format(message, function_name, line_no))
        return False


def verify_log_messages_by_time_stamp(dut, search_string, file_path, match_string):
    """
    Common function to compare the logs.
    :param dut:
    :param search_string: Time stamp
    :param file_path:
    :param match_string:
    :return:
    """
    response = find_line_in_file(dut, search_string=search_string, file_path=file_path, device="dut", verify=False)
    if response.find(match_string) > 1:
        return True
    else:
        return False


def get_image_tag(dut, repo_name, vrf="mgmt"):
    """
    To get tag value for a repo

    :param dut:
    :param repo_name:
    :return: tag vale on PASS
             False on FAIL
    """
    if vrf == "mgmt":
        command = "docker -H unix:///run/docker-mgmt.socket images"
    elif vrf == "default":
        command = "docker -H unix:///run/docker-default.socket images"
    output = st.show(dut, command)
    tag_out = filter_and_select(output, ['tag'], {'repo': repo_name})
    if not tag_out:
        st.error("No match for {} = {} in output".format('repository', repo_name))
        return False
    else:
        return tag_out


def read_disk_space(dut, **kwargs):
    cli_type = 'click'
    parsed_output = st.show(dut, 'sudo df -h', type=cli_type)
    if len(parsed_output) == 0:
        st.error("Output is Empty")
        return False
    if 'return_output' in kwargs:
        return parsed_output
    st.banner(parsed_output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], parsed_output[0][each]))
            return False
    return True


def sync_disk_space(dut, **kwargs):
    st.config(dut, "sync", type='click', conf=False)


def check_core_files(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :return:

    Usage:
     basic.check_core_files(dut1)
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type == "click":
        output = st.show(dut, "sudo show core list", type='click')

    elif cli_type in ["rest-put", "rest-patch"]:
        rest_url = st.get_datastore(dut, "rest_urls")["coreshow"]
        coredata = st.rest_read(dut, rest_url)
        st.log('The rest url is {}'.format(coredata))
        output = coredata['output']

    else:
        output = st.show(dut, "show core list", type='klish')

    entries = filter_and_select(output)

    if not entries:
        return False
    return True


def clear_core_files(dut, **kwargs):
    if st.is_feature_supported("klish", dut):
        st.config(dut, "clear core-files", type='klish')


def check_kdump_files(dut, **kwargs):

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_template = kwargs.get('skip_template', False)

    if cli_type == "click":
        output = st.show(dut, "sudo show kdump files", type='click', skip_tmpl=skip_template)

    else:
        output = st.show(dut, "show kdump files", type='klish', skip_tmpl=skip_template)

    if 'return_output' in kwargs:
        return output
    if 'No kernel core dump files' in output:
        return False
    return True


def clear_kdump_files(dut, **kwargs):
    pass


def set_klish_timeout(dut, timeout=10, **kwargs):
    conn_index = kwargs.get("conn_index", None)
    st.show(dut, "terminal timeout {}".format(timeout), type="klish", skip_error_check=True, skip_tmpl=True, conn_index=conn_index)


def verify_config_reload_status(dut, **kwargs):
    """
    Verify the output of 'show config-reload status'.
    Author: Aman Saini (aman.saini@broadcom.com)
    :param :dut:
    :param :return_output = True/False (default: False): returns the output.
    :param :State
    :param :StateDetail
    :param :StartTime
    :param :EndTime
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:

    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    # CLI not supported in click.
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    return_flag = True
    if cli_type in utils_obj.get_supported_ui_type_list():
        import apis.system.system_server as sys_server_api
        kwargs['cli_type'] = cli_type
        kwargs['return_output'] = kwargs.pop('return_output', False)
        return sys_server_api.verify_reload_stats(dut, **kwargs)
    elif cli_type == 'click':
        st.error("CLI not supported in CLICK. Supported only in KLISH.")
        return False
    elif cli_type == 'klish':
        command = "show config-reload status"
        output = st.show(dut, command, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)
    else:
        st.error("Supported modes are only KLISH and REST/GNMI.")
        return False
    return_output = kwargs.pop('return_output', False)

    st.log("output={}, kwargs={}".format(output, kwargs))
    if return_output:
        return output

    for key in ['cli_type', 'skip_template', 'return_output', 'skip_error']:
        kwargs.pop(key, None)

    if output == []:
        output = [{}]
    for key in kwargs.keys():
        if key in output[0]:
            if kwargs[key] != output[0][key]:
                st.error("key: {} Input value: {}, Output value: {} are not same".format(key, kwargs[key], output[0][key]))
                return_flag = False
            else:
                st.log('Found for key: {}, val:{}'.format(key, kwargs[key]))
        else:
            st.error("{} not found in the output.".format(key))
            return_flag = False
    return return_flag


def verify_system_processes_cpu(dut, pname, **kwargs):
    """
    :param dut:
    :param pname (mandetory)
    :param kwargs: cpu, memory, mem_usage
    :return:
    """
    ret_val = True
    if not isinstance(pname, list):
        pname = [pname]
    input_dict_list = kwargs_to_dict_list(**kwargs)
    for name, in_di_li in zip(pname, input_dict_list):
        output = st.show(dut, "show system processes cpu | grep {}".format(name), type="klish")
        kwargs['name'] = name
        in_di_li = [in_di_li]
        for input_dict in in_di_li:
            st.log("input_dict_list is {}".format(in_di_li))
            st.log("output is {}".format(output))
            if 'cpu' in kwargs:
                if int(output[0]['cpu']) <= int(in_di_li[0]['cpu']):
                    st.log("PASS: process {} actual CPU % {} <= expected CPU % {}".format(name, output[0]['cpu'], in_di_li[0]['cpu']))
                else:
                    st.log("INFO: process {} actual CPU % {} > expected CPU % {}".format(name, output[0]['cpu'], in_di_li[0]['cpu']))
                    ret_val = False
                del input_dict['cpu']
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
    return ret_val


def show_system_host_mac(dut):
    return st.show(dut, cmd="sonic-cfggen -H -v DEVICE_METADATA.localhost.mac", type='click')
