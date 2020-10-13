# This file contains the list of API's which performs logging / Syslog operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
import apis.system.switch_configuration as sc_obj
import re
import json
import apis.system.connection as conf_obj
import utilities.utils as utils
from utilities.common import exec_foreach


log_files = [r'/var/log/syslog', r'/var/log/syslog.1']


def show_logging(dut, severity=None, filter_list=None, lines=None):
    """
    To get logs from DUT.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param severity:
    :param filter_list:
    :param lines:
    :return:
    """

    if filter_list is None:
        filter_list = []
    filter_list = list(filter_list) if isinstance(filter_list, list) else [filter_list]
    command = "show logging"
    if lines:
        command += " -l {}".format(lines)
    if severity:
        command += " | grep '{}'".format(severity)
    for each_filter in filter_list:
        command += " | grep -i '{}'".format(each_filter)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = output.strip().split('\n')[:-1]
    for each in range(out_list.count("'")):
        out_list.remove("'")
    return out_list


def get_logging_count(dut, severity=None, filter_list=None):
    """
    To get log count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param severity:
    :param filter_list:
    :return:
    """

    if not severity and not filter_list:
        command = "sudo wc -l {} | grep total".format(' '.join(log_files))
        output = st.config(dut, command)
        output2 = re.findall(r'\d+', output)
        return int(output2[0]) if output2 else 0
    else:
        return len(show_logging(dut, severity, filter_list, lines=None))


def set_logging_severity(dut, **kwargs):
    """
    Set logging severity
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param severity:
    :param comp:
    :return:
    """
    if 'severity' not in kwargs:
        st.log("API: Mandatory parameter 'severity' is not provied.")
        return False
    command = "swssloglevel -l {} -a".format(kwargs['severity'].upper())
    if 'comp' in kwargs:
        command = ''
        comp_li = list( kwargs['comp']) if isinstance(kwargs['comp'], list) else [kwargs['comp']]
        for each_comp in comp_li:
            command += "swssloglevel -l {} -c {}\n".format(kwargs['severity'].upper(),each_comp)
    st.config(dut, command)
    return True


def clear_logging(dut, thread=True):
    """
    Clear all logging
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut: list
    :param thread: true
    :return:
    """
    def _clear_logging(dut):
        for each_log in log_files:
            command = "sudo truncate -s 0 {}".format(each_log)
            st.config(dut, command)
        return True

    dut_li = utils.make_list(dut)
    [out, exceptions] = exec_foreach(thread, dut_li, _clear_logging)
    st.log(exceptions)
    return False if False in out else True


def write_logging(dut, message):
    """
    Write logging
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param message:
    :return:
    """
    command = "logger {}".format(message)
    st.config(dut, command)
    return True


def check_unwanted_logs_in_logging(dut, user_filter=None):
    """
    Check unwanted log based on uers filter list
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param user_filter:
    :return:
    """
    result = True
    if user_filter is None:
        user_filter = []
    static_filter = ['error', 'i2c', 'fan', 'power']
    over_all_filter = static_filter + user_filter
    for each_string in over_all_filter:
        temp_count = get_logging_count(dut, filter_list=each_string)
        st.log("{} - logs found on the error string '{}'".format(temp_count, each_string))
        if temp_count:
            result = False
    return result


def config_syslog_server(dut, ipaddress_list):
    """
    Configure syslog servers.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress_list:
    :return:
    """

    ipaddress_li = list(ipaddress_list) if isinstance(ipaddress_list, list) else [ipaddress_list]
    st.log("Adding syslog server(s)")
    temp_local_data = {}
    syslog_local_final = {}
    for each_address in ipaddress_li:
        temp_local_data[each_address] = {}
    syslog_local_final['SYSLOG_SERVER'] = temp_local_data
    syslog_local_final_json = json.dumps(syslog_local_final)
    st.apply_json(dut, syslog_local_final_json)
    return True


def get_syslog_server(dut):
    """
    Get syslog servers.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """

    output = sc_obj.get_running_config(dut, 'SYSLOG_SERVER')
    return output


def clear_syslog_from_remote_server(dut):
    """
    Clear the logs from the syslog server
    Author: Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

    :param dut:
    :return:
    """
    syslog_ip = utils.ensure_service_params(dut, "syslog", "ip")
    syslog_port = utils.ensure_service_params(dut, "syslog", "port")
    syslog_username = utils.ensure_service_params(dut, "syslog", "username")
    syslog_password = utils.ensure_service_params(dut, "syslog", "password")
    syslog_path = utils.ensure_service_params(dut, "syslog", "path")
    command = "sudo truncate -s 0 {}".format(syslog_path)
    syslog_con_obj = conf_obj.connect_to_device(syslog_ip, syslog_username, syslog_password, port=syslog_port)
    conf_obj.execute_command(syslog_con_obj, command)
    return True


def get_syslog_from_remote_server(dut, severity=None, filter_list=None, lines=None):
    """
    Get the logs from the syslog server
    Author: Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

    :param dut:
    :param severity:
    :param filter_list:
    :param lines:
    :return:
    """

    syslog_ip = utils.ensure_service_params(dut, "syslog", "ip")
    syslog_port = utils.ensure_service_params(dut, "syslog", "port")
    syslog_username = utils.ensure_service_params(dut, "syslog", "username")
    syslog_password = utils.ensure_service_params(dut, "syslog", "password")
    syslog_path = utils.ensure_service_params(dut, "syslog", "path")

    if filter_list is None:
        filter_list = []
    filter_list = list(filter_list) if isinstance(filter_list, list) else [filter_list]
    command = "cat {}".format(syslog_path)
    if severity:
        command += " | grep '{}'".format(severity)
    for each_filter in filter_list:
        command += " | grep '{}'".format(each_filter)
    if lines:
        command += "| tail -n {} ".format(lines)
    syslog_con_obj = conf_obj.connect_to_device(syslog_ip, syslog_username, syslog_password, port=syslog_port)
    syslog_file_contents = conf_obj.execute_command(syslog_con_obj, command)
    return syslog_file_contents
