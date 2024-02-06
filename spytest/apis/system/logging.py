# This file contains the list of API's which performs logging / Syslog operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
import json

from spytest import st, putils

import apis.system.connection as conf_obj
import apis.system.switch_configuration as sc_obj

from utilities import utils
from utilities.common import make_list


log_files = [r'/var/log/syslog', r'/var/log/syslog.1']


def show_logging(dut, severity=None, filter_list=None, lines=None, log_type=None, keyword=None, cli_type=""):
    """
    To get logs from DUT.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param severity:
    :param filter_list:
    :param lines: Number of lines to be fetched.
    :param log_type: Value- IN_MEMORY=Use In-memory-logging command,
                             STANDARD=Use Standard syslog command,
                                 None=Selected based on severity.
    :param keyword: Search keyword
    :return:
    """

    if filter_list is None:
        filter_list = []
    filter_list = list(filter_list) if isinstance(filter_list, list) else [filter_list]
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'click' if cli_type in ['rest-patch', 'rest-put', 'klish'] + utils.get_supported_ui_type_list() else cli_type
    if log_type == 'IN_MEMORY':
        command = "show in-memory-logging"
    elif log_type == 'STANDARD':
        command = "show logging"
    elif severity in ['INFO', 'DEBUG']:
        command = "show in-memory-logging"
    else:
        command = "show logging"
    if lines:
        if cli_type == 'click':
            command += " -l {}".format(lines)
        elif cli_type == 'klish':
            command += "lines {}".format(lines)
    if keyword:
        if cli_type == 'click':
            command += " {}".format(keyword)
    if severity:
        command += " | grep '{}'".format(severity)
    for each_filter in filter_list:
        if cli_type == 'click':
            command += " | grep -i '{}'".format(each_filter)
        elif cli_type == 'klish':
            command += " | grep '{}'".format(each_filter)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = output.strip().split('\n')[:-1]
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return [x for x in out_list if x.strip()]


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
        comp_li = list(kwargs['comp']) if isinstance(kwargs['comp'], list) else [kwargs['comp']]
        for each_comp in comp_li:
            command += "swssloglevel -l {} -c {}\n".format(kwargs['severity'].upper(), each_comp)
    st.config(dut, command)
    return True


def clear_logging(dut, thread=True, log_file=None):
    """
    Clear all logging
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut: list
    :param thread: true
    :return:
    """
    def _clear_logging(dut):
        logs = utils.make_list(log_file) if log_file else log_files
        for each_log in logs:
            command = "sudo truncate -s 0 {}".format(each_log)
            st.config(dut, command)
        return True

    dut_li = utils.make_list(dut)
    [out, _] = putils.exec_foreach(thread, dut_li, _clear_logging)
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
    filters = ['i2c', 'fan', 'power']
    if user_filter:
        filters.extend(make_list(user_filter))
    for filter in filters:
        temp_count = get_logging_count(dut, filter_list=filter)
        st.debug("{} - logs found on the error string '{}'".format(temp_count, filter))
        if temp_count:
            if filter == 'fan':
                filters = ["INFO system#monitor: MEM :: Name:fand"]
                logs = show_logging(dut, filter_list=filter)
                for log in logs:
                    if not any(fil.lower() in log.lower() for fil in filters):
                        result = False
            else:
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


def sonic_clear(dut, skip_error_check=True, **kwargs):
    if st.is_feature_supported("sonic-clear-logging-command", dut):
        st.config(dut, "sonic-clear logging", skip_error_check=skip_error_check, **kwargs)


def check_for_logs_after_reboot(dut, severity=None, log_severity=[], except_logs=[]):
    output = show_logging(dut, severity)
    for log in output:
        results = re.findall(r".*.*sonic\s*(\S+)\s*.*", log)
        retval = [result in log_severity for result in results]
        if not all(retval):
            for except_log in except_logs:
                if except_log.lower() not in log.lower():
                    st.error('Unexpected log: {}'.format(log))
                    return False
                else:
                    continue
    return True


def show_memlogging(dut, severity=None, filter_list=None, lines=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To get memory logs from DUT.


    :param dut:
    :param severity:
    :param filter_list:
    :param lines:
    :return:
    """

    if filter_list is None:
        filter_list = []
    filter_list = list(filter_list) if isinstance(filter_list, list) else [filter_list]
    cli_type = 'click' if cli_type in ['rest-patch', 'rest-put', 'klish'] + utils.get_supported_ui_type_list() else cli_type
    command = "show in-memory-logging"
    if lines:
        if cli_type == 'click':
            command += " -l {}".format(lines)
        elif cli_type == 'klish':
            command += "lines {}".format(lines)
    if severity:
        command += " | grep '{}'".format(severity)
    for each_filter in filter_list:
        if cli_type == 'click':
            command += " | grep -i '{}'".format(each_filter)
        elif cli_type == 'klish':
            command += " | grep '{}'".format(each_filter)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = output.strip().split('\n')[:-1]
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return out_list


def get_memlogging_count(dut, severity=None, filter_list=None):
    """
    To get log count


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
        return len(show_memlogging(dut, severity, filter_list, lines=None))


def generate_log_from_cmd(dut, log_level, **kwargs):
    """
    :param dut:
    :param log_level:
    :param no_of_logs:
    :param msg_length:
    :param use_script:
    :return:
    """
    log_msg_id = kwargs.get("log_msg_id", -1)
    no_of_logs = kwargs.get("no_of_logs", 0)
    date_cmd = "$(date '+%Y-%m-%d %T.%N')"

    if no_of_logs == 0:
        st.log("'{}' logs can't be generated. Return the passed log_msg_id '{}'".format(no_of_logs, log_msg_id))
        return log_msg_id

    base_command = "logger -p {} ".format(log_level)

    st.log("Generating {} number of logs of {} level log".format(no_of_logs, log_level))
    for _ in range(no_of_logs):
        log_msg_id += 1
        log_message = '"Testing_log_msg_id_{}_start_{}_end"'.format(str(log_msg_id).zfill(7), date_cmd)
        final_command = base_command + log_message
        st.config(dut, final_command, skip_error_check=True)

    return log_msg_id


def generate_log_from_script(dut, log_level, logger_file_name, log_priority, **kwargs):
    """
    :param dut:
    :param log_level:
    :param no_of_logs:
    :param msg_length:
    :param use_script:
    :return:
    """
    no_of_logs = kwargs.get("no_of_logs", 0)
    log_msg_id = kwargs.get("log_msg_id", 0)
    msg_length = kwargs.get("msg_length", "small")

    if no_of_logs == 0:
        st.log("'{}' logs can't be generated. Return the passed log_msg_id '{}'".format(no_of_logs, log_msg_id))
        return log_msg_id

    st.log(
        "Generating {} number of logs of {} level log using script {} using log_msg_id '{}'".format(no_of_logs, log_level, logger_file_name, log_msg_id))
    if logger_file_name:
        command = "./{} {} {} {} {}".format(logger_file_name, log_priority,
                                            log_msg_id + 1, no_of_logs, msg_length)
        st.config(dut, command, skip_error_check=True)

    return log_msg_id + no_of_logs


def get_auth_logs(dut):
    """
    :param dut:
    :return:
    """
    command = "sudo cat /var/log/auth.log"
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = output.strip().split('\n')[:-1]
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return out_list
