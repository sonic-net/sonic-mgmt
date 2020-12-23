# This file contains the list of API's for operations on ZTP
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
from spytest import st
import apis.system.basic as basic_obj
import utilities.utils as utils_obj
import apis.system.switch_configuration as switch_conf_obj
import apis.system.interface as intf_obj
import apis.routing.ip as ip_obj
import apis.system.reboot as reboot_obj
import apis.system.boot_up as boot_up_obj
import datetime

wait_5 = 5
wait_10 = 10
wait_60 = 60


def show_ztp_status(dut, expect_reboot=False, cli_type=""):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to show ztp status
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    result = dict()
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type not in ["click", "klish"]:
        st.error("UNSUPPORTED CLI TYPE")
        return result
    command = "sudo ztp status" if cli_type == "click" else "show ztp-status"
    output = st.show(dut, command, expect_reboot=False, type=cli_type)
    file_name = dict()
    timestamps = dict()
    #excluded_file_name = ["--sonic-mgmt--#"]
    if output:
        for row in output:
            result["filenames"] = list()
            result["timestamps"] = list()
            if result.get("service"):
                pass
            else:
                result["service"] = row.get("service", "")
            # if not result["source"]:
            if result.get("source"):
                pass
            else:
                result["source"] = row.get("source", "")
            # if not result["status"]:
            if result.get("status"):
                pass
            else:
                result["status"] = row.get("status", "")
            # if not result["adminmode"]:
            if result.get("adminmode"):
                pass
            else:
                result["adminmode"] = row.get("adminmode", "")
            # if not result["timestamp"]:
            result["timestamp"] = row.get("timestamp", "")
            if row.get("filename"):
                if cli_type == "click":
                    values = row["filename"].split(":")
                    file_name[values[0].strip()] = values[1].strip()
                    result["filenames"].append(file_name)
                elif cli_type == "klish":
                    file_name[row.get("filename")] = row.get("filestatus")
                    result["filenames"].append(file_name)
                    if row.get("filetimestamp"):
                        timestamps.update({row.get("filename"):row.get("filetimestamp")})
                        result["timestamps"].append(timestamps)
            # if not result["processingtext"]:
            # result["processingtext"] = row["processingtext"] if "processingtext" in row and row["processingtext"] else ""
    st.debug(result)
    return result


def verify_ztp_config_section_from_status(dut, file_names=list(), status="SUCCESS", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to verify the config section
    :param dut:
    :param file_names:
    :param status:
    :return:
    """
    is_found = 1
    if file_names:
        response = show_ztp_status(dut, cli_type=cli_type)
        for file_name in file_names:
            for names in response["filenames"]:
                if names[file_name] != status:
                    is_found = 0
                else:
                    is_found = 1
        if not is_found:
            return False
        return True


def _verify_ztp_status_with_retry(dut, retry_cnt, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to verify ZTP status with retry value
    :param dut:
    :param retry_cnt:
    :return:
    """
    not_started_retry_cnt = 0
    st.log("Verifying the ZTP status with retry method ...")
    for _ in range(1, retry_cnt + 1):
        response = show_ztp_status(dut, cli_type=cli_type)
        if response["adminmode"] == "True":
            st.log("Found that admin mode as {}".format(response["adminmode"]))
            if response["service"] == "Inactive":
                st.log("Found that service as {}".format(response["service"]))
                if response["status"] == "FAILED":
                    st.log("Found that status as {}".format(response["status"]))
                    return False
                elif response["status"] == "SUCCESS":
                    st.log("Found that status as {}".format(response["status"]))
                    return True
            elif response["service"] == "Processing" or response["service"] == "Active Discovery":
                st.log("Found that service as {}".format(response["service"]))
                if response["status"] == "IN-PROGRESS":
                    st.log("Found that status as {}".format(response["status"]))
                    st.wait(3)
                elif response["status"] == "FAILED":
                    st.log("Found that status as {}".format(response["status"]))
                    return False
                elif response["status"] == "Not Started":
                    st.log("Found that status as {}".format(response["status"]))
                    not_started_retry_cnt += 1
                    if not_started_retry_cnt >= retry_cnt:
                        return False
                    st.wait(3)
                else:
                    return True
            elif response["service"] == "SUCCESS":
                st.log("Found that service as {}".format(response["service"]))
                return True
        else:
            st.log("Found that ZTP is disabled hence enabling it ..")
            return False
    return False


def poll_ztp_status(dut, status=["IN-PROGRESS", "Not Started"], iteration=40, retry=3, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll the ztp status
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param status:
    :param iteration:
    :param retry:
    :return:
    """
    i = 1
    status = list([str(e) for e in status]) if isinstance(status, list) else [status]
    while True:
        response = show_ztp_status(dut, cli_type=cli_type)
        if response["status"] in status:
            st.log("Observed {} during polling ...".format(status))
            return True
        if i > iteration:
            st.log("Max polling interval {} exceeded ...".format(i))
            return False
        i += 1
        st.wait(retry)


# This function should be called with running ztp run command
def verify_ztp_status(dut, retry_cnt=0, iteration=300, retry=3, expect_reboot=False, reboot_on_success=list(), cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to verify ZTP status
    :param dut:
    :param retry_cnt:
    :return:
    """
    retry_count_if_no_response = 0
    if retry_cnt:
        return _verify_ztp_status_with_retry(dut, retry_cnt, cli_type=cli_type)
    else:
        st.log("Verifying the ZTP status with iteration method ...")
        for _ in range(1, iteration + 1):
            response = show_ztp_status(dut, expect_reboot=expect_reboot, cli_type=cli_type)
            if not response:
                st.log("Observed no response in ZTP status ... retrying {} .. ".format(retry_count_if_no_response))
                if retry_count_if_no_response > 5:
                    st.error("show ztp status returned empty data...")
                    return False
                st.wait(retry)
                retry_count_if_no_response += 1
                continue
            if "service" not in response or "status" not in response or "adminmode" not in response:
                st.log("Values of service or status or adminmode is not populated yet, retrying ...")
                st.wait(10)
                continue
            if response["adminmode"] == "True":
                if "service" not in response or "status" not in response or "adminmode" not in response:
                    st.log("Values of service or status or adminmode is not populated yet, retrying ...")
                    st.wait(retry)
                else:
                    # return verify_ztp_status(dut)
                    st.log("Found that admin mode as {}".format(response["adminmode"]))
                    if response["service"] == "Inactive":
                        st.log("Found that service as {}".format(response["service"]))
                        if response["status"] == "FAILED":
                            st.log("Found that status as {}".format(response["status"]))
                            return False
                        elif response["status"] == "SUCCESS":
                            st.log("Found that status as {}".format(response["status"]))
                            return True
                        else:
                            st.log("ZTP status is not in expected values , retrying...")
                            st.wait(retry)
                            # return verify_ztp_status(dut)
                    elif response["service"] == "Processing" or response["service"] == "Active Discovery":
                        st.log("Found that service as {}".format(response["service"]))
                        if response["status"] == "IN-PROGRESS":
                            st.log("Found that status as {}".format(response["status"]))
                            st.log("Files - {}".format(response["filenames"]))
                            if reboot_on_success and "filenames" in response and response["filenames"]:
                                reboot_flag = list(reboot_on_success) if isinstance(reboot_on_success, list) else [reboot_on_success]
                                if len(response["filenames"]) > 0:
                                    filenames = response["filenames"][0]
                                    for filename in reboot_flag:
                                        if filename in filenames and filenames[filename] == "SUCCESS":
                                            return True
                            if cli_type == "klish":
                                if len(response["filenames"]) > 0:
                                    for key,value in response["filenames"][0].items():
                                        if ("configdb-json" in key or "graphservice" in key) and value == "IN-PROGRESS":
                                            st.wait(300)
                            st.wait(retry)
                            # return verify_ztp_status(dut)
                        elif response["status"] == "FAILED":
                            st.log("Found that status as {}".format(response["status"]))
                            return False
                        elif response["status"] == "Not Started":
                            st.log("Found that status as {}".format(response["status"]))
                            st.wait(retry)
                            # return verify_ztp_status(dut)
                        elif response["status"] == "SUCCESS":
                            st.log("Found that status as {}".format(response["status"]))
                            st.wait(retry)
                            # return verify_ztp_status(dut)
                        else:
                            st.log("ZTP status is not in expected values, retrying...")
                            st.wait(retry)
                    elif response["service"] == "SUCCESS":
                        st.log("Found that service as {}".format(response["service"]))
                        return True
            else:
                st.log("Found that ZTP is disabled hence enabling it ..")
                ztp_operations(dut, "enable")
                # ztp_operations(dut, "run")
                # return verify_ztp_status(dut)
        return False


def get_ztp_timestamp_obj(ztp_timestamp):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to get ztp timestamp
    :param ztp_timestamp:
    :return:
    """
    try:
        return datetime.datetime.strptime(ztp_timestamp, '%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        st.error(e)


def enable_ztp_if_disabled(dut, iteration=5, delay=1, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to enable ztp if it is disabled, added check for enable in polling mechanism
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param iteration:
    :param delay:
    :return:
    """
    i = 1
    while True:
        response = show_ztp_status(dut, cli_type=cli_type)
        if "adminmode" in response and response["adminmode"] != "True":
            st.log("Enabling ZTP ...")
            ztp_operations(dut, "enable")
            break
        if i > iteration:
            st.log("ZTP admin mode not found after max iterations ...")
            break
        i += 1
        st.wait(delay)
    i = 1
    while True:
        response = show_ztp_status(dut, cli_type=cli_type)
        if "adminmode" in response and response["adminmode"] == "True":
            st.log("Admin mode enabled at {} iteration".format(i))
            return True
        if i > iteration:
            st.log("Max iteration {} count reached ".format(i))
            return False
        i += 1
        st.wait(delay)


def ztp_operations(dut, operation, cli_type="", max_time=0):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to do ZTP operations
    :param dut:
    :param operation:
    :return:
    """
    if cli_type == "click":
        supported_opers = ["run", "enable", "disable"]
        if operation not in supported_opers:
            return False
        if operation in ["run", "disable"]:
            command = "ztp {} -y".format(operation)
        else:
            command = "ztp {}".format(operation)
    elif cli_type == "klish":
        no_form = "no" if operation == "disable" else ""
        command = "{} ztp enable".format(no_form)
    st.config(dut, command, type=cli_type, max_time=max_time)


def ztp_push_full_config(dut, cli_type=""):
    """
    NOT USED ANYWHERE
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    APU to push full config
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    config_dbjson = "config_db.json"
    config_file = "ztp_data_local.json"
    plugin_file_path = "/etc/sonic/ztp/{}".format(config_file)
    source = "/tmp/{}".format(config_dbjson)
    plugin_json = {config_dbjson: {"url": {"source": "file://{}".format(source),
                                           "timeout": 300}, "save-config": "true"}}
    file_path = basic_obj.write_to_json_file(plugin_json)
    st.upload_file_to_dut(dut, file_path, plugin_file_path)
    running_config = switch_conf_obj.get_running_config(dut)
    file_path = basic_obj.write_to_json_file(running_config)
    st.upload_file_to_dut(dut, file_path, source)
    st.wait(wait_5)
    ztp_operations(dut, "run")
    st.wait(wait_60)
    show_ztp_status(dut, cli_type=cli_type)
    st.wait(wait_10)
    show_ztp_status(dut, cli_type=cli_type)


def prepare_and_write_option_67_config_string(ssh_conn_obj, static_ip, config_path, config_file, dhcp_config_file, type="http"):
    """
    NOT USED ANYWHERE
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to write option 67 to DHCP server
    :param ssh_conn_obj:
    :param static_ip:
    :param config_path:
    :param config_file:
    :param dhcp_config_file:
    :param type:
    :return:
    """
    option_67_config = "option bootfile-name"
    if type == "http":
        config_json_url = "http://{}{}/{}".format(static_ip, config_path, config_file)
    elif type == "tftp":
        config_json_url = "tftp://{}/{}/{}".format(static_ip, config_path, config_file)
    elif type == "ftp":
        config_json_url = "ftp://{}/{}/{}".format(static_ip, config_path, config_file)
    option_67_config_string = '{} "{}";'.format(option_67_config, config_json_url)
    if not basic_obj.write_update_file(ssh_conn_obj, option_67_config,
                                       option_67_config_string, dhcp_config_file):
        st.log("Written content in file {} not found".format(dhcp_config_file))
        st.report_fail("content_not_found")


def write_option_67_to_dhcp_server(ssh_conn_obj, data):
    """
    NOT USER ANY WHERE
    :param ssh_conn_obj:
    :param data:
    :return:
    """
    option_67_config = "option bootfile-name"
    if data.type == "http":
        config_json_url = "http://{}{}/{}".format(data.static_ip, data.config_path, data.config_file)
    elif data.type == "tftp":
        config_json_url = "tftp://{}/{}/{}".format(data.static_ip, data.config_path, data.config_file)
    elif data.type == "ftp":
        config_json_url = "ftp://{}/{}/{}".format(data.static_ip, data.config_path, data.config_file)
    option_67_config_string = '{} "{}";'.format(option_67_config, config_json_url)
    if not basic_obj.write_update_file(ssh_conn_obj, option_67_config,
                                       option_67_config_string, data.dhcp_config_file):
        st.log("Written content in file {} not found".format(data.dhcp_config_file))
        st.report_fail("content_not_found")
    basic_obj.service_operations(ssh_conn_obj, data.dhcp_service_name, data.action, data.device)
    if not verify_dhcpd_service_status(ssh_conn_obj, data.dhcpd_pid):
        st.log("{} service not running".format(data.dhcp_service_name))
        st.report_fail("service_not_running", data.dhcp_service_name)


def config_and_verify_dhcp_option(ssh_conn_obj, dut, ztp_params, data, expect_reboot=False, reboot_on_success=list(), cli_type=""):
    """
    Common function to configure DHCP option along with status / logs verification
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param ssh_conn_obj:
    :param dut:
    :param ztp_params:
    :param data:
    :return:
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    retry_count = data.retry_count if "retry_count" in data and data.retry_count else 0
    iteration = data.iteration if "iteration" in data and data.iteration else 300
    delay = data.delay if "delay" in data and data.delay else 3
    if "func_name" in data:
        syslog_file_names = ["syslog_1_{}".format(data.func_name), "syslog_{}".format(data.func_name)]
    # basic_obj.copy_config_db_to_temp(dut, data.config_db_path, data.config_db_temp)
    if "config_file_type" in data and data.config_file_type == "text":
        file_path = "/tmp/file_temp.json"
        basic_obj.write_to_file(ssh_conn_obj, data.json_content, file_path, device="server")
    elif "config_file_type" in data and data.config_file_type == "EoL":
        file_path = ""
    else:
        file_path = basic_obj.write_to_json_file(data.json_content)
    if file_path:
        destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.config_path, data.config_file)
        basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    if "config_db_location" in data and data.config_db_location == "json":
        st.download_file_from_dut(dut, data.config_db_temp, file_path)
        destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.config_path, data.config_db_file_name)
        basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    if "scenario" in data and data.scenario == "invalid-json":
        st.log("Writing invalid content to make invalid json ...")
        basic_obj.write_to_file_to_line(ssh_conn_obj, ",", 5, destination_path, "server")
    if data.option_type == "67":
        st.log("Creating {} file on DHCP server ...".format(data.config_file))
        data.search_pattern = r'\s*option\s+bootfile-name\s*\S*\s*"\S+";'
        data.option_string = "option bootfile-name"
        if data.type == "http":
            data.option_url = "http://{}{}/{}".format(data.static_ip, data.config_path, data.config_file)
        elif data.type == "tftp":
            data.option_url = "tftp://{}/{}/{}".format(data.static_ip, data.config_path, data.config_file)
        elif data.type == "ftp":
            data.option_url = "ftp://{}/{}/{}".format(data.static_ip, data.config_path, data.config_file)
        write_option_to_dhcp_server(ssh_conn_obj, data)
        basic_obj.service_operations(ssh_conn_obj, data.dhcp_service_name, data.action, data.device)
        if not verify_dhcpd_service_status(ssh_conn_obj, data.dhcpd_pid):
            st.log("{} service not running".format(data.dhcp_service_name))
            st.report_fail("service_not_running", data.dhcp_service_name)
        # write_option_67_to_dhcp_server(ssh_conn_obj, data)
    data.device_action = "reboot" if cli_type == "klish" else data.device_action
    if data.device_action == "reboot":
        reboot_type = data.reboot_type if "reboot_type" in data and data.reboot_type else "normal"
        basic_obj.remove_file(dut, data.config_db_path)
        st.reboot(dut, reboot_type, skip_port_wait=True)
        st.wait_system_status(dut, 500)
    elif data.device_action == "run":
        ztp_operations(dut, data.device_action)
    if "band_type" in data and data.band_type=="inband":
        if not basic_obj.poll_for_system_status(dut):
            st.log("Sytem is not ready ..")
            st.report_env_fail("system_not_ready")
        if not basic_obj.check_interface_status(dut, ztp_params.oob_port,"up"):
            basic_obj.ifconfig_operation(dut, ztp_params.oob_port, "down")
        interface_status = basic_obj.check_interface_status(dut, ztp_params.inband_port, "up")
        if interface_status is not None:
            if not interface_status:
                intf_obj.interface_noshutdown(dut, ztp_params.inband_port, cli_type=cli_type)
    if "service" in data and data.service == "disable":
        basic_obj.service_operations_by_systemctl(dut, "ztp", "stop")
        if basic_obj.verify_service_status(dut, "ztp"):
            st.log("ZTP status is not stopped")
            st.report_fail("service_not_stopped", "ztp")
        basic_obj.service_operations_by_systemctl(dut, "ztp", "start")
    if not poll_ztp_status(dut, ["IN-PROGRESS", "Not Started", "SUCCESS"], cli_type=cli_type):
        st.report_fail("ztp_max_polling_interval")
    if "check" in data and data.check == "not":
        if verify_ztp_status(dut, retry_count, iteration, delay, cli_type=cli_type):
            if "logs_path" in data and "func_name" in data:
                capture_syslogs(dut, data.logs_path, syslog_file_names)
            st.log("ZTP status verification failed")
            st.report_fail("ztp_status_verification_failed")
    else:
        st.log("Iteration count {}".format(iteration))
        st.log("REBOOT ON SUCCESS - {}".format(reboot_on_success))
        if reboot_on_success:
            if "configdb-json" in reboot_on_success:
                st.wait_system_reboot(dut)
                st.wait_system_status(dut, 300)
            result = verify_ztp_status(dut, retry_count, iteration, delay, expect_reboot=expect_reboot, reboot_on_success=reboot_on_success, cli_type=cli_type)
        else:
            result = verify_ztp_status(dut, retry_count, iteration, delay, expect_reboot=expect_reboot, cli_type=cli_type)
        if not result:
            if "logs_path" in data and "func_name" in data:
                capture_syslogs(dut, data.logs_path, syslog_file_names)
            st.log("ZTP status verification failed")
            st.report_fail("ztp_status_verification_failed")
        if reboot_on_success:
            output = show_ztp_status(dut, cli_type=cli_type)
            if output["status"] != "SUCCESS":
                st.wait(300, "Waiting for device to reboot after success...")
                st.wait_system_status(dut, 300)
            # st.wait_system_reboot(dut)
            if not verify_ztp_status(dut, retry_count, iteration, delay, cli_type=cli_type):
                if "logs_path" in data and "func_name" in data:
                    capture_syslogs(dut, data.logs_path, syslog_file_names)
                st.log("ZTP status verification failed")
                st.report_fail("ztp_status_verification_failed")
            st.banner(boot_up_obj.sonic_installer_list(dut))
    verify_ztp_filename_logs(dut, data)
    if "ztp_log_string" in data and data.ztp_log_string:
        if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path, data.ztp_log_string):
            st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path, data.ztp_log_string))
            if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path_1, data.ztp_log_string):
                st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path_1, data.ztp_log_string))
                st.report_fail("ztp_log_verification_failed", data.ztp_log_path_1, data.ztp_log_string)
    if "result" in data and data.result == "pass":
        st.report_pass("test_case_passed")


def write_option_239_to_dhcp_server(ssh_conn_obj, data):
    st.log("##################### Writing option 239 to dhcp config file ... ##################")
    option_239 = 'option provision-url ='
    provisioning_script_path = "http://{}{}/{}".format(data["server_ip"], data["config_path"], data["provision_script"])
    option_239_config = '{} "{}";'.format(option_239, provisioning_script_path)
    option_67_config = "option bootfile-name"
    basic_obj.write_update_file(ssh_conn_obj, option_67_config,
                                "##", data["dhcp_config_file"])
    if not basic_obj.write_update_file(ssh_conn_obj, option_239,
                                       option_239_config, data["dhcp_config_file"]):
        st.log("Written content in file {} not found".format(data["dhcp_config_file"]))
        st.report_fail("content_not_found")

def write_option_225_to_dhcp_server(ssh_conn_obj, data):
    option_225 = "option option-225 ="
    option_225_path = data["minigraph_path"]
    option_225_config = '{} "{}";'.format(option_225, option_225_path)
    option_67_config = "option bootfile-name"
    option_239 = 'option provision-url ='
    basic_obj.write_update_file(ssh_conn_obj, option_67_config,
                                "##", data["dhcp_config_file"])
    basic_obj.write_update_file(ssh_conn_obj, option_239,
                                "##", data["dhcp_config_file"])
    if not basic_obj.write_update_file(ssh_conn_obj, option_225,
                                       option_225_config, data["dhcp_config_file"]):
        st.log("Written content in file {} not found".format(data["dhcp_config_file"]))
        st.report_fail("content_not_found")


def config_and_verify_option_225(ssh_conn_obj, dut, ztp_params, data, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if data.option_type == "225":
        if "func_name" in data:
            syslog_file_names = ["syslog_1_{}".format(data.func_name), "syslog_{}".format(data.func_name)]
        data.search_pattern = r'\s*option option-225\s*\S*\s*"\S+";'
        data.option_string = "option option-225 "  # "option dhcp6.boot-file-url "
        data.option_url = data.minigraph_path
        data.option_type = "option_67"
        clear_options_from_dhcp_server(ssh_conn_obj, data)
        data.option_type = "option_239"
        clear_options_from_dhcp_server(ssh_conn_obj, data)
        write_option_to_dhcp_server(ssh_conn_obj, data)
        # write_option_225_to_dhcp_server(ssh_conn_obj, data)
        basic_obj.service_operations(ssh_conn_obj, data.dhcp_service_name, data.action, data.device)
        if not verify_dhcpd_service_status(ssh_conn_obj, data.dhcpd_pid):
            st.log("{} service not running".format(data.dhcp_service_name))
            st.report_fail("service_not_running", data.dhcp_service_name)
        data.device_action = "reboot" if cli_type == "klish" else data.device_action
        if data.device_action == "reboot":
            reboot_type = data.reboot_type if "reboot_type" in data and data.reboot_type else "normal"
            basic_obj.remove_file(dut, data.config_db_path)
            st.reboot(dut, reboot_type, skip_port_wait=True)
            st.wait_system_status(dut, 400)
        elif data.device_action == "run":
            ztp_operations(dut, data.device_action)
        if not verify_ztp_status(dut, cli_type=cli_type):
            if "logs_path" in data and "func_name" in data:
                capture_syslogs(dut, data.logs_path, syslog_file_names)
            st.log("ZTP status verification failed")
            st.report_fail("ztp_status_verification_failed")
        verify_ztp_filename_logs(dut, data)
        if "ztp_log_string" in data and data.ztp_log_string:
            if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path, data.ztp_log_string):
                st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path, data.ztp_log_string))
                if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path_1, data.ztp_log_string):
                    st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path_1,
                                                                                  data.ztp_log_string))
                    st.report_fail("ztp_log_verification_failed", data.ztp_log_path_1, data.ztp_log_string)


def verify_ztp_attributes(dut, property, value, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    This is to verify the ztp attributes with the provided value
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: dut object
    :param property: status, service, adminmode, filenames, timestamp, source
    :param value: This is string except filenames, for file names {'03-test-plugin': 'Not Started', '02-test-plugin':
    'Not Started', 'configdb-json': 'Not Started'}
    :return: boolean
    """
    response = show_ztp_status(dut, cli_type=cli_type)
    if not response:
        return False
    if property in response:
        if property == "filenames":
            filenames = response["filenames"][0]
            for filename, status in filenames:
                if value[filename] != status:
                    return False
        else:
            if response[property] != value:
                return False
    else:
        return False
    return True


def verify_ztp_filename_logs(dut, data, status="SUCCESS", condition="positive"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    API to verify logs
    :param dut:
    :param data:
    :param status:
    :return:
    """
    filenames = list([str(e) for e in data.file_names]) if isinstance(data.file_names, list) else [data.file_names]
    log_msg = data.log_msg if "log_msg" in data and data.log_msg else "Checking configuration section {} result: {}"
    match = data.match if "match" in data else ""
    for file_name in filenames:
        log_string_1 = log_msg.format(file_name, status)
        st.log(log_string_1)
        if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path, log_string_1, match=match):
            if condition == "positive":
                st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path, log_string_1))
                if not basic_obj.poll_for_error_logs(dut, data.ztp_log_path_1, log_string_1, match=match):
                    st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path_1,
                                                                                  log_string_1))
                    st.report_fail("ztp_log_verification_failed", data.ztp_log_path_1, log_string_1)
                else:
                    return True
        else:
            return True



def config_ztp_backdoor_options(dut, ztp_cfg={"admin-mode": True, "restart-ztp-interval": 30}, dut_ztp_cfg_file="/host/ztp/ztp_cfg.json"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to enable backward options for ZTP
    :param dut:
    :param ztp_cfg:
    :param dut_ztp_cfg_file:
    :return:
    """
    ztp_cfg_file = basic_obj.write_to_json_file(ztp_cfg)
    st.upload_file_to_dut(dut, ztp_cfg_file, dut_ztp_cfg_file)


def ztp_status_verbose(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to get the ztp status verbose output with filename and its details as we are getting the status in ztp status API
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    command = "sudo ztp status -v" if cli_type == "click" else "show ztp-status"
    if cli_type == "click":
        return st.show(dut, command, type=cli_type)
    else:
        return show_ztp_status(dut, cli_type=cli_type)



def verify_plugin_chronological_order(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to verify the plugin chronological order of ztp status
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    st.log("Verifying timestamp for chronological order ... ")
    output = ztp_status_verbose(dut, cli_type=cli_type)
    data = list()
    if cli_type == "click":
        for val in output:
            data.append(val["filetimestamp"])
    else:
        for val in output["timestamps"]:
            for _, timestamp in val.items():
                data.append(timestamp)
        data.sort()
    for i, _ in enumerate(data):
        if i + 1 < len(data):
            result = utils_obj.date_time_delta(data[i], data[i + 1], True)
            st.log(result)
            if result[0] < 0 or result[1] < 0:
                st.log("Observed timestamp difference is not as expected ...")
                return False
    return True


def verify_dhclient_on_interface(dut, search_string, interface, expected_count=2):
    """
    API to verify DHCLIENT on provided interface using ps aux command
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param search_string:
    :param interface:
    :param expected_count:
    :return:
    """
    st.log("Verifying dhclient for {} interface".format(interface))
    ps_aux = basic_obj.get_ps_aux(dut, search_string)
    # if len(ps_aux) != expected_count:
    st.log("Observed {} DHCLIENT entries on {} interface".format(len(ps_aux), interface))
    # return False
    dhclient_str = "/run/dhclient.{}.pid".format(interface)
    if not ps_aux:
        st.error("DHCLIENT process not found on DUT ...")
        return False
    for entry in ps_aux:
        if dhclient_str in entry["command"]:
            st.log("Required dhclient is found ...")
            return True
    return False

def create_required_folders(conn_obj, path_list):
    """
    API to create folders as per the provided path in bulk
    :param dut:
    :param path:
    :return:
    """
    path_list = [path_list] if type(path_list) is str else list([str(e) for e in path_list])
    for path in path_list:
        basic_obj.make_dir(conn_obj, path, "server")
        basic_obj.change_permissions(conn_obj, path, 777, "server")


def config_dhcpv6_options(ssh_conn_obj, ztp_params, config_params, options=dict(), cli_type=""):
    """
    Common function to configure dhcpv6 options and verify the result on both inband and out of band interfaces
    :param ssh_conn_obj:
    :param ztp_params:
    :param config_params:
    :param options:
    :return:
    """
    cli_type = st.get_ui_type(config_params.dut, cli_type=cli_type)
    retry_count = config_params.retry_count if "retry_count" in config_params and config_params.retry_count else 0
    iteration = config_params.iteration if "iteration" in config_params and config_params.iteration else 300
    delay = config_params.delay if "delay" in config_params and config_params.delay else 3
    expect_reboot = True if "expect_reboot" in options and options ["expect_reboot"] else False
    st.log(config_params)
    if "func_name" in config_params:
        syslog_file_names = ["syslog_1_{}".format(config_params.func_name), "syslog_{}".format(config_params.func_name)]
    if "json_content" in config_params:
        file_path = basic_obj.write_to_json_file(config_params.json_content)
        st.log(file_path)
        if file_path:
            destination_path = "{}{}/{}".format(config_params.home_path, ztp_params.config_path, config_params.ztp_file)
            st.log(destination_path)
            basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    config_params.option_59_url = "http://[{}]{}/{}".format(config_params.static_ip, ztp_params.config_path, config_params.ztp_file)
    config_params.search_pattern = r'\s*option\s+dhcp6.boot-file-url\s+"\S+";'
    write_option_59_to_dhcp_server(ssh_conn_obj, config_params)
    basic_obj.service_operations(ssh_conn_obj, config_params.dhcp6_service_name, "restart", "server")
    if not verify_dhcpd_service_status(ssh_conn_obj, config_params.dhcpd6_pid):
        st.log("{} service is running which is not expected".format(config_params.dhcp6_service_name))
        st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
    reboot_type = config_params.reboot_type if "reboot_type" in config_params and config_params.reboot_type else "normal"
    if "ztp_operation" in config_params:
        config_params.ztp_operation = "reboot" if cli_type == "klish" else config_params.ztp_operation
        if config_params.ztp_operation == "reboot":
            basic_obj.remove_file(config_params.dut, config_params.config_db_path)
            st.reboot(config_params.dut, reboot_type, skip_port_wait=True)
        elif config_params.ztp_operation == "run":
            ztp_operations(config_params.dut, config_params.ztp_operation)
    else:
        st.log("ZTP operation is not mentioned hence rebooting the device ...")
        basic_obj.remove_file(config_params.dut, config_params.config_db_path)
        st.reboot(config_params.dut, reboot_type, skip_port_wait=True)
    if "reboot_on_success" in options and options["reboot_on_success"]:
        result = verify_ztp_status(config_params.dut, retry_count, iteration, delay, expect_reboot=expect_reboot, reboot_on_success=options["reboot_on_success"], cli_type=cli_type)
    else:
        result = verify_ztp_status(config_params.dut, retry_count, iteration, delay, expect_reboot=expect_reboot, cli_type=cli_type)
    if not result:
        if "logs_path" in config_params and "func_name" in config_params:
            capture_syslogs(config_params.dut, config_params.logs_path, syslog_file_names)
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    if "reboot_on_success" in options and options["reboot_on_success"]:
        reboot_obj.config_reload(config_params.dut)
        st.wait(5)
        if not ip_obj.ping(config_params.dut, config_params.static_ip, family="ipv6"):
            st.log("Pinging to DHCP server failed from DUT, issue either with DUT or server")
            # intf_obj.enable_dhcp_on_interface(config_params.dut, config_params.network_port, "v6")
        if not verify_ztp_status(config_params.dut, retry_count, iteration, delay, cli_type=cli_type):
            if "logs_path" in config_params and "func_name" in config_params:
                capture_syslogs(config_params.dut, config_params.logs_path, syslog_file_names)
            st.log("ZTP status verification failed")
            st.report_fail("ztp_status_verification_failed")
    verify_ztp_filename_logs(config_params.dut, config_params)
    if "ztp_log_string" in config_params and config_params.ztp_log_string:
        if not basic_obj.poll_for_error_logs(config_params.dut, config_params.ztp_log_path, config_params.ztp_log_string):
            st.log("ZTP log {} verification failed for message {}".format(config_params.ztp_log_path, config_params.ztp_log_string))
            if not basic_obj.poll_for_error_logs(config_params.dut, config_params.ztp_log_path_1, config_params.ztp_log_string):
                st.log("ZTP log {} verification failed for message {}".format(config_params.ztp_log_path_1, config_params.ztp_log_string))
                st.report_fail("ztp_log_verification_failed", config_params.ztp_log_path_1, config_params.ztp_log_string)
    if "result" in config_params and config_params.result == "pass":
        st.report_pass("test_case_passed")


def write_option_59_to_dhcp_server(connection_obj, data):
    """
    API to add option 59 in DHCP config file.
    :param connection_obj:
    :param data:
    :return:
    """
    line_number = basic_obj.get_file_number_with_regex(connection_obj, data.search_pattern, data.dhcp_config_file)
    option_59 = "option dhcp6.boot-file-url "
    option_59_path = data["option_59_url"]
    option_59_config = "'{} \"{}\";'".format(option_59, option_59_path)
    if line_number >= 0:
        basic_obj.delete_line_using_line_number(connection_obj, line_number, data.dhcp_config_file)
    basic_obj.write_to_file(connection_obj, option_59_config, data.dhcp_config_file, device="server")
    # else:
    #     basic_obj.delete_line_using_line_number(connection_obj, line_number, data.dhcp_config_file)
    #     basic_obj.write_to_file_to_line(connection_obj, option_59_config, line_number, data.dhcp_config_file, device="server")
    line_number = basic_obj.get_file_number_with_regex(connection_obj, data.search_pattern, data.dhcp_config_file)
    if line_number <=0:
        st.log("Written content in file {} not found".format(data["dhcp_config_file"]))
        st.report_fail("content_not_found")

def write_option_to_dhcp_server(connection_obj, data):
    """
    Common API to write matched line with new one
    :param connection_obj:
    :param data:
    :return:
    """
    line_number = basic_obj.get_file_number_with_regex(connection_obj, data.search_pattern, data.dhcp_config_file)
    option = data.option_string  # "option dhcp6.boot-file-url "
    option_path = data.option_url
    st.log("#####LINE NUMBER{}".format(line_number))
    option_config = "'{} \"{}\";'".format(option, option_path)
    if int(line_number) > 0:
        # line_number = data.line_number if line_number in data else 60
        basic_obj.delete_line_using_line_number(connection_obj, line_number, data.dhcp_config_file)
    basic_obj.write_to_file(connection_obj, option_config, data.dhcp_config_file, device="server")
    # basic_obj.write_to_file_to_line(connection_obj, option_config, line_number, data.dhcp_config_file, device="server")
    line_number = basic_obj.get_file_number_with_regex(connection_obj, data.search_pattern, data.dhcp_config_file)
    st.log("#####LINE NUMBER{}".format(line_number))
    if line_number <= 0:
        st.log("Written content in file {} not found".format(data["dhcp_config_file"]))
        st.report_fail("content_not_found")

def clear_options_from_dhcp_server(connection_obj, data):
    st.log("Clearing OPTIONS from DHCP server")
    option = ""
    if "option_type" in data and data.option_type == "option_67":
        option = r'\s*option\s+bootfile-name\s*\S*\s*"\S+";'
    elif "option_type" in data and data.option_type == "option_239":
        option = r'\s*option\s+provision-url\s*\S*\s*"\S+";'
    elif "option_type" in data and data.option_type == "option_59":
        option = r'\s*option\s+dhcp6.boot-file-url\s+"\S+";'
    elif "option_type" in data and data.option_type == "option_225":
        option = r'\s*option option-225\s*\S*\s*"\S+";'

    st.log("OPTION is {}".format(option))
    st.log("CONFIG FILE is {}".format(data.dhcp_config_file))
    if option:
        line_number = basic_obj.get_file_number_with_regex(connection_obj,
                                                           option, data.dhcp_config_file)
        if line_number > 0:
            basic_obj.delete_line_using_line_number(connection_obj, line_number,
                                                data.dhcp_config_file)

def verify_dhcpd_service_status(dut, process_id):
    """
    API to verify DHCLIENT on provided interface using ps aux command
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param search_string:
    :param interface:
    :param expected_count:
    :return:
    """
    st.log("Verifying DHCPD for {} ".format(process_id))
    dhcpd_pid = "/run/dhcp-server/{}".format(process_id)
    ps_aux = basic_obj.get_ps_aux(dut, dhcpd_pid, device="server")
    st.log(ps_aux)
    config_string = ""
    if process_id == "dhcpd6.pid":
        config_string = "-cf /etc/dhcp/dhcpd6.conf"
    if process_id == "dhcpd.pid":
        config_string = "-cf /etc/dhcp/dhcpd.conf"
    st.log("Verifying the output with {}".format(config_string))
    if config_string not in ps_aux:
        st.log("Required DHCPD service  not found ...")
        return False
    return True

def capture_syslogs(dut, destination_path, file_name):
    file_names = list(file_name) if isinstance(file_name, list) else [file_name]
    syslog_paths = ["/var/log/syslog.1", "/var/log/syslog"]
    for i, syslog_path in enumerate(syslog_paths):
        dst_file = "{}/{}".format(destination_path, file_names[i])
        st.download_file_from_dut(dut, syslog_path, dst_file)
    return True



