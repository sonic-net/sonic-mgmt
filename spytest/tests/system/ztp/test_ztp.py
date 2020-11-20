import os
import random
import pytest

from spytest import st, SpyTestDict, mutils

import apis.system.connection as con_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.system.ztp as ztp_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as intf_obj
import apis.system.reboot as reboot_obj
from apis.system.snmp import verify_snmp_details_using_docker
from apis.system.management_vrf import config as mvrfconfig

vars = dict()
ztp_params = SpyTestDict()
ztp_params.dhcp = SpyTestDict()
ztp_params.dhcp6 = SpyTestDict()
ssh_conn_obj = None
inband_ssh_conn_obj = None
ssh_conn_obj_oob_v6 = None
ssh_conn_obj_inb_v6 = None
functions_67 = ["test_ft_ztp_behv_invalid_json_and_config_sections",
                "test_ft_ztp_firmware_install_uninstall",
                "test_ft_ztp_restart_no_config", "test_ft_ztp_config_section_check_with_option_67",
                "test_ft_ztp_install_docker_package", "test_ft_ztp_after_warm_boot"]
functions_239 = ["test_ft_ztp_option_239"]
functions_225 = ["test_ft_ztp_with_legacy_options"]
feat_logging_console = False

def pre_config_ztp():
    global vars
    global ssh_conn_obj
    global inband_ssh_conn_obj
    global ssh_conn_obj_oob_v6
    global ssh_conn_obj_inb_v6
    vars = st.get_testbed_vars()
    # DHCPV4 out of band params
    ztp_params.dhcp.ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "ip")
    ztp_params.dhcp.username = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "username")
    ztp_params.dhcp.password = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "password")
    ztp_params.dhcp.config_file = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "config_file")
    ztp_params.dhcp.static_ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "static_ip")
    ztp_params.oob_port = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "interface")
    # DHCPV4 in band params
    ztp_params.dhcp.inband_ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "ip")
    ztp_params.dhcp.inband_username = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "username")
    ztp_params.dhcp.inband_password = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "password")
    ztp_params.config_path = mutils.ensure_service_params(vars.D1, "ztp", "config_path")
    ztp_params.firmware_path = mutils.ensure_service_params(vars.D1, "ztp", "firmware_path")
    ztp_params.home_path = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "home_path")
    ztp_params.build_file_name = mutils.ensure_service_params(vars.D1, "ztp", "build_file_name")
    ztp_params.uninstall_image = mutils.ensure_service_params(vars.D1, "ztp", "uninstall_image")
    ztp_params.dut_path = mutils.ensure_service_params(vars.D1, "ztp", "dut_path")
    ztp_params.ztp_cfg_file_name = mutils.ensure_service_params(vars.D1, "ztp", "ztp_cfg_file_name")
    ztp_params.provision_script_path = mutils.ensure_service_params(vars.D1, "ztp", "provision_script_path")
    ztp_params.docker_path = mutils.ensure_service_params(vars.D1, "ztp", "docker_path")
    ztp_params.docker_image = mutils.ensure_service_params(vars.D1, "ztp", "docker_image")
    ztp_params.docker_component_name = mutils.ensure_service_params(vars.D1, "ztp", "docker_component_name")
    ztp_params.inband_port = mutils.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "interface")
    ztp_params.minigraph_file = mutils.ensure_service_params(vars.D1, "ztp", "minigraph_file")
    ztp_params.xml_path = mutils.ensure_service_params(vars.D1, "ztp", "xml_path")
    # DHCPV6 out of band params
    ztp_params.dhcp6.ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "ip")
    ztp_params.dhcp6.username = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "username")
    ztp_params.dhcp6.password = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "password")
    ztp_params.dhcp6.oob_port = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "interface")
    ztp_params.dhcp6.oob_static_ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "static_ip")
    # DHCPV6 IN band params
    ztp_params.dhcp6.inband_ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "ip")
    ztp_params.dhcp6.inband_username = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "username")
    ztp_params.dhcp6.inband_password = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "password")
    ztp_params.dhcp6.inband_static_ip = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "static_ip")
    ztp_params.dhcp6.inband_port = mutils.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "interface")
    ztp_params.cli_type = st.get_ui_type(vars.D1)
    st.log("Clearing V4/V6 lease database from DUT ...")
    basic_obj.delete_directory_contents(vars.D1, config_params.lease_db_path)
    st.log("####### Connecting to DHCPV4 server -- OUT OF BAND ...###########")
    ssh_conn_obj = con_obj.connect_to_device(ztp_params.dhcp.ip,
                                             ztp_params.dhcp.username, ztp_params.dhcp.password)
    if not ssh_conn_obj:
        st.error("SSH connetion object not found.")
        reset_module_config()
        st.report_env_fail("ssh_connection_failed", ztp_params.dhcp.ip)
    inband_ssh_conn_obj = con_obj.connect_to_device(ztp_params.dhcp.inband_ip,
                                             ztp_params.dhcp.inband_username, ztp_params.dhcp.inband_password)
    if not inband_ssh_conn_obj:
        st.log("SSH connection to inband DHCP server is not successfull")
        # st.report_env_fail("ssh_connection_failed", ztp_params.dhcp.inband_ip)
    st.log("############Connecting to DHCPV6 server -- OUT OF BAND ...#########")
    ssh_conn_obj_oob_v6 = con_obj.connect_to_device(ztp_params.dhcp6.ip,
                                                    ztp_params.dhcp6.username, ztp_params.dhcp6.password)
    if not ssh_conn_obj_oob_v6:
        st.error("SSH connection object not found for DHCPV6 server OUT OF BAND.")
    ssh_conn_obj_inb_v6 = con_obj.connect_to_device(ztp_params.dhcp6.inband_ip,
                                                    ztp_params.dhcp6.inband_username, ztp_params.dhcp6.inband_password)
    if not ssh_conn_obj_inb_v6:
        st.error("SSH connection object not found for DHCPV4 server OUT OF BAND.")
    st.log("Stopping V4/V6 services on unwanted servers .. ")
    v6_connection_objs = [ssh_conn_obj_inb_v6, ssh_conn_obj_oob_v6]
    for connection_obj in v6_connection_objs:
        if connection_obj:
            basic_obj.service_operations(connection_obj, config_params.dhcp6_service_name, "stop", "server")
            if ztp_obj.verify_dhcpd_service_status(connection_obj, config_params.dhcpd6_pid):
                st.log("{} service is running which is not expected".format(config_params.dhcp6_service_name))
                reset_module_config()
                st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
    basic_obj.service_operations(ssh_conn_obj, config_params.dhcp_service_name, "restart", "server")
    if not ztp_obj.verify_dhcpd_service_status(ssh_conn_obj, config_params.dhcpd_pid):
        st.log("{} service is not running ".format(config_params.dhcp_service_name))
        reset_module_config()
        st.report_fail("service_running_not_expected", config_params.dhcp_service_name)
    st.wait(5)
    if not basic_obj.check_interface_status(vars.D1, ztp_params.oob_port,"up"):
        basic_obj.ifconfig_operation(vars.D1, ztp_params.oob_port, "up")
    intf_obj.enable_dhcp_on_interface(vars.D1, ztp_params.oob_port)
    if not ip_obj.ping(vars.D1, ztp_params.dhcp.static_ip):
        st.log("Pinging to DHCP server failed from DUT, issue either with DUT or server")
        reset_module_config()
        st.report_fail("ping_fail", ztp_params.dhcp.static_ip)
    ztp_cfg = {"admin-mode": True, "restart-ztp-interval": 30, "feat-console-logging": feat_logging_console}
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg)
    lines = basic_obj.get_number_of_lines_in_file(ssh_conn_obj, ztp_params.dhcp.config_file)
    st.log("###########LINES -- {}##############".format(lines))
def reset_module_config():
    basic_obj.delete_directory_contents(vars.D1, config_params.ztp_run_path)
    st.log("Resetting all DHCP services as part of module unconfig...")
    if ssh_conn_obj:
        con_obj.ssh_disconnect(ssh_conn_obj)
    connection_objs = [ssh_conn_obj_inb_v6, ssh_conn_obj_oob_v6]
    for connection_obj in connection_objs:
        if connection_obj:
            basic_obj.service_operations(connection_obj, config_params.dhcp6_service_name, "start", "server")
            con_obj.ssh_disconnect(connection_obj)
    if inband_ssh_conn_obj:
        basic_obj.service_operations(inband_ssh_conn_obj, config_params.dhcp_service_name, "start", "server")
        con_obj.ssh_disconnect(inband_ssh_conn_obj)
    reboot_obj.config_save(vars.D1)

@pytest.fixture(scope="module", autouse=True)
def ztp_module_hooks(request):
    st.add_prevent("ztp")
    initialize_config_params()
    pre_config_ztp()
    initialize_data_variables()
    path_list = [ztp_params.home_path+ztp_params.config_path, ztp_params.home_path+ztp_params.firmware_path,
                 ztp_params.home_path+ztp_params.provision_script_path, ztp_params.home_path+ztp_params.xml_path]
    ztp_obj.create_required_folders(ssh_conn_obj, path_list)
    if inband_ssh_conn_obj:
        basic_obj.service_operations(inband_ssh_conn_obj, data.dhcp_service_name, "stop", "server")
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml", "/etc/sonic/snmp.yml.bkp")
    source_path = "{}{}".format(config_params.local_provision_scripts_folder, config_params.snmp_filename)
    st.upload_file_to_dut(vars.D1, source_path, "/home/admin/snmp.yml")
    basic_obj.copy_file_to_local_path(vars.D1, "/home/admin/snmp.yml", "/etc/sonic/snmp.yml")
    yield
    reset_module_config()
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml.bkp", "/etc/sonic/snmp.yml")

@pytest.fixture(scope="function", autouse=True)
def ztp_func_hooks(request):
    initialize_config_params()
    initialize_data_variables()
    basic_obj.remove_file(vars.D1, data.ztp_local_json_path)
    if st.get_func_name(request) == 'test_ft_ztp_behv_invalid_json_and_config_sections':
        mvrfconfig(vars.D1, cli_type="click")
        reboot_obj.config_save(vars.D1)
    basic_obj.copy_config_db_to_temp(vars.D1, data.config_db_path, data.config_db_temp)
    basic_obj.change_permissions(vars.D1, data.config_db_temp)
    # st.log("Shutting down the inband interface ...")
    # intf_obj.interface_shutdown(vars.D1, ztp_params.inband_port)
    reboot_obj.config_save(vars.D1)
    ztp_obj.enable_ztp_if_disabled(vars.D1)
    config_params.func_name = st.get_func_name(request)
    yield
    basic_obj.copy_config_db_to_temp(vars.D1, data.config_db_temp, data.config_db_path)
    ztp_obj.ztp_operations(vars.D1, "disable")
    ztp_cfg = {"admin-mode": True, "restart-ztp-interval": 30, "feat-console-logging": feat_logging_console}
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg)
    if st.get_func_name(request) == 'test_ft_ztp_behv_invalid_json_and_config_sections':
        mvrfconfig(vars.D1, no_form=True, cli_type="click")
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.option_type = ""
    if st.get_func_name(request) in functions_67:
        config_params.option_type = "option_67"
    elif st.get_func_name(request) in functions_225:
        config_params.option_type = "option_225"
    elif st.get_func_name(request) in functions_239:
        config_params.option_type = "option_239"
    if config_params.option_type:
        ztp_obj.clear_options_from_dhcp_server(ssh_conn_obj, config_params)

wait_5 = 5
wait_10 = 10
wait_20 = 20
wait_60 = 60
def initialize_config_params():
    global config_params
    config_params = SpyTestDict()
    config_params.ztp_log_path_1 = "/var/log/ztp.log.1"
    config_params.result = "pass"
    config_params.lease_db_path = "/var/lib/dhcp"
    config_params.ztp_run_path = "/var/run/ztp"
    config_params.dhcp_service_name = "isc-dhcp-server"
    config_params.dhcp6_service_name = "isc-dhcp-server6"
    config_params.dhcpd_pid = "dhcpd.pid"
    config_params.dhcpd6_pid = "dhcpd6.pid"
    config_params.logs_path = "{}/logs".format(os.path.dirname(__file__))
    config_params.snmp_filename = "snmp.yml"
    config_params.local_path = os.path.dirname(__file__)
    config_params.local_provision_scripts_folder = "{}/scripts/".format(config_params.local_path)

def initialize_data_variables():
    global data
    data = SpyTestDict()
    data.ztp_log_path_1 = "/var/log/ztp.log.1"
    data.dhcp_service_name = "isc-dhcp-server"
    data.ztp_local_json_path = "/host/ztp/ztp_data.json"
    data.ztp_log_path = "/var/log/ztp.log"
    data.syslog_path = "/var/log/syslog"
    data.config_db_path = "/etc/sonic/config_db.json"
    data.client_path = "/home/admin"
    data.config_db_temp = "/home/admin/config_db_temp.json"
    data.temp_path = "/tmp"
    data.file_names = ["02-test-plugin","03-test-plugin","01-configdb-json"]
    data.local_path = os.path.dirname(__file__)
    data.local_provision_scripts_folder = "{}/scripts/".format(data.local_path)
    data.option_239_sh_file = "provisioning_script.sh"
    data.ping_script_file = "ping_test.sh"
    data.ztp_eol_file = "ztp_EoL.json"
    data.dut_ztp_cfg_file = "{}/{}".format(ztp_params.dut_path, ztp_params.ztp_cfg_file_name)
    data.config_db_location = "local"
    data.json_content = {"ztp":{"01-configdb-json":{"url":{"source":"file://{}".format(data.config_db_temp),
                                                       "timeout":300}},
                                                "02-test-plugin":{"message":"Test-Plugin-Test","message-file":"/home/admin/test-file1"},
                                                "03-test-plugin":{"message":"Test-Plugin-asdsads","message-file":"/home/admin/test-file2"}}}

@pytest.mark.ztp_behv_invalid_json_and_config_sections
@pytest.mark.ztp_regression
def test_ft_ztp_behv_invalid_json_and_config_sections(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Eamil: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # 1) Verify ZTP service behavior with invalid / incorrect DUT configuration
    # 2) Verify ZTP service behavior with invalid / incorrect JSON file
    # 3) Verify that ZTP is successful with JSON file with different end of line character format.
    # 4) Verify that ZTP is able to handle JSON file being downloaded with JSON
    #    format having values with or without quotes.
    vars = st.ensure_min_topology("D1")
    config_params.config_file = "ztp_invalid_json.json"
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "run"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = data.file_names
    config_params.json_content = data.json_content
    config_params.log_msg = "occured while processing ZTP JSON"
    config_params.option_type = "67"
    config_params.config_db_path = data.config_db_path
    config_params.config_db_temp = data.config_db_temp
    config_params.scenario = "invalid-json"
    config_params.retry_count = 0
    config_params.iteration = 110
    config_params.delay = 3
    config_params.check = "not"
    config_params.result = "Fail"
    config_params.config_db_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip, ztp_params.config_path,
                                                          config_params.config_file)
    st.log("Verifying the invalid json format scenario ....")
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)
    config_params.scenario = ""
    config_params.config_file = "ztp_invalid_json.json"
    config_params.file_names = ["02-test-plugin", "03-test-plugin", "01-configdb-json"]
    config_params.log_msg = "configdb-json: Error" # configdb-json: Error
    config_params.json_content = {
        "ztp": {"01-configdb-json": {"ur": {"source": "file://{}".format(config_params.config_db_temp),
                                            "timeout": 300}},
                "02-test-plugin": {"message": "Test-Plugin-Test",
                                   "message-file": "/home/admin/test-file3"},
                "03-test-plugin": {"message": "Test-Plugin-asdsads",
                                   "message-file": "/home/admin/test-file4"}}}
    config_params.iteration = 50
    st.log("Verifying the invalid provisioning data scenario ....")
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)
    st.log("Verifying the ZTP EoL scenario ....")
    config_params.result = "pass"
    config_params.config_file_type = "EoL"
    config_params.check = ""
    config_params.iteration = 300
    config_params.retry_count = 0
    config_params.config_file = data.ztp_eol_file
    config_params.log_msg = "Checking configuration section {} result: SUCCESS"
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.device_action = "reboot"
    source_path = "{}{}".format(data.local_provision_scripts_folder, config_params.config_file)
    destination_path = "{}{}/{}".format(ztp_params.home_path, config_params.config_path, data.ztp_eol_file)
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                              persist=True)
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)

# @pytest.mark.ztp_after_warm_boot
# def test_ft_ztp_after_warm_boot(ztp_func_hooks):
#     # ################ Author Details ################
#     # Name: Chaitanya Vella
#     # Email: chaitanya-vella.kumar@broadcom.com
#     # ################################################
#     # ############## Test bed details ################
#     #  D1 ---- DHCP Server
#     # ft_ztp_after_warm_boot : Verify ZTP downloaded configuration files / scripts state after the Warm Boot
#     # #################################################
#     """
#         Verify ZTP downloaded configuration files / scripts state after the Warm Boot
#         Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
#         :return:
#         """
#     vars = st.ensure_min_topology("D1")
#     config_params.config_file = "ztp_warmbooot.json"
#     config_params.static_ip = ztp_params.dhcp.static_ip
#     config_params.config_path = ztp_params.config_path
#     config_params.dhcp_config_file = ztp_params.dhcp.config_file
#     config_params.type = "http"
#     config_params.dhcp_service_name = data.dhcp_service_name
#     config_params.action = 'restart'
#     config_params.device = 'server'
#     config_params.device_action = "reboot"
#     config_params.reboot_type = "warm"
#     config_params.ztp_log_path = data.ztp_log_path
#     config_params.file_names = data.file_names
#     config_params.json_content = data.json_content
#     config_params.log_msg = "Checking configuration section {} result: SUCCESS"
#     config_params.ztp_log_string = "ZTP successfully completed"
#     config_params.option_type = "67"
#     config_params.config_db_path = data.config_db_path
#     config_params.config_db_temp = data.config_db_temp
#     ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)

@pytest.mark.ztp_firmware_install_uninstall
def test_ft_ztp_firmware_install_uninstall(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    # ft_ztp_firmware_install: Verify that SONiC ZTP successfully installs firmware image
    # #################################################
    vars = st.ensure_min_topology("D1")
    config_params.config_file = "ztp_firmware.json"
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = "restart"
    config_params.device = 'server'
    config_params.device_action = "run"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = ["firmware", "01-configdb-json"]
    config_params.option_type = "67"
    config_params.result = "pass"
    config_params.config_db_path = data.config_db_path
    config_params.config_db_temp = data.config_db_temp
    firmware_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip, ztp_params.firmware_path, ztp_params.build_file_name)
    config_params.json_content = {"ztp": {
                                        "firmware": {"install": {"url": firmware_url,"set-default": True},
                                                "remove": {"version": ztp_params.uninstall_image},
                                                     "plugin": "firmware",
                                                     "reboot-on-failure": "false",
                                                     "reboot-on-success": "true"
                                                     },
                                        "01-configdb-json": {"url": {"source": "file://{}".format(data.config_db_temp),
                                                                                          "timeout": 300}}
                                }}
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params, expect_reboot=True,
                                          reboot_on_success=["firmware"])


@pytest.mark.ztp_validate_cfg_file_with_incorrect_data
@pytest.mark.ztp_regression
def test_ft_ztp_validate_cfg_file_with_incorrect_data(ztp_func_hooks):
    vars = st.ensure_min_topology("D1")
    data.ztp_cfg = {"admin": True, "restart-ztp-interval":30,"reboot-on-success":"abcd"}
    ztp_cfg_file = basic_obj.write_to_json_file(data.ztp_cfg)
    st.upload_file_to_dut(vars.D1, ztp_cfg_file, data.dut_ztp_cfg_file)
    ztp_obj.enable_ztp_if_disabled(vars.D1)
    if st.get_ui_type(vars.D1) == "click":
        ztp_obj.ztp_operations(vars.D1, "run")
    else:
        st.reboot(vars.D1, "normal", skip_port_wait=True)
    log_string = "Invalid data type used for reboot-on-success"
    if not basic_obj.poll_for_error_logs(vars.D1, data.ztp_log_path, log_string):
        st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path, log_string))
        st.report_fail("ztp_log_verification_failed", data.ztp_log_path, log_string)
    st.report_pass("test_case_passed")

@pytest.mark.ztp_option_239
@pytest.mark.ztp_regression
def test_ft_ztp_option_239(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    # ztp_option_239 : Verify that ZTP works fine for DHCP option 239 to
    # execute a simple shell script as an alternative to ZTP JSON.
    # #################################################
    vars = st.ensure_min_topology("D1")
    source_path = "{}{}".format(data.local_provision_scripts_folder,data.option_239_sh_file)
    destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.provision_script_path, data.option_239_sh_file)
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path, persist=True)
    options = SpyTestDict()
    options.dhcp_config_file = ztp_params.dhcp.config_file
    options.server_ip = ztp_params.dhcp.static_ip
    options.config_path = ztp_params.provision_script_path
    options.provision_script = data.option_239_sh_file
    options.search_pattern = r'\s*option\s+provision-url\s*\S*\s*"\S+";'
    options.option_string = 'option provision-url '
    options.option_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip, ztp_params.provision_script_path,
                                       data.option_239_sh_file)
    ztp_obj.write_option_to_dhcp_server(ssh_conn_obj, options)
    # ztp_obj.write_option_239_to_dhcp_server(ssh_conn_obj, options)
    basic_obj.service_operations(ssh_conn_obj, data.dhcp_service_name, 'restart', "server")
    if not ztp_obj.verify_dhcpd_service_status(ssh_conn_obj, config_params.dhcpd_pid):
        st.log("{} service not running".format(data.dhcp_service_name))
        st.report_fail("service_not_running", data.dhcp_service_name)
    basic_obj.copy_config_db_to_temp(vars.D1, data.config_db_path, data.config_db_temp)
    basic_obj.remove_file(vars.D1, data.config_db_path)
    st.reboot(vars.D1, "normal", skip_port_wait=True)
    if not ztp_obj.poll_ztp_status(vars.D1, ["IN-PROGRESS", "Not Started", "SUCCESS"]):
        st.report_fail("ztp_max_polling_interval")
    if not ztp_obj.verify_ztp_status(vars.D1):
        if "logs_path" in config_params and "func_name" in config_params:
            syslog_file_names = ["syslog_1_{}".format(config_params.func_name),
                                 "syslog_{}".format(config_params.func_name)]
            ztp_obj.capture_syslogs(vars.D1, config_params.logs_path, syslog_file_names)
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    if "dhcp-opt239" not in ztp_status["source"]:
        st.log("ZTP source verification failed with {} against dhcp-opt239".format(ztp_status["source"]))
        st.report_fail("ztp_source_verification_failed", "dhcp-opt239", ztp_status["source"])
    st.report_pass("test_case_passed")

@pytest.mark.ft_ztp_restart_no_config
@pytest.mark.ztp_regression
def test_ft_ztp_restart_no_config(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    #  ft_ztp_restart_no_config	: Verify that SONiC ZTP is successful even though we have not pushed config db json
    #  with and without ""restart-ztp-no-config": false" attribute in ztp.json
    #  YET TO BE DONE #
    # #################################################
    vars = st.ensure_min_topology("D1")
    hostname = basic_obj.get_hostname(vars.D1)
    config_params.config_file = "ztp_restart_no_config.json"
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "reboot"
    config_params.reboot_type = "normal"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = ["03-provisioning-script", "04-connectivity-tests"]
    config_params.json_content = data.json_content
    config_params.log_msg = "Checking configuration section {} result: SUCCESS"
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.option_type = "67"
    config_params.config_db_path = data.config_db_path
    config_params.config_db_temp = data.config_db_temp
    config_params.config_db_file_name = "{}_config_db.json".format(hostname)
    config_params.json_config_path = "http://{}{}/".format(ztp_params.dhcp.static_ip, ztp_params.config_path)
    config_params.provision_script_path = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                         ztp_params.provision_script_path, data.option_239_sh_file)
    config_params.ping_script_path = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                    ztp_params.provision_script_path, data.ping_script_file)
    config_params.config_db_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                 ztp_params.config_path, config_params.config_db_file_name)
    config_params.json_content = {
        "ztp": {
            "03-provisioning-script": {
                "plugin": {
                    "url": config_params.provision_script_path
                }
            },
            "04-connectivity-tests": {
                "plugin": {
                    "url": config_params.ping_script_path
                }
            },
            "restart-ztp-no-config": False
        }
    }
    ztp_obj.ztp_operations(vars.D1, "disable")
    if not ztp_obj.verify_ztp_attributes(vars.D1, "adminmode", "False"):
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    st.reboot(vars.D1)
    if not ztp_obj.verify_ztp_attributes(vars.D1, "adminmode", "False"):
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    ztp_obj.enable_ztp_if_disabled(vars.D1)
    if ztp_obj.verify_ztp_attributes(vars.D1, "adminmode", "False"):
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    shell_scripts = [data.ping_script_file, data.option_239_sh_file]
    for shell_script in shell_scripts:
        source_path = "{}{}".format(data.local_provision_scripts_folder, shell_script)
        destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.provision_script_path, shell_script)
        basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                                  persist=True)
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)

@pytest.mark.ft_ztp_config_section_check_with_option_67
@pytest.mark.ztp_regression
def test_ft_ztp_config_section_check_with_option_67(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    #  ft_ztp_config_section_check_with_option_67	: This test function cover over 18 scenarios using option 67
    # #################################################
    vars = st.ensure_min_topology("D1")
    hostname = basic_obj.get_hostname(vars.D1)
    config_params.config_file = "ztp_plugin_conf.json"
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "run"
    config_params.reboot_type = "normal"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = ["02-configdb-json", "03-provisioning-script", "04-connectivity-tests", "05-test-plugin"]
    config_params.json_content = data.json_content
    config_params.log_msg = "Checking configuration section {} result: SUCCESS"
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.option_type = "67"
    config_params.result = ""
    config_params.service = "disable"
    config_params.config_db_path = data.config_db_path
    config_params.config_db_temp = data.config_db_temp
    config_params.config_file = "ztp_plugin_conf.json"
    config_params.config_db_file_name = "{}_config_db.json".format(hostname)
    config_params.featureconfig_file_name = "invalid_config.json"
    config_params.json_config_path = "http://{}{}/".format(ztp_params.dhcp.static_ip, ztp_params.config_path)
    config_params.provision_script_path = "https://{}{}/{} -k".format(ztp_params.dhcp.static_ip,
                                                                  ztp_params.provision_script_path,
                                                                  data.option_239_sh_file)
    config_params.ping_script_path = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                             ztp_params.provision_script_path, data.ping_script_file)
    config_params.config_db_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                          ztp_params.config_path, config_params.config_db_file_name)
    data.feature_config_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip, ztp_params.config_path,
                                                      config_params.featureconfig_file_name)
    config_params.json_content = {
        "ztp": {
            "02-configdb-json": {
                "dynamic-url": {
                    "source": {
                        "prefix": config_params.json_config_path,
                        "identifier": "hostname",
                        "suffix": "_config_db.json"
                    },
                    "destination": "/etc/sonic/config_db.json"
                }
            },
            "03-provisioning-script": {
                "plugin": {
                    "url": config_params.provision_script_path
                }
            },
            "04-connectivity-tests": {
                "plugin": {
                    "url": config_params.ping_script_path
                }
            },
            "05-test-plugin":{
                "message": "Test-Plugin-Test",
                "message-file": "/home/admin/test-file1",
                "reboot-on-success" : True
            },
            "06-snmp": {
                "community-ro": "sonic",
                "snmp-location": "Hyderabad",
                "snmp-syscontact": "admin",
                "ignore-result": "true",
                "restart-agent": True
            },
            "07-configdb-json": {"url":
                             {"source": data.feature_config_url, "timeout": 300},
                             "clear-config": "false", "save-config": "true", "ignore-result": True}
        }
    }
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg={"admin-mode": True, "restart-ztp-interval": 30, "log-level":"DEBUG", "feat-console-logging": feat_logging_console})
    source_path = "{}{}".format(data.local_provision_scripts_folder, data.option_239_sh_file)
    destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.provision_script_path, data.option_239_sh_file)
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                              persist=True)
    options = SpyTestDict()
    options.dhcp_config_file = ztp_params.dhcp.config_file
    options.server_ip = config_params.static_ip
    options.config_path = ztp_params.provision_script_path
    options.provision_script = data.option_239_sh_file
    options.search_pattern = r'\s*option\s+provision-url\s*\S*\s*"\S+";'
    options.option_string = 'option provision-url '
    options.option_url = "http://{}{}/{}".format(ztp_params.dhcp.static_ip, ztp_params.provision_script_path,
                                                 data.option_239_sh_file)
    ztp_obj.write_option_to_dhcp_server(ssh_conn_obj, options)
    shell_scripts = [data.ping_script_file, data.option_239_sh_file]
    for shell_script in shell_scripts:
        source_path = "{}{}".format(data.local_provision_scripts_folder, shell_script)
        destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.provision_script_path, shell_script)
        basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                                  persist=True)
    st.log("Preparing invalid config JSON to check the gracefull handling of ZTP ...")
    interface_name = random.choice(st.get_free_ports(vars.D1))
    vlan_list = vlan_obj.get_non_existing_vlan(vars.D1, 1)
    data.config_db_content = {
        "VLAN": {"Vlan{}".format(vlan_list[0]): {"members": [interface_name], "vlanid": vlan_list[0]}},
        "VLAN_MEMBER": {"Vlan{}|{}".format(vlan_list[0], interface_name): {"tagging_mode": "tagged"}}}
    file_path = basic_obj.write_to_json_file(data.config_db_content)
    destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.config_path, config_params.featureconfig_file_name)
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params, expect_reboot=True,reboot_on_success=["05-test-plugin"])
    # if ztp_params.cli_type == "click":
    #     st.log("Verifying the ZTP DEBUG logs ..")
    #     ztp_log_string = "DEBUG sonic-ztp"
    #     st.log(st.log(ztp_log_string))
    #     if not basic_obj.poll_for_error_logs(vars.D1, data.ztp_log_path, ztp_log_string):
    #         if not basic_obj.poll_for_error_logs(vars.D1, data.syslog_path, ztp_log_string):
    #             st.log("ZTP log {} verification failed for message {}".format(data.ztp_log_path, ztp_log_string))
    #             st.report_fail("ztp_log_verification_failed", data.ztp_log_path, ztp_log_string)
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    if "dhcp-opt67" not in ztp_status["source"]:
        st.log("ZTP source verification failed with {} against dhcp-opt67".format(ztp_status["source"]))
        st.report_fail("ztp_source_verification_failed", "dhcp-opt67", ztp_status["source"])
    st.log("Verifying the ZTP plugin chronological order ..")
    if not ztp_obj.verify_plugin_chronological_order(vars.D1):
        st.report_fail("ztp_chronoloigical_verification_failed")
    st.log("Verifying ZTP admin disable operation ..")
    if not ztp_obj.verify_dhclient_on_interface(vars.D1, "/sbin/dhclient", ztp_params.oob_port):
        st.report_fail("ztp_dhclient_error")
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    ztp_obj.ztp_operations(vars.D1, "disable")
    if not ztp_obj.verify_ztp_attributes(vars.D1, "adminmode", "False"):
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    ztp_status_after_disable = ztp_obj.show_ztp_status(vars.D1)
    if ztp_status["status"] != ztp_status_after_disable["status"]:
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    snmp_params = {"rocommunityv6": "sonic", "rocommunity" :"sonic"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syslocation": "Hyderabad"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syscontact": "admin"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    st.report_pass("test_case_passed")

@pytest.mark.ft_ztp_install_docker_package
@pytest.mark.ztp_regression
def test_ft_ztp_install_docker_package(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    # ft_ztp_install_docker_package : Verify that ZTP can install a docker package using pre-defined firmware plugin.
    vars = st.ensure_min_topology("D1")
    #hostname = basic_obj.get_hostname(vars.D1)
    config_params.config_file = "ztp_docker.json"
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "run"
    config_params.reboot_type = "normal"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = ["02-configdb-json", "03-firmware"]
    config_params.log_msg = "Checking configuration section {} result: SUCCESS"
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.option_type = "67"
    config_params.result = ""
    config_params.config_db_path = data.config_db_path
    config_params.config_db_temp = data.config_db_temp
    config_params.json_config_path = "http://{}{}/".format(ztp_params.dhcp.static_ip, ztp_params.config_path)
    config_params.docker_path = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                                      ztp_params.docker_path,
                                                                      ztp_params.docker_image)
    config_params.json_content  = {
        "ztp": {
            "02-configdb-json": {
                "url": {"source": "file://{}".format(config_params.config_db_temp),
                                            "timeout": 300}
            },
            "03-firmware": {
                "upgrade-docker": {
                    "url": config_params.docker_path,
                    "container-name": ztp_params.docker_component_name
                }
            }
        }
    }
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    if "dhcp-opt67" not in ztp_status["source"]:
        st.log("ZTP source verification failed with {} against dhcp-opt67".format(ztp_status["source"]))
        st.report_fail("ztp_source_verification_failed", "dhcp-opt67", ztp_status["source"])
    st.report_pass("test_case_passed")

@pytest.mark.ft_ztp_with_legacy_options
@pytest.mark.ztp_regression
def test_ft_ztp_with_legacy_options(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    # ft_ztp_with_legacy_options :  Verify that ZTP is successfully able to deploy acl.json file
    # using pre-defined graphservice plugin and also verify DHCP Options 225-minigraph_url,
    # 226-acl_url and 67 - ZTP JSON file are all sent by the DHCP server.
    vars = st.ensure_min_topology("D1")
    config_params.static_ip = ztp_params.dhcp.static_ip
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "run"
    config_params.reboot_type = "normal"
    config_params.file_names = ["graphservice"]
    config_params.ztp_log_path = data.ztp_log_path
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.option_type = "225"
    config_params.result = ""
    config_params.config_db_path = data.config_db_path
    config_params.minigraph_path = "http://{}{}/{}".format(ztp_params.dhcp.static_ip,
                                                        ztp_params.xml_path,
                                                        ztp_params.minigraph_file)
    st.log("################## MINIGRAPH XML PATH --- {} ".format(config_params.minigraph_path))
    source_path = "{}{}".format(data.local_provision_scripts_folder, ztp_params.minigraph_file)
    destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.xml_path, ztp_params.minigraph_file)
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                              persist=True)
    ztp_obj.config_and_verify_option_225(ssh_conn_obj, vars.D1, ztp_params, config_params)
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    if "dhcp-opt225-graph-url" not in ztp_status["source"]:
        st.log("ZTP source verification failed with {} against dhcp-opt225-graph-url".format(ztp_status["source"]))
        st.report_fail("ztp_source_verification_failed", "dhcp-opt225-graph-url", ztp_status["source"])
    st.report_pass("test_case_passed")
