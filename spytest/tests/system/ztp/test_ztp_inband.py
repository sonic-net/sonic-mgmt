import os
import pytest
import random

from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.connection as con_obj
import apis.system.basic as basic_obj
import apis.system.ztp as ztp_obj
import utilities.utils as utils_obj
import apis.switching.vlan as vlan_obj
from apis.system.snmp import verify_snmp_details_using_docker
#from apis.system.reboot import config_save
from apis.routing.ip import config_ip_addr_interface, ping
from apis.system.interface import interface_noshutdown
from apis.system.port import breakout, get_interface_details_by_alt_name

files_path = os.path.join(os.path.dirname(__file__), 'files')
files_path = os.path.abspath(files_path)
vars = dict()
ztp_params = SpyTestDict()
ztp_params.dhcp = SpyTestDict()
ztp_params.dhcp6 = SpyTestDict()
ssh_conn_obj = None
outofband_conn_obj = None
ssh_conn_obj_oob_v6 = None
ssh_conn_obj_inb_v6 = None
feat_logging_console = False

def pre_config_ztp():
    global vars
    global ssh_conn_obj
    global outofband_conn_obj
    global ssh_conn_obj_oob_v6
    global ssh_conn_obj_inb_v6
    vars = st.get_testbed_vars()
    # DHCPV4 out of band params
    ztp_params.dhcp.ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "ip")
    ztp_params.dhcp.username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "username")
    ztp_params.dhcp.password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "password")
    ztp_params.oob_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "interface")
    # DHCPV4 in band params
    ztp_params.dhcp.inband_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "ip")
    ztp_params.dhcp.inband_username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "username")
    ztp_params.dhcp.inband_password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "password")
    ztp_params.dhcp.inband_config_file = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "config_file")
    ztp_params.dhcp.inband_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "static_ip")
    ztp_params.inband_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "interface")
    ztp_params.config_path = utils_obj.ensure_service_params(vars.D1, "ztp", "config_path")
    ztp_params.firmware_path = utils_obj.ensure_service_params(vars.D1, "ztp", "firmware_path")
    ztp_params.home_path = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "home_path")
    ztp_params.port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "port")
    ztp_params.build_file_name = utils_obj.ensure_service_params(vars.D1, "ztp", "build_file_name")
    ztp_params.uninstall_image = utils_obj.ensure_service_params(vars.D1, "ztp", "uninstall_image")
    ztp_params.dut_path = utils_obj.ensure_service_params(vars.D1, "ztp", "dut_path")
    ztp_params.ztp_cfg_file_name = utils_obj.ensure_service_params(vars.D1, "ztp", "ztp_cfg_file_name")
    ztp_params.provision_script_path = utils_obj.ensure_service_params(vars.D1, "ztp", "provision_script_path")
    ztp_params.docker_path = utils_obj.ensure_service_params(vars.D1, "ztp", "docker_path")
    ztp_params.docker_image = utils_obj.ensure_service_params(vars.D1, "ztp", "docker_image")
    ztp_params.docker_component_name = utils_obj.ensure_service_params(vars.D1, "ztp", "docker_component_name")
    ztp_params.inband_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "interface")
    ztp_params.minigraph_file = utils_obj.ensure_service_params(vars.D1, "ztp", "minigraph_file")
    ztp_params.xml_path = utils_obj.ensure_service_params(vars.D1, "ztp", "xml_path")
    # DHCPV6 out of band params
    ztp_params.dhcp6.ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "ip")
    ztp_params.dhcp6.username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "username")
    ztp_params.dhcp6.password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "password")
    ztp_params.dhcp6.oob_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "interface")
    ztp_params.dhcp6.oob_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "static_ip")
    # DHCPV6 IN band params
    ztp_params.dhcp6.inband_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "ip")
    ztp_params.dhcp6.inband_username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "username")
    ztp_params.dhcp6.inband_password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "password")
    ztp_params.dhcp6.inband_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "static_ip")
    ztp_params.dhcp6.inband_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "interface")
    ztp_params.dhcp.inband_v4_subnet = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "subnet")
    ztp_params.dhcp.oob_v4_subnet= utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "subnet")
    ztp_params.dhcp6.inband_v6_subnet = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "subnet")
    ztp_params.dhcp6.oob_v6_subnet = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "subnet")
    ztp_params.dhcp.client_ip_inband = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "client_ip")
    ztp_params.breakout = utils_obj.ensure_service_params(vars.D1, "ztp", "breakout")
    ztp_params.cli_type = st.get_ui_type(vars.D1)
    st.log("Clearing V4/V6 lease database from DUT ...")
    basic_obj.delete_directory_contents(vars.D1, config_params.lease_db_path)
    st.log("################# Logging in to DHCPV4 server ---- IN BAND ...#################")
    ssh_conn_obj = con_obj.connect_to_device(ztp_params.dhcp.inband_ip,
                                             ztp_params.dhcp.inband_username, ztp_params.dhcp.inband_password)
    if not ssh_conn_obj:
        st.error("SSH connetion object not found for DHCPV4 server IN BAND.")
        reset_module_config()
        st.report_env_fail("ssh_connection_failed", ztp_params.dhcp.inband_ip)
    st.log("########Restarting DHCPV4 service##########")
    basic_obj.service_operations(ssh_conn_obj, config_params.dhcp_service_name, "restart", "server")
    st.log("########Verifying DHCPV4 service status##########")
    if not ztp_obj.verify_dhcpd_service_status(ssh_conn_obj, config_params.dhcpd_pid):
        st.log("{} service is not running ".format(config_params.dhcp_service_name))
        reset_module_config()
        st.report_fail("service_running_not_expected", config_params.dhcp_service_name)
    st.log("################# Logging in to DHCPV4 server ---- OUT OF BAND ... #################")
    outofband_conn_obj = con_obj.connect_to_device(ztp_params.dhcp.ip,
                                                   ztp_params.dhcp.username, ztp_params.dhcp.password)
    if not outofband_conn_obj:
        st.error("OUT OF BAND SSH connetion object not found.")
    else:
        basic_obj.service_operations(outofband_conn_obj, config_params.dhcp_service_name, "stop", "server")
        if ztp_obj.verify_dhcpd_service_status(outofband_conn_obj, config_params.dhcpd_pid):
            st.log("{} service is running which is not expected".format(config_params.dhcp_service_name))
            reset_module_config()
            st.report_fail("service_running_not_expected", config_params.dhcp_service_name)
        # st.report_env_fail("ssh_connection_failed", ztp_params.dhcp.ip)
    st.log("################# Logging in to DHCPV6 server -- OUT OF BAND ... #################")
    ssh_conn_obj_oob_v6 = con_obj.connect_to_device(ztp_params.dhcp6.ip,
                                                    ztp_params.dhcp6.username, ztp_params.dhcp6.password)
    if not ssh_conn_obj_oob_v6:
        st.error("SSH connection object not found for DHCPV6 server OUT OF BAND.")
    st.log("################# Logging in to DHCPV6 server ---- IN BAND ... ##################")
    ssh_conn_obj_inb_v6 = con_obj.connect_to_device(ztp_params.dhcp6.inband_ip,
                                                    ztp_params.dhcp6.inband_username, ztp_params.dhcp6.inband_password)
    if not ssh_conn_obj_inb_v6:
        st.error("SSH connection object not found for DHCPV6 server IN BAND.")
    st.log("Stopping V4/V6 services to avoid the DHCP option conflict .. ")
    v6_connection_objs = [ssh_conn_obj_inb_v6, ssh_conn_obj_oob_v6]
    for connection_obj in v6_connection_objs:
        if connection_obj:
            basic_obj.service_operations(connection_obj, config_params.dhcp6_service_name, "stop", "server")
            if ztp_obj.verify_dhcpd_service_status(connection_obj, config_params.dhcpd6_pid):
                st.log("{} service is running which is not expected".format(config_params.dhcp6_service_name))
                reset_module_config()
                st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
    basic_obj.poll_for_system_status(vars.D1)
    st.log("Shutting down the out of band interface ...")
    basic_obj.ifconfig_operation(vars.D1, ztp_params.oob_port, "down")
    ztp_cfg = {"admin-mode": True, "restart-ztp-interval": 30, "feat-console-logging": feat_logging_console}
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg)


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
    if outofband_conn_obj:
        basic_obj.service_operations(outofband_conn_obj, config_params.dhcp_service_name, "start", "server")
        con_obj.ssh_disconnect(outofband_conn_obj)


@pytest.fixture(scope="module", autouse=True)
def ztp_module_hooks(request):
    st.add_prevent("ztp")
    initialize_config_params()
    pre_config_ztp()
    initialize_data_variables()
    path_list = [ztp_params.home_path+ztp_params.config_path, ztp_params.home_path+ztp_params.firmware_path,
                 ztp_params.home_path+ztp_params.provision_script_path, ztp_params.home_path+ztp_params.xml_path]
    ztp_obj.create_required_folders(ssh_conn_obj, path_list)
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml", "/etc/sonic/snmp.yml.bkp")
    source_path = "{}{}".format(config_params.local_provision_scripts_folder, config_params.snmp_filename)
    st.upload_file_to_dut(vars.D1, source_path, "/home/admin/snmp.yml")
    basic_obj.copy_file_to_local_path(vars.D1, "/home/admin/snmp.yml", "/etc/sonic/snmp.yml")
    if ztp_params.breakout:
        if breakout(vars.D1, ztp_params.breakout, cli_type="klish", skip_error=True):
            intf_details = get_interface_details_by_alt_name(vars.D1, ztp_params.inband_port)
            if isinstance(intf_details, dict):
                inband_port = intf_details["interface"]
            else:
                inband_port = intf_details
            interface_noshutdown(vars.D1, inband_port)
            config_ip_addr_interface(vars.D1, inband_port, ztp_params.dhcp.client_ip_inband, ztp_params.dhcp.inband_v4_subnet)
            # enable_dhcp_on_interface(vars.D1, ztp_params.inband_port)
            if not ping(vars.D1, ztp_params.dhcp.inband_static_ip):
                st.log("Pinging to DHCP server failed from DUT, issue either with DUT or server")
    # config_save(vars.D1)

    # write_config_db(vars.D1, interface_data)
    yield
    reset_module_config()
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml.bkp", "/etc/sonic/snmp.yml")


@pytest.fixture(scope="function", autouse=True)
def ztp_func_hooks(request):
    initialize_config_params()
    initialize_data_variables()
    basic_obj.remove_file(vars.D1, data.ztp_local_json_path)
    basic_obj.copy_config_db_to_temp(vars.D1, data.config_db_path, data.config_db_temp)
    basic_obj.change_permissions(vars.D1, data.config_db_temp)
    ztp_obj.enable_ztp_if_disabled(vars.D1)
    config_params.func_name = st.get_func_name(request)
    yield
    ztp_obj.ztp_operations(vars.D1, "disable")
    basic_obj.copy_config_db_to_temp(vars.D1, data.config_db_temp, data.config_db_path)
    config_params.dhcp_config_file = ztp_params.dhcp.inband_config_file
    if st.get_func_name(request) == "test_ft_ztp_config_section_check_with_option_67_with_inband":
        config_params.option_type = "option_67"
        ztp_obj.clear_options_from_dhcp_server(ssh_conn_obj, config_params)
        config_params.option_type = "option_239"
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
    data.ztp_local_json_path = "/host/ztp/ztp_data_local.json"
    data.ztp_log_path = "/var/log/ztp.log"
    data.syslog_path = "/var/log/syslog"
    data.config_db_path = "/etc/sonic/config_db.json"
    data.client_path = "/home/admin"
    data.config_db_temp = "/home/admin/config_db_temp.json"
    data.temp_path = "/tmp"
    data.file_names = ["02-test-plugin", "03-test-plugin", "01-configdb-json"]
    data.local_path = os.path.dirname(__file__)
    data.local_provision_scripts_folder = "{}/scripts/".format(data.local_path)
    data.option_239_sh_file = "provisioning_script.sh"
    data.ping_script_file = "ping_test.sh"
    data.ztp_eol_file = "ztp_EoL.json"
    data.dut_ztp_cfg_file = "{}/{}".format(ztp_params.dut_path, ztp_params.ztp_cfg_file_name)
    data.config_db_location = "local"


@pytest.mark.ft_ztp_config_section_check_with_option_67_with_inband
def test_ft_ztp_config_section_check_with_inband_and_option_67(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server
    #  ft_ztp_config_section_check_with_option_67_with_inband	:
    #  Verify that SONiC ZTP is successful through in-band ports using
    #  ZTP URL provided in DHCP option 67 received over IPv4 network.
    # #################################################
    vars = st.ensure_min_topology("D1")
    hostname = basic_obj.get_hostname(vars.D1)
    config_params.config_file = "ztp_option_67_with_inband.json"
    config_params.static_ip = ztp_params.dhcp.inband_static_ip if not ztp_params.port else "{}:{}".format(ztp_params.dhcp.inband_static_ip, ztp_params.port)
    config_params.config_path = ztp_params.config_path
    config_params.dhcp_config_file = ztp_params.dhcp.inband_config_file
    config_params.type = "http"
    config_params.dhcp_service_name = data.dhcp_service_name
    config_params.action = 'restart'
    config_params.device = 'server'
    config_params.device_action = "reboot"
    config_params.reboot_type = "normal"
    config_params.ztp_log_path = data.ztp_log_path
    config_params.file_names = ["03-provisioning-script", "05-test-plugin", "06-snmp", "07-configdb-json"]
    config_params.log_msg = "Checking configuration section {} result: SUCCESS"
    config_params.ztp_log_string = "ZTP successfully completed"
    config_params.option_type = "67"
    config_params.result = ""
    config_params.service = "disable"
    config_params.config_db_path = data.config_db_path
    config_params.config_db_location = "json"
    config_params.config_db_temp = data.config_db_temp
    config_params.config_db_file_name = "{}_config_db.json".format(hostname)
    config_params.featureconfig_file_name = "feature_config.json"
    config_params.json_config_path = "http://{}{}/".format(config_params.static_ip, ztp_params.config_path)
    config_params.provision_script_path = "http://{}{}/{}".format(config_params.static_ip,
                                                                  ztp_params.provision_script_path,
                                                                  data.option_239_sh_file)
    config_params.config_db_url = "http://{}{}/{}".format(config_params.static_ip,
                                                          ztp_params.config_path, config_params.config_db_file_name)
    data.feature_config_url = "http://{}{}/{}".format(config_params.static_ip, ztp_params.config_path,
                                                      config_params.featureconfig_file_name)
    config_params.band_type="inband"
    config_params.json_content = {
        "ztp": {
            # "02-configdb-json": {
            #     "dynamic-url": {
            #         "source": {
            #             "prefix": config_params.json_config_path,
            #             "identifier": "hostname",
            #             "suffix": "_config_db.json"
            #         },
            #         "destination": "/etc/sonic/config_db.json"
            #     }
            # },
            "03-provisioning-script": {
                "plugin": {
                    "url": config_params.provision_script_path
                }
            },
            "05-test-plugin":{
                "message": "Test-Plugin-Test",
                "message-file": "/home/admin/test-file1"
            },
            "06-snmp": {
                "communities-ro": ["sonic", "buzznik"],
                "community-ro": "sonicro",
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
    options.dhcp_config_file = ztp_params.dhcp.inband_config_file
    options.server_ip = config_params.static_ip
    options.config_path = ztp_params.provision_script_path
    options.provision_script = data.option_239_sh_file
    options.search_pattern = r'\s*option\s+provision-url\s*\S*\s*"\S+";'
    options.option_string = 'option provision-url '
    options.option_url = "http://{}{}/{}".format(ztp_params.dhcp.inband_static_ip, ztp_params.provision_script_path,
                                                 data.option_239_sh_file)
    ztp_obj.write_option_to_dhcp_server(ssh_conn_obj, options)
    # ztp_obj.write_option_239_to_dhcp_server(ssh_conn_obj, options)
    shell_scripts = [data.option_239_sh_file]
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
    ztp_obj.config_and_verify_dhcp_option(ssh_conn_obj, vars.D1, ztp_params, config_params)
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
        st.log("ZTP source verification failed with {} against dhcp-opt239".format(ztp_status["source"]))
        st.report_fail("ztp_source_verification_failed", "dhcp-opt239", ztp_status["source"])
    st.log("Verifying the ZTP plugin chronological order ..")
    if not ztp_obj.verify_plugin_chronological_order(vars.D1):
        st.report_fail("ztp_chronoloigical_verification_failed")
    st.log("Verifying ZTP admin disable operation ..")
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    ztp_obj.ztp_operations(vars.D1, "disable")
    if not ztp_obj.verify_ztp_attributes(vars.D1, "adminmode", "False"):
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    ztp_status_after_disable = ztp_obj.show_ztp_status(vars.D1)
    if ztp_status["status"] != ztp_status_after_disable["status"]:
        st.log("ZTP status verification failed")
        st.report_fail("ztp_status_verification_failed")
    snmp_params = {"rocommunityv6": "sonic", "rocommunity": "sonic"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"rocommunityv6": "buzznik", "rocommunity": "buzznik"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syslocation": "Hyderabad"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syscontact": "admin"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    st.report_pass("test_case_passed")

