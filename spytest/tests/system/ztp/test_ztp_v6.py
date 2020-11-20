import pytest
import os
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.connection as con_obj
import apis.system.basic as basic_obj
import apis.system.ztp as ztp_obj
import utilities.utils as utils_obj
from apis.system.snmp import verify_snmp_details_using_docker
files_path = os.path.join(os.path.dirname(__file__), 'files')
files_path = os.path.abspath(files_path)
vars = dict()
ztp_params = SpyTestDict()
ztp_params.dhcp = SpyTestDict()
ztp_params.dhcp6 = SpyTestDict()
network_flag = "outofband"
ssh_conn_obj_oob_v6 = None
ssh_conn_obj = None
ssh_conn_obj_oob_v4 = None
ssh_conn_obj_inb_v4 = None
ssh_conn_obj_inb_v6 = None
feat_logging_console = False

def pre_config_ztp():
    global vars
    global ssh_conn_obj_oob_v6
    global ssh_conn_obj
    global ssh_conn_obj_oob_v4
    global ssh_conn_obj_inb_v4
    global ssh_conn_obj_inb_v6
    vars = st.get_testbed_vars()
    # DHCPV6 out of band params
    ztp_params.dhcp6.ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "ip")
    ztp_params.dhcp6.username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "username")
    ztp_params.dhcp6.password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "password")
    ztp_params.dhcp6.oob_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "interface")
    ztp_params.dhcp6.oob_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "static_ip")
    # DHCPV4 out of band params
    ztp_params.dhcp.ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "ip")
    ztp_params.dhcp.username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "username")
    ztp_params.dhcp.password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "password")
    ztp_params.oob_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "interface")
    ztp_params.static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "outofband", "static_ip")
    #DHCPV6 in band params
    ztp_params.dhcp6.inband_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "ip")
    ztp_params.dhcp6.inband_username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "username")
    ztp_params.dhcp6.inband_password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "password")
    ztp_params.dhcp6.inband_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "static_ip")
    ztp_params.dhcp6.inband_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "interface")
    # DHCPV4 in band params
    ztp_params.dhcp.inband_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "ip")
    ztp_params.dhcp.inband_username = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "username")
    ztp_params.dhcp.inband_password = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "password")
    ztp_params.dhcp.inband_static_ip = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "static_ip")
    ztp_params.inband_port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "interface")

    ztp_params.dhcp6.oob_config_file = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "config_file")
    ztp_params.dhcp6.inband_config_file = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "config_file")
    ztp_params.config_path = utils_obj.ensure_service_params(vars.D1, "ztp", "config_path")
    ztp_params.dhcp6.oob_home_path = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "outofband", "home_path")
    ztp_params.dhcp6.inband_home_path = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcpv6", "inband", "home_path")
    ztp_params.port = utils_obj.ensure_service_params(vars.D1, "ztp", "dhcp", "inband", "port")
    ztp_params.dut_path = utils_obj.ensure_service_params(vars.D1, "ztp", "dut_path")
    ztp_params.ztp_cfg_file_name = utils_obj.ensure_service_params(vars.D1, "ztp", "ztp_cfg_file_name")
    ztp_params.provision_script_path = utils_obj.ensure_service_params(vars.D1, "ztp", "provision_script_path")

    st.log("Clearing V4/V6 lease database from DUT ...")
    basic_obj.delete_directory_contents(vars.D1, config_params.lease_db_path)

    st.log("####### Connecting to DHCPV6 server -- OUT OF BAND ...###########")
    ssh_conn_obj_oob_v6 = con_obj.connect_to_device(ztp_params.dhcp6.ip,
                                                    ztp_params.dhcp6.username, ztp_params.dhcp6.password)
    if not ssh_conn_obj_oob_v6:
        st.error("SSH connection object not found for DHCPV6 server OUT OF BAND.")
        if network_flag != "inband":
            reset_module_config()
            st.report_env_fail("ssh_connection_failed", ztp_params.dhcp6.ip)
    st.log("############Connecting to DHCPV4 server -- OUT OF BAND ...#############")
    ssh_conn_obj_oob_v4 = con_obj.connect_to_device(ztp_params.dhcp.ip,
                                                    ztp_params.dhcp.username, ztp_params.dhcp.password)
    if not ssh_conn_obj_oob_v4:
        st.error("SSH connection object not found for DHCPV4 server OUT OF BAND.")
        # st.report_env_fail("ssh_connection_failed", ztp_params.dhcp6.ip)
    st.log("###########Connecting to DHCPV4 server -- IN BAND ...##############")
    ssh_conn_obj_inb_v4 = con_obj.connect_to_device(ztp_params.dhcp.inband_ip,
                                                    ztp_params.dhcp.inband_username, ztp_params.dhcp.inband_password)
    if not ssh_conn_obj_inb_v4:
        st.error("SSH connection object not found for DHCPV4 server OUT OF BAND.")
        # st.report_env_fail("ssh_connection_failed", ztp_params.dhcp6.ip)
    ssh_conn_obj_inb_v6 = con_obj.connect_to_device(ztp_params.dhcp6.inband_ip,
                                                    ztp_params.dhcp6.inband_username, ztp_params.dhcp6.inband_password)
    if not ssh_conn_obj_inb_v6:
        st.error("SSH connection object not found for DHCPV4 server OUT OF BAND.")
        if network_flag == "inband":
            reset_module_config()
            st.report_env_fail("ssh_connection_failed", ztp_params.dhcp6.inband_ip)
    st.log("###########Stopping V4/V6 services to avoid the DHCP option conflict .. ###########")
    v4_connection_objs = [ssh_conn_obj_oob_v4, ssh_conn_obj_inb_v4]
    for connection_obj in v4_connection_objs:
        if connection_obj:
            basic_obj.service_operations(connection_obj, config_params.dhcp_service_name, "stop", "server")
            if ztp_obj.verify_dhcpd_service_status(connection_obj, config_params.dhcpd_pid):
                st.log("{} service is running which is not expected".format(config_params.dhcp_service_name))
                reset_module_config()
                st.report_fail("service_running_not_expected", config_params.dhcp_service_name)
    st.log("Restarting V6 services on required server .. ")
    if network_flag != "inband":
        ssh_conn_obj = ssh_conn_obj_oob_v6
        st.log("Using OUT OF BAND V6 ssh object ... ")
        if ssh_conn_obj_inb_v6:
            basic_obj.service_operations(ssh_conn_obj_inb_v6, config_params.dhcp6_service_name, "stop", "server")
            if ztp_obj.verify_dhcpd_service_status(ssh_conn_obj_inb_v6, config_params.dhcpd6_pid):
                st.log("{} service is running which is not expected".format(config_params.dhcp6_service_name))
                reset_module_config()
                st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
        else:
            st.log("SSH object for INB V6 server is not found ...")
    else:
        st.log("Using INBAND V6 ssh object ... ")
        ssh_conn_obj = ssh_conn_obj_inb_v6
        if ssh_conn_obj_oob_v6:
            basic_obj.service_operations(ssh_conn_obj_oob_v6, config_params.dhcp6_service_name, "stop", "server")
            if ztp_obj.verify_dhcpd_service_status(ssh_conn_obj_oob_v6, config_params.dhcpd6_pid):
                st.log("{} service is running which is not expected".format(config_params.dhcp6_service_name))
                reset_module_config()
                st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
        else:
            st.log("SSH object for OOB V6 server is not found ...")
    basic_obj.service_operations(ssh_conn_obj, config_params.dhcp6_service_name, "restart", "server")
    if not ztp_obj.verify_dhcpd_service_status(ssh_conn_obj, config_params.dhcpd6_pid):
        st.log("{} service is not running ".format(config_params.dhcp6_service_name))
        reset_module_config()
        st.report_fail("service_running_not_expected", config_params.dhcp6_service_name)
    global dhcp6_port
    global dhcp6_static_ip
    global dhcp6_home_path
    global dhcp6_config_file
    if network_flag != "inband":
        dhcp6_port = ztp_params.dhcp6.oob_port
        dhcp6_static_ip = ztp_params.dhcp6.oob_static_ip
        dhcp6_home_path = ztp_params.dhcp6.oob_home_path
        dhcp6_config_file = ztp_params.dhcp6.oob_config_file
        ztp_params.home_path = ztp_params.dhcp6.oob_home_path
    else:
        dhcp6_port = ztp_params.dhcp6.inband_port
        dhcp6_static_ip = ztp_params.dhcp6.inband_static_ip
        dhcp6_home_path = ztp_params.dhcp6.inband_home_path
        dhcp6_config_file = ztp_params.dhcp6.inband_config_file
        ztp_params.home_path = ztp_params.dhcp6.inband_home_path
        basic_obj.ifconfig_operation(vars.D1, ztp_params.dhcp6.oob_port, "down")
    basic_obj.poll_for_system_status(vars.D1)
    ztp_cfg = {"admin-mode": True, "restart-ztp-interval": 30, "feat-console-logging": feat_logging_console}
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg)
def reset_module_config():
    basic_obj.delete_directory_contents(vars.D1, config_params.ztp_run_path)
    st.log("Resetting all DHCP services as part of module unconfig...")
    connection_objs = [ssh_conn_obj_oob_v4, ssh_conn_obj_inb_v4]
    for connection_obj in connection_objs:
        if connection_obj:
            basic_obj.service_operations(connection_obj, config_params.dhcp_service_name, "start", "server")
            con_obj.ssh_disconnect(connection_obj)
    if network_flag == "inband":
        if ssh_conn_obj_inb_v6:
            basic_obj.service_operations(ssh_conn_obj_inb_v6, config_params.dhcp6_service_name, "start", "server")
            con_obj.ssh_disconnect(ssh_conn_obj_inb_v6)
        if ssh_conn_obj_oob_v6:
            con_obj.ssh_disconnect(ssh_conn_obj_oob_v6)
    else:
        if ssh_conn_obj_oob_v6:
            basic_obj.service_operations(ssh_conn_obj_oob_v6, config_params.dhcp6_service_name, "start", "server")
            con_obj.ssh_disconnect(ssh_conn_obj_oob_v6)
        if ssh_conn_obj_inb_v6:
            con_obj.ssh_disconnect(ssh_conn_obj_inb_v6)
    basic_obj.ifconfig_operation(vars.D1, ztp_params.dhcp6.oob_port, "up")
    # intf_obj.interface_noshutdown(vars.D1, ztp_params.dhcp6.inband_port)
@pytest.fixture(scope="module", autouse=True)
def ztp_module_hooks(request):
    st.add_prevent("ztp")
    initialize_variables()
    pre_config_ztp()
    path_list = [ztp_params.home_path+ztp_params.config_path, ztp_params.home_path+ztp_params.provision_script_path]
    ztp_obj.create_required_folders(ssh_conn_obj, path_list)
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml", "/etc/sonic/snmp.yml.bkp")
    source_path = "{}{}".format(config_params.local_provision_scripts_folder, config_params.snmp_filename)
    st.upload_file_to_dut(vars.D1, source_path, "/home/admin/snmp.yml")
    basic_obj.copy_file_to_local_path(vars.D1, "/home/admin/snmp.yml", "/etc/sonic/snmp.yml")
    yield
    ztp_cfg = {"admin-mode": True, "restart-ztp-interval": 30, "feat-console-logging": feat_logging_console}
    ztp_obj.config_ztp_backdoor_options(vars.D1, ztp_cfg)
    reset_module_config()
    basic_obj.move_file_to_local_path(vars.D1, "/etc/sonic/snmp.yml.bkp", "/etc/sonic/snmp.yml")


@pytest.fixture(scope="function", autouse=True)
def ztp_func_hooks(request):
    initialize_variables()
    basic_obj.remove_file(vars.D1, config_params.ztp_local_json_path)
    basic_obj.copy_config_db_to_temp(vars.D1, config_params.config_db_path, config_params.config_db_temp)
    basic_obj.change_permissions(vars.D1, config_params.config_db_temp)
    ztp_obj.enable_ztp_if_disabled(vars.D1)
    config_params.func_name = st.get_func_name(request)
    yield
    ztp_obj.ztp_operations(vars.D1, "disable")
    basic_obj.copy_config_db_to_temp(vars.D1, config_params.config_db_temp, config_params.config_db_path)
    config_params.dhcp_config_file = dhcp6_config_file
    config_params.option_type = "option_59"
    ztp_obj.clear_options_from_dhcp_server(ssh_conn_obj, config_params)

def initialize_variables():
    global config_params
    config_params = SpyTestDict()
    config_params.ztp_log_path_1 = "/var/log/ztp.log.1"
    config_params.result = "pass"
    config_params.ztp_local_json_path = "/host/ztp/ztp_data.json"
    config_params.ztp_run_path = "/var/run/ztp"
    config_params.ztp_log_path = "/var/log/ztp.log"
    config_params.syslog_path = "/var/log/syslog"
    config_params.config_db_path = "/etc/sonic/config_db.json"
    config_params.client_path = "/home/admin"
    config_params.config_db_temp = "/home/admin/config_db_temp.json"
    config_params.temp_path = "/tmp"
    config_params.file_names = ["02-configdb-json", "01-provisioning-script", "06-snmp"]
    config_params.local_path = os.path.dirname(__file__)
    config_params.local_provision_scripts_folder = "{}/scripts/".format(config_params.local_path)
    config_params.option_239_sh_file = "provisioning_script.sh"
    config_params.snmp_filename = "snmp.yml"
    config_params.ztp_file = "ztp_dhcpv6.json"
    config_params.config_db_location = "local"
    config_params.lease_db_path = "/var/lib/dhcp"
    config_params.dhcp_service_name = "isc-dhcp-server"
    config_params.dhcp6_service_name = "isc-dhcp-server6"
    config_params.dhcpd_pid = "dhcpd.pid"
    config_params.dhcpd6_pid = "dhcpd6.pid"
    config_params.logs_path = "{}/logs".format(os.path.dirname(__file__))


@pytest.mark.ft_ztp_config_section_check_with_option_59_v6
def test_ft_ztp_config_section_check_with_option_59_v6(ztp_func_hooks):
    # ################ Author Details ################
    # Name: Chaitanya Vella
    # Email: chaitanya-vella.kumar@broadcom.com
    # ################################################
    # ############## Test bed details ################
    #  D1 ---- DHCP Server

    #  ft_ztp_config_section_check_with_option_67_with_inband	:
    #  Verify that SONiC ZTP is successful through in-band ports using ZTP
    #  URL provided in DHCP option 59 received over IPv6 network.
    # #################################################
    vars = st.ensure_min_topology("D1")
    config_params.home_path = dhcp6_home_path
    config_params.static_ip = dhcp6_static_ip
    config_params.dhcp_config_file = dhcp6_config_file
    config_params.ztp_operation = "reboot"
    config_params.result = ""
    config_params.dut = vars.D1
    config_params.dut_ztp_cfg_file = "{}/{}".format(ztp_params.dut_path, ztp_params.ztp_cfg_file_name)
    config_params.network_port = dhcp6_port
    config_params.json_content = {
        "ztp": {
            "02-configdb-json": {"url": {"source": "file://{}".format(config_params.config_db_temp),
                                 "timeout": 300}, "clear-config": "False","save-config": "True"},
            "01-provisioning-script": {
                "plugin": {
                    "url": "http://[{}]{}/{}".format(config_params.static_ip,
                                                                         ztp_params.provision_script_path,
                                                     config_params.option_239_sh_file)
                }
            },
            "06-snmp": {
                "community-ro": "sonicnew",
                "snmp-location": "Hyderabad",
                "snmp-syscontact": "adminnew",
                "ignore-result": "true",
                "restart-agent": True
            }
        }
    }
    source_path = "{}{}".format(config_params.local_provision_scripts_folder, config_params.option_239_sh_file)
    destination_path = "{}{}/{}".format(ztp_params.home_path, ztp_params.provision_script_path, config_params.option_239_sh_file)
    st.log("Copying file from client to server FROM : {} TO: {}".format(source_path, destination_path))
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=source_path, dst_path=destination_path,
                                              persist=True)
    # options={"reboot_on_success": "01-configdb-json"}
    ztp_obj.config_dhcpv6_options(ssh_conn_obj, ztp_params, config_params)
    ztp_status = ztp_obj.show_ztp_status(vars.D1)
    if "dhcp6-opt59" not in ztp_status["source"] or dhcp6_port not in ztp_status["source"]:
        st.log("ZTP source verification failed with {} against dhcp6-opt59 or port {}".format(ztp_status["source"], dhcp6_port))
        st.report_fail("ztp_source_verification_failed", "dhcp6-opt59", ztp_status["source"])
    snmp_params = {"rocommunityv6": "sonicnew", "rocommunity": "sonicnew"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syslocation": "Hyderabad"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    snmp_params = {"syscontact": "adminnew"}
    if not verify_snmp_details_using_docker(vars.D1, **snmp_params):
        st.report_fail("snmp_params_verification_failed")
    st.report_pass("test_case_passed")


