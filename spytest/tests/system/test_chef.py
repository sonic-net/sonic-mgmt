import pytest
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.connection as con_obj
import apis.system.chef as chef_obj
import apis.system.interface as intf_obj
import apis.switching.vlan as vlan_obj
import apis.system.basic as basic_obj
import utilities.utils as util_obj
import spytest.utils as utils
import apis.switching.portchannel as portchannel_obj
import apis.switching.mac as mac_obj
import random

chef_params = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def chef_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    if st.get_ui_type() in ['klish'] :
        st.report_unsupported('test_execution_skipped', 'Skipping Chef test case for ui_type={}'.format(st.get_ui_type()))
    global free_ports
    global node_name
    global exclude_list
    global free_ports_samespeed
    free_ports = st.get_free_ports(vars.D1)
    if not free_ports:
        st.log("No free ports available")
        st.report_env_fail("test_case_not_executeds")
    vlan_members = [free_ports[0], free_ports[1], free_ports[2]]
    st.log("VLAN Members: {}".format(",".join(vlan_members)))
    free_ports_samespeed = get_free_ports_speed_list(vars.D1, vlan_members)
    st.log("Free ports same speed: {}".format(",".join(free_ports_samespeed)))
    exclude_list = vlan_members + [free_ports_samespeed[0], free_ports_samespeed[1], free_ports_samespeed[2]]
    node_name = 'testsonic{}'.format(random.randrange(1,5000))
    chef_params.client_path = util_obj.ensure_service_params(vars.D1, "chef", "client_path")
    chef_obj.delete_client_pem_files(vars.D1, "{}/{}".format(chef_params.client_path, "client.pem"))
    chef_obj.delete_client_pem_files(vars.D1, "{}/{}".format(chef_params.client_path, "validation.pem"))
    chef_pre_config_in_parallel()
    yield
    vlan_obj.clear_vlan_configuration(vars.D1)
    portchannel_obj.clear_portchannel_configuration(vars.D1)
    mac_obj.clear_mac(vars.D1)
    basic_obj.service_operations(vars.D1, "chef-client", "stop")
    chef_obj.delete_client_pem_files(vars.D1, "{}/{}".format(chef_params.client_path, "client.pem"))
    chef_obj.delete_chef_node(ssh_conn_obj, node_name)
    if ssh_conn_obj:
        con_obj.ssh_disconnect(ssh_conn_obj)



@pytest.fixture(scope="function", autouse=True)
def chef_func_hooks(request):
    global hostname
    global_vars()
    chef_obj.reset_cookbook_json()
    hostname = basic_obj.get_hostname(vars.D1)
    yield


def global_vars():
    global data
    data = SpyTestDict()
    data.poll_wait = 30

def chef_pre_config(dut):
    st.log("CHEF pre-config Start")
    ip_addr = basic_obj.get_ifconfig_inet(dut, 'eth0')
    if not ip_addr:
        st.log("IP Address not found on eth0")
        st.report_env_fail("test_case_not_executeds")
    basic_obj.deploy_package(dut, mode='update')
    basic_obj.deploy_package(dut, packane_name='sshpass', mode='install')
    ip = util_obj.ensure_service_params(dut, "chef", "ip")
    username = util_obj.ensure_service_params(dut, "chef", "username")
    password = util_obj.ensure_service_params(dut, "chef", "password")
    st.log("Chef Server IP : {}".format(ip))
    url = "https://{}:443".format(ip)
    st.log("Chef server url used : {}".format(url))
    if not chef_obj.chef_package_install(dut, url, ip_addr[0], 'admin', 'broadcom', 'YourPaSsWoRd'):
        st.report_env_fail("test_case_not_executeds")
    st.log("Done Installing the dependents packages if not installed.")
    if not chef_obj.sync_with_server_time(dut, ip, username, password):
        st.report_env_fail("test_case_not_executeds")



def chef_pre_config_in_parallel(thread=True):
    [out, exceptions] = utils.exec_foreach(thread, vars.dut_list, chef_pre_config)
    st.log(exceptions)
    if False in out:
        st.report_env_fail("test_case_not_executeds")
    st.log("Fetching Chef config params from sonic services file")
    chef_params.ip = util_obj.ensure_service_params(vars.D1, "chef", "ip")
    chef_params.username = util_obj.ensure_service_params(vars.D1, "chef", "username")
    chef_params.password = util_obj.ensure_service_params(vars.D1, "chef", "password")
    chef_params.path = util_obj.ensure_service_params(vars.D1, "chef", "path")
    chef_params.roles = util_obj.ensure_service_params(vars.D1, "chef", "roles")
    chef_params.cookbook_path = util_obj.ensure_service_params(vars.D1, "chef", "cookbook_path")
    chef_params.client_path = util_obj.ensure_service_params(vars.D1, "chef", "client_path")
    chef_params.validation_file = util_obj.ensure_service_params(vars.D1, "chef", "validation_file")
    chef_params.client_rb = util_obj.ensure_service_params(vars.D1, "chef", "client_rb")
    chef_params.client_log = util_obj.ensure_service_params(vars.D1, "chef", "client_log")
    chef_params.default_rb = util_obj.ensure_service_params(vars.D1, "chef", "default_rb")
    chef_params.mgmt_intf = util_obj.ensure_service_params(vars.D1, "chef", "mgmt_intf")

    st.log("Logging in to chef server with the params from config file.")
    global ssh_conn_obj
    ssh_conn_obj = con_obj.connect_to_device(chef_params.ip,
                                             chef_params.username, chef_params.password)
    if not ssh_conn_obj:
        st.error("SSH connetion object not found.")
        st.report_env_fail("ssh_connection_failed", chef_params.ip)
    ip_addr = basic_obj.get_ifconfig_inet(vars.D1, chef_params.mgmt_intf)

    ssh_obj = con_obj.connect_to_device(ip_addr[0],'admin', 'YourPaSsWoRd')
    if ssh_obj:
        chef_obj.bootstrap_chef_node(ssh_conn_obj, ip_addr[0], 'admin', 'YourPaSsWoRd', node_name)
    else:
        chef_obj.bootstrap_chef_node(ssh_conn_obj, ip_addr[0], 'admin', 'broadcom', node_name)
    st.log("CHEF pre-config Done")


def chef_server_operations(ssh_conn_obj, dut, chef_params, role_file, file_path, destination_path):
    """
    Common function to do chef server side operations
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param ssh_conn_obj:
    :param dut:
    :param chef_params:
    :param role_file:
    :param file_path:
    :param destination_path:
    :return:
    """
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    st.log("Generating {} file on the chef server ".format(chef_params.validation_file))
    st.log("Changing directory to {}".format(chef_params.path))
    st.log(con_obj.execute_command(ssh_conn_obj, "cd {}".format(chef_params.path)))
    st.log("Uploading the role to chef server...")
    update_role = chef_obj.upload_role_chef_server(ssh_conn_obj, "{}/{}".format(chef_params.roles, role_file))
    if not update_role:
        st.log("error_update_role_chef_server")
        st.report_fail("error_update_role_chef_server")
    st.log("Updating node run list ...")
    update_node_list = chef_obj.update_node_run_list(ssh_conn_obj, node_name,
                                                     "recipe[sonic::vlan],role[{}]".format(hostname))
    if not update_node_list:
        st.log("error_update_node_run_list")
        st.report_fail("error_update_node_run_list")
    return True


def chef_client_operations(dut, chef_params):
    """
    Common function to do the chef client operations
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param chef_params:
    :return:
    """
    st.log("Running chef client ..")
    chef_obj.run_chef_client(dut)
    st.log("Verifying client file on chef client")
    if not basic_obj.verify_file_on_device(dut, chef_params.client_path):
        st.error("Chef client pem file not present under {}".format(chef_params.client_path))
        st.report_fail("error_client_pem_file_not_present", chef_params.client_path)
    return True

@pytest.mark.chef_multi_clients
def test_ft_chef_config_apply():
    role_file = "sonic_dut_1.json"
    destination_path = "{}/{}".format(chef_params.roles, role_file)
    free_ports = st.get_free_ports(vars.D1)
    vlan_list = vlan_obj.get_non_existing_vlan(vars.D1, 1)
    vlan_id = vlan_list[0]
    vlan_members = [free_ports[0], free_ports[1], free_ports[2]]
    vlan_config = {"VLAN {}".format(vlan_id): {"vlan_id": vlan_id, "tagging_mode": "tagged",
                                           "participation_list": vlan_members}}
    chef_obj.generate_cookbook_json(feature="vlans", config=vlan_config, run_list="recipe[sonic::vlan]")
    interface_config = {"{}".format(free_ports[2]):{"admin_status":"up"}}
    chef_obj.generate_cookbook_json(feature="interfaces", config=interface_config, run_list="recipe[sonic::interface]")
    fbd_config = {"FDB 1": {"mac": "00:00:00:00:00:01","vlan_id": vlan_id,"port": free_ports[0]}, "FDB 2": {"mac": "00:11:22:33:44:55","vlan_id": vlan_id,"port": free_ports[1]}}
    chef_obj.generate_cookbook_json(feature="fdbs", config=fbd_config,
                                    run_list="recipe[sonic::fdb]")
    lag_config = {"PortChannel500": {"links":[free_ports_samespeed[0]]},"PortChannel900":{"minimum_links": "2",
                                    "fallback": True, "links": [free_ports_samespeed[1], free_ports_samespeed[2]]}}
    chef_obj.generate_cookbook_json(feature="lags", config=lag_config,
                                    run_list="recipe[sonic::lag]")
    file_path = chef_obj.write_cookbook_json()
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    config=SpyTestDict()
    config.role_file = role_file
    config.vlan_id = vlan_id
    config.vlan_members = vlan_members
    updating_node_run_list_operations(ssh_conn_obj, node_name, chef_params, role_file)
    run_and_verify_chef_client(vars.D1, chef_params)
    if not utils.poll_wait(portchannel_obj.verify_portchannel_member, data.poll_wait,vars.D1, "PortChannel500", free_ports_samespeed[0]):
        st.report_fail("portchannel_member_verification_failed","PortChannel500", vars.D1, free_ports_samespeed[0])
    if not utils.poll_wait(portchannel_obj.verify_portchannel_member, data.poll_wait,vars.D1, "PortChannel900", free_ports_samespeed[1]):
        st.report_fail("portchannel_member_verification_failed","PortChanne900", vars.D1, free_ports_samespeed[1])
    if not utils.poll_wait(mac_obj.verify_mac_address_table,data.poll_wait,vars.D1, "00:00:00:00:00:01", port=free_ports[0]):
        st.log("MAC '{}' is failed to learn in port = {}".format("00:00:00:00:00:01", free_ports[0]))
        st.report_fail('mac_address_verification_fail')
    if not utils.poll_wait(vlan_obj.verify_vlan_brief,data.poll_wait,vars.D1, vlan_id):
        st.report_fail("operation_failed")
    if not utils.poll_wait(intf_obj.verify_interface_status,data.poll_wait,vars.D1, free_ports[2], 'admin', 'up'):
        st.report_fail("operation_failed")
    st.report_pass("test_case_passed")

def common_func_config_apply_multiple_clients(dut, chef_params):
    chef_obj.delete_client_pem_files(dut, "{}/{}".format(chef_params.client_path, chef_params.validation_file))
    st.log("Deleting client.pem file")
    chef_obj.delete_client_pem_files(dut, "{}/{}".format(chef_params.client_path, "client.pem"))
    st.log("Deleting {} file".format(chef_params.validation_file))
    st.log("Copying certificate from server to client")
    source_path = "{}/{}".format(chef_params.path, chef_params.validation_file)
    destination_path = "{}/{}".format(chef_params.client_path, chef_params.validation_file)
    chef_obj.copy_validation_pem_from_chef_sever_to_client(dut,
                                                           ip_address=chef_params.ip, username=chef_params.username,
                                                           password=chef_params.password,
                                                           src_path=source_path, dst_path=destination_path)

def run_and_verify_chef_client(dut, chef_params):
    st.log("Running chef client ..")
    chef_obj.run_chef_client(dut)
    st.log("Verifying client file on chef client")
    if not basic_obj.verify_file_on_device(dut, chef_params.client_path):
        st.log("Chef client pem file not present under {}".format(chef_params.client_path))
        st.error("Chef client pem file not present under {}".format(chef_params.client_path))

def updating_node_run_list_operations(ssh_conn_obj, hostname, chef_params, role_file):
    st.log("Changing directory to {}".format(chef_params.path))
    st.log(con_obj.execute_command(ssh_conn_obj, "cd {}".format(chef_params.path)))
    st.log("Uploading the role to chef server...")
    update_role = chef_obj.upload_role_chef_server(ssh_conn_obj, "{}/{}".format(chef_params.roles, role_file))
    if not update_role:
        st.log("error_update_role_chef_server")
        st.report_fail("error_update_role_chef_server")
    st.log("Updating node run list ...")
    update_node_list = chef_obj.update_node_run_list(ssh_conn_obj, hostname,
                            "recipe[sonic::vlan],role[sonic],recipe[sonic::fdb],recipe[sonic::lag],recipe[sonic::interface]")
    if not update_node_list:
        st.log("error_update_node_run_list")
        st.report_fail("error_update_node_run_list")

@pytest.mark.chef_config_cli_cmd_recipe
def test_ft_chef_config_cli_cmd_recipe():
    cookbook = "sonic-cli"
    recipe = "recipe[sonic-cli]"
    free_ports_samespeed = get_free_ports_speed_list(vars.D1, exclude_list)
    if len(free_ports_samespeed) < 8:
        st.log("Received less than 8 ports in the list of ports, needed a min of 8 ports")
        st.log("Length is freeports list is:{}".format(len(free_ports_samespeed)))
        st.log("Received free ports same speed list:{}".format(free_ports_samespeed))
        st.report_fail("test_case_failed")
    destination_path = "{}{}".format(chef_params.path, chef_params.default_rb)
    configuration = {"vlans":
                         {"add":
                              {"10":
                                   {"members":
                                        [{"port": free_ports_samespeed[0], "tagged": True},
                                         {"port": free_ports_samespeed[1], "tagged": False}]},
                               "40":
                                   {"members":
                                        [{"port": free_ports_samespeed[2], "tagged": True}, {"port": free_ports_samespeed[3], "tagged": False}]}
                               }},
                     "fdbs": {"add": [{"mac": "00:00:00:00:00:01", "vlan_id": 10, "port": free_ports_samespeed[0]},
                                      {"mac": "00:00:00:00:40:01", "vlan_id": 600, "port": free_ports_samespeed[1]}],
                              "del": [{"mac": "00:00:00:00:00:01", "vlan_id": 600, "port": free_ports_samespeed[2]}]},
                     "lags": {"add": {
                         "PortChannel004": {"links": [free_ports_samespeed[4], free_ports_samespeed[5]], "min-links": "2"},
                         "PortChannel005": {"links": [free_ports_samespeed[6], free_ports_samespeed[7]], "fallback": True, "min_links": "2"}
                     }}, "interfaces": {free_ports_samespeed[1]: {"admin_status": "up"},
                                        free_ports_samespeed[2]: {"admin_status": "up"}}}
    commands = ""
    #chef_obj.create_chef_cookbook(ssh_conn_obj, chef_params.cookbook_path, cookbook)
    commands = chef_obj.chef_execute_cli_commands(configuration)

    if commands:
        file_path = basic_obj.write_to_text_file(commands)
        basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path)
    chef_obj.upload_chef_cookbook(ssh_conn_obj, chef_params.cookbook_path, cookbook)
    chef_obj.operations_on_runlist(ssh_conn_obj, "{} ''".format(node_name), "set")
    chef_obj.show_node_run_list(ssh_conn_obj, node_name)
    chef_obj.update_node_run_list(ssh_conn_obj, node_name, "'{}'".format(recipe))
    st.log("Running chef client ..")
    if not chef_obj.run_chef_client(vars.D1):
        st.report_fail("test_case_failed")
    st.log("Verifying client file on chef client")
    vlan_id = 10
    if not utils.poll_wait(portchannel_obj.verify_portchannel_member, data.poll_wait,vars.D1, "PortChannel005", free_ports_samespeed[6]):
        st.report_fail("operation_failed")
    if not utils.poll_wait(mac_obj.verify_mac_address_table, data.poll_wait,vars.D1, "00:00:00:00:00:01", vlan_id):
        st.log("MAC '{}' is failed to learn in port = {}".format("00:00:00:00:00:01", free_ports_samespeed[0]))
        st.report_fail('mac_address_verification_fail')
    if not utils.poll_wait(vlan_obj.verify_vlan_brief, data.poll_wait,vars.D1, vlan_id):
        st.report_fail("operation_failed")
    if not utils.poll_wait(intf_obj.verify_interface_status, data.poll_wait,vars.D1, free_ports_samespeed[1], 'admin', 'up'):
        st.report_fail("operation_failed")
    chef_obj.operations_on_runlist(ssh_conn_obj, "{} ''".format(node_name), "set")
    st.report_pass("test_case_passed")

@pytest.mark.chef_error
def test_ft_chef_config_apply_with_errors():
    data.vlan_list = [5000]
    data.vlan_members = ["Ethernet0", "Ethernet4"]
    role_file = "sonic_temp.json"
    destination_path = "{}/{}".format(chef_params.roles, role_file)
    for vlan_id in data.vlan_list:
        vlan_config = {"VLAN {}".format(vlan_id): {"vlan_id": vlan_id, "tagging_mode": "tagged",
                                                   "participation_list": data.vlan_members}}
        chef_obj.generate_cookbook_json(feature="vlans", config=vlan_config, run_list="recipe[sonic::vlan]")
    file_path = chef_obj.write_cookbook_json()
    basic_obj.copy_file_from_client_to_server(ssh_conn_obj, src_path=file_path, dst_path=destination_path, persist=True)
    chef_server_operations(ssh_conn_obj, vars.D1, chef_params, role_file, file_path, destination_path)
    chef_client_operations(vars.D1, chef_params)
    error_string = "value {} does not match regular expression".format(data.vlan_list[0])
    log_path = "/var/chef/cache/chef-stacktrace.out"
    check_error = basic_obj.check_error_log(vars.D1, log_path, error_string)
    if not check_error:
        st.report_fail("error_string_not_found", error_string, chef_params.client_log)
    st.report_pass("test_case_passed")

def get_free_ports_speed_list(dut, exclude_list):
    free_speed_portlist = list()
    free_speed_ports = intf_obj.get_all_ports_speed_dict(dut)
    for each in free_speed_ports:
        tmp_list = list()
        for eachport in free_speed_ports[each]:
            if eachport not in exclude_list:
                tmp_list.append(eachport)
        free_speed_portlist.append(tmp_list)
    final_list = free_speed_portlist[
        [len(a) for a in free_speed_portlist].index(max([len(a) for a in free_speed_portlist]))]
    st.log("Final return value:{}".format(final_list))
    return final_list

