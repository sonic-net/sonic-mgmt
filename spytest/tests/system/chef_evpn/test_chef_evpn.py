#############################################################################
#Script Title : Chef For Evpn
#Author       : Chandra B S
#Mail-id      : chandra.singh@broadcom.com
#############################################################################

import os
import pytest

from spytest import st, mutils, putils

import apis.routing.ip_bgp as ip_bgp
import apis.system.connection as con_obj

from chef_evpn_vars import data, chef_server
import apis.system.chef_evpn as chef_evpn_obj
import chef_evpn_lib as loc_lib



def initialize_topology():
# code for ensuring min topology

    vars = st.ensure_min_topology('D1D2:2','D1D3:0','D1D4:2','D3D4:2','D3D2:2','D2D4:0')
    data.my_dut_list = st.get_dut_names()
    data.d1 = data.my_dut_list[0]
    data.d2 = data.my_dut_list[1]
    data.d3 = data.my_dut_list[2]
    data.d4 = data.my_dut_list[3]

    data.d1_d2_intf_1 = vars.D1D2P1
    data.d2_d1_intf_1 = vars.D2D1P1

    data.d1_d2_intf_2 = vars.D1D2P2
    data.d2_d1_intf_2 = vars.D2D1P2

    data.d1_d4_intf_1 = vars.D1D4P1
    data.d4_d1_intf_1 = vars.D4D1P1
    data.d1_d4_intf_2 = vars.D1D4P2
    data.d4_d1_intf_2 = vars.D4D1P2

    data.d3_d4_intf_1 = vars.D3D4P1
    data.d4_d3_intf_1 = vars.D4D3P1

    data.d3_d4_intf_2 = vars.D3D4P2
    data.d4_d3_intf_2 = vars.D4D3P2

    data.d3_d2_intf_1 = vars.D3D2P1
    data.d2_d3_intf_1 = vars.D2D3P1
    data.d3_d2_intf_2 = vars.D3D2P2
    data.d2_d3_intf_2 = vars.D2D3P2
    data.wait = 120


    def f1():
        ip = loc_lib.get_dut_ip(data.d1)
        return ip
    def f2():
        ip = loc_lib.get_dut_ip(data.d2)
        return ip
    def f3():
        ip = loc_lib.get_dut_ip(data.d3)
        return ip
    def f4():
        ip = loc_lib.get_dut_ip(data.d4)
        return ip

    [res, _] = putils.exec_all(True, [[f1], [f2], [f3], [f4]] )
    data.d1_ip = res[0]
    data.d2_ip = res[1]
    data.d3_ip = res[2]
    data.d4_ip = res[3]


    data.role_path = os.path.join(os.path.dirname(__file__), data.role_dir)
    st.log('#####################{}'.format(data.role_path))

    chef_param_list = ['ip', 'username', 'password', 'cookbook_path', 'path', 'client_path', 'validation_file', 'client_rb', 'client_log', 'user_home_folder']
    for chef_param in chef_param_list:
        chef_server[chef_param] = mutils.ensure_service_params(data.d1, chef_server.name, chef_param)

    chef_server.url = "https://{}:443".format(chef_server.ip)
    st.log("Chef server url used : {}".format(chef_server.url))

    st.log("Logging in to chef server with the params from config file.")
    chef_server.ssh_obj = con_obj.connect_to_device(chef_server.ip, chef_server.username, chef_server.password)
    if not chef_server.ssh_obj:
        st.error("SSH connetion object not found.")
        st.report_env_fail("ssh_connection_failed", chef_server.ip)


    for key,value in data.items():
        st.log('{} - {}'.format(key,value))



@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue():

    if st.get_ui_type() in ['klish'] :
        st.report_unsupported('test_execution_skipped', 'Skipping Chef_EVPN test case for ui_type={}'.format(st.get_ui_type()))
    
    st.log('Define Common config, including TGEN related, if any')

    initialize_topology()

    f1 = lambda x: loc_lib.chef_pre_config(data.d1, data.d1_ip)
    f2 = lambda x: loc_lib.chef_pre_config(data.d2, data.d2_ip)
    f3 = lambda x: loc_lib.chef_pre_config(data.d3, data.d3_ip)
    f4 = lambda x: loc_lib.chef_pre_config(data.d4, data.d4_ip)
    putils.exec_all(True, [[f1, 1], [f2, 1],[f3, 1], [f4, 1]])

    if not chef_evpn_obj.sync_with_server_time(data.my_dut_list, chef_server.ip, chef_server.username, chef_server.password):
                   st.report_env_fail("test_case_not_executeds")


    f1 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d1, chef_server.client_path)
    f2 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d2, chef_server.client_path)
    f3 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d3, chef_server.client_path)
    f4 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d4, chef_server.client_path)
    putils.exec_all(True, [[f1, 1], [f2, 1],[f3, 1], [f4, 1]])

    chef_evpn_obj.generate_certs(chef_server.ssh_obj, chef_server.path)

    #Cleanup exisitng node if any
    chef_evpn_obj.delete_chef_node(chef_server.ssh_obj, ' '.join(data.node_list), ' '.join(data.role_list))

    '''
    for node in data.node_list:
        chef_evpn_obj.delete_chef_node(chef_server.ssh_obj, node)
    '''

    putils.exec_all(True, [[f1, 1], [f2, 1],[f3, 1], [f4, 1]])


    #Generate certs and bootstrap node
    chef_evpn_obj.generate_certs(chef_server.ssh_obj, chef_server.path)
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d1_ip, 'admin', 'broadcom', data.node_list[0]):
        st.report_env_fail("chef_bootstrap_fail")
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d2_ip, 'admin', 'broadcom', data.node_list[1]):
        st.report_env_fail("chef_bootstrap_fail")
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d3_ip, 'admin', 'broadcom', data.node_list[2]):
        st.report_env_fail("chef_bootstrap_fail")
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d4_ip, 'admin', 'broadcom', data.node_list[3]):
        st.report_env_fail("chef_bootstrap_fail")

    #upload cookbook
    chef_evpn_obj.upload_chef_cookbook(chef_server.ssh_obj, chef_server.path)

    yield
    st.log('Define Common cleanup, including TGEN related, if any')
    for role,node_name in zip(data.role_list, data.node_list):
        run_list ='role[{}],recipe[sonic::vlan],recipe[sonic::loopback],recipe[sonic::lag],recipe[sonic::vrf],recipe[sonic::interface],recipe[sonic::bgprouter]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj, node_name, run_list, 'remove')

    loc_lib.bgp_unconfig()
    loc_lib.static_route_unconfig()
    loc_lib.ip_unconfig()
    loc_lib.portchannel_unconfig()
    loc_lib.vlan_unconfig()
    loc_lib.vrf_unconfig()


@pytest.mark.chef_evpn_test_case
def test_chef_evpn_001():
    result = 0

    chef_server.role_dir = os.path.join(chef_server.path,'roles')
    for file_name,role,node_name in zip(data.role_tc_list, data.role_list, data.node_list):
        st.log('{}, {}, {}'.format(file_name,role,node_name))
        new_file_name = loc_lib.modify_role_file(file_name)
        #copy_role_file_to_chef_server(file_name)
        loc_lib.copy_role_file_to_chef_server(new_file_name)
        st.log('{}, {}, {}'.format(new_file_name,role,node_name))

        chef_evpn_obj.upload_role_chef_server(chef_server.ssh_obj, chef_server.role_dir, file_name=new_file_name)
        run_list ='role[{}],recipe[sonic::vlan],recipe[sonic::loopback],recipe[sonic::lag],recipe[sonic::vrf],recipe[sonic::interface],recipe[sonic::bgprouter]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj,node_name,run_list)

    f1 = lambda x: chef_evpn_obj.run_chef_client(data.d1)
    f2 = lambda x: chef_evpn_obj.run_chef_client(data.d2)
    f3 = lambda x: chef_evpn_obj.run_chef_client(data.d3)
    f4 = lambda x: chef_evpn_obj.run_chef_client(data.d4)
    putils.exec_all(True, [[f1, 1], [f2, 1],[f3, 1], [f4, 1]])
    st.wait(data.wait)

    if not loc_lib.retry_api(ip_bgp.check_bgp_session, data.d1, nbr_list=[data.d2_d1_vlan_1_ip, data.d4_d1_pc_1_ip], state_list=['Established']*2):
        st.error("one or more BGP sessions did not come up between dut1 and dut2")
        result += 1
    if not loc_lib.retry_api(ip_bgp.check_bgp_session, data.d1, nbr_list=[data.d2_d1_intf_1_ip, data.d2_d1_intf_1_ip6], state_list=['Established']*2, vrf_name='Vrf-01'):
        st.error("one or more BGP sessions did not come up between dut1 and dut2")
        result += 1
    if not loc_lib.retry_api(ip_bgp.check_bgp_session, data.d3, nbr_list=[data.d4_d3_intf_1_ip, data.d4_d3_vlan_1_ip, data.d2_d3_pc_1_ip, data.d4_d3_intf_1_ip6], state_list=['Established']*4):
        st.error("one or more BGP sessions did not come up between dut3 and dut4")
        result += 1
    if not loc_lib.verify_ping():
        st.error("Ping to loopback interface failed")
        result += 1

    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.print_debug()
        st.report_fail('test_case_failed')




