import re, os
import pytest
from spytest import st, mutils, putils

import apis.routing.ip as ip_obj
from apis.routing.evpn import verify_vxlan_tunnel_status, create_evpn_instance,create_overlay_intf,map_vlan_vni
from apis.routing.bgp import config_bgp
import apis.system.connection as con_obj
from apis.switching.portchannel import clear_portchannel_configuration, verify_portchannel_and_member_status
from apis.system.basic import get_hwsku
import apis.switching.mclag as mclag
import apis.switching.vlan as vlan

from chef_evpn_vars import data, chef_server
import apis.system.chef_evpn as chef_evpn_obj
import chef_evpn_lib as loc_lib

def initialize_topology():
# code for ensuring min topology

    vars = st.ensure_min_topology("D1D2:2","D1D3:1","D2D3:1","D2CHIP:TD3","D3CHIP:TD3")

    data.my_dut_list = st.get_dut_names()
    data.d1 = vars.D1
    data.d2 = vars.D2
    data.d3 = vars.D3
    data.wait = 10
    data.clear_parallel = True
    data.portChannelName = 'PortChannel001'
    data.peerlinkintf = 'PortChannel002'
    data.mclag_domain = 1
    data.d1d2p1 = vars.D1D2P1
    data.d2d1p1 = vars.D2D1P1
    data.d1d2p2 = vars.D1D2P2
    data.d2d1p2 = vars.D2D1P2
    data.d3d1p1 = vars.D3D1P1
    data.d3d2p1 = vars.D3D2P1

    data.d3d1p2 = vars.D3D1P2
    data.d1_d2_intf_1 = vars.D1D2P1
    data.d2_d1_intf_1 = vars.D2D1P1

    data.d1_d2_intf_2 = vars.D1D2P2
    data.d2_d1_intf_2 = vars.D2D1P2
    data.d1_d3_intf_1 = vars.D1D3P1
    data.d3_d1_intf_1 = vars.D3D1P1
    data.d3_d1_intf_2 = vars.D3D1P2

    data.d2_d3_intf_1 = vars.D2D3P1
    data.d3_d2_intf_1 = vars.D3D2P1
    data.d1d2_ip = '11.11.11.1'
    data.d2d1_ip = '11.11.11.2'

    [res, _] = putils.exec_foreach(True, data.my_dut_list,loc_lib.get_dut_ip)
    data.d1_ip = res[0]
    data.d2_ip = res[1]
    data.d3_ip = res[2]
    data.cli_type = "click"

    data.role_path = os.path.join(os.path.dirname(__file__), data.role_dir)
    st.log('#####################{}'.format(data.role_path))

    chef_param_list = ['ip', 'username', 'password', 'cookbook_path', 'path', 'client_path', 'validation_file', 'client_rb',
                       'client_log', 'user_home_folder']
    for chef_param in chef_param_list:
        chef_server[chef_param] = mutils.ensure_service_params(data.d1, chef_server.name, chef_param)

    chef_server.url = "https://{}:443".format(chef_server.ip)
    st.log("Chef server url used : {}".format(chef_server.url))

    st.log("Logging in to chef server with the params from config file.")
    chef_server.ssh_obj = con_obj.connect_to_device(chef_server.ip, chef_server.username, chef_server.password)
    if not chef_server.ssh_obj:
        st.error("SSH connetion object not found.")
        st.report_env_fail("ssh_connection_failed", chef_server.ip)


@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue():
    if st.get_ui_type() in ['klish'] :
        st.report_unsupported('test_execution_skipped', 'Skipping Chef_MCLAG test case for ui_type={}'.format(st.get_ui_type()))

    st.log('Define Common config, including TGEN related, if any')
    initialize_topology()

    loc_lib.chef_pre_config(data.d1, data.d1_ip)

    if not chef_evpn_obj.sync_with_server_time(data.my_dut_list, chef_server.ip, chef_server.username, chef_server.password):
                   st.report_env_fail("test_case_not_executeds")

    f1 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d1, chef_server.client_path)
    f2 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d2, chef_server.client_path)
    f3 = lambda x: chef_evpn_obj.delete_client_pem_files(data.d3, chef_server.client_path)

    putils.exec_all(True, [[f1, 1],[f2, 1],[f3, 1]])

    chef_evpn_obj.generate_certs(chef_server.ssh_obj, chef_server.path)

    # Cleanup exisitng node if any
    chef_evpn_obj.delete_chef_node(chef_server.ssh_obj, ' '.join(data.node_list_mc), ' '.join(data.role_list_mc))

    # Generate certs and bootstrap node
    chef_evpn_obj.generate_certs(chef_server.ssh_obj, chef_server.path)
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d1_ip, 'admin', 'broadcom',
                                      data.node_list_mc[0]):
        st.report_env_fail("chef_bootstrap_fail")
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d2_ip, 'admin', 'broadcom',
                                      data.node_list_mc[1]):
        st.report_env_fail("chef_bootstrap_fail")
    if not chef_evpn_obj.bootstrap_chef_node(chef_server.ssh_obj, chef_server.path, data.d3_ip, 'admin', 'broadcom',
                                      data.node_list_mc[2]):
        st.report_env_fail("chef_bootstrap_fail")

    # upload cookbook
    #chef_evpn_obj.upload_chef_cookbook(chef_server.ssh_obj, chef_server.path)

    yield
    st.log('Define Common cleanup, including TGEN related, if any')
    for role, node_name in zip(data.role_list_mc, data.node_list_mc):
        run_list = 'role[{}],recipe[sonic::vlan],recipe[sonic::lag],recipe[sonic::interface],recipe[sonic::mclag]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj, node_name, run_list, 'remove')
    # Cleanup exisitng node if any
    chef_evpn_obj.delete_chef_node(chef_server.ssh_obj, ' '.join(data.node_list_mc), ' '.join(data.role_list_mc))


@pytest.fixture(scope="function", autouse=True)
def cmds_func_hooks(request):
    yield
    d1 = {'domain_id': 1, 'config' : 'del', 'cli_type': 'click'}
    putils.exec_parallel(True, [data.d1, data.d2], mclag.config_domain, [d1, d1])
    if st.get_func_name(request) == 'test_chef_evpn_vxlan_nvo':
        evpn_cleanup()
        bgp_cleanup()
    ip_obj.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel, cli_type=data.cli_type)
    clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel, cli_type=data.cli_type)

def bgp_cleanup():
    dict1 = {'config': 'no', 'local_as': data.d1_as, 'removeBGP': 'yes', 'config_type_list': ['removeBGP'], 'cli_type':"vtysh"}
    dict2 = {'config': 'no', 'local_as': data.d2_as, 'removeBGP': 'yes', 'config_type_list': ['removeBGP'], 'cli_type':"vtysh"}
    dict3 = {'config': 'no', 'local_as': data.d3_as, 'removeBGP': 'yes', 'config_type_list': ['removeBGP'], 'cli_type':"vtysh"}
    putils.exec_parallel(True, [data.d1, data.d2, data.d3], config_bgp, [dict1, dict2, dict3])


def evpn_cleanup():
    st.log("Delete L2 vlan to VNI mapping")
    putils.exec_all(True, [[map_vlan_vni, data.d2, "vtepLeaf1", "100", "100", "1", "no", False, data.cli_type],
                          [map_vlan_vni, data.d3, "vtepLeaf2","100", "100","1", "no", False, data.cli_type]])

    st.log("Remove evpn nvo instance from all leaf nodes")
    putils.exec_all(True, [[create_evpn_instance, data.d2,"nvoLeaf1", "vtepLeaf1", "no", False, data.cli_type],
                          [create_evpn_instance, data.d3,"nvoLeaf2", "vtepLeaf2", "no", False, data.cli_type]])

    st.log("Remove vtep from all leaf nodes")
    putils.exec_all(True, [[create_overlay_intf,data.d2,"vtepLeaf1", "3.3.3.2", "no", False, data.cli_type],
                          [create_overlay_intf, data.d3,"vtepLeaf2", "4.4.4.2", "no", False, data.cli_type]])

@pytest.mark.chef_evpn_mclag_regression
def test_chef_evpn_l3mclag():
    result = 0
    chef_server.role_dir = os.path.join(chef_server.path,'roles')

    for file_name,role,node_name in zip(data.role_tc_list_l3, data.role_list_mc, data.node_list_mc):
        st.log('{}, {}, {}'.format(file_name,role,node_name))
        new_file_name = modify_role_jsonfile(file_name)
        loc_lib.copy_role_file_to_chef_server(new_file_name)
        st.log('{}, {}, {}'.format(file_name, role, node_name))

        chef_evpn_obj.upload_role_chef_server(chef_server.ssh_obj, chef_server.role_dir, file_name=new_file_name)
        if file_name =="tmpl_qt_d3_tc_l3mclag.json":
            run_list ='role[{}],recipe[sonic::lag],recipe[sonic::interface]'.format(role)
        else:
            run_list ='role[{}],recipe[sonic::lag],recipe[sonic::interface],recipe[sonic::mclag]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj,node_name,run_list)

    run_chef_all_nodes()
    st.wait(data.wait)
    dict1 = {'domain_id': data.mclag_domain, 'local_ip': data.d1d2_ip, 'peer_ip': data.d2d1_ip,'session_status': 'OK'}
    dict2 = {'domain_id': data.mclag_domain, 'local_ip': data.d2d1_ip, 'peer_ip': data.d1d2_ip,'session_status': 'OK'}
    [result, exceptions] = putils.exec_parallel(True, [data.d1, data.d2], mclag.verify_domain, [dict1, dict2])
    if not all(i is None for i in exceptions):
        st.log(exceptions)
    if False in result:
        st.log('MCLAG -{} state verification FAILED'.format(data.mclag_domain))
        st.report_fail('chef_mclag_state_fail')
    if not verify_portchannel_and_member_status(data.d3, data.portChannelName,
                                                                [data.d3d1p1, data.d3d2p1],
                                                                iter_count=6, iter_delay=1, state='up'):
        st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, data.d1, "up"))
        st.report_fail('chef_mclag_state_fail')
    st.report_pass('chef_l3mclag_pass')


@pytest.mark.chef_evpn_mclag_regression
def test_chef_evpn_l2mclag():
    result = 0
    chef_server.role_dir = os.path.join(chef_server.path,'roles')

    for file_name,role,node_name in zip(data.role_tc_list_l2, data.role_list_mc, data.node_list_mc):

        new_file_name = modify_role_jsonfile(file_name)
        loc_lib.copy_role_file_to_chef_server(new_file_name)
        st.log('{}, {}, {}'.format(file_name, role, node_name))

        chef_evpn_obj.upload_role_chef_server(chef_server.ssh_obj, chef_server.role_dir, file_name=new_file_name)
        if file_name =="tmpl_qt_d3_tc_l2mclag.json":
            run_list ='role[{}],recipe[sonic::lag],recipe[sonic::vlan],recipe[sonic::interface]'.format(role)
        else:
            run_list ='role[{}],recipe[sonic::lag],recipe[sonic::vlan],recipe[sonic::interface],recipe[sonic::mclag]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj,node_name,run_list)

    run_chef_all_nodes()
    st.wait(data.wait)
    dict1 = {'domain_id': data.mclag_domain, 'local_ip': data.d1d2_ip, 'peer_ip': data.d2d1_ip, 'peer_link_inf': data.peerlinkintf,'session_status': 'OK'}
    dict2 = {'domain_id': data.mclag_domain, 'local_ip': data.d2d1_ip, 'peer_ip': data.d1d2_ip, 'peer_link_inf': data.peerlinkintf,'session_status': 'OK'}
    [result, exceptions] = putils.exec_parallel(True, [data.d1, data.d2], mclag.verify_domain, [dict1, dict2])
    if not all(i is None for i in exceptions):
        st.log(exceptions)
    if False in result:
        st.log('MCLAG -{} state verification FAILED'.format(data.mclag_domain))
        st.report_fail('chef_mclag_state_fail')
    if not verify_portchannel_and_member_status(data.d3, data.portChannelName,
                                                                [data.d3d1p1, data.d3d2p1],
                                                                iter_count=6, iter_delay=1, state='up'):
        st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, data.d1, "up"))
        st.report_fail('chef_mclag_state_fail')
    data.role_list_mc_new = [data.role_list_mc[0],data.role_list_mc[1]]
    data.node_list_mc_new = [data.node_list_mc[0], data.node_list_mc[1]]
    for role, node_name in zip(data.role_list_mc_new, data.node_list_mc_new):
        run_list = 'role[{}],recipe[sonic::vlan],recipe[sonic::lag],recipe[sonic::interface]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj, node_name, run_list, 'remove')

    for file_name,role, node_name in zip(data.role_tc_list_mclagdel, data.role_list_mc_new, data.node_list_mc_new):
        loc_lib.copy_role_file_to_chef_server(file_name)
        chef_evpn_obj.upload_role_chef_server(chef_server.ssh_obj, chef_server.role_dir, file_name=file_name)
        run_list = 'role[{}],recipe[sonic::mclag]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj, node_name, run_list)
    putils.exec_all(True, [[chef_evpn_obj.run_chef_client, data.d1],[chef_evpn_obj.run_chef_client, data.d2]])
    st.wait(data.wait)
    [result, exceptions] = putils.exec_parallel(True, [data.d1, data.d2], mclag.verify_domain, [dict1, dict2])
    if not all(i is None for i in exceptions):
        st.log(exceptions)
    if True in result:
        st.log('MCLAG -{} state verification FAILED'.format(data.mclag_domain))
        st.report_fail('chef_mclag_delete_fail')
    st.report_pass('chef_l2mclag_pass')


@pytest.mark.chef_evpn_vxlan_nvo
def test_chef_evpn_vxlan_nvo():
    for dut in [data.d2, data.d3]:
        dut_type=get_hwsku(dut)
        if "7326" in dut_type or "AS7726" in dut_type or "S5232f" in dut_type or "S5248f" in dut_type or "S5296f" in dut_type or "AS5835" in dut_type or "IX8A" in dut_type or "IX8" in dut_type:
            st.log("platform {} can be used as leaf node for EVPN testing".format(dut_type))
        else:
            st.error("expecting leaf node for EVPN testing to be \"7326\" or \"AS7726\" or \"S5232f\" or \"S5248f\" or \"S5296f\" or \"AS5835\" or \"IX8A\" or \"IX8\"")
            st.report_env_fail("platform_check_fail",dut)
    chef_server.role_dir = os.path.join(chef_server.path,'roles')
    for file_name,role,node_name in zip(data.role_tc_list_evpn, data.role_list_mc, data.node_list_mc):

        new_file_name = modify_role_jsonfile(file_name)
        loc_lib.copy_role_file_to_chef_server(new_file_name)
        st.log('{}, {}, {}'.format(file_name, role, node_name))
        chef_evpn_obj.upload_role_chef_server(chef_server.ssh_obj, chef_server.role_dir, file_name=new_file_name)
        run_list ='role[{}],recipe[sonic::vlan],recipe[sonic::vxlan],recipe[sonic::interface],recipe[sonic::evpn_nvo],recipe[sonic::loopback],recipe[sonic::router],recipe[sonic::bgprouter]'.format(role)
        chef_evpn_obj.update_node_run_list(chef_server.ssh_obj,node_name,run_list)
    run_chef_all_nodes()
    st.wait(data.wait)
    if not verify_vxlan_tunnel_status(data.d2, '3.3.3.2', ['4.4.4.2'], ['oper_up']):
        st.report_fail('test_case_failed')
    if not verify_vxlan_tunnel_status(data.d3, '4.4.4.2',['3.3.3.2'],['oper_up']):
        st.report_fail('test_case_failed')
    st.report_pass('test_case_passed')


def run_chef_all_nodes():
    f1 = lambda x: chef_evpn_obj.run_chef_client(data.d1)
    f2 = lambda x: chef_evpn_obj.run_chef_client(data.d2)
    f3 = lambda x: chef_evpn_obj.run_chef_client(data.d3)
    putils.exec_all(True, [[f1, 1], [f2, 1], [f3, 1]])


def modify_role_jsonfile(file_name):
    new_file_name = re.sub(r'tmpl', 'new', file_name)
    file_name = os.path.join(data.role_path, file_name)
    fin = open(os.path.join(data.role_path, file_name), 'r')
    fout = open(os.path.join(data.role_path, new_file_name), 'w')
    file_data = fin.readlines()
    for line in file_data:

        for var, value in zip(
                ['D1D2P1', 'D2D1P1', 'D1D2P2', 'D2D1P2', 'D1D3P1', 'D3D1P1', 'D2D3P1', 'D3D2P1', 'D3D1P2'],
                [data.d1_d2_intf_1, data.d2_d1_intf_1, data.d1_d2_intf_2, data.d2_d1_intf_2, data.d1_d3_intf_1,
                 data.d3_d1_intf_1, data.d2_d3_intf_1, data.d3_d2_intf_1, data.d3_d1_intf_2]):

            if var in line:
                line = re.sub(r'{}'.format(var), value, line)

        fout.write(line)

    fin.close()
    fout.close()
    return new_file_name

