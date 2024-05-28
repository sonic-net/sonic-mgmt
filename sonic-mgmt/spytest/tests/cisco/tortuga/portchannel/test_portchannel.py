import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import tortuga_common_utils as common_obj

# Global variables
data_glob = SpyTestDict()
data_glob.portchannel_name = "PortChannel01"
data_glob.pc_ip_D1D3 = "100.10.1.1/24"
data_glob.pc_ip_D3D1 = "100.10.1.2/24"
data_glob.pc_ipv6_D1D3 = "100:10:1::1/120"
data_glob.pc_ipv6_D3D1 = "100:10:1::2/120"

@pytest.fixture(scope='function', autouse=True)
def portchannel_func_hooks(request):
    global vars
    global updated_path
    vars = st.ensure_min_topology("D1D3:2", "D1D4:2", "D3T1:2", "D4T1:2")
    data_glob.function_unconfig = False
    data_glob.spine0 = vars.D1
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.members_dut1 = [vars.D1D3P1, vars.D1D3P2]
    data_glob.members_dut2 = [vars.D3D1P1, vars.D3D1P2]
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)
    yield
    function_unconfig()
    
def function_unconfig():
    if not data_glob.function_unconfig:
        data_glob.function_unconfig = True
        st.log('Function config Cleanup')
        common_obj.remove_temp_config(updated_path)
        vlan_obj.clear_vlan_configuration([data_glob.spine0, data_glob.leaf0, data_glob.leaf1])
        dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
        for dut in dut_list:
            if portchannel_obj.get_portchannel(dut, data_glob.portchannel_name):
                members = portchannel_obj.get_portchannel_members(dut, data_glob.portchannel_name)
                for member in members:
                    portchannel_obj.delete_portchannel_member(dut, data_glob.portchannel_name, member)
                portchannel_obj.delete_portchannel(dut, data_glob.portchannel_name)

## L3 Stream Config
data_l3 = SpyTestDict()
data_l3.my_dut_list = None
data_l3.t1d3_ip_gateway = "10.1.1.1"
data_l3.t1d3_ipv6_gateway = "10:1:1::1"
data_l3.t1d4_ip_gateway = "11.1.1.1"
data_l3.t1d4_ipv6_gateway = "11:1:1::1"

data_l3.d3t1_ip_addr = "10.1.1.1"
data_l3.t1d3_ip_addr = "10.1.1.2"
data_l3.d3t1_ipv6_addr = "10:1:1::1"
data_l3.t1d3_ipv6_addr = "10:1:1::2"
data_l3.t1d3_mac_addr = "00:0a:01:00:11:01"

data_l3.d4t1_ip_addr = "11.1.1.1"
data_l3.t1d4_ip_addr = "11.1.1.2"
data_l3.d4t1_ipv6_addr = "11:1:1::1"
data_l3.t1d4_ipv6_addr = "11:1:1::2"
data_l3.t1d4_mac_addr = "00:0a:01:00:12:01"

data_l3.transmit_mode = 'single_burst'
data_l3.pkts_per_burst = "500"
data_l3.mask = "24"
data_l3.tgen_stats_threshold = 20
data_l3.tgen_rate_pps = '1000'
data_l3.tgen_l3_len = '500'
data_l3.traffic_run_time = 20
## L3 Stream Config

####################
#                  #
#    D1 = spine0      #
#    D3 = leaf0      #
#    D4 = leaf1      #
#                  #
####################

######################################################################
#                                                                    #
#  spt --- leaf0 ---(PortChannel)--- spine0 --- leaf1 --- spt               #
#                                                                    #
######################################################################

CONFIGS_FILE = 'portchannel_l3_cfg.yaml'

@pytest.fixture()
def setup_teardown_portchannel():
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)
            common_obj.config_static(node, 'sonic', True, updated_path)
            common_obj.config_static(node, 'bgp', True, updated_path)

    count = 5    
    st.show(data_glob.spine0, 'sudo ping -c {} {} -q'.format(count, '12.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(data_glob.spine0, 'sudo ping -c {} {} -q'.format(count, '11.1.1.1'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_portchannel'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', False, updated_path)
            common_obj.config_static(node, 'sonic', False, updated_path)

def test_portchannel_v4_add_del():

    #add PortChannel01 and add ipv4 address to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [], add=True)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], 'down', add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], 'down', add=True)

    #Test PortChannel01 ipv4 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, 'ipv4', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, 'ipv4', add=True)
    
    #remove ipv4 address from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [], add=False)
    
    #Test PortChannel01 ipv4 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv4', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv4', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    st.report_pass('test_case_passed')
   
def test_portchannel_v6_add_del():
    
    #add PortChannel01 and add ipv6 address to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D1D3, [], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D3D1, [], add=True)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], 'down', add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], 'down', add=True)

    #Test PortChannel01 ipv6 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ipv6_D1D3, 'ipv6', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ipv6_D3D1, 'ipv6', add=True)
    
    #remove ipv6 address from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D1D3, [], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D3D1, [], add=False)
    
    #Test PortChannel01 ipv6 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv6', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv6', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    st.report_pass('test_case_passed')

def test_portchannel_dual_stack_add_del():

    #add PortChannel01 and add dual stack to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [], add=True)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], 'down', add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], 'down', add=True)

    #Test PortChannel01 ipv4 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, 'ipv4', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, 'ipv4', add=True)
    
    #Test PortChannel01 ipv6 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ipv6_D1D3, 'ipv6', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ipv6_D3D1, 'ipv6', add=True)
    
    #remove dual stack from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [], add=False)
    
    #Test PortChannel01 ipv4 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv4', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv4', add=False)
    
    #Test PortChannel01 ipv6 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv6', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv6', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)
    
    st.report_pass('test_case_passed')

def test_portchannel_member_v4_add_del(setup_teardown_portchannel):
    
    #add PortChannel01, add multiple member interfaces and add ipv4 address to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [data_glob.members_dut1[0],data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [data_glob.members_dut2[0],data_glob.members_dut2[1]], add=True)
    st.wait(60)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=True)

    #Test PortChannel01 ipv4 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, 'ipv4', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, 'ipv4', add=True)

    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv4 traffic")
    common_obj.traffic_cleanup(handles)

    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)

    #Test portchannel member interfaces 
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)
    
    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic after one member removal Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv4 traffic after one member removal")
    common_obj.traffic_cleanup(handles)

    #remove ipv4 address from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [data_glob.members_dut2[0]], add=False)
    
    #Test PortChannel01 ipv4 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv4', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv4', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    st.report_pass('test_case_passed')

# Failure Tc, Jira : MIGSOFTWAR-14793
def skip_test_portchannel_member_v6_add_del(setup_teardown_portchannel):
    
    #add PortChannel01, add multiple member interfaces, add ipv6 address to PortChannel01 and ipv4 address for BGP 
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0],data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0],data_glob.members_dut2[1]], add=True)
    st.wait(60)
    
    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=True)

    #Test PortChannel01 ipv6 address addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ipv6_D1D3, 'ipv6', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ipv6_D3D1, 'ipv6', add=True)
    
    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', False)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv6 traffic")
    common_obj.traffic_cleanup(handles)
    
    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)

    #Test portchannel member interfaces 
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)
    
    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', False)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic after one member removal Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv6 traffic after one member removal")
    common_obj.traffic_cleanup(handles)

    #remove dual stack from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0]], add=False)
    
    #Test PortChannel01 ipv6 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv6', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv6', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)
    
    st.report_pass('test_case_passed')

# Failure Tc, Jira : MIGSOFTWAR-14793
def skip_test_portchannel_member_v4_v6_add_del(setup_teardown_portchannel):
    
    #add PortChannel01, add multiple member interfaces and add dual stack to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0],data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0],data_glob.members_dut2[1]], add=True)
    st.wait(60)
    
    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=True)

    #Test PortChannel01 dual stack addition
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, 'ipv4', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, 'ipv4', add=True)
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ipv6_D1D3, 'ipv6', add=True)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ipv6_D3D1, 'ipv6', add=True)

    #test ipv4 traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv4 traffic")
    common_obj.traffic_cleanup(handles)
        
    #test ipv6 traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', False)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv6 traffic")
    common_obj.traffic_cleanup(handles)

    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)

    #Test portchannel member interfaces 
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)
    
    #test ipv4 traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic after one member removal Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv4 traffic after one member removal")
    common_obj.traffic_cleanup(handles)
        
    #test ipv6 traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', False)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic after one member removal Passed")
    else:
        st.report_fail('failed_traffic_verification', "ipv6 traffic after one member removal")
    common_obj.traffic_cleanup(handles)

    #remove dual stack from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0]], add=False)
    
    #Test PortChannel01 ipv4 address removal
    common_obj.check_portchannel_ip_address(data_glob.spine0, data_glob.portchannel_name, '', 'ipv4', add=False)
    common_obj.check_portchannel_ip_address(data_glob.leaf0, data_glob.portchannel_name, '', 'ipv4', add=False)
    
    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    st.report_pass('test_case_passed')
    
