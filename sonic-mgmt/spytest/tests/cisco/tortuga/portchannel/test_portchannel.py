import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.system.interface as intf_obj
import tortuga_common_utils as common_obj
import apis.routing.ip as ip_obj

# Global variables
data_glob = SpyTestDict()
data_glob.portchannel_name = "PortChannel01"
data_glob.pc_ip_D1D3 = "100.10.1.1/24"
data_glob.pc_ip_D3D1 = "100.10.1.2/24"
data_glob.pc_ipv6_D1D3 = "100:10:1::1/120"
data_glob.pc_ipv6_D3D1 = "100:10:1::2/120"
data_glob.pre_config = False   #This var allows yaml pre configs

@pytest.fixture(scope='function', autouse=True)
def bvi_func_hooks(request):
    data_glob.function_unconfig = False #This var allows cleanup of pre configs and remaining configs in case of TC failures
    yield
    function_unconfig()

def function_unconfig():
    if not data_glob.function_unconfig:
        data_glob.function_unconfig = True
        data_glob.pre_config = False
        st.log('Function config Cleanup')
        dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
        ip_obj.clear_ip_configuration(dut_list, family='all')
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
data_l3.traffic_run_time = 5
## L3 Stream Config

####################
#                  #
#    D1 = spine0   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

######################################################################
#                                                                    #
#  Tgen --- leaf0 ---(PortChannel)--- spine0 --- leaf1 --- Tgen      #
#                                                                    #
######################################################################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global updated_path
    global nodes
    
    st.ensure_min_topology("D1D3:2", "D1D4:2", "D3T1:2", "D4T1:2")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    data_glob.spine0 = vars.D1
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.members_dut1 = [vars.D1D3P1, vars.D1D3P2]
    data_glob.members_dut2 = [vars.D3D1P1, vars.D3D1P2]
    CONFIGS_FILE = 'portchannel_l3_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)
    
    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)

@pytest.fixture()
def setup_teardown_portchannel(setup_teardown_basic):

    if not data_glob.pre_config:
        with open(updated_path) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                common_obj.config_static(node, 'sonic', True, updated_path)
                common_obj.config_static(node, 'bgp', True, updated_path)

        count = 5
        
        data_glob.pre_config = True

    yield 'setup_teardown_portchannel'
    
    if data_glob.function_unconfig:
        return

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

    data_glob.function_unconfig = True
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

    data_glob.function_unconfig = True
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
    
    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_portchannel_member_v4_add_del(setup_teardown_portchannel):

    #add PortChannel01, add multiple member interfaces and add ipv4 address to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [data_glob.members_dut1[0],data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [data_glob.members_dut2[0],data_glob.members_dut2[1]], add=True)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=True)

    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "ipv4 traffic")

    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)

    #Test portchannel member interfaces
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)

    #test traffic
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv4 traffic after one member removal Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "ipv4 traffic after one member removal")

    #remove ipv4 address from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, '', [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, '', [data_glob.members_dut2[0]], add=False)

    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_portchannel_member_v6_add_del(setup_teardown_portchannel):

    #add PortChannel01, add multiple member interfaces and add ipv6 address to PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0],data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0],data_glob.members_dut2[1]], add=True)

    #Test PortChannel01 creation
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=True)

    #test traffic
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', False)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "ipv6 traffic")

    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)

    #Test portchannel member interfaces
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)

    #test traffic
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        st.log("Traffic check for ipv6 traffic after one member removal Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "ipv6 traffic after one member removal")

    #remove ipv6 address from PortChannel01 and del PortChannel01
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0]], add=False)

    #Test PortChannel01 deletion
    common_obj.check_portchannel_add_del(data_glob.spine0, data_glob.portchannel_name, [], add=False)
    common_obj.check_portchannel_add_del(data_glob.leaf0, data_glob.portchannel_name, [], add=False)

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')


#TC Description:
#Create PortChannel between Spine0 and Leaf0 with min-links configured as 2
#Initially the PortChannel is created with 2 members and is expected to be UP
#Verify ipv4 traffic with Base Config
#Verify PortChannel State (expected Down) and traffic (expected Fail) after member interface shut
#Verify PortChannel State (expected Up) and traffic (expected Pass) after member interface unshut
def test_portchannel_minlink(setup_teardown_portchannel):

    #Create PortChannel between Spine0 and Leaf0 with min_links = 2
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0], data_glob.members_dut1[1]], min_link = '2', add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0], data_glob.members_dut2[1]], min_link = '2', add=True)

    #test ipv4 traffic with base config
    handles = common_obj.traffic_test_config(data_l3, data_l3, 'T1D3P1', 'T1D4P1', 'unicast', True)
    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if not common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed Traffic verfication', "ipv4 traffic")

    #shut one of member link of PortChannel
    intf_obj.interface_shutdown(data_glob.spine0, [data_glob.members_dut1[0]])

    #Port channel status check
    if not portchannel_obj.verify_portchannel_state(data_glob.spine0, data_glob.portchannel_name, state="down"):
        st.report_fail('msg', "PortChannel in Up state after member shutdown")

    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed Traffic verfication', "ipv4 traffic after shutting of one member")

    #unshut member link
    intf_obj.interface_noshutdown(data_glob.spine0, [data_glob.members_dut1[0]])

    #Waiting additional time for Port state to transition back and for BGP to converge
    st.wait(10)

    #Port channel status check
    if not portchannel_obj.verify_portchannel_state(data_glob.spine0, data_glob.portchannel_name, state="up"):
        st.report_fail("PortChannel in Down state after member unshut")

    common_obj.traffic_start(handles, data_l3, data_l3)
    common_obj.traffic_stop(handles, mode='burst')

    if not common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_l3, data_l3):
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "ipv4 traffic after one member Unshut")

    #Delete PortChannel between Spine0 and Leaf0 with min_links = 2
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, data_glob.pc_ip_D1D3, data_glob.pc_ipv6_D1D3, [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, data_glob.pc_ip_D3D1, data_glob.pc_ipv6_D3D1, [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=False)

    #This is the last TC with current preconfig, setting function_unconfig to False to allow cleanup
    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')