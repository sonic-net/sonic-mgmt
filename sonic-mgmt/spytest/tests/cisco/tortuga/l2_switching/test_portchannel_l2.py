import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as intf_obj
import tortuga_common_utils as common_obj

#SIM File : tortuga_spytest_5D_linux_stc.yaml

# Global variables
data_glob = SpyTestDict()
data_glob.portchannel_name = "PortChannel01"
data_glob.vlan = ['10','20']
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
        vlan_obj.clear_vlan_configuration(dut_list)
        for dut in dut_list:
            if portchannel_obj.get_portchannel(dut, data_glob.portchannel_name):
                members = portchannel_obj.get_portchannel_members(dut, data_glob.portchannel_name)
                for member in members:
                    portchannel_obj.delete_portchannel_member(dut, data_glob.portchannel_name, member)
                portchannel_obj.delete_portchannel(dut, data_glob.portchannel_name)

##Vlan id 10 stream config
data_vid_10 = SpyTestDict()
data_vid_10.my_dut_list = None
data_vid_10.t1d3_ip_gateway = "10.0.1.2"
data_vid_10.t1d4_ip_gateway = "10.0.1.1"

data_vid_10.t1d3_ip_addr = "10.0.1.1"
data_vid_10.t1d3_mac_addr = "00:0a:01:00:11:01"

data_vid_10.t1d4_ip_addr = "10.0.1.2"
data_vid_10.t1d4_mac_addr = "00:0a:01:00:12:01"

data_vid_10.pkts_per_burst = '500'
data_vid_10.transmit_mode = 'continuous'
data_vid_10.tgen_stats_threshold = 50
data_vid_10.tgen_rate_pps = '500'
data_vid_10.tgen_l3_len = '500'
data_vid_10.traffic_run_time = 5
##L2 stream config

##Vlan id 20 stream config
data_vid_20 = SpyTestDict()
data_vid_20.my_dut_list = None
data_vid_20.t1d3_ip_gateway = "10.0.2.2"
data_vid_20.t1d4_ip_gateway = "10.0.2.1"

data_vid_20.t1d3_ip_addr = "10.0.2.1"
data_vid_20.t1d3_mac_addr = "00:0a:01:00:13:01"

data_vid_20.t1d4_ip_addr = "10.0.2.2"
data_vid_20.t1d4_mac_addr = "00:0a:01:00:14:01"

data_vid_20.pkts_per_burst = '500'
data_vid_20.transmit_mode = 'continuous'
data_vid_20.tgen_stats_threshold = 50
data_vid_20.tgen_rate_pps = '500'
data_vid_20.tgen_l3_len = '500'
data_vid_20.traffic_run_time = 5
##L2 stream config

####################
#                  #
#    D1 = spine0   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global updated_path
    
    st.ensure_min_topology("D1D3:2", "D1D4:2", "D3T1:2", "D4T1:2")
    vars = st.get_testbed_vars()
    
    data_glob.spine0 = vars.D1
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.members_dut1 = [vars.D1D3P1, vars.D1D3P2]
    data_glob.members_dut2 = [vars.D3D1P1, vars.D3D1P2]
    
    #Set mac address for intra vlan traffic
    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr
    data_vid_20.t1d3_dest_mac_addr = data_vid_20.t1d4_mac_addr
    data_vid_20.t1d4_dest_mac_addr = data_vid_20.t1d3_mac_addr
    
    CONFIGS_FILE = 'portchannel_l2_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)
    
    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)

#Topology
#
# |--------------------|  |---------------------|  |-------------------|
# |      (10.0.1.1) P1-|--|-P1--Vlan10--|       |  |                   |
# |                    |  |             |  |-P1-|  |-P1-|              |
# |                    |  |          D3 |--| PC |--| PC |-|  Vlan10    |
# |                    |  |             |  |-P2-|  |-P2-| |    +       |
# |      (10.0.2.1) P2-|--|-P2--Vlan20--|       |  |      |  Vlan20    |
# |                    |  |---------------------|  |      |            |
# |                    |                           |      |            |
# |         T1         |                           |      |   D1       |
# |                    |                           |      |            |
# |                    |  |---------------------|  |      |            |
# |      (10.0.2.2) P2-|--|-P2-----Vlan20--|    |  |      |            |
# |                    |  |                |    |  |      |            |
# |                    |  |          D4    |-P1-|--|-P1---|            |
# |                    |  |                |    |  |                   |
# |      (10.0.1.2) P1-|--|-P1-----Vlan10--|    |  |                   |
# |--------------------|  |---------------------|  |-------------------|
#
@pytest.fixture()
def setup_teardown_portchannel_l2(setup_teardown_basic):

    if not data_glob.pre_config:
        with open(updated_path) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                common_obj.config_static(node, 'sonic', True, updated_path)
        data_glob.pre_config = True

    yield 'setup_teardown_portchannel_l2'

    if data_glob.function_unconfig:
        return
    
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)

#Topology
#
# |--------------------|  |---------------------|  |-------------------|
# |      (10.0.1.1) P1-|--|-P1--Vlan10          |  |                   |
# |                    |  |                     |  |                   |
# |                    |  |          D3         |  |                   |
# |                    |  |                     |  |                   |
# |      (10.0.2.1) P2-|--|-P2--Vlan20          |  |                   |
# |                    |  |---------------------|  |                   |
# |                    |                           |                   |
# |         T1         |                           |          D1       |
# |                    |                           |                   |
# |                    |  |---------------------|  |                   |
# |      (10.0.2.2) P2-|--|-P2-----Vlan20--|    |  |                   |
# |                    |  |                |    |  |                   |
# |                    |  |          D4    |-P1-|--|-P1--Vlan 10,20    |
# |                    |  |                |    |  |                   |
# |      (10.0.1.2) P1-|--|-P1-----Vlan10--|    |  |                   |
# |--------------------|  |---------------------|  |-------------------|
@pytest.fixture()
def setup_teardown_portchannel_l2_without_pc(setup_teardown_basic):

    if not data_glob.pre_config:
        with open(updated_path) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                common_obj.config_static(node, 'sonic_without_pc', True, updated_path)
        data_glob.pre_config = True

    yield 'setup_teardown_portchannel_l2'

    if data_glob.function_unconfig:
        return
    
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_without_pc', False, updated_path)
            
#Start of TCs with PortChannel PreConfig

def test_portchannel_l2(setup_teardown_portchannel_l2):
    
    traffic_types = ['unicast', 'multicast', 'broadcast']
    
    #Test BUM traffic for VLAN 10
    for traffic_type in traffic_types:
        handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', traffic_type, True, is_l2=True)
        common_obj.traffic_start(handles, data_vid_10, data_vid_10)
        common_obj.traffic_stop(handles)
        if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
            st.log("Traffic verification for L2 {} Passed".format(traffic_type))
        else:
            st.report_fail('failed_traffic_verification', "for L2 {} ".format(traffic_type))
        common_obj.traffic_cleanup(handles)
        
    #Test trunk traffic for Vlan 20
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_20, 'T1D3P2', 'T1D4P2', 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P2', data_vid_20, data_vid_20):
        st.log("Traffic verification for L2 {} Passed".format('unicast'))
    else:
        st.report_fail('failed_traffic_verification', "for L2 {} ".format('unicast'))
    common_obj.traffic_cleanup(handles)
    
    #Currently subsequent TCs are skipped because of failures, therefore initiating cleanup
    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')

@pytest.mark.skip(reason = "Traffic Loss during PC member shut carrying traffic, Jira : MIGSOFTWAR-14795")
def test_portchannel_l2_member_shut_unshut(setup_teardown_portchannel_l2):
    
    #config traffic
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', 'unicast', True, verify_ping=False, is_l2=True)

    #start traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
 
    #shut one of member link
    intf_obj.interface_shutdown(data_glob.spine0, [data_glob.members_dut1[0]])
    intf_obj.interface_shutdown(data_glob.leaf0, [data_glob.members_dut2[0]])

    #stop traffic
    common_obj.traffic_stop(handles)

    #check traffic
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification with one member shut down Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "one member shut down case")

    #start traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    
    #unshut member link
    intf_obj.interface_noshutdown(data_glob.spine0, [data_glob.members_dut1[0]])
    intf_obj.interface_noshutdown(data_glob.leaf0, [data_glob.members_dut2[0]])
   
    #stop traffic
    common_obj.traffic_stop(handles)

    #check traffic
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification with member unshut back Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "member unshut back case")

    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')

@pytest.mark.skip(reason = "Traffic Loss during PC member remove carrying traffic, Jira : MIGSOFTWAR-14796")
def test_portchannel_l2_member_del_add(setup_teardown_portchannel_l2):
    
    #config traffic
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', 'unicast', True, verify_ping=False, is_l2=True)

    #start traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
 
    #remove one of member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=False)

    #stop traffic
    common_obj.traffic_stop(handles)

    #check traffic
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification with one member removed Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "one member removed case")
    
    #start traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    
    #add back member link
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=True)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=True)
   
    #stop traffic
    common_obj.traffic_stop(handles)

    #check traffic
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification with member added back Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "member added back case")

    #This is the last TC with current preconfig, setting function_unconfig to False to allow cleanup
    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')

#End of TCs with PortChannel PreConfig

#Start of TCs without PortChannel PreConfig

#TC Description:
#Create PortChannel between Spine0 and Leaf0 as Trunk (Vlan 10,20) and with min-links configured as 2
#Initially the PortChannel is created with 2 members and is expected to be UP
#Verify ipv4 traffic with Base Config
#Verify PortChannel State (expected Down) and traffic (expected Fail) after member interface shut
#Verify PortChannel State (expected Up) and traffic (expected Pass) after member interface unshut
@pytest.mark.skip(reason = "Traffic Forwarding even with LACP Down, Jira : MIGSOFTWAR-21661")
def test_min_link_portchannel(setup_teardown_portchannel_l2_without_pc):

    #Create PortChannel between Spine0 and Leaf0 with min_links = 2
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', '', [data_glob.members_dut1[0], data_glob.members_dut1[1]], min_link = '2', add=True)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', '', [data_glob.members_dut2[0], data_glob.members_dut2[1]], min_link = '2', add=True)

    #Add PortChannel to Vlan 10 and 20 on both Spine0 and Leaf0
    for vlan in data_glob.vlan:
        vlan_obj.add_vlan_member(data_glob.spine0, vlan, [data_glob.portchannel_name], tagging_mode=True)
        vlan_obj.add_vlan_member(data_glob.leaf0, vlan, [data_glob.portchannel_name], tagging_mode=True)

    #Verify Traffic with Base Config
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('Failed_traffic_verification', "for L2")

    #shut one of member link of PortChannel
    intf_obj.interface_shutdown(data_glob.spine0, [data_glob.members_dut1[0]])
    intf_obj.interface_shutdown(data_glob.leaf0, [data_glob.members_dut2[0]])
    
    #Port channel status check
    if not portchannel_obj.verify_portchannel_state(data_glob.spine0, data_glob.portchannel_name, state="down"):
        st.report_fail('msg', "PortChannel in Up state after member shutdown")

    #Verify traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if not common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 after shutting of one member Passed")
    else:
        st.report_fail('failed Traffic verfication', "L2 after shutting of one member")

    #unshut back member link
    intf_obj.interface_noshutdown(data_glob.spine0, [data_glob.members_dut1[0]])
    intf_obj.interface_noshutdown(data_glob.leaf0, [data_glob.members_dut2[0]])
    st.wait(5)
    
    #Port channel status check
    if not portchannel_obj.verify_portchannel_state(data_glob.spine0, data_glob.portchannel_name, state="up"):
        st.report_fail('msg', "PortChannel in Down state after member unshut")

    #Verify traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 after unshut of one member Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('Failed_traffic_verification', "L2 after member unshut")
        
    #Add PortChannel to Vlan 10 and 20 on both Spine0 and Leaf0
    for vlan in data_glob.vlan:
        vlan_obj.delete_vlan_member(data_glob.spine0, vlan, [data_glob.portchannel_name], tagging_mode=True)
        vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, [data_glob.portchannel_name], tagging_mode=True)
        
    #Delete PortChannel between Spine0 and Leaf0 with min_links = 2
    common_obj.portchannel_create_delete(data_glob.spine0, data_glob.portchannel_name, '', '', [data_glob.members_dut1[0], data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_create_delete(data_glob.leaf0, data_glob.portchannel_name, '', '', [data_glob.members_dut2[0], data_glob.members_dut2[1]], add=False)

    #This is the last TC with current preconfig, setting function_unconfig to False to allow cleanup
    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')

#End of TCs without PortChannel PreConfig

