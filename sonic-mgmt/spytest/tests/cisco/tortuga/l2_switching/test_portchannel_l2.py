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
data_vid_10.tgen_stats_threshold = 100
data_vid_10.tgen_rate_pps = '1000'
data_vid_10.tgen_l3_len = '500'
data_vid_10.traffic_run_time = 20
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
data_vid_20.tgen_stats_threshold = 100
data_vid_20.tgen_rate_pps = '1000'
data_vid_20.tgen_l3_len = '500'
data_vid_20.traffic_run_time = 20
##L2 stream config

####################
#                  #
#    D1 = spine0   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

######################################################################
#                                                                    #
#  spt --- leaf0 ---(PortChannel)--- spine0 --- leaf1 --- spt        #
#                                                                    #
######################################################################

CONFIGS_FILE = 'portchannel_l2_cfg.yaml'

@pytest.fixture()
def setup_teardown_portchannel_l2():
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', True, updated_path)

    yield 'setup_teardown_portchannel_l2'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)

def test_portchannel_l2(setup_teardown_portchannel_l2):
    
    traffic_types = ['unicast', 'multicast', 'broadcast']
    
    #Test BUM traffic for VLAN 10
    for traffic_type in traffic_types:
        handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', traffic_type, True)
        common_obj.traffic_start(handles, data_vid_10, data_vid_10)
        common_obj.traffic_stop(handles)
        if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
            st.log("Traffic verification for L2 {} Passed".format(traffic_type))
        else:
            st.report_fail('failed_traffic_verification', "for L2 {} ".format(traffic_type))
        common_obj.traffic_cleanup(handles)
        
    #Test trunk traffic for Vlan 20
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_20, 'T1D3P2', 'T1D4P2', 'unicast', True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P2', data_vid_20, data_vid_20):
        st.log("Traffic verification for L2 {} Passed".format('unicast'))
    else:
        st.report_fail('failed_traffic_verification', "for L2 {} ".format('unicast'))
    common_obj.traffic_cleanup(handles)
    
    st.report_pass('test_case_passed')

def test_portchannel_l2_member_shut_unshut(setup_teardown_portchannel_l2):
    
    #config traffic
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', 'unicast', True, verify_ping=False)

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

    st.report_pass('test_case_passed')

def test_portchannel_l2_member_del_add(setup_teardown_portchannel_l2):
    
    #config traffic
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', 'unicast', True, verify_ping=False)

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

    st.report_pass('test_case_passed')

    
