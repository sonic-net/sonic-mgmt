import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as portchannel_obj
import apis.switching.mac as mac_obj
import tortuga_common_utils as common_obj

data_glob = SpyTestDict()
data_glob.portchannel_name = "PortChannel01"
data_glob.vlan = ['10','20']
data_glob.vlan_intf = ['Vlan10','Vlan20']
data_glob.vlan_ip = ['10.0.1.10/24','10.0.2.20/24']
data_glob.vlan_ipv6 = ['10:0:1::10/64', '10:0:2::20/64']
data_glob.mac_aging_time_orig = 600
data_glob.mac_aging_time_new = 120

@pytest.fixture(scope='function', autouse=True)
def bvi_func_hooks(request):
    data_glob.function_unconfig = False
    yield
    function_unconfig()
    
def function_unconfig():
    if not data_glob.function_unconfig:
        data_glob.function_unconfig = True
        st.log('Function config Cleanup')
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
data_l3.t1d3_mac_addr = "00:0A:01:00:11:01"

data_l3.d4t1_ip_addr = "11.1.1.1"
data_l3.t1d4_ip_addr = "11.1.1.2"
data_l3.d4t1_ipv6_addr = "11:1:1::1"
data_l3.t1d4_ipv6_addr = "11:1:1::2"
data_l3.t1d4_mac_addr = "00:0A:02:00:12:01"

data_l3.transmit_mode = 'single_burst'
data_l3.pkts_per_burst = "500"
data_l3.tgen_stats_threshold = 20
data_l3.tgen_rate_pps = '1000'
data_l3.tgen_l3_len = '500'
data_l3.traffic_run_time = 20
##L3 Stream Config

##Vlan id 10 stream config
data_vid_10 = SpyTestDict()
data_vid_10.my_dut_list = None
data_vid_10.vlan = "10"
data_vid_10.t1d3_ip_gateway = "10.0.1.10"
data_vid_10.t1d3_ipv6_gateway = "10:0:1::10"
data_vid_10.t1d4_ip_gateway = "10.0.1.10"
data_vid_10.t1d4_ipv6_gateway = "10:0:1::10"

data_vid_10.t1d3_ip_addr = "10.0.1.1"
data_vid_10.t1d3_ipv6_addr = "10:0:1::1"
data_vid_10.t1d3_mac_addr = "00:0A:03:00:11:01"
data_vid_10.t1d3_mac_addr_mac_move = "00:0A:03:11:11:11"

data_vid_10.t1d4_ip_addr = "10.0.1.2"
data_vid_10.t1d4_ipv6_addr = "10:0:1::2"
data_vid_10.t1d4_mac_addr = "00:0A:04:00:12:01"

data_vid_10.transmit_mode = 'single_burst'
data_vid_10.pkts_per_burst = "500"
data_vid_10.tgen_stats_threshold = 20
data_vid_10.tgen_rate_pps = '1000'
data_vid_10.tgen_l3_len = '500'
data_vid_10.traffic_run_time = 20
##L2 stream config

##Vlan id 20 stream config
data_vid_20 = SpyTestDict()
data_vid_20.my_dut_list = None
data_vid_20.vlan = "20"
data_vid_20.t1d3_ip_gateway = "10.0.2.20"
data_vid_20.t1d3_ipv6_gateway = "10:0:2::20"
data_vid_20.t1d4_ip_gateway = "10.0.2.20"
data_vid_20.t1d4_ipv6_gateway = "10:0:2::20"

data_vid_20.t1d3_ip_addr = "10.0.2.1"
data_vid_20.t1d3_ipv6_addr = "10:0:2::1"
data_vid_20.t1d3_mac_addr = "00:0A:05:00:11:01"
data_vid_20.t1d3_mac_addr_mac_move = "00:0A:05:11:11:11"

data_vid_20.t1d4_ip_addr = "10.0.2.2"
data_vid_20.t1d4_ipv6_addr = "10:0:2::2"
data_vid_20.t1d4_mac_addr = "00:0A:06:00:12:01"

data_vid_20.transmit_mode = 'single_burst'
data_vid_20.pkts_per_burst = "500"
data_vid_20.tgen_stats_threshold = 20
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
#  spt --- leaf0(BVI) ---(PortChannel)--- spine0 --- leaf1 --- spt   #
#                                                                    #
######################################################################
   
@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global updated_path
    global nodes
    
    st.ensure_min_topology("D1D3:4", "D1D4:4", "D3T1:2", "D4T1:2")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    data_glob.spine0 = vars.D1
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.members_dut1 = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4]
    data_glob.members_dut2 = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3, vars.D3D1P4]
    CONFIGS_FILE = 'bvi_basic_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)
    
    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)
    
@pytest.fixture(scope='module', autouse=True)
def setup_teardown_bgp(setup_teardown_basic):
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', True, updated_path)

    yield 'setup_teardown_bgp'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', False, updated_path)

# Using Physical intfs for vlan members
# Multiple Vlans
@pytest.fixture()
def setup_teardown_bvi(setup_teardown_basic):
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', True, updated_path)
            
    #Set mac address for inter vlan traffic
    data_vid_10.t1d3_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[0])
    data_vid_10.t1d4_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[0])
    data_vid_20.t1d3_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[1])
    data_vid_20.t1d4_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[1])


    yield 'setup_teardown_bvi'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)
       
# Using Portchannel between spine0 and leaf0 as vlan 10 member
# Multiple Vlans
@pytest.fixture()
def setup_teardown_bvi_pc(setup_teardown_basic):
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_pc', True, updated_path)
            
    #Set mac address for inter vlan traffic
    data_vid_10.t1d3_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[0])
    data_vid_10.t1d4_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[0])
    data_vid_20.t1d3_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[1])
    data_vid_20.t1d4_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[1])

    yield 'setup_teardown_bvi_pc'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_pc', False, updated_path)
            
# Using Physical intfs for vlan members
# Single Vlan, L2 + L3 
@pytest.fixture()
def setup_teardown_bvi_bd(setup_teardown_bgp):
    #Set mac address for intra vlan traffic
    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr
    
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_bd', True, updated_path)

    yield 'setup_teardown_bvi_bd'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_bd', False, updated_path)
            
# Using Portchannel between spine0 and leaf0 as vlan 10 member
# Single Vlan, L2 + L3 
@pytest.fixture()
def setup_teardown_bvi_bd_pc(setup_teardown_bgp):
    #Set mac address for intra vlan traffic
    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr
    
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_bd_pc', True, updated_path)

    yield 'setup_teardown_bvi_bd_pc'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic_bd_pc', False, updated_path)

#Testcases
def test_bvi_ipv4(setup_teardown_bvi_bd):
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic")
    
    #leaf0 (10.0.1.1) -----> leaf1(11.1.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',True)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3")
    
    st.report_pass('test_case_passed')
    
def test_bvi_ipv4_pc_member_add_remove(setup_teardown_bvi_bd_pc):
    
    #Check intra vlan traffic
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic")
        
    #Check L2 <----> L3 traffic
    #leaf0 (10.0.1.1) -----> leaf1(11.1.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',True)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3")
        
    #Remove one members from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[3]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[3]], add=False)
    
    #Add multiple members to portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0],data_glob.members_dut1[3]], add=True)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0],data_glob.members_dut2[3]], add=True)
    
    #Remove first original member from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)
    
    #Check intra vlan traffic
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic after removing original member Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic after removing original member")
    
    #Check L2 <----> L3 traffic
    #leaf0 (10.0.1.1) -----> leaf1(11.1.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',True)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 after removing original member Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3 after removing original member")
        
    #Add back member to portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=True)
    
    #Remove additional member from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=False)
     
    st.report_pass('test_case_passed')

def test_bvi_new_mac_advertised(setup_teardown_bvi_bd):
    
    #Update mac aging time to 2 mins 
    dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
    for dut in dut_list:
        common_obj.update_mac_aging(dut, data_glob.mac_aging_time_new, verify=True)
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic")  
        
    #Check mac table
    if not mac_obj.verify_mac_address(data_glob.spine0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.spine0))
    if not mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf0))
    if not mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf1))
    common_obj.traffic_cleanup(handles)  
        
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    temp_mac = data_vid_10.t1d3_mac_addr
    data_vid_10.t1d3_mac_addr = data_vid_10.t1d3_mac_addr_mac_move
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr_mac_move
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, cl_count=False, is_l2=True)
    data_vid_10.t1d3_mac_addr = temp_mac
    data_vid_10.t1d4_dest_mac_addr = temp_mac
    
    #wait for old mac to get aged
    st.wait(data_glob.mac_aging_time_new)
    
    #Check mac table for old mac aged
    if mac_obj.verify_mac_address(data_glob.spine0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.spine0))
    if mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.leaf0))
    if mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.leaf1))
    
    #check traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic with new mac advertised  Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic with new mac advertised") 
        
    #Check mac table for new mac advertised
    if not mac_obj.verify_mac_address(data_glob.spine0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.spine0))
    if not mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf0))
    if not mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf1))
    common_obj.traffic_cleanup(handles)
        
    #Update mac aging time to 2 mins 
    dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
    for dut in dut_list:
        common_obj.update_mac_aging(dut, data_glob.mac_aging_time_orig, verify=True)
        
    st.report_pass('test_case_passed')   

def test_bvi_pc_new_mac_advertised(setup_teardown_bvi_bd_pc):
    
    #Update mac aging time to 2 mins 
    dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
    for dut in dut_list:
        common_obj.update_mac_aging(dut, data_glob.mac_aging_time_new, verify=True)
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic ")   
        
    #Check mac table
    if not mac_obj.verify_mac_address_table(data_glob.spine0, data_vid_10.t1d3_mac_addr, vlan=data_glob.vlan[0], port=data_glob.portchannel_name):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.spine0))
    if not mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf0))
    if not mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf1))
    common_obj.traffic_cleanup(handles) 
        
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    temp_mac = data_vid_10.t1d3_mac_addr
    data_vid_10.t1d3_mac_addr = data_vid_10.t1d3_mac_addr_mac_move
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr_mac_move
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, cl_count=False, is_l2=True)
    data_vid_10.t1d3_mac_addr = temp_mac
    data_vid_10.t1d4_dest_mac_addr = temp_mac
    
    #wait for old mac to get aged
    st.wait(data_glob.mac_aging_time_new)
    
    #Check mac table for old mac aged
    if mac_obj.verify_mac_address(data_glob.spine0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.spine0))
    if mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.leaf0))
    if mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr):
        st.report_fail('msg', "old MAC present for host for node {}".format(data_glob.leaf1)) 
        
    #check traffic
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic with new mac advertised  Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic with new mac advertised") 
    
    #Check mac table for new mac advertised
    if not mac_obj.verify_mac_address(data_glob.spine0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.spine0))
    if not mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf0))
    if not mac_obj.verify_mac_address(data_glob.leaf1, data_glob.vlan[0], data_vid_10.t1d3_mac_addr_mac_move):
        st.report_fail('msg', "MAC absent for host for node {}".format(data_glob.leaf1))
    common_obj.traffic_cleanup(handles)
    
    #Update mac aging time to 2 mins 
    dut_list = [data_glob.spine0, data_glob.leaf0, data_glob.leaf1]
    for dut in dut_list:
        common_obj.update_mac_aging(dut, data_glob.mac_aging_time_orig, verify=True)
        
    st.report_pass('test_case_passed')

@pytest.mark.skip(reason = "Ping Failed for L2<--->L3 Traffic, Jira : MIGSOFTWAR-14793")
def test_bvi_ipv6(setup_teardown_bvi_bd):
    
    #leaf0 (10:0:1::1) -----> leaf1(10:0:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification',"for L2 traffic")
      
    #leaf0 (10:0:1::1) -----> leaf1(11:1:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',False)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification',"for L2 <-> L3")
    
    st.report_pass('test_case_passed')
    
@pytest.mark.skip(reason = "Ping Failed for L2<--->L3 Traffic, Jira : MIGSOFTWAR-14793")
def test_bvi_ipv6_pc_member_add_remove(setup_teardown_bvi_bd_pc):
    
    #Check intra vlan traffic
    #leaf0 (10:0:1::1) -----> leaf1(10:0:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic")
        
    #Check L2 <----> L3 traffic
    #leaf0 (10:0:1::1) -----> leaf1(11:1:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',False)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3")
        
    #Remove one members from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[3]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[3]], add=False)
    
    #Add multiple members to portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0],data_glob.members_dut1[3]], add=True)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0],data_glob.members_dut2[3]], add=True)
    
    #Remove first original member from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=False)
    
    #Check intra vlan traffic
    #leaf0 (10:0:1::1) -----> leaf1(10:0:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic after removing original member Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic after removing original member")
        
    #Check L2 <----> L3 traffic
    #leaf0 (10:0:1::1) -----> leaf1(11:1:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',False)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 after removing original member Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3 after removing original member")
        
    #Add back member to portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[1]], add=True)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[1]], add=True)
    
    #Remove additional member from portchannel
    common_obj.portchannel_add_del_member(data_glob.spine0, data_glob.portchannel_name, [data_glob.members_dut1[0]], add=False)
    common_obj.portchannel_add_del_member(data_glob.leaf0, data_glob.portchannel_name, [data_glob.members_dut2[0]], add=False)
    
    st.report_pass('test_case_passed')
    
def test_bvi_multicast(setup_teardown_bvi_bd):
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'multicast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic with multicast mac Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic with multicast mac")
        
    st.report_pass('test_case_passed')
    
def test_bvi_config_unconfig(setup_teardown_bvi_bd):
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic")
       
    #leaf0 (10.0.1.1) -----> leaf1(11.1.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',True, verify_ping=False)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3")
    
    #remove and add back vlan interface 
    if_data = {'name': data_glob.vlan_intf[0],
                 'ip' : (data_glob.vlan_ip[0]).split('/')[0],
                 'subnet': (data_glob.vlan_ip[0]).split('/')[1],
                 'family': "ipv4"
              }
    if not ip_obj.config_unconfig_interface_ip_addresses(data_glob.leaf0, [if_data] , config='remove'):
        st.report_fail('config_cmd_error', "{} ipv4 address delete".format(data_glob.vlan_intf[0])) 
    if not ip_obj.config_unconfig_interface_ip_addresses(data_glob.leaf0, [if_data] , config='add'):
        st.report_fail('config_cmd_error', "{} ipv4 address add".format(data_glob.vlan_intf[0])) 
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for L2 traffic after removing/adding vlan interface Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 traffic after removing/adding vlan interface")
    
    #leaf0 (10.0.1.1) -----> leaf1(11.1.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_l3, "T1D3P1", "T1D4P2", 'unicast',True, verify_ping=False)
    common_obj.traffic_start(handles, data_vid_10, data_l3)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_l3):
        st.log("Traffic verification for L2 <-> L3 after removing/adding vlan interface Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for L2 <-> L3 after removing/adding vlan interface") 
     
    st.report_pass('test_case_passed')

def test_bvi_inter_vlan_ipv4(setup_teardown_bvi):
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.2.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Inter VLAN routing Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing")
     
    #leaf0 (10.0.2.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_10, "T1D3P2", "T1D4P1", 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P1', data_vid_20, data_vid_10):
        st.log("Traffic verification for Inter VLAN routing Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing")
    
    st.report_pass('test_case_passed')

def test_bvi_inter_vlan_ipv6(setup_teardown_bvi):
    
    #leaf0 (10:0:1::1) -----> leaf1(10:0:2::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Inter VLAN routing v6 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing v6")
     
    #leaf0 (10:0:2::1) -----> leaf1(10:0:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_10, "T1D3P2", "T1D4P1", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P1', data_vid_20, data_vid_10):
        st.log("Traffic verification for Inter VLAN routing v6 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing v6")
    
    st.report_pass('test_case_passed')

def test_bvi_inter_vlan_ipv4_pc(setup_teardown_bvi_pc):
    
    #leaf0 (10.0.1.1) -----> leaf1(10.0.2.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Inter VLAN routing Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing")
    
    #leaf0 (10.0.2.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_10, "T1D3P2", "T1D4P1", 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P1', data_vid_20, data_vid_10):
        st.log("Traffic verification for Inter VLAN routing Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing")
    
    st.report_pass('test_case_passed')

# Failure Tc, Jira : MIGSOFTWAR-14794    
def test_bvi_inter_vlan_ipv6_pc(setup_teardown_bvi_pc):
    
    #leaf0 (10:0:1::1) -----> leaf1(10:0:2::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Inter VLAN routing v6 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing v6")
    
    #leaf0 (10:0:2::1) -----> leaf1(10:0:1::2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_10, "T1D3P2", "T1D4P1", 'unicast',False, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P1', data_vid_20, data_vid_10):
        st.log("Traffic verification for Inter VLAN routing v6 Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Inter VLAN routing v6")
    
    st.report_pass('test_case_passed')
