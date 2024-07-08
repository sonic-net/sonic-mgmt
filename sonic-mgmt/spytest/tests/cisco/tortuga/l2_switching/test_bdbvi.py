import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.system.interface as intf_obj
import tortuga_common_utils as common_obj

data_glob = SpyTestDict()
data_glob.vlan = ['10','20']
data_glob.vlan_intf = ['Vlan10','Vlan20']

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
#          Tgen --- leaf0 --- spine0 ---- leaf1 --- Tgen             #
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
    CONFIGS_FILE = 'bdbvi_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)

    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)

# Using Physical intfs for vlan members
# Multiple Vlans
######################################################################
#                               Spine0                               #
#                       /          |          \                      #
#                   D1D3P1      D1D3P2      D1D4P1                   #
#                   Trunk(10)   Trunk(20)   Trunk(10/20)             #
#                   D3D1P1      D3D1P2      D4D1P1                   #
#                       \       /               |                    #
#                         Leaf0               Leaf1                  #
#                         /    \              /    \                 #
#                      D3T1P1 D3T1P2       D4T1P1 D4T1P2             #
#                      Access Access      Access Access              #
#                         \      \           /       /               #
#                                    Tgen                            #
######################################################################
@pytest.fixture()
def setup_teardown_bvi(setup_teardown_basic):
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', True, updated_path)

    yield 'setup_teardown_bvi'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)

'''
Add a static mac entry physical interface and send traffic.
Verify traffic with static mac.
Verify Dynamic Entry is not learnt also.
Remove the static mac and send traffic.
Verify it learns the mac dynamically.
'''
def test_static_mac(setup_teardown_bvi):

    #Set mac address for inter vlan traffic
    data_vid_10.t1d3_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[0])
    data_vid_20.t1d4_dest_mac_addr = basic_obj.get_ifconfig_ether(vars.D3, data_glob.vlan_intf[1])

    static_mac = '00:0A:06:00:12:01'

    if mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[1], static_mac):
        st.report_fail('msg', "MAC already present for host for node {}".format(data_glob.leaf0))
    st.config(data_glob.leaf0 , "fdbclear")

    #Configure the static mac
    common_obj.config_mac(data_glob.leaf0 , static_mac, data_glob.vlan[1], data_glob.members_dut1[1], verify=True)

    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Static MAC L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Static MAC L2 traffic")

    #Check for duplicate entries
    if not mac_obj.verify_mac_address_table(data_glob.leaf0, static_mac, vlan=data_glob.vlan[1], type='Static'):
        st.report_fail('msg', "Static MAC absent for host for node {}".format(data_glob.leaf0))
    if mac_obj.verify_mac_address_table(data_glob.leaf0, static_mac, vlan=data_glob.vlan[1], type='Dynamic'):
        st.report_fail('msg', "Duplicate issue : Dynamic MAC already present for host for node {}".format(data_glob.leaf0))

    #Delete the static mac
    common_obj.delete_mac(data_glob.leaf0 , static_mac, data_glob.vlan[1], verify=True)

    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, "T1D3P1", "T1D4P2", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Dynamic MAC L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for Dynamic MAC L2 traffic")

    if not mac_obj.verify_mac_address(data_glob.leaf0, data_glob.vlan[1], static_mac, type='Dynamic'):
        st.report_fail('msg', "Dynamic MAC absent for host for node {}".format(data_glob.leaf0))

    st.report_pass('test_case_passed')

'''
Verify intra vlan traffic.
Shut/Unshut BD.
Verify intra vlan traffic (no drops).
'''
def test_bd_shut_unshut(setup_teardown_bvi):

    #Set mac address for intra vlan traffic
    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr

    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for bd shut L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for bd shut L2 traffic")

    #shut unshut member interface
    intf_obj.interface_shutdown(data_glob.spine0, data_glob.members_dut1[0], skip_verify=False)

    if not intf_obj.poll_for_interface_status(data_glob.spine0, data_glob.members_dut1[0], 'oper', 'down'):
        st.report_fail('interface_state_fail', data_glob.members_dut1[0], data_glob.spine0, 'down')

    intf_obj.interface_noshutdown(data_glob.spine0, data_glob.members_dut1[0], skip_verify=False)

    if not intf_obj.poll_for_interface_status(data_glob.spine0, data_glob.members_dut1[0], 'oper', 'up'):
        st.report_fail('interface_state_fail', data_glob.members_dut1[0], data_glob.spine0, 'up')

    #leaf0 (10.0.1.1) -----> leaf1(10.0.1.2)
    #traffic check
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, "T1D3P1", "T1D4P1", 'unicast',True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
        st.log("Traffic verification for bd unshut L2 traffic Passed")
    else:
        common_obj.traffic_cleanup(handles)
        st.report_fail('failed_traffic_verification', "for bd unshut L2 traffic")

    st.report_pass('test_case_passed')

