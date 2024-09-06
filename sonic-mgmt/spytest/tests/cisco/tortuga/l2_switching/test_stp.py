import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import pvst_common_utils as pvst_obj
import apis.system.interface as intf_obj
import tortuga_common_utils as common_obj
import apis.switching.portchannel as portchannel_obj

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
        dut_list = [data_glob.spine0, data_glob.spine1, data_glob.leaf0, data_glob.leaf1]
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
data_vid_10.vlan = "10"

data_vid_10.t1d3_ip_addr = "10.0.1.1"
data_vid_10.t1d3_ipv6_addr = "10:0:1::1"
data_vid_10.t1d3_mac_addr = "00:0A:03:00:11:01"

data_vid_10.t1d4_ip_addr = "10.0.1.2"
data_vid_10.t1d4_ipv6_addr = "10:0:1::2"
data_vid_10.t1d4_mac_addr = "00:0A:04:00:12:01"

data_vid_10.t1d3_ip_gateway = data_vid_10.t1d4_ip_addr
data_vid_10.t1d3_ipv6_gateway = data_vid_10.t1d4_ipv6_addr
data_vid_10.t1d4_ip_gateway = data_vid_10.t1d3_ip_addr
data_vid_10.t1d4_ipv6_gateway = data_vid_10.t1d3_ipv6_addr

data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr

data_vid_10.transmit_mode = 'continuous'
data_vid_10.tgen_stats_threshold = 50
data_vid_10.tgen_rate_pps = '100'
data_vid_10.tgen_l3_len = '100'
data_vid_10.pkts_per_burst = '100'
data_vid_10.traffic_run_time = 5
##L2 stream config

##Vlan id 30 stream config
data_vid_30 = SpyTestDict()
data_vid_30.my_dut_list = None
data_vid_30.vlan = "30"

data_vid_30.t1d3_ip_addr = "10.0.3.1"
data_vid_30.t1d3_ipv6_addr = "10:0:3::1"
data_vid_30.t1d3_mac_addr = "00:0A:07:00:11:01"

data_vid_30.t1d4_ip_addr = "10.0.3.2"
data_vid_30.t1d4_ipv6_addr = "10:0:3::2"
data_vid_30.t1d4_mac_addr = "00:0A:08:00:12:01"

data_vid_30.t1d3_ip_gateway = data_vid_30.t1d4_ip_addr
data_vid_30.t1d3_ipv6_gateway = data_vid_30.t1d4_ipv6_addr
data_vid_30.t1d4_ip_gateway = data_vid_30.t1d3_ip_addr
data_vid_30.t1d4_ipv6_gateway = data_vid_30.t1d3_ipv6_addr

data_vid_30.t1d3_dest_mac_addr = data_vid_30.t1d4_mac_addr
data_vid_30.t1d4_dest_mac_addr = data_vid_30.t1d3_mac_addr

data_vid_30.transmit_mode = 'continuous'
data_vid_30.tgen_stats_threshold = 50
data_vid_30.tgen_rate_pps = '100'
data_vid_30.tgen_l3_len = '100'
data_vid_30.pkts_per_burst = '100'
data_vid_30.traffic_run_time = 5
##L2 stream config

##L2 stream config

####################
#                  #
#    D1 = spine0   #
#    D2 = spine1   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global updated_path
    global data_glob
    st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:2", "D2D4:2", "D3T1:2", "D4T1:2")
    vars = st.get_testbed_vars()

    data_glob = SpyTestDict()
    data_glob.spine0 = vars.D1
    data_glob.spine1 = vars.D2
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.nodes = [vars.D1, vars.D2, vars.D3, vars.D4]
    data_glob.vlan = ['10','20','30']
    data_glob.stp_vlan = ['10','30']
    data_glob.stp_instance = {'10':'0','30': '1'}
    data_glob.vlan_intf = ['Vlan10','Vlan20','Vlan30']
    data_glob.vlan_ip = ['10.0.1.10/24','10.0.2.20/24','10.0.3.20/24']
    data_glob.vlan_ipv6 = ['10:0:1::10/64', '10:0:2::20/64', '10:0:3::20/64']
    data_glob.default_forward_delay = 15
    data_glob.default_hellotime = 2
    data_glob.default_max_age = 20
    data_glob.default_priority = 32768
    data_glob.default_port_priority = 128
    data_glob.default_port_cost = 50
    data_glob.default_rg_timeout = 30
    data_glob.portchannel_name = 'PortChannel01'
    data_glob.pre_config = False   #This var allows yaml pre configs
    #vlan to traffic stream mapping
    data_glob.vlan_stream = {
        '10' : data_vid_10,
        '30' : data_vid_30
    }
    CONFIGS_FILE = 'stp_basic_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)

    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)

# Multiple Vlans
@pytest.fixture()
def setup_teardown_stp(setup_teardown_basic):
    if not data_glob.pre_config:
        with open(updated_path) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                common_obj.config_static(node, 'sonic', True, updated_path)
        #wait for STP to converge
        st.wait(2*data_glob.default_forward_delay)
        data_glob.mac_add = SpyTestDict()
        data_glob.mac_add['spine0'] = basic_obj.get_ifconfig_ether(data_glob.spine0, vars.D1D3P1)
        data_glob.mac_add['spine1'] = basic_obj.get_ifconfig_ether(data_glob.spine1, vars.D2D3P1)
        data_glob.mac_add['leaf0'] = basic_obj.get_ifconfig_ether(data_glob.leaf0, vars.D3D1P1)
        data_glob.mac_add['leaf1'] = basic_obj.get_ifconfig_ether(data_glob.leaf1, vars.D4D1P1)

        data_glob.pre_config = True

    yield 'setup_teardown_stp'

    if data_glob.function_unconfig:
        return
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)

def test_bridge_params(setup_teardown_stp):
    '''
    Test Description :
    Verify following Global STP parameters updates via show CLI "show spanning-tree" :
        - forward delay
        - MaxAge
        - Hello Time
        - Priority (via bridge identifier)
        - Root Guard Timeout (enabling root guard on intf required for show cli)
    Verify following parameters also :
        - stp instance
        - bridge identifier
        - rootport
        - rootbridge identifier
    Verify the above parameters for all vlans on Spine0
    '''
    st.log("Update Bridge parameters on root port")
    config_dict = {
        'forward_delay' : 20,
        'hello' : 5,
        'max_age' : 25,
        'priority' : 0,
        'root_guard_timeout' : 40
    }
    if pvst_obj.config_stp_parameters(data_glob.spine0, **config_dict):
        st.log('STP configured successfully on root node.')
    else:
        st.report_fail('msg','STP configuration failed on root node')

    st.log("Check STP parameters on Spine0")
    for vlan in data_glob.stp_vlan:
        bridge_identifier = (hex(int(vlan))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1, 'stp_instance': data_glob.stp_instance[vlan],
            'bridge_identifier': bridge_identifier, 'rootport': 'Root', 'rootbridge_identifier' : bridge_identifier,
            'bridge_fwddly': '20', 'bridge_maxage': '25', 'bridge_hellotime': '5',
            'rootbridge_fwddly': '20', 'rootbridge_maxage': '25','rootbridge_hellotime': '5'
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.log("Root node params for Bridge successfully verified for vlan {}.".format(vlan))
        else:
            st.report_fail("msg","Root node params for Bridge verification failed for vlan {}.".format(vlan))

    st.log("Enable Root guard on an interface on Spine0.")
    if pvst_obj.config_stp_interface_params(data_glob.spine0, vars.D1D3P1, root_guard='enable'):
        st.log('Root guard configured on node {} intf {}.'.format(data_glob.spine0,  vars.D1D3P1))
    else:
        st.report_fail('msg','Root guard configuration on node {} intf {} failed.'.format(data_glob.spine0, vars.D1D3P1))

    st.log("Verify Root Guard Timeout")
    if pvst_obj.get_root_guard_details(data_glob.spine0, rg_param="rg_timeout") == config_dict['root_guard_timeout']:
        st.log("Root Guard timeout for Bridge successfully verified.")
    else:
        st.report_fail("msg","Root Guard timeout for Bridge verification failed.")

    if pvst_obj.config_stp_interface_params(data_glob.spine0, vars.D1D3P1, root_guard='disable'):
        st.log('Root guard disabled on node {} intf {}.'.format(data_glob.spine0,  vars.D1D3P1))
    else:
        st.report_fail('msg','Disabling Root guard on node {} intf {} failed.'.format(data_glob.spine0, vars.D1D3P1))

    st.log("Update Bridge parameters on root port to default")
    config_dict = {
        'forward_delay' : data_glob.default_forward_delay,
        'hello' : data_glob.default_hellotime,
        'max_age' : data_glob.default_max_age,
        'priority' : data_glob.default_priority,
        'root_guard_timeout' : data_glob.default_rg_timeout
    }
    if pvst_obj.config_stp_parameters(data_glob.spine0, **config_dict):
        st.log('STP configured successfully on root node.')
    else:
        st.report_fail('msg','STP configuration failed on root node')

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_vlan_params(setup_teardown_stp):
    '''
    Test Description:
    Verify following vlan specific parameters update via show CLI:
        - forward delay
        - Hello time
        - Max age
        - Priority (via bridge identifier)
    Verify other vlans parameters arr not affected by above updates.
    Other Vlans should still use global params.
    '''

    st.log("Update Vlan 10 parameters on Spine0 port")
    config_dict = {
        'forward_delay' : 20,
        'hello' : 5,
        'max_age' : 25,
        'priority' : 0
    }
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], **config_dict):
        st.log('STP configured successfully on Spine0 for Vlan 10.')
    else:
        st.report_fail('msg','STP configuration failed on Spine0 for Vlan 10.')

    st.log("Check STP parameters on Spine0 for Vlan 10")
    bridge_identifier = (hex(int(data_glob.vlan[0]))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D1D3P1, 'stp_instance': data_glob.stp_instance[data_glob.vlan[0]],
        'bridge_identifier': bridge_identifier, 'rootport': 'Root', 'rootbridge_identifier' : bridge_identifier,
        'bridge_fwddly': '20', 'bridge_maxage': '25', 'bridge_hellotime': '5',
        'rootbridge_fwddly': '20', 'rootbridge_maxage': '25','rootbridge_hellotime': '5'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("Root node params for Vlan successfully verified for vlan {}.".format(data_glob.vlan[0]))
    else:
        st.report_fail("msg","Root node params for Vlan verification failed for vlan {}.".format(data_glob.vlan[0]))

    st.log("Check STP parameters on Spine0 for Vlan 30")
    bridge_identifier = (hex(int(data_glob.vlan[2])+data_glob.default_priority)[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    expected_dict = {
        'vlan': data_glob.vlan[2], 'iface' : vars.D1D3P1, 'stp_instance': data_glob.stp_instance[data_glob.vlan[2]],
        'bridge_identifier': bridge_identifier,
        'bridge_fwddly': '15', 'bridge_maxage': '20', 'bridge_hellotime': '2',
        'rootbridge_fwddly': '15', 'rootbridge_maxage': '20','rootbridge_hellotime': '2'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("Root node params for Vlan successfully verified for vlan {}.".format(data_glob.vlan[2]))
    else:
        st.report_fail("msg","Root node params for Vlan verification failed for vlan {}.".format(data_glob.vlan[2]))

    st.log("ADD wait for STP params convergence via BPDU from ROOT")
    st.wait(5)

    st.log("Check STP parameters on non-root node gets updated with changes in Root node")
    bridge_identifier = (hex(int(data_glob.vlan[0]))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    expected_dict = {
        'vlan': data_glob.vlan[0],'iface' : vars.D1D3P1,
        'rootport': vars.D3D1P1, 'rootbridge_identifier' : bridge_identifier,
        'bridge_fwddly': '15', 'bridge_maxage': '20', 'bridge_hellotime': '2',
        'rootbridge_fwddly': '20', 'rootbridge_maxage': '25','rootbridge_hellotime': '5'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict):
        st.log("BPDU update Bridge params successfully verified.")
    else:
        st.report_fail("msg","BPDU update Bridge params verification failed.")

    st.log("Update Bridge parameters on root port to default")
    config_dict = {
        'forward_delay' : data_glob.default_forward_delay,
        'hello' : data_glob.default_hellotime,
        'max_age' : data_glob.default_max_age,
        'priority' : data_glob.default_priority
    }
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], **config_dict):
        st.log('STP configured successfully on Spine0 for Vlan 10.')
    else:
        st.report_fail('msg','STP configuration failed on Spine0 for Vlan 10.')

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_port_params_port_fast_uplink_fast(setup_teardown_stp):
    '''
    Verify Port Fast Status on untagged port on Leaf0.
    Verify Port Fast functionality by disabling/enabling STP on vlan 10 on Leaf0.
    Verify uplink fast status and port state update time on the configured ports on Spine1 (D2D4P1 and D2D4P2).
    Verify Lower Bridge Id helps in deciding root Port.
    Verify Lower Port Id helps in deciding Root Port in case Alternate Port is present.
    Verify Lower Port Priority helps in deciding the Designated Port.
    Verify Lower Port Cost helps in deciding Root Port.
    Verify Port Cost has higher priority than Port priority.
    Verify Port Cost and priority is updated for other vlans also.
    '''

    st.log("Configure spine0 as ROOT for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], priority=0):
        st.log('Configured Spine0 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine0 configuration as root for Vlan 10 failed.')

    # Following will ensure D2D4P1 will be selected as root port (Lower Port Number)
    # and D2D3P1 and D2D4P2 will be blocked
    st.log("Configure leaf1 with lower priority for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=4096):
        st.log('Configured leaf1 with lower priority for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Leaf1 configuration with lower priority for Vlan 10 failed.')

    st.log("ADD wait for STP params convergence via BPDU from ROOT")
    st.wait(10)

    st.log("Verify PortFast status for interface connected to Tgen should be Yes")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D3T1P1,
        'portstate' : 'FORWARDING', 'portfast' : 'Y'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict):
        st.log("Leaf0 D3T1P1 is portfast for Vlan 10")
    else:
        st.report_fail("msg","Leaf0 D3T1P1 is NOT portfast for Vlan 10.")

    st.log("Disable/Enable STP on Vlan 10 and Verify PortFast functionality.")
    if pvst_obj.config_spanning_tree(data_glob.leaf0, mode='disable', vlan=data_glob.vlan[0]):
        st.log("Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.leaf0))
    else:
        st.report_fail('msg', 'Disabling Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.leaf0))

    if pvst_obj.config_spanning_tree(data_glob.leaf0, mode='enable', vlan=data_glob.vlan[0]):
        st.log("Vlan {} is enabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.leaf0))
    else:
        st.report_fail('msg', 'Enabling Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.leaf0))

    st.log("Wait for PortFast delay and vlan enable delay")
    st.wait(5)

    st.log("Verify PortFast status and PortState for interface connected to Tgen should be Yes and Forwarding")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D3T1P1,
        'portstate' : 'FORWARDING', 'portfast' : 'Y'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict):
        st.log("Leaf0 D3T1P1 is portfast for Vlan 10")
    else:
        st.report_fail("msg","Leaf0 D3T1P1 is NOT portfast for Vlan 10.")

    st.log("Verify Uplink fast status on D2D4P2")
    st.log("Verify Spine1 port D2D4P2 port state to be BLOCKING for Vlan 10")
    st.log("Verify Spine1 port D2D4P1 is selected as root port due to Lower PORT ID")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D4P2,
        'portstate' : 'BLOCKING', 'rootport' : vars.D2D4P1, 'portuplinkfast' : 'Y'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 D2D4P1 is root port for Vlan 10")
    else:
        st.report_fail("msg","Spine1 D2D4P1 is NOT root port for Vlan 10.")

    st.log("Update D4D2P2 priority on Leaf1 port such that it will be chosen as designated port (Lower Priority)")
    if pvst_obj.config_stp_interface_params(data_glob.leaf1, vars.D4D2P2, priority=0):
        st.log('STP configured successfully on Leaf1 for D4D2P2.')
    else:
        st.report_fail('msg','STP configuration failed on Leaf1 for D4D2P2.')

    st.log("Uplink fast delay is 2s")
    st.wait(2)

    st.log("Verify Uplink fast status on D2D4P1")
    st.log("Verify Spine1 port D2D4P1 port state to be BLOCKING for Vlan 10")
    st.log("Verify Spine1 port D2D4P2 is selected as root port for Vlan 10")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D4P1,
        'portstate' : 'BLOCKING', 'rootport': vars.D2D4P2, 'portuplinkfast' : 'Y'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 D2D4P2 is root port for Vlan 10")
    else:
        st.report_fail("msg","Spine1 D2D4P2 is NOT root port for Vlan 10.")

    st.log("update D2D4P2 port cost on Spine1 port such that it will be NOT be chosen as root port anymore")
    if pvst_obj.config_stp_interface_params(data_glob.spine1, vars.D2D4P2, cost=400, priority=192):
        st.log('STP configured successfully on Spine1 for D2D4P2.')
    else:
        st.report_fail('msg','STP configuration failed on Spine1 for D2D4P2.')

    st.log("Uplink fast delay is 2s")
    st.wait(2)

    st.log("Verify Spine1 port D2D4P1 is selected as root port for Vlan 10")
    st.log("Verify Spine1 port D2D4P2 port state to be BLOCKING for Vlan 10")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D4P2,
        'portstate' : 'BLOCKING', 'rootport': vars.D2D4P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 D2D4P1 is root port for Vlan 10")
    else:
        st.report_fail("msg","Spine1 D2D4P1 is NOT root port for Vlan 10.")

    st.log("Check STP port parameters on Spine1 for all Vlans")
    for vlan in data_glob.stp_vlan:
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D2D4P2,
            'portpriority' : '192', 'portpathcost' : '400'
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
            st.log("Port params successfully verified for vlan {}.".format(vlan))
        else:
            st.report_fail("msg","Port params verification failed for vlan {}.".format(vlan))

    st.log("Spine0 cleanup")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Spine0 cleanup success full.')
    else:
        st.report_fail('msg','Spine0 cleanup failed.')

    st.log("Leaf1 cleanup")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Leaf1 STP Vlan cleanup success full.')
    else:
        st.report_fail('msg','Leaf1 STP Vlan cleanup failed.')

    if pvst_obj.config_stp_interface_params(data_glob.leaf1, vars.D4D2P2, priority=data_glob.default_port_priority):
        st.log('Leaf1 STP Interface cleanup success full.')
    else:
        st.report_fail('msg','Leaf1 STP Interface cleanup failed.')

    st.log("Spine1 Cleanup")
    if pvst_obj.config_stp_interface_params(data_glob.spine1, vars.D2D4P2, cost=data_glob.default_port_cost, priority=data_glob.default_port_priority):
        st.log('Spine1 cleanup success full.')
    else:
        st.report_fail('msg','Spine1 cleanup failed.')

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_root_guard(setup_teardown_stp):
    '''
    Test Description:
    Verify Root Guard functionality
    Configure Spine0 as Root for Vlan 10
    Configure Root Guard on Ports facing Spine1 such that it cant become Root for Vlan 10.
    Verify State on above ports when Spine1 sends superior BPDUs via Show CLI "show spanning-tree root_guard"
    Verify Spine0 remains root in this scenario on Leaf0 and Leaf1.
    Verify ports returns to Consistent state after Root Guard timeout,
    when Spine1 stops sending Superior BPDUs.
    '''

    st.log("Configure spine0 as ROOT for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], priority=4096):
        st.log('Configured Spine0 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine0 configuration as root for Vlan 10 failed.')

    st.log("Configure Root Guard on D3D2P1, D4D2P1 and D4D2P2")
    rg_intf_list = [
        (vars.D3D2P1, data_glob.leaf0),
        (vars.D4D2P1, data_glob.leaf1),
        (vars.D4D2P2, data_glob.leaf1)
    ]
    for intf, node in rg_intf_list:
        if pvst_obj.config_stp_interface_params(node, intf, root_guard='enable'):
            st.log('Root guard configured on node {} intf {}.'.format(node, intf))
        else:
            st.report_fail('msg','Root guard configuration on node {} intf {} failed.'.format(node, intf))

    st.log("Confirm Ports are in Consistent state for now on Vlan 10")
    for intf, node in rg_intf_list:
        if pvst_obj.check_rg_current_state(node, int(data_glob.vlan[0]), intf):
            st.log(' Port in Root guard consistent state on node {} intf {} on vlan 10.'.format(node, intf))
        else:
            st.report_fail('msg','Port in Root guard inconsistent state on node {} intf {} on vlan 10.'.format(node, intf))

    st.log("Configure spine1 with lower priority than Spine0 for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=0):
        st.log('Configured Spine1 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration as root for Vlan 10 failed.')

    st.log("ADD wait for STP params convergence via BPDU from Spine1")
    st.wait(5)

    st.log("Confirm Ports are in IN-Consistent state for now on vlan 10")
    for intf, node in rg_intf_list:
        if not pvst_obj.check_rg_current_state(node, data_glob.vlan[0], intf):
            st.log('Port in Root guard inconsistent state on node {} intf {} on vlan 10.'.format(node, intf))
        else:
            st.report_fail('msg','Port in Root guard consistent state on node {} intf {} on vlan 10.'.format(node, intf))

    st.log("Confirm that Spine0 is still root on Leaf0 and Leaf1")
    bridge_identifier = (hex(int(data_glob.vlan[0])+4096)[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    intf_list = [
        (vars.D3D1P1, data_glob.leaf0),
        (data_glob.portchannel_name, data_glob.leaf1),
    ]
    for intf, node in intf_list:
        expected_dict = {
            'vlan': data_glob.vlan[0],'iface' : intf,
            'rootport': intf, 'rootbridge_identifier' : bridge_identifier,
        }
        if pvst_obj.verify_stp_vlan_iface(node, **expected_dict):
            st.log("Root details verified on node {} successfully.".format(node))
        else:
            st.report_fail("msg","Root details verification on node {} failed.".format(node))

    st.log("Configure spine1 with default priority for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Configured Spine1 with default priority for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration with default priority for Vlan 10 failed.')

    st.log("ADD wait for Root Guard Timeout")
    st.wait(data_glob.default_rg_timeout)

    st.log("Confirm Ports are in Consistent state on Vlan 10")
    for intf, node in rg_intf_list:
        if pvst_obj.check_rg_current_state(node, int(data_glob.vlan[0]), intf):
            st.log(' Port in Root guard consistent state on node {} intf {} on vlan 10.'.format(node, intf))
        else:
            st.report_fail('msg','Port in Root guard inconsistent state on node {} intf {} on vlan 10.'.format(node, intf))

    st.log("Disable Root Guard on D3D2P1, D4D2P1 and D4D2P2")
    for intf, node in rg_intf_list:
        if pvst_obj.config_stp_interface_params(node, intf, root_guard='disable'):
            st.log('Root guard disabled on node {} intf {}.'.format(node, intf))
        else:
            st.report_fail('msg','Root guard disabling on node {} intf {} failed.'.format(node, intf))

    st.log("Spine0 cleanup")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Spine0 cleanup success full.')
    else:
        st.report_fail('msg','Spine0 cleanup failed.')

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_bpdu_guard(setup_teardown_stp):
    '''
    Test Description:
    Verify BPDU Guard functionality
    Configure Spine0 as Root for Vlan 10 and 30 (where STP is enabled).
    Configure BPDU Guard on Leaf0 port facing Spine1 as it won't receive any BPDU for any Vlan.
    Verify BPDU guard status via show CLI "show spanning-tree bpdu_guard".
    Lower priority for vlan 10 in Spine1 such that BPDUs are sent to Leaf0
    Verify Port Admin State change on Leaf0.
    Disable STP on Spine1.
    Verify Port State change after startup of Port.
    '''

    st.log("Configure spine0 as ROOT for vlan 10 and 30")
    for vlan in data_glob.stp_vlan:
        if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, vlan, priority=4096):
            st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.spine0,vlan))
        else:
            st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.spine0,vlan))

    st.log("ADD wait for STP params convergence via BPDU from Spine0")
    st.wait(5)

    st.log("Configure BPDU Guard on Leaf0 intf D3D2P1")
    if pvst_obj.config_stp_interface_params(data_glob.leaf0, vars.D3D2P1, bpdu_guard_action='--shutdown'):
        st.log('BPDU guard configured on node {} intf {}.'.format(data_glob.leaf0, vars.D3D2P1))
    else:
        st.report_fail('msg','BPDU guard configuration on node {} intf {} failed.'.format(data_glob.leaf0, vars.D3D2P1))

    st.log("Verify Ports configuration and port state from BPDU guard CLI")
    if pvst_obj.check_bpdu_guard_action(data_glob.leaf0, vars.D3D2P1, config_shut='Yes', opr_shut='No'):
        st.log('Port is configured shut but not in shutdown state on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))
    else:
        st.report_fail('msg','Port bpdu guard config/oper state inconsistencey on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))

    st.log("Configure spine1 with lower priority than Spine0 for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=0):
        st.log('Configured Spine1 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration as root for Vlan 10 failed.')

    st.log("ADD wait for BPDU from Spine1")
    st.wait(5)

    st.log("Verify Port with BPDU guard enabled in shutdown state")
    if pvst_obj.check_bpdu_guard_action(data_glob.leaf0, vars.D3D2P1, config_shut='Yes', opr_shut='Yes'):
        st.log('Port is configured shut and in shutdown state on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))
    else:
        st.report_fail('msg','Port with bpdu guard still up on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))

    st.log("Verify Port admin state")
    if not intf_obj.poll_for_interface_status(data_glob.leaf0, vars.D3D2P1, 'oper', 'down'):
        st.report_fail('interface_state_fail', vars.D3D2P1, data_glob.leaf0, 'down')

    st.log("Disable STP on Spine1 intf D2D3P1")
    if pvst_obj.config_stp_interface(data_glob.spine1, vars.D2D3P1,mode='disable'):
        st.log('STP disabled on spine1 intf {} successfully.'.format(vars.D2D3P1))
    else:
        st.report_fail('msg','Disabling STP on spine1 intf {} failed.'.format(vars.D2D3P1))

    st.log("Add wait to stop BPU flows from spine1")
    st.wait(5)

    st.log("Startup the Port with BPDU guard enabled and verify the admin state")
    intf_obj.interface_noshutdown(data_glob.leaf0, vars.D3D2P1, skip_verify=False)
    if not intf_obj.poll_for_interface_status(data_glob.leaf0, vars.D3D2P1, 'oper', 'up'):
        st.report_fail('interface_state_fail', vars.D3D2P1, data_glob.leaf0, 'up')

    st.log("Verify Ports configuration and port state from BPDU guard CLI")
    if pvst_obj.check_bpdu_guard_action(data_glob.leaf0, vars.D3D2P1, config_shut='Yes', opr_shut='No'):
        st.log('Port is configured shut but not in shutdown state on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))
    else:
        st.report_fail('msg','Port bpdu guard config/oper state inconsistencey on node {} intf {} on vlan 10.'.format(data_glob.leaf0, vars.D3D2P1))

    st.log("Disable BPDU Guard on Leaf0 intf D3D2P1")
    if pvst_obj.config_stp_interface_params(data_glob.leaf0, vars.D3D2P1, bpdu_guard='disable'):
        st.log('BPDU guard disabled on node {} intf {}.'.format(data_glob.leaf0, vars.D3D2P1))
    else:
        st.report_fail('msg','BPDU guard disabling on node {} intf {} failed.'.format(data_glob.leaf0, vars.D3D2P1))

    st.log("Enable STP on Spine1 intf D2D3P1")
    if pvst_obj.config_stp_interface(data_glob.spine1, vars.D2D3P1,mode='enable'):
        st.log('STP enabled on spine1 intf {} successfully.'.format(vars.D2D3P1))
    else:
        st.report_fail('msg','Enabling STP on spine1 intf {} failed.'.format(vars.D2D3P1))

    st.log("Configure spine1 with default priority for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Configured Spine1 with default priority for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration with default priority for Vlan 10 failed.')

    st.log("Spine0 cleanup")
    for vlan in data_glob.stp_vlan:
        if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, vlan, priority=data_glob.default_priority):
            st.log('Spine0 cleanup success full for vlan {}.'.format(vlan))
        else:
            st.report_fail('msg','Spine0 cleanup failed for vlan {}.'.format(vlan))

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_traffic_multiple_vlans(setup_teardown_stp):
    '''
    Test Description:
    Verify Traffic flows without looping for Vlan10.
    While traffic is running, verify traffic doesn't loop when Root change takes place from Leaf0 to Leaf1 for Vlan 10.
    Verify traffic after Root changes back to Leaf0 from Leaf1 for Vlan 10.
    Verify traffic for Vlan10 when STP is disabled/enabled on Vlan 30.
    Verify Traffic flows without looping for Vlan30.
    While traffic is running, verify traffic doesn't loop when redundant links are added to Vlan.
    '''

    st.log("Set following roots for different vlans: Vlan10 : leaf0, Vlan30: spine0")
    vlan_root_map = {
        '10' : data_glob.leaf0,
        '30' : data_glob.spine0
    }
    for vlan in data_glob.stp_vlan :
        if pvst_obj.config_stp_vlan_parameters(vlan_root_map[vlan], vlan, priority=4096):
            st.log('Configured {} as root for vlan {} successfully.'.format(vlan_root_map[vlan],vlan))
        else:
            st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(vlan_root_map[vlan],vlan))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Test Traffic for Vlan 10")
    handles = common_obj.traffic_test_config(data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]], "T1D3P1", "T1D4P1", 'broadcast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed".format(data_glob.vlan[0]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {}.".format(data_glob.vlan[0]))

    st.log("Verify traffic while Root Change")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])

    st.log("Change Root Bridge for Vlan10 from Leaf0 to Leaf1")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=0):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.leaf1,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.leaf1,data_glob.vlan[0]))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed after Root Node Change".format(data_glob.vlan[0]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} after Root Node Change.".format(data_glob.vlan[0]))

    st.log("Verify Leaf1 has became the Root Node")
    expected_dict = {'vlan': data_glob.vlan[0], 'iface' : data_glob.portchannel_name, 'rootport': 'Root'}
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict):
        st.log("Leaf1 is root for Vlan 10.")
    else:
        st.report_fail("msg","Leaf1 is NOT root for Vlan 10.")

    st.log("Change Root Bridge for Vlan10 back to Leaf0 from Leaf1")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.leaf0,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.leaf0,data_glob.vlan[0]))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Verify Leaf0 has became the Root Node Again")
    expected_dict = {'vlan': data_glob.vlan[0], 'iface' : vars.D3D1P1, 'rootport': 'Root'}
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict):
        st.log("Leaf0 is root for Vlan 10.")
    else:
        st.report_fail("msg","Leaf0 is NOT root for Vlan 10.")

    st.log("Verify Traffic for Vlan 10 After Changing root Back.")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed after changing root back.".format(data_glob.vlan[0]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} changing root back.".format(data_glob.vlan[0]))

    st.log("Remove Vlan 30 from PVST on All nodes")
    for node in data_glob.nodes:
        if pvst_obj.config_spanning_tree(node, mode='disable', vlan=data_glob.vlan[2]):
            st.log("Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[2], node))
        else:
            st.report_fail('msg', 'Disabling Vlan {} on Node {} Failed.'.format(data_glob.vlan[2], node))

    st.log("Verify Traffic for Vlan 10 After Disabling Vlan 30")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed after Disabling Vlan {}".format(data_glob.vlan[0], data_glob.vlan[2]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} after Disabling Vlan {}.".format(data_glob.vlan[0], data_glob.vlan[2]))

    st.log("Enable Vlan 30 on PVST on All nodes")
    for node in data_glob.nodes:
        if pvst_obj.config_spanning_tree(node, mode='enable', vlan=data_glob.vlan[2]):
            st.log("Vlan {} is enabled on Node {} successfully.".format(data_glob.vlan[2], node))
        else:
            st.report_fail('msg', 'Enabling Vlan {} on Node {} Failed.'.format(data_glob.vlan[2], node))

    st.log("Configure Spine0 as Root for Vlan30")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[2], priority=4096):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.spine0,data_glob.vlan[2]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.spine0,data_glob.vlan[2]))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Verify Traffic for Vlan 10 After Enabling Vlan 30")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed after Enabling Vlan {}".format(data_glob.vlan[0], data_glob.vlan[2]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} after Enabling Vlan {}.".format(data_glob.vlan[0], data_glob.vlan[2]))

    st.log("Verify Traffic for Vlan 30")
    handles = common_obj.traffic_test_config(data_glob.vlan_stream[data_glob.vlan[2]], data_glob.vlan_stream[data_glob.vlan[2]], "T1D3P2", "T1D4P2", 'broadcast',True, verify_ping=False, is_l2=True)
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[2]], data_glob.vlan_stream[data_glob.vlan[2]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P2', data_glob.vlan_stream[data_glob.vlan[2]], data_glob.vlan_stream[data_glob.vlan[2]]):
        st.log("Traffic verification for Vlan {} Passed".format(data_glob.vlan[2]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {}.".format(data_glob.vlan[2]))

    st.log("Verify traffic while adding more redundant paths")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[2]], data_glob.vlan_stream[data_glob.vlan[2]])
    vlan_obj.add_vlan_member(data_glob.spine0, data_glob.vlan[2], [vars.D1D3P2], tagging_mode=True)
    vlan_obj.add_vlan_member(data_glob.leaf0, data_glob.vlan[2], [vars.D3D1P2], tagging_mode=True)
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P2', data_glob.vlan_stream[data_glob.vlan[2]], data_glob.vlan_stream[data_glob.vlan[2]]):
        st.log("Traffic verification for Vlan {} Passed after adding redundant link".format(data_glob.vlan[2]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} after adding redundant link.".format(data_glob.vlan[2]))

    st.log("Verify Redundant intf being added to STP")
    expected_dict = {'vlan': data_glob.vlan[2], 'iface' : vars.D1D3P2}
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("Intf D1D3P2 added to STP in Vlan 10.")
    else:
        st.report_fail("msg","Intf D1D3P2 NOT added to STP in Vlan 10.")

    vlan_obj.delete_vlan_member(data_glob.spine0, data_glob.vlan[2], [vars.D1D3P2], tagging_mode=True)
    vlan_obj.delete_vlan_member(data_glob.leaf0, data_glob.vlan[2], [vars.D3D1P2], tagging_mode=True)

    st.log("Root Nodes Cleanup")
    for vlan in data_glob.stp_vlan:
        if pvst_obj.config_stp_vlan_parameters(vlan_root_map[vlan], vlan, priority=data_glob.default_priority):
            st.log('Cleanup of root {} for vlan {} successfully.'.format(vlan_root_map[vlan],vlan))
        else:
            st.report_fail('msg','{} cleanup as root for vlan {} failed.'.format(vlan_root_map[vlan],vlan))

    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')
