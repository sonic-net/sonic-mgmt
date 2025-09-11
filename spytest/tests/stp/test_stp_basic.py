import os
import yaml
import pytest
from spytest import st, SpyTestDict

import apis.system.basic as basic_obj
import apis.switching.vlan as vlan_obj
import apis.switching.pvst as pvst_obj
import apis.system.interface as intf_obj
import common_utils as common_obj
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
        for dut in dut_list:
            for vlan in vlan_obj.get_vlan_list(dut):
                pvst_obj.config_spanning_tree(dut, mode='disable', vlan=vlan)
            vlan_obj.clear_vlan_configuration([dut])
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
data_vid_10.t1d3_mac_addr = "00:0A:03:00:11:01"

data_vid_10.t1d4_ip_addr = "10.0.1.2"
data_vid_10.t1d4_mac_addr = "00:0A:04:00:12:01"

data_vid_10.t1d3_ip_gateway = data_vid_10.t1d4_ip_addr
data_vid_10.t1d4_ip_gateway = data_vid_10.t1d3_ip_addr

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
data_vid_30.t1d3_mac_addr = "00:0A:07:00:11:01"

data_vid_30.t1d4_ip_addr = "10.0.3.2"
data_vid_30.t1d4_mac_addr = "00:0A:08:00:12:01"

data_vid_30.t1d3_ip_gateway = data_vid_30.t1d4_ip_addr
data_vid_30.t1d4_ip_gateway = data_vid_30.t1d3_ip_addr

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
    data_glob.new_vlan = '40'
    data_glob.stp_instance = {'10':'0','30': '1'}
    data_glob.default_forward_delay = 15
    data_glob.default_hellotime = 2
    data_glob.default_max_age = 20
    data_glob.default_priority = 32768
    data_glob.default_port_priority = 128
    data_glob.default_port_cost = 50
    data_glob.default_rg_timeout = 30
    data_glob.new_rg_timeout = 20
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
    Verify Non root node params are updated successfully.
    Verify STP is enabled on Vlan 10 and 30 and not on Vlan 20 as per pre configs.
    Create new Vlan and verify it should not get added to STP automatically.
    Enable Per Vlan STP and verify STP is enabled on New Vlan with Default params.
    Remove/Add Common Interface from all Vlans.
    Verify Orchagent Crash didn't occur by check the STP CLI output.
    Remove Vlan and verify it should be removed from STP.
    Verify Disable/Enable of STP on Vlan.
    Verify interface removal from Vlan.
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
    st.wait(10)

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

    st.log("Check STP is enabled for Vlan 10 and 30")
    for vlan in data_glob.stp_vlan:
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1, 'stp_instance': data_glob.stp_instance[vlan]
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.log("vlan {} is enabled on Spine0.".format(vlan))
        else:
            st.report_fail("msg","vlan {} is not enabled on Spine0.".format(vlan))

    st.log("Check STP is not enabled for Vlan 20")
    expected_dict = {
        'vlan': data_glob.vlan[1], 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.report_fail("msg","STP is enabled for vlan {}.".format(data_glob.vlan[1]))
    else:
        st.log("STP disabled for vlan {}.".format(data_glob.vlan[1]))

    st.log("Create new Vlan 40 and add member interface")
    vlan_obj.create_vlan(data_glob.spine0, [data_glob.new_vlan])
    vlan_obj.add_vlan_member(data_glob.spine0, data_glob.new_vlan, [vars.D1D3P1], tagging_mode=True)

    st.log("Verify new Vlan 40 is not added to STP automatically")
    expected_dict = {
        'vlan': data_glob.new_vlan, 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.report_fail("msg","New Vlan 40 is added to STP without Per Vlan STP")
    else:
        st.log("New Vlan 40 is not added to STP")

    if pvst_obj.config_spanning_tree(data_glob.spine0, mode='enable', vlan=data_glob.new_vlan):
        st.log("Vlan {} is enabled on Node {} successfully.".format(data_glob.new_vlan, data_glob.spine0))
    else:
        st.report_fail('msg', 'Enabling Vlan {} on Node {} Failed.'.format(data_glob.new_vlan, data_glob.spine0))

    st.log("Verify new Vlan 40 is added to STP with default params")
    bridge_identifier = (hex(data_glob.default_priority + int(data_glob.new_vlan))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    expected_dict = {
        'vlan': data_glob.new_vlan, 'iface' : vars.D1D3P1, 'bridge_identifier': bridge_identifier,
        'bridge_fwddly': data_glob.default_forward_delay, 'bridge_maxage': data_glob.default_max_age,
        'bridge_hellotime': data_glob.default_hellotime
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("STP enabled for new vlan 40 successfully.")
    else:
        st.report_fail("msg","Failed to enable STP for new Vlan 40 with desired params.")

    st.log("Remove Common Member from all Vlans.")
    vlan_obj.delete_vlan_member(data_glob.spine0, data_glob.new_vlan, [vars.D1D3P1], tagging_mode=True)
    for vlan in data_glob.vlan:
        vlan_obj.delete_vlan_member(data_glob.spine0, vlan, [vars.D1D3P1], tagging_mode=True)

    st.log("Above should not lead to Orchagent Crash. Verify by Spanning Tree output.")
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, vlan=data_glob.vlan[0], iface=data_glob.portchannel_name):
        st.log("Spanning Tree CLI output present.")
    else:
        st.report_fail("msg","Spanning Tree CLI output absent.")

    st.log("Disable STP on Vlan 40")
    if pvst_obj.config_spanning_tree(data_glob.spine0, mode='disable', vlan=data_glob.new_vlan):
        st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.new_vlan, data_glob.spine0))
    else:
        st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.new_vlan, data_glob.spine0))

    st.log("Remove new Vlan 40")
    vlan_obj.delete_vlan(data_glob.spine0, [data_glob.new_vlan])

    st.log("Verify STP is disabled for Vlan 40 after its removal.")
    expected_dict = {
        'vlan': data_glob.new_vlan, 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.report_fail("msg","STP still enabled for vlan 40.")
    else:
        st.log("STP disabled for vlan 40 successfully.")

    st.log("Add back the deleted member interface to all vlans")
    for vlan in data_glob.vlan:
        vlan_obj.add_vlan_member(data_glob.spine0, vlan, [vars.D1D3P1], tagging_mode=True)

    st.log("Disable STP on Vlan 30")
    if pvst_obj.config_spanning_tree(data_glob.spine0, mode='disable', vlan=data_glob.vlan[2]):
        st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[2], data_glob.spine0))
    else:
        st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[2], data_glob.spine0))

    st.log("Verify STP is disabled successfully on Vlan via Show CLI.")
    expected_dict = {
        'vlan': data_glob.vlan[2], 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.report_fail("msg","STP still enabled for vlan {}.".format(data_glob.vlan[2]))
    else:
        st.log("STP disabled for vlan {}.".format(data_glob.vlan[2]))

    st.log("Enable STP back on Vlan 30")
    pvst_obj.config_spanning_tree(data_glob.spine0, mode='enable', vlan=data_glob.vlan[2])

    st.log("Verify STP is enabled successfully on Vlan 30 via Show CLI.")
    bridge_identifier = (hex(data_glob.default_priority + int(data_glob.vlan[2]))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
    expected_dict = {
        'vlan': data_glob.vlan[2], 'iface' : vars.D1D3P1, 'stp_instance': data_glob.stp_instance[data_glob.vlan[2]],
        'bridge_identifier': bridge_identifier, 'bridge_fwddly': data_glob.default_forward_delay,
        'bridge_maxage': data_glob.default_max_age, 'bridge_hellotime': data_glob.default_hellotime
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("STP enabled for vlan {}.".format(data_glob.vlan[2]))
    else:
        st.report_fail("msg","STP still disabled for vlan {}.".format(data_glob.vlan[2]))

    st.log("Remove interface from Vlan 10")
    vlan_obj.delete_vlan_member(data_glob.spine0, data_glob.stp_vlan[0], [vars.D1D3P1], tagging_mode=True)
    st.log("Verify interface is removed from for STP for Vlan 10 but present for Vlan 30")
    expected_dict = {
        'vlan': data_glob.stp_vlan[0], 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.report_fail("msg","Interface {} still enabled in STP for Vlan 10.".format(vars.D1D3P1))
    else:
        st.log("Interface {} disabled from STP for Vlan 10.".format(vars.D1D3P1))
    expected_dict = {
        'vlan': data_glob.stp_vlan[1], 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("Interface {} still enabled in STP for Vlan 30".format(vars.D1D3P1))
    else:
        st.report_fail("msg","Interface {} disabled from STP for Vlan 30 also.".format(vars.D1D3P1))

    st.log("Enable the interface back on Vlan 10")
    vlan_obj.add_vlan_member(data_glob.spine0, data_glob.stp_vlan[0], [vars.D1D3P1], tagging_mode=True)

    expected_dict = {
        'vlan': data_glob.stp_vlan[0], 'iface' : vars.D1D3P1
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
        st.log("Interface {} enabled on STP for Vlan 10 successfully".format(vars.D1D3P1))
    else:
        st.report_fail("msg","Interface {} still disabled on STP for Vlan 10.".format(vars.D1D3P1))

    st.log("Disable STP on VLAN 10 and 30 on Spine0.")
    for vlan in data_glob.stp_vlan:
        if pvst_obj.config_spanning_tree(data_glob.spine0, mode='disable', vlan=vlan):
            st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(vlan, data_glob.spine0))
        else:
            st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(vlan, data_glob.spine0))

    st.log("Verify STP is disabled on all Vlans.")
    for vlan in data_glob.vlan:
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.report_fail("msg","STP still enabled for vlan {}.".format(vlan))
        else:
            st.log("STP disabled for vlan {}.".format(vlan))

    st.log("Enable STP on VLAN 10 and 30 on Spine0.")
    for vlan in data_glob.stp_vlan:
        if pvst_obj.config_spanning_tree(data_glob.spine0, mode='enable', vlan=vlan):
            st.log("Per Vlan STP on Vlan {} is enabled on Node {} successfully.".format(vlan, data_glob.spine0))
        else:
            st.report_fail('msg', 'Enabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(vlan, data_glob.spine0))

    st.log("Wait 30s for STP to converge.")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Verify Default STP parameters on Spine0 for all STP enabled Vlans")
    for vlan in data_glob.stp_vlan:
        bridge_identifier = (hex(data_glob.default_priority + int(vlan))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1,
            'bridge_identifier': bridge_identifier, 'bridge_fwddly': data_glob.default_forward_delay,
            'bridge_maxage': data_glob.default_max_age, 'bridge_hellotime': data_glob.default_hellotime
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.log("Root node params for Bridge successfully verified for vlan {}.".format(vlan))
        else:
            st.report_fail("msg","Root node params for Bridge verification failed for vlan {}.".format(vlan))

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_tortuga_STP_scenarios(setup_teardown_stp):
    '''
    Single Leaf dual-attach to STP switch
    Dual Leaf Loopback : Connect interfaces on two GSTP enabled Leafs
    GSTP enabled Leafs connected to multiple STP enabled Downstream switches
    GSTP enabled Leafs connected to STP enabled Downstream switch
    '''
    st.log ("Single Leaf dual-attach to Downstream STP switch")
    st.log("Isolate Spine1 and Leaf1")
    st.log("Remove link: D2D3P1 from Vlan 10 on Spine1")
    vlan_obj.delete_vlan_member(data_glob.spine1, data_glob.vlan[0], [vars.D2D3P1], tagging_mode=True)
    st.log("Remove link: PortChannel01 from Vlan 10 on Leaf1")
    vlan_obj.delete_vlan_member(data_glob.leaf1, data_glob.vlan[0], [data_glob.portchannel_name], tagging_mode=True)

    st.log("Configure spine1 as ROOT for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=0):
        st.log('Configured Spine1 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration as root for Vlan 10 failed.')

    st.log("ADD wait for STP params convergence via BPDU")
    st.wait(10)

    st.log("Verify one of the links is BLOCKED on Leaf1")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D4D2P1,
        'portstate' : 'BLOCKING'
    }
    result_leaf1_D4D2P1 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
    expected_dict['iface'] = vars.D4D2P2
    result_leaf1_D4D2P2 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
    if result_leaf1_D4D2P1 ^ result_leaf1_D4D2P2:
        st.log("One link is BLOCKED on Leaf1 for Vlan 10")
    else:
        st.report_fail("msg","Either Both on none of the Leaf1 links are BLOCKED for Vlan 10.")

    st.log("Dual Leaf Loopback : Connect interfaces on two GSTP enabled Leafs (Spine1 and Leaf1 in this case)")

    st.log("Disable Per Vlan STP on Vlan 10 on Leaf1.")
    if pvst_obj.config_spanning_tree(data_glob.leaf1, mode='disable', vlan=data_glob.vlan[0]):
        st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.leaf1))
    else:
        st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.leaf1))

    st.log("Configure Global Static STP on Leaf1")
    config_dict = {
        'global-stp-mac-enable' : data_glob.mac_add['spine1'],
        'priority' : 0
    }
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], **config_dict):
        st.log('GSTP configured successfully on Leaf1 for Vlan 10.')
    else:
        st.report_fail('msg','GSTP configuration failed on Leaf1 for Vlan 10.')

    st.log("Verify GSTP configured on Leaf1")
    bridge_identifier = (hex(int(data_glob.vlan[0]))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine1'].split(':'))
    expected_dict = {
        'vlan': data_glob.vlan[0],'iface' : vars.D4D2P1,
        'bridge_identifier': bridge_identifier, 'rootport': 'Root', 'rootbridge_identifier' : bridge_identifier
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict):
        st.log("GSTP on Leaf1 successfully verified.")
    else:
        st.report_fail("msg","GSTP on Leaf1 verification failed.")

    st.log("Verify Both Links are BLOCKED")
    expected_dict = {
        'vlan': data_glob.vlan[0],'iface' : vars.D2D4P1,
        'portstate' : 'BLOCKING'
    }
    result_spine_1 = pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict)
    expected_dict['iface'] = vars.D2D4P2
    result_spine_2 = pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict)
    expected_dict['iface'] = vars.D4D2P1
    result_leaf_1 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
    expected_dict['iface'] = vars.D4D2P2
    result_leaf_2 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)

    if (not(result_spine_1 or result_leaf_1)) or (not(result_spine_2 or result_leaf_2)):
        st.report_fail('msg','Atleast One of the link is in forwarding.')
    else:
        st.log("Both links are BLOCKED as expected.")

    st.log("GSTP enabled Leafs connected to multiple STP enabled Downstream switches")
    st.log("Add Back the links to form a Loop with leaf1 and Spine1")
    st.log("Add link: D2D3P1 on Vlan 10 on Spine1")
    vlan_obj.add_vlan_member(data_glob.spine1, data_glob.vlan[0], [vars.D2D3P1], tagging_mode=True)
    st.log("Add link: PortChannel01 on Vlan 10 on Leaf1")
    vlan_obj.add_vlan_member(data_glob.leaf1, data_glob.vlan[0], [data_glob.portchannel_name], tagging_mode=True)

    st.log("Configure spine0 as Lower Priority for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], priority=4096):
        st.log('Configured Spine0 as Lower Priority for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine0 configuration as Lower Priority for Vlan 10 failed.')

    st.log("ADD wait for STP params convergence via BPDU")
    st.wait(10)

    st.log("Verify D3D1P1 is BLOCKED on Leaf0 as its has higher priority than Spine0")
    expected_dict = {
        'vlan': data_glob.vlan[0],'iface' : vars.D3D1P1,
        'portstate' : 'BLOCKING'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict):
        st.log("Leaf0 D3D1P1 is BLOCKED for Vlan 10")
    else:
        st.report_fail("msg","Leaf0 D3D1P1 is NOT BLOCKED for Vlan 10.")

    st.log("GSTP enabled Leafs connected to STP enabled Downstream switch with GSTP configured on Spine0, Spine1 and Leaf1")

    st.log("Disable Per Vlan STP on Vlan 10 on Spine0.")
    if pvst_obj.config_spanning_tree(data_glob.spine0, mode='disable', vlan=data_glob.vlan[0]):
        st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.spine0))
    else:
        st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.spine0))

    st.log("Configure Global Static STP on Spine0")
    config_dict = {
        'global-stp-mac-enable' : data_glob.mac_add['spine1'],
        'priority' : 0
    }
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine0, data_glob.vlan[0], **config_dict):
        st.log('GSTP configured successfully on Spine0 for Vlan 10.')
    else:
        st.report_fail('msg','GSTP configuration failed on Spine0 for Vlan 10.')

    st.log("ADD wait for STP params convergence via BPDU")
    st.wait(10)

    st.log("Verify one of the links is BLOCKED on Leaf0")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D3D1P1,
        'portstate' : 'BLOCKING'
    }
    result_leaf0_spine0 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
    expected_dict['iface'] = vars.D3D2P1
    result_leaf0_spine1 = pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
    if result_leaf0_spine1 ^ result_leaf0_spine0:
        st.log("One link is BLOCKED on Leaf0 for Vlan 10")
    else:
        st.report_fail("msg","Either Both on none of the Leaf0 links are BLOCKED for Vlan 10.")

    st.log("Disable GSTP /Enable Per Vlan STP on Vlan 10 on Spine0 and Leaf1.")
    for dut in [data_glob.spine0, data_glob.leaf1]:
        if pvst_obj.config_spanning_tree(dut, mode='disable', vlan=data_glob.vlan[0]):
            st.log("GSTP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[0], dut))
        else:
            st.report_fail('msg', 'Disabling GSTP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], dut))

        if pvst_obj.config_spanning_tree(dut, mode='enable', vlan=data_glob.vlan[0]):
            st.log("Per Vlan STP on Vlan {} is enabled on Node {} successfully.".format(data_glob.vlan[0], dut))
        else:
            st.report_fail('msg', 'Enabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], dut))

    st.log("Spine1 Cleanup")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Spine1 cleanup success full.')
    else:
        st.report_fail('msg','Spine1 cleanup failed.')

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')

def test_port_params_port_fast_uplink_fast(setup_teardown_stp):
    '''
    Verify Disable/Enable of STP on Interface.
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

    st.log("Disable STP from interface {}.".format(vars.D1D3P1))
    if pvst_obj.config_stp_interface(data_glob.spine0, vars.D1D3P1, mode='disable'):
        st.log("STP disabled on interface {} successfully".format(vars.D1D3P1))
    else:
        st.report_fail("Failed to disable STP on interface {}".format(vars.D1D3P1))

    st.log("Verify Interface is removed from STP for all Vlans.")
    for vlan in data_glob.stp_vlan:
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.report_fail("msg","STP still enabled for interface {} for vlan {}.".format(vars.D1D3P1, vlan))
        else:
            st.log("STP disabled for interface {} for vlan {}.".format(vars.D1D3P1, vlan))

    st.log("Enable STP on interface {}.".format(vars.D1D3P1))
    if pvst_obj.config_stp_interface(data_glob.spine0, vars.D1D3P1, mode='enable'):
        st.log("STP enabled on interface {} successfully".format(vars.D1D3P1))
    else:
        st.report_fail("Failed to enable STP on interface {}".format(vars.D1D3P1))

    for vlan in data_glob.stp_vlan:
        bridge_identifier = (hex(data_glob.default_priority + int(vlan))[2:]).zfill(4) + ''.join(data_glob.mac_add['spine0'].split(':'))
        expected_dict = {
            'vlan': vlan, 'iface' : vars.D1D3P1
        }
        if pvst_obj.verify_stp_vlan_iface(data_glob.spine0, **expected_dict):
            st.log("Bridge params verified successfully for interface {} for vlan {}.".format(vars.D1D3P1, vlan))
        else:
            st.report_fail("msg","Bridge params verification failed for interface {} for vlan {}.".format(vars.D1D3P1, vlan))

    # Following will ensure D2D4P1 or D2D4P2 will be selected as root port (Lower Port ID)
    # and D2D3P1 will be blocked
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
        st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.leaf0))
    else:
        st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.leaf0))

    if pvst_obj.config_spanning_tree(data_glob.leaf0, mode='enable', vlan=data_glob.vlan[0]):
        st.log("Per Vlan STP on Vlan {} is enabled on Node {} successfully.".format(data_glob.vlan[0], data_glob.leaf0))
    else:
        st.report_fail('msg', 'Enabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[0], data_glob.leaf0))

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
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D4P2,
        'portuplinkfast' : 'Y'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Verified Uplink Fast Status for D2D4P2")
    else:
        st.report_fail("msg","Uplink Fast Status Verification for D2D4P2 failed")

    st.log("Verify one of the links is BLOCKED on Spine1")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D4P1,
        'portstate' : 'BLOCKING'
    }
    result_spine1_1 = pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict)
    expected_dict['iface'] = vars.D2D4P2
    result_spine1_2 = pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict)
    if result_spine1_1 ^ result_spine1_2:
        st.log("One link is BLOCKED on Spine1 for Vlan 10")
    else:
        st.report_fail("msg","Either Both on none of the Spine1 links are BLOCKED for Vlan 10.")

    st.log("Verify Forwarding Spine1 port is selected as root port due to Lower PORT ID")
    forwardind_port = vars.D2D4P1 if result_spine1_2 else vars.D2D4P2
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : forwardind_port,
        'rootport' : forwardind_port
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 {} is root port for Vlan 10".format(forwardind_port))
    else:
        st.report_fail("msg","Spine1 {} is NOT root port for Vlan 10.".format(forwardind_port))

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
    Verify Root Guard Timeout Update.
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

    st.log("ADD wait for STP params convergence via BPDU from ROOT")
    st.wait(10)

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

    for dut in [data_glob.leaf0, data_glob.leaf1]:
        if pvst_obj.config_stp_parameters(dut, root_guard_timeout = data_glob.new_rg_timeout):
            st.log('Root Guard timeout updated successfully on {}.'.format(dut))
        else:
            st.report_fail('msg','Root Guard timeout updated failed on {}'.format(dut))

    st.log("Verify Root Guard Timeout")
    for dut in [data_glob.leaf0, data_glob.leaf1]:
        if pvst_obj.get_root_guard_details(dut, rg_param="rg_timeout") == data_glob.new_rg_timeout:
            st.log("Root Guard timeout for {} successfully verified.".format(dut))
        else:
            st.report_fail("msg","Root Guard timeout for {} verification failed.".format(dut))

    st.log("Configure spine1 with lower priority than Spine0 for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=0):
        st.log('Configured Spine1 as root for Vlan 10 successfully.')
    else:
        st.report_fail('msg','Spine1 configuration as root for Vlan 10 failed.')

    st.log("ADD wait for STP params convergence via BPDU from Spine1")
    st.wait(10)

    st.log("Confirm Ports are in IN-Consistent state for now on vlan 10")
    for intf, node in rg_intf_list:
        if not pvst_obj.check_rg_current_state(node, int(data_glob.vlan[0]), intf):
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
    st.wait(data_glob.new_rg_timeout)

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
        st.log('Spine0 Vlan cleanup success full.')
    else:
        st.report_fail('msg','Spine0 Vlan cleanup failed.')

    st.log("Set the root guard timeout to default")
    for dut in [data_glob.leaf0, data_glob.leaf1]:
        if pvst_obj.config_stp_parameters(dut, root_guard_timeout = data_glob.default_rg_timeout):
            st.log('Root Guard timeout cleanup successfully on {}.'.format(dut))
        else:
            st.report_fail('msg','Root Guard timeout cleanup failed on {}'.format(dut))

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
    st.wait(10)

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
    st.wait(10)

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

    st.log("Add wait to stop BPDU flows from spine1")
    st.wait(10)

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
    Verify traffic after Root changes from to Leaf0 from Leaf1 for Vlan 10.
    Verify traffic when intf is in blocking state in another vlan.
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

    st.log("Change Root Bridge for Vlan10 from Leaf0 to Leaf1")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=0):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.leaf1,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.leaf1,data_glob.vlan[0]))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Verify traffic after Root Change")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
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

    st.log("Change Root Bridge for Vlan10 from Leaf1 from Spine1")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[0], priority=data_glob.default_priority):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.leaf0,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.leaf0,data_glob.vlan[0]))

    st.log("Configure Spine1 as root for Vlan 10")
    if pvst_obj.config_stp_vlan_parameters(data_glob.spine1, data_glob.vlan[0], priority=0):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.spine1,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.spine1,data_glob.vlan[0]))

    st.log("Decrease priority for leaf1 in Vlan 30 so D2D3P1 will be in blocking state for this vlan")
    if pvst_obj.config_stp_vlan_parameters(data_glob.leaf1, data_glob.vlan[2], priority=8192):
        st.log('Configured {} as root for vlan {} successfully.'.format(data_glob.leaf1,data_glob.vlan[0]))
    else:
        st.report_fail('msg','{} configuration as root for vlan {} failed.'.format(data_glob.leaf1,data_glob.vlan[0]))

    st.log("Wait for STP to converge")
    st.wait(2*data_glob.default_forward_delay)

    st.log("Verify D2D3P1 on Spine1 is blocking for Vlan 30.")
    expected_dict = {
        'vlan': data_glob.vlan[2], 'iface' : vars.D2D3P1,
        'portstate' : 'BLOCKING'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 D2D3P1 is BLOCKING for Vlan 30")
    else:
        st.report_fail("msg","Spine1 D2D3P1 is not BLOCKING for Vlan 30")

    st.log("Verify D2D3P1 on Spine1 is forwarding for Vlan 10.")
    expected_dict = {
        'vlan': data_glob.vlan[0], 'iface' : vars.D2D3P1,
        'portstate' : 'FORWARDING'
    }
    if pvst_obj.verify_stp_vlan_iface(data_glob.spine1, **expected_dict):
        st.log("Spine1 D2D3P1 is FORWARDING for Vlan 10")
    else:
        st.report_fail("msg","Spine1 D2D3P1 is not FORWARDING for Vlan 10")

    st.log("Verify Traffic for Vlan 10 After Changing root to Spine0.")
    st.log("Verify Traffic for Vlan 10 when D2D3P1 is blocking for Vlan 30 but forwarding for Vlan 10.")
    common_obj.traffic_start(handles, data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]])
    common_obj.traffic_stop(handles)
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_glob.vlan_stream[data_glob.vlan[0]], data_glob.vlan_stream[data_glob.vlan[0]]):
        st.log("Traffic verification for Vlan {} Passed after changing root back.".format(data_glob.vlan[0]))
    else:
        st.report_fail('failed_traffic_verification', "for Vlan {} changing root back.".format(data_glob.vlan[0]))

    st.log("Remove Vlan 30 from PVST on All nodes")
    for node in data_glob.nodes:
        if pvst_obj.config_spanning_tree(node, mode='disable', vlan=data_glob.vlan[2]):
            st.log("Per Vlan STP on Vlan {} is disabled on Node {} successfully.".format(data_glob.vlan[2], node))
        else:
            st.report_fail('msg', 'Disabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[2], node))

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
            st.log("Per Vlan STP on Vlan {} is enabled on Node {} successfully.".format(data_glob.vlan[2], node))
        else:
            st.report_fail('msg', 'Enabling Per Vlan STP on Vlan {} on Node {} Failed.'.format(data_glob.vlan[2], node))

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