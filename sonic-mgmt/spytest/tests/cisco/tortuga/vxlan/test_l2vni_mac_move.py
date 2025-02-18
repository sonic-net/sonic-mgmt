import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.routing.vrf as vrf_obj
import vxlan_utils as vxlan_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##  T1  -- SPT
##
##  SPT data0 (tp1) --- SD3 ------ SD4 --- SPT data1 (tp3)
##  SPT data2 (tp2) --- SD3 ------ SD4 --- SPT data3 (tp4)
##  tp1: SPT data0
##  tp2: SPT data1
##  tp3: SPT data2
##  tp4: SPT data3

data = SpyTestDict()
#### Config template file ####
CONFIGS_FILE = "vxlan_l2vni_mac_move.yaml"

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "100"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "1000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield 
    
## Tgen Stream Config
move_host_gw_ip_addr = "200.200.200.1"
move_host_ip_addr = "200.200.200.5"
move_host_diff_ip_addr = "200.200.200.6"
move_host_mac_addr = "00:0a:01:00:11:01"

data.d3tp1_ip_addr = move_host_gw_ip_addr
data.tp1d3_ip_addr = move_host_ip_addr
data.tp1d3_mac_addr = move_host_mac_addr

data.d4tp2_ip_addr = move_host_gw_ip_addr
data.tp2d4_ip_addr = move_host_ip_addr
data.tp2d4_mac_addr = move_host_mac_addr

data.d3tp3_ip_addr = "200.200.200.1"
data.tp3d3_ip_addr = "200.200.200.2"
data.tp3d3_mac_addr = "00:0a:01:00:11:02"

data.d4tp4_ip_addr = "200.200.200.1"
data.tp4d4_ip_addr = "200.200.200.3"
data.tp4d4_mac_addr = "00:0a:01:00:12:02"

LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

SAG1_VLAN = '3'

VXLAN_INTERFACE = "VXLAN-3"

SAG_MAC = "00:11:22:33:44:55"
SAG1_IP = data.d3tp3_ip_addr


####################
@pytest.fixture(scope="module", autouse=True)
def setup_teardown_l2vni_sag():
    vars = st.get_testbed_vars()
    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
        st.wait(60)

    yield 'setup_teardown_l2vni_sag'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(5)
            config_static(node, 'sonic', add=False)
            st.wait(2)
    #router_preconfig_cleanup()
    ### Remove the temp config file after the test ###
    vxlan_obj.remove_temp_config(updated_config_file)
    
## same mac and ip address
def test_l2vni_basic_mac_move():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    data.d3tp1_ip_addr = move_host_gw_ip_addr
    data.tp1d3_ip_addr = move_host_ip_addr
    data.tp1d3_mac_addr = move_host_mac_addr

    data.d4tp2_ip_addr = move_host_gw_ip_addr
    data.tp2d4_ip_addr = move_host_ip_addr
    data.tp2d4_mac_addr = move_host_mac_addr
   
    st.banner("Start to test basic mac move ")
    streams_basic, handles_basic = traffic_setup_basic()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    result = vxlan_obj.check_traffic(streams_basic, timeout=5)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed")

    #######################
    ## Connect host to left
    st.banner("Connect the host to the left leaf")
    streams_left, handles_left = traffic_setup_left(streams_basic, handles_basic)
    count = 1
    st.show('leaf0', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    result = vxlan_obj.check_traffic(streams_left, timeout=5)
    traffic_cleanup_left(streams_left, handles_left)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after connecting the host to the left leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P1")

    if leaf0_vlan_member not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in local port of bridge of leaf0: {}'.format(leaf0_output))

    if VXLAN_INTERFACE not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in vxlan port of bridge {} of leaf1: {}'.format(VXLAN_INTERFACE, leaf1_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))

    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf1_output:
    #   traffic_cleanup_basic(streams_basic, handles_basic)
    #   report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))

    st.wait(2)

    #########################
    ## Move the host to right
    st.banner("Move the host to the right leaf")
    streams_right, handles_right = traffic_setup_right(streams_basic, handles_basic)
    count = 1
    st.show('leaf1', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
 
    result = vxlan_obj.check_traffic(streams_right, timeout=5)
    traffic_cleanup_right(streams_right, handles_right)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after moving the host to the right leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf1_vlan_member = vxlan_obj.get_replacement(vars, "D4T1P1")

    if leaf1_vlan_member not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in local port of bridge of leaf1: {}'.format(leaf1_output))

    if VXLAN_INTERFACE not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in vxlan port of bridge {} of leaf0: {}'.format(VXLAN_INTERFACE, leaf0_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))
        traffic_cleanup_basic(streams_basic, handles_basic)
    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf0_output:
    #    report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))

    st.wait(2)

    #############################
    ## Move the host back to left
    st.banner("Move the host back to the left leaf")
    streams_left2, handles_left2 = traffic_setup_left(streams_basic, handles_basic)
    count = 1
    st.show('leaf0', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
 
    result = vxlan_obj.check_traffic(streams_left2, timeout=5)
    traffic_cleanup_left(streams_left2, handles_left2)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after moving the host back to the left leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P1")

    if leaf0_vlan_member not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in local port of bridge of leaf0: {}'.format(leaf0_output))

    if VXLAN_INTERFACE not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in vxlan port of bridge {} of leaf1: {}'.format(VXLAN_INTERFACE, leaf1_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))
    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf1_output:
    #    traffic_cleanup_basic(streams_basic, handles_basic)
    #    report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))

    # Cleanup	
    traffic_cleanup_basic(streams_basic, handles_basic)

    st.report_pass("test_case_passed", "test_l2vni_basic_mac_move passed")

## same mac and ip address with shutdown interface
## MIGSOFTWAR-15520
def test_l2vni_mac_move_with_intfdown():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    data.d3tp1_ip_addr = move_host_gw_ip_addr
    data.tp1d3_ip_addr = move_host_ip_addr
    data.tp1d3_mac_addr = move_host_mac_addr

    data.d4tp2_ip_addr = move_host_gw_ip_addr
    data.tp2d4_ip_addr = move_host_ip_addr
    data.tp2d4_mac_addr = move_host_mac_addr
   
    st.banner("Start to test mac move with interface down")
    streams_basic, handles_basic = traffic_setup_basic()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    result = vxlan_obj.check_traffic(streams_basic, timeout=5)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed")

    #######################
    ## Connect host to left
    st.banner("Connect the host to the left leaf")
    streams_left, handles_left = traffic_setup_left(streams_basic, handles_basic)
    count = 1
    st.show('leaf0', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
 
    result = vxlan_obj.check_traffic(streams_left, timeout=5)
    traffic_cleanup_left(streams_left, handles_left)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after connecting the host to the left leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P1")

    if leaf0_vlan_member not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in bridge of leaf0: {}'.format(leaf0_output))

    if VXLAN_INTERFACE not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in bridge {} of leaf1: {}'.format(VXLAN_INTERFACE, leaf1_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))
    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf1_output:
    #    traffic_cleanup_basic(streams_basic, handles_basic)
    #    report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))

    st.wait(2)

    ######################################
    ## shutdown the interface at left leaf
    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P1")
    st.config(nodes['leaf0'], 'sudo config interface shutdown {}'.format(leaf0_vlan_member))
    ## Move the host to right
    st.banner("Move the host to the right leaf")
    streams_right, handles_right = traffic_setup_right(streams_basic, handles_basic)
    count = 1
    st.show('leaf1', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
 
    result = vxlan_obj.check_traffic(streams_right, timeout=5)
    traffic_cleanup_right(streams_right, handles_right)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after moving the host to the right leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf1_vlan_member = vxlan_obj.get_replacement(vars, "D4T1P1")

    if leaf1_vlan_member not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in bridge of leaf1: {}'.format(leaf1_output))

    if VXLAN_INTERFACE not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in bridge {} of leaf0: {}'.format(VXLAN_INTERFACE, leaf0_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))
    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf0_output:
    #    traffic_cleanup_basic(streams_basic, handles_basic)
    #    report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))

    ## startup the interface
    st.config(nodes['leaf0'], 'sudo config interface startup {}'.format(leaf0_vlan_member))
    st.wait(2)

    #############################
    ## shutdown the interface at right leaf
    leaf1_vlan_member = vxlan_obj.get_replacement(vars, "D4T1P1")
    st.config(nodes['leaf1'], 'sudo config interface shutdown {}'.format(leaf1_vlan_member))
 
    ## Move the host back to left
    st.banner("Move the host back to the left leaf")
    streams_left2, handles_left2 = traffic_setup_left(streams_basic, handles_basic)
    count = 1
    st.show('leaf0', 'sudo ping -c {} {} -q'.format(count, move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
 
    result = vxlan_obj.check_traffic(streams_left2, timeout=5)
    traffic_cleanup_left(streams_left2, handles_left2)
    if not result:
        traffic_cleanup_basic(streams_basic, handles_basic)
        st.report_fail("test_case_failed", "test_l2vni_basic_mac_move traffic failed after moving the host back to the left leaf")

    # Verify Bridge FDB on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo bridge fdb show | grep {}'.format(move_host_mac_addr), skip_tmpl=True, skip_error_check=True)

    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P1")

    if leaf0_vlan_member not in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='MAC is not in bridge of leaf0: {}'.format(leaf0_output))

    if VXLAN_INTERFACE not in leaf1_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf1'], msg='MAC is not in bridge {} of leaf1: {}'.format(VXLAN_INTERFACE, leaf1_output))

    # Verify IP Neighbor on both leafs
    leaf0_output = st.show(nodes['leaf0'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)
    leaf1_output = st.show(nodes['leaf1'], 'sudo ip neighbor show {}'.format(move_host_ip_addr), skip_tmpl=True, skip_error_check=True)

    if "extern_learn" in leaf0_output:
        traffic_cleanup_basic(streams_basic, handles_basic)
        report_fail(nodes['leaf0'], msg='IP neighbor is incorrect on leaf0: {}'.format(leaf0_output))
    # Extern ip neighbor is disabled for now, as we dont support ARP Suppression/A-IRB
    #if "extern_learn" not in leaf1_output:
    #    traffic_cleanup_basic(streams_basic, handles_basic)
    #    report_fail(nodes['leaf1'], msg='IP neighbor is incorrect on leaf1: {}'.format(leaf1_output))

    ## startup the interface
    st.config(nodes['leaf1'], 'sudo config interface startup {}'.format(leaf1_vlan_member))
    st.wait(2)	
    traffic_cleanup_basic(streams_basic, handles_basic)

    st.report_pass("test_case_passed", "test_l2vni_mac_move_with_intfdown passed")


def traffic_setup_basic():
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    int_dict = {"T1D3P2": {"host_ip": data.tp3d3_ip_addr, "gateway": data.d3tp3_ip_addr, "mac" : data.tp3d3_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip_addr, "gateway": data.d4tp4_ip_addr, "mac" : data.tp4d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict)
    ### Generate Traffic item and Ping test , get tg handle, stream id and port handles ###
    # T1D3P2 --- l2vni --- T1D4P2
    stream_list = [("T1D3P2", "T1D4P2")]
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=False)
    return streams, handles

def traffic_setup_left(streams_base, handles_base):
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip_addr, "gateway": data.d3tp1_ip_addr, "mac" : data.tp1d3_mac_addr }}
    handles = vxlan_obj.config_tgen_interface(int_dict)

    handles.update(handles_base)
    ### Generate Traffic item and Ping test , get tg handle, stream id and port handles ###
    # T1D3P1 --- l2vni --- T1D4P2
    stream_list = [("T1D3P1", "T1D4P2")]
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=False)
    return streams, handles

def traffic_cleanup_left(streams, handles):
    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip_addr, "gateway": data.d3tp1_ip_addr, "mac" : data.tp1d3_mac_addr }}
 
    vxlan_obj.cleanup_traffic(int_dict, streams, handles)
 
def traffic_setup_right(streams_base, handles_base):
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    int_dict = {"T1D4P1": {"host_ip": data.tp2d4_ip_addr, "gateway": data.d4tp2_ip_addr, "mac" : data.tp2d4_mac_addr }}
    handles = vxlan_obj.config_tgen_interface(int_dict)
    handles.update(handles_base)
    ### Generate Traffic item and Ping test , get tg handle, stream id and port handles ###
    # T1D3P2 --- l2vni --- T1D4P1
    stream_list = [("T1D3P2", "T1D4P1")]
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=False)
    return streams, handles

def traffic_cleanup_right(streams, handles):
    int_dict = {"T1D4P1": {"host_ip": data.tp2d4_ip_addr, "gateway": data.d4tp2_ip_addr, "mac" : data.tp2d4_mac_addr }}
 
    vxlan_obj.cleanup_traffic(int_dict, streams, handles)
 
def traffic_cleanup_basic(streams, handles):
    int_dict = {"T1D3P2": {"host_ip": data.tp3d3_ip_addr, "gateway": data.d3tp3_ip_addr, "mac" : data.tp3d3_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip_addr, "gateway": data.d4tp4_ip_addr, "mac" : data.tp4d4_mac_addr}}
 
    vxlan_obj.cleanup_traffic(int_dict, streams, handles)

def router_preconfig_cleanup():
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=True, conf=True)
    else:
        st.config(node, config, skip_error_check=True, conf=True)

def config_static(node, config_domain, add=True):
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(node, config_list[node][config_domain]['config'], domain)
        else:
            config_node(node, config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)
