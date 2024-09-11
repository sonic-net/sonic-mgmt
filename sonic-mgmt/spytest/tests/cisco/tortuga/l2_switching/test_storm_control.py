import pytest
from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import tortuga_common_utils as common_obj
import apis.system.storm_control as scapi
import apis.system.reboot as reboot

data_glob = SpyTestDict()
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
        st.log("Remove any stale vlan configs")
        vlan_obj.clear_vlan_configuration([data_glob.leaf0])
        st.log("Remove any stale storm control configs")
        storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
        for stc_type in storm_control_type:
            if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type=stc_type):
                common_obj.config_storm_control(data_glob.leaf0, stc_type, "del", data_glob.intf_list[0], data_vid_10.kbps)



##Vlan id 10 stream config
data_vid_10 = SpyTestDict()

data_vid_10.vlan = "10"
data_vid_10.t1d3_ip_gateway = "110.0.1.2"
data_vid_10.t1d4_ip_gateway = "110.0.1.1"

data_vid_10.t1d3_ip_addr = "110.0.1.1"
data_vid_10.t1d3_mac_addr = "00:0A:03:00:11:01"

data_vid_10.t1d4_ip_addr = "110.0.1.2"
data_vid_10.t1d4_mac_addr = "00:0A:04:00:12:01"

# Set dest mac address for unknown unicast traffic
data_vid_10.t1d3_dest_mac_addr = "00:0A:03:00:00:01"
data_vid_10.t1d4_dest_mac_addr = "00:0A:03:00:00:02"

data_vid_10.transmit_mode = 'continuous'
data_vid_10.frame_size = 68
data_vid_10.traffic_run_time = 10
data_vid_10.duration = 10
data_vid_10.tgen_stats_threshold = 20

@pytest.fixture(scope="module", autouse=True)
def initial_tgen_setup():
    #Check whether spytest is run on HW or SIM
    dut_type = common_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data_vid_10.tgen_rate_pps = '500'
        data_vid_10.kbps = 200
    else:
        data_vid_10.tgen_rate_pps = '50000'
        data_vid_10.kbps = 5000

    data_vid_10.packets = (data_vid_10.kbps*1024)/((data_vid_10.frame_size-4)*8)
    data_vid_10.bum_deviation = int(0.10 * data_vid_10.packets)
    data_vid_10.lower_pkt_count = int(data_vid_10.packets - data_vid_10.bum_deviation)
    data_vid_10.higher_pkt_count = int(data_vid_10.packets + data_vid_10.bum_deviation)

##L2 stream config

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars

    st.ensure_min_topology("D3T1:2")
    vars = st.get_testbed_vars()

    data_glob.leaf0 = vars.D3
    data_glob.intf_list = [vars.D3T1P1, vars.D3T1P2]
    data_glob.vlan = ['10']

    yield 'setup_teardown_basic'


#
# Single Vlan with untagged ports only
#
# |--------------------|  |---------------------|
# |      (10.0.1.1) P1-|--|-P1-----Vlan10--|    |
# |                    |  |                |    |
# |         T1         |  |          D3    |    |
# |                    |  |                |    |
# |      (10.0.1.2) P2-|--|-P2-----Vlan10--|    |
# |--------------------|  |---------------------|
#
@pytest.fixture()
def setup_teardown_stc(setup_teardown_basic):
    if not data_glob.pre_config:
        vlan_obj.create_vlan(data_glob.leaf0, data_glob.vlan)
        vlan_obj.add_vlan_member(data_glob.leaf0, data_glob.vlan[0], data_glob.intf_list, tagging_mode=False)
        data_glob.pre_config = True

    yield 'setup_teardown_stc'

    if data_glob.function_unconfig:
        return
    vlan_obj.delete_vlan_member(data_glob.leaf0, data_glob.vlan[0], data_glob.intf_list, tagging_mode=False)
    vlan_obj.delete_vlan(data_glob.leaf0, data_glob.vlan)


def test_BUM_traffic(setup_teardown_stc):
    '''
    Test Case Description :
        Verify Traffic : Storm Control for broadcast, unknown-multicast and unknown-unicast.
        Verify Threshold update using show CLI.
        Verify unknown unicast traffic is not affected,
        when broadcast and unknown-multicast are still configured.
        Verify Storm control delete for every type.
    '''

    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]

    st.log("add storm control of different types with same threshold on intf {}.".format(data_glob.intf_list[0]))
    for stc_type in storm_control_type:
        common_obj.config_storm_control(data_glob.leaf0, stc_type, "add", data_glob.intf_list[0], data_vid_10.kbps)
        if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type=stc_type, rate=data_vid_10.kbps):
            st.report_fail('msg', "storm_control config verify failed for type {} on intf {} on node {}.".format(stc_type, data_glob.intf_list[0], data_glob.leaf0))
        else:
            st.log("storm_control config verify successful for type {} on intf {} on node {}.".format(stc_type, data_glob.intf_list[0], data_glob.leaf0))

    traffic_types = ['broadcast', 'multicast', 'unicast']

    st.log("Test Storm Control traffic")
    for traffic_type in traffic_types:
        handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D3P2', traffic_type, True, is_l2=True, traffic_type="raw")
        common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
        common_obj.traffic_stop(handles, traffic_type="raw")
        if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, rate_limit=True, traffic_type="raw"):
            st.log("Traffic verification for Storm control type {} Passed".format(storm_control_type[traffic_types.index(traffic_type)]))
        else:
            st.report_fail('failed_traffic_verification'," for type {}.".format(storm_control_type[traffic_types.index(traffic_type)]))
        if traffic_type != 'unicast':
            common_obj.traffic_cleanup(handles)

    st.log("Verify threshold update")
    common_obj.config_storm_control(data_glob.leaf0, "broadcast", "add", data_glob.intf_list[0], data_vid_10.kbps*3)
    if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="broadcast", rate=data_vid_10.kbps*3):
        st.report_fail('msg', "storm_control update verify failed for type {} on intf {} on node {}.".format("broadcast", data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("storm_control update verify successful for type {} on intf {} on node {}.".format("broadcast", data_glob.intf_list[0], data_glob.leaf0))

    st.log("Verify other traffic is not affected")
    st.log("Delete Unknown Unicast STC on both leaves")
    common_obj.config_storm_control(data_glob.leaf0, "unknown-unicast", "del", data_glob.intf_list[0], data_vid_10.kbps)
    if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="unknown-unicast", rate=data_vid_10.kbps):
        st.report_fail('msg', "storm_control config still present for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("storm_control config removal successful for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))

    st.log("Verify Unknown Unicast traffic")
    common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
    common_obj.traffic_stop(handles, traffic_type="raw")
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, traffic_type="raw"):
        st.log("Traffic verification for unknown unicast Passed")
    else:
        st.report_fail('failed_traffic_verification'," for unknown unicast.")

    #Unknown Unicast already deleted
    storm_control_type = ["broadcast", "unknown-multicast"]
    st.log("Cleanup")
    st.log("Del storm control of different types with same threshold on intf {}.".format(data_glob.intf_list[0]))
    for stc_type in storm_control_type:
        common_obj.config_storm_control(data_glob.leaf0, stc_type, "del", data_glob.intf_list[0], data_vid_10.kbps)
        if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type=stc_type, rate=data_vid_10.kbps):
            st.report_fail('msg', "storm_control config still present for type {} on intf {} on node {}.".format(stc_type, data_glob.intf_list[0], data_glob.leaf0))
        else:
            st.log("storm_control config removal successful for type {} on intf {} on node {}.".format(stc_type, data_glob.intf_list[0], data_glob.leaf0))

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')


def test_unrelated_traffic(setup_teardown_stc):
    '''
    Test Case Description :
        Verify Unrelated traffic is not affected.
        Known unicast traffic should not be affected,
        when unknown-unicast Storm control is applied on ingress.
    '''

    st.log("Configure unknown unicast stc")
    common_obj.config_storm_control(data_glob.leaf0, "unknown-unicast", "add", data_glob.intf_list[0], data_vid_10.kbps)
    if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="unknown-unicast", rate=data_vid_10.kbps):
        st.report_fail('msg', "unknown-unicast storm_control config failed on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("unknown-unicast storm_control config successful on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))

    # Set mac address for known unicast traffic
    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr

    st.log("Verify known unicast traffic")
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D3P2', 'unicast', True, is_l2=True, traffic_type="raw", verify_ping=False)
    common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
    common_obj.traffic_stop(handles, traffic_type="raw")
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, traffic_type="raw"):
        st.log("Traffic verification for known unicast Passed")
    else:
        st.report_fail('failed_traffic_verification'," for known unicast.")
    common_obj.traffic_cleanup(handles)

    # Set back mac address for unknown unicast traffic
    data_vid_10.t1d3_dest_mac_addr = "00:0A:03:00:00:01"
    data_vid_10.t1d4_dest_mac_addr = "00:0A:03:00:00:02"

    st.log("Cleanup")
    common_obj.config_storm_control(data_glob.leaf0, "unknown-unicast", "del", data_glob.intf_list[0], data_vid_10.kbps)
    if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="unknown-unicast"):
        st.report_fail('msg', "storm_control config still present for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("storm_control config removal successful for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))

    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')


def test_incremental_bps(setup_teardown_stc):
    '''
    Test Case Description :
        Verify traffic for incremental updates of threshold from 5000 kbps to 20000 kbps on HW.
    '''

    st.log("Configure unknown unicast traffic")
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D3P2', 'unicast', True, is_l2=True, traffic_type="raw")

    temp_pkts = data_vid_10.packets
    temp_bum_deviation = data_vid_10.bum_deviation
    temp_lower_pkt_count = data_vid_10.lower_pkt_count
    temp_higher_pkt_count = data_vid_10.higher_pkt_count

    for kbps_value in (data_vid_10.kbps*i for i in range(1,5)):
        st.log("Configure unknown unicast stc with threshold {}.".format(kbps_value))
        common_obj.config_storm_control(data_glob.leaf0, "unknown-unicast", "add", data_glob.intf_list[0], kbps_value)
        if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="unknown-unicast", rate=kbps_value):
            st.report_fail('msg', "unknown-unicast storm_control config with threshold {} failed on intf {} on node {}.".format(kbps_value, data_glob.intf_list[0], data_glob.leaf0))
        else:
            st.log("unknown-unicast storm_control config with threshold {} successful on intf {} on node {}.".format(kbps_value, data_glob.intf_list[0], data_glob.leaf0))

        data_vid_10.packets = (kbps_value*1024)/(data_vid_10.frame_size*8)
        data_vid_10.bum_deviation = int(0.10 * data_vid_10.packets)
        data_vid_10.lower_pkt_count = int(data_vid_10.packets - data_vid_10.bum_deviation)
        data_vid_10.higher_pkt_count = int(data_vid_10.packets + data_vid_10.bum_deviation)
        st.log("Verify traffic")
        common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
        common_obj.traffic_stop(handles, traffic_type="raw")
        if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, rate_limit=True, traffic_type="raw"):
            st.log("Traffic verification for Unknown Unicast Storm control with threshold {} Passed".format(kbps_value))
        else:
            st.report_fail('failed_traffic_verification'," for unknown unicast with threshold {}.".format(kbps_value))

    data_vid_10.packets = temp_pkts
    data_vid_10.bum_deviation = temp_bum_deviation
    data_vid_10.lower_pkt_count = temp_lower_pkt_count
    data_vid_10.higher_pkt_count = temp_higher_pkt_count

    st.log("Cleanup")
    common_obj.config_storm_control(data_glob.leaf0, "unknown-unicast", "del", data_glob.intf_list[0], data_vid_10.kbps)
    if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="unknown-unicast"):
        st.report_fail('msg', "storm_control config still present for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("storm_control config removal successful for type {} on intf {} on node {}.".format("unknown-unicast", data_glob.intf_list[0], data_glob.leaf0))


    data_glob.function_unconfig = True
    st.report_pass('test_case_passed')


def test_fast_and_express_reboot(setup_teardown_stc):
    '''
    Test Case Description :
        Verify Fast & Express reboot support for Storm control configs.
        Verify Traffic after Fast & Express reboot.
    '''

    st.log("Configure broadcast stc")
    common_obj.config_storm_control(data_glob.leaf0, "broadcast", "add", data_glob.intf_list[0], data_vid_10.kbps)
    if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="broadcast", rate=data_vid_10.kbps):
        st.report_fail('msg', "broadcast storm_control config failed on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("broadcast storm_control config successful on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))

    st.log("Save the current config")
    reboot.config_save(data_glob.leaf0)

    st.log("Initiate Fast reboot")
    reboot.dut_reboot(data_glob.leaf0, method='fast')

    st.log("Verify config after Fast Reboot")
    if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="broadcast", rate=data_vid_10.kbps):
        st.report_fail('msg', "broadcast storm_control config  verification after fast reboot failed on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("broadcast storm_control config verification after fast reboot successful on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))

    st.log("Verify known unicast traffic")
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D3P2', 'broadcast', True, is_l2=True, traffic_type="raw")
    common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
    common_obj.traffic_stop(handles, traffic_type="raw")
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, rate_limit=True, traffic_type="raw"):
        st.log("Traffic verification for broadcast after fast reboot Passed")
    else:
        st.report_fail('failed_traffic_verification'," for broadcast after fast reboot.")

    st.log("Initiate Express reboot")
    st.config(data_glob.leaf0, "express-reboot", conf=False, max_time=1000, min_time=30, skip_error_check=True, expect_reboot=True)

    st.log("Verify config after Express Reboot")
    if not scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="broadcast", rate=data_vid_10.kbps):
        st.report_fail('msg', "broadcast storm_control config  verification after express reboot failed on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("broadcast storm_control config verification after express reboot successful on intf {} on node {}.".format(data_glob.intf_list[0], data_glob.leaf0))

    st.log("Verify known unicast traffic")
    common_obj.traffic_start(handles, data_vid_10, data_vid_10, traffic_type="raw")
    common_obj.traffic_stop(handles, traffic_type="raw")
    if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D3P2', data_vid_10, data_vid_10, rate_limit=True, traffic_type="raw"):
        st.log("Traffic verification for broadcast after express reboot Passed")
    else:
        st.report_fail('failed_traffic_verification'," for broadcast after express reboot.")

    st.log("Cleanup")
    common_obj.config_storm_control(data_glob.leaf0, "broadcast", "del", data_glob.intf_list[0], data_vid_10.kbps)
    if scapi.verify_config(data_glob.leaf0, interface_name=data_glob.intf_list[0], type="broadcast"):
        st.report_fail('msg', "storm_control config still present for type {} on intf {} on node {}.".format("broadcast", data_glob.intf_list[0], data_glob.leaf0))
    else:
        st.log("storm_control config removal successful for type {} on intf {} on node {}.".format("broadcast", data_glob.intf_list[0], data_glob.leaf0))

    data_glob.function_unconfig = False
    st.report_pass('test_case_passed')