#############################################################################
#Script Title : 
#Author       : 
#Mail-id      : 
#############################################################################


import pytest
from spytest import st

import apis.system.port as port_obj
import apis.system.reboot as reboot_obj

import apis.system.Calnex.paragon as clx_obj
from ptp_vars_new import data
import ptp_lib as loc_lib


@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue():

    st.log('Define Common config, including TGEN related, if any')
    ts_name = 'S4'
    loc_lib.initialize_topology() 
    clx_obj.disconnect()
    if not loc_lib.retry_api(loc_lib.connect_to_calnex):
        st.log('Could not connect to Calnex...Exiting')
        exit(0)

    st.log('Set the config profile to L3')
    loc_lib.configure_profile(profile='l3')
    st.log('Configure topology for L3')
    loc_lib.config_l3_topo(config='yes')    
    loc_lib.config_static_routing(config='yes')    
    if not loc_lib.verify_ping():
        st.log('Topology bringup Failed')
        st.report_fail('test_case_failed')

    yield
    st.log('Define Common cleanup, including TGEN related, if any')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])
    st.log('Epilogue: Cleanup L3 config')
    loc_lib.config_static_routing(config='no')
    loc_lib.config_l3_topo(config='no')
    st.log('Epilogue: Terminate Calnex connection')
    clx_obj.disconnect()
    port_obj.set_status(data.d1, [data.d1_d3_intf_1],'startup')
    port_obj.set_status(data.d4, [data.d4_d3_intf_1],'startup')
    reboot_obj.config_save(data.d1)
    reboot_obj.config_save(data.d1,shell='vtysh')


@pytest.fixture(scope="function")
def cleanup_ptp_ipv4_MC_S4():
    ts_name = 'S4'
    port_obj.set_status(data.d1, [data.d1_d3_intf_1],'shutdown')
    port_obj.set_status(data.d4, [data.d4_d3_intf_1],'shutdown')
    for i in data[ts_name]['dut_list']:
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list_all[i]
        data[ts_name]['disable_ptp_del_port'][i].pop('mode')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])

@pytest.mark.sanity
def test_ptp_ipv4_MC_S4(cleanup_ptp_ipv4_MC_S4):

    #Prepare test data
    ts_name = 'S4'
    data.ptp_port_list = [
        [data.d1_d2_intf_1, data.d1_clx_intf_1],
        [data.d2_d1_intf_1, data.d2_d4_intf_1],
        [],
        [data.d4_d2_intf_1, data.d4_clx_intf_1]
    ]

    for i in data[ts_name]['dut_list']:
        data[ts_name]['config_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp_disable'][i]['port_list'] = data.ptp_port_list[i]


    data[ts_name]['verify_ptp_clock'][0]['clock_id'] = data.clock_id_list[0]
    data[ts_name]['verify_ptp_clock'][3]['clock_id'] = data.clock_id_list[3]

    data[ts_name]['verify_ptp_parent'][3]['parent_clock_id'] = data.clock_id_list[0]

    #Connect to Calnex, Recall config file and Enable Master/Slave Emulation
    if not loc_lib.retry_api(loc_lib.load_config_on_calnex, filename=data[ts_name]['clx_filename']):
        st.log('Could not load config file to Calnex...Exiting')
        exit(0)

    #DUT Configurations - Enable ptp on all devices TC#1
    tc_id = 1
    st.log('Enable PTP on all devices')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['config_ptp'])

    # Verification
    final_result = 0
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)
   
    #Flap Master port TC# 2
    tc_id = 2
    st.log('Flap the slave port of transparent-clock on device 2')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'startup')

    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - config_reload TC#3
    tc_id = 3
    reboot_obj.config_save(data.d2)
    reboot_obj.config_save(data.d2,shell='vtysh')
    reboot_obj.config_reload(data.d2)

    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - Disable ptp on all devices - TC#4
    tc_id = 4
    st.log('Disable PTP on all devices')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp'])

    result = 0
    if not loc_lib.retry_api(loc_lib.verify_ptp_on_duts, api_name='verify_ptp', param_dict_list=data[ts_name]['verify_ptp_disable']):
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_ptp_on_duts, api_name='verify_ptp_clock', param_dict_list=data[ts_name]['disable_ptp']):
        result += 1

    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['enable_ptp'])

    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #Flap Master port TC# 5
    tc_id = 5
    st.log('Flap the master port of transparent-clock on device 2')
    port_obj.set_status(data.d2, [data.d2_d4_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d4_intf_1],'startup')

    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)
   
    if final_result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.print_debug()
        st.report_fail('test_case_failed')



@pytest.fixture(scope="function")
def cleanup_ptp_ipv6_MC_S5():
    ts_name = 'S5'
    port_obj.set_status(data.d1, [data.d1_d3_intf_1],'shutdown')
    port_obj.set_status(data.d4, [data.d4_d3_intf_1],'shutdown')
    for i in data[ts_name]['dut_list']:
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list_all[i]
        data[ts_name]['disable_ptp_del_port'][i].pop('mode')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])

@pytest.mark.sanity
def test_ptp_ipv6_MC_S5(cleanup_ptp_ipv6_MC_S5):
    #Prepare test data
    ts_name = 'S5'
    data.ptp_port_list = [
        [data.d1_d2_intf_1, data.d1_clx_intf_1],
        [data.d2_d1_intf_1, data.d2_d4_intf_1],
        [],
        [data.d4_d2_intf_1, data.d4_clx_intf_1]
    ]

    for i in data[ts_name]['dut_list']:
        data[ts_name]['config_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp_disable'][i]['port_list'] = data.ptp_port_list[i]


    data[ts_name]['verify_ptp_clock'][0]['clock_id'] = data.clock_id_list[0]
    data[ts_name]['verify_ptp_clock'][3]['clock_id'] = data.clock_id_list[3]

    data[ts_name]['verify_ptp_parent'][3]['parent_clock_id'] = data.clock_id_list[0]

    #Connect to Calnex, Recall config file and Enable Master/Slave Emulation
    if not loc_lib.retry_api(loc_lib.load_config_on_calnex, filename=data[ts_name]['clx_filename']):
        st.log('Could not load config file to Calnex...Exiting')
        exit(0)

    #DUT Configurations - Enable ptp on all devices TC#1
    tc_id = 1
    st.log('Enable PTP on all devices')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['config_ptp'])

    # Verification
    final_result = 0
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    # Flap Slave port     
    tc_id = 2
    st.log('Flap the slave port of boundary-clock on DUT1')
    port_obj.set_status(data.d1, [data.d1_clx_intf_1],'shutdown')
    port_obj.set_status(data.d1, [data.d1_clx_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    # Flap Master port     
    tc_id = 3
    st.log('Flap the master port of boundary-clock on DUT1')
    port_obj.set_status(data.d4, [data.d4_clx_intf_1],'shutdown')
    port_obj.set_status(data.d4, [data.d4_clx_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - config_reload TC#4
    tc_id = 4
    reboot_obj.config_save(data.d1)
    reboot_obj.config_save(data.d1,shell='vtysh')
    reboot_obj.config_reload(data.d1)
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - Disable ptp on all devices - TC#5
    tc_id = 5
    st.log('Disable PTP on all devices')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp'])
    
    result = 0
    if not loc_lib.retry_api(loc_lib.verify_ptp_on_duts, api_name='verify_ptp', param_dict_list=data[ts_name]['verify_ptp_disable']):
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_ptp_on_duts, api_name='verify_ptp_clock', param_dict_list=data[ts_name]['disable_ptp']):
        result += 1

    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['enable_ptp'])

    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #Flap Master port TC# 6
    tc_id = 6
    st.log('Flap the master port of transparent-clock on device 2')
    port_obj.set_status(data.d2, [data.d2_d4_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d4_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)
   
    #Flap Master port TC# 7
    tc_id = 7
    st.log('Flap the slave port of transparent-clock on device 2')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    if final_result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.print_debug()
        st.report_fail('test_case_failed')
