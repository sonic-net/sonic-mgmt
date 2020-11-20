#############################################################################
#Script Title : 
#Author       : 
#Mail-id      : 
#############################################################################


import pytest
from spytest import st

import apis.system.basic as basic_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj

import apis.system.Calnex.paragon as clx_obj
from ptp_vars_new import data
import ptp_lib as loc_lib
import re



@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue():

    st.log('Define Common config, including TGEN related, if any')
    ts_name = 'S2'
    loc_lib.initialize_topology() 
    data.skip_traffic = True
    for i in range(len(data.my_dut_list)):
        if re.search(r'base|cloud',data.dut_version_list[i], re.I):
            st.report_unsupported('test_execution_skipped','Unsupported for software version {}'.format(data.dut_version_list[i]))
    
    clx_obj.disconnect()
    if not loc_lib.retry_api(loc_lib.connect_to_calnex):
        st.log('Could not connect to Calnex...Exiting')
        exit(0)
    st.log('Set the config profile to L2')
    loc_lib.configure_profile(profile='l2')
    if data.alias_mode == 'alias':
        loc_lib.configure_alias_mode()
    st.log('Shutdown all ports except the needed ones')
    loc_lib.shutdown_all_but_needed_ports()
    #st.log('Config spanning tree on all DUTs')
    #loc_lib.configure_stp_all(stp_type='pvst',stp_mode='enable')
    st.log('Need to breakout port after changing profile')
    loc_lib.configure_breakout_ports()
    st.log('Remove PTP ports from default VLAN')
    loc_lib.remove_ptp_ports_from_default_vlan()
    st.log('Bring up PTP Ports')
    loc_lib.bring_up_ptp_ports()
    #For STP to converge. will move to rpvst once that is stable
    #st.wait(30)
    st.wait(3)
    #loc_lib.show_stp_all()
    loc_lib.config_traffic(traffic_type='l2')

    yield
    st.log('Define Common cleanup, including TGEN related, if any')
    loc_lib.control_traffic(action='stop')
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])
    loc_lib.configure_ptp_default()
    st.log('Epilogue: Terminate Calnex connection')
    clx_obj.disconnect()
    reboot_obj.config_save(data.d2)
    reboot_obj.config_save(data.d2,shell='vtysh')


@pytest.fixture(scope="function")
def cleanup_ptp_L2_MC_S2():
    ts_name = 'S2'
    loc_lib.control_traffic(action='stop')
    for i in range(4):
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list_all[i]
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])
    loc_lib.configure_ptp_default()



@pytest.mark.sanity
def test_ptp_L2_MC_S2(cleanup_ptp_L2_MC_S2):

    #Prepare test data
    ts_name = 'S2'
    data.ptp_port_list = [
        [data.d1_d2_intf_1, data.d1_d3_intf_1, data.d1_clx_intf_1],
        [data.d2_d1_intf_1, data.d2_d4_intf_1],
        [data.d3_d1_intf_1, data.d3_d4_intf_1],
        [data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_clx_intf_1]
    ]

    for i in range(4):
        if not data.ptp_port_list[i]: 
            continue              
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
    final_result  = 0
    loc_lib.control_traffic(action='run',clear_stats='yes')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id, verify_traffic=1)
    #DUT Configurations - STP failover to alternate path then failback TC#2
    tc_id = 2
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

    #Flap Slave port TC# 6
    tc_id = 6
    st.log('Flap the slave port of transparent-clock on device 2')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id, verify_traffic=1)

    if final_result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.print_debug()
        st.report_fail('test_case_failed')



@pytest.fixture(scope="function")
def cleanup_ptp_L2_UC_S1():
    ts_name = 'S1'
    loc_lib.control_traffic(action='stop')
    for i in range(4):
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list_all[i]
    loc_lib.configure_ptp_on_duts('config_ptp', data[ts_name]['disable_ptp_del_port'])
    loc_lib.configure_ptp_default()



@pytest.mark.sanity
def test_ptp_L2_UC_S1(cleanup_ptp_L2_UC_S1):

    ts_name = 'S1'
    data.ptp_port_list = [
        [data.d1_d2_intf_1, data.d1_d3_intf_1, data.d1_clx_intf_1],
        [data.d2_d1_intf_1, data.d2_d4_intf_1],
        [data.d3_d1_intf_1, data.d3_d4_intf_1],
        [data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_clx_intf_1]
    ]

    for i in range(4):
        if not data.ptp_port_list[i]:
            continue
        data[ts_name]['config_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['disable_ptp_del_port'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp_disable'][i]['port_list'] = data.ptp_port_list[i]
        data[ts_name]['verify_ptp_clock'][i]['clock_id'] = data.clock_id_list[i]

    data[ts_name]['verify_ptp_parent'][1]['parent_clock_id'] = data.clock_id_list[0]
    data[ts_name]['verify_ptp_parent'][2]['parent_clock_id'] = data.clock_id_list[0]
    data[ts_name]['verify_ptp_parent'][3]['parent_clock_id'] = data.clock_id_list[1]

    data.clx_d1_intf_1_mac = 'a0:00:00:00:00:01'
    data.d1_d2_intf_1_mac = basic_obj.get_ifconfig(data.d1, data.d1_d2_intf_1)[0]['mac'] 
    data.d1_d3_intf_1_mac = basic_obj.get_ifconfig(data.d1, data.d1_d3_intf_1)[0]['mac'] 
    data.d2_d1_intf_1_mac = basic_obj.get_ifconfig(data.d2, data.d2_d1_intf_1)[0]['mac'] 
    data.d2_d4_intf_1_mac = basic_obj.get_ifconfig(data.d2, data.d2_d4_intf_1)[0]['mac'] 
    data.d3_d1_intf_1_mac = basic_obj.get_ifconfig(data.d3, data.d3_d1_intf_1)[0]['mac'] 
    data.d3_d4_intf_1_mac = basic_obj.get_ifconfig(data.d3, data.d3_d4_intf_1)[0]['mac'] 
    data.d4_d2_intf_1_mac = basic_obj.get_ifconfig(data.d4, data.d4_d2_intf_1)[0]['mac'] 
    data.d4_d3_intf_1_mac = basic_obj.get_ifconfig(data.d4, data.d4_d3_intf_1)[0]['mac'] 
    data.clx_d4_intf_1_mac = 'd0:00:00:00:00:01'

    for i,port_list,addr_list in zip(data[ts_name]['dut_list'], [[data.d1_clx_intf_1, data.d1_d2_intf_1, data.d1_d3_intf_1], [data.d2_d1_intf_1, data.d2_d4_intf_1], [data.d3_d1_intf_1, data.d3_d4_intf_1], [data.d4_d2_intf_1, data.d4_d3_intf_1, data.d4_clx_intf_1]], [[data.clx_d1_intf_1_mac, data.d2_d1_intf_1_mac, data.d3_d1_intf_1_mac], [data.d1_d2_intf_1_mac, data.d4_d2_intf_1_mac], [data.d1_d3_intf_1_mac, data.d4_d3_intf_1_mac], [data.d2_d4_intf_1_mac, data.d3_d4_intf_1_mac, data.clx_d4_intf_1_mac]]):
        data[ts_name]['config_ptp'][i]['master_table_intf_list'] = port_list
        data[ts_name]['config_ptp'][i]['master_table_addr_list'] = addr_list

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
    loc_lib.control_traffic(action='run',clear_stats='yes')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id, verify_traffic=1)

    #Flap Slave port TC# 2
    tc_id = 2
    st.log('Flap the slave port of boundary clock on DUT1') 
    port_obj.set_status(data.d1, [data.d1_clx_intf_1],'shutdown')
    port_obj.set_status(data.d1, [data.d1_clx_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - STP failover to alternate path then failback TC#3
    tc_id = 3
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'shutdown')
    port_obj.set_status(data.d2, [data.d2_d1_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id)

    #DUT Configurations - config_reload TC#4
    tc_id = 4
    reboot_obj.config_save(data.d2)
    reboot_obj.config_save(data.d2,shell='vtysh')
    reboot_obj.config_reload(data.d2)
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
    st.log('Flap the master port of boundary-clock on DUT4')
    port_obj.set_status(data.d4, [data.d4_clx_intf_1],'shutdown')
    port_obj.set_status(data.d4, [data.d4_clx_intf_1],'startup')
    final_result += loc_lib.verify_ptp_test_result(ts_name, tc_id, verify_traffic=1)

    if final_result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.print_debug()
        st.report_fail('test_case_failed')



