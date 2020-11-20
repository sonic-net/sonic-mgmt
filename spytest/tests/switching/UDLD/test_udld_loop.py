##########################################################################################
# Title: UDLD Script with TX and RX loop
# Author: Chandra Sekhar Reddy <Chandra.vedanaparthi@broadcom.com>
##########################################################################################

import pytest

from spytest import st, SpyTestDict

import apis.switching.vlan as vlan
import apis.system.interface as intf
import apis.switching.udld as udld
import apis.system.reboot as reboot_api
from udld_vars import *

import utilities.common as utils
import utilities.parallel as pll

data = SpyTestDict()

def print_log(message,alert_type="LOW"):
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start = "\n======================================================================================\n"
    log_end =   "\n======================================================================================"
    log_delimiter ="\n###############################################################################################\n"

    if alert_type == "HIGH":
        st.log("{} {} {}".format(log_delimiter,message,log_delimiter))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{} {} {}".format(log_start,message,log_start))

def initialize_topology():
    global dut_list
    global dut1
    global dut2
    global dut3
    global dut_reload
    global udld_global
    global udld_int
    global udld_neighbor
    global vars
    ### Verify Minimum topology requirement is met
    vars = st.ensure_min_topology("D1D2:1", "D2D3:2")

    print_log("Start Test with topology D1D2:1,D2D3:2",'HIGH')

    print_log(
        "Test Topology Description\n==============================\n\
        - Test script uses UDLD RX and TX loop topology with D1,D2 and D3.\n\
        - Between DUT1 to DUT2 one link and DUT2 to DUT3 2 link.\n\
        - Access Vlan 10 between DUT1,DUT2 and DUT3\n\
        In addition, each test case will have trigger configs/unconfigs and corresponding streams used",'HIGH')


    ### Initialize DUT variables and ports
    dut_list = st.get_dut_names()
    dut1 = dut_list[0]
    dut2 = dut_list[1]
    dut3 = dut_list[2]
    dut_reload = [dut_list[0]]

    udld_global = {}
    udld_global.update({
        dut1: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_mode_agg': 'Aggressive',
            'udld_message_time': 1,
            'udld_multiplier': 3
        }
    })
    udld_global.update({
        dut2: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_mode_agg': 'Aggressive',
            'udld_message_time': 1,
            'udld_multiplier': 3
        }
    })

    udld_int = {}
    udld_int.update({
        dut1: {
            'udld_int': [vars.D1D2P1],
            'udld_enable': 'yes',
            'config': 'yes',
            'neighbor_state': ['Bidirectional'],
            'neighbor_state_norm': ['Shutdown'],
            'neighbor_state_agg': ['Shutdown']
        }
    })
    udld_int.update({
        dut2: {
            'udld_int': [vars.D2D1P1],
            'udld_enable': 'yes',
            'config': 'yes',
            'neighbor_state': ['Bidirectional'],
            'neighbor_state_norm': ['Shutdown'],
            'neighbor_state_agg': ['Shutdown']
        }
    })
    udld_neighbor = {}
    udld_neighbor.update({
        dut1: {
            'local_port': [vars.D1D2P1],
            'device_name': ['sonic'],
            'remote_port': [vars.D2D1P1],
            'neighbor_state': ['Bidirectional']
        }
    })
    udld_neighbor.update({
        dut2: {
            'local_port': [vars.D2D1P1],
            'device_name': ['sonic'],
            'remote_port': [vars.D1D2P1],
            'neighbor_state': ['Bidirectional']
        }
    })

def validate_topology():
    # Enable all links in the topology and verify links up
    dut_port_dict = {}
    for dut in dut_list:
        port_list = st.get_dut_links_local(dut, peer=None, index=None)
        dut_port_dict[dut] = port_list
    #Usage: exec_all(use_threads, list_of_funcs)
    [result, exceptions] = utils.exec_all(True, [[intf.interface_operation, dut, dut_port_dict[dut], 'startup',False]
                                          for dut in dut_port_dict.keys()])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    return False if False in result else True


@pytest.fixture(scope="module",autouse=True)
def prologue_epilogue():
    print_log("Starting to initialize and validate topology...",'MED')
    initialize_topology()
    validate_topology()
    api_list = []
    api_list.append([udld_module_config])
    [result, exceptions] = utils.exec_all(True, api_list, True)
    if not all(i is None for i in exceptions):
        result.append(False)
        print_log(exceptions)
    if False in result:
        st.report_fail("module_config_failed", "prolog")
        return

    yield
    api_list = []
    api_list.append([udld_module_unconfig])
    [result, exceptions] = utils.exec_all(True, api_list, True)
    if not all(i is None for i in exceptions):
        result.append(False)
        print_log(exceptions)
    if False in result:
        st.report_fail("module_unconfig_failed", "epilog")

def udld_module_config():
    '''
    - Configure vlans 10 on DUT1 to DUT2 to DUT3
    - Configure the ports to add in acess vlan 10
    - Configure UDLD global and interface

    '''
    ver_flag = True
    print_log("Starting UDLD Module Configurations...\n\
    STEPS:\n\
    - Configure vlans 10 on DUT1 to DUT2 to DUT3\n\
    - Configure the ports to add in acess vlan 10\n\
    - Configure UDLD global and interface.", "HIGH")

    ### Create Access VLAN on all DUTs
    utils.exec_all(True,[[vlan.create_vlan, dut, trunk_base_vlan] for dut in dut_list])


    ### Add Access ports between DUT1<->DUT2<->DUT3<->DUT1 in vlan 10
    api_list = []
    api_list.append([vlan.add_vlan_member, dut1, trunk_base_vlan, [vars.D1D2P1]])
    api_list.append([vlan.add_vlan_member, dut2, trunk_base_vlan, [vars.D2D1P1,vars.D2D3P1,vars.D2D3P2]])
    api_list.append([vlan.add_vlan_member, dut3, trunk_base_vlan, [vars.D3D2P1,vars.D3D2P2]])
    utils.exec_all(True, api_list)

    [result, exceptions] = pll.exec_parallel(True, [dut2, dut3], udld.udld_cfg_ebtables_rule, [{'add': False}, {'add': False}])
    if not all(i is None for i in exceptions):
        result.append(False)
        print_log(exceptions)
    if False in result:
        print_log('UDLD Delete ebtables rule FAILED','ERROR')
        ver_flag = False

    ###Enable UDLD global
    dict1 = {'udld_enable': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.config_udld_global, [dict1])

    ###Enable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': udld_int[dut1]['udld_enable'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.config_intf_udld, [dict1])
    return ver_flag


def udld_module_unconfig():
    ver_flag = True
    print_log("Starting UDLD Module UnConfigurations...", "HIGH")

    ### Remove the trunk ports between DUT1<->DUT2<->DUT3 in vlan 10
    api_list = []
    api_list.append([vlan.delete_vlan_member, dut1, trunk_base_vlan, [vars.D1D2P1]])
    api_list.append([vlan.delete_vlan_member, dut2, trunk_base_vlan, [vars.D2D1P1]])
    utils.exec_all(True, api_list)

    ### delete Access VLAN on all DUTs
    utils.exec_all(True,[[vlan.delete_vlan, dut, trunk_base_vlan] for dut in dut_list])

    [result, exceptions] = pll.exec_parallel(True, [dut2, dut3], udld.udld_cfg_ebtables_rule, [{'add': True}, {'add': True}])
    if not all(i is None for i in exceptions):
        result.append(False)
        print_log(exceptions)
    if False in result:
        print_log('UDLD Add ebtables rule FAILED','ERROR')
        ver_flag = False
    return ver_flag



def verify_udld_global(udld_global):
    '''
    Verify UDLD state and other attributes
    :param udld_global: dictionary  of UDLD global attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD state and other attributes", 'MED')
    dict1 = {'udld_admin_state': udld_global[dut1]['udld_admin_state'], 'udld_mode': udld_global[dut1]['udld_mode'],\
             'udld_message_time': udld_global[dut1]['udld_message_time'], 'udld_multiplier': udld_global[dut1]['udld_multiplier']}
    [result, exceptions] = pll.exec_parallel(True, [dut1], udld.verify_udld_global, [dict1])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_mode(udld_mode_def ='Normal'):
    '''
    Verify UDLD mode and other attributes
    :param udld_global: dictionary  of UDLD global attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD modes", 'MED')
    dict1 = {'udld_mode': udld_mode_def}
    [result, exceptions] = pll.exec_parallel(True, [dut1], udld.verify_udld_global, [dict1])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD modes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_neighbor(udld_neighbor):
    '''
    Verify UDLD neighbor state and other attributes
    :param udld_neighbor: dictionary  of UDLD neighbor attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD neighbor state and other attributes", 'MED')
    dict1 = {'local_port': udld_neighbor[dut1]['local_port'], 'device_name': udld_neighbor[dut1]['device_name'],\
             'remote_port': udld_neighbor[dut1]['remote_port'], 'neighbor_state': udld_neighbor[dut1]['neighbor_state']}

    dict2 = {'local_port': udld_neighbor[dut2]['local_port'], 'device_name': udld_neighbor[dut2]['device_name'],\
             'remote_port': udld_neighbor[dut2]['remote_port'], 'neighbor_state': udld_neighbor[dut2]['neighbor_state']}
    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_neighbors, [dict1, dict2])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD neighbor state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag


def verify_udld_port_status(udld_ports,dut,status='up'):
    '''
    Verify UDLD port status
    :param udld_ports: list of ports
    :param status: up/down
    :return:
    '''
    ver_flag = True
    if status == "up":
        for interface in udld_ports:
            if not intf.poll_for_interface_status(dut, [interface], "oper", "up", iteration=1, delay=1):
                st.error("The interface {} is down  on the DUT {}".format(interface,dut))
                ver_flag = False
    else:
        for interface in udld_ports:
            if not intf.poll_for_interface_status(dut, [interface], "oper", "down", iteration=1, delay=1):
                st.error("The interface {} is up on the DUT {}".format(interface,dut))
                ver_flag = False
    return ver_flag

def verify_udld_interface(udld_int,mode):
    '''
    Verify UDLD interface local port state
    :param udld_int: dictionary  of UDLD global attributes to be verified
    :param mode: normal/aggressive/normal_udld_block/aggressive_udld_block
    :return:
    '''
    ver_flag = True
    int_local_list1 =  udld_int[dut1]['udld_int']
    if mode == "normal" or mode == "aggressive":
        st.log("mode inside {}".format(mode))
        int_mode_list1 =  udld_int[dut1]['neighbor_state']
    elif mode == "loopnormal":
        st.log("mode inside {}".format(mode))
        int_mode_list1 =  udld_int[dut1]['neighbor_state_norm']
    elif mode == "loopaggressive":
        int_mode_list1 =  udld_int[dut1]['neighbor_state_agg']
    st.log("Before output......................")
    st.log("mode {}".format(mode))
    st.log("int_local_list1 {}".format(int_local_list1))
    st.log("int_mode_list1 {}".format(int_mode_list1))
    st.log("After output......................")
    for int_local1,int_mode1 in zip(int_local_list1,int_mode_list1):
        dict1 = {'udld_intf': int_local1, 'udld_status': int_mode1}
        [result, exceptions] = pll.exec_parallel(True, [dut1], udld.verify_udld_interface, [dict1])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('UDLD Local port states FAILED','ERROR')
            ver_flag = False
    return ver_flag


def test_udld_loops_normal_aggressive():
    '''
        Verify  UDLD Tx/Rx loops in normal mode with out PVST/RPVST
        Verify  UDLD Tx/Rx loops in aggressive mode with out PVST/RPVST
    '''
    tc_list = ['FtOpSoSwudldloopnormal001', 'FtOpSoSwudldloopaggressive001']
    print_log("START of TC:test_pvst_udld_normal_aggressive ==>Sub-Test:Verify UDLD functionality with PVST\n TCs:<{}>".format(tc_list), "HIGH")
    final_result = True
    tc_result1 = 0
    tc_result2 = 0
    udld_global_fail = 0
    udld_mode_fail = 0
    udld_interface_normal_loop_fail = 0
    udld_interface_no_normal_loop_fail = 0
    udld_interface_aggressive_loop_fail = 0
    udld_interface_no_aggressive_loop_fail = 0
    udld_neighbor_fail = 0
    udld_neighbor_warm_reboot_norm_fail = 0
    ##########################################NORMAL MODE UDLD RX/TX loop TESTS START#######################################
    st.wait(5)
    print_log("Verify that the port from DUT1 to DUT2 should go down in Normal Mode with UDLD TX/RX loop...",'MED')
    udld_interfaces = [vars.D1D2P1]
    state = 'down'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT3 is going to down state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT3 is not going to down state verification FAILED", "HIGH")
        udld_interface_normal_loop_fail += 1
        tc_result1 += 1
        final_result = False

    ###Disable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.config_intf_udld, [dict1])

    ###Disable UDLD global
    dict1 = {'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.config_udld_global, [dict1])

    ###do shut and no shut on DUt1 to DUT2
    udld_interfaces = [vars.D1D2P1]
    for udld_interface in udld_interfaces:
        intf.interface_operation(dut1, udld_interface , "shutdown")
        intf.interface_operation(dut1, udld_interface , "startup")
    st.wait(5)

    print_log("Verify that the port from DUT1 to DUT2 should go up in Normal Mode with UDLD TX/RX loop...",'MED')
    udld_interfaces = [vars.D1D2P1]
    state = 'up'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT2 is going to up state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT2 is not going to up state verification FAILED", "HIGH")
        udld_interface_no_normal_loop_fail += 1
        tc_result1 += 1
        final_result = False

    if tc_result1 > 0:
       st.report_tc_fail("FtOpSoSwudldloopnormal001", "UDLD_TX_RX_loop_Normal_Failed", "test_udld_loops_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwudldloopnormal001", "UDLD_TX_RX_loop_Normal_Passed", "test_udld_loops_normal_aggressive")

    ###Enable UDLD global
    dict1 = {'udld_enable': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.config_udld_global, [dict1])

    ###Enable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': udld_int[dut1]['udld_enable'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.config_intf_udld, [dict1])

    ###Enable UDLD mode Aggressive
    print_log("Enable the UDLD Mode Agrgressive on All DUTs...", 'MED')
    dict1 = {'udld_mode': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.config_udld_mode, [dict1])

    ### Verify UDLD mode
    if verify_udld_mode('Aggressive'):
        print_log("UDLD Mode Aggressive verification PASSED", "HIGH")
    else:
        print_log("UDLD Mode Aggressive verification FAILED", "HIGH")
        udld_mode_fail += 1
        tc_result2 += 1
        final_result = False

    st.wait(2)
    print_log("Verify that the port from DUT1 to DUT2 should go down in Aggressive Mode with UDLD TX/RX loop...",'MED')
    udld_interfaces = [vars.D1D2P1]
    state = 'down'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT2 is going to down state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT2 is not going to down state verification FAILED", "HIGH")
        udld_interface_aggressive_loop_fail += 1
        tc_result2 += 1
        final_result = False

    ###Disable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.config_intf_udld, [dict1])

    ###Disable UDLD global
    dict1 = {'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.config_udld_global, [dict1])

    ###do shut and no shut on DUt1 to DUT2
    udld_interfaces = [vars.D1D2P1]
    for udld_interface in udld_interfaces:
        intf.interface_operation(dut1, udld_interface , "shutdown")
        intf.interface_operation(dut1, udld_interface , "startup")
    st.wait(5)

    print_log("Verify that the port from DUT1 to DUT2 should go up in Aggressive Mode with UDLD TX/RX loop...",'MED')
    udld_interfaces = [vars.D1D2P1]
    state = 'up'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT2 is going to up state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT2 is not going to up state verification FAILED", "HIGH")
        udld_interface_no_aggressive_loop_fail += 1
        tc_result2 += 1
        final_result = False

    api_list = []
    api_list.append([vlan.delete_vlan_member, dut2, trunk_base_vlan, [vars.D2D3P1,vars.D2D3P2]])
    api_list.append([vlan.delete_vlan_member, dut3, trunk_base_vlan, [vars.D3D2P1,vars.D3D2P2]])
    utils.exec_all(True, api_list)

    ###Enable UDLD global
    dict1 = {'udld_enable': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    dict2 = {'udld_enable': udld_global[dut2]['udld_enable'], 'config': udld_global[dut2]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_global, [dict1, dict2])

    ###Enable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': udld_int[dut1]['udld_enable'], 'config': udld_int[dut1]['config']}
    dict2 = {'intf': udld_int[dut2]['udld_int'],'udld_enable': udld_int[dut2]['udld_enable'], 'config': udld_int[dut2]['config']}
    pll.exec_parallel(True,dut_list,udld.config_intf_udld, [dict1, dict2])
    st.wait(2)

    ####################PDB will REMOVE after suite completion
    #import pdb;pdb.set_trace()

    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor verification FAILED", "HIGH")
        udld_neighbor_fail += 1
        tc_result2 += 1
        final_result = False

    print_log("Do Warm Reboot in Aggressive Mode...", 'MED')
    utils.exec_foreach(True, dut_reload, reboot_api.config_warm_restart, oper="enable")
    utils.exec_all(True, [[st.reboot, dut, "warm"] for dut in dut_reload])
    st.wait(10)
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in normal mode after cold reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode after cold reboot verification FAILED", "HIGH")
        udld_neighbor_warm_reboot_norm_fail += 1
        tc_result2 += 1
        final_result = False

    ###Disable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    dict2 = {'intf': udld_int[dut2]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,dut_list,udld.config_intf_udld, [dict1, dict2])

    ###Disable UDLD global
    dict1 = {'udld_enable': 'no', 'config': 'no'}
    dict2 = {'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,dut_list,udld.config_udld_global, [dict1, dict2])


    if tc_result2 > 0:
       st.report_tc_fail("FtOpSoSwudldloopaggressive001", "UDLD_TX_RX_loop_Aggressive_Failed", "test_udld_loops_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwudldloopaggressive001", "UDLD_TX_RX_loop_Aggressive_Passed", "test_udld_loops_normal_aggressive")

    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if udld_interface_normal_loop_fail > 0:
            fail_msg += 'UDLD loop port down Failed in Normal mode:'
        if udld_interface_no_normal_loop_fail > 0:
            fail_msg += 'UDLD no loop port up Failed in Normal mode:'
        if udld_mode_fail > 0:
            fail_msg += 'UDLD mode Aggressive config Failed:'
        if udld_interface_aggressive_loop_fail > 0:
            fail_msg += 'UDLD loop port down Failed in Aggressive mode:'
        if udld_interface_no_aggressive_loop_fail > 0:
            fail_msg += 'UDLD no loop port up Failed in Aggressive mode:'
        if udld_neighbor_fail > 0:
            fail_msg += 'UDLD neighbor Failed:'
        if udld_neighbor_warm_reboot_norm_fail > 0:
            fail_msg += 'UDLD neighbor Failed after warm reboot:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
