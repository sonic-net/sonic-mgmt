import pytest
from spytest import st, tgapi, SpyTestDict
import apis.switching.pvst as stp
import apis.switching.pvst_elasticity_wrapper as stp_wrap
import apis.switching.vlan as vlan
from spytest.utils import random_vlan_list
import apis.system.interface as ifapi
from utilities.parallel import  exec_all,ensure_no_exception
import apis.system.reboot as reboot_obj
import apis.system.interface as interface
import apis.switching.portchannel as portchannel
from utilities import parallel

sc_data = SpyTestDict()
tg_info = dict()

@pytest.fixture(scope="module", autouse=True)
def pvst_elastic_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    vlan_variables()
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)
    [_, exceptions] = exec_all(True, [[config_tg_stream], [looguard_module_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)
    yield
    stp.config_stp_in_parallel(sc_data.dut_list, feature="rpvst", mode="disable", vlan=None)
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)

@pytest.fixture(scope="function", autouse=True)
def pvst_elastic_function_hooks(request):
    if st.get_func_name(request) == "test_ft_stp_loopguard_lag_interfaces":
        vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)
        st.log('Creating port-channel and adding members in both DUTs')
        portchannel.config_portchannel(vars.D1, vars.D2, sc_data.portchannel_name, sc_data.members_dut1,
                                           sc_data.members_dut2, "add")
        portchannel.config_portchannel(vars.D1, vars.D2, sc_data.portchannel_name2, sc_data.members_dut1_p2,
                                       sc_data.members_dut2_p2, "add")
        parallel.exec_all(True, [[vlan.create_vlan_and_add_members, sc_data.vlan_pc_d1], [vlan.create_vlan_and_add_members,sc_data.vlan_pc_d2]])
    yield
    if st.get_func_name(request) == "test_ft_stp_loopguard_lag_interfaces":
        vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)
        portchannel.clear_portchannel_configuration([vars.D1, vars.D2])
        parallel.exec_all(True, [[vlan.create_vlan_and_add_members, sc_data.vlan_data_d1],
                                 [vlan.create_vlan_and_add_members, sc_data.vlan_data_d2]])
        parallel.exec_all(True, [[vlan.create_vlan_and_add_members, sc_data.vlan1_data_d1],
                                 [vlan.create_vlan_and_add_members, sc_data.vlan1_data_d2]])
    

def vlan_variables():
    global tg
    global tg_handler
    sc_data.vlan_list = random_vlan_list(count=2)
    sc_data.vlan = str(sc_data.vlan_list[1])
    sc_data.vlan1 = str(sc_data.vlan_list[0])
    sc_data.source_mac = "00:0A:01:00:00:01"
    sc_data.line_rate = 100
    sc_data.wait_stream_run = 10
    sc_data.wait_for_stats = 10
    sc_data.frame_size = 68
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2", "T1D2P1", "T1D2P2")
    tg = tg_handler["tg"]
    tg_info['tg_info'] = tg_handler
    tg_info['vlan_id'] = sc_data.vlan
    sc_data.mac_count = 100
    sc_data.portchannel_name = "PortChannel7"
    sc_data.portchannel_name2 = "PortChannel8"
    sc_data.dut_list = [vars.D1, vars.D2]
    sc_data.members_dut1 = [vars.D1D2P1, vars.D1D2P2]
    sc_data.members_dut2 = [vars.D2D1P1, vars.D2D1P2]
    sc_data.members_dut1_p2 = [vars.D1D2P3, vars.D1D2P4]
    sc_data.members_dut2_p2 = [ vars.D2D1P3, vars.D2D1P4]
    sc_data.vlan_pc_d1 = [
        {"dut": [vars.D1], "vlan_id": sc_data.vlan, "tagged": [sc_data.portchannel_name,  sc_data.portchannel_name2]}]
    sc_data.vlan_pc_d2 = [
        {"dut": [vars.D2], "vlan_id": sc_data.vlan, "tagged": [sc_data.portchannel_name,  sc_data.portchannel_name2]}]
    
    sc_data.vlan_data_d1 = [{"dut": [vars.D1], "vlan_id": sc_data.vlan, "tagged": [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]}]
    sc_data.vlan_data_d2 = [{"dut": [vars.D2], "vlan_id": sc_data.vlan, "tagged": [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2]}]
    sc_data.vlan1_data_d1 = [
        {"dut": [vars.D1], "vlan_id": sc_data.vlan1, "tagged": [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]}]
    sc_data.vlan1_data_d2 = [
        {"dut": [vars.D2], "vlan_id": sc_data.vlan1, "tagged": [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2]}]


def looguard_module_prolog():
    parallel.exec_all(True, [[vlan.create_vlan_and_add_members, sc_data.vlan_data_d1],
                             [vlan.create_vlan_and_add_members, sc_data.vlan_data_d2]])
    parallel.exec_all(True, [[vlan.create_vlan_and_add_members, sc_data.vlan1_data_d1],
                             [vlan.create_vlan_and_add_members, sc_data.vlan1_data_d2]])
    stp.config_stp_in_parallel(sc_data.dut_list, feature="rpvst", mode="enable", vlan=None)
    stp.config_stp_vlan_parameters(vars.D2, sc_data.vlan, priority=0)
    st.log("Wait for convergence")
    st.wait(10)

def config_tg_stream():
    st.log("Traffic Config for verifying STP Loopguard feature")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=sc_data.vlan, mac_src='00:0a:01:00:00:01',
                                mac_dst='00:0a:02:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_3"],frame_size= sc_data.frame_size)
    tg_info['tg1_stream_id'] = tg_1['stream_id']

    tg_2 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_3"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=sc_data.vlan, mac_src='00:0a:02:00:00:01',
                                mac_dst='00:0a:01:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_1"],frame_size= sc_data.frame_size)
    tg_info['tg2_stream_id'] = tg_2['stream_id']
    return tg_info

def verify_traffic():
    ifapi.clear_interface_counters(vars.D1)
    ifapi.show_interface_counters_all(vars.D1)
    st.log("Starting of traffic from TGen")
    tg.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'], duration=10)
    st.wait(sc_data.wait_stream_run)
    st.log("Stopping of traffic from TGen to get interface counters")
    tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])
    st.wait(sc_data.wait_for_stats)
    ifapi.show_interface_counters_all(vars.D1)
    tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
    tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_3"])
    total_rx_tg2 = tg_2_stats.rx.total_packets
    total_tx_tg1 = tg_1_stats.tx.total_packets
    percentage_95_total_tx_tg1 = (95 * int(total_tx_tg1)) / 100
    if not int(percentage_95_total_tx_tg1) <= int(total_rx_tg2):
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)
    return True



def test_ft_stp_loopguard_enable_global():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on device1")
    if not stp.config_loopguard_global(vars.D1, mode='enable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("verify traffic")
    if not verify_traffic():
        st.report_fail("failed_traffic_verification")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.log("verify traffic")
    if not verify_traffic():
        st.report_fail("port_inconsistent_state_fail")
    st.log("Unconfiguring the loop guard global mode")
    if not stp.config_loopguard_global(vars.D1, mode='disable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.report_pass("test_case_passed")


def test_ft_stp_loopguard_enable_interface():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("verify traffic")
    if not verify_traffic():
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.log("verify traffic")
    if not verify_traffic():
        st.report_fail("port_inconsistent_state_fail")
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")
        
        
def test_ft_stp_loopguard_enable_interface_other_vlan_instance():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan1, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.wait(5)
    if not stp.verify_stp_intf_status(vars.D1, interface=vars.D1D2P2, status="FORWARDING", vlanid=sc_data.vlan1):
        st.report_fail("port_forwarding_fail")
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")
        

def test_ft_stp_loopguard_config_reload():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on device1")
    if not stp.config_loopguard_global(vars.D1, mode='enable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    reboot_obj.config_save(vars.D1)
    st.reboot(vars.D1)
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.log("Unconfiguring the loop guard global mode")
    if not stp.config_loopguard_global(vars.D1, mode='disable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.report_pass("test_case_passed")

       
def test_ft_stp_loopguard_enable_global_interface_root():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on device1")
    if not stp.config_loopguard_global(vars.D1, mode='enable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("Enable root guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.log("Unconfiguring the loop guard global mode")
    if not stp.config_loopguard_global(vars.D1, mode='disable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("Unconfiguring the root guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='disable')
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")


def test_ft_stp_loopguard_enable_interface_shut_noshut():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("shutdown the root forwarding port")
    interface.interface_shutdown(vars.D1, vars.D1D2P1)
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.wait(5)
    if not stp.verify_stp_intf_status(vars.D1, interface=vars.D1D2P2, status="FORWARDING", vlanid=sc_data.vlan1):
        st.report_fail("port_forwarding_fail")
    interface.interface_noshutdown(vars.D1, vars.D1D2P1)
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")


def test_ft_stp_loopguard_enable_both_interface():
    st.log("Verify the stp convergence")
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    stp.config_stp_interface_params(vars.D1, vars.D1D2P1, loop_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P1, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P1):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P1, mode="enable")
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    stp.config_stp_interface_params(vars.D1, vars.D1D2P1, loop_guard='disable')
    st.report_pass("test_case_passed")
        
        
def test_ft_stp_loopguard_lag_interfaces():
    st.log("Verify the stp convergence")
    st.wait(10)
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on portchannel")
    stp.config_stp_interface_params(vars.D1, sc_data.portchannel_name2, loop_guard='enable')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, sc_data.portchannel_name2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, sc_data.portchannel_name2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an lag interface")
    stp.config_stp_enable_interface(vars.D2, sc_data.portchannel_name2, mode="enable")
    st.log("Unconfiguring the loop guard lag interface mode")
    stp.config_stp_interface_params(vars.D1, sc_data.portchannel_name2, loop_guard='disable')
    st.report_pass("test_case_passed")
        
        
def test_ft_stp_loopguard_option_none():
    st.log("Verify the stp convergence")
    st.wait(10)
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("Enable root guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='enable')
    st.log("Enable loop guard  option none on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='none')
    st.log("disable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="disable")
    st.wait(5)
    st.log("verify port moved to inconsistent state")
    if not stp.check_rg_current_state(vars.D1, sc_data.vlan, vars.D1D2P2):
        st.report_fail("port_inconsistent_state_fail")
    st.log("enable stp on an interface")
    stp.config_stp_enable_interface(vars.D2, vars.D2D1P2, mode="enable")
    st.log("Unconfiguring the root guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='disable')
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")
        
        
def test_ft_stp_loopguard_global_interface_coexist():
    st.log("Enable loop guard on device1")
    if not stp.config_loopguard_global(vars.D1, mode='enable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("Enable root guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='enable')
    st.log("Enable loop guard  option none on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='none')
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.log("Unconfiguring the loop guard global mode")
    if not stp.config_loopguard_global(vars.D1, mode='disable'):
        st.report_fail("STP_loop_guard_config_fail")
    st.log("Enable loop guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable')
    st.log("Enable root guard on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='enable')
    st.log("Enable loop guard  option none on interface")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='none')
    st.log("Unconfiguring the root guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, root_guard='disable')
    st.log("Unconfiguring the loop guard interface mode")
    stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='disable')
    st.report_pass("test_case_passed")
        


def test_ft_stp_loopguard_pvst_mode():
    st.log("Disable rpvst and enable pvst")
    stp.config_stp_in_parallel(sc_data.dut_list, feature="rpvst", mode="disable", vlan=None)
    stp.config_stp_in_parallel(sc_data.dut_list, feature="pvst", mode="enable", vlan=None)
    st.wait(10)
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=40, delay=1):
        st.report_fail("stp_convergence_fail")
    st.log("Enable loop guard on device1")
    if stp.config_loopguard_global(vars.D1, mode='enable'):
        st.report_fail("loopguard_pvst_should_fail")
    st.log("Enable loop guard on interface")
    if stp.config_stp_interface_params(vars.D1, vars.D1D2P2, loop_guard='enable'):
        st.report_fail("loopguard_pvst_should_fail")
    st.log("revert back to previous config")
    stp.config_stp_in_parallel(sc_data.dut_list, feature="pvst", mode="disable", vlan=None)
    stp.config_stp_in_parallel(sc_data.dut_list, feature="rpvst", mode="enable", vlan=None)
    st.wait(10)
    if not stp_wrap.poll_stp_convergence(vars, sc_data.vlan, iteration=20, delay=1):
        st.report_fail("stp_convergence_fail")
    st.report_pass("test_case_passed")