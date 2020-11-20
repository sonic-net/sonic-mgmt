import pytest

from spytest import st, tgapi, SpyTestDict, utils

import apis.system.pfc as pfc_obj
import apis.system.interface as interface_obj
from apis.system.switch_configuration import get_running_config
from apis.system.basic import get_hwsku, get_ifconfig_ether
from apis.system.reboot import config_save, config_save_reload
import apis.switching.vlan as vlan_obj
from apis.switching.mac import config_mac, delete_mac, get_mac
import apis.switching.portchannel as portchannel_obj
import apis.routing.ip as ip_obj
from apis.routing.arp import add_static_arp, delete_static_arp
from apis.qos.qos import clear_qos_config
import apis.qos.cos as cos_obj

from utilities.parallel import exec_all, exec_parallel, ExecAllFunc, ensure_no_exception

pfc_data = SpyTestDict()

def initialize_variables():
    pfc_data.source_mac_dut1_tg1 = '00:00:00:00:00:01'
    pfc_data.source_mac_dut1_tg2 = '00:00:00:00:00:02'
    pfc_data.source_mac_dut2_tg1 = '00:00:00:00:00:03'
    pfc_data.source_mac_dut2_tg2 = '00:00:00:00:00:04'
    pfc_data.destination_mac_dut1_tg1 = '00:00:00:00:00:05'
    pfc_data.destination_mac_dut1_tg2 = '00:00:00:00:00:06'
    pfc_data.destination_mac_dut2_tg1 = '00:00:00:00:00:07'
    pfc_data.destination_mac_dut2_tg2 = '00:00:00:00:00:08'
    pfc_data.rate_percent = 100
    pfc_data.pkt_size_min = 68
    pfc_data.pkt_size_max = 9100
    pfc_data.polling_interval = 100
    pfc_data.detection_time1 = 200
    pfc_data.detection_time2 = 300
    pfc_data.restoration_time1 = 2000
    pfc_data.restoration_time2 = 3000
    pfc_data.lossless_priorities = [3, 5]
    pfc_data.asym_lossless_priority = 1
    pfc_data.all_lossless_priorities = [1, 3, 5]
    pfc_data.all_lossy_priority = 6
    pfc_data.lossy_priorities = [queue for queue in range(8) if queue not in pfc_data.lossless_priorities]
    pfc_data.asym_test_priorities = [pfc_data.asym_lossless_priority, pfc_data.lossless_priorities[1]]
    pfc_data.wait_2, pfc_data.wait_3, pfc_data.wait_5 = 2, 3, 5
    pfc_data.dscp_list=[56, 57]
    pfc_data.portchannel_name1 = "PortChannel1"
    pfc_data.portchannel_name2 = "PortChannel2"
    pfc_data.map_dict = {"0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7"}
    pfc_data.vlan = str(utils.random_vlan_list()[0])
    pfc_data.vlan_1 = str(utils.random_vlan_list(exclude=[pfc_data.vlan])[0])
    pfc_data.vlan_2 = str(utils.random_vlan_list(exclude=[pfc_data.vlan, pfc_data.vlan_1])[0])
    pfc_data.ports_list_dut1 = [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]
    pfc_data.ports_list_dut2 = [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2]
    pfc_data.dut_rt_int_mac = get_ifconfig_ether(vars.D1, vars.D1T1P1)

@pytest.fixture(scope="module", autouse=True)
def pfc_module_hooks(request):
    #add things at the start of this module
    global vars
    vars = st.ensure_min_topology('D1T1:2', 'D1D2:2', 'D2T1:2')
    initialize_variables()
    [output, exceptions] = exec_all(True, [[get_hwsku, vars.D1], [get_hwsku, vars.D2]])
    ensure_no_exception(exceptions)
    pfc_data.hwsku1, pfc_data.hwsku2 = output
    [output, exceptions] = exec_all(True, [[pfc_module_tg_prolog], [pfc_module_dut_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'PFC Module configuration failed')
    
    
    st.debug("Toggle the asymmetric PFC config")
    [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_asymmetric, vars.D1, 'on', pfc_data.ports_list_dut1], [pfc_obj.config_pfc_asymmetric, vars.D2, 'on', pfc_data.ports_list_dut2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to configure Asymmetric PFC mode as ON')
    [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_asymmetric, vars.D1, 'off', pfc_data.ports_list_dut1], [pfc_obj.config_pfc_asymmetric, vars.D2, 'off', pfc_data.ports_list_dut2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to configure Asymmetric PFC mode as OFF')
    clear_counters()
    get_debug_info(intf_counter=False, pfc_counter=False, queue_counter=False)
    yield
    vlan_obj.clear_vlan_configuration([vars.D1, vars.D2])
    exceptions = exec_all(True, [[pfc_obj.config_pfc_asymmetric, vars.D1, 'off', pfc_data.ports_list_dut1], [pfc_obj.config_pfc_asymmetric, vars.D2, 'off', pfc_data.ports_list_dut2]])[1]
    ensure_no_exception(exceptions)
    exec_all(True, [[clear_qos_config, vars.D1], [clear_qos_config, vars.D2]])


@pytest.fixture(scope="function", autouse=True)
def pfc_func_hooks(request):
    # add things at the start every test case
    # use 'request.function.func_name' to compare
    if st.get_func_name(request) == 'test_ft_pfc_asym':
        ft_pfc_asym_prolog()
    elif st.get_func_name(request) in ['test_ft_pfc_asym_multi_vlan', 'test_ft_pfc_sym_multi_vlan', 'test_ft_pfc_sym_cold_boot', 'test_ft_pfc_asym_congestion_in_both_duts', 'test_ft_pfc_congestion_in_both_duts']:
        if not config_sym_asym_pfc_buffer(pfc_data.lossless_priorities, pfc_data.asym_test_priorities):
            st.report_fail('msg', 'Failed to configure lossy-lossless priorities configuration on DUT2')
    elif st.get_func_name(request) in ['test_ft_pfc_asym_portchannel', 'test_ft_pfc_sym_portchannel']:
        if not config_sym_asym_pfc_buffer(pfc_data.lossless_priorities, pfc_data.asym_test_priorities):
            st.report_fail('msg', 'Failed to configure lossy-lossless priorities configuration on DUT2')
        if not portchannel_config_prolog():
            get_debug_info()
            st.report_fail("portchannel_create_failed", pfc_data.portchannel_name1, vars.D1)
    elif st.get_func_name(request) == 'test_ft_pfc_sym':
        ft_pfc_sym_prolog()
    elif st.get_func_name(request) == 'test_ft_pfc_sym_l3_interface':
        if not config_ip_address():
            get_debug_info()
            st.report_fail('ip_static_route_create_fail', vars.D1)
    else:
        pass
    yield
    # add things at the end every test case
    # use 'request.function.func_name' to compare
    if st.get_func_name(request) in ['test_ft_pfc_asym_multi_vlan', 'test_ft_pfc_sym_multi_vlan', 'test_ft_pfc_sym_cold_boot', 'test_ft_pfc_asym_congestion_in_both_duts', 'test_ft_pfc_congestion_in_both_duts']:
        config_sym_asym_pfc_buffer(pfc_data.asym_test_priorities, pfc_data.lossless_priorities)
    elif st.get_func_name(request) in ['test_ft_pfc_asym_portchannel', 'test_ft_pfc_sym_portchannel']:
        config_sym_asym_pfc_buffer(pfc_data.asym_test_priorities, pfc_data.lossless_priorities)
        portchannel_config_epilog()
    elif st.get_func_name(request) == 'test_ft_pfc_sym_l3_interface':
        unconfig_test_ft_pfc_sym_l3_interface()
    else:
        pass


def pfc_module_tg_prolog():
    st.debug("Getting TG handlers")
    pfc_data.tg1, pfc_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    pfc_data.tg2, pfc_data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    pfc_data.tg3, pfc_data.tg_ph_3 = tgapi.get_handle_byname("T1D2P2")
    pfc_data.tg4, pfc_data.tg_ph_4 = tgapi.get_handle_byname("T1D2P1")
    pfc_data.tg = pfc_data.tg1
    pfc_data.streams = dict()
    stream = pfc_data.tg.tg_traffic_config(port_handle=pfc_data.tg_ph_1, mode='create', length_mode='random',
                 mac_src=pfc_data.source_mac_dut1_tg1, mac_src_mode='fixed', l2_encap='ethernet_ii_vlan',
                 mac_dst=pfc_data.destination_mac_dut1_tg1, mac_dst_mode='fixed', vlan="enable", vlan_id=pfc_data.vlan,
                 rate_percent=pfc_data.rate_percent, transmit_mode='continuous', vlan_user_priority=pfc_data.lossless_priorities[0],
                 frame_size_min=pfc_data.pkt_size_min, frame_size_max=pfc_data.pkt_size_max)
    pfc_data.streams['d1tg1_stream'] = stream['stream_id']
    stream = pfc_data.tg.tg_traffic_config(port_handle=pfc_data.tg_ph_2, mode='create', length_mode='random',
                 mac_src=pfc_data.source_mac_dut1_tg2, mac_src_mode='fixed', l2_encap='ethernet_ii_vlan',
                 mac_dst=pfc_data.destination_mac_dut1_tg2, mac_dst_mode='fixed', vlan="enable", vlan_id=pfc_data.vlan,
                 rate_percent=pfc_data.rate_percent, transmit_mode='continuous', vlan_user_priority=pfc_data.lossless_priorities[1],
                 frame_size_min=pfc_data.pkt_size_min, frame_size_max=pfc_data.pkt_size_max)
    pfc_data.streams['d1tg2_stream'] = stream['stream_id']
    stream = pfc_data.tg.tg_traffic_config(port_handle=pfc_data.tg_ph_3, mode='create', length_mode='random',
                 mac_src=pfc_data.source_mac_dut2_tg2, mac_src_mode='fixed', l2_encap='ethernet_ii_vlan',
                 mac_dst=pfc_data.destination_mac_dut1_tg2, mac_dst_mode='fixed', vlan="enable", vlan_id=pfc_data.vlan,
                 rate_percent=pfc_data.rate_percent, transmit_mode='continuous', vlan_user_priority=pfc_data.all_lossy_priority,
                 frame_size_min=pfc_data.pkt_size_min, frame_size_max=pfc_data.pkt_size_max)
    pfc_data.streams['d2tg2_stream'] = stream['stream_id']
    return True

def pfc_module_dut_prolog(**kwargs):
    if kwargs.get('vlan_config', True):
        st.banner("VLAN Configuration")
        dict1 = {'vlan_list': [pfc_data.vlan, pfc_data.vlan_1, pfc_data.vlan_2]}
        dict2 = {'vlan_list': [pfc_data.vlan, pfc_data.vlan_1, pfc_data.vlan_2]}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.create_vlan, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to configure VLANs")
            return False
        
        dict1 = {'vlan':  pfc_data.vlan, 'port_list': [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], 'tagging_mode': True}
        dict2 = {'vlan':  pfc_data.vlan, 'port_list': [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2], 'tagging_mode': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.add_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to add ports to VLAN")
            return False
        
        dict1 = {'vlan':  pfc_data.vlan_1, 'port_list': [vars.D1T1P1, vars.D1D2P1], 'tagging_mode': True}
        dict2 = {'vlan':  pfc_data.vlan_1, 'port_list': [vars.D2D1P1, vars.D2T1P1], 'tagging_mode': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.add_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to add ports to VLAN")
            return False
        
        dict1 = {'vlan':  pfc_data.vlan_2, 'port_list': [vars.D1T1P2, vars.D1D2P2], 'tagging_mode': True}
        dict2 = {'vlan':  pfc_data.vlan_2, 'port_list': [vars.D2D1P2, vars.D2T1P1], 'tagging_mode': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.add_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to add ports to VLAN")
            return False
    
    
    if kwargs.get('mac_config', True):
        st.banner("MAC Addresses configuration")
        [output, exceptions] = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan, vars.D1D2P1], [config_mac, vars.D2, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan, vars.D2T1P1]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to configure MAC address")
            return False
        [output, exceptions] = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan, vars.D1D2P2], [config_mac, vars.D2, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan, vars.D2T1P1]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to configure MAC address")
            return False
        [output, exceptions] = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan_1, vars.D1D2P1], [config_mac, vars.D2, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan_1, vars.D2T1P1]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to configure MAC address")
            return False
        [output, exceptions] = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan_2, vars.D1D2P2], [config_mac, vars.D2, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan_2, vars.D2T1P1]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to configure MAC address")
            return False


    if kwargs.get('apply_buffer_config', True):
        dict1 = {'hwsku': pfc_data.hwsku1, 'ports_dict': {port: {'lossless_queues': pfc_data.lossless_priorities, 'lossy_queues': pfc_data.lossy_priorities} for port in pfc_data.ports_list_dut1}, 'core_buffer_config': True}
        dict2 = {'hwsku': pfc_data.hwsku2, 'ports_dict': {port: {'lossless_queues': pfc_data.lossless_priorities, 'lossy_queues': pfc_data.lossy_priorities} for port in pfc_data.ports_list_dut2}, 'core_buffer_config': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], pfc_obj.config_pfc_buffer_prameters, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to configure buffer constants')
            return False
    if kwargs.get('lossless_qos_map', True):
        [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_lossless_queues, vars.D1,
                                                      pfc_data.lossless_priorities, pfc_data.ports_list_dut1],
                                                     [pfc_obj.config_pfc_lossless_queues, vars.D2,
                                                      pfc_data.lossless_priorities, pfc_data.ports_list_dut2]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to configure port_qos_map for pfc_lossless priorities')
            return False


    if kwargs.get('mapping_config', True):
        st.banner("Mapping configuration")
        dict1 = {'obj_name': "AZURE_SYM", 'pfc_priority_to_queue_map_dict': {str(prioirty): str(prioirty) for prioirty in pfc_data.lossless_priorities}}
        dict2 = {'obj_name': "AZURE_SYM", 'pfc_priority_to_queue_map_dict': {str(prioirty): str(prioirty) for prioirty in pfc_data.all_lossless_priorities}}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], cos_obj.config_pfc_priority_to_queue_map, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to map pfc_priority_to_queue')
            return False
        
        dict1 = {'obj_name': "AZURE_ASYM", 'pfc_priority_to_queue_map_dict': pfc_data.map_dict}
        dict2 = {'obj_name': "AZURE_ASYM", 'pfc_priority_to_queue_map_dict': pfc_data.map_dict}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], cos_obj.config_pfc_priority_to_queue_map, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to map pfc_priority_to_queue')
            return False
        
        dict1 = {'obj_name': "AZURE", 'tc_to_queue_map_dict': pfc_data.map_dict}
        dict2 = {'obj_name': "AZURE", 'tc_to_queue_map_dict': pfc_data.map_dict}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], cos_obj.config_tc_to_queue_map, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to map tc_to_queue')
            return False
        
        dict1 = {'obj_name': "AZURE", 'tc_to_pg_map_dict': pfc_data.map_dict}
        dict2 = {'obj_name': "AZURE", 'tc_to_pg_map_dict': pfc_data.map_dict}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], cos_obj.config_tc_to_pg_map, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to map tc_to_pg')
            return False
        
        dict1 = {'obj_name': "AZURE", 'dscp_to_tc_map_dict': {str(pfc_data.dscp_list[0]): str(pfc_data.lossless_priorities[0]), str(pfc_data.dscp_list[1]): str(pfc_data.all_lossy_priority)}}
        dict2 = {'obj_name': "AZURE", 'dscp_to_tc_map_dict': {str(pfc_data.dscp_list[0]): str(pfc_data.lossless_priorities[0]), str(pfc_data.dscp_list[1]): str(pfc_data.all_lossy_priority)}}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], cos_obj.config_dscp_to_tc_map, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error('Failed to map dscp_to_tc')
            return False
    
        st.banner("Applying mapping configuration to ports")
        qos_map1 = [{'port': vars.D1T1P1, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D1T1P2, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D1D2P1, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D1D2P2, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D1T1P1, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D1T1P2, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D1D2P1, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D1D2P2, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D1T1P1, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D1T1P2, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D1D2P1, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D1D2P2, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'}]
        qos_map2 = [{'port': vars.D2T1P1, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D2T1P2, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D2D1P1, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D2D1P2, 'obj_name': 'AZURE', 'map': 'tc_to_queue_map'},
                    {'port': vars.D2T1P1, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D2T1P2, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D2D1P1, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D2D1P2, 'obj_name': 'AZURE', 'map': 'tc_to_pg_map'},
                    {'port': vars.D2T1P1, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D2T1P2, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D2D1P1, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'},
                    {'port': vars.D2D1P2, 'obj_name': 'AZURE', 'map': 'dscp_to_tc_map'}]
        [output, exceptions] = exec_all(True, [[cos_obj.config_port_qos_map_all, vars.D1, qos_map1], [cos_obj.config_port_qos_map_all, vars.D2, qos_map2]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.error("Failed to attach the mapping configuration to ports")
            return False
    return True


def config_sym_asym_pfc_buffer(lossy_priorities, lossless_priorities):
    if not pfc_obj.config_pfc_lossless_queues(vars.D2, lossy_priorities, pfc_data.ports_list_dut2, config=False):
        st.error('Failed to remove lossless priorities on DUT2')
        return False
    ports_dict = {port: {'lossy_queues': lossy_priorities} for port in pfc_data.ports_list_dut2}
    if not pfc_obj.config_pfc_buffer_prameters(vars.D2, pfc_data.hwsku2, ports_dict, core_buffer_config=False):
        st.error('Failed to configure lossy priorities buffer configuration on DUT2')
        return False
    
    if not pfc_obj.config_pfc_lossless_queues(vars.D2, lossless_priorities, pfc_data.ports_list_dut2):
        st.error('Failed to configure lossless priorities on DUT2')
        return False
    ports_dict = {port: {'lossless_queues': lossless_priorities} for port in pfc_data.ports_list_dut2}
    if not pfc_obj.config_pfc_buffer_prameters(vars.D2, pfc_data.hwsku2, ports_dict, core_buffer_config=False):
        st.error('Failed to configure lossless priorities buffer configuration on DUT2')
        return False
    return True

def ft_pfc_asym_prolog():
    if not verify_pfc_counters_initialization([vars.D1, vars.D2], [vars.D1D2P1, vars.D2D1P1]):
        st.report_fail('pfc_counters_not_initialized', 180)
    [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_asymmetric, vars.D1, 'on', pfc_data.ports_list_dut1],
                                                 [pfc_obj.config_pfc_asymmetric, vars.D2, 'on', pfc_data.ports_list_dut2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to configure Asymmetric PFC mode as ON')
    qos_map1 = [{'port': vars.D1T1P1, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D1T1P2, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D1D2P1, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D1D2P2, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'}]
    qos_map2 = [{'port': vars.D2T1P1, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D2T1P2, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D2D1P1, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'},
                {'port': vars.D2D1P2, 'obj_name': 'AZURE_ASYM', 'map': 'pfc_to_queue_map'}]
    [output, exceptions]= exec_all(True, [[cos_obj.config_port_qos_map_all, vars.D1, qos_map1], [cos_obj.config_port_qos_map_all, vars.D2, qos_map2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', "Failed to attach the pfc_to_queue_map configuration to ports")


def ft_pfc_sym_prolog():
    st.debug("Configuring mapping for the Symmetric PFC")
    qos_map1 = [{'port': vars.D1T1P1, 'map': 'pfc_to_queue_map'}, {'port': vars.D1T1P2, 'map': 'pfc_to_queue_map'},
                {'port': vars.D1D2P1, 'map': 'pfc_to_queue_map'}, {'port': vars.D1D2P2, 'map': 'pfc_to_queue_map'}]
    qos_map2 = [{'port': vars.D2T1P1, 'map': 'pfc_to_queue_map'}, {'port': vars.D2T1P2, 'map': 'pfc_to_queue_map'},
                {'port': vars.D2D1P1, 'map': 'pfc_to_queue_map'}, {'port': vars.D2D1P2, 'map': 'pfc_to_queue_map'}]
    [output, exceptions]= exec_all(True, [[cos_obj.clear_port_qos_map_all, vars.D1, qos_map1],
                                          [cos_obj.clear_port_qos_map_all, vars.D2, qos_map2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to clear pfc_to_queue_map from port_qos_map')
    qos_map1 = [{'port': vars.D1T1P1, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D1T1P2, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D1D2P1, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D1D2P2, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'}]
    qos_map2 = [{'port': vars.D2T1P1, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D2T1P2, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D2D1P1, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'},
                {'port': vars.D2D1P2, 'map': 'pfc_to_queue_map', 'obj_name': 'AZURE_SYM'}]
    [output, exceptions] = exec_all(True, [[cos_obj.config_port_qos_map_all, vars.D1, qos_map1],
                                           [cos_obj.config_port_qos_map_all, vars.D2, qos_map2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to add pfc_to_queue_map to port_qos_map')

def verify_loss_less_traffic(rx_traffic, tx_traffic):
    if not (int(rx_traffic) >= int(tx_traffic)):
        return False
    return True

def verify_lossy_traffic(rx_traffic, tx_traffic):
    if not int(tx_traffic) > int(rx_traffic):
        return False
    return True

def verify_pfc_counters(verify_pfc_counter_dict_list):
    pfc_data.count=0
    for verify_pfc_counter_dict in verify_pfc_counter_dict_list:
        for pfc_counters_dict in verify_pfc_counter_dict['pfc_counters_dict_list']:
            if ((pfc_counters_dict['port'] == verify_pfc_counter_dict['port']) and
                    (pfc_counters_dict['port_mode'] == verify_pfc_counter_dict['mode'])):
                st.log('Port is:{}'.format(verify_pfc_counter_dict['port']))
                st.log('Mode is:{}'.format(verify_pfc_counter_dict['mode']))
                st.log('DUT:{}'.format(verify_pfc_counter_dict['dut']))
                pfc_data.count+=1
                st.log('Inside the loop')
                counter_list = verify_pfc_counter_dict['counter']
                st.log('counter_list is:{}'.format(counter_list))
                for pfc_priority in ['pfc0', 'pfc1', 'pfc2', 'pfc3', 'pfc4', 'pfc5', 'pfc6', 'pfc7']:
                    if pfc_priority not in counter_list:
                        if not int(pfc_counters_dict[pfc_priority]) == 0:
                            st.log('Hitted invalid_pfc_counter')
                            return False
                    else:
                        if not int(pfc_counters_dict[pfc_priority]) > 100:
                            st.log('Hitted pfc_counter_fail')
                            return False
    st.log('length:{}'.format(len(verify_pfc_counter_dict_list)))
    st.log('Count:{}'.format(pfc_data.count))
    if not pfc_data.count == int(len(verify_pfc_counter_dict_list)):
        return False
    return True

def verify_clear_pfc_counters(pfc_counters_dict_list, ports_list, mode_list):
    for port in ports_list:
        for mode in mode_list:
            for pfc_priority in ['pfc{}'.format(priority) for priority in range(8)]:
                counter = utils.filter_and_select(pfc_counters_dict_list, [pfc_priority], {'port_mode': mode, 'port': port})[0][pfc_priority]
                if int(counter) !=0:
                    st.error("The {} counter for port: {} at mode: {} is: {}".format(pfc_priority, port, mode, counter))
                    return False
    return True

def clear_counters(**kwargs):
    if kwargs.get('pfc_counters', True):
        exceptions = exec_all(True, [[pfc_obj.clear_pfc_counters, vars.D1],[pfc_obj.clear_pfc_counters, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get('intf_counters', True):
        exceptions = exec_all(True, [[interface_obj.clear_interface_counters, vars.D1],[interface_obj.clear_interface_counters, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get('queue_counters', True):
        exceptions = exec_all(True, [[interface_obj.clear_queue_counters, vars.D1],[interface_obj.clear_queue_counters, vars.D2]])[1]
        ensure_no_exception(exceptions)

def verify_queue_counters(dut1_intf1, dut1_intf2, dut2_intf, queue_counters_dict, loss_less_list, multi_dut=False):
    [output, exceptions] = exec_all(True, [[interface_obj.show_queue_counters, vars.D1, dut1_intf1],[interface_obj.show_queue_counters, vars.D2, dut2_intf]])
    ensure_no_exception(exceptions)
    try:
        if multi_dut:
            dut1_queue_cnt1 = int(utils.filter_and_select(output[0], ['pkts_count'], {'txq': queue_counters_dict[vars.D1][dut1_intf1][0]})[0]['pkts_count'].replace(',', ''))
            dut1_queue_cnt2 = int(utils.filter_and_select(output[0], ['pkts_count'], {'txq': queue_counters_dict[vars.D1][dut1_intf1][1]})[0]['pkts_count'].replace(',', ''))
        else:
            dut1_queue_cnt1 = int(utils.filter_and_select(output[0], ['pkts_count'], {'txq': queue_counters_dict[vars.D1][dut1_intf1]})[0]['pkts_count'].replace(',', ''))
            dut1_queue_cnt2 = int(utils.filter_and_select(interface_obj.show_queue_counters(vars.D1, dut1_intf2), ['pkts_count'], {'txq': queue_counters_dict[vars.D1][dut1_intf2]})[0]['pkts_count'].replace(',', ''))
        dut2_queue_cnt1 = int(utils.filter_and_select(output[1], ['pkts_count'], {'txq': queue_counters_dict[vars.D2][dut2_intf][0]})[0]['pkts_count'].replace(',', ''))
        dut2_queue_cnt2 = int(utils.filter_and_select(output[1], ['pkts_count'], {'txq': queue_counters_dict[vars.D2][dut2_intf][1]})[0]['pkts_count'].replace(',', ''))
        st.log('{} traffic transmitted from DUT1:{}'.format(queue_counters_dict[vars.D2][dut2_intf][0], dut1_queue_cnt1))
        st.log('{} traffic transmitted from DUT1:{}'.format(queue_counters_dict[vars.D2][dut2_intf][1], dut1_queue_cnt2))
        st.log('{} traffic transmitted from DUT2:{}'.format(queue_counters_dict[vars.D2][dut2_intf][0], dut2_queue_cnt1))
        st.log('{} traffic transmitted from DUT2:{}'.format(queue_counters_dict[vars.D2][dut2_intf][1], dut2_queue_cnt2))
    except Exception as e:
        st.log("{} exception occurred at flow verification".format(e))
        return False
    if loss_less_list[0]:
        if not verify_loss_less_traffic(dut2_queue_cnt1, dut1_queue_cnt1):
            st.error('Traffic loss observed for priority-{} traffic'.format(queue_counters_dict[vars.D2][dut2_intf][0]))
            return False
    else:
        if not verify_lossy_traffic(dut2_queue_cnt1, dut1_queue_cnt1):
            st.error('Traffic loss not observed for priority-{} traffic'.format(queue_counters_dict[vars.D2][dut2_intf][0]))
            return False
    if loss_less_list[1]:
        if not verify_loss_less_traffic(dut2_queue_cnt2, dut1_queue_cnt2):
            st.error('Traffic loss observed for priority-{} traffic'.format(queue_counters_dict[vars.D2][dut2_intf][1]))
            return False
    else:
        if not verify_lossy_traffic(dut2_queue_cnt2, dut1_queue_cnt2):
            st.error('Traffic loss not observed for priority-{} traffic'.format(queue_counters_dict[vars.D2][dut2_intf][1]))
            return False
    return True

def verify_portchannel_state_using_thread(dut_list, port_channel_list, thread=True):
    sub_list = [[portchannel_obj.poll_for_portchannel_status, dut, port_channel_list[cnt]] for cnt, dut in
                enumerate(dut_list, start=0)]
    [output, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)
    if False in output:
        return False
    return True

def portchannel_config_prolog():
    st.log("Removing back to back connected ports from existing VLANs in both the DUTs")
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan, [vars.D1D2P1, vars.D1D2P2], True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan, [vars.D2D1P1, vars.D2D1P2], True]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan_1, vars.D1D2P1, True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan_1, vars.D2D1P1, True]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan_2, vars.D1D2P2, True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan_2, vars.D2D1P2, True]])[1]
    ensure_no_exception(exceptions)
    st.log('Creating port-channels and adding members in both DUTs')
    if not portchannel_obj.config_portchannel(vars.D1, vars.D2, pfc_data.portchannel_name1, vars.D1D2P1, vars.D2D1P1, "add"):
        st.error('Failed to create port-channel: {}'.format(pfc_data.portchannel_name1))
        return False
    if not portchannel_obj.config_portchannel(vars.D1, vars.D2, pfc_data.portchannel_name2, vars.D1D2P2, vars.D2D1P2, "add"):
        st.error('Failed to create port-channel: {}'.format(pfc_data.portchannel_name2))
        return False
    if not verify_portchannel_state_using_thread([vars.D1, vars.D2], [pfc_data.portchannel_name1, pfc_data.portchannel_name2]):
        st.error('Port-Channel is not Up')
        return False
    exceptions = exec_all(True, [ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, pfc_data.vlan, [pfc_data.portchannel_name1,  pfc_data.portchannel_name2], tagging_mode=True), ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, pfc_data.vlan, [pfc_data.portchannel_name1,  pfc_data.portchannel_name2], tagging_mode=True)])[1]
    ensure_no_exception(exceptions)
    config_mac(vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan, pfc_data.portchannel_name1)
    config_mac(vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan, pfc_data.portchannel_name2)
    return True

def portchannel_config_epilog():
    [output, exceptions] = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan, [pfc_data.portchannel_name1, pfc_data.portchannel_name2], True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan, [pfc_data.portchannel_name1, pfc_data.portchannel_name2], True]])
    if not all(output):
        st.report_fail("msg", "Failed to delete VLAN member ship")
    ensure_no_exception(exceptions)
    
    if not delete_mac(vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan):
        st.report_fail("msg", "Failed to delete static MAC: {}".format(pfc_data.destination_mac_dut1_tg1))
    if not delete_mac(vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan):
        st.report_fail("msg", "Failed to delete static MAC: {}".format(pfc_data.destination_mac_dut1_tg1))
    
    if not portchannel_obj.clear_portchannel_configuration([vars.D1, vars.D2]):
        st.report_fail("msg", "Failed to clear PortChannel configuration")
    
    [output, exceptions] = exec_all(True, [ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, pfc_data.vlan, [vars.D1D2P1, vars.D1D2P2], tagging_mode=True), ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, pfc_data.vlan, [vars.D2D1P1, vars.D2D1P2], tagging_mode=True)])
    if not all(output):
        st.report_fail("msg", "Failed to add ports to VLAN")
    ensure_no_exception(exceptions)
    
    [output, exceptions] = exec_all(True, [ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, pfc_data.vlan_1, vars.D1D2P1, tagging_mode=True), ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, pfc_data.vlan_1, vars.D2D1P1, tagging_mode=True)])
    if not all(output):
        st.report_fail("msg", "Failed to add ports to VLAN")
    ensure_no_exception(exceptions)
    [output, exceptions] = exec_all(True, [ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, pfc_data.vlan_2, vars.D1D2P2, tagging_mode=True), ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, pfc_data.vlan_2, vars.D2D1P2, tagging_mode=True)])
    if not all(output):
        st.report_fail("msg", "Failed to add ports to VLAN")
    ensure_no_exception(exceptions)
    if not config_mac(vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan, vars.D1D2P1):
        st.report_fail("msg", "Failed to configure static MAC: {}".format(pfc_data.destination_mac_dut1_tg1))
    if not config_mac(vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan, vars.D1D2P2):
        st.report_fail("msg", "Failed to configure static MAC: {}".format(pfc_data.destination_mac_dut1_tg2))
    if not config_mac(vars.D1, pfc_data.destination_mac_dut1_tg1, pfc_data.vlan_1, vars.D1D2P1):
        st.report_fail("msg", "Failed to configure static MAC: {}".format(pfc_data.destination_mac_dut1_tg1))
    if not config_mac(vars.D1, pfc_data.destination_mac_dut1_tg2, pfc_data.vlan_2, vars.D1D2P2):
        st.report_fail("msg", "Failed to configure static MAC: {}".format(pfc_data.destination_mac_dut1_tg2))
    get_debug_info(intf_counter=False, pfc_counter=False, queue_counter=False)

def pfc_enable(enable_pfc = True):
    if enable_pfc:
        dict1 = {'hwsku': pfc_data.hwsku1, 'ports_dict': {port: {'lossless_queues': pfc_data.lossless_priorities} for port in pfc_data.ports_list_dut1}}
        dict2 = {'hwsku': pfc_data.hwsku2, 'ports_dict': {port: {'lossless_queues': pfc_data.lossless_priorities} for port in pfc_data.ports_list_dut2}}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], pfc_obj.config_pfc_buffer_prameters, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.report_fail('msg', 'Failed to configure queues: {} as loss_less queues'.format(pfc_data.lossless_priorities))
        
        [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_lossless_queues, vars.D1, pfc_data.lossless_priorities, pfc_data.ports_list_dut1], [pfc_obj.config_pfc_lossless_queues, vars.D2, pfc_data.lossless_priorities, pfc_data.ports_list_dut2]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.report_fail('msg', 'Failed to configure queues: {} as loss_less queues'.format(pfc_data.lossless_priorities))
        
    else:
        dict1 = {'hwsku': pfc_data.hwsku1, 'ports_dict': {port: {'lossy_queues': pfc_data.lossless_priorities} for port in pfc_data.ports_list_dut1}}
        dict2 = {'hwsku': pfc_data.hwsku2, 'ports_dict': {port: {'lossy_queues': pfc_data.lossless_priorities} for port in pfc_data.ports_list_dut2}}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], pfc_obj.config_pfc_buffer_prameters, [dict1, dict2])
        ensure_no_exception(exceptions)
        if not all(output):
            st.report_fail('msg', 'Failed to configure queues: {} as lossy queues'.format(pfc_data.lossless_priorities))
        
        [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.config_pfc_lossless_queues, vars.D1, pfc_data.lossless_priorities, pfc_data.ports_list_dut1, config=False), ExecAllFunc(pfc_obj.config_pfc_lossless_queues, vars.D2, pfc_data.lossless_priorities, pfc_data.ports_list_dut2, config=False)])
        ensure_no_exception(exceptions)
        if not all(output):
            st.report_fail('msg', 'Failed to configure queues: {} as lossy queues'.format(pfc_data.lossless_priorities))

def config_ip_address():
    st.debug('Deleting ports VLAN membership')
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan, [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan, [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2], True]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan_1, [vars.D1T1P1, vars.D1D2P1], True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan_1, [vars.D2D1P1, vars.D2T1P1], True]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.delete_vlan_member, vars.D1, pfc_data.vlan_2, [vars.D1T1P2, vars.D1D2P2], True], [vlan_obj.delete_vlan_member, vars.D2, pfc_data.vlan_2, [vars.D2D1P2, vars.D2T1P1], True]])[1]
    ensure_no_exception(exceptions)
    [output, exceptions] = exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P1, '1.1.1.1', '8'],
                                           [ip_obj.config_ip_addr_interface, vars.D2, vars.D2D1P1, '3.3.3.2', '8']])
    ensure_no_exception(exceptions)
    if not all(output):
        return False
    [output, exceptions] = exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P2, '2.2.2.1', '8'],
                                           [ip_obj.config_ip_addr_interface, vars.D2, vars.D2D1P2, '4.4.4.2', '8']])
    ensure_no_exception(exceptions)
    if not all(output):
        return False
    [output, exceptions] = exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1D2P1, '3.3.3.1', '8'],
                                           [ip_obj.config_ip_addr_interface, vars.D2, vars.D2T1P1, '5.5.5.1', '8']])
    ensure_no_exception(exceptions)
    if not all(output):
        return False
    if not ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P2, '4.4.4.1', '8'):
        return False
    if not ip_obj.create_static_route(vars.D1, '3.3.3.2', '5.0.0.0/8'):
        return False
    [output, exceptions] = exec_all(True, [[ip_obj.create_static_route, vars.D1, '4.4.4.2', '6.0.0.0/8'],
                                           [ip_obj.create_static_route, vars.D2, '5.5.5.2', '6.0.0.0/8']])
    ensure_no_exception(exceptions)
    if not all(output):
        st.error("Failed to configure Static routes")
        return False
    if not add_static_arp(vars.D2, "5.5.5.2", "00:00:00:00:00:11", interface = vars.D2T1P1):
        return False
    return True

def unconfig_test_ft_pfc_sym_l3_interface():
    ip_obj.clear_ip_configuration([vars.D1, vars.D2])
    if not pfc_module_dut_prolog(mapping_config=False, apply_buffer_config=False, lossless_qos_map=False):
        return False
    [output, exceptions] = exec_all(True, [ExecAllFunc(ip_obj.delete_static_route, vars.D1, '3.3.3.2', '5.0.0.0/8'),
                                           ExecAllFunc(delete_static_arp, vars.D2, "5.5.5.2", interface = vars.D2T1P1, mac="00:00:00:00:00:11")])
    ensure_no_exception(exceptions)
    if not all(output):
        st.error("Failed to delete static route")
        return False
    [output, exceptions] = exec_all(True, [ExecAllFunc(ip_obj.delete_static_route, vars.D1, '4.4.4.2', '6.0.0.0/8'),
                                           ExecAllFunc(ip_obj.delete_static_route, vars.D2, "5.5.5.2", '6.0.0.0/8')])
    ensure_no_exception(exceptions)
    if not all(output):
        st.error("Failed to delete static route")
        return False
    get_debug_info(intf_counter=False, pfc_counter=False, queue_counter=False)

def pfc_wd_verify(intf, queue, wd_stats_list, is_action_forward = True):
    temp_result_list = []
    for wd_stats in wd_stats_list:
        try:
            if wd_stats['port']+":"+str(wd_stats['queue']) == intf+":"+str(queue):
                st.debug('storm_detect: {}'.format(wd_stats['storm_detect']))
                if not (int(wd_stats['storm_detect']) >= 1):
                    temp_result_list.append(False)
                    temp_result_list.append("Storm is not detected on Port: {}, Queue: {}".format(wd_stats['port'], wd_stats['queue']))
                    return temp_result_list
                if is_action_forward:
                    st.debug('tx_ok: {}, tx_drop: {}'.format(wd_stats['tx_ok'], wd_stats['tx_drop']))
                    if not ((int(wd_stats['tx_ok'])>=1) and (int(wd_stats['tx_drop']) == 0)):
                        temp_result_list.append(False)
                        temp_result_list.append("The traffic is not forwarded as per the forward action")
                        return temp_result_list
                else:
                    if not (int(wd_stats['tx_drop']) >= 1):
                        temp_result_list.append(False)
                        temp_result_list.append("The traffic is not dropped as per the drop action")
                        return temp_result_list
                temp_result_list.append(True)
                temp_result_list.append("PFC Watch dog statistics verification is successful")
                return temp_result_list
        except:
            temp_result_list.append(False)
            temp_result_list.append("PFC Watch dog statistics verification is failed - {}".format(wd_stats))
            return temp_result_list
    temp_result_list.append(False)
    temp_result_list.append("3: PFC Watch dog statistics verification is failed")
    return temp_result_list

def unconfig_test_ft_pfc_wd(dut, port_list):
    pfc_obj.stop_pfc_wd(dut, interface = port_list)
    pfc_obj.pfc_wd_counter_poll_config(vars.D1, False)

def verify_pfc_counters_initialization(dut_list, port_list, thread = True):
    params = list()
    for index, dut in enumerate(dut_list, start = 0):
        params.append(ExecAllFunc(utils.poll_wait, pfc_obj.verify_pfc_counters, 180, dut, port_list[index], mode = 'tx', pfc7 = 0))
    [out, exceptions] = exec_all(thread, params)
    st.log(exceptions)
    return False if False in out else True

def create_tg_stream(port_handle_list, src_mac_list, dst_mac_list, vlan_list, vlan_priority_list, dscp_list=[None],
                     src_ip_list=[None], dst_ip_list=[None], is_l2_stream=True):
    st.log("Reset TG ports")
    pfc_data.tg.tg_traffic_control(action='reset', port_handle=port_handle_list)
    st.log("Creating TG streams")
    pfc_data.stream_list = []
    for index, port_handler in enumerate(port_handle_list, start=0):
        if is_l2_stream:
            stream = pfc_data.tg.tg_traffic_config(port_handle=port_handler, mode='create', length_mode='random',
                     mac_src=src_mac_list[index], mac_src_mode='fixed', l2_encap='ethernet_ii_vlan',
                     mac_dst=dst_mac_list[index], mac_dst_mode='fixed', vlan="enable", vlan_id=vlan_list[index],
                     rate_percent=pfc_data.rate_percent, transmit_mode='continuous', vlan_user_priority=vlan_priority_list[index],
                     frame_size_min=pfc_data.pkt_size_min, frame_size_max=pfc_data.pkt_size_max)
            pfc_data.stream_list.append(stream['stream_id'])
        else:
            stream = pfc_data.tg.tg_traffic_config(port_handle=port_handler, mode='create', length_mode='random',
                     mac_src=src_mac_list[index], mac_src_mode='fixed', mac_dst=dst_mac_list[index],
                     mac_dst_mode='fixed', rate_percent=pfc_data.rate_percent, transmit_mode='continuous',
                     l3_protocol='ipv4', ip_src_addr=src_ip_list[index], ip_dst_addr=dst_ip_list[index],
                     ip_dscp=dscp_list[index], frame_size_min=pfc_data.pkt_size_min, frame_size_max=pfc_data.pkt_size_max)
            pfc_data.stream_list.append(stream['stream_id'])
    return pfc_data.stream_list

def get_debug_info(**kwargs):
    if kwargs.get("vlan_config", True):
        exceptions = exec_all(True, [[vlan_obj.show_vlan_config, vars.D1], [vlan_obj.show_vlan_config, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get("mac_config", True):
        exceptions = exec_all(True,[[get_mac, vars.D1], [get_mac, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get("running_config", True):
        exceptions = exec_all(True, [[get_running_config, vars.D1], [get_running_config, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get("intf_counter", True):
        exceptions = exec_all(True, [[interface_obj.show_interfaces_counters, vars.D1], [interface_obj.show_interfaces_counters, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get("pfc_counter", True):
        exceptions = exec_all(True, [[pfc_obj.show_pfc_counters, vars.D1], [pfc_obj.show_pfc_counters, vars.D2]])[1]
        ensure_no_exception(exceptions)
    if kwargs.get("queue_counter", True):
        exceptions = exec_all(True, [[interface_obj.show_queue_counters, vars.D1, vars.D1D2P1], [interface_obj.show_queue_counters, vars.D2, vars.D2T1P1]])[1]
        ensure_no_exception(exceptions)
        interface_obj.show_queue_counters(vars.D1, vars.D1D2P2)

def get_pfc_raw_stream(prioirty):
    if int(prioirty) == 0:
        raw_stream = "01010001ffff00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 1:
        raw_stream = "010100020000ffff0000000000000000000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 2:
        raw_stream = "0101000400000000ffff000000000000000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 3:
        raw_stream = "01010008000000000000ffff00000000000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 4:
        raw_stream = "010100100000000000000000ffff0000000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 5:
        raw_stream = "0101002000000000000000000000ffff000000000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 6:
        raw_stream = "01010040000000000000000000000000ffff00000000000000000000000000000000000000000000000000000000"
    elif int(prioirty) == 7:
        raw_stream = "010100800000000000000000000000000000ffff0000000000000000000000000000000000000000000000000000"
    else:
        raw_stream = "0101008000000000000000000000000000000000ffff000000000000000000000000000000000000000000000000"
    return raw_stream

def traffic_test_with_lossless_traffics(stream1, stream2, verify_clear_pfc_cnt= False):
    st.log("Test with Loss less traffics")
    clear_counters()
    if verify_clear_pfc_cnt:
        st.log('Verify whether the PFC counters are cleared or not')
        [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2T1P1, vars.D2D1P1, vars.D2D1P2])])
        ensure_no_exception(exceptions)
        pfc_counters_dict_list1, pfc_counters_dict_list2 = output
        if not verify_clear_pfc_counters(pfc_counters_dict_list1,
                                         [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D1))
            return False
        if not verify_clear_pfc_counters(pfc_counters_dict_list2, [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2],
                              ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D2))
            return False
    st.log("Sending traffic from both the TGs connected to Ports-{}, {} in DUT-{} for 3 seconds".format(vars.D1T1P1,
                                                                                                         vars.D1T1P2,
                                                                                                         vars.D1))
    pfc_data.tg.tg_traffic_control(action='run', stream_handle=[stream1, stream2], enable_arp=0)
    st.wait(pfc_data.wait_3)
    pfc_data.tg.tg_traffic_control(action='stop', stream_handle=[stream1, stream2])
    st.wait(pfc_data.wait_5)
    st.log("Fetching PFC counter statistics")
    [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2D1P1, vars.D2D1P2])])
    ensure_no_exception(exceptions)
    pfc_counters_dict_list1, pfc_counters_dict_list2 = output
    pfc_counter1 = 'pfc{}'.format(pfc_data.lossless_priorities[0])
    pfc_counter2 = 'pfc{}'.format(pfc_data.lossless_priorities[1])
    pfc_data.verify_pfc_counter_dict_list = [{'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Rx', 'counter': [pfc_counter1]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Rx', 'counter': [pfc_counter2]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Tx', 'counter': [pfc_counter1]},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Tx', 'counter': [pfc_counter2]}]
    if not verify_pfc_counters(pfc_data.verify_pfc_counter_dict_list):
        st.error('Invalid PFC counters after traffic test')
        return False
    st.log("Verifying queue counters")
    uc_list = ['UC{}'.format(pfc_data.lossless_priorities[0]), 'UC{}'.format(pfc_data.lossless_priorities[1])]
    if not utils.poll_wait(verify_queue_counters, 20, vars.D1D2P1, vars.D1D2P2, vars.D2T1P1, {vars.D1: {vars.D1D2P1: uc_list[0], vars.D1D2P2: uc_list[1]}, vars.D2: {vars.D2T1P1:uc_list}}, [True, True]):
        st.error("Queue counters verification failed")
        return False
    st.log('#####################Traffic test with both loss-less traffics is passed#####################')
    return True

def traffic_test_with_lossy_lossless_traffics(stream1, stream2, verify_clear_pfc_cnt= False):
    st.log("Test with Lossy and loss less traffics")
    clear_counters()
    if verify_clear_pfc_cnt:
        st.log('Verify whether the PFC counters are cleared or not')
        [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2T1P1, vars.D2D1P1, vars.D2D1P2])])
        ensure_no_exception(exceptions)
        pfc_counters_dict_list1, pfc_counters_dict_list2 = output
        if not verify_clear_pfc_counters(pfc_counters_dict_list1,
                                         [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D1))
            return False
        if not verify_clear_pfc_counters(pfc_counters_dict_list2, [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2],
                              ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D2))
            return False
    st.log("Sending traffic from both the TGs connected to Ports-{},{} in DUT-{} for 3 seconds".format(vars.D1T1P1,
                                                                                                         vars.D1T1P2,
                                                                                                         vars.D1))
    pfc_data.tg.tg_traffic_control(action='run', stream_handle=[stream1, stream2], enable_arp=0)
    st.wait(pfc_data.wait_3)
    pfc_data.tg.tg_traffic_control(action='stop', stream_handle=[stream1, stream2])
    st.wait(pfc_data.wait_5)
    st.log("Fetching PFC counter statistics")
    [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2D1P1, vars.D2D1P2])])
    ensure_no_exception(exceptions)
    pfc_counters_dict_list1, pfc_counters_dict_list2 = output
    pfc_counter = 'pfc{}'.format(pfc_data.lossless_priorities[0])
    pfc_data.verify_pfc_counter_dict_list = [{'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Rx', 'counter': [pfc_counter]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Tx', 'counter': [pfc_counter]},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Tx', 'counter': []}]
    if not verify_pfc_counters(pfc_data.verify_pfc_counter_dict_list):
        st.error('Invalid PFC counters after traffic test')
        return False

    st.log("Verifying queue counters")
    uc_list = ['UC{}'.format(pfc_data.lossless_priorities[0]), 'UC{}'.format(pfc_data.all_lossy_priority)]
    if not utils.poll_wait(verify_queue_counters, 20, vars.D1D2P1, vars.D1D2P2, vars.D2T1P1, {vars.D1: {vars.D1D2P1: uc_list[0], vars.D1D2P2: uc_list[1]}, vars.D2: {vars.D2T1P1:uc_list}}, [True, False]):
        st.error("Queue counters verification failed")
        return False
    st.log('#####################Traffic test with lossy, loss-less traffics is passed#####################')
    return True

def traffic_test_with_lossyrx_lossless_traffics(stream1, stream2, is_asym=False, verify_clear_pfc_cnt= False):
    st.log("Test with Lossy(Rx) and loss less traffics")
    clear_counters()
    if verify_clear_pfc_cnt:
        st.log('Verify whether the PFC counters are cleared or not')
        [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2T1P1, vars.D2D1P1, vars.D2D1P2])])
        ensure_no_exception(exceptions)
        pfc_counters_dict_list1, pfc_counters_dict_list2 = output
        if not verify_clear_pfc_counters(pfc_counters_dict_list1,
                                         [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D1))
            return False
        if not verify_clear_pfc_counters(pfc_counters_dict_list2, [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2],
                              ['Port Rx', 'Port Tx']):
            st.error('PFC Counters are not cleared properly in DUT:{}'.format(vars.D2))
            return False
    st.log("Sending traffic from both the TGs connected to Ports-{},{} in DUT-{} for 3 seconds".format(vars.D1T1P1,
                                                                                                         vars.D1T1P2,
                                                                                                         vars.D1))
    pfc_data.tg.tg_traffic_control(action='run', stream_handle=[stream1, stream2], enable_arp=0)
    st.wait(pfc_data.wait_3)
    pfc_data.tg.tg_traffic_control(action='stop', stream_handle=[stream1, stream2])
    st.wait(pfc_data.wait_5)
    st.log("Fetching PFC counter statistics")
    [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2D1P1, vars.D2D1P2])])
    ensure_no_exception(exceptions)
    pfc_counters_dict_list1, pfc_counters_dict_list2 = output
    pfc_counter1 = 'pfc{}'.format(pfc_data.asym_lossless_priority)
    pfc_counter2 = 'pfc{}'.format(pfc_data.lossless_priorities[1])
    pfc_data.verify_pfc_counter_dict_list = [{'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Rx', 'counter': [pfc_counter1]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Rx', 'counter': [pfc_counter2]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Tx', 'counter': [pfc_counter1]},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Tx', 'counter': [pfc_counter2]}]
    if not verify_pfc_counters(pfc_data.verify_pfc_counter_dict_list):
        st.error('Invalid PFC counters after traffic test')
        return False
    st.log("Verifying queue counters")
    uc_list = ['UC{}'.format(pfc_data.asym_lossless_priority), 'UC{}'.format(pfc_data.lossless_priorities[1])]
    if not utils.poll_wait(verify_queue_counters, 20, vars.D1D2P1, vars.D1D2P2, vars.D2T1P1, {vars.D1: {vars.D1D2P1: uc_list[0], vars.D1D2P2: uc_list[1]}, vars.D2: {vars.D2T1P1:uc_list}}, [is_asym, True]):
        st.error("Queue counters verification failed")
        return False
    st.log('#####################Traffic test with both lossyrx, loss-less traffics is passed#####################')
    return True

def traffic_test_congestion_in_both_duts(stream1, stream2, stream3, is_asym=False):
    st.log("Test with Lossy(Rx) and loss less traffics")
    clear_counters()
    st.log("Sending traffic from both the TGs connected to Ports-{},{} in DUT-{} and TG connected to Port-{} in "
           "DUT-{} for 3 seconds".format(vars.D1T1P1, vars.D1T1P2, vars.D1, vars.D2T1P1, vars.D2))
    pfc_data.tg.tg_traffic_control(action='run', stream_handle=[stream1, stream2, stream3], enable_arp=0)
    st.wait(pfc_data.wait_3)
    pfc_data.tg.tg_traffic_control(action='stop', stream_handle=[stream1, stream2, stream3])
    st.wait(pfc_data.wait_5)
    st.log("Fetching PFC counter statistics")
    [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2T1P2, vars.D2D1P1, vars.D2D1P2])])
    ensure_no_exception(exceptions)
    pfc_counters_dict_list1, pfc_counters_dict_list2 = output
    pfc_counter1 = 'pfc{}'.format(pfc_data.asym_lossless_priority)
    pfc_counter2 = 'pfc{}'.format(pfc_data.lossless_priorities[1])
    pfc_data.verify_pfc_counter_dict_list = [{'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Rx', 'counter': [pfc_counter1, pfc_counter2]},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P1, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1D2P2, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1T1P1, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D1, 'pfc_counters_dict_list': pfc_counters_dict_list1,
                                          'port': vars.D1T1P2, 'mode': 'Port Tx', 'counter': [pfc_counter2]},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P1, 'mode': 'Port Tx', 'counter': [pfc_counter1, pfc_counter2]},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Rx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2D1P2, 'mode': 'Port Tx', 'counter': []},
                                         {'dut': vars.D2, 'pfc_counters_dict_list': pfc_counters_dict_list2,
                                          'port': vars.D2T1P2, 'mode': 'Port Tx', 'counter': []}]
    if not verify_pfc_counters(pfc_data.verify_pfc_counter_dict_list):
        st.error('Invalid PFC counters after traffic test')
        return False
    st.log("Verifying queue counters")
    uc_list = ['UC{}'.format(pfc_data.asym_lossless_priority), 'UC{}'.format(pfc_data.lossless_priorities[1])]
    if not utils.poll_wait(verify_queue_counters, 12, vars.D1D2P1, None, vars.D2T1P1, {vars.D1: {vars.D1D2P1: uc_list}, vars.D2: {vars.D2T1P1:uc_list}}, [is_asym, True], multi_dut=True):
        st.error("Queue counters verification failed")
        return False
    st.log('#####################Traffic test with both lossyrx, loss-less traffics is passed#####################')
    return True

def traffic_test_with_pfc_disable(stream1, stream2):
    st.log("Test with Lossy and loss less traffics")
    clear_counters()
    st.log("Sending traffic from both the TGs connected to Ports-{},{} in DUT-{} for 3 seconds".format(vars.D1T1P1,
                                                                                                         vars.D1T1P2,
                                                                                                         vars.D1))
    pfc_data.tg.tg_traffic_control(action='run', stream_handle=[stream1, stream2], enable_arp=0)
    st.wait(pfc_data.wait_3)
    pfc_data.tg.tg_traffic_control(action='stop', stream_handle=[stream1, stream2])
    st.wait(pfc_data.wait_5)
    st.log('Verify that PFC counters are not incremented')
    st.log("Fetching PFC counter statistics")
    [output, exceptions] = exec_all(True, [ExecAllFunc(pfc_obj.show_pfc_counters, vars.D1, ports=[vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2]), ExecAllFunc(pfc_obj.show_pfc_counters, vars.D2, ports=[vars.D2T1P1, vars.D2D1P1, vars.D2D1P2])])
    ensure_no_exception(exceptions)
    pfc_counters_dict_list1, pfc_counters_dict_list2 = output
    if not verify_clear_pfc_counters(pfc_counters_dict_list1, [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], ['Port Rx', 'Port Tx']):
        st.error('PFC Counters are incremented in DUT:{} even the PFC is disabled'.format(vars.D1))
        return False
    if not verify_clear_pfc_counters(pfc_counters_dict_list2, [vars.D2T1P1, vars.D2D1P1, vars.D2D1P2],
                              ['Port Rx', 'Port Tx']):
        st.error('PFC Counters are incremented in DUT:{} even the PFC is disabled'.format(vars.D2))
        return False
    st.log("Verifying queue counters")
    uc_list = ['UC{}'.format(pfc_data.lossless_priorities[0]), 'UC{}'.format(pfc_data.all_lossy_priority)]
    if not utils.poll_wait(verify_queue_counters, 20, vars.D1D2P1, vars.D1D2P2, vars.D2T1P1, {vars.D1: {vars.D1D2P1: uc_list[0], vars.D1D2P2: uc_list[1]}, vars.D2: {vars.D2T1P1:uc_list}}, [False, False]):
        st.error("Queue counters verification failed")
        return False
    st.log('#####################Lossy and loss-less traffics are treated equally if PFC is disabled#####################')
    return True

def traffic_test_for_pfcwd(dut, stream_list, detection_time_list, interface_list, queue_list, is_action_forward_list):
    clear_counters()
    st.log("Sending traffic from TG")
    pfc_data.tg.tg_traffic_control(action='run', stream_handle = stream_list, enable_arp=0)
    pfc_data.tg.tg_traffic_control(action='run', stream_handle = [pfc_data.streams['pause_frames_stream1'], pfc_data.streams['pause_frames_stream2']], enable_arp=0)
    wait_time = (int(detection_time_list[0])+int(detection_time_list[1]))/100 + 4
    st.wait(wait_time)
    pfc_data.tg.tg_traffic_control(action='stop', port_handle=[pfc_data.tg_ph_3, pfc_data.tg_ph_4])
    pfc_data.tg.tg_traffic_control(action='stop', port_handle=[pfc_data.tg_ph_1, pfc_data.tg_ph_2])
    for cnt, interface in enumerate(interface_list, start=0):
        st.log('cnt {}, interface {}'.format(cnt, interface))
        iter_count = 1
        temp_result = False
        while (iter_count <= 5):
            st.log("Iteration:{} Verifying PFC-WD functionality on Port-{}".format(iter_count, interface))
            wd_stats_list = pfc_obj.show_pfc_wd_stats(dut, ports = interface)
            st.log(" interface  - {}".format(interface))
            st.log("queue_list[cnt]   - {}".format(queue_list[cnt]))
            st.log(" wd_stats_list  - {}".format(wd_stats_list))
            st.log(" is_action_forward_list[cnt]  - {}".format(is_action_forward_list[cnt]))
            pfcwd_detect = pfc_wd_verify(interface, queue_list[cnt], wd_stats_list, is_action_forward_list[cnt])
            st.log("pfcwd_detect   - {}".format(pfcwd_detect))
            if pfcwd_detect[0] == True:
                temp_result = True
                iter_count = 6
            if ((temp_result == False) and (iter_count >= 5)):
                st.error(pfcwd_detect[1])
                return False
            st.wait(pfc_data.wait_2)
            iter_count += 1
    st.log('#####################Successfully verified PFC watch dog functionality#####################')
    return True



def test_ft_pfc_asym():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify Asymmetric PFC functionality
    '''
    result_dict = {'ft_pfc_asym_10g': True, 'ft_pfc_asym_10g_rcvd_pause_all': True}
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_user_priority=pfc_data.all_lossy_priority)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        st.error("######## Traffic validation with lossy and loss-less traffic is failed ########")
        result_dict['ft_pfc_asym_10g'] = False
        get_debug_info()
        exec_all(True, [[st.generate_tech_support, vars.D1, 'ft_pfc_asym_10g'], [st.generate_tech_support, vars.D2, 'ft_pfc_asym_10g']])
    
    if not config_sym_asym_pfc_buffer(pfc_data.lossless_priorities, pfc_data.asym_test_priorities):
        st.report_fail('msg', 'Failed to configure lossy-lossless priorities configuration on DUT2')
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'], is_asym=True):
        st.error("######## Traffic validation with loss-less(only for D2) and loss-less(for both D1, D2) traffic is failed ########")
        result_dict['ft_pfc_asym_10g_rcvd_pause_all'] = False
        get_debug_info()
        exec_all(True, [[st.generate_tech_support, vars.D1, 'ft_pfc_asym_10g_rcvd_pause_all'], [st.generate_tech_support, vars.D2, 'ft_pfc_asym_10g_rcvd_pause_all']])
    config_sym_asym_pfc_buffer(pfc_data.asym_test_priorities, pfc_data.lossless_priorities)
    for testcase, result in result_dict.items():
        if result:
            st.report_tc_pass(testcase, "test_case_passed")
    if all(list(result_dict.values())):
        st.report_pass('msg', 'Successfully validated asymmetric PFC functionality')
    else:
        st.report_fail('msg', 'Failed to validate asymmetric PFC functionality')


def test_ft_pfc_asym_cold_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify asymmetric PFC functionality after cold boot
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with both loss-less priority streams in asymmetric PFC mode')
    if not config_save([vars.D1, vars.D2]):
        get_debug_info()
        st.report_fail("msg", "Failed to save configuration")
    exec_all(True, [[st.reboot, vars.D1], [st.reboot, vars.D2]])
    if not traffic_test_with_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with both loss-less priority streams in asymmetric PFC mode after cold-boot')
    st.report_pass("msg", "Successfully validated PFC asymmetric functionality with cold-reboot")


def test_ft_pfc_asym_multi_vlan():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify Asymmetric PFC functionality with multi VLAN traffic
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'],is_asym=True):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with lossy-rx, loss-less priority streams in asymmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_asym_warm_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify asymmetric PFC functionality after warm boot
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.all_lossy_priority)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with lossy and loss-less priority streams in asymmetric PFC mode')
    exec_all(True, [[st.reboot, vars.D1, 'warm'], [st.reboot, vars.D2, 'warm']])
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with lossy and loss-less priority streams in asymmetric PFC mode after warm-boot')
    st.report_pass("msg", "Successfully validated PFC asymmetric functionality with warm-reboot")


def test_ft_pfc_asym_congestion_in_both_duts():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify Asymmetric PFC functionality with congestion in both DUTs
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], mac_dst=pfc_data.destination_mac_dut1_tg1, vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_congestion_in_both_duts(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'],
         pfc_data.streams['d2tg2_stream'], is_asym = True):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with congestion on both the DUTs with asymmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_asym_portchannel():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify Asymmetric PFC functionality on Port-Channel member ports
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], mac_dst=pfc_data.destination_mac_dut1_tg2, vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'], is_asym=True):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'on port-channel member ports with asymmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_sym():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality
    '''
    result_dict = {'ft_pfc_sym_10g_lossless': True, 'ft_pfc_sym_10g_both_lossy_lossless_traffics': True, 'FtOpSoSys8021QbbScal001': True}
    if not verify_pfc_counters_initialization([vars.D1, vars.D2], [vars.D1D2P1, vars.D2D1P1]):
        st.report_fail('pfc_counters_not_initialized', 180)
    [output, exceptions] = exec_all(True, [[pfc_obj.config_pfc_asymmetric, vars.D1, 'off', pfc_data.ports_list_dut1], [pfc_obj.config_pfc_asymmetric, vars.D2, 'off', pfc_data.ports_list_dut2]])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail('msg', 'Failed to configure the asymmetric mode as off')
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        st.error("######## Traffic validation with both loss-less traffics is failed ########")
        result_dict['ft_pfc_sym_10g_lossless'] = False
        get_debug_info()
        exec_all(True, [[st.generate_tech_support, vars.D1, 'ft_pfc_sym_10g_lossless'], [st.generate_tech_support, vars.D2, 'ft_pfc_sym_10g_lossless']])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_user_priority=pfc_data.all_lossy_priority)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        st.error("######## Traffic validation with lossy and loss-less traffic is failed ########")
        result_dict['ft_pfc_sym_10g_both_lossy_lossless_traffics'] = False
        get_debug_info()
        exec_all(True, [[st.generate_tech_support, vars.D1, 'ft_pfc_sym_10g_both_lossy_lossless_traffics'], [st.generate_tech_support, vars.D2, 'ft_pfc_sym_10g_both_lossy_lossless_traffics']])
    if pfc_obj.config_pfc_lossless_queues(vars.D2, pfc_data.all_lossy_priority, vars.D2T1P2, skip_error=True):
        st.error("######## Allowed to configure more than two priorities as loss-less ########")
        result_dict['FtOpSoSys8021QbbScal001'] = False
        get_debug_info()
        exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSys8021QbbScal001'], [st.generate_tech_support, vars.D2, 'FtOpSoSys8021QbbScal001']])
    for testcase, result in result_dict.items():
        if result:
            st.report_tc_pass(testcase, "test_case_passed")
    if all(list(result_dict.values())):
        st.report_pass('msg', 'Successfully validated symmetric PFC functionality')
    else:
        st.report_fail('msg', 'Failed to validate symmetric PFC functionality')


def test_ft_pfc_sym_cold_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality after cold boot
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with loss-less(only for D2) and loss-less(for both D1, D2) priority streams in symmetric PFC mode')
    if not config_save([vars.D1, vars.D2]):
        get_debug_info()
        st.report_fail("msg", "Failed to save configuration")
    exec_all(True, [[st.reboot, vars.D1], [st.reboot, vars.D2]])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with loss-less(only for D2) and loss-less(for both D1, D2) priority streams in symmetric PFC mode after cold-boot')
    st.report_pass("test_case_passed")


def test_ft_pfc_sym_multi_vlan():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality with multi VLAN traffic
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'], verify_clear_pfc_cnt=True):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with loss-less(only for D2) and loss-less(for both D1, D2) priority streams in symmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_sym_warm_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality after warm boot
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with both loss-less priority streams in symmetric PFC mode')
    exec_all(True, [[st.reboot, vars.D1, 'warm'], [st.reboot, vars.D2, 'warm']])
    if not traffic_test_with_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with both loss-less priority streams in symmetric PFC mode after warm-boot')
    st.report_pass("test_case_passed")


def test_ft_pfc_save_reload():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify PFC functionality after save and reload
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.all_lossy_priority)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with lossy and loss-less priority streams in symmetric PFC mode')
    if not config_save_reload([vars.D1, vars.D2]):
        get_debug_info()
        st.report_fail("msg", "Configuration save reload failed")
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with both lossy and loss-less priority streams in symmetric PFC mode after save-reload')
    st.report_pass("test_case_passed")


def test_ft_pfc_with_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify PFC functionality after shut and no-shut operation on the ports
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan_1, vlan_user_priority=pfc_data.lossless_priorities[0])
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], vlan_id=pfc_data.vlan_2, vlan_user_priority=pfc_data.all_lossy_priority)
    for _ in range(5):
        exceptions = exec_all(True, [[interface_obj.interface_operation, vars.D1, pfc_data.ports_list_dut1, 'shutdown'], [interface_obj.interface_operation, vars.D2, pfc_data.ports_list_dut2, 'shutdown']])[1]
        ensure_no_exception(exceptions)
        exceptions = exec_all(True, [[interface_obj.interface_operation, vars.D1, pfc_data.ports_list_dut1, 'startup'], [interface_obj.interface_operation, vars.D2, pfc_data.ports_list_dut2, 'startup']])[1]
        ensure_no_exception(exceptions)
    [output, exceptions] = exec_all(True, [ExecAllFunc(utils.poll_wait, interface_obj.verify_interface_status, 60, vars.D1, [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1, vars.D1D2P2], 'oper', 'up'), ExecAllFunc(utils.poll_wait, interface_obj.verify_interface_status, 60, vars.D2, [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1, vars.D2D1P2], 'oper', 'up')])
    ensure_no_exception(exceptions)
    if not all(output):
        st.report_fail("msg", "Ports are not up after port shutdown and no-shutdown")
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'after ports shutdown and do-shutdown operation')
    st.report_pass("test_case_passed")


def test_ft_pfc_congestion_in_both_duts():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify PFC functionality with congestion in both DUTs
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], mac_dst=pfc_data.destination_mac_dut1_tg1, vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_congestion_in_both_duts(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'],
         pfc_data.streams['d2tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'with congestion on both the DUTs with symmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_sym_portchannel():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality on Port-Channel memeber ports
    '''
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg1_stream'], vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.asym_lossless_priority)
    pfc_data.tg.tg_traffic_config(mode='modify', stream_id=pfc_data.streams['d1tg2_stream'], mac_dst=pfc_data.destination_mac_dut1_tg2, vlan_id=pfc_data.vlan, vlan_user_priority=pfc_data.lossless_priorities[1])
    if not traffic_test_with_lossyrx_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'on port-channel member ports with symmetric PFC mode')
    st.report_pass("test_case_passed")


def test_ft_pfc_sym_l3_interface():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality on L3 interface
    '''
    pfc_data.streams['D1T1P1_L3_Stream'], pfc_data.streams['D1T1P2_L3_Stream'] =create_tg_stream([pfc_data.tg_ph_1, pfc_data.tg_ph_2], [pfc_data.source_mac_dut1_tg1, pfc_data.source_mac_dut1_tg2], [pfc_data.dut_rt_int_mac, pfc_data.dut_rt_int_mac], None, None, dscp_list=pfc_data.dscp_list, src_ip_list=['1.1.1.2', '2.2.2.2'], dst_ip_list=['5.5.5.2', '6.6.6.2'], is_l2_stream=False)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['D1T1P1_L3_Stream'], pfc_data.streams['D1T1P2_L3_Stream']):
        get_debug_info()
        st.report_fail('pfc_validation_fail', 'on L3 interfaces')
    st.report_pass("test_case_passed")


def test_ft_pfc_disable_enable():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify symmetric PFC functionality with feature enable and disable operation
    '''
    pfc_enable(enable_pfc = False)
    get_debug_info()
    pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream'] = create_tg_stream([pfc_data.tg_ph_1, pfc_data.tg_ph_2], [pfc_data.source_mac_dut1_tg1, pfc_data.source_mac_dut1_tg2], [pfc_data.destination_mac_dut1_tg1, pfc_data.destination_mac_dut1_tg2], [pfc_data.vlan, pfc_data.vlan], [pfc_data.lossless_priorities[0], pfc_data.all_lossy_priority])
    if not traffic_test_with_pfc_disable(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_tc_fail('FtOpSoSysPFCFn021', 'pfc_validation_fail', 'in disabled case')
    pfc_enable(enable_pfc = True)
    if not traffic_test_with_lossy_lossless_traffics(pfc_data.streams['d1tg1_stream'], pfc_data.streams['d1tg2_stream']):
        get_debug_info()
        st.report_tc_fail('FtOpSoSysPFCFn023', 'pfc_validation_fail', 'after PFC disable and enable case')
    st.report_pass("test_case_passed")


def test_ft_pfc_wd():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Verify PFC watch dog functionality
    '''
    if not pfc_obj.pfc_wd_counter_poll_interval(vars.D1, pfc_data.polling_interval):
        st.report_fail('polling_interval_config_failed')
    if not pfc_obj.start_pfc_wd(vars.D1, 'forward', pfc_data.detection_time1, pfc_data.restoration_time1, interface=[vars.D1T1P1]):
        unconfig_test_ft_pfc_wd(vars.D1, [vars.D1T1P1, vars.D1T1P2])
        st.report_fail('start_pfc_wd_fail')
    if not pfc_obj.start_pfc_wd(vars.D1, 'drop', pfc_data.detection_time2, pfc_data.restoration_time2, interface=[vars.D1T1P2]):
        unconfig_test_ft_pfc_wd(vars.D1, [vars.D1T1P1, vars.D1T1P2])
        st.report_fail('start_pfc_wd_fail')
    if not pfc_obj.pfc_wd_counter_poll_config(vars.D1, True):
        st.report_fail('polling_enable_failed')
    pfc_data.tg.tg_traffic_control(action='reset', port_handle=[pfc_data.tg_ph_1, pfc_data.tg_ph_2, pfc_data.tg_ph_3, pfc_data.tg_ph_4])
    pfc_data.streams['D2T1P1_Priority3_Stream'], pfc_data.streams['D2T1P2_Priority5_Stream'] = create_tg_stream([pfc_data.tg_ph_4, pfc_data.tg_ph_3], [pfc_data.source_mac_dut2_tg1, pfc_data.source_mac_dut2_tg2], [pfc_data.destination_mac_dut2_tg1, pfc_data.destination_mac_dut2_tg2], [pfc_data.vlan, pfc_data.vlan], pfc_data.lossless_priorities)
    stream_data = get_pfc_raw_stream(pfc_data.lossless_priorities[0])
    stream = pfc_data.tg.tg_traffic_config(port_handle=pfc_data.tg_ph_1, mode='create', l2_encap='ethernet_ii', transmit_mode='continuous', rate_percent=pfc_data.rate_percent, mac_src='00:00:ab:cd:06:05',mac_dst='01:80:C2:00:00:01', ethernet_value='8808', data_pattern_mode='fixed', data_pattern=stream_data)
    pfc_data.streams['pause_frames_stream1'] = stream['stream_id']
    stream_data = get_pfc_raw_stream(pfc_data.lossless_priorities[1])
    stream = pfc_data.tg.tg_traffic_config(port_handle=pfc_data.tg_ph_2, mode='create', l2_encap='ethernet_ii', transmit_mode='continuous', rate_percent=pfc_data.rate_percent, mac_src='00:00:ab:cd:05:06',mac_dst='01:80:C2:00:00:01', ethernet_value='8808', data_pattern_mode='fixed', data_pattern=stream_data)
    pfc_data.streams['pause_frames_stream2'] = stream['stream_id']
    exceptions = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut2_tg1, pfc_data.vlan, vars.D1T1P1],
                                 [config_mac, vars.D2, pfc_data.destination_mac_dut2_tg1, pfc_data.vlan, vars.D2D1P1]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[config_mac, vars.D1, pfc_data.destination_mac_dut2_tg2, pfc_data.vlan, vars.D1T1P2],
                                 [config_mac, vars.D2, pfc_data.destination_mac_dut2_tg2, pfc_data.vlan, vars.D2D1P2]])[1]
    ensure_no_exception(exceptions)
    if not traffic_test_for_pfcwd(vars.D1, [pfc_data.streams['D2T1P1_Priority3_Stream'], pfc_data.streams['D2T1P2_Priority5_Stream']], [pfc_data.detection_time1, pfc_data.detection_time2], [vars.D1T1P1, vars.D1T1P2], pfc_data.lossless_priorities, [True, False]):
        get_debug_info()
        unconfig_test_ft_pfc_wd(vars.D1, [vars.D1T1P1, vars.D1T1P2])
        st.report_tc_fail('FtOpSoSysPFCWdFn022', 'invalid_pfc_rx_counter', vars.D1D2P1, vars.D1)
    else:
        st.report_tc_pass('FtOpSoSysPFCWdFn022', 'test_case_passed')
    st.debug('Warm reboot the devices')
    exec_all(True, [[st.reboot, vars.D1, 'warm'], [st.reboot, vars.D2, 'warm']])
    if not pfc_obj.pfc_wd_counter_poll_config(vars.D1, True):
        st.report_fail('polling_enable_failed')
    pfc_obj.clear_pfc_counters(vars.D1, cli_type='click') ##Added for debug as per SONIC-30677
    pfc_obj.show_pfc_wd_stats(vars.D1, cli_type='click')
    if not traffic_test_for_pfcwd(vars.D1, [pfc_data.streams['D2T1P1_Priority3_Stream'], pfc_data.streams['D2T1P2_Priority5_Stream']], [pfc_data.detection_time1, pfc_data.detection_time2], [vars.D1T1P1, vars.D1T1P2], pfc_data.lossless_priorities, [True, False]):
        get_debug_info()
        pfc_obj.show_pfc_wd_stats(vars.D1, cli_type='click')
        unconfig_test_ft_pfc_wd(vars.D1, [vars.D1T1P1, vars.D1T1P2])
        st.report_fail('invalid_pfc_rx_counter', vars.D1D2P1, vars.D1)
    unconfig_test_ft_pfc_wd(vars.D1, [vars.D1T1P1, vars.D1T1P2])
    st.report_pass("test_case_passed")
