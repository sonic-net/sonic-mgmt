import pytest
from re import findall
from random import sample

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list, poll_wait

from apis.system.interface import show_interface_counters_all, clear_interface_counters, interface_operation
from apis.system.reboot import config_save, config_save_reload
from apis.system.basic import get_ifconfig_ether
import apis.switching.portchannel as lag_api
import apis.switching.vlan as vlan
import apis.routing.ip as ip
from apis.routing.arp import add_static_arp, delete_static_arp

from utilities.parallel import exec_all, exec_parallel, ensure_no_exception
from utilities.common import make_list, filter_and_select, ExecAllFunc

lag_data = SpyTestDict()

def initialize_variables():
    lag_data.clear()
    lag_data.random_vlan = str(random_vlan_list()[0])
    lag_data.portchannel_name = 'PortChannel7'
    lag_data.cli_type = 'click'
    lag_data.lag_up = 'Up'
    lag_data.lag_down = 'Dw'
    lag_data.source_mac = '00:05:00:00:00:01'
    lag_data.destination_mac = '00:06:00:00:00:02'
    lag_data.host_mac = '00:09:00:00:00:01'
    lag_data.mac_step = '00:00:00:00:00:01'
    lag_data.mac_count = 200
    lag_data.frame_size = 90
    lag_data.pkts_per_burst = 2000
    lag_data.dut1_tg_port_ip = '20.0.0.1'
    lag_data.dut2_tg_port_ip = '40.0.0.1'
    lag_data.dut1_lag_port_ip = '30.0.0.1'
    lag_data.dut2_lag_port_ip = '30.0.0.2'
    lag_data.dut1_tg_src_ip = '20.0.0.2'
    lag_data.dut1_tg_dst_ip = '40.0.0.2'
    lag_data.dest_network = '40.0.0.0'
    lag_data.dut_rt_int_mac = get_ifconfig_ether(vars.D1, vars.D1T1P1)
    lag_data.members_dut1 = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    lag_data.sorted_members_dut1 = get_ports_in_order(vars.D1, lag_data.members_dut1)
    lag_data.members_dut2 = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    lag_data.sorted_members_dut2 = get_ports_in_order(vars.D2, lag_data.members_dut2)
    st.debug('DUT1 ports are:{}'.format(lag_data.members_dut1))
    st.debug('DUT2 ports are:{}'.format(lag_data.members_dut2))
    st.debug('DUT1 ports after sorting are:{}'.format(lag_data.sorted_members_dut1))
    st.debug('DUT2 ports after sorting are:{}'.format(lag_data.sorted_members_dut2))


@pytest.fixture(scope="module", autouse=True)
def portchannel_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:1", "D2T1:1")
    initialize_variables()
    [output, exceptions] = exec_all(True, [[lacp_fallback_module_tg_config_prolog], [lacp_fallback_module_dut_config_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('module_config_failed', 'on DUT')
    yield
    if not vlan.clear_vlan_configuration([vars.D1, vars.D2]):
        st.report_fail('vlan_config_clear_failed')
    if not lag_api.clear_portchannel_configuration([vars.D1, vars.D2]):
        st.report_fail('portchannel_config_clear_failed')
    dict1 = {'interfaces': lag_data.members_dut1, 'operation': 'startup'}
    dict2 = {'interfaces': lag_data.members_dut2, 'operation': 'startup'}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], interface_operation, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('interface_admin_startup_fail', 'in both DUTs')


@pytest.fixture(scope="function", autouse=True)
def portchannel_func_hooks(request):
    yield
    if st.get_func_name(request) == 'test_ft_lag_fallback':
        lag_data.tg1.tg_traffic_config(mode='enable', stream_id=lag_data.streams['lacp_l2_tagged_stream'], high_speed_result_analysis=1)
        lag_data.tg1.tg_traffic_config(mode='disable', stream_id=lag_data.streams['lacp_l2_untagged_stream'],)
        if not ft_lag_fallback_epilog():
            st.report_fail('test_case_failed')
    if st.get_func_name(request) == 'test_ft_lag_fallback_l3_traffic':
        if not ft_lag_fallback_l3_traffic_epilog():
            st.report_fail('test_case_failed')
    elif st.get_func_name(request) == 'test_nt_lag_fallback_all_members_shut_noshut':
        if not interface_operation(vars.D1, lag_data.members_dut1, operation='startup'):
            st.report_fail('interface_admin_startup_fail', lag_data.members_dut1)
    elif st.get_func_name(request) == 'test_nt_lag_fallback_members_multiple_shut_noshut':
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.members_dut2):
            st.report_fail('portchannel_config_clear_failed')
    elif st.get_func_name(request) in ['test_lr_lacp_fallback_cold_boot', 'test_lr_lacp_fallback_save_reload', 'test_lr_lacp_fallback_fast_boot', 'test_lr_lacp_fallback_warm_boot']:
        if not vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode = True, skip_error_check=True):
            st.report_fail('vlan_member_deletion_failed', 'in DUT2')
    elif st.get_func_name(request) == 'test_lr_lacp_fallback_graceful_restart':
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.members_dut2):
            st.report_fail('portchannel_config_clear_failed')
    else:
        pass


def get_ports_in_order(dut, ports_list):
    ports = make_list(ports_list)
    if any("/" in port for port in ports_list):
        ports = st.get_other_names(dut, ports_list)
    port_index_list = findall(r"\d+", ",".join(ports))
    port_index_list = [int(port_index) for port_index in port_index_list]
    port_index_list.sort()
    final_ports_list = ['Ethernet{}'.format(port_index) for port_index in port_index_list]
    if any("/" in port for port in ports_list):
        final_ports_list = st.get_other_names(dut, final_ports_list)
    return final_ports_list


def lacp_fallback_module_tg_config_prolog():
    lag_data.tg1, lag_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    lag_data.tg2, lag_data.tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    lag_data.tg = lag_data.tg1
    lag_data.tg.tg_traffic_control(action='reset', port_handle=[lag_data.tg_ph_1, lag_data.tg_ph_2])
    lag_data.streams = {}
    stream = lag_data.tg.tg_traffic_config(port_handle=lag_data.tg_ph_1, mode='create', length_mode='fixed',
             frame_size=lag_data.frame_size, mac_src=lag_data.source_mac, mac_src_step=lag_data.mac_step,
             mac_src_mode='increment', mac_src_count=lag_data.mac_count, mac_dst=lag_data.destination_mac,
             mac_dst_step=lag_data.mac_step, mac_dst_mode='increment', mac_dst_count=lag_data.mac_count,
             transmit_mode='single_burst', l2_encap='ethernet_ii_vlan', vlan='enable', vlan_id=lag_data.random_vlan,
             pkts_per_burst=lag_data.pkts_per_burst, high_speed_result_analysis=1)
    lag_data.streams['lacp_l2_tagged_stream'] = stream['stream_id']
    stream = lag_data.tg.tg_traffic_config(port_handle=lag_data.tg_ph_1, mode='create', length_mode='fixed',
             frame_size=lag_data.frame_size, mac_src=lag_data.source_mac, mac_src_step=lag_data.mac_step,
             mac_src_count=lag_data.mac_count, mac_src_mode='increment', mac_dst=lag_data.destination_mac,
             mac_dst_step=lag_data.mac_step, mac_dst_mode='increment', mac_dst_count=lag_data.mac_count,
             transmit_mode='single_burst', l2_encap='ethernet_ii', pkts_per_burst=lag_data.pkts_per_burst, high_speed_result_analysis=1)
    lag_data.streams['lacp_l2_untagged_stream'] = stream['stream_id']
    stream = lag_data.tg.tg_traffic_config(port_handle=lag_data.tg_ph_1, mode='create', length_mode='fixed',
             frame_size=lag_data.frame_size, mac_src=lag_data.source_mac, mac_src_step=lag_data.mac_step,
             mac_src_count=lag_data.mac_count, mac_src_mode='increment', mac_dst=lag_data.dut_rt_int_mac,
             mac_dst_mode='fixed', ip_src_addr=lag_data.dut1_tg_src_ip, ip_src_mode='increment', ip_src_step='0.0.0.1',
             ip_src_count=lag_data.mac_count, ip_dst_addr=lag_data.dut1_tg_dst_ip, l3_protocol='ipv4',
             ip_dst_mode='fixed', transmit_mode='single_burst', pkts_per_burst=lag_data.pkts_per_burst)
    lag_data.streams['lacp_l3_stream'] = stream['stream_id']
    return True

def lacp_fallback_module_dut_config_prolog():
    dict1 = {'portchannel_list': [lag_data.portchannel_name], 'fallback': True}
    dict2 = {'portchannel_list': [lag_data.portchannel_name], 'fallback': False}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], lag_api.create_portchannel, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to create Port-Channel: {}'.format(lag_data.portchannel_name))
        return False
    [output, exceptions] = exec_all(True, [[vlan.create_vlan, vars.D1, lag_data.random_vlan], [vlan.create_vlan, vars.D2, lag_data.random_vlan]])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to create VLAN: {}'.format(lag_data.random_vlan))
        return False
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to add ports as tagged members to VLAN: {}'.format(lag_data.random_vlan))
        return False
    if not lag_api.add_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.members_dut1):
        st.error('Failed to add members to port-channel: {}'.format(lag_data.portchannel_name))
        return False
    return True

def ft_lag_fallback_l3_traffic_epilog():
    ip.delete_static_route(vars.D1, next_hop=lag_data.dut2_lag_port_ip, static_ip="{}/{}".format(lag_data.dest_network, 8), family='ipv4')
    if not delete_static_arp(vars.D2, lag_data.dut1_tg_dst_ip, interface=vars.D2T1P1):
        st.error('Failed to delete static ARP')
        return False
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': lag_data.dut1_tg_port_ip, 'subnet': 8, 'family': 'ipv4',
             'config': 'remove', 'skip_error': True}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': lag_data.dut2_tg_port_ip, 'subnet': 8, 'family': 'ipv4',
             'config': 'remove', 'skip_error': True}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], ip.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to remove IP address')
        return False
    dict1 = {'interface_name': lag_data.portchannel_name, 'ip_address': lag_data.dut1_lag_port_ip, 'subnet': 8,
             'family': 'ipv4', 'config': 'remove'}
    dict2 = {'interface_name': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'ip_address': lag_data.dut2_lag_port_ip, 'subnet': 8,
             'family': 'ipv4', 'config': 'remove'}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], ip.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to remove IP address')
        return False
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error('Failed to add ports as tagged members of VLAN: {}'.format(lag_data.random_vlan))
        return False
    return True

def ft_lag_fallback_epilog():
    if lag_data.fail_step == 1:
        if not vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
            return False
    elif lag_data.fail_step == 2:
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[0]):
            return False
    elif lag_data.fail_step == 3:
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[1]):
            return False
    elif lag_data.fail_step == 4:
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members):
            return False
    elif lag_data.fail_step == 5:
        if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members):
            return False
        if not vlan.add_vlan_member(vars.D1, lag_data.random_vlan, [vars.D1T1P1, lag_data.portchannel_name], tagging_mode=True):
            return False
    elif lag_data.fail_step == 6:
        dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': False}
        dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'tagging_mode': False}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.delete_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if False in output:
            return False
        dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
        dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if False in output:
            return False
    elif lag_data.fail_step == 7:
        dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
        dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
        [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
        ensure_no_exception(exceptions)
        if False in output:
            return False
    else:
        pass
    return True

def verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters, **kwargs):
    if kwargs['verify_loss_traffic']:
        rx_count = filter_and_select(intf_counters, ['rx_ok'], {'iface': vars.D1T1P1})[0]['rx_ok']
        tx_count = filter_and_select(kwargs['dut2_intf_counters'], ['tx_ok'], {'iface': vars.D2T1P1})[0]['tx_ok']
        st.log("Traffic received:{}".format(rx_count))
        st.log("Traffic transmitted:{}".format(tx_count))
        if not int(tx_count.replace(',', '')) >= 0.99 * int(rx_count.replace(',', '')):
            st.error('Traffic loss observed')
            return False
    dut_hash_ports_tx_counters = {}
    dut_hash_ports_rx_counters = {}
    for port in kwargs['lag_members']:
        dut_hash_ports_tx_counters[port] = int(
            filter_and_select(intf_counters, ['tx_ok'], {'iface': port})[0]['tx_ok'].replace(',', ''))
        dut_hash_ports_rx_counters[port] = int(
            filter_and_select(intf_counters, ['rx_ok'], {'iface': port})[0]['rx_ok'].replace(',', ''))
    for port in kwargs['lag_members']:
        if port in make_list(dut_hashed_ports['ports']):
            if 'rx' in dut_hashed_ports['direction']:
                if not dut_hash_ports_rx_counters[port] >= dut_hashed_ports['pkts_count']:
                    st.error('Packets are not hashed on port:{} in direction: {}'.format(port, 'rx'))
                    return False
            if 'tx' in dut_hashed_ports['direction']:
                if not dut_hash_ports_tx_counters[port] >= dut_hashed_ports['pkts_count']:
                    st.error('Packets are not hashed on port:{} in direction: {}'.format(port, 'tx'))
                    return False
        else:
            if 'rx' in dut_hashed_ports['direction']:
                if not dut_hash_ports_rx_counters[port] <= 100:
                    st.error('Packets are hashed on port:{} in direction: {}'.format(port, 'rx'))
                    return False
            if 'tx' in dut_hashed_ports['direction']:
                if not dut_hash_ports_tx_counters[port] <= 100:
                    st.error('Packets are hashed on port:{} in direction: {}'.format(port, 'tx'))
                    return False
    return True


def test_ft_lag_fallback():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario-1: Verify that only one port(least index port) will be selected as LAG member in LACP Fallback mode with peer links not part of LAG.
    Scenario-2: Verify that tagged traffic hashed through the LAG member ports which is having Fallback enabled.
    Scenario-3: Verify LACP Fallback functionality with peer links as a part of Dynamic LAG and free from Dynamic LAG along with traffic test.
    Scenario-4: Verify that untagged traffic hashed through the LAG member ports which is having Fallback enabled.
    '''
    result_dict = {'FtOpSoSwFnLaFb004': True, 'FtOpSoSwFnLaFb005': True, 'FtOpSoSwFnLaFb006': True, 'FtOpSoSwFnLaFb007': True}
    lag_data.fail_step = 0
    if not poll_wait(lag_api.verify_portchannel_details, 10, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.error("######## Port-Channel verification failed ########")
        result_dict['FtOpSoSwFnLaFb004'] = False
        exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb004'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb004']])
    lag_data.fail_step = 1
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.error("######## Failed to add port as tagged member of VLAN ########")
        result_dict['FtOpSoSwFnLaFb005'] = False
        exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb005'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb005']])
    exceptions = \
    exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', stream_handle=lag_data.streams['lacp_l2_tagged_stream'], enable_arp=0)
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.sorted_members_dut1[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        if result_dict['FtOpSoSwFnLaFb005']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb005'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb005'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb005']])
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        if result_dict['FtOpSoSwFnLaFb005']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb005'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb005'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb005']])

    if not vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.error("######## Failed to delete member port from VLAN ########")
        result_dict['FtOpSoSwFnLaFb007'] = False
        exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    dut1_random_members = sample(lag_data.members_dut1, k=2)
    lag_data.dut2_random_members = []
    for port in dut1_random_members:
        port_index = lag_data.members_dut1.index(port)
        lag_data.dut2_random_members.append(lag_data.members_dut2[port_index])
    lag_data.fail_step = 2
    if not lag_api.add_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[0]):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Failed to add port as member to Port-Channel ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [dut1_random_members[0]], [[port for port in lag_data.members_dut1 if port != dut1_random_members[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.dut2_random_members[0]], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Port-Channel verification failed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': dut1_random_members[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.dut2_random_members[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[0]):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Failed to remove member from Port-Channel ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    lag_data.fail_step = 3
    if not lag_api.add_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[1]):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Failed to add port as member to Port-Channel ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [dut1_random_members[1]], [[port for port in lag_data.members_dut1 if port != dut1_random_members[1]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 95, vars.D2, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.dut2_random_members[1]], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Port-Channel verification failed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': dut1_random_members[1], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.dut2_random_members[1], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    lag_data.fail_step = 4
    if not lag_api.add_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members[0]):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Failed to add port as member to Port-Channel ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [dut1_random_members], [[port for port in lag_data.members_dut1 if port not in dut1_random_members]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.dut2_random_members], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Port-Channel verification failed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': dut1_random_members, 'pkts_count': 900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.dut2_random_members, 'pkts_count': 900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        if result_dict['FtOpSoSwFnLaFb007']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb007'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb007'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb007']])

    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
    lag_data.fail_step = 5
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.delete_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.error("######## Failed to delete member port from VLAN ########")
        result_dict['FtOpSoSwFnLaFb006'] = False
        exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    if not lag_api.delete_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.dut2_random_members):
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Failed to remove member from Port-Channel ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    lag_data.fail_step = 6
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': False}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'tagging_mode': False}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Failed to add port as untagged of VLAN ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])

    if not poll_wait(lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Port-Channel verification failed ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    exceptions = \
    exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg1.tg_traffic_config(mode='disable', stream_id=lag_data.streams['lacp_l2_tagged_stream'])
    lag_data.tg1.tg_traffic_control(action='clear_stats', port_handle=[lag_data.tg_ph_1, lag_data.tg_ph_2])
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_untagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_untagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)

    tgapi.get_traffic_stats(lag_data.tg1, mode='aggregate', port_handle=lag_data.tg_ph_1)
    tgapi.get_traffic_stats(lag_data.tg2, mode='aggregate', port_handle=lag_data.tg_ph_2)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.sorted_members_dut1[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Traffic not hashed ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    lag_data.fail_step = 7
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': False}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'tagging_mode': False}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.delete_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Failed to delete member port from VLAN ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
            exec_all(True, [[st.generate_tech_support, vars.D1, 'FtOpSoSwFnLaFb006'], [st.generate_tech_support, vars.D2, 'FtOpSoSwFnLaFb006']])
    lag_data.fail_step = 8
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.add_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        if result_dict['FtOpSoSwFnLaFb006']:
            st.error("######## Failed to add port as tagged of VLAN ########")
            result_dict['FtOpSoSwFnLaFb006'] = False
    for testcase, result in result_dict.items():
        if result:
            st.report_tc_pass(testcase, "test_case_passed")
    if all(list(result_dict.values())):
        st.report_pass('lacp_fallback_validation_success', 'with tagged and untagged traffic')
    else:
        st.report_fail('msg', 'Failed to validate LACP Fallback functionality')


def test_ft_lag_fallback_l3_traffic():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify LACP Fallback functionality with L3 traffic.
    '''
    dict1 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D1T1P1, lag_data.portchannel_name], 'tagging_mode': True}
    dict2 = {'vlan': lag_data.random_vlan, 'port_list': [vars.D2T1P1], 'tagging_mode': True}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], vlan.delete_vlan_member, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('vlan_member_deletion_failed', 'in both DUTs')
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': lag_data.dut1_tg_port_ip, 'subnet': 8, 'family': 'ipv4',
             'config': 'add'}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': lag_data.dut2_tg_port_ip, 'subnet': 8, 'family': 'ipv4',
             'config': 'add'}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], ip.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('ip_routing_int_create_fail', 'in both DUTs')
    dict1 = {'interface_name': lag_data.portchannel_name, 'ip_address': lag_data.dut1_lag_port_ip, 'subnet': 8,
             'family': 'ipv4', 'config': 'add'}
    dict2 = {'interface_name': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'ip_address': lag_data.dut2_lag_port_ip, 'subnet': 8,
             'family': 'ipv4', 'config': 'add'}
    [output, exceptions] = exec_parallel(True, [vars.D1, vars.D2], ip.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('ip_routing_int_create_fail', 'in both DUTs')
    ip.create_static_route(vars.D1, next_hop=lag_data.dut2_lag_port_ip, static_ip="{}/{}".format(lag_data.dest_network, 8), family='ipv4')
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[0]],
                    [[port for port in lag_data.members_dut1 if port != lag_data.sorted_members_dut1[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 95, vars.D2, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')

    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    if not add_static_arp(vars.D2, lag_data.dut1_tg_dst_ip, lag_data.host_mac, interface=vars.D2T1P1):
        st.report_fail('static_arp_create_fail', vars.D2)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l3_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l3_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.sorted_members_dut1[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'with L3 traffic')


def test_nt_lag_fallback_all_members_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify Fallback LAG member port selection with shutdown no-shutdown operation on the LAG all member ports.
    '''
    if not interface_operation(vars.D1, lag_data.members_dut1, operation='shutdown'):
        st.report_fail('interface_admin_shut_down_fail', lag_data.members_dut1)
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [lag_data.members_dut1]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name,
                    lag_data.lag_down, [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not interface_operation(vars.D1, lag_data.sorted_members_dut1[-1], operation='startup'):
        st.report_fail('interface_admin_startup_fail', lag_data.sorted_members_dut1[-1])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[-1]], [[port for port in lag_data.members_dut1 if port!=lag_data.sorted_members_dut1[-1]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name,
                    lag_data.lag_down, [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not interface_operation(vars.D1, lag_data.sorted_members_dut1[-2], operation='startup'):
        st.report_fail('interface_admin_startup_fail', lag_data.sorted_members_dut1[-2])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[-2]],
                    [[port for port in lag_data.members_dut1 if port != lag_data.sorted_members_dut1[-2]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name,
                    lag_data.lag_down, [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not interface_operation(vars.D1, lag_data.sorted_members_dut1[-3], operation='startup'):
        st.report_fail('interface_admin_startup_fail', lag_data.sorted_members_dut1[-3])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[-3]],
                    [[port for port in lag_data.members_dut1 if port != lag_data.sorted_members_dut1[-3]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name,
                    lag_data.lag_down, [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not interface_operation(vars.D1, lag_data.sorted_members_dut1[-4], operation='startup'):
        st.report_fail('interface_admin_startup_fail', lag_data.sorted_members_dut1[-4])
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[-4]],
                    [[port for port in lag_data.members_dut1 if port != lag_data.sorted_members_dut1[-4]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name,
                    lag_data.lag_down, [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('lacp_fallback_validation_success', 'after no-shutdown operation on all LACP member ports')


def test_nt_lag_fallback_active_member_remove_add():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify Fallback LAG member port selection with remove and add the least index port.
    '''
    if not poll_wait(lag_api.verify_portchannel_details, 10, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not lag_api.delete_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.sorted_members_dut1[0]):
        st.report_fail('portchannel_config_clear_failed')
    if not poll_wait(lag_api.verify_portchannel_details, 10, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[1]], [[port for port in lag_data.members_dut1 if port not in lag_data.sorted_members_dut1[:2]]]):
        st.error('Port-Channel member status failed')
        lag_api.add_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.sorted_members_dut1[0])
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[1])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'int DUT1', vars.D2)
    exceptions = \
    exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.sorted_members_dut1[1], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.error('Traffic validation failed')
        lag_api.add_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.sorted_members_dut1[0])
        vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[1])], tagging_mode = True)
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[1])], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.error('Traffic validation failed')
        lag_api.add_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.sorted_members_dut1[0])
        vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[1])], tagging_mode = True)
        st.report_fail('traffic_not_hashed', vars.D2)
    if not lag_api.add_portchannel_member(vars.D1, lag_data.portchannel_name, lag_data.sorted_members_dut1[0]):
        st.report_fail('add_members_to_portchannel_failed', lag_data.sorted_members_dut1[0], lag_data.portchannel_name, vars.D1)
    if not vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[1])], tagging_mode = True):
        st.report_fail('vlan_member_deletion_failed', 'in DUT2')
    if not poll_wait(lag_api.verify_portchannel_details, 10, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'in DUT2', lag_data.random_vlan)
    exceptions = \
    exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.sorted_members_dut1[0], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.error('Traffic validation failed')
        vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode = True)
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.error('Traffic validation failed')
        vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode = True)
        st.report_fail('traffic_not_hashed', vars.D2)
    vlan.delete_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode = True)
    st.report_pass('lacp_fallback_validation_success', 'after remove and add active members of LAG')


def test_nt_lag_fallback_members_multiple_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify the traffic hashed properly through the LAG fall-back active member ports after shutdown and no-shutdown operation.
    '''
    if not lag_api.add_portchannel_member(vars.D2, lag_data.portchannel_name, lag_data.members_dut2):
        st.report_fail('add_members_to_portchannel_failed', lag_data.members_dut2, lag_data.portchannel_name, vars.D2)
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.members_dut1], [None]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.members_dut2], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    for _ in range(5):
        if not interface_operation(vars.D2, lag_data.members_dut2, 'shutdown'):
            st.error('Failed to shutdown the ports')
            interface_operation(vars.D2, lag_data.members_dut2, 'startup')
            st.report_fail('interface_admin_shut_down_fail', lag_data.members_dut2)
        if not interface_operation(vars.D2, lag_data.members_dut2, 'startup'):
            st.error('Failed to startup the ports')
            st.report_fail('interface_admin_startup_fail', lag_data.members_dut2)
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.members_dut1], [None]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.members_dut2], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': lag_data.members_dut1, 'pkts_count': 400}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': lag_data.members_dut2, 'pkts_count': 400}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'after multiple shutdown no-shutdown operations')


def test_lr_lacp_fallback_cold_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify LACP Fallback functionality after cold reboot.
    '''
    if not poll_wait(lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'in DUT2', lag_data.random_vlan)
    exceptions = exec_all(True, [[config_save, vars.D1], [config_save, vars.D2]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[st.reboot, vars.D1], [st.reboot, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(15, "wait for link init sequence complete")
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[0]],
                    [[port for port in lag_data.members_dut1 if port !=lag_data.sorted_members_dut1[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(3, "Added wait for VLAN programming")
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': [lag_data.sorted_members_dut1[0]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': [lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'with cold-boot')


def test_lr_lacp_fallback_save_reload():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify LACP Fallback functionality after config save and reload.
    '''
    if not poll_wait(lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'in DUT2', lag_data.random_vlan)
    exceptions = exec_all(True, [[config_save_reload, vars.D1], [config_save_reload, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(15, "wait for link init sequence complete")
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[0]],
                    [[port for port in lag_data.members_dut1 if port !=lag_data.sorted_members_dut1[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(5)
    lag_data.tg1.tg_traffic_control(action='clear_stats', port_handle=[lag_data.tg_ph_1, lag_data.tg_ph_2])
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': [lag_data.sorted_members_dut1[0]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        tgapi.get_traffic_stats(lag_data.tg1, mode='aggregate', port_handle=lag_data.tg_ph_1)
        tgapi.get_traffic_stats(lag_data.tg2, mode='aggregate', port_handle=lag_data.tg_ph_2)
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': [lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        tgapi.get_traffic_stats(lag_data.tg1, mode='aggregate', port_handle=lag_data.tg_ph_1)
        tgapi.get_traffic_stats(lag_data.tg2, mode='aggregate', port_handle=lag_data.tg_ph_2)
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'with config save and reload')


def test_lr_lacp_fallback_fast_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify LACP Fallback functionality after fast reboot.
    '''
    if not poll_wait(lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'in DUT2', lag_data.random_vlan)
    exceptions = exec_all(True, [[config_save, vars.D1], [config_save, vars.D2]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[st.reboot, vars.D1, 'fast'], [st.reboot, vars.D2, 'fast']])[1]
    ensure_no_exception(exceptions)
    st.wait(15, "wait for link init sequence complete")
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[0]],
                    [[port for port in lag_data.members_dut1 if port !=lag_data.sorted_members_dut1[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(3, "Added wait for VLAN programming")
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': [lag_data.sorted_members_dut1[0]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': [lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'with fast-boot')


def test_lr_lacp_fallback_warm_boot():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    Scenario: Verify LACP Fallback functionality after warm reboot.
    '''
    if not poll_wait(lag_api.verify_portchannel_details, 95, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                     [lag_data.sorted_members_dut1[0]], [lag_data.sorted_members_dut1[1:]]):
        st.report_fail('portchannel_member_state_failed')
    if not vlan.add_vlan_member(vars.D2, lag_data.random_vlan, lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])], tagging_mode=True):
        st.report_fail('vlan_tagged_member_fail', 'in DUT2', lag_data.random_vlan)
    exceptions = exec_all(True, [[st.reboot, vars.D1, 'warm'], [st.reboot, vars.D2, 'warm']])[1]
    ensure_no_exception(exceptions)
    st.wait(15, "wait for link init sequence complete")
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D1, lag_data.portchannel_name, lag_data.lag_up,
                    [lag_data.sorted_members_dut1[0]],
                    [[port for port in lag_data.members_dut1 if port !=lag_data.sorted_members_dut1[0]]]),
        ExecAllFunc(poll_wait, lag_api.verify_portchannel_details, 8, vars.D2, lag_data.portchannel_name, lag_data.lag_down,
                    [None], [None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    exceptions = \
        exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(3, "Added wait for VLAN programming")
    lag_data.tg.tg_traffic_control(action='run', enable_arp=0, stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    lag_data.tg.tg_traffic_control(action='stop', stream_handle=lag_data.streams['lacp_l2_tagged_stream'])
    st.wait(2)
    [output, exceptions] = exec_all(True, [[show_interface_counters_all, vars.D1],
                                           [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    intf_counters_1, intf_counters_2 = output
    dut_hashed_ports = {'direction': ['tx'], 'ports': [lag_data.sorted_members_dut1[0]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_1, verify_loss_traffic=True,
                                        dut2_intf_counters=intf_counters_2, lag_members=lag_data.members_dut1):
        st.report_fail('traffic_not_hashed', vars.D1)
    dut_hashed_ports = {'direction': ['rx'], 'ports': [lag_data.members_dut2[lag_data.members_dut1.index(lag_data.sorted_members_dut1[0])]], 'pkts_count': 1900}
    if not verify_traffic_hashed_or_not(dut_hashed_ports, intf_counters_2, verify_loss_traffic=False,
                                        lag_members=lag_data.members_dut2):
        st.report_fail('traffic_not_hashed', vars.D2)
    st.report_pass('lacp_fallback_validation_success', 'with warm-boot')
