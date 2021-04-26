import pytest
from random import randrange as randomnumber

from spytest import st, tgapi, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as intf_obj
import apis.system.logging as slog
from apis.system.reboot import config_save, config_save_reload
import apis.system.lldp as lldp_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.system.port as port_obj
import apis.system.rest as rest_obj

from utilities.parallel import exec_all, exec_parallel, ensure_no_exception
from utilities.common import ExecAllFunc
from utilities.common import random_vlan_list, poll_wait

vars = dict()
data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def portchannel_module_hooks(request):
    # add things at the start of this module
    global vars
    data.module_unconfig = False
    data.portchannel_name = "PortChannel7"
    data.portchannel_name2 = "PortChannel8"
    data.vlan = (random_vlan_list(count=2))
    data.vid = data.vlan[0]
    data.vlan_id = data.vlan[1]
    data.cli_type_click = "click"
    vars = st.ensure_min_topology("D1D2:4", "D1T1:1", "D2T1:1")
    data.lag_up = 'Up'
    data.lag_down = 'Dw'
    data.ip_src_count = 1000
    data.ip_dst_count = 1000
    data.tcp_src_port_count = 1000
    data.tcp_dst_port_count = 1000
    data.ip41 = '10.1.1.1'
    data.ip42 = '30.1.1.1'
    data.ip43 = '40.1.1.1'
    data.src_ip = '10.1.1.2'
    data.dst_ip = '30.1.1.3'
    data.src_port = '123'
    data.dst_port = '234'
    data.graceful_restart_config = False
    data.dut1_rt_int_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    data.my_dut_list = st.get_dut_names()[0:2]
    data.dut1 = st.get_dut_names()[0]
    data.dut2 = st.get_dut_names()[1]
    data.members_dut1 = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.members_dut2 = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.rest_url = "/restconf/data/sonic-portchannel:sonic-portchannel"
    exec_all(True, [[tg_config], [dut_config]], first_on_main=True)
    yield
    module_unconfig()

def tg_config():
    st.log("Getting TG handlers")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    data.tg = data.tg1
    st.log("Reset and clear statistics of TG ports")
    data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1, data.tg_ph_3])
    data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_3])
    data.h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ip41,
                                          gateway=data.src_ip, arp_send_req='1')
    st.log("INTFCONF: " + str(data.h1))
    data.h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_3, mode='config', intf_ip_addr=data.ip42,
                                          gateway=data.dst_ip, arp_send_req='1')
    st.log("INTFCONF: " + str(data.h2))
    data.streams = {}


def dut_config():
    st.log('Creating port-channel and adding members in both DUTs')
    portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name, data.members_dut1,
                                           data.members_dut2, "add")
    st.log('Creating random VLAN in both the DUTs')
    if False in create_vlan_using_thread([vars.D1, vars.D2], [[data.vid], [data.vid]]):
        st.report_fail('vlan_create_fail', data.vid)
    st.log('Adding Port-Channel and TGen connected ports as tagged members to the random VLAN')
    if False in add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid],
                                        [[data.portchannel_name, vars.D1T1P1],[data.portchannel_name, vars.D2T1P1]]):
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)


def module_unconfig():
    if not data.module_unconfig:
        data.module_unconfig = True
        st.log('Module config Cleanup')
        vlan_obj.clear_vlan_configuration([data.dut1, data.dut2])
        portchannel_obj.clear_portchannel_configuration([data.dut1, data.dut2])



@pytest.fixture(scope="function", autouse=True)
def portchannel_func_hooks(request):
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    if st.get_func_name(request) == 'test_ft_portchannel_behavior_with_tagged_traffic':
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_untagged_traffic_on_portchannel':
        config_test_ft_portchannel_with_new_member_and_untagged_traffic()
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_lag_l3_hash_sip_dip_l4port':
        config_test_ft_lag_l3_hash_sip_dip_l4port()
        verify_portchannel_status()
    elif st.get_func_name(request) == 'test_ft_portchannel_with_vlan_variations':
        dict1 = {"portchannel": data.portchannel_name, "members": [data.members_dut1[2],
                                            data.members_dut1[3]], "flag": 'del'}
        dict2 = {"portchannel": data.portchannel_name, "members": [data.members_dut2[2],
                                            data.members_dut2[3]], "flag": 'del'}
        output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
        ensure_no_exception(output[1])
    else:
        pass
    yield
    if st.get_func_name(request) == 'test_ft_portchannel_behavior_with_tagged_traffic':
        portchannel_behavior_with_tagged_traffic_verify()
    elif st.get_func_name(request) == 'test_ft_untagged_traffic_on_portchannel':
        portchannel_behavior_with_untagged_traffic_verify()
    elif st.get_func_name(request) == 'test_ft_lag_l3_hash_sip_dip_l4port':
        unconfig_test_ft_lag_l3_hash_sip_dip_l4port()
    elif st.get_func_name(request) == 'test_ft_portchannel_with_vlan_variations':
        dict1 = {"portchannel": data.portchannel_name, "members": [data.members_dut1[2],
                                                                   data.members_dut1[3]], "flag": 'add'}
        dict2 = {"portchannel": data.portchannel_name, "members": [data.members_dut2[2],
                                                                   data.members_dut2[3]], "flag": 'add'}
        output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
        ensure_no_exception(output[1])
    else:
        pass

def graceful_restart_prolog():
    dict1 = {'portchannel': data.portchannel_name, 'members': [vars.D1D2P3, vars.D1D2P4]}
    dict2 = {'portchannel': data.portchannel_name, 'members': [vars.D2D1P3, vars.D2D1P4]}
    exceptions = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])[1]
    ensure_no_exception(exceptions)
    dict1 = {'portchannel_list': data.portchannel_name2}
    dict2 = {'portchannel_list': data.portchannel_name2}
    exceptions = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.create_portchannel, [dict1, dict2])[1]
    ensure_no_exception(exceptions)
    dict1 = {'portchannel': data.portchannel_name2, 'members': [vars.D1D2P3, vars.D1D2P4]}
    dict2 = {'portchannel': data.portchannel_name2, 'members': [vars.D2D1P3, vars.D2D1P4]}
    exceptions = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])[1]
    ensure_no_exception(exceptions)


def verify_portchannel_status(delay=2):
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1, 'iter_delay': delay}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2, 'iter_delay': delay}
    output = exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    ensure_no_exception(output[1])

def create_vlan_using_thread(dut_list, vlan_list, thread = True):
    sub_list = [[vlan_obj.create_vlan, dut, vlan_list[cnt]] for cnt, dut in enumerate(dut_list, start=0)]
    [output, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)
    return output

def config_test_ft_portchannel_with_new_member_and_untagged_traffic():
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                    [data.portchannel_name, vars.D2T1P1]], True)
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                                [data.portchannel_name, vars.D2T1P1]], tagged=False)
    dict1 = {'vlan_list': data.vid, 'untagged': [data.portchannel_name, vars.D1T1P1]}
    dict2 = {'vlan_list': data.vid, 'untagged': [data.portchannel_name, vars.D2T1P1]}
    output = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.verify_vlan_config, [dict1, dict2])
    ensure_no_exception(output[1])
    if not output[0][0]:
        st.report_fail('vlan_untagged_member_fail', [data.portchannel_name, vars.D1T1P1], data.vid)
    if not output[0][1]:
        st.report_fail('vlan_untagged_member_fail', [data.portchannel_name, vars.D2T1P1], data.vid)

def config_test_ft_lag_l3_hash_sip_dip_l4port():
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                    [data.portchannel_name, vars.D2T1P1]], True)
    verify_portchannel_status()
def portchannel_behavior_with_tagged_traffic_verify():
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    if data.return_value == 2:
        portchannel_obj.create_portchannel(vars.D1, data.portchannel_name)
        portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, data.members_dut1)
    elif data.return_value == 3:
        if not intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup', skip_verify=False):
            st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    elif data.return_value == 4:
        if not vlan_obj.add_vlan_member(vars.D1, data.vid, [data.portchannel_name], True):
            st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
        if not vlan_obj.verify_vlan_config(vars.D1, data.vid, tagged=[data.portchannel_name]):
            st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    elif data.return_value == 5:
        intf_obj.interface_noshutdown(vars.D1, data.members_dut1, skip_verify=False)
    else:
        dict1 = {'portchannel': data.portchannel_name}
        output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.get_portchannel_members, [dict1, dict1])
        ensure_no_exception(output[1])
        member_ports1 = []
        member_ports2 = []
        for port in data.members_dut1:
            if port not in output[0][0]:
                member_ports1.append(port)
        for port in data.members_dut2:
            if port not in output[0][1]:
                member_ports2.append(port)
        add_del_member_using_thread([vars.D1, vars.D2], [data.portchannel_name, data.portchannel_name],
                                [member_ports1,member_ports2], flag='add')
        intf_obj.interface_noshutdown(vars.D1, data.members_dut1)

def portchannel_behavior_with_untagged_traffic_verify():
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash3'])
    delete_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                                               [data.portchannel_name, vars.D2T1P1]])
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                    [data.portchannel_name, vars.D2T1P1]], tagged=True)

def unconfig_test_ft_portchannel_disabled_with_traffic():
    intf_obj.interface_operation(vars.D1, data.portchannel_name, 'startup')

def unconfig_test_ft_lag_l3_hash_sip_dip_l4port():
    ip_obj.clear_ip_configuration([vars.D1, vars.D2], family='ipv4', thread=True)
    add_vlan_member_using_thread([vars.D1, vars.D2], [data.vid, data.vid], [[data.portchannel_name, vars.D1T1P1],
                                                    [data.portchannel_name, vars.D2T1P1]],tagged=True)

def clear_intf_counters_using_thread(dut_list, thread=True):
    sub_list = [[intf_obj.clear_interface_counters, dut] for dut in dut_list]
    [_, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)

def add_del_member_using_thread(dut_list, portchannel_list, member_list, flag = 'add', thread=True):
    sub_list = []
    if flag == 'add':
        sub_list.append([portchannel_obj.add_del_portchannel_member, dut_list[0], portchannel_list[0], member_list[0],
                         flag, True])
        sub_list.append([portchannel_obj.add_del_portchannel_member, dut_list[1], portchannel_list[1], member_list[1],
                         flag, True])
        [_, exceptions] = exec_all(thread, sub_list)
        ensure_no_exception(exceptions)
    else:
        sub_list.append([portchannel_obj.delete_portchannel_member, dut_list[0], portchannel_list[0], member_list[0]])
        sub_list.append([portchannel_obj.delete_portchannel_member, dut_list[1], portchannel_list[1], member_list[1]])
        [_, exceptions] = exec_all(thread, sub_list)
        ensure_no_exception(exceptions)

def verify_traffic_hashed_or_not(dut, port_list, pkts_per_port, traffic_loss_verify = False, rx_port = '',
                                 tx_port = '', dut2 =''):
    if traffic_loss_verify is True:
        sub_list = []
        sub_list.append([intf_obj.show_interface_counters_all, dut])
        sub_list.append([intf_obj.show_interface_counters_all, dut2])
        [output, exceptions] = exec_all(True, sub_list)
        ensure_no_exception(exceptions)
        data.intf_counters_1, data.intf_counters_2 = output
    else:
        data.intf_counters_1 = intf_obj.show_interface_counters_all(dut)
    data.intf_count_dict = {}
    for port in port_list:
        for counter_dict in data.intf_counters_1:
            if counter_dict['iface'] == port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    data.intf_count_dict[port] = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                if not (data.intf_count_dict[port] >= pkts_per_port):
                    intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
                    st.report_fail("traffic_not_hashed", dut)
    if traffic_loss_verify is True:
        for counter_dict in data.intf_counters_1:
            if counter_dict['iface'] == rx_port:
                try:
                    rx_ok_counter = counter_dict['rx_ok'].replace(',', '')
                    data.rx_traffic = int(rx_ok_counter) if rx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        for counter_dict in data.intf_counters_2:
            if counter_dict['iface'] == tx_port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    data.tx_traffic = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        if not (data.tx_traffic >= 0.95* data.rx_traffic):
            st.log("data.tx_traffic:{}".format(data.tx_traffic))
            st.log("data.rx_traffic:{}".format(data.rx_traffic))
            intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
            st.report_fail('traffic_loss_observed')
    return data.intf_count_dict

def delete_vlan_member_using_thread(dut_list, vlan_list, members_list, tagged= False):
    sub_list = []
    sub_list.append([vlan_obj.delete_vlan_member, dut_list[0], vlan_list[0], members_list[0], tagged])
    sub_list.append([vlan_obj.delete_vlan_member, dut_list[1], vlan_list[1], members_list[1], tagged])
    [_, exceptions] = exec_all(True, sub_list)
    ensure_no_exception(exceptions)

def add_vlan_member_using_thread(dut_list, vlan_list, port_list, tagged = True):
    sub_list = []
    sub_list.append([vlan_obj.add_vlan_member, dut_list[0], vlan_list[0], port_list[0], tagged, False])
    sub_list.append([vlan_obj.add_vlan_member, dut_list[1], vlan_list[1], port_list[1], tagged, False])
    [output, exceptions] = exec_all(True, sub_list)
    ensure_no_exception(exceptions)
    return output

def get_intf_counters_using_thread(dut_list, thread=True):
    sub_list = [[intf_obj.show_interface_counters_all, dut] for dut in dut_list]
    [output, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)
    return output

def verify_portchannel_cum_member_status(dut, portchannel, members_list, iter_count=10, iter_delay=2, state='up'):
    i = 1
    while i <= iter_count:
        st.log("Checking iteration {}".format(i))
        st.wait(iter_delay)
        if not portchannel_obj.verify_portchannel_member_state(dut, portchannel, members_list, state='up'):
            i += 1
            if i == iter_count:
                st.report_fail("portchannel_member_verification_failed", portchannel, dut, members_list)
        else:
            break


def check_lldp_neighbors(dut, port, ipaddress, hostname):
    try:
        lldp_value = lldp_obj.get_lldp_neighbors(dut, interface=port)[0]
    except Exception:
        st.error("No LLDP entries are found")
        return False
    lldp_value_dut2 = lldp_value['chassis_mgmt_ip']
    try:
        if not ipaddress[0] == lldp_value_dut2 :
            st.error("Entries are not matching")
            return False
    except Exception:
        st.error("Entries are not matching")
        return False
    lldp_value_hostname = lldp_value['chassis_name']
    if not hostname == lldp_value_hostname:
        st.error("Host name is not matching")
        return False
    return True

def get_mgmt_ip_using_thread(dut_list, mgmt_list, thread=True):
    sub_list = [[basic_obj.get_ifconfig_inet, dut, mgmt_list[cnt]] for cnt, dut in enumerate(dut_list, start=0)]
    [output, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)
    return output

def get_hostname_using_thread(dut_list, thread=True):
    sub_list = [[basic_obj.get_hostname, dut] for dut in dut_list]
    [output, exceptions] = exec_all(thread, sub_list)
    ensure_no_exception(exceptions)
    return output

def verify_portchannel_rest(dut,json_data):
    get_resp = rest_obj.get_rest(dut,rest_url=data.rest_url)
    return rest_obj.verify_rest(get_resp["output"],json_data)

def verify_graceful_restart_syslog(dut):
    count_msg1 = slog.get_logging_count(dut, severity="NOTICE", filter_list=[
        "teamd#teammgrd: :- sig_handler: --- Received SIGTERM. Terminating PortChannels gracefully"])
    count_msg2 = slog.get_logging_count(dut, severity="NOTICE",
                           filter_list=["teamd#teammgrd: :- sig_handler: --- PortChannels terminated gracefully"])
    if not (count_msg1 == 1 and count_msg2 == 1):
        st.error('SYSLOG message is not observed for graceful restart')
        return False
    return True


def test_ft_portchannel_behavior_with_tagged_traffic():
    '''
    Author: Jagadish <jagadish.chatrasi@broadcom.com>
    This test case covers below test scenarios/tests
    Test scenario-1: Verify that deleting port channel with vlan membership.
    Test scenario-2: Verify that removal of a port from a LAG does not interrupt traffic.
    Test scenario-3: Verify that L2 LAG hashing functionality working fine in Sonic
    Test scenario-4: Verify that adding ports to a LAG causes traffic to redistribute to new ports.
    Test scenario-5: Verify LLDP interaction with LAG.
    Test scenario-6: Verify that a LAG with only 1 port functions properly.
    Test scenario-7: Verify that shutdown and "no shutdown" of port channel group port bring the port back to active state.
    Test scenario-8: Verify that the LAG in DUT is not UP when LAG is not created at partner DUT
    Test scenario-9: Verify that LAG status should be Down when none of LAG members are in Active state.
    Test scenario-10: Verify that no traffic is forwarded on a disabled LAG
    Test scenario-11: Verify only participating lags that are members of the VLAN forward tagged traffic
    Test scenario-12: Verify that the LAG in DUT is not UP when LAG is not created at partner DUT
    '''
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=72,
              mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=200,
              mac_dst='00:02:00:00:00:02', mac_dst_step='00:00:00:00:00:01', mac_dst_mode='increment', mac_dst_count=200,
              rate_pps=2000, l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.vid, transmit_mode='continuous')
    data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']
    data.return_value = 1
    st.log("Test scenario-1: Verifying that deleting port channel with vlan membership should not be successful")
    if portchannel_obj.delete_portchannel(vars.D1, data.portchannel_name):
        data.return_value = 2
        st.report_fail('portchannel_with_vlan_membership_should_not_successful', data.portchannel_name)
    st.log("Test scenario-1: Successfully verified that deleting port channel with vlan membership should not be successful")

    st.log("Test scenario-2: Verifying that removal of a port from a LAG does not interrupt traffic")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    random_number = int(randomnumber(4))
    random_member1 = data.members_dut1[random_number]
    if not portchannel_obj.delete_portchannel_member(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('portchannel_member_delete_failed', random_member1, data.portchannel_name)
    temp_member_list1 = data.members_dut1[:]
    temp_member_list1.remove(random_member1)
    if portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('portchannel_member_verification_failed', data.portchannel_name, vars.D1, random_member1)
    st.wait(2)
    st.log('Test scenario-3: Verifying that L2 LAG hashing functionality working fine in Sonic')
    portchannel_members_counters1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Test scenario-3: Successfully verified that L2 LAG hashing functionality working fine in Sonic')

    verify_portchannel_cum_member_status(vars.D1, data.portchannel_name, temp_member_list1, iter_delay=1)
    portchannel_members_counters2 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (portchannel_members_counters1[random_member1]+10 > portchannel_members_counters2[random_member1]):
        st.report_fail('portchannel_count_verification_fail', vars.D1, random_member1)
    if not portchannel_obj.add_portchannel_member(vars.D1, data.portchannel_name, random_member1):
        st.report_fail('add_members_to_portchannel_failed', random_member1, data.portchannel_name, vars.D1)
    verify_portchannel_cum_member_status(vars.D1, data.portchannel_name, data.members_dut1, iter_delay=1)
    st.wait(2)
    portchannel_members_counters3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Test scenario-4: Verifying that adding ports to a LAG causes traffic to redistribute to new ports')
    if not (portchannel_members_counters3[random_member1] >= portchannel_members_counters2[random_member1]+10):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log('Test scenario-4: Successfully verified that adding ports to a LAG causes traffic to redistribute to new ports')

    st.log("LAG Members: {}".format(",".join(temp_member_list1)))
    st.log("LAG Member Counters-0: {} {} {}".format( portchannel_members_counters1[temp_member_list1[0]],
            portchannel_members_counters2[temp_member_list1[0]], portchannel_members_counters3[temp_member_list1[0]]))
    st.log("LAG Member Counters-1: {} {} {}".format( portchannel_members_counters1[temp_member_list1[1]],
            portchannel_members_counters2[temp_member_list1[1]], portchannel_members_counters3[temp_member_list1[1]]))
    st.log("LAG Member Counters-2: {} {} {}".format( portchannel_members_counters1[temp_member_list1[2]],
            portchannel_members_counters2[temp_member_list1[2]], portchannel_members_counters3[temp_member_list1[2]]))

    if not ((portchannel_members_counters1[temp_member_list1[0]] < portchannel_members_counters2[temp_member_list1[0]] <
             portchannel_members_counters3[temp_member_list1[0]])
            and (portchannel_members_counters1[temp_member_list1[1]] < portchannel_members_counters2[temp_member_list1[1]] <
             portchannel_members_counters3[temp_member_list1[1]])
            and (portchannel_members_counters1[temp_member_list1[2]] < portchannel_members_counters2[temp_member_list1[2]] <
             portchannel_members_counters3[temp_member_list1[2]])):
        st.report_fail('traffic_not_hashed', vars.D1)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    st.wait(1)
    st.log('Fetching interface counters in both the DUTs')
    data.intf_count1, data.intf_count2 = get_intf_counters_using_thread([vars.D1, vars.D2])
    for counter_dict in data.intf_count1:
        if counter_dict['iface'] == vars.D1T1P1:
            rx_ok_counter = counter_dict['rx_ok'].replace(',', '')
            data.data_rx = int(rx_ok_counter) if rx_ok_counter.isdigit() else 0
            break
    for counter_dict in data.intf_count2:
        if counter_dict['iface'] == vars.D2T1P1:
            tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
            data.data_tx = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
            break
    st.log('Total frames sent:{}'.format(data.data_rx))
    st.log('Total frames received:{}'.format(data.data_tx))
    data.data101_tx = 1.05 * data.data_tx
    if not (data.data101_tx >= data.data_rx):
        st.report_fail('traffic_verification_failed')
    st.log("Test scenario-2: Successfully verified that removal of a port from a LAG does not interrupt traffic")

    st.log("Test scenario-7: Verifying that shutdown and 'no shutdown' of port channel group port bring the port back to active state")
    st.log('To be added once STP supported')

    st.log("Test scenario-5: Verifying LLDP interaction with LAG")
    data.mgmt_int = 'eth0'
    _, ipaddress_d2 = get_mgmt_ip_using_thread([vars.D1, vars.D2], [data.mgmt_int, data.mgmt_int])
    _, hostname_d2 = get_hostname_using_thread([vars.D1, vars.D2])
    if not poll_wait(check_lldp_neighbors, 20, vars.D1, random_member1, ipaddress_d2, hostname_d2):
        st.report_fail("no_lldp_entries_are_available")
    st.log("Test scenario-5: Successfully verified LLDP interaction with LAG")

    st.log("Test scenario-10: Verifying that no traffic is forwarded on a disabled LAG")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash1'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    st.log('Administratively disable portchannel in DUT1')
    if not poll_wait(intf_obj.interface_operation, 5, data.dut1, data.portchannel_name, 'shutdown', skip_verify=False):
        st.report_fail('interface_admin_shut_down_fail', data.portchannel_name)
    st.wait(2)
    st.log('Verify whether traffic is hashed over portchannel members or not and fetchig counters')
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    st.log('Verify whether the portchannel is down or not')
    try:
        data.portchannel_status_output = portchannel_obj.get_portchannel(vars.D1, portchannel_name=data.portchannel_name)[0]
    except Exception:
        data.return_value = 3
        st.report_fail('portchannel_verification_failed', data.portchannel_name, vars.D1)
    if not ((data.portchannel_status_output['protocol'] == 'LACP(A)(Dw)') or (data.portchannel_status_output['protocol']
            == 'LACP' and data.portchannel_status_output['state'] == 'D')):
        data.return_value = 3
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    data.int_counter2 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (((data.int_counter1[vars.D1D2P1] + 100) >= data.int_counter2[vars.D1D2P1]) and
            ((data.int_counter1[vars.D1D2P2] + 100) >= data.int_counter2[vars.D1D2P2]) and
            ((data.int_counter1[vars.D1D2P3] + 100) >= data.int_counter2[vars.D1D2P3]) and
            ((data.int_counter1[vars.D1D2P4] + 100) >= data.int_counter2[vars.D1D2P4])):
        data.return_value = 3
        st.report_fail('traffic_hashed', vars.D1)
    st.log('Administratively Enable portchannel in DUT1')
    if not poll_wait(intf_obj.interface_operation, 5, vars.D1, data.portchannel_name, 'startup', skip_verify=False):
        st.report_fail('interface_admin_startup_fail', data.portchannel_name)
    st.log('Verify that whether the portchannel is Up or not')
    if not portchannel_obj.verify_portchannel_and_member_status(vars.D1, data.portchannel_name, data.members_dut1):
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'up')
    st.wait(1)
    data.int_counter3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    if not ((data.int_counter3[vars.D1D2P1] > data.int_counter2[vars.D1D2P1]) and
            (data.int_counter3[vars.D1D2P2] > data.int_counter2[vars.D1D2P2]) and
            (data.int_counter3[vars.D1D2P3] > data.int_counter2[vars.D1D2P3]) and
            (data.int_counter3[vars.D1D2P4] > data.int_counter2[vars.D1D2P4])):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log("Test scenario-10: Successfully verified that no traffic is forwarded on a disabled LAG")

    st.log("Test scenario-11: Verifying only participating lags that are members of the VLAN forward tagged traffic")
    st.log('Exclude Port-channel from VLAN')
    if not vlan_obj.delete_vlan_member(vars.D1, data.vid, [data.portchannel_name], tagging_mode=True):
        data.return_value = 4
        st.report_fail('vlan_member_deletion_failed', data.portchannel_name)
    st.wait(2)
    st.log('Verify whether traffic is hashed over portchannel members or not and fetchig counters')
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not vlan_obj.verify_vlan_config(vars.D1, data.vid):
        st.report_fail('vlan_member_delete_failed', data.vid, data.portchannel_name)
    data.int_counter1 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 100)
    if not (((data.int_counter1[vars.D1D2P1] + 10) >= data.int_counter2[vars.D1D2P1]) and
            ((data.int_counter1[vars.D1D2P2] + 10) >= data.int_counter2[vars.D1D2P2]) and
            ((data.int_counter1[vars.D1D2P3] + 10) >= data.int_counter2[vars.D1D2P3]) and
            ((data.int_counter1[vars.D1D2P4] + 10) >= data.int_counter2[vars.D1D2P4])):
        data.return_value = 4
        st.report_fail('traffic_hashed', vars.D1)
    st.log('Include Port-channel from VLAN')
    if not vlan_obj.add_vlan_member(vars.D1, data.vid, [data.portchannel_name], tagging_mode=True):
        data.return_value = 4
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    if not vlan_obj.verify_vlan_config(vars.D1, data.vid, tagged=[data.portchannel_name]):
        data.return_value = 4
        st.report_fail('vlan_tagged_member_fail', data.portchannel_name, data.vid)
    data.int_counter3 = verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_Mac_Hash1'])
    if not ((data.int_counter3[vars.D1D2P1] > data.int_counter2[vars.D1D2P1]) and
            (data.int_counter3[vars.D1D2P2] > data.int_counter2[vars.D1D2P2]) and
            (data.int_counter3[vars.D1D2P3] > data.int_counter2[vars.D1D2P3]) and
            (data.int_counter3[vars.D1D2P4] > data.int_counter2[vars.D1D2P4])):
        st.report_fail('traffic_not_hashed', vars.D1)
    st.log("Test scenario-11: Successfully verified only participating lags that are members of the VLAN forward tagged traffic")

    st.log("Test scenario-6: Verifying that a LAG with only 1 port functions properly")
    random_member2 = data.members_dut2[random_number]
    temp_member_list2 = data.members_dut2[:]
    temp_member_list2.remove(random_member2)
    add_del_member_using_thread([vars.D1, vars.D2], [data.portchannel_name, data.portchannel_name],
                [temp_member_list1,temp_member_list2], flag='del')
    sub_list = []
    sub_list.append([portchannel_obj.verify_portchannel_and_member_status, vars.D1, data.portchannel_name,
                     random_member1])
    sub_list.append([portchannel_obj.verify_portchannel_and_member_status, vars.D2, data.portchannel_name,
                     random_member2])
    [output, exceptions] = exec_all(True, sub_list)
    ensure_no_exception(exceptions)
    st.log("Test scenario-6: Successfully verified that a LAG with only 1 port functions properly")

    st.log("Test scenario-12: Verifying that the LAG in DUT is not UP when LAG is not created at partner DUT")
    dict1 = {'portchannel': data.portchannel_name, 'members': temp_member_list1, 'flag': "add"}
    dict2 = {'portchannel': data.portchannel_name, 'members': random_member2, 'flag': "del"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_del_portchannel_member, [dict1, dict2])
    ensure_no_exception(output[1])
    if not output[0][0]:
        st.report_fail('portchannel_create_failed', data.portchannel_name, vars.D1)
    if not output[0][1]:
        st.report_fail('portchannel_deletion_failed', data.portchannel_name)
    if not portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, "down"):
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    st.log("Test scenario-12: Successfully Verified that the LAG in DUT is not UP when LAG is not created at partner DUT")

    if not portchannel_obj.add_del_portchannel_member(vars.D2, data.portchannel_name, data.members_dut2):
        st.report_fail('portchannel_create_failed', data.portchannel_name, vars.D2)
    verify_portchannel_status(delay=1)
    st.log("Verifying that LAG status should be Down when none of LAG members are in Active state")
    intf_obj.interface_shutdown(vars.D1, data.members_dut1, skip_verify=False)
    if not portchannel_obj.poll_for_portchannel_status(vars.D1, data.portchannel_name, "down"):
        data.return_value = 5
        st.report_fail('portchannel_state_fail', data.portchannel_name, vars.D1, 'down')
    intf_obj.interface_noshutdown(vars.D1, data.members_dut1, skip_verify=False)
    st.log("Successfully verified that LAG status should be Down when none of LAG members are in Active state")
    st.report_pass("test_case_passed")


@pytest.mark.community
@pytest.mark.community_pass
def test_ft_untagged_traffic_on_portchannel():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify that LAGs treat untagged packets identically to regular ports.
    '''
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=200,
             mac_dst='00:06:00:00:00:02', mac_dst_step='00:00:00:00:00:01', mac_dst_mode='increment', mac_dst_count=200,
             pkts_per_burst=2000, l2_encap='ethernet_ii_vlan', transmit_mode='single_burst')
    data.streams['D1T1_SD_Mac_Hash3'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_Mac_Hash3'], enable_arp=0)
    st.wait(2)
    exec_parallel(True, [vars.D1, vars.D2], intf_obj.show_interface_counters_all, [None,None])
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1 , 400)
    st.report_pass('test_case_passed')


@pytest.mark.l3_lag_hash
def test_ft_lag_l3_hash_sip_dip_l4port():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    scenario1-Verify that L3 LAG hashing functionality working fine in Sonic
    scenario2 - Verify an ARP table entry learned on Port-Channel based routing interface is removed
    from ARP table after Port-Channel is shutdown.
    """
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', mac_dst=data.dut1_rt_int_mac,
             mac_src='00:05:00:00:00:01', mac_src_mode='increment', mac_src_step='00:00:00:00:00:01', mac_dst_mode='fixed',
             ip_src_addr=data.ip41, ip_src_mode='increment', ip_src_count=data.ip_src_count, ip_src_step='0.0.0.1', mac_src_count=1000,
             ip_dst_addr=data.ip42, ip_dst_mode='fixed', pkts_per_burst=1000, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash1'] = stream['stream_id']
    result_state = True
    data.subnet = '8'
    data.ip_addr_pc1 = '20.1.1.2'
    data.ip_addr_pc2 = '20.1.1.3'
    data.ipv4 = 'ipv4'
    data.ip_addr_po1 = '10.1.1.3'
    data.ip_addr_po2 = '30.1.1.2'
    data.ip_addr_po3 = '30.1.1.3'
    data.static_ip1 = '10.0.0.0/8'
    data.static_ip2 = '30.0.0.0/8'
    data.static_ip3 = '40.0.0.0/8'
    data.remote_mac = '00:00:00:00:00:01'
    data.remote_mac2 = '00:00:00:00:00:02'
    dict1 = {'interface_name': data.portchannel_name, 'ip_address': data.ip_addr_pc1, 'subnet': data.subnet,
             'family': "ipv4"}
    dict2 = {'interface_name': data.portchannel_name, 'ip_address': data.ip_addr_pc2, 'subnet': data.subnet,
             'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(output[1])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': data.ip_addr_po1, 'subnet': data.subnet, 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': data.ip_addr_po2, 'subnet': data.subnet, 'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])
    ensure_no_exception(output[1])
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address': "{}/8".format(data.ip_addr_po1), 'family': "ipv4"}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address': "{}/8".format(data.ip_addr_po2), 'family': "ipv4"}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.verify_interface_ip_address, [dict1, dict2])
    ensure_no_exception(output[1])
    if not output[0][0]:
        st.report_fail('ip_routing_int_create_fail', data.ip_addr_po1)
    if not output[0][1]:
        st.report_fail('ip_routing_int_create_fail', data.ip_addr_po2)
    #Scenario 2
    # ping from partner
    ip_obj.ping(vars.D2, data.ip_addr_pc1 , family='ipv4', count=3)
    # test arp entry on portchannel
    if not arp_obj.verify_arp(vars.D1, data.ip_addr_pc2):
        st.error('Dynamic arp entry on prtchannel failed: ARP_entry_dynamic_entry_fail')
        result_state = False
    port_obj.shutdown(vars.D1, [data.portchannel_name])
    # test arp entry on portchannel after shutdown it
    if arp_obj.verify_arp(vars.D1, data.ip_addr_pc2):
        st.error('Dynamic arp entry on prtchannel is not removed after shutdown:ARP_dynamic_entry_removal_fail')
        result_state = False
    port_obj.noshutdown(vars.D1, [data.portchannel_name])

    ip_obj.create_static_route(vars.D1, data.ip_addr_pc2, data.static_ip2, shell='vtysh', family=data.ipv4)
    dict1 = {'next_hop': data.ip_addr_pc2, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    dict2 = {'next_hop': data.ip_addr_po3, 'static_ip': data.static_ip3, 'shell': "vtysh", 'family': 'ipv4'}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.create_static_route, [dict1, dict2])
    ensure_no_exception(output[1])
    arp_obj.add_static_arp(vars.D2, data.ip_addr_po3, data.remote_mac, interface=vars.D2T1P1)
    arp_obj.add_static_arp(vars.D2, data.ip42, data.remote_mac2, interface=vars.D2T1P1)
    ip_obj.create_static_route(vars.D2, data.ip_addr_pc1, data.static_ip1, shell='vtysh', family=data.ipv4)
    [output, exceptions] = exec_all(True, [
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D1, data.ipv4, ip_address=data.static_ip2, type="S"),
        ExecAllFunc(poll_wait, ip_obj.verify_ip_route, 10, vars.D2, data.ipv4, ip_address=data.static_ip1, type="S")])
    if not all(output):
        st.error('ip_static_route_create_fail')
        result_state = False
    ensure_no_exception(exceptions)
    if not ip_obj.ping(vars.D1, data.ip_addr_pc2):
        st.report_fail("ping_fail", data.ip_addr_pc2)
    dict1 = {'addresses': data.ip_addr_po2}
    dict2 = {'addresses': data.ip_addr_po1}
    output = exec_parallel(True, [vars.D1, vars.D2], ip_obj.ping, [dict1, dict2])
    ensure_no_exception(output[1])
    if not output[0][0]:
        st.report_fail("ping_fail", data.ip_addr_po2)
    if not output[0][1]:
        st.report_fail("ping_fail", data.ip_addr_po1)
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=data.h1['handle'], dst_ip=data.ip42,
                      ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash1'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash1'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 200,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_mode='fixed', mac_dst=data.dut1_rt_int_mac, ip_src_addr=data.ip41,
             ip_src_mode='fixed', ip_dst_addr=data.ip43, ip_dst_mode='increment', ip_dst_step='0.0.0.1',
             ip_dst_count=data.ip_dst_count, pkts_per_burst=2000, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash2'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash2'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash2'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    data.tg.tg_traffic_control(action='reset', port_handle=data.tg_ph_1)
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=90,
             mac_src='00:05:00:00:00:01', mac_src_mode='fixed', mac_dst=data.dut1_rt_int_mac, tcp_src_port_step=1,
             ip_src_addr=data.ip41, tcp_src_port=data.src_port, tcp_src_port_mode='incr', tcp_src_port_count=data.tcp_src_port_count,
             tcp_dst_port=data.dst_port, ip_dst_addr=data.ip42, tcp_dst_port_mode='incr', pkts_per_burst=2000,
             l4_protocol='tcp', tcp_dst_port_step=1, tcp_dst_port_count=data.tcp_dst_port_count, l3_protocol='ipv4', transmit_mode='single_burst')
    data.streams['D1T1_SD_ip_Hash3'] = stream['stream_id']
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['D1T1_SD_ip_Hash3'], enable_arp=0)
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['D1T1_SD_ip_Hash3'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, data.members_dut1, 300,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    clear_intf_counters_using_thread([vars.D1, vars.D2])
    if result_state:
        st.report_pass('test_case_passed')
    else:
        st.report_fail("traffic_not_hashed", data.dut1)


@pytest.mark.lag_member_interchanged
def test_ft_member_state_after_interchanged_the_members_across_portchannels():
    """
    Author: vishnuvardhan.talluri@broadcom.com
    scenario; Verify that the LAG members in DUT are not UP when LAG members between two different Lags are
    interchanged
    :return:
    """
    verify_portchannel_status()
    portchannel_name_second = "PortChannel102"
    result_state = True

    # Remove 2 members from portchannel
    dict1 = {'portchannel': data.portchannel_name, 'members': data.members_dut1[2:]}
    dict2 = {'portchannel': data.portchannel_name, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.delete_portchannel_member, [dict1, dict2])
    ensure_no_exception(output[1])
    # add second portchannel
    portchannel_obj.config_portchannel(data.dut1, data.dut2, portchannel_name_second, data.members_dut1[2:],
                                       data.members_dut2[2:], "add")
    dict1 = {'interfaces': portchannel_name_second, 'operation': "startup", 'skip_verify': True}
    output = exec_parallel(True, [vars.D1, vars.D2], intf_obj.interface_operation, [dict1, dict1])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        st.report_fail('interface_admin_startup_fail', portchannel_name_second)
    #Verify portchannel is up
    dict1 = {'portchannel': portchannel_name_second, 'members': data.members_dut1[2:]}
    dict2 = {'portchannel': portchannel_name_second, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_and_member_status, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    # Interchange ports from one portchannel to another portchannel
    portchannel_obj.delete_portchannel_member(data.dut1, data.portchannel_name, data.members_dut1[0])
    portchannel_obj.delete_portchannel_member(data.dut1, portchannel_name_second, data.members_dut1[2])
    # Wait 3 times the lacp long timeout period to allow dut members to go down
    st.wait(90)
    output1 = portchannel_obj.verify_portchannel_member_state(data.dut2, data.portchannel_name, data.members_dut2[0], "down")
    if not output1:
        output1 = portchannel_obj.verify_portchannel_member_state(data.dut2, data.portchannel_name,
                                                                  data.members_dut2[0], "down")
    output2 = portchannel_obj.verify_portchannel_member_state(data.dut2, portchannel_name_second, data.members_dut2[2], "down")
    if not (output1 and output2):
        result_state = False
    # swapping the ports in DUT1 only
    output1 = portchannel_obj.add_portchannel_member(data.dut1, data.portchannel_name, data.members_dut1[2])
    output2 = portchannel_obj.add_portchannel_member(data.dut1, portchannel_name_second, data.members_dut1[0])
    if not (output1 and output2):
        result_state = False
    # Wait for few seconds after converge and ensure member ports states proper
    st.wait(5)
    # Verify portchannel member state with provided state
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1[2], 'state': "down"}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2[0], 'state': "down"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut1[0], 'state': "down"}
    dict2 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut2[2], 'state': "down"}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut1[1]}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': data.members_dut2[1]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    dict1 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut1[3]}
    dict2 = {'portchannel': portchannel_name_second, 'members_list': data.members_dut2[3]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.verify_portchannel_member_state, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    # ensuring module config
    portchannel_obj.config_portchannel(data.dut1, data.dut2, portchannel_name_second,
                                       [data.members_dut1[0], data.members_dut1[3]], data.members_dut2[2:], 'delete')
    dict1 = {'portchannel': data.portchannel_name,
             'members': [data.members_dut1[0], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name, 'members': data.members_dut2[2:]}
    output = exec_parallel(True, [vars.D1, vars.D2], portchannel_obj.add_portchannel_member, [dict1, dict2])
    ensure_no_exception(output[1])
    if not (output[0][0] and output[0][1]):
        result_state = False
    if result_state:
        st.report_pass("operation_successful")
    else:
        st.report_fail("portchannel_member_state_failed")


@pytest.mark.portchannel_with_vlan_variations
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_portchannel_with_vlan_variations():
    '''
    Author: Jagadish <pchvsai.durga@broadcom.com>
    This test case covers below test scenarios/tests
    FtOpSoSwLagFn041 : Verify that port-channel is up or not when port-channel created followed by add it to VLAN and
    then making the port-channel up.
    FtOpSoSwLagFn042 : Verify that port-channel is up when port-channel is created, making the port-channel up and then
    adding the port-channel to VLAN
    '''
    dict1 = {'portchannel': data.portchannel_name, 'members_list': [data.members_dut1[0], data.members_dut1[1]]}
    dict2 = {'portchannel': data.portchannel_name, 'members_list': [data.members_dut2[0], data.members_dut2[1]]}
    output = exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    ensure_no_exception(output[1])
    portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name2, [data.members_dut1[2], data.members_dut1[3]],
                                           [data.members_dut2[2], data.members_dut2[3]], "add")
    dict1 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut1[2], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut2[2], data.members_dut2[3]]}
    output = exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    ensure_no_exception(output[1])
    vlan_obj.create_vlan_and_add_members(vlan_data=[{"dut": [vars.D1,vars.D2], "vlan_id":data.vlan_id, "tagged":data.portchannel_name2}])
    dict1 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut1[2], data.members_dut1[3]]}
    dict2 = {'portchannel': data.portchannel_name2, 'members_list': [data.members_dut2[2], data.members_dut2[3]]}
    output = exec_parallel(True, [vars.D1, vars.D2], verify_portchannel_cum_member_status, [dict1, dict2])
    ensure_no_exception(output[1])
    #Clean up
    dict1 = {"vlan": data.vlan_id, "port_list": data.portchannel_name2, "tagging_mode": True}
    dict2 = {"vlan": data.vlan_id, "port_list": data.portchannel_name2, "tagging_mode": True}
    output = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.delete_vlan_member, [dict1, dict2])
    ensure_no_exception(output[1])
    dict1 = {"vlan_list": data.vlan_id}
    dict2 = {"vlan_list": data.vlan_id}
    output = exec_parallel(True, [vars.D1, vars.D2], vlan_obj.delete_vlan, [dict1, dict2])
    if not portchannel_obj.config_portchannel(data.dut1, data.dut2, data.portchannel_name2, [data.members_dut1[2], data.members_dut1[3]],
                                           [data.members_dut2[2], data.members_dut2[3]], "del"):
        st.report_fail("portchannel_deletion_failed", data.portchannel_name2)
    ensure_no_exception(output[1])
    st.report_pass('test_case_passed')


def test_ft_lacp_graceful_restart_with_cold_boot():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify the LACP graceful restart functionality with cold reboot.
    '''
    if not data.graceful_restart_config:
        graceful_restart_prolog()
    data.graceful_restart_config = True
    [output, exceptions] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    config_save(vars.D2)
    slog.clear_logging(vars.D2)
    [output, exceptions] = exec_all(True, [ExecAllFunc(st.reboot, vars.D2), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 60, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_down, data.lag_down], [None, None], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not poll_wait(verify_graceful_restart_syslog, 60, vars.D2):
        st.report_fail('failed_to_generate_lacp_graceful_restart_log_in_syslog')
    [output, exceptions] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('verify_lacp_graceful_restart_success', 'with cold reboot')


def test_ft_lacp_graceful_restart_with_save_reload():
    '''
    This test case covers below test scenarios/tests
    scenario-1: Verify the LACP graceful restart functionality with config save and reload.
    '''
    if not data.graceful_restart_config:
        graceful_restart_prolog()
    data.graceful_restart_config = True
    [output, exceptions] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    ensure_no_exception(exceptions)
    slog.clear_logging(vars.D2)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    [output, exceptions] = exec_all(True, [ExecAllFunc(config_save_reload, vars.D2), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 120, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_down, data.lag_down], [None, None], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    if not poll_wait(verify_graceful_restart_syslog, 60, vars.D2):
        st.report_fail('failed_to_generate_lacp_graceful_restart_log_in_syslog')
    [output, exceptions] = exec_all(True, [ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D1, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D1D2P1, vars.D1D2P2], [vars.D1D2P3, vars.D1D2P4]], [None, None]), ExecAllFunc(poll_wait, portchannel_obj.verify_portchannel_details, 7, vars.D2, [data.portchannel_name, data.portchannel_name2], [data.lag_up, data.lag_up], [[vars.D2D1P1, vars.D2D1P2], [vars.D2D1P3, vars.D2D1P4]], [None, None])])
    ensure_no_exception(exceptions)
    if False in output:
        st.report_fail('portchannel_member_state_failed')
    st.report_pass('verify_lacp_graceful_restart_success', 'with config save reload')
