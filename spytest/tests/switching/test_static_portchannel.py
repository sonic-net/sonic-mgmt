import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.switching.portchannel as portchannelobj
from apis.switching.vlan import create_vlan, add_vlan_member, delete_vlan_member, clear_vlan_configuration
from apis.switching.mac import get_mac_address_count
from apis.system.basic import get_ifconfig_ether
import apis.system.interface as intfobj
import apis.system.reboot as rbobj
import apis.routing.ip as ipobj
import apis.routing.arp as arpobj

from utilities.common import ExecAllFunc
from utilities.parallel import exec_parallel, ensure_no_exception, exec_all

vars = dict()
static_data = SpyTestDict()

def initialize_variables():
    static_data.portchannel_name = "PortChannel1"
    static_data.portchannel_name2 = "PortChannel2"
    static_data.portchannel_name3 = "PortChannel3"
    static_data.portchannel_name4 = "PortChannel4"
    static_data.max_portchannels = 128
    static_data.vid = str(random_vlan_list()[0])
    static_data.ip41 = '60.1.1.1'
    static_data.ip42 = '30.1.1.1'
    static_data.ip43 = '40.1.1.1'
    static_data.ip_mask = '8'
    static_data.src_ip = '60.1.1.2'
    static_data.dst_ip = '30.1.1.3'
    static_data.ip_src_count = 1000
    static_data.ip_dst_count = 1000
    static_data.tcp_src_port_count = 1000
    static_data.tcp_dst_port_count = 1000
    static_data.src_port = '123'
    static_data.dst_port = '234'
    static_data.subnet = '8'
    static_data.ip_addr_pc1 = '20.1.1.2'
    static_data.ip_addr_pc2 = '20.1.1.3'
    static_data.ipv4 = 'ipv4'
    static_data.ip_addr_po1 = '60.1.1.3'
    static_data.ip_addr_po2 = '30.1.1.2'
    static_data.ip_addr_po3 = '30.1.1.3'
    static_data.static_ip1 = '60.0.0.0/8'
    static_data.static_ip2 = '30.0.0.0/8'
    static_data.static_ip3 = '40.0.0.0/8'
    static_data.remote_mac = '00:00:00:00:12:34'
    static_data.remote_mac2 = '00:00:00:00:56:78'
    static_data.mtu_default = intfobj.get_interface_property(vars.D1, vars.D1D2P1, 'mtu')[0]


def static_port_channel_dut_config():
    static_data.dut1_rt_int_mac = get_ifconfig_ether(vars.D1, vars.D1T1P1)
    static_data.members_dut1 = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    static_data.members_dut2 = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    st.log('Creating port-channel and adding members in both DUTs')
    dict1 = {'portchannel_list': [static_data.portchannel_name], 'static': True}
    dict2 = {'portchannel_list': [static_data.portchannel_name], 'static': True}
    exceptions = exec_parallel(True, [vars.D1, vars.D2], portchannelobj.create_portchannel, [dict1, dict2])[1]
    ensure_no_exception(exceptions)
    dict1 = {'portchannel': static_data.portchannel_name, 'members': static_data.members_dut1}
    dict2 = {'portchannel': static_data.portchannel_name, 'members': static_data.members_dut2}
    exceptions = exec_parallel(True, [vars.D1, vars.D2], portchannelobj.add_del_portchannel_member, [dict1, dict2])[1]
    ensure_no_exception(exceptions)
    st.log('Creating random VLAN in both the DUTs')
    exceptions = exec_all(True, [[create_vlan, vars.D1, static_data.vid], [create_vlan, vars.D2, static_data.vid]])[1]
    ensure_no_exception(exceptions)
    st.log('Adding Port-Channel and TGen connected ports as tagged members to the random VLAN')
    exceptions = \
        exec_all(True, [[add_vlan_member, vars.D1, static_data.vid, [static_data.portchannel_name, vars.D1T1P1], True],
                        [add_vlan_member, vars.D2, static_data.vid, [static_data.portchannel_name, vars.D2T1P1], True]])[1]
    ensure_no_exception(exceptions)


def static_port_channel_tg_config():
    st.log("Getting TG handlers")
    static_data.tg1, static_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    static_data.tg3, static_data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    static_data.tg = static_data.tg1

    st.log("Reset and clear statistics of TG ports")
    static_data.tg.tg_traffic_control(action='reset', port_handle=[static_data.tg_ph_1, static_data.tg_ph_3])
    static_data.tg.tg_traffic_control(action='clear_stats', port_handle=[static_data.tg_ph_1, static_data.tg_ph_3])
    st.log("Creating TG streams")
    static_data.streams = {}
    stream = static_data.tg.tg_traffic_config(port_handle=static_data.tg_ph_1, mode='create', length_mode='fixed',
                                              frame_size=72,
                                              mac_src='00:00:01:00:00:01', mac_src_step='00:00:00:00:00:01',
                                              mac_src_mode='increment', mac_src_count=100,
                                              mac_dst='00:00:02:00:00:02', mac_dst_step='00:00:00:00:00:01',
                                              mac_dst_mode='increment', mac_dst_count=100,
                                              rate_percent=100, l2_encap='ethernet_ii_vlan', vlan="enable",
                                              vlan_id=static_data.vid, transmit_mode='continuous')
    static_data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']
    stream = static_data.tg.tg_traffic_config(port_handle=static_data.tg_ph_3, mode='create', length_mode='fixed',
                                              frame_size=72,
                                              mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01',
                                              mac_src_mode='increment', mac_src_count=100,
                                              mac_dst='00:02:00:00:00:02', mac_dst_step='00:00:00:00:00:01',
                                              mac_dst_mode='increment', mac_dst_count=100,
                                              rate_percent=100, l2_encap='ethernet_ii_vlan', vlan="enable",
                                              vlan_id=static_data.vid, transmit_mode='continuous')
    static_data.streams['D2T1_SD_Mac_Hash1'] = stream['stream_id']

@pytest.fixture(scope="module", autouse=True)
def portchannel_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:1", "D2T1:1")
    initialize_variables()
    exec_all(True, [[static_port_channel_tg_config], [static_port_channel_dut_config]], first_on_main=True)
    yield
    st.log('Module config Cleanup')
    clear_vlan_configuration([vars.D1, vars.D2])
    portchannelobj.clear_portchannel_configuration([vars.D1, vars.D2])


@pytest.fixture(scope="function", autouse=True)
def portchannel_func_hooks(request):
    yield
    if st.get_func_name(request) == 'test_ft_verify_static_portchannel_is_up_or_not_with_one_active_member':
        portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1[1:])
    if st.get_func_name(request) == 'test_ft_verify_static_portchannel_is_up_with_active_members_when_no_lag_in_partner':
        portchannelobj.create_portchannel(vars.D2, static_data.portchannel_name, static=True)
        portchannelobj.add_del_portchannel_member(vars.D2, static_data.portchannel_name, static_data.members_dut2)
        add_vlan_member(vars.D2, static_data.vid, static_data.portchannel_name, tagging_mode=True)
    if st.get_func_name(request) == 'test_ft_verify_fallback_is_configure_or_not_on_static_portchannel':
        if portchannelobj.get_portchannel(vars.D1, static_data.portchannel_name2):
            portchannelobj.delete_portchannel(vars.D1, static_data.portchannel_name2)
    if st.get_func_name(request) == 'test_ft_verify_static_portchannel_del_from_ip_assigned_vlan':
        st.wait(2)
        ipobj.config_ip_addr_interface(vars.D1, 'Vlan{}'.format(static_data.vid), static_data.ip41, static_data.ip_mask,config='remove')
        portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
    if st.get_func_name(request) == 'test_ft_del_ip_assigned_portchannel':
        if not portchannelobj.get_portchannel(vars.D1, static_data.portchannel_name):
            portchannelobj.create_portchannel(vars.D1, static_data.portchannel_name, static=True)
        ipobj.delete_ip_interface(vars.D1, static_data.portchannel_name, static_data.ip41, static_data.ip_mask, skip_error=True)
        portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
        exceptions = exec_all(True, [[add_vlan_member, vars.D1, static_data.vid, static_data.portchannel_name, True],
                                     [add_vlan_member, vars.D2, static_data.vid, static_data.portchannel_name, True]])[1]
        ensure_no_exception(exceptions)
    if st.get_func_name(request) == 'test_ft_verify_static_portchannel_l3_hash_sip_dip_l4port':
        arpobj.delete_static_arp(vars.D2, static_data.ip42, interface=vars.D2T1P1, mac=static_data.remote_mac2)
        ipobj.clear_ip_configuration([vars.D1, vars.D2], family='ipv4', thread=True)
        exceptions = exec_all(True, [[add_vlan_member, vars.D1, static_data.vid, [static_data.portchannel_name, vars.D1T1P1], True],
                                     [add_vlan_member, vars.D2, static_data.vid, [static_data.portchannel_name, vars.D2T1P1], True]])[1]
        ensure_no_exception(exceptions)
    if st.get_func_name(request) == 'test_ft_verify_static_portchannel_vlan_routing_l3_traffic':
        arpobj.delete_static_arp(vars.D2, static_data.ip42, interface=vars.D2T1P1, mac=static_data.remote_mac2)
        ipobj.clear_ip_configuration([vars.D1, vars.D2], family='ipv4', thread=True)
        exceptions = exec_all(True, [[add_vlan_member, vars.D1, static_data.vid, vars.D1T1P1, True],
                                     [add_vlan_member, vars.D2, static_data.vid, vars.D2T1P1, True]])[1]
        ensure_no_exception(exceptions)

def verify_traffic_hashed_or_not(dut, port_list, pkts_per_port, traffic_loss_verify = False, rx_port = '', tx_port = '', dut2 =''):
    if traffic_loss_verify is True:
        [output, exceptions] = exec_all(True, [[intfobj.show_interface_counters_all, dut], [intfobj.show_interface_counters_all, dut2]])
        ensure_no_exception(exceptions)
        static_data.intf_counters_1, static_data.intf_counters_2 = output
    else:
        static_data.intf_counters_1 = intfobj.show_interface_counters_all(dut)
    static_data.intf_count_dict = {}
    for port in port_list:
        for counter_dict in static_data.intf_counters_1:
            if counter_dict['iface'] == port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    static_data.intf_count_dict[port] = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                if not (static_data.intf_count_dict[port] >= pkts_per_port):
                    intfobj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
                    st.report_fail("traffic_not_hashed", dut)
    if traffic_loss_verify is True:
        for counter_dict in static_data.intf_counters_1:
            if counter_dict['iface'] == rx_port:
                try:
                    rx_ok_counter = counter_dict['rx_ok'].replace(',', '')
                    static_data.rx_traffic = int(rx_ok_counter) if rx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        for counter_dict in static_data.intf_counters_2:
            if counter_dict['iface'] == tx_port:
                try:
                    tx_ok_counter = counter_dict['tx_ok'].replace(',', '')
                    static_data.tx_traffic = int(tx_ok_counter) if tx_ok_counter.isdigit() else 0
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        if not (static_data.tx_traffic >= 0.95* static_data.rx_traffic):
            st.log("data.tx_traffic:{}".format(static_data.tx_traffic))
            st.log("data.rx_traffic:{}".format(static_data.rx_traffic))
            intfobj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
            st.report_fail('traffic_loss_observed')
    return True

def test_ft_verify_static_portchannel_created_or_not():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.1 Verify that a Static Port Channel can be created.
    '''
    st.log('Scenario - 3.1.1 Verify that a Static Port Channel can be created')
    if not portchannelobj.verify_portchannel(vars.D1, static_data.portchannel_name):
        st.report_fail('portchannel_create_failed', static_data.portchannel_name, vars.D1)
    st.report_pass('portchannel_create_successful', static_data.portchannel_name, vars.D1)

def test_ft_verify_static_portchannel_with_l2_traffic():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.2 Verify that l2 traffic is forwarded Through the Static Port Channel.
    '''
    st.log('Scenario - 3.1.2 Verify that l2 traffic is forwarded Through the Static Port Channel.')
    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    static_data.tg.tg_traffic_control(action='run', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1'], static_data.streams['D2T1_SD_Mac_Hash1']])
    st.wait(5)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1'], static_data.streams['D2T1_SD_Mac_Hash1']])

    verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 20, traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    verify_traffic_hashed_or_not(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4], 20, traffic_loss_verify=True, rx_port=vars.D2T1P1, tx_port=vars.D1T1P1, dut2=vars.D1)
    [output, exceptions] = exec_all(True, [[get_mac_address_count, vars.D1, None, static_data.portchannel_name],[get_mac_address_count, vars.D2, None, static_data.portchannel_name]])

    ensure_no_exception(exceptions)
    mac_count1, mac_count2 = output
    if int(mac_count1) < 100:
        st.report_fail('traffic_verification_fail', vars.D1)
    if int(mac_count2) < 100:
        st.report_fail('traffic_verification_fail', vars.D2)
    st.log('verified that traffic is successfully passing')
    st.report_pass('portchannel_l2_forwarding_success')

def test_ft_verify_static_portchannel_func_when_dis_en_mem_ports():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.2 Verify that l2 traffic is forwarded Through the Static Port Channel.
    '''
    count = 0
    st.log('Scenari - 3.1.5 Verify that traffic flow is fine through LAG after LAG member shut/no-shut.')
    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.wait(3)
    intfobj.interface_operation(vars.D1, vars.D1D2P1, operation="shutdown")
    st.wait(3)

    static_data.tg.tg_traffic_control(action='run', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1'], static_data.streams['D2T1_SD_Mac_Hash1']])
    st.wait(3)
    intfobj.interface_operation(vars.D1, vars.D1D2P1, operation="startup")
    st.wait(3)
    if not intfobj.poll_for_interface_status(vars.D1, vars.D1D2P1, property='oper', value='up', iteration='2', delay=2):
        count +=1
        st.log("Interface is not UP after performing a Flap")
    portchannelobj.get_portchannel_members(vars.D1, portchannel=static_data.portchannel_name)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1'], static_data.streams['D2T1_SD_Mac_Hash1']])
    verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 20,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    verify_traffic_hashed_or_not(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4], 20,
                                 traffic_loss_verify=True, rx_port=vars.D2T1P1, tx_port=vars.D1T1P1, dut2=vars.D1)

    if count == 0:
        st.report_pass('portchannel_member_en_dis_success')
    else:
        st.report_fail('portchannel_member_en_dis_failed')

def test_ft_verify_static_portchannel_del_with_member_ports():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.2.1 Verify that deletion of a Static Port Channel with member ports Present is not Successful.
    '''
    st.log("Scenario - 3.2.1 Verify that deletion of a Static Port Channel with member ports Present is not Successful.")
    portchannelobj.delete_portchannel(vars.D1, static_data.portchannel_name)
    st.report_pass('portchannel_with_vlan_membership_should_not_successful', static_data.portchannel_name)

def test_ft_verify_static_portchannel_add_member_to_other_portchannel():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.2.5 A member port already part of a port-channel shouldn't be allowed to add it to another port-channel.
    '''
    st.log("Scenario - 3.2.5 A member port already part of a port-channel shouldn't be allowed to add it to another port-channel.")
    if not portchannelobj.create_portchannel(vars.D1, static_data.portchannel_name2,static=True):
        st.report_fail('portchannel_create_failed', static_data.portchannel_name2, vars.D1)
    portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name2, static_data.members_dut1[0], skip_verify=False, skip_err_check=True)
    portchannelobj.delete_portchannel(vars.D1, static_data.portchannel_name2)
    st.report_pass('add_member_ports_to_other_portchannel')

def test_ft_verify_static_portchannel_is_up_or_not_with_one_active_member():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.8 Verify that the status of the Port Channel is Up as long as at least one of its member ports is in Link Up state
    '''
    st.log('Scenario - 3.1.8: Verify that the status of the Port Channel is Up as long as at least one of its member ports is in Link Up state.')
    portchannelobj.delete_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1[1:])
    if not portchannelobj.poll_for_portchannel_status(vars.D1, static_data.portchannel_name, 'up', iteration=10):
        portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1[1:])
        st.report_fail('portchannel_state_fail', static_data.portchannel_name, vars.D1, 'down')
    st.report_pass('portchannel_state_with_atlease_one_link', static_data.portchannel_name)

def test_ft_verify_static_portchannel_is_up_with_active_members_when_no_lag_in_partner():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.7 Verify that the static LAG in main DUT is UP with lag configured with active members when LAG is not created at partner DUT.
    '''
    st.log('Scenario - 3.1.7 Verifying that the static LAG in main DUT is UP with lag configured with active members when LAG is not created at partner DUT')
    portchannelobj.add_del_portchannel_member(vars.D2, static_data.portchannel_name, static_data.members_dut2, 'del')
    delete_vlan_member(vars.D2, static_data.vid, static_data.portchannel_name, tagging_mode=True)
    portchannelobj.delete_portchannel(vars.D2, static_data.portchannel_name)
    if not portchannelobj.poll_for_portchannel_status(vars.D1, static_data.portchannel_name, 'up', iteration=10):
        st.report_fail('portchannel_state_fail', static_data.portchannel_name, vars.D1, 'down')
    st.report_pass('portchannel_state_with_partner_dut', static_data.portchannel_name)


def test_ft_verify_static_portchannel_enable_disable_with_MTU_Value():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.4 Verify that mtu value is configured and enable/disable the portchannel.
    '''
    st.log('Scenario - 3.1.4 Verify that mtu value is configured and enable/disable the portchannel.')
    portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1, 'del')
    intfobj.interface_properties_set(vars.D1, static_data.members_dut1+[static_data.portchannel_name], 'mtu', '4096')
    portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
    portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1, 'del')
    intfobj.interface_properties_set(vars.D1, static_data.members_dut1+[static_data.portchannel_name], 'mtu', static_data.mtu_default)
    portchannelobj.add_del_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
    intfobj.interface_operation(vars.D1, static_data.portchannel_name, operation="shutdown")
    if not intfobj.interface_operation(vars.D1, static_data.portchannel_name, operation="startup"):
        st.report_fail('portchannel_state_fail', static_data.portchannel_name, vars.D1, 'down')
    st.report_pass('Enable_disable_portchannel_with_mtu', static_data.portchannel_name)

def test_ft_verify_static_portchannel_del_from_ip_assigned_vlan():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.2.1 Verify that deletion of a Static Port Channel which is member of vlan with an IP address is assigned on it is not Successful.
    '''
    st.log('Scenario - 3.2.1 Verify that deletion of a Static Port Channel which is member of vlan with an IP address is assigned on it is not Successful')
    portchannelobj.delete_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
    ipobj.config_ip_addr_interface(vars.D1, 'Vlan{}'.format(static_data.vid), static_data.ip41, static_data.ip_mask)

    portchannelobj.delete_portchannel(vars.D1, static_data.portchannel_name)
    st.report_pass('portchannel_delete_with_ip_configured_vlan', static_data.portchannel_name, 'Vlan{}'.format(static_data.vid))

def test_ft_del_ip_assigned_portchannel():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.2.2 Verify that deletion of a Static Port Channel with IP address is assigned on it is not Successful.
    '''
    st.log('Scenario - 3.2.2 Verify that deletion of a Static Port Channel with IP address is assigned on it is not Successful.')
    portchannelobj.delete_portchannel_member(vars.D1, static_data.portchannel_name, static_data.members_dut1)
    exceptions = exec_all(True, [
        ExecAllFunc(delete_vlan_member, vars.D1, static_data.vid, static_data.portchannel_name, tagging_mode=True),
        ExecAllFunc(delete_vlan_member, vars.D2, static_data.vid, static_data.portchannel_name, tagging_mode=True)])[1]
    ensure_no_exception(exceptions)
    ipobj.config_ip_addr_interface(vars.D1, static_data.portchannel_name, static_data.ip41, static_data.ip_mask)

    result = portchannelobj.delete_portchannel(vars.D1, static_data.portchannel_name, skip_error=True)
    cli_type = st.get_ui_type(vars.D1)
    if cli_type == 'click':
        if result:
            st.report_fail('msg', 'Allowed to delete PortChannel which is configured with IP address')
    else:
        if not result:
            st.report_fail('msg', 'Delete PortChannel which is configured with IP address is not allowed')
    st.report_pass('portchannel_delete_with_ip_configured_portchannel')


def test_ft_verify_fallback_is_configure_or_not_on_static_portchannel():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.2.6 Verify that "fallback" cannot be configured on a static Port Channel.
    '''
    st.log('Scenario - 3.2.6 Verify that "fallback" cannot be configured on a static Port Channel.')
    if portchannelobj.create_portchannel(vars.D1, static_data.portchannel_name2, fallback=True, static=True):
        st.report_fail('portchannel_fallback_configuration_fail')
    else:
        st.report_pass('portchannel_fallback_configuration')


def test_ft_verify_max_static_portchannel():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.4.1 Verify the max number of Static Port Channels configurable per system.
    '''
    portchannel_list=[]
    for i in range(2, static_data.max_portchannels + 1, 1):
       portchannelobj.create_portchannel(vars.D1, "PortChannel"+str(i), static=True)
    for i in range(2, static_data.max_portchannels + 1, 1):
        temp = "PortChannel"+str(i)
        portchannel_list.append(temp)
    portchannelobj.delete_portchannels(vars.D1, portchannel_list)
    st.wait(10)
    portchannel_list1 = portchannelobj.get_portchannel_names(vars.D1)
    portchannel_list1 = list(dict.fromkeys(portchannel_list1))
    if len(portchannel_list1) != 1:
        st.report_fail('portchannel_config_clear_failed')
    elif static_data.portchannel_name not in portchannel_list1:
        st.report_fail('portchannel_not_found',static_data.portchannel_name)
    else:
        st.report_pass('max_portchannels_per_system')



def test_ft_verify_static_portchannel_l3_hash_sip_dip_l4port():
    """
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.1.3 Verify that L3 LAG hashing functionality working fine with Static Port Channel.
    """
    st.log('Scenario - 3.1.3 Verify that L3 LAG hashing functionality working fine with Static Port Channel.')
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_1)
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_3)
    stream = static_data.tg.tg_traffic_config(port_handle=static_data.tg_ph_1, mode='create', length_mode='fixed', mac_dst=static_data.dut1_rt_int_mac, mac_src='00:05:00:00:00:01', mac_src_mode='increment', mac_src_step='00:00:00:00:00:01', mac_dst_mode='fixed', ip_src_addr=static_data.ip41, ip_src_mode='increment', ip_src_count=static_data.ip_src_count, ip_src_step='0.0.0.1', mac_src_count=1000, ip_dst_addr=static_data.ip42, ip_dst_mode='fixed', pkts_per_burst=1000, l3_protocol='ipv4', transmit_mode='single_burst')
    static_data.streams['D1T1_SD_ip_Hash1'] = stream['stream_id']

    exceptions = \
    exec_all(True, [[delete_vlan_member, vars.D1, static_data.vid, [vars.D1T1P1, static_data.portchannel_name], True],
                    [delete_vlan_member, vars.D2, static_data.vid, [vars.D2T1P1, static_data.portchannel_name], True]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[ipobj.config_ip_addr_interface, vars.D1, static_data.portchannel_name, static_data.ip_addr_pc1, static_data.subnet],
                                 [ipobj.config_ip_addr_interface, vars.D2, static_data.portchannel_name, static_data.ip_addr_pc2, static_data.subnet]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[ipobj.config_ip_addr_interface, vars.D1, vars.D1T1P1, static_data.ip_addr_po1, static_data.subnet],
                                 [ipobj.config_ip_addr_interface, vars.D2, vars.D2T1P1, static_data.ip_addr_po2, static_data.subnet]])[1]
    ensure_no_exception(exceptions)
    if not ipobj.verify_interface_ip_address(vars.D1, vars.D1T1P1, "{}/8".format(static_data.ip_addr_po1), static_data.ipv4):
        st.report_fail('ip_routing_int_create_fail', static_data.ip_addr_po1)
    if not ipobj.verify_interface_ip_address(vars.D2, vars.D2T1P1, "{}/8".format(static_data.ip_addr_po2), static_data.ipv4):
        st.report_fail('ip_routing_int_create_fail', static_data.ip_addr_po2)
    st.wait(5)
    if not arpobj.add_static_arp(vars.D2, static_data.ip42, static_data.remote_mac2, interface=vars.D2T1P1):
        st.report_fail("msg", "Failed to configure static ARP")
    # ping from dut to partner
    ipobj.ping(vars.D1, static_data.ip_addr_pc2 , family='ipv4', count=3)
    exceptions = exec_all(True, [[ipobj.create_static_route, vars.D1, static_data.ip_addr_pc2, static_data.static_ip2],
                                 [ipobj.create_static_route, vars.D2, static_data.ip_addr_pc1, static_data.static_ip1]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    static_data.tg.tg_traffic_control(action='run', stream_handle=static_data.streams['D1T1_SD_ip_Hash1'])
    st.wait(2)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=static_data.streams['D1T1_SD_ip_Hash1'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 200,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_1)
    st.report_pass('portchannel_l3_forwarding_success', static_data.portchannel_name, vars.D1)


def test_ft_verify_static_portchannel_vlan_routing_l3_traffic():
    """
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    3.1.6 Verify that LAG can forward traffic when participating in VLAN Routing.
    """
    st.log("verify that scenario - 3.1.6 Verify that LAG can forward traffic when participating in VLAN Routing.")

    exceptions = exec_all(True, [[ipobj.config_ip_addr_interface, vars.D1, 'Vlan{}'.format(static_data.vid), static_data.ip_addr_pc1, static_data.subnet], [ipobj.config_ip_addr_interface, vars.D2, 'Vlan{}'.format(static_data.vid), static_data.ip_addr_pc2, static_data.subnet]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[delete_vlan_member, vars.D1, static_data.vid, vars.D1T1P1, True],
                                 [delete_vlan_member, vars.D2, static_data.vid, vars.D2T1P1, True]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[ipobj.config_ip_addr_interface, vars.D1, vars.D1T1P1, static_data.ip_addr_po1, static_data.subnet],
                                 [ipobj.config_ip_addr_interface, vars.D2, vars.D2T1P1, static_data.ip_addr_po2, static_data.subnet]])[1]
    ensure_no_exception(exceptions)

    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_1)
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_3)
    stream = static_data.tg.tg_traffic_config(port_handle=static_data.tg_ph_1, mode='create', length_mode='fixed',
                                          mac_dst=static_data.dut1_rt_int_mac,
                                          mac_src='00:05:00:00:00:01', mac_src_mode='increment',
                                          mac_src_step='00:00:00:00:00:01', mac_dst_mode='fixed',
                                          ip_src_addr=static_data.ip41, ip_src_mode='increment',
                                          ip_src_count=static_data.ip_src_count, ip_src_step='0.0.0.1',
                                          mac_src_count=1000,
                                          ip_dst_addr=static_data.ip42, ip_dst_mode='fixed', pkts_per_burst=1000,
                                          l3_protocol='ipv4', transmit_mode='single_burst')
    static_data.streams['D1T1_SD_ip_Hash1'] = stream['stream_id']

    if not ipobj.verify_interface_ip_address(vars.D1, vars.D1T1P1, "{}/8".format(static_data.ip_addr_po1),
                                         static_data.ipv4):
        st.report_fail('ip_routing_int_create_fail', static_data.ip_addr_po1)
    if not ipobj.verify_interface_ip_address(vars.D2, vars.D2T1P1, "{}/8".format(static_data.ip_addr_po2),
                                         static_data.ipv4):
        st.report_fail('ip_routing_int_create_fail', static_data.ip_addr_po2)

    exceptions = exec_all(True, [[ipobj.create_static_route, vars.D1, static_data.ip_addr_pc2, static_data.static_ip2],
                [ipobj.create_static_route, vars.D2, static_data.ip_addr_pc1, static_data.static_ip1]])[1]
    ensure_no_exception(exceptions)
    st.wait(5)

    if not arpobj.add_static_arp(vars.D2, static_data.ip42, static_data.remote_mac2, interface=vars.D2T1P1):
        st.report_fail("msg", "Failed to configure static ARP")
    # ping from dut to partner
    ipobj.ping(vars.D1, static_data.ip_addr_pc2 , family='ipv4', count=3)

    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    static_data.tg.tg_traffic_control(action='run', stream_handle=static_data.streams['D1T1_SD_ip_Hash1'])
    st.wait(2)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=static_data.streams['D1T1_SD_ip_Hash1'])
    st.log("Verify that traffic is forwarding over portchannel members")
    verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 200,
                             traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_1)
    st.report_pass('portchannel_l3_vlan_routing_success', static_data.portchannel_name)

def test_ft_verify_static_portchannel_funtionality_during_warm_reboot():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.3.2 Verify that port-channel is up and no traffic loss is observed during and after warm reboot.
    '''
    st.log('Scenario - 3.3.2 Verify that port-channel is up and no traffic loss is observed during and after warm reboot.')
    static_data.tg.tg_traffic_control(action='reset', port_handle=static_data.tg_ph_1)
    stream = static_data.tg.tg_traffic_config(port_handle=static_data.tg_ph_1, mode='create', length_mode='fixed',
                                              frame_size=72,
                                              mac_src='00:00:01:00:00:01', mac_src_step='00:00:00:00:00:01',
                                              mac_src_mode='increment', mac_src_count=1000,
                                              mac_dst='00:00:02:00:00:02', mac_dst_step='00:00:00:00:00:01',
                                              mac_dst_mode='increment', mac_dst_count=1000,
                                              rate_percent=100, l2_encap='ethernet_ii_vlan', vlan="enable",
                                              vlan_id=static_data.vid, transmit_mode='continuous')
    static_data.streams['D1T1_SD_Mac_Hash1'] = stream['stream_id']

    st.log("performing Config save")
    exceptions = exec_all(True, [[rbobj.config_save, vars.D1], [rbobj.config_save, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.reboot(vars.D2, 'warm')
    st.wait(10)
    exceptions = exec_all(True, [[portchannelobj.verify_portchannel_state, vars.D1, static_data.portchannel_name, "up"],
                                 [portchannelobj.verify_portchannel_state, vars.D2, static_data.portchannel_name, "up"]])[1]
    ensure_no_exception(exceptions)

    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    static_data.tg.tg_traffic_control(action='run', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1']])
    st.wait(5)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1']])
    if not verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 20, traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2):
        st.report_fail('portchannel_functionality_during_warmreboot_failed')
    else:
        st.report_pass('portchannel_functionality_during_warmreboot')



def test_ft_verify_static_portchannel_funtionality_after_save_and_reboot():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.3.1 Verify that the Static LAG configuration should be retained after save and reboot.
    '''
    st.log('Scenario - 3.3.1 Verify that the Static LAG configuration should be retained after save and reboot.')
    st.log("performing Config save and reboot")
    rbobj.config_save_reload([vars.D1, vars.D2])
    st.wait(10)
    exceptions = exec_all(True, [[portchannelobj.verify_portchannel_state, vars.D1, static_data.portchannel_name, "up"],
                                 [portchannelobj.verify_portchannel_state, vars.D2, static_data.portchannel_name, "up"]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[intfobj.clear_interface_counters, vars.D1], [intfobj.clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    static_data.tg.tg_traffic_control(action='run', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1']])
    st.wait(5)
    static_data.tg.tg_traffic_control(action='stop', stream_handle=[static_data.streams['D1T1_SD_Mac_Hash1']])
    verify_traffic_hashed_or_not(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 20,
                                 traffic_loss_verify=True, rx_port=vars.D1T1P1, tx_port=vars.D2T1P1, dut2=vars.D2)
    st.report_pass('portchannel_functionality_after_save_and_reboot')

def test_ft_verify_static_portchannel_config_after_fast_reboot():
    '''
    Author: Venkatesh Terli <venkatesh.terli@broadcom.com>
    Scenario - 3.3.3 Verify that portchannel configuration is retained after save and fast-reboot.
    '''
    st.log('Scenario - 3.3.3 Verify that portchannel configuration is retained after save and fast-reboot.')
    st.log("performing Config save")
    rbobj.config_save(vars.D1)
    st.log("performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    st.log("Checking whether config is loaded to running config from config_db after warm-reboot")
    portchannelobj.verify_portchannel_state(vars.D1, static_data.portchannel_name)
    st.report_pass('portchannel_functionality_after_save_and_fastreboot')

