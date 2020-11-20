# Error Handling FT long run test cases.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.basic as bsapi
import apis.switching.vlan as vapi
import apis.common.asic_bcm as asicapi
import apis.system.error_handling as ehapi
from apis.system.reboot import config_save
from apis.system.switch_configuration import get_running_config
from apis.system.logging import clear_logging

from utilities import common as utils

@pytest.fixture(scope="module", autouse=True)
def error_handling_module_hooks():
    global_vars_and_constants_init()
    if not st.is_valid_base_config():
        full_cleanup()
    error_handling_module_config(config='yes')
    if eh_data.clear_logs:
        clear_logging(eh_data.dut_list, thread=True)
    yield
    error_handling_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def error_handling_func_hooks():
    if eh_data.debug:
        get_running_config(vars.D1)
    yield
    if eh_data.clear_logs:
        clear_logging(eh_data.dut_list, thread=True)


def global_vars_and_constants_init():
    global eh_data, vars, intf_d1d2p1, intf_d2d1p1, intf_d1t1p1
    eh_data = SpyTestDict()
    vars = st.ensure_min_topology('D1D2:1', 'D1T1:2')
    eh_data.platform = bsapi.get_hwsku(vars.D1).lower()
    hw_constants = st.get_datastore(vars.D1, "constants", eh_data.platform)
    if not hw_constants:
        hw_constants = st.get_datastore(vars.D1, "constants")

    # Falgs
    eh_data.debug = True
    eh_data.clear_logs = True
    eh_data.thread_mode = True
    eh_data.dut_list = [vars.D1, vars.D2]
    eh_data.ping_delay = 5
    eh_data.ping_retry = 1
    eh_data.error_route_table = "ERROR_ROUTE_TABLE"
    eh_data.error_neigh_table = "ERROR_NEIGH_TABLE"
    eh_data.swss_rc_success = "SWSS_RC_SUCCESS"
    eh_data.swss_rc_exists = "SWSS_RC_EXISTS"
    eh_data.swss_rc_not_found = "SWSS_RC_NOT_FOUND"
    eh_data.swss_rc_table_full = "SWSS_RC_TABLE_FULL"
    eh_data.log_str_swss = "swss#orchagent:"
    eh_data.log_str_bgp = "bgp#fpmsyncd:"
    eh_data.route_not_install_flag = '#'
    # Global vars
    eh_data.ipv4_addr = "10.1.1.1"
    eh_data.ipv4_nbr = "10.1.1.2"
    eh_data.ipv4_mask = "255.255.255.0"
    eh_data.ipv4_mask_len = '24'
    eh_data.ipv6_addr = "2001::1"
    eh_data.ipv6_nbr = "2001::2"
    eh_data.ipv6_mask_len = '64'
    eh_data.local_asn = '65400'
    eh_data.remote_asn = '65007'
    eh_data.tg_remote_asn = '65009'
    eh_data.ipv4_route = "12.12.12.0"
    eh_data.ipv4_route2 = "13.13.13.0"
    eh_data.ipv6_route = "0600:0000:0000:0000:0000:0000:0000:0000"
    eh_data.ipv6_route2 = "0700:0000:0000:0000:0000:0000:0000:0000"
    eh_data.ipv6_route_mask = "600::0/64"
    eh_data.ipv6_route2_mask = "700::0/64"
    eh_data.ipv6_route_sf = "600::"
    eh_data.ipv6_route2_sf = "700::"
    eh_data.egr_intf = '100002'
    eh_data.vrf = '0'
    eh_data.loopback4_1 = "66.66.66.66"
    eh_data.loopback4_2 = "77.77.77.77"
    eh_data.loopback6_1 = "6666::6666"
    eh_data.loopback6_2 = "7777::7777"
    eh_data.af_ipv4 = "ipv4"
    eh_data.af_ipv6 = "ipv6"
    eh_data.shell_sonic = "sonic"
    eh_data.shell_vtysh = "vtysh"
    eh_data.route_map_name = 'error_handling_route_map'
    eh_data.peer_gp_namev4 = 'error_handlingv4'
    eh_data.tg_peer_gp_namev4 = 'tg_error_handlingv4'
    eh_data.peer_gp_namev6 = 'error_handlingv6'
    eh_data.tg_peer_gp_namev6 = 'tg_error_handlingv6'
    eh_data.ipv4_nbr2 = "10.1.1.3"
    eh_data.ipv6_nbr2 = "2001::3"
    eh_data.ipv4_nbr2_mac = "00:00:00:00:00:01"
    eh_data.ipv6_nbr2_mac = "00:00:00:00:00:02"
    eh_data.ipv4_nbr3 = "10.1.1.4"
    eh_data.ipv6_nbr3 = "2001::4"
    eh_data.ipv4_nbr3_mac = "00:00:00:00:00:03"
    eh_data.ipv6_nbr3_mac = "00:00:00:00:00:04"
    # TG vars
    eh_data.tg1_ipv4_addr = "20.1.1.1"
    eh_data.tg1_ipv4_nbr = "20.1.1.2"
    eh_data.tg1_ipv4_mask = "255.255.255.0"
    eh_data.tg1_ipv4_mask_len = '24'
    eh_data.tg1_ipv6_addr = "3001::1"
    eh_data.tg1_ipv6_nbr = "3001::2"
    eh_data.tg1_ipv6_mask_len = '64'
    # Constants
    eh_data.ipv4_max_routes = int(hw_constants['MAX_IPV4_ROUTES_FOR_ERROR_HANDLING'])
    st.log("MAX_IPV4_ROUTES_FOR_ERROR_HANDLING: {}".format(eh_data.ipv4_max_routes))
    eh_data.ipv6_max_routes = int(hw_constants['MAX_IPV6_ROUTES_FOR_ERROR_HANDLING'])
    st.log("MAX_IPV6_ROUTES_FOR_ERROR_HANDLING: {}".format(eh_data.ipv6_max_routes))
    eh_data.max_route_install_wait_time = 120
    eh_data.bcmcmd_timeout = 600
    eh_data.cli_type = st.get_ui_type(vars.D1)
    intf_d1d2p1 = vars.D1D2P1
    intf_d2d1p1 = vars.D2D1P1
    intf_d1t1p1 = vars.D1T1P1
    if eh_data.cli_type == "klish":
        if vars.config.ifname_type == "alias":
            intf_d1d2p1 = st.get_other_names(vars.D1, [vars.D1D2P1])[0]
            intf_d2d1p1 = st.get_other_names(vars.D2, [vars.D2D1P1])[0]
            intf_d1t1p1 = st.get_other_names(vars.D1, [vars.D1T1P1])[0]

def error_handling_module_config(config='yes'):
    def config_dut():
        config_ip_topology(config)
        config_ip_loopback(config)
        config_bgp_route_map(config)
        config_bgp_topology(config)
        if config == 'yes':
            config_save(eh_data.dut_list)
        config_tg_ip_bgp_stream_error_handling(config)

    def config_tg():
        if config == 'yes':
            get_tg_parameters()
        tg_tg_ip_bgp_config(tg, tg_ph_list, config=config)

    config_dut()
    config_tg()



def full_cleanup():
    bgpapi.cleanup_router_bgp(st.get_dut_names())
    ipapi.clear_ip_configuration(st.get_dut_names(), thread=eh_data.thread_mode, family='all')
    vapi.clear_vlan_configuration(st.get_dut_names(), thread=eh_data.thread_mode)


def thread_call(thread_info, first_on_main=False):
    [out, exceptions] = utils.exec_all(eh_data.thread_mode, thread_info, first_on_main=first_on_main)
    st.log([out, exceptions])


def config_tg_ip_bgp_stream_error_handling(config='yes'):
    ip_config = 'add' if config == 'yes' else 'remove'
    tg_dut_ip_bgp_config(config=ip_config)
    eh_data.route_count_init_v4 = asicapi.bcmcmd_route_count_hardware(vars.D1, timeout=eh_data.bcmcmd_timeout)
    eh_data.route_count_init_v6 = asicapi.bcmcmd_ipv6_route_count_hardware(vars.D1, timeout=eh_data.bcmcmd_timeout)


def get_tg_parameters():
    global tg, tg_ph_list, tg_data
    tg_data = {}
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_list = [tg_ph_1, tg_ph_2]
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    return tg, tg_ph_list


def tg_dut_ip_bgp_config(config='add'):
    st.banner("{}Config IP Addresses and BGP on TG connected interfaces".
                      format('Un' if config != 'add' else ''))
    # IPv4
    ipapi.config_ip_addr_interface(dut=vars.D1, interface_name=intf_d1t1p1,
                                   ip_address=eh_data.tg1_ipv4_addr, subnet=eh_data.tg1_ipv4_mask_len, family="ipv4",
                                   config=config)
    if config == 'add':
        bgpapi.config_bgp_multi_neigh_use_peergroup(vars.D1, local_asn=eh_data.local_asn,
                                                    peer_grp_name=eh_data.tg_peer_gp_namev4,
                                                    remote_asn=eh_data.tg_remote_asn,
                                                    neigh_ip_list=eh_data.tg1_ipv4_nbr,
                                                    family='ipv4', activate=1)
    # IPv6
    ipapi.config_ip_addr_interface(dut=vars.D1, interface_name=intf_d1t1p1,
                                   ip_address=eh_data.tg1_ipv6_addr, subnet=eh_data.tg1_ipv6_mask_len, family="ipv6",
                                   config=config)
    if config == 'add':
        bgpapi.config_bgp_multi_neigh_use_peergroup(vars.D1, local_asn=eh_data.local_asn,
                                                    peer_grp_name=eh_data.tg_peer_gp_namev6,
                                                    remote_asn=eh_data.tg_remote_asn,
                                                    neigh_ip_list=eh_data.tg1_ipv6_nbr,
                                                    family='ipv6', activate=1)


def tg_tg_ip_bgp_config(tg_obj, tg_ph_li, config='yes'):
    st.banner("{}Config IP Addresses and BGP on TG interfaces".format('Un' if config != 'yes' else ''))
    if config == 'yes':
        st.banner("IPv4 Addresses and BGP on TG interfaces", delimiter='*')
        tg_data['ipv4_h1'] = tg_obj.tg_interface_config(port_handle=tg_ph_li[0], mode='config',
                                                        intf_ip_addr=eh_data.tg1_ipv4_nbr,
                                                        gateway=eh_data.tg1_ipv4_addr,
                                                        netmask=eh_data.tg1_ipv4_mask, arp_send_req='1')
        st.log('>>>>>  ipv4_h1 : {}'.format(tg_data['ipv4_h1']))
        tg_data['bgp4_rtr1'] = tg_obj.tg_emulation_bgp_config(handle=tg_data['ipv4_h1']['handle'], mode='enable',
                                                              active_connect_enable='1',
                                                              local_as=eh_data.tg_remote_asn,
                                                              remote_as=eh_data.local_asn,
                                                              remote_ip_addr=eh_data.tg1_ipv4_addr)
        st.log('>>>>>  bgp4_rtr1 : {}'.format(tg_data['bgp4_rtr1']))

        st.banner("IPv6 Addresses and BGP on TG interfaces", delimiter='*')
        tg_data['ipv6_h1'] = tg_obj.tg_interface_config(port_handle=tg_ph_li[0], mode='config',
                                                        ipv6_intf_addr=eh_data.tg1_ipv6_nbr,
                                                        ipv6_prefix_length=eh_data.tg1_ipv6_mask_len,
                                                        ipv6_gateway=eh_data.tg1_ipv6_addr, arp_send_req='1')
        st.log('>>>>>  ipv6_h1 : {}'.format(tg_data['ipv6_h1']))
        tg_data['bgp6_rtr1'] = tg_obj.tg_emulation_bgp_config(handle=tg_data['ipv6_h1']['handle'], mode='enable',
                                                              ip_version='6', active_connect_enable='1',
                                                              local_as=eh_data.tg_remote_asn,
                                                              remote_as=eh_data.local_asn,
                                                              remote_ipv6_addr=eh_data.tg1_ipv6_addr)
        st.log('>>>>>  bgp6_rtr1 : {}'.format(tg_data['bgp6_rtr1']))

        tg_bgp_routes_add()
        tg_bgp_protocol_start_stop(action='start', af='both')
        tg_bgp_routes_advertise_withdraw(action='withdraw', af='both')
        check_for_routes_in_device(eh_data.route_count_init_v4, 'ipv4', flag='e', report=True)
        check_for_routes_in_device(eh_data.route_count_init_v6, 'ipv6', flag='e', report=True)

    else:
        tg_bgp_routes_advertise_withdraw(action='withdraw', af='both')
        tg_bgp_protocol_start_stop(action='stop', af='both')
        tg_obj.tg_interface_config(port_handle=tg_ph_li[0], handle=tg_data['ipv4_h1']['handle'], mode='destroy')
        tg_obj.tg_interface_config(port_handle=tg_ph_li[0], handle=tg_data['ipv6_h1']['handle'], mode='destroy')


def tg_bgp_routes_add():
    st.banner("Adding BGP Routes to TG")
    tg_data['bgp4_route1'] = tg.tg_emulation_bgp_route_config(handle=tg_data['bgp4_rtr1']['handle'], mode='add',
                                                              num_routes=eh_data.ipv4_max_routes, prefix='55.0.0.0',
                                                              as_path='as_seq:1')
    st.log('>>>>>  bgp4_route1 : {}'.format(tg_data['bgp4_route1']))
    tg_data['bgp6_route1'] = tg.tg_emulation_bgp_route_config(handle=tg_data['bgp6_rtr1']['handle'], mode='add',
                                                              num_routes=eh_data.ipv6_max_routes,
                                                              prefix='6002:1::0', as_path='as_seq:1', ip_version='6')
    st.log('>>>>>  bgp6_route1 : {}'.format(tg_data['bgp6_route1']))


def tg_bgp_protocol_start_stop(action='start', af='ipv4'):
    # action = start | stop
    st.banner("{} BGP {} Protocol on TG".format(action, af))
    if af in 'ipv4' or af == 'both':
        tg_data['bgp4_route1_ctrl'] = tg.tg_emulation_bgp_control(handle=tg_data['bgp4_rtr1']['handle'], mode=action)
        st.log('>>>>>  bgp4_route1_ctrl : {}'.format(tg_data['bgp4_route1_ctrl']))
    if af in 'ipv6' or af == 'both':
        tg_data['bgp6_route1_ctrl'] = tg.tg_emulation_bgp_control(handle=tg_data['bgp6_rtr1']['handle'], mode=action)
        st.log('>>>>>  bgp6_route1_ctrl : {}'.format(tg_data['bgp6_route1_ctrl']))


def tg_bgp_routes_advertise_withdraw(action='readvertise', af='ipv4'):
    # action = withdraw | readvertise
    st.banner("'{}' - BGP {} Routes from TG".format(action, af))
    if af in 'ipv4' or af == 'both':
        tg.tg_bgp_routes_control(handle=tg_data['bgp4_route1']['handle'], route_handle=tg_data['bgp4_route1']['handle'],
                                 mode=action)
    if af in 'ipv6' or af == 'both':
        tg.tg_bgp_routes_control(handle=tg_data['bgp6_route1']['handle'], route_handle=tg_data['bgp6_route1']['handle'],
                                 mode=action)


def check_for_routes_in_device(route_count, af, flag='ge', report=False):
    result = True
    if af in 'ipv4' or af == 'both':
        if not ehapi.verify_route_count_bcmshell(vars.D1, route_count, af='ipv4', itter=30, delay=10, flag=flag,
                                                 timeout=eh_data.bcmcmd_timeout):
            st.error("Expected IPv4 routes are failed to install")
            result = False
    if af in 'ipv6' or af == 'both':
        if not ehapi.verify_route_count_bcmshell(vars.D1, route_count, af='ipv6', itter=30, delay=10, flag=flag,
                                                 timeout=eh_data.bcmcmd_timeout):
            st.error("Expected IPv6 routes are failed to install")
            result = False
    if report and not result:
        report_result(result)


def config_ip_topology(config='yes'):
    st.banner("{}Config IP Addresses on interfaces".format('Un' if config != 'yes' else ''))
    config = 'add' if config == 'yes' else 'remove'
    thread_info = list()
    thread_info.append(utils.ExecAllFunc(ipapi.config_ip_addr_interface, vars.D1, intf_d1d2p1, eh_data.ipv4_addr,
                                         eh_data.ipv4_mask_len, family=eh_data.af_ipv4, config=config))
    thread_info.append(utils.ExecAllFunc(ipapi.config_ip_addr_interface, vars.D2, intf_d2d1p1, eh_data.ipv4_nbr,
                                         eh_data.ipv4_mask_len, family=eh_data.af_ipv4, config=config))
    thread_call(thread_info)

    thread_info = list()
    thread_info.append(utils.ExecAllFunc(ipapi.config_ip_addr_interface, vars.D1, intf_d1d2p1, eh_data.ipv6_addr,
                                         eh_data.ipv6_mask_len, family=eh_data.af_ipv6, config=config))
    thread_info.append(utils.ExecAllFunc(ipapi.config_ip_addr_interface, vars.D2, intf_d2d1p1, eh_data.ipv6_nbr,
                                         eh_data.ipv6_mask_len, family=eh_data.af_ipv6, config=config))
    thread_call(thread_info)

    if config == 'add':
        if not check_ip_ping(vars.D1, ipv4=eh_data.ipv4_nbr, ipv6=eh_data.ipv6_nbr, retry=eh_data.ping_retry,
                             time_delay=eh_data.ping_delay):
            st.error("Ping Operation failed between DUT and Partner")
            st.report_fail('operation_failed')


def config_ip_loopback(config='yes'):
    st.banner("{}Config Loopback Addresses on interfaces on D2".format('Un' if config != 'yes' else ''))
    config = 'add' if config == 'yes' else 'remove'
    if config == 'add':
        ipapi.configure_loopback(vars.D2, loopback_name='Loopback1', config='yes')
    ipapi.config_ip_addr_interface(vars.D2, 'Loopback1', eh_data.loopback4_1, 32, family=eh_data.af_ipv4,
                                   config=config)
    ipapi.config_ip_addr_interface(vars.D2, "Loopback1", eh_data.loopback6_1, 128, family=eh_data.af_ipv6,
                                   config=config)
    if config == 'remove':
        ipapi.configure_loopback(vars.D2, loopback_name='Loopback1', config='no')


def config_bgp_route_map(config='yes'):
    st.banner("{}Config BGP Route Map".format('Un' if config != 'yes' else ''))
    thread_info = list()
    thread_info.append(utils.ExecAllFunc(ipapi.config_route_map_global_nexthop, vars.D1,
                                         route_map=eh_data.route_map_name,
                                         sequence='10', config=config))
    thread_info.append(utils.ExecAllFunc(ipapi.config_route_map_global_nexthop, vars.D2,
                                         route_map=eh_data.route_map_name,
                                         sequence='10', config=config))
    thread_call(thread_info)


def config_bgp_topology(config='yes'):
    st.banner("{}Config BGP on devices".format('Un' if config != 'yes' else ''))
    if config == 'yes':
        thread_info = list()
        thread_info.append(
            utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, vars.D1, local_asn=eh_data.local_asn,
                              peer_grp_name=eh_data.peer_gp_namev4, remote_asn=eh_data.remote_asn,
                              neigh_ip_list=eh_data.ipv4_nbr, family=eh_data.af_ipv4, activate=1))
        thread_info.append(
            utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, vars.D2, local_asn=eh_data.remote_asn,
                              peer_grp_name=eh_data.peer_gp_namev4, remote_asn=eh_data.local_asn,
                              neigh_ip_list=eh_data.ipv4_addr, family=eh_data.af_ipv4, activate=1))
        thread_call(thread_info)

        thread_info = list()
        thread_info.append(
            utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, vars.D1, local_asn=eh_data.local_asn,
                              peer_grp_name=eh_data.peer_gp_namev6, remote_asn=eh_data.remote_asn,
                              neigh_ip_list=eh_data.ipv6_nbr, family=eh_data.af_ipv6, activate=1,
                              routemap=eh_data.route_map_name, routemap_dir='in'))
        thread_info.append(
            utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, vars.D2, local_asn=eh_data.remote_asn,
                              peer_grp_name=eh_data.peer_gp_namev6, remote_asn=eh_data.local_asn,
                              neigh_ip_list=eh_data.ipv6_addr, family=eh_data.af_ipv6, activate=1,
                              routemap=eh_data.route_map_name, routemap_dir='in'))
        thread_call(thread_info)

        if config == 'yes':
            if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, vars.D1, family='ipv4',
                                   neighbor=[eh_data.ipv4_nbr], state='Established'):
                st.error("BGP Neighbor failed to Establish between DUT and Partner")
                st.report_fail('operation_failed')
            if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, vars.D1, family='ipv6',
                                   neighbor=[eh_data.ipv6_nbr], state='Established'):
                st.error("BGP Neighbor failed to Establish between DUT and Partner")
                st.report_fail('operation_failed')
    else:
        bgpapi.cleanup_router_bgp(st.get_dut_names())


def config_bgp_error_handling(config='yes'):
    st.banner("{}Config BGP error handling".format('Un' if config != 'yes' else ''))
    action = 'enable' if config == 'yes' else 'disable'
    ehapi.config_bgp_error_handling(vars.D1, action=action)


def config_bgp_redistribute(config='yes'):
    bgpapi.config_bgp(dut=vars.D2, local_as=eh_data.remote_asn, addr_family=eh_data.af_ipv4, config=config,
                      config_type_list=["redist"], redistribute='connected')
    bgpapi.config_bgp(dut=vars.D2, local_as=eh_data.remote_asn, addr_family=eh_data.af_ipv6, config=config,
                      config_type_list=["redist"], redistribute='connected')
    st.wait(1)


def config_static_route(dut, nhp, ip, shell, af, action):
    st.log("Creating a {} static route {} with Neighbor {}".format(af, ip, nhp))
    if action == "add":
        ipapi.create_static_route(dut, next_hop=nhp, static_ip=ip, shell=shell, family=af)
        if not ipapi.verify_ip_route(dut, af, ip):
            st.report_fail('ip_routing_int_create_fail', dut)


def check_ip_ping(dut, ipv4=None, ipv6=None, retry=1, time_delay=5):
    i = 0
    while True:
        result = True
        if ipv4:
            if not ipapi.ping(dut, ipv4, family=eh_data.af_ipv4):
                st.log("Ping to {} on Dut {} is failed.".format(ipv4, dut))
                result = False
        if ipv6:
            if not ipapi.ping(dut, ipv6, family=eh_data.af_ipv6):
                st.log("Ping to {} on Dut {} is failed.".format(ipv6, dut))
                result = False
        if result or (i == retry):
            break
        i += 1
        st.wait(time_delay)
    return result


def report_result(status):
    if status:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')


@pytest.mark.error_handling_ft
@pytest.mark.error_handling_ft_long_run
def test_ft_eh_rt_ipv4_ipv6_notify_table_full():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    st.banner('Test cases covered - ft_eh_rt_max_routes_plus_one, ft_eh_rt_noty_table_full')
    result = True

    tg_bgp_routes_advertise_withdraw(action='readvertise', af='both')
    st.wait(eh_data.max_route_install_wait_time)

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_table_full))
    if not ehapi.verify_num_entries_show_error_db(vars.D1, 1, itter=30, delay=30, flag='ge',
                                                  table=eh_data.error_route_table, error=eh_data.swss_rc_table_full):
        st.error("entry_not_found_in_error_db")
        st.banner('{} - Test Validation Failed '.format(eh_data.swss_rc_table_full), delimiter="*")
        result = False

    tg_bgp_routes_advertise_withdraw(action='withdraw', af='both')
    st.wait(eh_data.max_route_install_wait_time)
    check_for_routes_in_device(eh_data.route_count_init_v4, 'ipv4', flag='e')
    check_for_routes_in_device(eh_data.route_count_init_v6, 'ipv6', flag='e')
    ehapi.clear_error_db(vars.D1, eh_data.error_route_table)
    report_result(result)


@pytest.mark.error_handling_ft
@pytest.mark.error_handling_ft_long_run
def test_ft_eh_rt_bgp_not_installed():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    st.banner('Test cases covered - ft_eh_rt_ebgp_neig_withdrawn, ft_eh_rt_ibgp_neig_withdrawn, '
                      'ft_eh_rt_show_ip_route_not_installed, ft_eh_rt_show_ipv6_route_sonic, '
                      'ft_eh_rt_show_ipv6_route_vtysh, ft_eh_rt_re_insatll_route, '
                      'ft_eh_rt_clear_ip_route_not_installed')

    result = True
    config_bgp_error_handling(config='yes')
    tg_bgp_routes_advertise_withdraw(action='readvertise', af='both')
    st.wait(eh_data.max_route_install_wait_time)

    st.banner("IPV4")

    st.log("Checking for 'show ip route not-installed'")
    if ehapi.eh_not_installed_route_options(vars.D1, mode='count_ipv4_route_sonic_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are not found in - show ip route not-installed ")
        result = False

    st.log("Checking for 'show ip route - sonic shell'")
    if ehapi.eh_not_installed_route_options(vars.D1, mode='count_ipv4_route_sonic_for_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are not found in - show ip route - sonic shell ")
        result = False

    st.log("Performing  'clear ip route not-installed' for re-install of routes")
    ehapi.eh_not_installed_route_options(vars.D1, mode='clear_ipv4_route_vtysh_not_installed', ifname_type=vars.config.ifname_type)

    st.log("Checking for 'show ip route not-installed' on Partner for route withdraw")
    if not ehapi.eh_not_installed_route_options(vars.D2, mode='count_ipv4_route_sonic_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are found in - show ip route not-installed ")
        result = False

    st.banner("IPV6")

    st.log("Checking for 'show ipv6 route not-installed'")
    if ehapi.eh_not_installed_route_options(vars.D1, mode='count_ipv6_route_sonic_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are not found in - show ipv6 route not-installed ")
        result = False

    st.log("Checking for 'show ipv6 route - sonic shell'")
    if ehapi.eh_not_installed_route_options(vars.D1, mode='count_ipv6_route_sonic_for_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are not found in - show ipv6 route - sonic shell ")
        result = False

    st.log("Performing  'clear ipv6 route not-installed' for re-install of routes")
    ehapi.eh_not_installed_route_options(vars.D1, mode='clear_ipv6_route_vtysh_not_installed', ifname_type=vars.config.ifname_type)

    st.log("Checking for 'show ipv6 route not-installed' on Partner for route withdraw")
    if not ehapi.eh_not_installed_route_options(vars.D2, mode='count_ipv6_route_sonic_not_installed', ifname_type=vars.config.ifname_type) == 0:
        st.error("Not Installed routes are found in - show ipv6 route not-installed ")
        result = False

    tg_bgp_routes_advertise_withdraw(action='withdraw', af='both')
    st.wait(eh_data.max_route_install_wait_time)
    check_for_routes_in_device(eh_data.route_count_init_v4, 'ipv4', flag='e')
    check_for_routes_in_device(eh_data.route_count_init_v6, 'ipv6', flag='e')
    config_bgp_error_handling(config='no')
    report_result(result)

