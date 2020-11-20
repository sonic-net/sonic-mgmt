# Error Handling FT test cases.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.routing.arp as arpapi
import apis.system.basic as bsapi
import apis.switching.vlan as vapi
import apis.common.asic_bcm as asicapi
import apis.system.error_handling as ehapi
import apis.system.logging as logapi

from utilities import common as utils
from utilities.utils import list_filter_and_select
import utilities.utils as cutils

@pytest.fixture(scope="module", autouse=True)
def error_handling_module_hooks(request):
    global_vars_and_constants_init()
    error_handling_module_config(config='yes')
    ehapi.eh_bcm_debug_show(vars.D1, af='both', table_type='all', ifname_type=vars.config.ifname_type)
    yield
    error_handling_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def error_handling_func_hooks(request):
    ehapi.clear_error_db(vars.D1)
    yield


def global_vars_and_constants_init():
    global eh_data, vars, intf_d1d2p1, intf_d2d1p1
    eh_data = SpyTestDict()
    vars = st.ensure_min_topology('D1D2:1')
    eh_data.platform = bsapi.get_hwsku(vars.D1).lower()
    hw_constants = st.get_datastore(vars.D1, "constants", eh_data.platform)
    if not hw_constants:
        hw_constants = st.get_datastore(vars.D1, "constants")
    # Flags
    eh_data.thread_mode = True
    eh_data.ping_delay = 5
    eh_data.ping_retry = 1
    eh_data.output_poll = 30
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
    eh_data.egr_intf = '132769' if eh_data.platform in hw_constants['TD3_PLATFORMS'] else '100002'
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
    eh_data.ipv4_max_routes = hw_constants['MAX_IPV4_ROUTES_SUPPORTED']
    st.log("MAX_IPV4_ROUTES_SUPPORTED: {}".format(eh_data.ipv4_max_routes))
    eh_data.ipv6_max_routes = hw_constants['MAX_IPV6_ROUTES_SUPPORTED']
    st.log("MAX_IPV6_ROUTES_SUPPORTED: {}".format(eh_data.ipv6_max_routes))
    eh_data.cli_type = st.get_ui_type(vars.D1)
    intf_d1d2p1 = vars.D1D2P1
    intf_d2d1p1 = vars.D2D1P1
    if eh_data.cli_type == "klish":
        if vars.config.ifname_type == "alias":
            intf_d1d2p1 = st.get_other_names(vars.D1, [vars.D1D2P1])[0]
            intf_d2d1p1 = st.get_other_names(vars.D2, [vars.D2D1P1])[0]


def error_handling_module_config(config='yes'):
    config_ip_topology(config)
    config_ip_loopback(config)
    config_bgp_route_map(config)
    config_bgp_topology(config)
    config_bgp_error_handling(config)


def full_cleanup():
    bgpapi.cleanup_router_bgp(st.get_dut_names())
    ipapi.clear_ip_configuration(st.get_dut_names(), thread=eh_data.thread_mode, family='all')
    vapi.clear_vlan_configuration(st.get_dut_names(), thread=eh_data.thread_mode)


def thread_call(thread_info):
    [out, exceptions] = utils.exec_all(eh_data.thread_mode, thread_info)
    st.log([out, exceptions])


def config_tg_ip_bgp_stream_error_handling(config='yes'):
    ip_config = 'add' if config == 'yes' else 'remove'
    tg_dut_ip_bgp_config(config=ip_config)
    if config == 'yes':
        get_tg_parameters()
    tg_tg_ip_bgp_config(tg, tg_ph_list, config=config)
    if config == 'yes':
        tg_tg_bgp_routes_add()


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
    cutils.banner_log("{}Config IP Addresses and BGP on TG connected interfaces".
                      format('Un' if config != 'add' else ''))
    # IPv4
    ipapi.config_ip_addr_interface(dut=vars.D1, interface_name=vars.D1T1P1,
                                   ip_address=eh_data.tg1_ipv4_addr, subnet=eh_data.tg1_ipv4_mask_len, family="ipv4",
                                   config=config)
    if config == 'add':
        bgpapi.config_bgp_multi_neigh_use_peergroup(vars.D1, local_asn=eh_data.local_asn,
                                                    peer_grp_name=eh_data.tg_peer_gp_namev4,
                                                    remote_asn=eh_data.tg_remote_asn,
                                                    neigh_ip_list=eh_data.tg1_ipv4_nbr, family='ipv4', activate=1)
    # IPv6
    ipapi.config_ip_addr_interface(dut=vars.D1, interface_name=vars.D1T1P1,
                                   ip_address=eh_data.tg1_ipv6_addr, subnet=eh_data.tg1_ipv6_mask_len, family="ipv6",
                                   config=config)
    if config == 'add':
        bgpapi.config_bgp_multi_neigh_use_peergroup(vars.D1, local_asn=eh_data.local_asn,
                                                    peer_grp_name=eh_data.tg_peer_gp_namev6,
                                                    remote_asn=eh_data.tg_remote_asn,
                                                    neigh_ip_list=eh_data.tg1_ipv6_nbr, family='ipv6', activate=1)


def tg_tg_ip_bgp_config(tg_obj, tg_ph_li, config='yes'):
    cutils.banner_log("{}Config IP Addresses and BGP on TG interfaces".format('Un' if config != 'yes' else ''))
    if config == 'yes':
        cutils.banner_log("IPv4 Addresses and BGP on TG interfaces", delimiter='*')
        tg_data['ipv4_h1'] = tg_obj.tg_interface_config(port_handle=tg_ph_li[0], mode='config',
                                                        intf_ip_addr=eh_data.tg1_ipv4_nbr,
                                                        gateway=eh_data.tg1_ipv4_addr,
                                                        netmask=eh_data.tg1_ipv4_mask, arp_send_req='1')
        st.log('ipv4_h1 : {}'.format(tg_data['ipv4_h1']))
        tg_data['bgp4_rtr1'] = tg_obj.tg_emulation_bgp_config(handle=tg_data['ipv4_h1']['handle'], mode='enable',
                                                              active_connect_enable='1',
                                                              local_as=eh_data.tg_remote_asn,
                                                              remote_as=eh_data.local_asn,
                                                              remote_ip_addr=eh_data.tg1_ipv4_addr)
        st.log('bgp4_rtr1 : {}'.format(tg_data['bgp4_rtr1']))

        cutils.banner_log("IPv6 Addresses and BGP on TG interfaces", delimiter='*')
        tg_data['ipv6_h1'] = tg_obj.tg_interface_config(port_handle=tg_ph_li[0], mode='config',
                                                        ipv6_intf_addr=eh_data.tg1_ipv6_nbr,
                                                        ipv6_prefix_length=eh_data.tg1_ipv6_mask_len,
                                                        ipv6_gateway=eh_data.tg1_ipv6_addr, arp_send_req='1')
        st.log('ipv6_h1 : {}'.format(tg_data['ipv6_h1']))
        tg_data['bgp6_rtr1'] = tg_obj.tg_emulation_bgp_config(handle=tg_data['ipv6_h1']['handle'], mode='enable',
                                                              ip_version='6', active_connect_enable='1',
                                                              local_as=eh_data.tg_remote_asn,
                                                              remote_as=eh_data.local_asn,
                                                              remote_ipv6_addr=eh_data.tg1_ipv6_addr)
        st.log('bgp6_rtr1 : {}'.format(tg_data['bgp6_rtr1']))

    else:
        start_stop_bgp_routes_from_tg(action='stop', af='both')
        tg_obj.tg_interface_config(port_handle=tg_ph_li[0], handle=tg_data['ipv4_h1']['handle'], mode='destroy')
        tg_obj.tg_interface_config(port_handle=tg_ph_li[0], handle=tg_data['ipv6_h1']['handle'], mode='destroy')


def tg_tg_bgp_routes_add():
    cutils.banner_log("Adding and Advertising BGP Routes from TG")
    tg.tg_emulation_bgp_route_config(handle=tg_data['bgp4_rtr1']['handle'], mode='add',
                                     num_routes=eh_data.ipv4_max_routes, prefix='121.1.1.0', as_path='as_seq:1')
    tg.tg_emulation_bgp_route_config(handle=tg_data['bgp6_rtr1']['handle'], mode='add',
                                     num_routes=eh_data.ipv6_max_routes, prefix='6002:1::0', as_path='as_seq:1',
                                     ip_version='6')
    start_stop_bgp_routes_from_tg(action='stop', af='both')


def start_stop_bgp_routes_from_tg(action='start', af='ipv4'):
    if af in 'ipv4' or af == 'both':
        tg.tg_emulation_bgp_control(handle=tg_data['bgp4_rtr1']['handle'], mode=action)
    if af in 'ipv6' or af == 'both':
        tg.tg_emulation_bgp_control(handle=tg_data['bgp6_rtr1']['handle'], mode=action)


def config_ip_topology(config='yes'):
    cutils.banner_log("{}Config IP Addresses on interfaces".format('Un' if config != 'yes' else ''))
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
    cutils.banner_log("{}Config Loopback Addresses on interfaces on D2".format('Un' if config != 'yes' else ''))
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
    cutils.banner_log("{}Config BGP Route Map".format('Un' if config != 'yes' else ''))
    thread_info = list()
    thread_info.append(utils.ExecAllFunc(ipapi.config_route_map_global_nexthop, vars.D1,
                                         route_map=eh_data.route_map_name,
                                         sequence='10', config=config))
    thread_info.append(utils.ExecAllFunc(ipapi.config_route_map_global_nexthop, vars.D2,
                                         route_map=eh_data.route_map_name,
                                         sequence='10', config=config))
    thread_call(thread_info)


def config_bgp_topology(config='yes'):
    cutils.banner_log("{}Config BGP on devices".format('Un' if config != 'yes' else ''))
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
            if not utils.poll_wait(bgpapi.verify_bgp_summary, 30,vars.D1, family='ipv4',
                                   neighbor=[eh_data.ipv4_nbr], state='Established'):
                st.error("BGP Neighbor failed to Establish between DUT and Partner")
                st.report_fail('operation_failed')
            if not utils.poll_wait(bgpapi.verify_bgp_summary, 30,vars.D1, family='ipv6',
                                   neighbor=[eh_data.ipv6_nbr], state='Established'):
                st.error("BGP Neighbor failed to Establish between DUT and Partner")
                st.report_fail('operation_failed')
    else:
        bgpapi.cleanup_router_bgp(st.get_dut_names())


def config_bgp_error_handling(config='yes'):
    cutils.banner_log("{}Config BGP error handling".format('Un' if config != 'yes' else ''))
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


def config_nbr2(action):
    if action == "add":
        arpapi.add_static_arp(vars.D1, eh_data.ipv4_nbr2, eh_data.ipv4_nbr2_mac, interface=intf_d1d2p1)
        arpapi.config_static_ndp(vars.D1, eh_data.ipv6_nbr2, eh_data.ipv6_nbr2_mac, intf_d1d2p1, operation="add")
    elif action == "delete":
        arpapi.delete_static_arp(vars.D1, eh_data.ipv4_nbr2, interface=intf_d1d2p1, mac=eh_data.ipv4_nbr2_mac)
        arpapi.config_static_ndp(vars.D1, eh_data.ipv6_nbr2, eh_data.ipv6_nbr2_mac, intf_d1d2p1, operation="del")


def config_nbr3(action):
    if action == "add":
        arpapi.add_static_arp(vars.D1, eh_data.ipv4_nbr3, eh_data.ipv4_nbr3_mac, interface=intf_d1d2p1)
        arpapi.config_static_ndp(vars.D1, eh_data.ipv6_nbr3, eh_data.ipv6_nbr3_mac, intf_d1d2p1, operation="add")
    elif action == "delete":
        arpapi.delete_static_arp(vars.D1, eh_data.ipv4_nbr3, interface=intf_d1d2p1, mac=eh_data.ipv4_nbr3_mac)
        arpapi.config_static_ndp(vars.D1, eh_data.ipv6_nbr3, eh_data.ipv6_nbr3_mac, intf_d1d2p1, operation="del")


def config_nbr2_bcm(action):
    bcm_nbr_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv4_nbr2, intf=eh_data.egr_intf, af=eh_data.af_ipv4,
                   action=action)
    bcm_nbr_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv6_nbr2, intf=eh_data.egr_intf, af=eh_data.af_ipv6,
                   action=action)


def config_nbr3_bcm(action):
    bcm_nbr_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv4_nbr3, intf=eh_data.egr_intf, af=eh_data.af_ipv4,
                   action=action)
    bcm_nbr_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv6_nbr3, intf=eh_data.egr_intf, af=eh_data.af_ipv6,
                   action=action)


def config_route(action):
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.ipv4_route, eh_data.ipv4_mask_len),
                                   nhp=eh_data.ipv4_nbr, family=eh_data.af_ipv4, action=action)
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.ipv6_route, eh_data.ipv6_mask_len),
                                   nhp=eh_data.ipv6_nbr, family=eh_data.af_ipv6, action=action)


def config_route2(action):
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.ipv4_route2, eh_data.ipv4_mask_len),
                                   nhp=eh_data.ipv4_nbr, family=eh_data.af_ipv4, action=action)
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.ipv6_route2, eh_data.ipv6_mask_len),
                                   nhp=eh_data.ipv6_nbr, family=eh_data.af_ipv6, action=action)


def config_loopback_route(action):
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.loopback4_1, '32'),
                                   nhp=eh_data.ipv4_nbr, family=eh_data.af_ipv4, action=action)
   ipapi.config_linux_static_route(vars.D1, route="{}/{}".format(eh_data.loopback6_1, '128'),
                                   nhp=eh_data.ipv6_nbr, family=eh_data.af_ipv6, action=action)


def config_route_bcm(action):
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv4_route, mask=eh_data.ipv4_mask,
                     masklen=eh_data.ipv4_mask_len,intf=eh_data.egr_intf, af=eh_data.af_ipv4, action=action)
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv6_route, mask=None, masklen=eh_data.ipv6_mask_len,
                     intf=eh_data.egr_intf, af=eh_data.af_ipv6, action=action)


def config_route2_bcm(action):
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv4_route2, mask=eh_data.ipv4_mask,
                     masklen=eh_data.ipv4_mask_len, intf=eh_data.egr_intf, af=eh_data.af_ipv4, action=action)
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.ipv6_route2, mask=None, masklen=eh_data.ipv6_mask_len,
                     intf=eh_data.egr_intf, af=eh_data.af_ipv6, action=action)


def config_loopback_route_bcm(action):
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.loopback4_1, mask='255.255.255.255', masklen='32',
                     intf=eh_data.egr_intf, af=eh_data.af_ipv4, action=action)
    bcm_route_config(vars.D1, vrf=eh_data.vrf, ip=eh_data.loopback6_1, mask=None, masklen='128',
                     intf=eh_data.egr_intf, af=eh_data.af_ipv6, action=action)


def get_bcmcmd_route_intf(dut, match, items, af='ipv4'):
    intf = None
    if af == 'ipv4':
        intf = asicapi.bcmcmd_l3_defip_show(dut, match, items)
    elif af == 'ipv6':
        intf = asicapi.bcmcmd_l3_ip6route_show(dut, match, items)

    if intf:
        return intf[0]['intf']
    else:
        st.error("Unable to find the 'intf' of match : {}".format(match))
        report_result(0)


def bcm_route_config(dut, vrf, ip, mask, masklen, intf, af, action, verify=False):
    st.log(" Create an {} route {} on interface {} on dut {} using bcmcmd".format(af, ip, intf, dut))
    command = ''
    if af == "ipv4":
        eh_data.mask = mask
        command = "l3_defip_show"
        if action == "delete":
            intf = get_bcmcmd_route_intf(vars.D1, {'route': ip, 'mask_len': str(masklen)}, ['intf'], af=af)
            st.log("IP {} - intf {}".format(ip, intf))
    elif af == "ipv6":
        eh_data.mask = masklen
        command = "l3_ip6route_show"
        if action == "delete":
            intf = get_bcmcmd_route_intf(vars.D1, {'route': ip, 'mask_len': str(masklen)}, ['intf'], af=af)
            st.log("IP {} - intf {}".format(ip, intf))
    else:
        st.log("Invalid family type")
        st.report_fail('failed_to_create_bcm_route', af, ip)

    asicapi.bcmcmd_route_config(dut, vrf=vrf, ip=ip, mask=eh_data.mask, intf=intf, af=af, action=action)

    if verify:
        st.log("Verify {} operation for bcm route entry {}".format(action, ip))
        if action == "add":
            if not asicapi.verify_bcmcmd_routing_output(dut, command, destination=ip, egr_intf=intf):
                st.report_fail('failed_to_create_bcm_route', af, ip)
        elif action == "delete":
            if asicapi.verify_bcmcmd_routing_output(dut, command, destination=ip, egr_intf=intf):
                st.report_fail('failed_to_create_bcm_route', af, ip)


def bcm_nbr_config(dut, vrf, ip, intf, af, action, verify=False):
    st.log(" Create an {} Neighbor {} on interface {} on dut {} using bcmcmd".format(af, ip, intf, dut))
    command = ''
    if af == "ipv4":
        command = "l3_l3table_show"
    elif af == "ipv6":
        command = "l3_ip6host_show"
    else:
        st.log("Invalid family type")
        st.report_fail('failed_to_create_bcm_nbr', af, ip)
    asicapi.bcmcmd_nbr_config(dut, ip=ip, intf=intf, af=af, action=action)

    if verify:
        st.log("Verify {} operation for bcm Neighbor entry {}".format(action, ip))
        if action == "add":
            if not asicapi.verify_bcmcmd_routing_output(dut, command, nhip=ip, egr_intf=intf):
                st.report_fail('failed_to_create_bcm_nbr', af, ip)
        elif action == "delete":
            if asicapi.verify_bcmcmd_routing_output(dut, command, nhip=ip, egr_intf=intf):
                st.report_fail('failed_to_create_bcm_nbr', af, ip)


def report_result(status):
    if status:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')


@pytest.mark.error_handling_ft
def test_ft_eh_nt_notify():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    cutils.banner_log('Test cases covered - '
                      'ft_eh_nt_noty_not_found, ft_eh_nt_noty_parms_check, '
                      'ft_eh_clear_error_database, ft_eh_error_creat_delete')

    result = True
    st.log("Create a ipv4 and ipv6 Neighbor from CLI")
    config_nbr2("add")
    config_nbr3("add")
    ehapi.eh_bcm_debug_show(vars.D1, af='both', table_type='nbr', ifname_type=vars.config.ifname_type)

    st.log("Check no entry added to error DB for {} condition".format(eh_data.swss_rc_success))
    entry1 = {'nexthop': eh_data.ipv4_nbr2, 'interface': intf_d1d2p1}
    entry2 = {'nexthop': eh_data.ipv6_nbr2, 'interface': intf_d1d2p1}
    entry3 = {'nexthop': eh_data.ipv4_nbr3, 'interface': intf_d1d2p1}
    entry4 = {'nexthop': eh_data.ipv6_nbr3, 'interface': intf_d1d2p1}
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry1, entry2, entry3, entry4, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_success), delimiter="*")
        result = False

    st.log("Now delete the Neighbor from bcmshell")
    """
    SDK ISSUE: CSP : CS8958084 :
    In Accton-AS7326-56X - 'l3 ip6host destroy' is not working hence using 'l3 ip6host clear' as work around.

    Below code need to revert once the SDK issue resolve.
    config_nbr2_bcm("delete")
    config_nbr3_bcm("delete")
    """
    config_nbr2_bcm("clear")
    config_nbr3_bcm("clear")
    ehapi.eh_bcm_debug_show(vars.D1, af='both', table_type='nbr', ifname_type=vars.config.ifname_type)
    st.log("Now try deleting the same neighbor from CLI")
    config_nbr2("delete")
    config_nbr3("delete")
    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_not_found))
    entry1 = {'nexthop': eh_data.ipv4_nbr2, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_not_found,
              'operation': "remove"}
    entry2 = {'nexthop': eh_data.ipv6_nbr2, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_not_found,
              'operation': "remove"}
    entry3 = {'nexthop': eh_data.ipv4_nbr3, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_not_found,
              'operation': "remove"}
    entry4 = {'nexthop': eh_data.ipv6_nbr3, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_not_found,
              'operation': "remove"}
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry1, entry2, entry3, entry4, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_not_found), delimiter="*")
        result = False

    st.log("Now create the same Neighbor from CLI the entry from error db should go away on successful addition")
    config_nbr2("add")
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry1, entry2, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format("Entry Go Away"), delimiter="*")
        result = False

    st.log("Check if the other failed entries are still remaining")
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry3, entry4, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format("Other Entry"), delimiter="*")
        result = False

    st.log("Clear error database for '{}'".format(eh_data.error_neigh_table))
    ehapi.clear_error_db(vars.D1, eh_data.error_neigh_table)
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry3, entry4, result=False, ifname_type=vars.config.ifname_type):
        st.error("Post clear error db - entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format("Clear Command"), delimiter="*")
        result = False

    config_nbr2("delete")
    report_result(result)


@pytest.mark.error_handling_ft
def test_ft_eh_rt_notify():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    cutils.banner_log('Test cases covered - '
                      'ft_eh_rt_noty_entry_exist, ft_eh_rt_noty_parms_check,'
                      ' ft_eh_clear_error_database, ft_eh_error_creat_delete')

    result = True
    st.log("Create ipv4/ipv6 route from cli")
    config_route("add")
    config_route2("add")

    ehapi.eh_bcm_debug_show(vars.D1, af='both', table_type='route', ifname_type=vars.config.ifname_type)

    st.log("Check no entry added to error DB for {} condition".format(eh_data.swss_rc_success))
    entry1 = {'route': eh_data.ipv4_route, 'subnet': eh_data.ipv4_mask_len, 'nexthop': eh_data.ipv4_nbr,
              'interface': intf_d1d2p1}
    entry2 = {'route': eh_data.ipv6_route_sf, 'subnet': eh_data.ipv6_mask_len, 'nexthop': eh_data.ipv6_nbr,
              'interface': intf_d1d2p1}
    entry3 = {'route': eh_data.ipv4_route2, 'subnet': eh_data.ipv4_mask_len, 'nexthop': eh_data.ipv4_nbr,
              'interface': intf_d1d2p1}
    entry4 = {'route': eh_data.ipv6_route2_sf, 'subnet': eh_data.ipv6_mask_len, 'nexthop': eh_data.ipv6_nbr,
              'interface': intf_d1d2p1}

    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, entry3, entry4, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_success), delimiter="*")
        result = False

    st.log("Now delete the route from bcm shell")
    config_route_bcm("delete")
    config_route2_bcm("delete")

    st.log("Delete same ipv4/ipv6 route from cli")
    config_route("delete")
    config_route2("delete")

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_not_found))
    entry1 = {'route': eh_data.ipv4_route, 'subnet': eh_data.ipv4_mask_len,
              'failure': eh_data.swss_rc_not_found, 'operation': 'remove'}
    entry2 = {'route': eh_data.ipv6_route_sf, 'subnet': eh_data.ipv6_mask_len,
              'failure': eh_data.swss_rc_not_found, 'operation': 'remove'}
    entry3 = {'route': eh_data.ipv4_route2, 'subnet': eh_data.ipv4_mask_len,
              'failure': eh_data.swss_rc_not_found, 'operation': 'remove'}
    entry4 = {'route': eh_data.ipv6_route2_sf, 'subnet': eh_data.ipv6_mask_len,
              'failure': eh_data.swss_rc_not_found, 'operation': 'remove'}

    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, entry3, entry4, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_not_found), delimiter="*")
        result = False

    st.log("Create ipv4/ipv6 route from bcmshell")
    config_route_bcm("add")
    config_route2_bcm("add")

    # Create the same static route from cli
    st.log("Create the same ipv4/ipv6 route from cli")
    config_route("add")
    config_route2("add")

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_exists))
    entry1 = {'route': eh_data.ipv4_route, 'subnet': eh_data.ipv4_mask_len, 'nexthop': eh_data.ipv4_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    entry2 = {'route': eh_data.ipv6_route_sf, 'subnet': eh_data.ipv6_mask_len, 'nexthop': eh_data.ipv6_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    entry3 = {'route': eh_data.ipv4_route2, 'subnet': eh_data.ipv4_mask_len, 'nexthop': eh_data.ipv4_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    entry4 = {'route': eh_data.ipv6_route2_sf, 'subnet': eh_data.ipv6_mask_len, 'nexthop': eh_data.ipv6_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}

    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, entry3, entry4, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_exists), delimiter="*")
        result = False

    st.log("Now deleting the same routes from CLI the entry from error db should go away on successful deletion")
    config_route2("delete")
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry3, entry4, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format('Entry Go Away'), delimiter="*")
        result = False

    st.log("Check if the other failed entries are still remaining")
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format('Other Entry'), delimiter="*")
        result = False

    st.log("Clear error database for '{}'".format(eh_data.error_route_table))
    ehapi.clear_error_db(vars.D1, eh_data.error_route_table)
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, result=False, ifname_type=vars.config.ifname_type):
        st.error("Post clear error db - entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format('Clear Command'), delimiter="*")
        result = False

    config_route("delete")
    report_result(result)


@pytest.mark.error_handling_ft
def test_ft_eh_bgp_route_notify():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    cutils.banner_log('Test cases covered - ft_eh_bgp_route_notify')
    result = True
    st.log("Setting components severity to INFO")
    logapi.set_logging_severity(vars.D1, severity="INFO", comp=['orchagent', 'fpmsyncd'])
    st.log("Create to be advertise BGP route from bcmshell")
    config_loopback_route_bcm('add')
    st.log("Now Advertise the same routes from neighbor to hit entry_exists condition")
    config_bgp_redistribute('yes')
    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_exists))
    entry1 = {'route': eh_data.loopback4_1, 'subnet': '32', 'nexthop': eh_data.ipv4_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    entry2 = {'route': eh_data.loopback6_1, 'subnet': '128',
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_exists), delimiter="*")
        result = False

    log_out = logapi.show_logging(vars.D1, lines=200)
    st.log("Checking for Error handling notification")
    log_msg1 = len(list_filter_and_select(log_out, filter_list=[eh_data.log_str_swss, eh_data.loopback4_1, intf_d1d2p1,
                                                                eh_data.swss_rc_exists]))
    log_msg2 = len(list_filter_and_select(log_out, filter_list=[eh_data.log_str_swss, eh_data.loopback6_1, intf_d1d2p1,
                                                                eh_data.swss_rc_exists]))
    log_msg3 = len(list_filter_and_select(log_out, filter_list=[eh_data.log_str_bgp, eh_data.loopback4_1, 'create']))
    log_msg4 = len(list_filter_and_select(log_out, filter_list=[eh_data.log_str_bgp, eh_data.loopback6_1, 'create']))

    if not (log_msg1 and log_msg2 and log_msg3 and log_msg4):
        st.error("Failed to recv notification logs")
        result = False

    logapi.set_logging_severity(vars.D1, severity="ERROR", comp=['orchagent', 'fpmsyncd'])
    ehapi.clear_error_db(vars.D1, eh_data.error_route_table)
    report_result(result)


@pytest.mark.error_handling_ft
def test_ft_eh_rt_bgp_plus_static_routes():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    cutils.banner_log('Test cases covered - ft_eh_rt_bgp_plus_static_routes ')
    result = True

    ehapi.eh_bcm_debug_show(vars.D1, af='both', table_type='route', ifname_type=vars.config.ifname_type)
    ipapi.show_ip_route(vars.D1, family=eh_data.af_ipv4)
    ipapi.show_ip_route(vars.D1, family=eh_data.af_ipv6)

    st.log("Enabling connected route re-distribute in BGP peer")
    config_bgp_redistribute('yes')
    if not ipapi.verify_ip_route(vars.D1, family=eh_data.af_ipv4, shell=eh_data.shell_sonic,
                                 ip_address=eh_data.loopback4_1+"/32"):
        st.error("Failed install BGP route")
        result = False
    if not ipapi.verify_ip_route(vars.D1, family=eh_data.af_ipv6, shell=eh_data.shell_sonic,
                                 ip_address=eh_data.loopback6_1+"/128"):
        st.error("Failed install BGP route")
        result = False

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_success))
    entry1 = {'route': eh_data.loopback4_1, 'subnet': '32', 'interface': intf_d1d2p1}
    entry2 = {'route': eh_data.loopback6_1, 'subnet': '128', 'interface': intf_d1d2p1}
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_success), delimiter="*")
        result = False

    st.log("Trying to add same ipv4/ipv6 BGP route from cli")
    config_loopback_route('add')

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_exists))
    entry1 = {'route': eh_data.loopback4_1, 'subnet': '32', 'nexthop': eh_data.ipv4_nbr,
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}
    entry2 = {'route': eh_data.loopback6_1, 'subnet': '128',
              'failure': eh_data.swss_rc_exists, 'interface': intf_d1d2p1, 'operation': 'create'}

    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, entry1, entry2, result=False, ifname_type=vars.config.ifname_type):
        st.error("entry_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_exists), delimiter="*")
        result = False

    config_bgp_redistribute('no')
    config_loopback_route('delete')
    report_result(result)


@pytest.mark.error_handling_ft
def test_ft_eh_redis_cli():
    cutils.banner_log('Test cases covered - ft_eh_show_redis, ft_eh_clear_redis')
    result = True
    st.log("Create a ipv4 and ipv6 Neighbor from CLI")
    config_nbr2("add")
    st.log("Now delete the Neighbor from bcmshell")

    """
    SDK ISSUE: CSP : CS8958084 :
    In Accton-AS7326-56X - 'l3 ip6host destroy' is not working hence using 'l3 ip6host clear' as work around.

    Below code need to revert once the SDK issue resolve.
    config_nbr2_bcm("delete")
    """
    config_nbr2_bcm("clear")

    st.log("Now try deleting the same neighbor from CLI")
    config_nbr2("delete")

    ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, iteration=1, ifname_type=vars.config.ifname_type)
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_neigh_table, nhp=eh_data.ipv4_nbr2, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_not_found, opcode='remove'):
        st.error("REDIS: entry_found_not_in_error_db for {} ".format(eh_data.error_neigh_table))
        result = False
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_neigh_table, nhp=eh_data.ipv6_nbr2, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_not_found, opcode='remove'):
        st.error("REDIS: entry_found_not_in_error_db for {} ".format(eh_data.error_neigh_table))
        result = False

    st.log("Create ipv4/ipv6 route from bcmshell")
    config_route_bcm("add")
    st.log("Create the same ipv4/ipv6 route from cli")
    config_route("add")
    ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, iteration=1, ifname_type=vars.config.ifname_type)
    st.log(" Check if the failed ipv4 route entry got populated in error db")
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_route_table, mask=eh_data.ipv4_mask_len,
                                       route=eh_data.ipv4_route, nhp=eh_data.ipv4_nbr, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_exists, opcode="create"):
        st.error("REDIS: entry_found_not_in_error_db for {} ".format(eh_data.error_route_table))
        result = False
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_route_table, mask=eh_data.ipv6_mask_len,
                                       route=eh_data.ipv6_route_sf, nhp=eh_data.ipv6_nbr, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_exists, opcode="create"):
        st.error("REDIS: entry_found_not_in_error_db for {} ".format(eh_data.error_route_table))
        result = False

    st.log("Now clear the entries from error db - {}".format(eh_data.error_neigh_table))
    ehapi.clear_error_db(vars.D1, eh_data.error_neigh_table)

    ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_route_table, iteration=1, ifname_type=vars.config.ifname_type)
    st.log(" Check if the failed ipv4 route entry got populated in error db")
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_route_table, mask=eh_data.ipv4_mask_len,
                                       route=eh_data.ipv4_route, nhp=eh_data.ipv4_nbr, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_exists, opcode="create"):
        st.error("REDIS Post Clear: entry_found_not_in_error_db for {} ".format(eh_data.error_route_table))
        result = False
    if not ehapi.verify_error_db_redis(vars.D1, eh_data.error_route_table, mask=eh_data.ipv6_mask_len,
                                       route=eh_data.ipv6_route_sf, nhp=eh_data.ipv6_nbr, ifname=intf_d1d2p1,
                                       rc=eh_data.swss_rc_exists, opcode="create"):
        st.error("REDIS Post Clear: entry_found_not_in_error_db for {} ".format(eh_data.error_route_table))
        result = False

    st.log("Now clear the entries from error db - {}".format(eh_data.error_route_table))
    ehapi.clear_error_db(vars.D1, eh_data.error_route_table)

    st.log("Verify that there are no entries in error db")
    if ehapi.get_num_entries_error_db(vars.D1, ifname_type=vars.config.ifname_type) != 0:
        st.error("REDIS Post Clear: entry_found_in_error_db")
        result = False

    config_route_bcm("delete")
    config_route("delete")
    report_result(result)


@pytest.mark.error_handling_ft
def test_ft_eh_nt_notify_table_full():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    cutils.banner_log('Test cases covered - ft_eh_nt_notify_table_full')
    result = True
    st.log(" Set the all the entries in l3_entry_only table to valid to simulate {}".format(eh_data.swss_rc_table_full))
    if not asicapi.bcmcmd_l3_entry_only_config(vars.D1, action="add"):
        result = False
    st.log("Running this test case with native interface name as we dont have support for neighbor creation in KLISH")
    st.log("Create a ipv4 and ipv6 Neighbor from CLI")
    config_nbr2("add")

    st.log("Check if entry got added to error DB for {} condition".format(eh_data.swss_rc_table_full))
    entry1 = {'nexthop': eh_data.ipv4_nbr2, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_table_full,
              'operation': "create"}
    entry2 = {'nexthop': eh_data.ipv6_nbr2, 'interface': intf_d1d2p1, 'failure': eh_data.swss_rc_table_full,
              'operation': "create"}
    #Hardcoded the cli type as click as the support to add/replace the neighbor is not availalbe in klish.
    if not ehapi.verify_show_error_db_multi(vars.D1, eh_data.error_neigh_table, entry1, entry2, ifname_type=vars.config.ifname_type):
        st.error("entry_not_found_in_error_db")
        cutils.banner_log('{} - Test Validation Failed '.format(eh_data.swss_rc_table_full), delimiter="*")
        result = False

    st.log("Now reset all the entries in l3 entry table")
    asicapi.bcmcmd_l3_entry_only_config(vars.D1, action="delete")

    config_nbr2("delete")
    report_result(result)