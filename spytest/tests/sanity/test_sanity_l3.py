import pytest

from spytest import SpyTestDict, st, tgapi

import apis.common.wait as waitapi
import apis.routing.ip as ipfeature
import apis.switching.vlan as vapi
import apis.switching.portchannel as portchannel_obj
import apis.routing.arp as arpapi

tg_info = dict()

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "24"
data.counters_threshold = 15
data.tgen_stats_threshold = 20
data.tgen_rate_pps = 1000
data.tgen_l3_len = 500
data.post_run_wait_time = 20
data.post_run_wait_time = 20
data.post_stop_wait_time = 5
data.post_clear_wait_time = 1
data.post_create_wait_time = 2
data.clear_parallel = True

data.d1t1_ip_addr = "192.168.11.1"
data.d1d2_ip_addr = "192.168.12.1"
data.d2d1_ip_addr = "192.168.12.2"
data.d2t1_ip_addr = "192.168.13.1"
data.t1d1_ip_addr = "192.168.11.2"
data.t1d2_ip_addr = "192.168.13.2"
data.static_ip_list = ["192.168.11.0/24", "192.168.13.0/24"]

data.d1t1_ip_addr_v6 = "2011::1"
data.d1d2_ip_addr_v6 = "2012::1"
data.d2d1_ip_addr_v6 = "2012::2"
data.d2t1_ip_addr_v6 = "2013::1"
data.static_ipv6_list = ["2011::/64", "2013::/64"]
data.mask_v6 = "64"


def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)


def cleanup_config():
    st.log("Cleanup IP/VLAN/PO configuration")
    ipfeature.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6', thread=data.clear_parallel)
    vapi.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel)


def config_dut1(dut1, config='yes'):
    if config == 'yes':
        st.banner('Configuring IPv4, IPv6 and Static routes', dut=dut1)
        ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr, data.mask)
        ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
        ipfeature.create_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
        ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
    else:
        st.banner('UnConfiguring IPv4, IPv6 and Static routes', dut=dut1)
        ipfeature.delete_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
        ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
        ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr, data.mask)
        ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
        ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6, data.mask_v6, family='ipv6')


def config_dut2(dut2, config='yes'):
    if config == 'yes':
        st.banner('Configuring IPv4, IPv6 and Static routes', dut=dut2)
        ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr, data.mask)
        ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr, data.mask)
        ipfeature.create_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
        ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.create_static_route(dut2, data.d1d2_ip_addr_v6, data.static_ipv6_list[0], family='ipv6')
    else:
        st.banner('UnConfiguring IPv4, IPv6 and Static routes', dut=dut2)
        ipfeature.delete_static_route(dut2, data.d1d2_ip_addr_v6, data.static_ipv6_list[0], family='ipv6')
        ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6, data.mask_v6, family='ipv6')
        ipfeature.delete_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
        ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr, data.mask)
        ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr, data.mask)


def pre_test_l3_fwding():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    config = 'yes'
    st.exec_all([[config_dut1, dut1, config], [config_dut2, dut2, config]])


def post_test_l3_fwding():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    config = 'no'
    st.exec_all([[config_dut1, dut1, config], [config_dut2, dut2, config]])
    vapi.show_vlan_config(dut1)


def tg_config():
    global tg1, tg_ph_1, tg_ph_2
    # L3 traffic streams
    (tg1, _, tg_ph_1, tg_ph_2) = get_handles()

    tg1.tg_traffic_control(action='reset', port_handle=[tg_ph_1, tg_ph_2])

    res = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
                                  gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: " + str(res))
    handle1 = res['handle']

    res = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,
                                  gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: " + str(res))
    handle2 = res['handle']

    rv = tg1.tg_traffic_config(port_handle=tg_ph_1, port_handle2=tg_ph_2, mode='create', transmit_mode='continuous',
                               length_mode='fixed',
                               l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle1,
                               emulation_dst_handle=handle2)
    tg_info['tg1_stream_id'] = rv['stream_id']
    rv_1 = tg1.tg_traffic_config(port_handle=tg_ph_2, port_handle2=tg_ph_1, mode='create', transmit_mode='continuous',
                                 length_mode='fixed',
                                 l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle2,
                                 emulation_dst_handle=handle1)
    tg_info['tg2_stream_id'] = rv_1['stream_id']


def ping(dut, addresses, family='ipv4', **kwargs):
    kwargs.setdefault("tgen", False)
    rv = ipfeature.ping(dut, addresses, family, **kwargs)
    if not rv:
        st.error("{} ping failed - checking with higher timeout for debug".format(family), dut=dut)
        kwargs["timeout"] = 10
        ipfeature.ping(dut, addresses, family, **kwargs)
    return rv


@pytest.fixture(scope="module", autouse=True)
def sanity_l3_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D1T1:1", "D2T1:1")
    data.tgen_rate_pps = tgapi.normalize_pps(data.tgen_rate_pps)
    cleanup_config()
    st.exec_all([[tg_config], [pre_test_l3_fwding]], True)
    result1 = lambda: ping(vars.D1, data.t1d1_ip_addr, tgen=True)
    result2 = lambda: ping(vars.D2, data.t1d2_ip_addr, tgen=True)
    st.exec_all([[result1], [result2]])
    if not result1 or not result2:
        st.error("IPv4 ping failed from TGEN ports")
        st.report_fail("msg", "IPv4 Ping Failed")
    yield
    post_test_l3_fwding()


@pytest.fixture(scope="function", autouse=True)
def sanity_l3_func_hooks(request):
    yield


@pytest.mark.base_test_sanity
@pytest.mark.inventory(feature='Sanity', release='Arlo+')
@pytest.mark.inventory(testcases=['l2_to_l3_port'])
def test_l2_to_l3_port():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    data.vlan = '10'
    data.vlan_int = 'Vlan' + '10'
    result_flag = 1
    ping_flag = 1

    # configure from L3 to L2 port
    vapi.create_vlan(dut1, data.vlan)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')

    st.vsonic_wait(30)

    ipfeature.config_ip_addr_interface(dut1, data.vlan_int, data.d1d2_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut1, data.vlan_int, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')

    vapi.add_vlan_member(dut1, data.vlan, vars.D1D2P1, False)
    if not vapi.verify_vlan_config(dut1, str(data.vlan), None, vars.D1D2P1):
        result_flag = 0

    st.vsonic_wait(30)

    result1 = ping(dut1, data.d2t1_ip_addr, tgen=True)
    if not result1:
        st.warn("1. Failed to ping {}".format(data.d2t1_ip_addr), dut=dut1)
        result_flag = 0
    result2 = ping(dut1, data.d2t1_ip_addr_v6, 'ipv6', tgen=True)
    if not result2:
        st.warn("2. Failed to ping {}".format(data.d2t1_ip_addr_v6), dut=dut1)
        result_flag = 0

    clear_arp = []
    clear_arp.append([arpapi.clear_arp_table, dut1])
    clear_arp.append([arpapi.clear_arp_table, dut2])
    st.exec_all(clear_arp)

    clear_ndp = []
    clear_ndp.append([arpapi.clear_ndp_table, dut1])
    clear_ndp.append([arpapi.clear_ndp_table, dut2])
    st.exec_all(clear_ndp)

    result1 = ping(dut2, data.d1d2_ip_addr)
    if not result1:
        st.warn("3. Failed to ping {}".format(data.d1d2_ip_addr), dut=dut2)
        result_flag = 0
    result2 = ping(dut2, data.d1d2_ip_addr_v6, 'ipv6')
    if not result2:
        st.warn("4. Failed to ping {}".format(data.d1d2_ip_addr_v6), dut=dut2)
        result_flag = 0

    # Revert back from L2 to L3 port
    vapi.delete_vlan_member(dut1, data.vlan, [vars.D1D2P1])
    ipfeature.delete_ip_interface(dut1, data.vlan_int, data.d1d2_ip_addr, data.mask)
    ipfeature.delete_ip_interface(dut1, data.vlan_int, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
    vapi.delete_vlan(dut1, [data.vlan])

    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')

    waitapi.vsonic_ip_apply(dut1)
    ping_result = ping(dut1, data.d2t1_ip_addr, tgen=True)
    if not ping_result:
        st.warn("5. Failed to ping {}".format(data.d2t1_ip_addr), dut=dut1)

    if ping_result and result_flag and ping_flag:
        st.report_pass("operation_successful")
    else:
        st.report_fail("failed_l2_to_l3_port")
