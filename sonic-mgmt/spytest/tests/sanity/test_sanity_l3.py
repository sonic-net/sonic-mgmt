import pytest
from spytest import st, tgapi, SpyTestDict

import apis.common.wait as waitapi
import apis.routing.ip as ipfeature
import apis.switching.vlan as vapi
import apis.switching.portchannel as portchannel_obj
import apis.system.basic as basic_obj
import apis.routing.bgp as bgpapi

tg_info = dict()

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = 1000
data.tgen_l3_len = 500
data.post_run_wait_time = 20
data.post_run_wait_time = 20
data.post_stop_wait_time = 5
data.post_clear_wait_time = 1
data.post_create_wait_time = 2
data.clear_parallel = True
data.port_channel = "PortChannel100"
data.loopback_d1 = "Loopback11"
data.loopback_d2 = "Loopback12"
data.dut1_as = "65100"
data.dut2_as = "65200"

data.d1t1_ip_addr = "192.168.11.1"
data.d1d2_ip_addr = "192.168.12.1"
data.d2d1_ip_addr = "192.168.12.2"
data.d2t1_ip_addr = "192.168.13.1"
data.t1d1_ip_addr = "192.168.11.2"
data.t1d2_ip_addr = "192.168.13.2"
data.loopback_d1_addr = "192.168.14.1"
data.loopback_d2_addr = "192.168.15.1"
data.static_ip_list = ["192.168.11.0/24","192.168.13.0/24", "192.168.14.0/24","192.168.15.0/24"]

data.d1t1_ip_addr_v6 = "2011::1"
data.d1d2_ip_addr_v6 = "2012::1"
data.d2d1_ip_addr_v6 = "2012::2"
data.d2t1_ip_addr_v6 = "2013::1"
data.loopback_d1_addr_v6 = "2014::1"
data.loopback_d2_addr_v6 = "2015::1"
data.static_ipv6_list = ["2011::0/64","2013::0/64","2014::0/64","2015::0/64"]
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



@pytest.fixture(scope="module", autouse=True)
def sanity_l3_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D1T1:1", "D2T1:1")
    st.log("POST TEST : Cleanup call are started..")
    ipfeature.clear_ip_configuration(st.get_dut_names(),thread= data.clear_parallel)
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6',thread= data.clear_parallel)
    vapi.clear_vlan_configuration(st.get_dut_names(),thread= data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(),thread= data.clear_parallel)
    pre_test_l3_fwding()
    yield
    post_test_l3_fwding()
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case

@pytest.mark.base_test_sanity
def test_l3_fwding():
    #pre_test_l3_fwding()
    data.my_dut_list = st.get_dut_names()

    dut1 = vars.D1
    dut2 = vars.D2
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)

    if basic_obj.is_vsonic_device(vars.D1):
        st.wait(15)
        ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
        ipfeature.ping(dut1, data.d2d1_ip_addr, timeout=7)
    else:
        ipfeature.ping(dut1, data.d2t1_ip_addr)
        ipfeature.ping(dut1, data.d2d1_ip_addr)

    if basic_obj.is_vsonic_device(vars.D2):
        st.wait(15)
        ping_result = ipfeature.ping(dut2, data.d1t1_ip_addr, timeout=7)
        ping_result = ipfeature.ping(dut2, data.d1d2_ip_addr, timeout=7)
    else:
        ping_result = ipfeature.ping(dut2, data.d1t1_ip_addr)
        ping_result = ipfeature.ping(dut2, data.d1d2_ip_addr)

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
        st.report_fail("operation_failed")

@pytest.mark.base_test_sanity
def test_static_route_mgmt_loopback():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    #verify IPv4 and Ipv6 static route
    ipv4_result = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
    if ipv4_result:
        st.log("Ipv4 static route ping from D1 to D2 TGN succeeded")
    else:
        st.warn("Ipv4 static route ping from D1 to D2 TGN failed.")
    ipv6_result = ipfeature.ping(dut1, data.d2t1_ip_addr_v6, family='ipv6', timeout=7)
    if ipv6_result:
        st.log("Ipv6 static route ping from D1 to D2 TGN succeeded")
    else:
        st.warn("Ipv6 static route ping from D1 to D2 TGN failed.")

    #configure static route via MGMT

    #step1 delete the present static route
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.delete_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
    ipfeature.delete_static_route(dut2, data.d1d2_ip_addr_v6, data.static_ipv6_list[0], family='ipv6')

    #step2 add static route via mgmt int
    mgmt_dut2 = st.get_mgmt_ip(dut2)
    ipfeature.create_static_route(dut1, mgmt_dut2, data.static_ip_list[1])
    st.log("checking show ip routes")
    st.show(dut1, "show ip route")

    # step3 verify ping to route
    mgmt_result = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
    if mgmt_result:
        st.log("MGMT static route ping from D1 to D2 TGN succeeded")
    else:
        st.warn("MGMT static route ping from D1 to D2 TGN failed.")

    #step4 remove static route via mgmt int
    ipfeature.delete_static_route(dut1, mgmt_dut2, data.static_ip_list[1])

    #configure static route to loop back

    #step1 configure the loop back on d1 and d2
    st.log("configuring loopbacks on both D1 and D2")
    ipfeature.config_ip_addr_interface(dut1, data.loopback_d1, data.loopback_d1_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut2, data.loopback_d2, data.loopback_d2_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut1, data.loopback_d1, data.loopback_d1_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, data.loopback_d2, data.loopback_d2_addr_v6, data.mask_v6, family='ipv6')

    # step2 add static route to loopback
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[3])
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[3], family='ipv6')
    st.log("checking show ip routes")
    st.show(dut1, "show ip route")

    #step3 verify ping to route
    lop_result = ipfeature.ping(dut1, data.loopback_d2_addr, timeout=7)
    if lop_result:
        st.log("Ipv4 loop back static route ping to D2 loopback from D1 succeeded")
    else:
        st.warn("Ipv4 loop back static route ping to D2 loopback from D1  failed.")
    lopv6_result = ipfeature.ping(dut1, data.loopback_d2_addr_v6, family='ipv6', timeout=7)
    if lopv6_result:
        st.log("Ipv6 loop back static route ping to D2 loopback from D1 succeeded")
    else:
        st.warn("Ipv6 loop back static route ping to D2 loopback from D1 failed.")

    # step4 remove static route to loopback
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[3])
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[3], family='ipv6')

    # step5 publish result of test case
    if ipv4_result and ipv6_result and mgmt_result and lop_result and lopv6_result:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")
    #we need loop back in next tc so it will be cleared in next bgp tc

@pytest.mark.base_test_sanity
def test_static_route_with_BGP():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    #configure static route with BGP

    #step1 configure bgp
    bgpapi.config_bgp(dut=dut1, router_id= data.loopback_d1_addr, local_as = data.dut1_as, neighbor = data.d2d1_ip_addr,
                      update_src = data.d1d2_ip_addr, network = data.loopback_d1_addr, remote_as = data.dut2_as, config
                      = "yes", config_type_list = ["neighbor", "activate", "update_src", "network"])

    bgpapi.config_bgp(dut=dut2, router_id=data.loopback_d2_addr, local_as=data.dut2_as, neighbor=data.d1d2_ip_addr,
                      update_src= data.d2d1_ip_addr, network= data.loopback_d2_addr, remote_as=data.dut1_as, config=
                      "yes", config_type_list=["neighbor", "activate", "update_src", "network"])
    #ipv6
    bgpapi.config_bgp(dut=dut1, router_id=data.loopback_d1_addr_v6, local_as=data.dut1_as, neighbor=data.d2d1_ip_addr_v6,
                      update_src=data.d1d2_ip_addr_v6, network=data.loopback_d1_addr_v6+'/'+data.mask_v6, remote_as=data.dut2_as, config
                      ="yes", addr_family="ipv6", config_type_list=["neighbor", "activate", "update_src", "network"])

    bgpapi.config_bgp(dut=dut2, router_id=data.loopback_d2_addr_v6, local_as=data.dut2_as, neighbor=data.d1d2_ip_addr_v6,
                      update_src=data.d2d1_ip_addr_v6, network=data.loopback_d2_addr_v6+'/'+data.mask_v6, remote_as=data.dut1_as, config=
                      "yes", addr_family="ipv6", config_type_list=["neighbor", "activate", "update_src", "network"])

    st.log("checking checking ip bgp neighbor")
    st.show(dut1, "show ip bgp neighbor")
    result = bgpapi.verify_bgp_summary(dut1, family='ipv4', shell="vtysh", neighbor=data.d2d1_ip_addr, state='Established')
    if not result:
        st.warn("Ipv4 BGP didn't come up")
    resultv6 = bgpapi.verify_bgp_summary(dut1, family='ipv6', shell="vtysh", neighbor=data.d2d1_ip_addr_v6,
                                       state='Established')
    if not resultv6:
        st.warn("Ipv6 BGP didn't come up")

    #step2 add static route with bgp
    ipfeature.create_static_route(dut1, data.loopback_d2_addr, data.static_ip_list[1])
    ipfeature.create_static_route(dut1, data.loopback_d2_addr_v6, data.static_ipv6_list[1], family='ipv6')
    st.log("checking show ip routes")
    st.show(dut1, "show ip route")

    #step3 verify ping to route
    bgp_result = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
    if bgp_result:
        st.log("BGP static route ping to D2 TGN from D1 succeeded")
    else:
        st.warn("BGP static route ping to D2 TGN from D1 failed.")
    bgpv6_result = ipfeature.ping(dut1, data.d2t1_ip_addr_v6, family='ipv6', timeout=7)
    if bgpv6_result:
        st.log("BGPv6 static route ping to D2 TGN from D1 succeeded")
    else:
        st.warn("BGPv6 static route ping to D2 TGN from D1 failed.")

    #step4 remove static route with bgp
    ipfeature.delete_static_route(dut1, data.loopback_d2_addr, data.static_ip_list[1])
    ipfeature.delete_static_route(dut1, data.loopback_d2_addr_v6, data.static_ipv6_list[1], family='ipv6')

    #step5 remove BGP and loopback configs
    bgpapi.config_bgp(dut=dut1, router_id=data.loopback_d1_addr, local_as=data.dut1_as, neighbor=data.d2d1_ip_addr,
                      update_src= data.d1d2_ip_addr, network=data.loopback_d1_addr, remote_as=data.dut2_as, config="no",
                      config_type_list=["neighbor", "activate", "update_src", "network"])

    bgpapi.config_bgp(dut=dut2, router_id=data.loopback_d2_addr, local_as=data.dut2_as, neighbor=data.d1d2_ip_addr,
                      update_src= data.d2d1_ip_addr, network=data.loopback_d2_addr, remote_as=data.dut1_as, config="no",
                      config_type_list=["neighbor", "activate", "update_src", "network"])
    #ipv6
    bgpapi.config_bgp(dut=dut1, router_id=data.loopback_d1_addr_v6, local_as=data.dut1_as, neighbor=data.d2d1_ip_addr_v6,
                      update_src=data.d1d2_ip_addr_v6, network= data.loopback_d1_addr_v6+'/'+data.mask_v6, remote_as=
                      data.dut2_as, config="no", addr_family="ipv6", config_type_list=["neighbor", "activate", "update_src", "network"])

    bgpapi.config_bgp(dut=dut2, router_id=data.loopback_d2_addr_v6, local_as=data.dut2_as, neighbor=data.d1d2_ip_addr_v6,
                      update_src=data.d2d1_ip_addr_v6, network=data.loopback_d2_addr_v6+'/'+data.mask_v6, remote_as=
                      data.dut1_as, config="no", addr_family="ipv6", config_type_list=["neighbor", "activate", "update_src", "network"])

    ipfeature.delete_ip_interface(dut1, data.loopback_d1, data.loopback_d1_addr, data.mask)
    ipfeature.delete_ip_interface(dut2, data.loopback_d2, data.loopback_d2_addr, data.mask)
    ipfeature.delete_ip_interface(dut1, data.loopback_d1, data.loopback_d1_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.delete_ip_interface(dut2, data.loopback_d2, data.loopback_d2_addr_v6, data.mask_v6, family='ipv6')

    #step6 publish results
    if result and resultv6 and bgp_result and bgpv6_result:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")

@pytest.mark.base_test_sanity
def test_static_route_with_portchannel():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    #configure static route with port channel

    #step1 remove ip from b2b interfce which will be used for portchannel
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr, data.mask)
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6, data.mask_v6, family='ipv6')

    #step2 create port channel
    portchannel_obj.create_portchannel(dut1, data.port_channel)
    portchannel_obj.create_portchannel(dut2, data.port_channel)

    #step3 add member to port channel
    portchannel_obj.add_portchannel_member(dut1, data.port_channel, vars.D1D2P1)
    portchannel_obj.add_portchannel_member(dut2, data.port_channel, vars.D2D1P1)

    #step4 add ip to port channel
    ipfeature.config_ip_addr_interface(dut1, data.port_channel, data.d1d2_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut2, data.port_channel, data.d2d1_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut1, data.port_channel, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, data.port_channel, data.d2d1_ip_addr_v6, data.mask_v6, family='ipv6')

    if not portchannel_obj.verify_portchannel_state(dut1, data.port_channel, state="up"):
        st.warn("port channel is in down state")

    #step5 add static route via port channel
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
    st.log("checking show ip routes")
    st.show(dut1, "show ip route")

    # step6 verify ping to route
    poc_result = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
    if poc_result:
        st.log("port channel static route ping to D2 TGN from D1 succeeded")
    else:
        st.warn("port channel static route ping to D2 TGN from D1 failed.")
    pocv6_result = ipfeature.ping(dut1, data.d2t1_ip_addr_v6, family='ipv6', timeout=7)
    if pocv6_result:
        st.log("port channel v6 static route ping to D2 TGN from D1 succeeded")
    else:
        st.warn("port channel v6 static route ping to D2 TGN from D1 failed.")

    #step7 revert back the configs done for port channel
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family='ipv6')
    portchannel_obj.delete_portchannel(dut1, data.port_channel)
    portchannel_obj.delete_portchannel(dut2, data.port_channel)

    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6, data.mask_v6, family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr, data.mask)
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6, data.mask_v6, family='ipv6')

    #step8 publish result of test case
    if poc_result and pocv6_result:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")
