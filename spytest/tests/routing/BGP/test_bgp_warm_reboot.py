import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select

import apis.routing.ip as ipfeature
import apis.system.port as papi
import apis.routing.bgp as bgpfeature
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj

def initialize_variables():
    global data
    data = SpyTestDict()
    data.as_num = 100
    data.remote_as_num = 200
    data.remote_as_num1 = 300
    data.counters_threshold = 0
    data.my_ip_addr = "10.10.10.1"
    data.neigh_ip_addr = "10.10.10.2"
    data.intf_ip_addr = "20.20.20.1"
    data.neigh_ip_addr2 = "20.20.20.2"
    data.ip_prefixlen = "24"
    data.my_ipv6_addr = "2000::1"
    data.neigh_ipv6_addr = "2000::2"
    data.intf_ipv6_addr = "3000::1"
    data.neigh_ipv6_addr2 = "3000::2"
    data.dut1_to_tg_port_1_ip6 = "1000::1"
    data.tg_to_dut1_port_1_ip6 = "1000::2"
    data.ipv6_prefixlen = "64"
    data.test_bgp_route_count = 3000
    data.traffic_rate_pps = data.test_bgp_route_count
    data.includeTraffic = False


@pytest.fixture(scope="module", autouse=True)
def bgp_warm_reboot_module_hooks(request):
    global vars, tg_handler, tg, dut, ctrl_start, ctrl_stop
    global dut_to_tg_port_1, dut_to_tg_port_2, hwsku_under_test
    initialize_variables()
    vars = st.ensure_min_topology("D1T1:2")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"]
    ctrl_start = {'mode': 'start'}
    ctrl_stop = {'mode': 'stop'}

    # Test setup details
    dut = vars.D1
    dut_to_tg_port_1 = vars.D1T1P1
    dut_to_tg_port_2 = vars.D1T1P2
    hwsku_under_test = basic_obj.get_hwsku(dut)

    # Configuring v4/v6 routing interfaces on the DUT.
    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_1, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_1, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_2, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_2, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")

    # Configuring BGP router and v4/v6 neighbors on the DUT.
    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num, family="ipv6")

    yield
    st.log("L3 Performance Enhancements Module Cleanup.")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_1, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_1, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_2, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_2, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num)
    bgpfeature.cleanup_router_bgp(dut)


@pytest.fixture(scope="function", autouse=True)
def bgp_warm_reboot_func_hooks(request):
    # Function configuration
    yield
    # Function cleanup

def verify_bgp_route_count(dut, family='ipv4', shell="sonic", **kwargs):
    if family.lower() == 'ipv4':
        output = bgpfeature.show_bgp_ipv4_summary(dut)
    if family.lower() == 'ipv6':
        output = bgpfeature.show_bgp_ipv6_summary(dut)
    st.debug(output)
    if 'neighbor' in kwargs and 'state' in kwargs:
        match = {'neighbor': kwargs['neighbor']}
        try:
            entries = filter_and_select(output, None, match)[0]
        except Exception:
            st.log("ERROR 1")
        if entries['state']:
            if kwargs['state'] == 'Established':
                if entries['state'].isdigit():
                    return entries['state']
                else:
                    return 0
            else:
                return 0
        else:
            return 0
    else:
        return 0
    return 0


@pytest.fixture(scope="function")
def fixture_v4(request):
    global h1, h2, bgp_rtr1
    st.log("Test Fixture Config.")
    # TG ports reset
    st.log("Resetting the TG ports")
    tgapi.traffic_action_control(tg_handler, actions=['reset'])

    # TG protocol interface creation
    st.log("TG protocol interface creation")
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',
                                             intf_ip_addr=data.neigh_ip_addr, gateway=data.my_ip_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
                                             intf_ip_addr=data.neigh_ip_addr2, gateway=data.intf_ip_addr,
                                             arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Configuring BGP on TG interface
    conf_var = {'mode': 'enable', 'active_connect_enable': '1', 'local_as': data.remote_as_num,
                'remote_as': data.as_num, 'remote_ip_addr': data.my_ip_addr}
    route_var = {'mode': 'add', 'num_routes': data.test_bgp_route_count, 'prefix': '121.1.1.0', 'as_path': 'as_seq:1'}

    # Starting the BGP router on TG.
    bgp_rtr1 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var,
                                   route_var=route_var, ctrl_var=ctrl_start)

    st.log("BGP_HANDLE: " + str(bgp_rtr1))

    # Verifying the BGP neighborship
    st.wait(10)
    st.log("Verifying the BGP neighborship.")
    if not bgpfeature.verify_bgp_summary(dut, neighbor=data.neigh_ip_addr, state='Established'):
        st.report_fail("bgp_ip_peer_establish_fail", data.neigh_ip_addr)

    yield
    st.log("Test Fixture Cleanup.")
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], handle=h1['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], handle=h2['handle'], mode='destroy')


@pytest.fixture(scope="function")
def fixture_v6(request):
    global h1, h2, bgp_rtr2

    st.log("Test Fixture Config.")
    # TG ports reset
    st.log("Resetting the TG ports")
    tgapi.traffic_action_control(tg_handler, actions=['reset'])

    # TG protocol interface creation
    st.log("TG protocol interface creation")
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',
                                ipv6_intf_addr=data.neigh_ipv6_addr, ipv6_prefix_length=64,
                                ipv6_gateway=data.my_ipv6_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
                                ipv6_intf_addr=data.neigh_ipv6_addr2, ipv6_prefix_length=64,
                                ipv6_gateway=data.intf_ipv6_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Configuring BGP on TG interface
    conf_var = {'mode': 'enable', 'ip_version': '6', 'active_connect_enable': '1', 'local_as': data.remote_as_num,
                'remote_as': data.as_num, 'remote_ipv6_addr': data.my_ipv6_addr}
    route_var = {'mode': 'add', 'ip_version': '6', 'num_routes': data.test_bgp_route_count, 'prefix': '3300:1::',
                 'as_path': 'as_seq:1'}

    # Starting the BGP router on TG.
    bgp_rtr2 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var,
                                   route_var=route_var, ctrl_var=ctrl_start)
    st.log("BGP_HANDLE: " + str(bgp_rtr2))

    # Verifying the BGP neighborship
    st.wait(10)
    st.log("Verifying the BGP neighborship.")
    if not bgpfeature.verify_bgp_summary(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established'):
        st.report_fail("bgp_ip6_peer_establish_fail", data.neigh_ip_addr)

    yield
    st.log("Test Fixture Cleanup.")
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], handle=h1['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], handle=h2['handle'], mode='destroy')


@pytest.mark.long_run
@pytest.mark.test_bgp_v4_warm_reboot
def test_bgp_v4_warm_reboot(fixture_v4):
    ################# Author Details ################
    # Name: V Sreenivasula Reddy
    # Email:  sreenivasula.reddy@broadcom.com
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################

    bgpfeature.enable_docker_routing_config_mode(vars.D1)
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
                               emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
                               mode='create', transmit_mode='continuous', length_mode='fixed',
                               rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: " + str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Starting the TG traffic after clearing the DUT counters
    papi.clear_interface_counters(dut)
    tg.tg_traffic_control(action="run", handle=tr1['stream_id'])

    bgpfeature.enable_docker_routing_config_mode(vars.D1)
    st.log("saving the BGP config in vtysh shell")
    reboot_obj.config_save(vars.D1, shell='vtysh')
    st.log("config save in D1")
    reboot_obj.config_save([vars.D1])
    st.log("Performing warm reboot")
    st.reboot(vars.D1, "warm")


    # Stopping the TG traffic
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.report_fail("traffic_verification_failed_during_warm_reboot")
    st.report_pass("test_case_passed")


@pytest.mark.long_run
@pytest.mark.test_bgp_v6_warm_reboot
def test_bgp_v6_warm_boot(fixture_v6):
    ################# Author Details ################
    # Name: V Sreenivasula Reddy
    # Email:  sreenivasula.reddy@broadcom.com
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################

    # Configuring traffic stream on the TG interfac

    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
                               emulation_dst_handle=bgp_rtr2['route'][0]['handle'], circuit_endpoint_type='ipv6',
                               mode='create', transmit_mode='continuous', length_mode='fixed',
                               rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

    # Starting the TG traffic after clearing the DUT counters
    papi.clear_interface_counters(dut)
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg.tg_traffic_control(action="run", handle=tr1['stream_id'])

    bgpfeature.enable_docker_routing_config_mode(vars.D1)
    st.log("saving the BGP config in vtysh shell")
    reboot_obj.config_save(vars.D1, shell='vtysh')
    st.log("config save in D1")
    reboot_obj.config_save([vars.D1])
    st.log("Performing warm reboot")
    st.reboot(vars.D1, "warm")

    # Stopping the TG traffic
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.wait(5)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.report_fail("traffic_verification_failed_during_warm_reboot")
    st.report_pass("test_case_passed")

