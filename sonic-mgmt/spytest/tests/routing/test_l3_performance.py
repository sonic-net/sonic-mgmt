import pytest
import datetime

from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select

import apis.routing.ip as ipfeature
import apis.system.port as papi
import apis.routing.bgp as bgpfeature
import apis.system.interface as interface_obj
import apis.system.basic as basic_obj
import apis.common.asic as asicapi
import apis.switching.vlan as vlan

data = SpyTestDict()
data.as_num = 100
data.remote_as_num = 200
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
data.ipv6_prefixlen = "64"
data.test_bgp_route_count = 20000
data.traffic_rate_pps = data.test_bgp_route_count
data.includeTraffic = False

@pytest.fixture(scope="module", autouse=True)
def l3_performance_enhancements_module_hooks(request):
    global vars, tg_handler, tg, dut, dut_to_tg_port_1, dut_to_tg_port_2, cli_type
    global hwsku_under_test, def_v4_route_count, def_v6_route_count

    vars = st.ensure_min_topology("D1T1:2")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"]

    if tgapi.is_soft_tgen(vars):
        data.test_bgp_route_count = 200

    # Test setup details
    dut = vars.D1
    dut_to_tg_port_1 = vars.D1T1P1
    dut_to_tg_port_2 = vars.D1T1P2
    hwsku_under_test = basic_obj.get_hwsku(dut)
    cli_type = st.get_ui_type(dut)

    # Module Configuration
    st.log("L3 Performance Enhancements Module Configuration.")
    # Configuring v4/v6 routing interfaces on the DUT.
    ipfeature.config_ipv6(dut, action='enable')
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_1, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_1, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_2, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, dut_to_tg_port_2, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")

    # Configuring BGP router and v4/v6 neighbors on the DUT.
    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num, family="ipv6")

    # Get the default route count from DUT
    def_v4_route_count = asicapi.get_ipv4_route_count(dut)
    def_v6_route_count = asicapi.get_ipv6_route_count(dut)

    yield
    # Module Cleanup
    st.log("L3 Performance Enhancements Module Cleanup.")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_1, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_1, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_2, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.delete_ip_interface(dut, dut_to_tg_port_2, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num)
    bgpfeature.cleanup_router_bgp(dut)

@pytest.fixture(scope="function", autouse=True)
def l3_performance_enhancements_func_hooks(request):
    # Function configuration
    yield
    # Function cleanup

def check_intf_traffic_counters(dut, loopCnt, case):
    flag = 0
    iter = 1
    p1_rcvd = 0
    p2_txmt = 0

    while iter <= loopCnt:
        output = papi.get_interface_counters_all(dut)
        for entry in output:
            if entry["iface"] == dut_to_tg_port_2:
                DUT_rx_value = entry["rx_bps"]
            if entry["iface"] == dut_to_tg_port_1:
                DUT_tx_value = entry["tx_bps"]
        p1_rcvd = DUT_rx_value
        p1_rcvd = p1_rcvd.replace(" MB/s","")
        p1_rcvd = p1_rcvd.replace(" B/s","")
        p1_rcvd = p1_rcvd.replace(" KB/s","")
        p1_rcvd = p1_rcvd.replace(" GB/s","")
        p1_rcvd = 0.0 if p1_rcvd == "" else p1_rcvd
        p2_txmt = DUT_tx_value
        p2_txmt = p2_txmt.replace(" MB/s","")
        p2_txmt = p2_txmt.replace(" B/s","")
        p2_txmt = p2_txmt.replace(" KB/s","")
        p2_txmt = p2_txmt.replace(" GB/s","")
        p2_txmt = 0.0 if p2_txmt == "" else p2_txmt

        st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
        if cli_type == "klish":
            st.log("Converting counters to bits by multiplying 1000000")
            p2_txmt = int(float(p2_txmt)*1000000)
            p1_rcvd = int(float(p1_rcvd)*1000000)
        if case == "install":
            if (int(float(p2_txmt)) == 0):
                flag = 0
                break

            if (abs(int(float(p1_rcvd))-int(float(p2_txmt))) == data.counters_threshold):
                flag = 1
                break
        elif case == "withdraw":
            if (int(float(p2_txmt))) == 0:
                flag = 1
                break
        iter = iter+1

    if flag:
        return True
    else:
        return False

def check_bcmcmd_route_count(dut, loopCnt, ipType, defcount, expcount):
    flag = 0
    iter = 1
    while iter <= loopCnt:
        if ipType == "ipv4":
            curr_count = asicapi.get_ipv4_route_count(dut)
        elif ipType == "ipv6":
            curr_count = asicapi.get_ipv6_route_count(dut)

        route_cnt = int(curr_count) - int(defcount)

        st.log("Learnt route count after iteration {} : {}".format(iter,route_cnt))

        if int(route_cnt) == int(expcount):
            flag = 1
            break
        iter = iter+1

    if flag:
        return True
    else:
        return False

def verify_bgp_route_count(dut,family='ipv4',shell="sonic",**kwargs):
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
                intf_ip_addr=data.neigh_ip_addr,gateway=data.my_ip_addr,arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
                intf_ip_addr=data.neigh_ip_addr2,gateway=data.intf_ip_addr,arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    # Configuring BGP on TG interface
    conf_var = {'mode':'enable', 'active_connect_enable':'1', 'local_as':data.remote_as_num, 'remote_as':data.as_num, 'remote_ip_addr':data.my_ip_addr}
    route_var = {'mode':'add', 'num_routes':data.test_bgp_route_count, 'prefix':'121.1.1.0', 'as_path':'as_seq:1'}
    ctrl_start = {'mode':'start'}

    # Starting the BGP router on TG.
    bgp_rtr1 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var, route_var = route_var, ctrl_var=ctrl_start)
    st.log("BGP_HANDLE: "+str(bgp_rtr1))

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
    global h1, h2, bgp_rtr1, bgp_rtr2
    st.log("Test Fixture Config.")
    # TG ports reset
    st.log("Resetting the TG ports")
    tgapi.traffic_action_control(tg_handler, actions=['reset'])

    # TG protocol interface creation
    st.log("TG protocol interface creation")
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',
            ipv6_intf_addr=data.neigh_ipv6_addr,ipv6_prefix_length=64,
            ipv6_gateway=data.my_ipv6_addr,arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
            ipv6_intf_addr=data.neigh_ipv6_addr2,ipv6_prefix_length=64,
            ipv6_gateway=data.intf_ipv6_addr,arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    # Configuring BGP on TG interface
    conf_var = {'mode':'enable', 'ip_version':'6', 'active_connect_enable':'1', 'local_as':data.remote_as_num, 'remote_as':data.as_num, 'remote_ipv6_addr':data.my_ipv6_addr}
    route_var = {'mode':'add', 'ip_version':'6', 'num_routes':data.test_bgp_route_count, 'prefix':'3300:1::', 'as_path':'as_seq:1'}
    ctrl_start = {'mode':'start'}

    # Starting the BGP router on TG.
    bgp_rtr2 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var, route_var = route_var, ctrl_var=ctrl_start)
    st.log("BGP_HANDLE: "+str(bgp_rtr2))

    # Verifying the BGP neighborship
    st.wait(10)
    st.log("Verifying the BGP neighborship.")
    if not bgpfeature.verify_bgp_summary(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established'):
        st.report_fail("bgp_ip6_peer_establish_fail", data.neigh_ip_addr)

    yield
    st.log("Test Fixture Cleanup.")
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], handle=h1['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], handle=h2['handle'], mode='destroy')


def show_ip_route_validation_cli(type='click'):
    st.log("{} validation".format(type))
    test_case = 'FtOpSoRtPerfFn053' if type == 'click' else 'FtOpSoRtPerfFn052'
    start_time = datetime.datetime.now()
    if "via" not in st.show(dut, "show ip route", type=type, skip_tmpl=True, max_time=300):
        st.report_tc_fail(test_case, 'test_case_failed')
    end_time = datetime.datetime.now()
    st.log("start_time for route display using {}: {} ".format(type,start_time))
    st.log("end_time for route display using {}: {} ".format(type,end_time))
    time_diff_in_secs = end_time - start_time
    st.log("time_diff_in_secs: {}".format(time_diff_in_secs))
    st.report_tc_pass(test_case,'test_case_passed')

def bgp_router_cli_validation(dut,type = "vtysh"):
    cmd = ['router bgp 100']
    for each in range(101,121):
        if type == 'vtysh':
            cmd.append('neighbor 192.168.{}.2 remote-as 300'.format(each))
        else:
            cmd.extend(['neighbor 192.168.{}.2'.format(each), 'remote-as 300', 'exit'])
    cmd.append('exit')
    cmd.append('no router bgp')
    if type == "vtysh":
        for each in cmd:
            st.vtysh_config(dut,each)
    else:
        st.config(dut, cmd, type=type, skip_error_check=True)

@pytest.mark.test_ft_l3_performance_enhancements_v4_route_intstall_withdraw
def test_ft_l3_performance_enhancements_v4_route_intstall_withdraw(fixture_v4):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - FtOpSoRtPerfFn025 : Performance measurement for IP route installation in hardware
    #  Measure time taken for routes to get installed into the hardware
    #  (with fresh advertisement of routes ...but not due to any other trigger).
    # Objective - FtOpSoRtPerfFn026 : Performance measurement for IP route withdraw in hardware
    #  Measure time taken for routes to get removed from the hardware by stop advertising the Routes from neighbor.
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################
    # Withdraw the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, 0):
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != 0:
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    if data.includeTraffic:
        # Configuring traffic stream on the TG interface
        tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
                 emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
                 mode='create', transmit_mode='continuous', length_mode='fixed',
                 rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

        # Starting the TG traffic after clearing the DUT counters
        papi.clear_interface_counters(dut)
        tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

    st.banner("Measuring time taken for route installation of {} ipv4 routes on HWSKU {}".format(data.test_bgp_route_count, hwsku_under_test))

    # Taking the start time timestamp
    #start_time = datetime.datetime.now()

    # Readvertise the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    result = True
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, data.test_bgp_route_count):
        st.error("route_table_not_updated_by_advertise_from_tg")
        result = False

    if data.includeTraffic:
        st.wait(25)
        # Verifying the BGP route count on the DUT
        if not check_intf_traffic_counters(dut, 20, "install"):
            st.error("ingress_traffic_rate_not_matching_with_egress_rate")
            result = False
    if result:
        st.report_tc_pass("FtOpSoRtPerfFn025","test_case_passed")
    else:
        st.report_tc_fail("FtOpSoRtPerfFn025","ingress_traffic_rate_not_matching_with_egress_rate")

    # Taking the end time timestamp
    #end_time = datetime.datetime.now()

    # verifying click cli show ip route validation
    show_ip_route_validation_cli('click')
    st.banner("verifying vtysh cli show ip route")
    start_time = datetime.datetime.now()
    st.show(dut, "show ip route", type="vtysh", skip_tmpl=True, max_time=300)
    end_time = datetime.datetime.now()
    time_diff_in_secs = end_time - start_time
    st.banner("time_diff_in_secs for route display using vtysh: {} ".format(time_diff_in_secs))

    #verifying klish cli show ip route validation
    if st.is_feature_supported("klish"):
        show_ip_route_validation_cli('klish')

    # Verify the total route count using SONiC CLI
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Time taken for route installation
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Time taken for intsalling {} v4 routes on HWSKU {} = ".format(data.test_bgp_route_count,hwsku_under_test) +str(time_in_secs.seconds))
    st.banner("Measuring time taken for route withdraw of {} ipv4 routes on HWSKU {}".format(data.test_bgp_route_count,hwsku_under_test))

    # Taking the start time timestamp
    start_time = datetime.datetime.now()

    # Withdraw the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, 0):
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    if data.includeTraffic:
        # Verifying the BGP route count on the DUT
        if not check_intf_traffic_counters(dut, 20, "withdraw"):
            st.report_fail("egress_traffic_rate_not_zero")

    # Taking the end time timestamp
    end_time = datetime.datetime.now()

    # Verify the total route count using SONiC CLI
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != 0:
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    # Time taken for route withdraw
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Time taken for withdrawing {} v4 routes on HWSKU {} = ".format(data.test_bgp_route_count,hwsku_under_test) +str(time_in_secs.seconds))

    # Stopping the TG traffic
    if data.includeTraffic:
        tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.report_pass("test_case_passed")


def test_ft_l3_performance_enhancements_v6_route_intstall_withdraw(fixture_v6):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - FtOpSoRtPerfFn042 : Performance measurement for IPv6 route installation in hardware
    #  Measure time taken for routes to get installed into the hardware
    #  (with fresh advertisement of routes ...but not due to any other trigger).
    # Objective - FtOpSoRtPerfFn043 : Performance measurement for IPv6 route withdraw in hardware
    #  Measure time taken for routes to get removed from the hardware by stop advertising the Routes from neighbor.
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################
    # Withdraw the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr2['conf']['handle'], route_handle=bgp_rtr2['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv6", def_v6_route_count, 0):
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != 0:
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    if data.includeTraffic:
        # Configuring traffic stream on the TG interface
        tr2=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
                 emulation_dst_handle=bgp_rtr2['route'][0]['handle'], circuit_endpoint_type='ipv6',
                 mode='create', transmit_mode='continuous', length_mode='fixed',
                 rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

        # Starting the TG traffic after clearing the DUT counters
        papi.clear_interface_counters(dut)
        tg.tg_traffic_control(action="run",handle=tr2['stream_id'])

    st.banner("# Measuring time taken for route installation of {} ipv6 routes on HWSKU {}".format(data.test_bgp_route_count,hwsku_under_test))

    # Taking the start time timestamp
    start_time = datetime.datetime.now()

    # Readvertise the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr2['conf']['handle'], route_handle=bgp_rtr2['route'][0]['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv6", def_v6_route_count, data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    if data.includeTraffic:
        st.wait(25)
        # Verifying the BGP route count on the DUT
        if not check_intf_traffic_counters(dut, 20, "install"):
            st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

    # Taking the end time timestamp
    end_time = datetime.datetime.now()

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Time taken for route installation
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Time taken for intsalling {} v6 routes on HWSKU {} = ".format(data.test_bgp_route_count,hwsku_under_test) +str(time_in_secs.seconds))
    st.banner("# Measuring time taken for route withdraw of {} ipv4 routes on HWSKU {}".format(data.test_bgp_route_count,hwsku_under_test))

    # Taking the start time timestamp
    start_time = datetime.datetime.now()

    # Withdraw the routes.
    ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr2['conf']['handle'], route_handle=bgp_rtr2['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv6", def_v6_route_count, 0):
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    if data.includeTraffic:
        # Verifying the BGP route count on the DUT
        if not check_intf_traffic_counters(dut, 20, "withdraw"):
            st.report_fail("egress_traffic_rate_not_zero")

    # Taking the end time timestamp
    end_time = datetime.datetime.now()

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != 0:
        st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

    # Time taken for route withdraw
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Time taken for withdrawing {} v6 routes on HWSKU {} = ".format(data.test_bgp_route_count,hwsku_under_test) +str(time_in_secs.seconds))

    if data.includeTraffic:
        # Stopping the TG traffic
        tg.tg_traffic_control(action='stop', handle=tr2['stream_id'])
    st.report_pass("test_case_passed")

def test_ft_l3_performance_enhancements_v4_bgp_link_flap_convergence_time(fixture_v4):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - FtOpSoRtPerfFn031 : Performance measurement for BGP Link Flap case
    #   Measure time taken for the traffic ( corresponding to BGP routes )
    #   to resume when the link carrying traffic ( corresponding to BGP routes )
    #   goes down and then comes up.
    #   Measurement is taken from the time of link up
    #   (i.e link up after link going down) to the time of RX rate = TX rate.
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################
    # Configuring traffic stream on the TG interface
    tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
                             emulation_dst_handle=bgp_rtr1['route'][0]['handle'],
                             circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous',
                             length_mode='fixed', rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Starting the TG traffic after clearing the DUT counters
    papi.clear_interface_counters(dut)
    tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

    st.wait(25)

    # Verifying the BGP route count on the DUT
    if not check_intf_traffic_counters(dut, 20, "install"):
        st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

    # Shutdown the routing interface link.
    st.log("Shutdown the routing interface links.")
    if not interface_obj.interface_operation(dut, dut_to_tg_port_1 , "shutdown"):
        st.report_fail('interface_admin_shut_down_fail', dut_to_tg_port_1)

    if not interface_obj.poll_for_interface_status(dut, dut_to_tg_port_1, 'oper', 'down', iteration=10, delay=1):
        st.report_fail('interface_admin_shut_down_fail', dut_to_tg_port_1)

    st.banner("# Measuring Convergence time ( control plane + data plane ) taken for BGP Link Flap scenario on HWSKU {}".format(hwsku_under_test))

    # Startup the routing interface link.
    st.log("Startup the routing interface link.")
    if not interface_obj.interface_operation(dut, dut_to_tg_port_1, "startup"):
        st.report_fail('interface_admin_startup_fail', dut_to_tg_port_1)

    if not interface_obj.poll_for_interface_status(dut, dut_to_tg_port_1, 'oper', 'up', iteration=10, delay=1):
        st.report_fail('interface_admin_startup_fail', dut_to_tg_port_1)

    # Taking the start time timestamp
    start_time = datetime.datetime.now()
    bgpfeature.config_bgp(dut=vars.D1, local_as=data.as_num, config='yes', neighbor=data.neigh_ip_addr, config_type_list=["connect"], connect='1')

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Taking the end time timestamp
    end_time = datetime.datetime.now()

    # Time taken for route installation
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Convergence time ( control plane + data plane ) taken for BGP Link Flap scenario (After Link up, time taken for BGP to re establish, learn and install the routes to hardware) on HWSKU {} = ".format(hwsku_under_test) +str(time_in_secs.seconds))

    # Stopping the TG traffic
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.report_pass("test_case_passed")

def test_ft_l3_performance_enhancements_v4_bgp_session_failover_convergence_time(fixture_v4):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - FtOpSoRtPerfFn032 : Performance measurement for BGP Session Failover case
    #  Measure time taken for the traffic ( corresponding to BGP routes ) to resume fully
    #  (i.e RX rate = TX rate) after the BGP session flaps ( i.e BGP session goes down and then comes up
    #  This is triggered using "clear ip bgp * " CLI command ).
    #
    ############### Test bed details ################
    #  TG --- DUT --- TG
    #################################################
    # Configuring traffic stream on the TG interface
    tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'],
             emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
             mode='create', transmit_mode='continuous', length_mode='fixed',
             rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Starting the TG traffic after clearing the DUT counters
    papi.clear_interface_counters(dut)
    tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

    st.wait(25)

    # Verifying the BGP route count on the DUT
    if not check_intf_traffic_counters(dut, 20, "install"):
        st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

    # Clearing the BGP session.
    st.log("Clearing the BGP session.")
    bgpfeature.clear_ip_bgp(dut)

    st.banner("# Measuring Convergence time ( control plane + data plane ) taken for BGP session failover scenario on HWSKU {}".format(hwsku_under_test))
    # Taking the start time timestamp
    start_time = datetime.datetime.now()
    bgpfeature.config_bgp(dut=vars.D1, local_as=data.as_num, config='yes', neighbor=data.neigh_ip_addr, config_type_list=["connect"], connect='1')

    # Verify the total route count using bcmcmd
    if not check_bcmcmd_route_count(dut, 50, "ipv4", def_v4_route_count, data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Verify the total route count
    count = verify_bgp_route_count(dut, family='ipv4', neighbor=data.neigh_ip_addr, state='Established')
    st.log("Route count: "+str(count))
    if int(count) != int(data.test_bgp_route_count):
        st.report_fail("route_table_not_updated_by_advertise_from_tg")

    # Taking the end time timestamp
    end_time = datetime.datetime.now()

    # Time taken for route installation
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time

    st.banner("Convergence time ( control plane + data plane ) taken for BGP session failover scenario (After session up, time taken for BGP to re establish, learn and install the routes to hardware) on HWSKU {} = ".format(hwsku_under_test) +str(time_in_secs.seconds))

    # Stopping the TG traffic
    tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.report_pass("test_case_passed")

@pytest.mark.test_cli_validation_ip_address
def test_cli_validation_ip_address():
    vlan.config_vlan_range(dut, vlan_range = "101 121", config="add", skip_verify=False)
    st.banner("click cli validation for ip address config")
    start_time = datetime.datetime.now()
    st.log("IP address config on 20 vlan routing interface using click")
    for each in range(101,121):
        cmd = ["config interface ip add Vlan{} 192.168.{}.1/31".format(each, each)]
        st.config(dut, cmd, type="click")
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    st.banner("time taken for IP address config on 20 vlan routing interface using click: {}".format(time_diff))

    st.log("IP address unconfig on 20 vlan routing interface using click")
    for each in range(101, 121):
        cmd = ["config interface ip remove Vlan{} 192.168.{}.1/31".format(each, each)]
        st.config(dut, cmd, type="click")
    st.report_tc_pass("FtOpSoRtPerfFn054","test_case_passed")

    if st.is_feature_supported("klish"):
        st.banner("klish cli validation for ip address config")
        start_time = datetime.datetime.now()
        for each in range(101, 121):
            cmd = ["interface Vlan {}".format(each), 'ip address 192.168.{}.1/31'.format(each), 'exit']
            st.config(dut, cmd, type="klish")
            end_time = datetime.datetime.now()
        time_diff = end_time - start_time
        st.banner("time taken for IP address config on 20 vlan routing interface using klish: {}".format(time_diff))
        for each in range(101, 121):
            cmd = ["interface Vlan {}".format(each), 'no ip address 192.168.{}.1/31'.format(each), 'exit']
            st.config(dut, cmd, type="klish")
        st.report_tc_pass("FtOpSoRtPerfFn055", "test_case_passed")
    st.report_pass("test_case_passed")


@pytest.mark.test_cli_validation_bgp_router_config
def test_cli_validation_bgp_router_config():
    st.banner("vtysh cli validation for bgp router config")
    start_time = datetime.datetime.now()
    bgp_router_cli_validation(dut, type="vtysh")
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    st.banner("time taken for BGP router config on 20 vlan routing interface using vtysh: {}".format(time_diff))
    st.report_tc_pass("FtOpSoRtPerfFn056", "test_case_passed")

    if st.is_feature_supported("klish"):
        st.banner("klish cli validation for bgp router config")
        start_time = datetime.datetime.now()
        bgp_router_cli_validation(dut, type="klish")
        end_time = datetime.datetime.now()
        time_diff = end_time - start_time
        st.banner("time taken for BGP router config on 20 vlan routing interface using klish: {}".format(time_diff))
        st.report_tc_pass("FtOpSoRtPerfFn057", "test_case_passed")
    st.report_pass("test_case_passed")

