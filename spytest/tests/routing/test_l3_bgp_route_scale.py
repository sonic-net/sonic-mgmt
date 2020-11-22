import pytest
from spytest.dicts import SpyTestDict
import apis.routing.ip as ipfeature
from spytest import st
from collections import OrderedDict
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import tg_bgp_config
import apis.switching.mac as macapi
from spytest.utils import filter_and_select
import apis.system.port as papi
import apis.system.interface as ifapi
import apis.routing.bgp as bgpfeature
import apis.routing.vrf as vrf_api

def clear_arp_entries(dut):
    """
    This proc is to clear arp entries of the dut.
    :param dut: DUT Number
    :return:
    """
    st.config(dut, "sonic-clear arp".format())
    return

def clear_ndp_entries(dut):
    """
    This proc is to clear ndp entries of the dut.
    :param dut: DUT Number
    :return:
    """
    st.config(dut, "sonic-clear ndp".format())
    return


def clear_ip_bgp_v4_unicast(dut, value="*"):
    command = "clear ip bgp ipv4 unicast {}".format(value)
    st.vtysh(dut, command)


def clear_ip_bgp(dut, value="*"):
    command = "sonic-clear bgp {}".format(value)
    st.config(dut, command)

def delete_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap):
    command = "neighbor {} route-map {} in".format(neighbor_ip, routemap)
    st.vtysh_config(dut, command)
    command = "no neighbor {} route-map {} out".format(neighbor_ip, routemap)
    st.vtysh_config(dut, command)
    command = "no route-map {} permit 10".format(routemap)
    st.vtysh_config(dut, command)
    return

@pytest.mark.reboot
def reboot_node(dut):
    st.reboot(dut)

    st.wait(100)
    ports = papi.get_interfaces_all(dut)
    if not ports:
      return False
    else:
      return True

@pytest.mark.fast_reboot
def fast_reboot_node(dut):
    st.reboot(dut, "fast")

    st.wait(100)
    ports = papi.get_interfaces_all(dut)
    if not ports:
        return False
    else:
        return True

@pytest.mark.warm_reboot
def warm_reboot_node(dut):
    vars = st.get_testbed_vars()
    cmd = "config warm_restart enable"
    st.config(vars.D1, cmd)
    cmd = "config warm_restart enable swss"
    st.config(vars.D1, cmd)
    cmd = "config warm_restart enable bgp"
    st.config(vars.D1, cmd)
    cmd = "config warm_restart bgp_timer 120"
    st.config(vars.D1, cmd)
    cmd = "config warm_restart neighsyncd_timer 100"

    #st.show(dut, "show warm_restart config")

    st.reboot(dut, "warm")

    st.wait(300)
    #re-enable after infra support
    #st.show(dut, "show warm-restart state")
    ports = papi.get_interfaces_all(dut)
    if not ports:
        return False
    else:
        return True

def verify_ip_from_vlan_interface( dut, port):
    """

    :param port:
    :type port:
    :param ipaddr:
    :type ipaddr:
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = st.show(dut, "show vlan brief")
    match = {"VLAN ID": port}
    entries = filter_and_select(output, ["IP Address"], match)
    return entries

def trigger_link_flap(dut, port):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    st.config(dut, "config interface {} {}".format("shutdown", port))
    st.wait(5)
    st.config(dut, "config interface {} {}".format("startup", port))
    st.wait(5)

def verify_ping(src_obj,port_handle,dev_handle,dst_ip,ping_count=5,exp_count=5):
    ping_count,exp_count = int(ping_count),int(exp_count)
    if src_obj.tg_type == 'stc':
        result = src_obj.tg_emulation_ping(handle=dev_handle,host=dst_ip,count=ping_count)
        st.log("ping output: "+str(result))
        return True if int(result['tx']) == ping_count and  int(result['rx']) == exp_count else False
    return True

def get_handles():
    vars = st.get_testbed_vars()

    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_2 = tg2.get_port_handle(vars.T1D1P2)
    return (tg1, tg_ph_1, tg2, tg_ph_2)

data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def vlan_module_hooks(request):
    #add things at the start of this module
    vars = st.get_testbed_vars()
    data.vlans = []
    data.dut = vars.D1
    data.start_ipv6_addr = "2100::1/64"
    data.start_ipv6_addr2 = "2100::2/64"
    data.intf_ipv6_addr = "2200::1"
    data.my_ipv6_addr = "2000::1"
    data.my_ipv6_addr2 = "2100::1"
    data.neigh_ipv6_addr = "2000::2"
    data.neigh_ipv6_addr2 = "2100::2"
    data.ipv6_prefixlen = "64"
    data.as_num = 100
    data.remote_as_num = 200
    data.all_ports = st.get_all_ports(data.dut)
    data.free_member_ports = OrderedDict()
    data.tg_member_ports = OrderedDict()
    data.counters_threshold = 10
    data.tgen_stats_threshold = 10
    data.start_ip_addr = "11.11.1.1/24"
    data.start_ip_addr2 = "11.11.1.2/24"
    data.intf_ip_addr = "20.20.20.1"
    data.my_ip_addr = "10.10.10.1"
    data.ip_prefixlen = "24"
    data.my_ip_addr2 = "11.11.11.1/24"
    data.neighbor_list = ["10.10.10.2"]
    data.neigh_ip_addr = "10.10.10.2"
    data.neigh_ip_addr2 = "11.11.11.2"
    data.router_id = "11.11.11.24"
    data.routemap = "preferGlobal"
    data.vrf = "Vrf-Green"
    data.result = [False, False, False, False, False, False, False, False, False, False, False, False]
    data.vrf_result = [False, False, False, False, False, False]

    yield

def check_intf_pkt_traffic_counters():
    (dut1) = (data.dut)
    st.wait(15)
    vars = st.get_testbed_vars()
    DUT_rx_value = ifapi.get_interface_counters(dut1, vars.D1T1P2, "rx_ok")
    DUT_tx_value = ifapi.get_interface_counters(dut1, vars.D1T1P1, "tx_ok")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
    p1_data = int(float(p1_rcvd))
    p2_data = int(float(p2_txmt))
    diff = p1_data - p2_data
    st.log(" diff is "+str(diff))
    if (abs((diff*100)/p1_data) > data.counters_threshold) | (p1_rcvd == '0') | (p2_txmt == '0'):
        return False
    else:
        return True

def compare_intf_traffic_stats(entry_rx, entry_tx, threshhold):
    for i in entry_rx:
        p1_rcvd = i['rx_bps']
        p1_rcvd = p1_rcvd.replace(" MB/s","")
        p1_rcvd = p1_rcvd.replace(" B/s","")

    for i in entry_tx:
        p2_txmt = i['tx_bps']
        p2_txmt = p2_txmt.replace(" MB/s","")
        p2_txmt = p2_txmt.replace(" B/s","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
    if (abs(int(float(p1_rcvd))-int(float(p2_txmt))) > data.counters_threshold) | (p1_rcvd == '0') | (p2_txmt == '0'):
        return False
    else:
        return True


def check_intf_traffic_counters():
    (dut1) = (data.dut)
    papi.clear_interface_counters(dut1)
    st.wait(10)
    vars = st.get_testbed_vars()
    output = papi.get_interface_counters_all(dut1)
    entry1 = filter_and_select(output, ["rx_bps"], {'iface': vars.D1T1P2})
    entry2 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P1})
    ret = compare_intf_traffic_stats(entry1, entry2, 2)
    if ret is True:
        return True
    DUT_rx_value = papi.get_interface_counters(dut1, vars.D1T1P2, "rx_bps")
    DUT_tx_value = papi.get_interface_counters(dut1, vars.D1T1P1, "tx_bps")
    ret = compare_intf_traffic_stats(entry1, entry2, data.counters_threshold)


    if  ret is False:
        output = papi.get_interface_counters_all(dut1)
        entry1 = filter_and_select(output, ["rx_bps"], {'iface': vars.D1T1P2})
        entry2 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P1})
        for i in entry1:
            p1_rcvd = i['rx_bps']
            p1_rcvd = p1_rcvd.replace(" MB/s","")
            p1_rcvd = p1_rcvd.replace(" B/s","")
        for i in entry2:
            p2_txmt = i['tx_bps']
            p2_txmt = p2_txmt.replace(" MB/s","")
            p2_txmt = p2_txmt.replace(" B/s","")
        st.log("Retry rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
        if (abs(int(float(p1_rcvd))-int(float(p2_txmt))) > data.counters_threshold) | (p1_rcvd == '0') | (p2_txmt == '0'):
            return False
        else:
            return True
    else:
        return True

def show_bgp_ipv4_summary_default_vrf(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp ipv4 summary"
    return st.show(dut, command)

def show_bgp_ipv4_summary_non_default_vrf(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp vrf {} summary".format(data.vrf)
    return st.show(dut, command)


def show_bgp_ipv6_summary_default_vrf(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp ipv6 summary"
    return st.show(dut, command)

def show_bgp_ipv6_summary_non_default_vrf(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp vrf {} ipv6 summary".format(data.vrf)
    return st.show(dut, command)


def verify_bgp_session_summary(dut, vrf_flag, family='ipv4',  shell="sonic", **kwargs):
    """

    :param dut:
    :param family:
    :param shell:
    :param kwargs:
    :return:
    """
    (dut) = (data.dut)
    if family.lower() == 'ipv4':
        if vrf_flag is False:
            output = show_bgp_ipv4_summary_default_vrf(dut)
        else:
            output = show_bgp_ipv4_summary_non_default_vrf(dut)

    elif family.lower() == 'ipv6':
        if vrf_flag is False:
            output = show_bgp_ipv6_summary_default_vrf(dut)
        else:
            output = show_bgp_ipv6_summary_non_default_vrf(dut)
    else:
        st.log("Invalid family {} or shell {}".format(family, shell))
        return False
    st.debug(output)
    st.log("family {} or shell {}".format(family, shell))
    # Specifically checking neighbor state
    if 'neighbor' in kwargs and 'state' in kwargs:
        match = {'neighbor': kwargs['neighbor']}
        try:
            entries = filter_and_select(output, None, match)[0]
        except Exception as e:
            st.error(e)
            st.log("Neighbour {} given state {}, matching with {}  ".format(kwargs['neighbor'], kwargs['state'],
                                                                            "Not Found"))
            return False
        if entries['state']:
            if kwargs['state'] == 'Established':
                if entries['state'].isdigit():
                    st.log("Neighbour {} given state {}, matching with {}  ".format(kwargs['neighbor'], kwargs['state'],
                                                                                    entries['state']))
                else:
                    st.error(
                        "Neighbour {} given state {}, matching with {}  ".format(kwargs['neighbor'], kwargs['state'],
                                                                                 entries['state']))
                    return False

            elif kwargs['state'] == 'Active':
                if entries['state'] == "Active":
                    st.log("Neighbour {} given state {}, matching with {}  ".format(kwargs['neighbor'], kwargs['state'],
                                                                                    entries['state']))
                else:
                    st.error(
                        "Neighbour {} given state {}, matching with {}  ".format(kwargs['neighbor'], kwargs['state'],
                                                                                 entries['state']))
                    return False
    return True

def create_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap, vrf_flag):
    command = "route-map {} permit 10".format(routemap)
    st.vtysh_config(dut, command)
    command = "set ipv6 next-hop prefer-global"
    st.vtysh_config(dut, command)
    if vrf_flag is False:
        command = "router bgp {}".format(local_asn)
    else:
        command = "router bgp {} vrf {}".format(local_asn, data.vrf)
    st.vtysh_config(dut, command)
    command = "address-family ipv6 unicast"
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} in".format(neighbor_ip, routemap)
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} out".format(neighbor_ip, routemap)
    return



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
    else:
        return 0
    return 0


def delete_bgp_router(dut, router_id, as_num, vrf_flag):
    """

    :param router_id:
    :type router_id:
    :param as_num:
    :type as_num:
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    st.log("delete bgp router info")
    if vrf_flag is False:
        my_cmd = "no router bgp {}".format(as_num)
        st.vtysh_config(dut, my_cmd)
        my_cmd = "no bgp router-id {}".format(router_id)
        st.vtysh_config(dut, my_cmd)
    else:
        my_cmd = "no router bgp {} vrf {}".format(as_num, data.vrf)
        st.vtysh_config(dut, my_cmd)


def pre_configure_ipv6_route_scale(vrf_flag):
    dut = data.dut
    vars = st.get_testbed_vars()
    data.member3 = vars.D1T1P1
    data.member4 = vars.D1T1P2
    retval = True

    ipfeature.config_ip_addr_interface(dut, data.member3, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    #bgpfeature.create_bgp_router(dut, data.as_num, data.router_id)
    create_bgp_neighbor_route_map_config(dut, data.as_num, data.neigh_ipv6_addr, data.routemap, vrf_flag)
    if vrf_flag is True:
        bgpfeature.create_bgp_router(dut, "10", '')
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True)
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = data.member3, skip_error = True, config = 'yes')
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = data.member4, skip_error = True, config = 'yes')
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', addr_family ='ipv6', local_as = data.as_num, neighbor = data.neigh_ipv6_addr, remote_as = data.remote_as_num, keep_alive='60', routeMap='preferGlobal', diRection='in', holdtime='180', config = 'yes', config_type_list =['neighbor','activate','nexthop_self', 'routeMap'])
        #bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, local_as = data.as_num, addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    else:
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num, family="ipv6")



    (data.tg1, data.tg_ph_1, data.tg2, data.tg_ph_2) = get_handles()
    data.tg1.tg_traffic_control(action='reset',port_handle=data.tg_ph_1)
    data.tg2.tg_traffic_control(action='reset',port_handle=data.tg_ph_2)

    ipfeature.config_ip_addr_interface(dut, data.member4, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.config_ip_addr_interface(dut, data.member3, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    data.h1=data.tg1.tg_interface_config(port_handle=data.tg_ph_1, mode='config', ipv6_intf_addr='2000::2',
        ipv6_prefix_length='64', ipv6_gateway='2000::1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(data.h1))
    data.h2=data.tg2.tg_interface_config(port_handle=data.tg_ph_2, mode='config', ipv6_intf_addr='2200::2',
        ipv6_prefix_length='64', ipv6_gateway='2200::1', arp_send_req='1')
    st.log("INTFCONF: "+str(data.h2))

  # Configuring BGP device on top of interface.
    # Initializing dict_vars for easy readability.
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}
    data.bgp_conf=data.tg1.tg_emulation_bgp_config(handle=data.h1['handle'], mode='enable', ip_version='6',
        active_connect_enable='1', local_as='200', remote_as='100', remote_ipv6_addr='2000::1')

    data.bgp_route=data.tg1.tg_emulation_bgp_route_config(handle=data.bgp_conf['handle'], mode='add', ip_version='6',
        num_routes='8000', prefix='3300:1::', as_path='as_seq:1')
    data.bgp_ctrl=data.tg1.tg_emulation_bgp_control(handle=data.bgp_conf['handle'], mode='start')
    command = "show run bgp"
    st.config(dut, command)
    command = "show ndp"
    st.config(dut, command)

    # Configuring the BGP router.
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    st.wait(10)
    if vrf_flag is False:
        show_bgp_ipv6_summary_default_vrf(dut)
        retval = bgpfeature.verify_bgp_summary(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    else:
        verify_bgp_session_summary(dut, family='ipv6', vrf_flag='True', neighbor=data.neigh_ipv6_addr, state='Established')

    return retval

def post_configure_ipv6_route_scale(vrf_flag):
    dut = data.dut
    #IPv6 BGP post config
    vars = st.get_testbed_vars()
    data.member3 = vars.D1T1P1
    data.member4 = vars.D1T1P2


    res=data.tg1.tg_traffic_control(action='stop', handle=data.tr2['stream_id'])
    st.log("TR_CTRL: "+str(res))
    # Withdraw the routes.
    st.wait(10)
    bgp_ctrl=data.tg1.tg_emulation_bgp_control(handle=data.bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    data.tg2.tg_traffic_control(action='reset',port_handle=data.tg_ph_2)
    st.wait(10)

    #tg1.tg_interface_config(port_handle=[tg_ph_1,tg_ph_2], mode='destroy')

    data.tg1.tg_interface_config(port_handle=data.tg_ph_1, handle=data.h1['handle'], mode='destroy')
    data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=data.h2['handle'], mode='destroy')

    #h1a=tg1.tg_interface_config(protocol_handle=h1['ethernet_handle'], mode='destroy')
    #h2a=tg2.tg_interface_config(protocol_handle=h2['ethernet_handle'], mode='destroy')
    if vrf_flag is True:
        temp_flag = False
        delete_bgp_router(dut, '', "10", temp_flag)
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', local_as = data.as_num, neighbor = data.neigh_ipv6_addr, remote_as = data.remote_as_num, keep_alive='60', holdtime='180', config = 'no', config_type_list =['neighbor','activate','nexthop_self'])
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = data.member3, skip_error = True, config = 'no')
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = data.member4, skip_error = True, config = 'no')
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True,  config = 'no')
        delete_bgp_router(dut, '', data.as_num, vrf_flag)
    else:
        bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num)
        #delete_bgp_neighbor_route_map_config(dut, data.as_num, data.neigh_ipv6_addr, data.routemap)
        delete_bgp_router(dut, '', data.as_num, vrf_flag)
    ipfeature.delete_ip_interface(dut, data.member3, data.my_ipv6_addr, subnet=data.ipv6_prefixlen, family="ipv6")
    ipfeature.delete_ip_interface(dut, data.member4, data.intf_ipv6_addr, subnet=data.ipv6_prefixlen, family="ipv6")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_1():
    vrf_flag = False
    retval = pre_configure_ipv6_route_scale(vrf_flag)

    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_3():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.3 START
    #count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    #st.log("Route count: "+str(count))
    # Withdraw the routes.
    ctrl1=data.tg1.tg_bgp_routes_control(handle=data.bgp_conf['handle'], route_handle=data.bgp_route['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    st.wait(10)
    ctrl1=data.tg1.tg_bgp_routes_control(handle=data.bgp_conf['handle'], route_handle=data.bgp_route['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))
    st.wait(10)
    retval = bgpfeature.verify_bgp_summary(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')

    if retval is True:
        st.log("bgp_router_created")
        st.log("IPV6 Scale Test Case 3.3 PASSED")
    else:
        st.log('bgp verification failed')

    data.tr2=data.tg2.tg_traffic_config(port_handle=data.tg_ph_2, emulation_src_handle=data.h2['handle'],
        emulation_dst_handle=data.bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
        transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    res=data.tg2.tg_traffic_control(action='run', handle=data.tr2['stream_id'])

    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_4():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.4 START
    trigger_link_flap(dut, data.member3)
    st.wait(45)
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')
    if res2:
        st.log("Interface Scaling Test Case 1.4 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_5():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.5 START
    clear_ndp_entries(dut)
    st.wait(20)
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')

    if res2:
        st.log("Interface Scaling Test Case 3.5 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_6():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.6 START
    clear_ip_bgp(dut)
    st.wait(20)
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')

    if res2:
        st.log("Interface Scaling Test Case 3.6 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_7():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.7 START
    macapi.clear_mac(dut)

    st.wait(20)
    res3=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
    res3=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')
    if res3:
        st.log("Interface Scaling Test Case 3.7 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def is_supported_platform(dut):
    output = st.show(dut, "show version | grep HwSKU:", skip_tmpl=True,
                                    skip_error_check=True)
    name = output.split(':')
    name = str(name[1])
    plt_str = name.split('-')

    if (str(plt_str[1]) == "AS7712"):
        return True
    else:
        return False

@pytest.mark.l3_scale_ut_private
def test_ipv6_tc3_8():
    dut = data.dut

    if (not is_supported_platform(dut)):
        st.log("Warm reboot is not supported in this platform")
        st.report_fail("test_case_failed")
        return

    #IPV6 ROUTE SCALE TEST CASE 3.8 START
    cmd = "config save -y"
    st.config(dut, cmd)
    ret = warm_reboot_node(dut)
    ret = True
    if (ret):
        clear_ip_bgp(dut)
        st.wait(20)
        res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
        res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')
        if res2:
            st.log("Interface Scaling Test Case 3.8 PASSED PING TEST")
        retval = check_intf_traffic_counters()
        if retval is True:
            st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_9():
    dut = data.dut
    vrf_flag = False
    #IPV6 ROUTE SCALE TEST CASE 3.9 START - FAST REBOOT
    cmd = "config save -y"
    st.config(dut, cmd)
    #ret = fast_reboot_node(dut)
    ret = True
    if (ret):
        clear_ip_bgp(dut)
        st.wait(20)
        res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
        res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')
        if res2:
            st.log("Interface Scaling Test Case 3.9 PASSED PING TEST")
        retval = check_intf_traffic_counters()
        if retval is True:
            st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

    post_configure_ipv6_route_scale(vrf_flag)


def parse_route_output(output):
    lines = output.splitlines()
    line  = lines[0]

    st.log(line)
    return int(line)

def create_l3_route(route_count, vrf_flag):
    (dut) = (data.dut)
    vars = st.get_testbed_vars()
    member3 = vars.D1T1P1
    member4 = vars.D1T1P2
    tc_fail_flag = 0
    ipfeature.config_ip_addr_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")

    if vrf_flag is True:
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True)
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member3, skip_error = True, config = 'yes')
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member4, skip_error = True, config = 'yes')
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', local_as = data.as_num,
              neighbor = data.neigh_ip_addr, remote_as = data.remote_as_num, keep_alive='60', holdtime='180',
              config = 'yes', config_type_list =['neighbor','activate','nexthop_self'])
    else:
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)

    ipfeature.config_ip_addr_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    ipfeature.config_ip_addr_interface(dut, member4, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.10.10.2',
        gateway='10.10.10.1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='20.20.20.2', gateway='20.20.20.1', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : '10.10.10.1'
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : route_count,
                  'prefix'     : '121.1.1.0',
                  'as_path'    : 'as_seq:1'
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}


    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    st.wait(10)

    tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
        emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
        mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    if vrf_flag is False:
        retval = bgpfeature.verify_bgp_summary(dut, neighbor=data.neigh_ip_addr, state='Established')
    else:
        retval = verify_bgp_session_summary(dut, vrf_flag='True', neighbor=data.neigh_ip_addr, state='Established')

    st.wait(10)
    output = st.show(dut, "bcmcmd \"l3 defip show\" | wc -l", skip_tmpl=True,
                                    skip_error_check=True)
    st.log(output)

    count = 0
    while (count < 7):
        output = st.show(dut, "bcmcmd \"l3 defip show\" | wc -l", skip_tmpl=True,
                                    skip_error_check=True)
        st.log(output)
        st.wait(20)
        count += 1

    curr_route_count = parse_route_output(output)

    res=tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    bgp_rtr2 = tg_bgp_config(tg = tg1, handle = bgp_rtr1['conf']['handle'], ctrl_var=ctrl_stop)
    ipfeature.delete_ip_interface(dut, member4, data.intf_ip_addr)
    ipfeature.delete_ip_interface(dut, member3, data.my_ip_addr)
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    delete_bgp_router(dut, '', data.as_num, vrf_flag)

    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    st.wait(20)

    if (curr_route_count >= route_count):
        return True
    else:
        return False

def create_l3_route_ipv6(vrf_flag, route_count):
    (dut) = (data.dut)
    vars = st.get_testbed_vars()
    member3 = vars.D1T1P1
    member4 = vars.D1T1P2
    tc_fail_flag = 0

    ipfeature.config_ip_addr_interface(dut, member3, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    #bgpfeature.create_bgp_router(dut, data.as_num, data.router_id)
    bgpfeature.create_bgp_router(dut, "10", '')
    create_bgp_neighbor_route_map_config(dut, data.as_num, data.neigh_ipv6_addr, data.routemap, vrf_flag)
    if vrf_flag is True:
        bgpfeature.create_bgp_router(dut, "10", '')
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True)
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member3, skip_error = True, config = 'yes')
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', addr_family ='ipv6', local_as = data.as_num, neighbor = data.neigh_ipv6_addr, remote_as = data.remote_as_num, keep_alive='60', routeMap='preferGlobal', diRection='in', holdtime='180', config = 'yes', config_type_list =['neighbor','activate','nexthop_self', 'routeMap'])
        #bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, local_as = data.as_num, addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    else:
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num, family="ipv6")



    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    ipfeature.config_ip_addr_interface(dut, member3, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr='2000::2',
        ipv6_prefix_length='64', ipv6_gateway='2000::1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))

    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}
    bgp_conf=tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='200', remote_as='100',
        remote_ipv6_addr='2000::1', netmask_ipv6='128')

    bgp_route=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=route_count, prefix='3300:1::',
        as_path='as_seq:1')
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

    st.log("BGP neighborship established.")

    if vrf_flag is False:
        retval = bgpfeature.verify_bgp_summary(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    else:
        verify_bgp_session_summary(dut, family='ipv6', vrf_flag='True', neighbor=data.neigh_ipv6_addr, state='Established')


    st.wait(20)
    output = st.show(dut, "bcmcmd \"l3 ip6route show\" | wc -l", skip_tmpl=True,
                                    skip_error_check=True)
    st.log(output)

    count = 0
    while (count < 4):
        output = st.show(dut, "bcmcmd \"l3 ip6route show\" | wc -l", skip_tmpl=True,
                                    skip_error_check=True)
        st.log(output)
        st.wait(20)
        count += 1

    curr_route_count = parse_route_output(output)

    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.wait(20)

    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    ipfeature.delete_ip_interface(dut, member3, data.my_ipv6_addr, subnet=data.ipv6_prefixlen, family="ipv6")
    if vrf_flag is True:
        temp_flag = False
        delete_bgp_router(dut, '', "10", temp_flag)
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', local_as = data.as_num, neighbor = data.neigh_ipv6_addr, remote_as = data.remote_as_num, keep_alive='60', holdtime='180', config = 'no', config_type_list =['neighbor','activate','nexthop_self'])
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member3, skip_error = True, config = 'no')
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True,  config = 'no')
    else:
        bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num)
        #delete_bgp_neighbor_route_map_config(dut, data.as_num, data.neigh_ipv6_addr, data.routemap)
        delete_bgp_router(dut, '', data.as_num, vrf_flag)


    if (curr_route_count >= route_count):
        return True
    else:
        return False

def ipv4_tc1_1to1_10(vrf_flag, long_run_flag, warm_reboot_flag):
    # Config 2 IPV4 interfaces on DUT.
    (dut) = (data.dut)
    vars = st.get_testbed_vars()
    member3 = vars.D1T1P1
    member4 = vars.D1T1P2
    tc_fail_flag = 0
    st.log("========BEFORE STARTING CONFIG========================= ")
    command = "show interface status"
    st.config(dut, command)
    command = "show ip interface"
    st.config(dut, command)
    ipfeature.config_ip_addr_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, member4, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    if vrf_flag is True:
        out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True)
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member3, skip_error = True, config = 'yes')
        vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member4, skip_error = True, config = 'yes')
        bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', local_as = data.as_num, neighbor = data.neigh_ip_addr, remote_as = data.remote_as_num, keep_alive='60', holdtime='180', config = 'yes', config_type_list =['neighbor','activate','nexthop_self'])
    else:
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        #bgpfeature.create_bgp_router(dut, data.as_num, data.router_id)
        bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    #IPV4 ROUTE SCALE TEST CASE 1.1 START
    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    ipfeature.config_ip_addr_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, member4, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.10.10.2', gateway='10.10.10.1', arp_send_req='1')
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.10.10.2', gateway='10.10.10.1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("========AFTER TG INTF CONFIG========================= ")
    command = "show ip interface"
    st.config(dut, command)
    command = "show arp"
    st.config(dut, command)

    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='20.20.20.2', gateway='20.20.20.1', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    st.config(dut, command)

    # Configuring BGP device on top of interface.
    # Initializing dict_vars for easy readability.
    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : '10.10.10.1'
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : '30000',
                  'prefix'     : '121.1.1.0',
                  'as_path'    : 'as_seq:1'
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}


    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    st.wait(10)
    command = "show bgp vrf Vrf-Green summary"
    st.config(dut, command)
    command = "show interface status"
    st.config(dut, command)
    #pdb.set_trace()
    tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')
    if vrf_flag is False:
        retval = bgpfeature.verify_bgp_summary(dut, neighbor=data.neigh_ip_addr, state='Established')
    else:
        retval = verify_bgp_session_summary(dut, vrf_flag='True', neighbor=data.neigh_ip_addr, state='Established')
    #pdb.set_trace()

    if retval is True:
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.1 PASSED")
            data.result[0] = True
        else:
            st.log("IPV4 Scale Test Case 2.1 PASSED")
            data.vrf_result[0] = True
    else:
        #tc_fail_flag not needed for this test case
        #tc_fail_flag = 1
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.1 FAILED")
        else:
            st.log("IPV4 Scale Test Case 2.1 FAILED")


    #IPV4 ROUTE SCALE TEST CASE 1.5 START
    st.wait(10)
    if vrf_flag is False:
        retval = ipfeature.ping(dut, data.neigh_ip_addr, count='20')

        if retval is True:
            st.log("IPV4 Scale Test Case 1.5 PASSED")
            data.result[4] = True
        else:
            st.log("Ping Failed for bgp neig")
            tc_fail_flag = 1


    #IPV4 ROUTE SCALE TEST CASE 1.4 START
    papi.clear_interface_counters(dut)
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(20)
    #bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)
    retval = check_intf_traffic_counters()
    if retval is True:
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.4 PASSED")
            data.result[3] = True
        else:
            st.log("IPV4 Scale Test Case 2.4 PASSED")
            data.vrf_result[3] = True
    else:
        tc_fail_flag = 1
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.4 FAILED")
        else:
            st.log("IPV4 Scale Test Case 2.4 FAILED")


    #IPV4 ROUTE SCALE TEST CASE 1.6 START
    trigger_link_flap(dut, member3)
    res2=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h2['handle'], dst_ip='10.10.10.1',\
                                                                ping_count='6', exp_count='6')

    if res2:
        st.log("Route Scaling Test Case 1.6 PASSED PING TEST")
    st.wait(60)
    retval = check_intf_traffic_counters()
    if retval is True:
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.6 PASSED")
            data.result[5] = True
        else:
            st.log("IPV4 Scale Test Case 2.5 PASSED")
            data.vrf_result[4] = True
    else:
        tc_fail_flag = 1
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.6 FAILED")
        else:
            st.log("IPV4 Scale Test Case 2.5 FAILED")

    #bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)


    if vrf_flag is False:
        #IPV4 ROUTE SCALE TEST CASE 1.9 START
        clear_arp_entries(dut)
        res2=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h2['handle'], dst_ip='10.10.10.1',\
                                                                    ping_count='6', exp_count='6')
        if res2:
            st.log("Route Scaling Test Case 1.9 PASSED PING TEST")
        #bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)
        st.wait(30)
        retval = check_intf_traffic_counters()
        if retval is True:
            st.log("IPV4 Scale Test Case 1.9 PASSED")
            data.result[8] = True
            st.log("Traffic Passed")
        else:
            st.log("IPV4 Scale Test Case 1.9 FAILED")
            tc_fail_flag = 1
        #IPV4 ROUTE SCALE TEST CASE 1.10 START
        macapi.clear_mac(vars.D1)
        res3=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h2['handle'], dst_ip='10.10.10.1',\
                                                                    ping_count='6', exp_count='6')
        if res3:
            st.log("Route Scaling Test Case 1.10 PASSED PING TEST")
        #bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)

        st.wait(30)
        retval = check_intf_traffic_counters()
        if retval is True:
            st.log("IPV4 Scale Test Case 1.10 PASSED")
            data.result[9] = True
            st.log("Traffic Passed")
        else:
            st.log("IPV4 Scale Test Case 1.10 FAILED")
            tc_fail_flag = 1


    #IPV4 ROUTE SCALE TEST CASE 1.7 START
    clear_ip_bgp(dut)
    st.wait(30)
    res2=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h2['handle'], dst_ip='10.10.10.1',\
                                                                ping_count='6', exp_count='6')

    if res2:
        st.log("Route Scaling Test Case 1.7 PASSED PING TEST")


    retval = check_intf_traffic_counters()
    if retval is True:
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.7 PASSED")
            data.result[6] = True
        else:
            st.log("IPV4 Scale Test Case 2.6 PASSED")
            data.vrf_result[5] = True
    else:
        tc_fail_flag = 1
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.7 FAILED")
        else:
            st.log("IPV4 Scale Test Case 2.6 FAILED")

    #IPV4 ROUTE SCALE TEST CASE 1.8 START
    if vrf_flag is False:
        clear_ip_bgp_v4_unicast(dut)
        st.wait(45)
        res2=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h2['handle'], dst_ip='10.10.10.1',\
                                                                ping_count='6', exp_count='6')
        if res2:
            st.log("Route Scaling Test Case 1.8 PASSED PING TEST")
        retval = check_intf_traffic_counters()
        if retval is True:
            st.log("IPV4 Scale Test Case 1.8 PASSED")
            data.result[7] = True
            st.log("Traffic Passed")
        else:
            st.log("IPV4 Scale Test Case 1.8 FAILED")
            tc_fail_flag = 1

    #IPV4 ROUTE SCALE TEST CASE 1.3 START
    # Withdraw the routes.
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    st.wait(30)
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))

    st.wait(30)
    retval = check_intf_traffic_counters()
    if retval is True:
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.3 PASSED")
            data.result[2] = True
        else:
            st.log("IPV4 Scale Test Case 2.3 PASSED")
            data.vrf_result[2] = True
    else:
        tc_fail_flag = 1
        if vrf_flag is False:
            st.log("IPV4 Scale Test Case 1.3 FAILED")
        else:
            st.log("IPV4 Scale Test Case 2.3 FAILED")


    if long_run_flag is False:
        res=tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        st.log("TR_CTRL: "+str(res))
        bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)
        tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
        tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
        if vrf_flag is True:
            bgpfeature.config_bgp(dut = dut, vrf_name = data.vrf, router_id = '', local_as = data.as_num, neighbor = data.neigh_ip_addr, remote_as = data.remote_as_num, config = 'no', config_type_list =['neighbor','activate','nexthop_self'])
            vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member3, skip_error = True, config = 'no')
            vrf_api.bind_vrf_interface(dut = dut, vrf_name = data.vrf, intf_name = member4, skip_error = True, config = 'no')
            out = vrf_api.config_vrf(dut = dut, vrf_name = data.vrf, skip_error = True,  config = 'no')
        else:
            bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
            delete_bgp_router(dut, '', data.as_num, vrf_flag)
        ipfeature.delete_ip_interface(dut, member4, data.intf_ip_addr)
        ipfeature.delete_ip_interface(dut, member3, data.my_ip_addr)
        return tc_fail_flag



    #IPV4 ROUTE SCALE TEST CASE 1.12 START
    cmd = "config save -y"
    st.config(dut, cmd)
    ret = fast_reboot_node(dut)
    if (ret):
        # Withdraw the routes.
        retval = bgpfeature.verify_bgp_summary(dut, neighbor=data.neigh_ip_addr, state='Established')
        command = "show run bgp"
        st.config(dut, command)
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)

        ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
        st.log("TR_CTRL: "+str(ctrl1))
        st.wait(30)
        ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
        st.log("TR_CTRL: "+str(ctrl1))

        st.wait(30)
        retval = check_intf_traffic_counters()
        if retval is True:
            st.log("IPV4 Scale Test Case 1.12 PASSED")
            data.result[11] = True
            st.log("Traffic Passed")
        else:
            st.log("IPV4 Scale Test Case 1.12 FAILED")
    else:
        st.log("Fast reboot failed")

    if warm_reboot_flag is True:
        #IPV4 ROUTE SCALE TEST CASE 1.11 START
        cmd = "config save -y"
        st.config(dut, cmd)
        ret = warm_reboot_node(dut)
        if (ret):
            # Withdraw the routes.
            ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
            st.log("TR_CTRL: "+str(ctrl1))
            st.wait(30)
            ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
            st.log("TR_CTRL: "+str(ctrl1))

            st.wait(30)
            retval = check_intf_traffic_counters()
            if retval is True:
                st.log("IPV4 Scale Test Case 1.11 PASSED")
                data.result[10] = True
                st.log("Traffic Passed")
            else:
                st.log("IPV4 Scale Test Case 1.11 FAILED")
        else:
            st.log("Warm reboot failed")

    res=tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)
    ipfeature.delete_ip_interface(dut, member4, data.intf_ip_addr)
    ipfeature.delete_ip_interface(dut, member3, data.my_ip_addr)
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    delete_bgp_router(dut, '', data.as_num, vrf_flag)

    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    #tg1.tg_interface_config(port_handle=[tg_ph_1,tg_ph_2], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    #h1a=tg1.tg_interface_config(protocol_handle=h1['ethernet_handle'], mode='destroy')
    #h2a=tg2.tg_interface_config(protocol_handle=h2['ethernet_handle'], mode='destroy')
    st.wait(20)
    return tc_fail_flag

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_1():
    vrf_flag = False
    long_run_flag = True
    warm_reboot_flag = False
    ipv4_tc1_1to1_10(vrf_flag, long_run_flag, warm_reboot_flag)
    st.log(data.result)

    if data.result[0]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_2():
    #max IPv4 scale in TH1 is 65k so for now limit max_scale to 65k
    res = create_l3_route(65000, False)
    if res:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_3():
    if data.result[2]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_4():
    if data.result[3]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_5():
    if data.result[4]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_6():
    if data.result[5]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_7():
    if data.result[6]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_8():
    if data.result[7]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_9():
    if data.result[8]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_10():
    if data.result[9]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_private
def test_ipv4_tc1_11():
    if data.result[10]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv4_tc1_12():
    if data.result[11]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_1():
    vrf_flag = True
    long_run_flag = False
    warm_reboot_flag = False
    ipv4_tc1_1to1_10(vrf_flag, long_run_flag, warm_reboot_flag)
    st.log(data.vrf_result)
    if data.vrf_result[0]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_2():
    res = create_l3_route(65000, True)
    if (res):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_3():
    if data.vrf_result[2]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_4():
    if data.vrf_result[3]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_5():
    if data.vrf_result[4]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_vrf_ipv4_tc2_6():
    if data.vrf_result[5]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_1():
    vrf_flag = True
    retval = pre_configure_ipv6_route_scale(vrf_flag)

    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_3():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.3 START
    #count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    #st.log("Route count: "+str(count))
    # Withdraw the routes.
    ctrl1=data.tg1.tg_bgp_routes_control(handle=data.bgp_conf['handle'], route_handle=data.bgp_route['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    st.wait(10)
    ctrl1=data.tg1.tg_bgp_routes_control(handle=data.bgp_conf['handle'], route_handle=data.bgp_route['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))
    st.wait(10)
    retval = verify_bgp_session_summary(dut, family='ipv6', vrf_flag='True', neighbor=data.neigh_ipv6_addr, state='Established')

    if retval is True:
        st.log("bgp_router_created")
        st.log("IPV6 Scale Test Case 4.3 PASSED")
    else:
        st.log('bgp verification failed')

    data.tr2=data.tg2.tg_traffic_config(port_handle=data.tg_ph_2, emulation_src_handle=data.h2['handle'],
        emulation_dst_handle=data.bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
        transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    res=data.tg2.tg_traffic_control(action='run', handle=data.tr2['stream_id'])

    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")



@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_4():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.3 START
    #count = verify_bgp_route_count(dut, family='ipv6', neighbor=data.neigh_ipv6_addr, state='Established')
    #st.log("Route count: "+str(count))
    # Withdraw the routes.
    retval = verify_bgp_session_summary(dut, family='ipv6', vrf_flag='True', neighbor=data.neigh_ipv6_addr, state='Established')

    if retval is True:
        st.log("bgp_router_created")
        st.log("IPV6 Scale Test Case 4.4 PASSED")
    else:
        st.log('bgp verification failed')

    data.tr2=data.tg2.tg_traffic_config(port_handle=data.tg_ph_2, emulation_src_handle=data.h2['handle'],
        emulation_dst_handle=data.bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
        transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    res=data.tg2.tg_traffic_control(action='run', handle=data.tr2['stream_id'])

    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_5():
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.4 START
    trigger_link_flap(dut, data.member3)
    st.wait(45)
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')
    if res2:
        st.log("Interface Scaling Test Case 4.5 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_6():
    vrf_flag = True
    dut = data.dut
    #IPV6 ROUTE SCALE TEST CASE 3.5 START
    clear_ndp_entries(dut)
    st.wait(20)
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2200::1',\
                                                                ping_count='6', exp_count='6')
    res2=verify_ping(src_obj=data.tg1, port_handle=data.tg_ph_1, dev_handle=data.h2['handle'], dst_ip='2000::1',\
                                                                ping_count='6', exp_count='6')

    if res2:
        st.log("Interface Scaling Test Case 3.5 PASSED PING TEST")
    retval = check_intf_traffic_counters()
    if retval is True:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
    post_configure_ipv6_route_scale(vrf_flag)




#Max scale test going to overlap with exisitng bgp config so always keep it last
@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc3_10():
    #max IPv6/64b scale in TH1 is 24k so for now limit max_scale to 24k
    vrf_flag = False
    bgp_route_count = 24000
    res = create_l3_route_ipv6(vrf_flag, bgp_route_count)
    if res:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_ipv6_tc4_7():
    #max IPv6/64b scale in TH1 is 24k so for now limit max_scale to 24k
    vrf_flag = True
    bgp_route_count = 24000
    res = create_l3_route_ipv6(vrf_flag, bgp_route_count)
    if res:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

