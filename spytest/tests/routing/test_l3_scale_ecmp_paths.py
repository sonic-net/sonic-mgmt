import os
import pytest
from collections import OrderedDict

from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select

import apis.common.asic as asicapi
import apis.switching.vlan as vapi
import apis.routing.ip as ipfeature
import apis.switching.mac as macapi
import apis.system.port as papi
import apis.routing.bgp as bgpfeature
import apis.routing.arp as arp_obj

def clear_arp_entries(dut):
    """
    This proc is to clear arp entries of the dut.
    :param dut: DUT Number
    :return:
    """
    st.config(dut, "sonic-clear arp".format())
    return

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
        print("ping output: %s" % (result))
        return True if int(result['tx']) == ping_count and  int(result['rx']) == exp_count else False
    return True

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P3")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P4")
    return (tg1, tg_ph_1, tg2, tg_ph_2)

def get_handles_1():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D1P3")
    tg4, tg_ph_4 = tgapi.get_handle_byname("T1D1P4")
    return (tg1, tg_ph_1, tg2, tg_ph_2, tg3, tg_ph_3, tg4, tg_ph_4)

def get_handles_2():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg_ph_1, tg2, tg_ph_2)

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def l3_scale_ecmp_paths_module_hooks(request):
    #add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1D2:4","D1T1:4","D2T1:1")
    data.start_ip_addr = "10.2.100.1/24"
    data.vlans = []
    data.dut = vars.D1
    data.dut1_start_ip_addr = "10.2.2.1/24"
    data.dut2_start_ip_addr = "10.2.2.2/24"
    data.v6_start_ip_addr = "2100:0:2::1/64"
    data.v6_dut2_start_ip_addr = "2100:0:2::2/64"
    data.v6_new_dut2_start_ip_addr = "2200:0:2::2/64"
    data.neigh_ip_addr = "10.2.2.2/24"
    data.start_ip_addr2 = "11.11.1.2/24"
    data.nexthop_start_ip_addr = "10.2.100.10/32"
    #data.nexthop_start_ip_addr = "10.2.101.10/32"
    #data.static_route = "200.1.0.0/24"
    #data.static_route = ["200.1.0.0/16"]
    data.static_route = "200.1.0.0/16"
    data.vlan_count = 16
    data.vlan_val = 100
    data.max_ecmp = 128
    data.base_val = 101
    data.src_ip_addr = "10.2.100.1"
    data.edit_index = 4
    data.ip_prefixlen = 24
    data.all_ports = st.get_all_ports(data.dut)
    data.free_member_ports = OrderedDict()
    data.tg_member_ports = OrderedDict()
    data.d1t1_ip_addr = "10.2.106.1"
    data.t1d1_ip_addr = "10.2.106.2"
    data.d1_ip_addr = "11.11.6.1/24"
    data.d2_ip_addr = "11.11.6.2/24"
    data.tg_start_ip_addr = "10.2.101.10/24"
    data.thresh = 12
    data.dut1_ports = [vars.D1D2P1,vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.dut2_ports = [vars.D2D1P1,vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.as_num = 100
    data.remote_as_num = 200
    data.new_as_num = 300
    data.routemap = "preferGlobal"
    data.vrf = "Vrf-Green"

    # create required random vlans excluding existing vlans

    # create required random vlans excluding existing vlans

    yield

def check_end_to_end_intf_traffic_counters():
    dut1 = vars.D1
    DUT_tx_value = papi.get_interface_counters(dut1, vars.D1T1P1, "tx_ok")
    for i in DUT_tx_value:
        p1_tx = i['tx_ok']
        p1_tx = p1_tx.replace(",","")
    st.log("tx_ok xounter value on DUT Inress port : {}".format(p1_tx))
    if (abs(int(float(p1_tx))) > 0):
        output = papi.get_interface_counters_all(dut1)
        entry1 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P1})
        for i in entry1:
            p1_txmt = i['tx_bps']
            p1_txmt = p1_txmt.replace(" MB/s","")
            p1_txmt = p1_txmt.replace(" KB/s","")
            p1_txmt = p1_txmt.replace(" B/s","")
        if (abs(int(float(p1_txmt))) == 0):
            st.show(dut1, "show arp")
            st.error("End to End traffic is Zero")
            return False
        else:
            st.log("End to End traffic is fine")
            return True
    else:
        st.error("End to End traffic is not fine")
        return False

def intf_traffic_stats(entry_tx):
    for i in entry_tx:
        p_txmt = i['tx_bps']
        p_txmt = p_txmt.replace(" MB/s","")
        p_txmt = p_txmt.replace(" KB/s","")
        p_txmt = p_txmt.replace(" B/s","")

    p_tx = abs(int(float(p_txmt)))
    return p_tx



def check_inter_dut_intf_traffic_counters():
    dut2 = vars.D2
    (dut1) = (data.dut)
    papi.clear_interface_counters(dut2)
    papi.clear_interface_counters(dut1)
    st.wait(5)
    output = papi.get_interface_counters_all(dut2)
    p1_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P1}))
    p2_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P2}))
    p3_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P3}))
    p4_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P4}))

    st.log("Inter Dut port stats  tx_ok xounter value on DUT Egress ports : {} {} {} {}".format(p1_tx, p2_tx, p3_tx, p4_tx))
    if (p1_tx == 0) | (p2_tx == 0) | (p3_tx == 0) | (p4_tx == 0):
        st.error("Error:Inter Dut port stats  tx_ok xounter value on DUT Egress ports : {} {} {} {}".format(p1_tx, p2_tx, p3_tx, p4_tx))
    else:
        st.log("Inter Dut port stats  tx_ok xounter value on DUT Egress ports - Non Zero")
        return True

    DUT_rx_value = papi.get_interface_counters(dut2, vars.D2T1P1, "rx_ok")
    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    st.log("rx_ok xounter value on DUT Inress port : {}".format(p1_rcvd))

    if (abs(int(float(p1_rcvd))) > 0):
        output = papi.get_interface_counters_all(dut2)
        entry1 = filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P1})
        entry2 = filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P2})
        entry3 = filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P3})
        entry4 = filter_and_select(output, ["tx_bps"], {'iface': vars.D2D1P4})
        for i in entry1:
            p1_txmt = i['tx_bps']
            p1_txmt = p1_txmt.replace(" MB/s","")
            p1_txmt = p1_txmt.replace(" KB/s","")
            p1_txmt = p1_txmt.replace(" B/s","")
        for i in entry2:
            p2_txmt = i['tx_bps']
            p2_txmt = p2_txmt.replace(" MB/s","")
            p2_txmt = p2_txmt.replace(" KB/s","")
            p2_txmt = p2_txmt.replace(" B/s","")
        for i in entry3:
            p3_txmt = i['tx_bps']
            p3_txmt = p3_txmt.replace(" MB/s","")
            p3_txmt = p3_txmt.replace(" KB/s","")
            p3_txmt = p3_txmt.replace(" B/s","")
        for i in entry4:
            p4_txmt = i['tx_bps']
            p4_txmt = p4_txmt.replace(" MB/s","")
            p4_txmt = p4_txmt.replace(" KB/s","")
            p4_txmt = p4_txmt.replace(" B/s","")

        st.log("Inter Dut port stats  tx_ok xounter value on DUT Egress ports : {} {} {} {}".format(p1_txmt, p2_txmt, p3_txmt, p4_txmt))
        if (abs(int(float(p1_txmt))) == 0) | (abs(int(float(p2_txmt))) == 0) | (abs(int(float(p3_txmt))) == 0) | (abs(int(float(p4_txmt))) == 0):
            st.show(dut1, "show arp")
            st.error("Inter Dut port stats  tx_ok xounter value on DUT Egress ports are non zero")
            return False
        else:
            st.log("All ECMP paths are utilized")
            return True
    else:
        st.error("rx_ok xounter value on DUT Inress port : {}".format(p1_rcvd))
        return False

def create_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap, vrf_flag):
    command = "route-map {} permit 10".format(routemap)
    st.vtysh_config(dut, command)
    command = "set ipv6 next-hop prefer-global"
    st.vtysh_config(dut, command)

def create_bgp_neighbor_config(dut, local_asn, neighbor_ip, remote_asn, routemap, keep_alive=60, hold=180, password=None, family="ipv6"):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param remote_asn:
    :param keep_alive:
    :param hold:
    :param password:
    :param family:
    :return:
    """
    st.log("Creating BGP neighbor ..")
    # Add validation for IPV4 / IPV6 address
    # config_router_bgp_mode(dut, local_asn)

    command = "neighbor {} remote-as {}".format(neighbor_ip, remote_asn)
    st.vtysh_config(dut, command)
    command = "neighbor {} timers {} {}".format(neighbor_ip, keep_alive, hold)
    st.vtysh_config(dut, command)
    if password:
        command = " neighbor {} password {}".format(neighbor_ip, password)
        st.vtysh_config(dut, command)
    # Gather the IP type using the validation result
    # ipv6 = False
    if family == "ipv6":
        command = "address-family ipv6 unicast"
        st.vtysh_config(dut, command)
        command = "neighbor {} activate".format(neighbor_ip)
        st.vtysh_config(dut, command)
        command = "neighbor {} route-map {} in".format(neighbor_ip, routemap)
        st.vtysh_config(dut, command)
        #command = "neighbor {} route-map {} out".format(neighbor_ip, routemap)
    return True




def check_intf_traffic_counters():
    (dut1) = (data.dut)
    papi.clear_interface_counters(dut1)
    st.wait(5)
    DUT_tx_value = papi.get_interface_counters(dut1, vars.D1T1P4, "tx_bps")

    for i in DUT_tx_value:
        p2_txmt = i['tx_bps']
        p2_txmt = p2_txmt.replace(" MB/s","")
        p2_txmt = p2_txmt.replace(" KB/s","")
        p2_txmt = p2_txmt.replace(" B/s","")

    st.log("tx_ok xounter value on DUT Egress port : {}".format(p2_txmt))

    if (abs(int(float(p2_txmt))) == 0):
        output = papi.get_interface_counters_all(dut1)
        entry1 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P4})
        for i in entry1:
            p2_txmt = i['tx_bps']
            p2_txmt = p2_txmt.replace(" MB/s","")
            p2_txmt = p2_txmt.replace(" KB/s","")
            p2_txmt = p2_txmt.replace(" B/s","")
        st.log("RETRY tx_ok xounter value on DUT Egress port : {}".format(p2_txmt))
        if (abs(int(float(p2_txmt))) == 0):
            st.show(dut1, "show arp")
            asicapi.dump_l3_egress(dut1)
            return False
        else:
            return True
    else:
        return True

def check_intf_traffic_bo_counters():
    (dut1) = (data.dut)
    papi.clear_interface_counters(dut1)
    st.wait(5)
    output = papi.get_interface_counters_all(dut1)
    p1_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P1}))
    p2_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P2}))
    p3_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P3}))
    p4_tx = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P4}))
    st.log("Inter Dut port stats  tx_ok xounter value on DUT Egress ports : {} {} {} {}".format(p1_tx, p2_tx, p3_tx, p4_tx))
    if (p2_tx == 0) | (p3_tx == 0) | (p4_tx == 0):
        st.log("Error:Inter Dut port stats  tx_ok xounter value on DUT Egress ports : {} {} {}".format(p2_tx, p3_tx, p4_tx))
    else:
        return True

    DUT_rx_value = papi.get_interface_counters(dut1, vars.D1T1P4, "rx_ok")
    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    st.log("rx_ok xounter value on DUT Inress port : {}".format(p1_rcvd))

    if (abs(int(float(p1_rcvd))) > 0):
        output = papi.get_interface_counters_all(dut1)
        entry1 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P1})
        entry2 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P2})
        entry3 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P3})
        entry4 = filter_and_select(output, ["tx_bps"], {'iface': vars.D1T1P4})
        for i in entry1:
            p1_txmt = i['tx_bps']
            p1_txmt = p1_txmt.replace(" MB/s","")
            p1_txmt = p1_txmt.replace(" KB/s","")
            p1_txmt = p1_txmt.replace(" B/s","")
        for i in entry2:
            p2_txmt = i['tx_bps']
            p2_txmt = p2_txmt.replace(" MB/s","")
            p2_txmt = p2_txmt.replace(" KB/s","")
            p2_txmt = p2_txmt.replace(" B/s","")
        for i in entry3:
            p3_txmt = i['tx_bps']
            p3_txmt = p3_txmt.replace(" MB/s","")
            p3_txmt = p3_txmt.replace(" KB/s","")
            p3_txmt = p3_txmt.replace(" B/s","")
        for i in entry4:
            p4_txmt = i['tx_bps']
            p4_txmt = p4_txmt.replace(" MB/s","")
            p4_txmt = p4_txmt.replace(" KB/s","")
            p4_txmt = p4_txmt.replace(" B/s","")

        st.log("RETRY tx_ok xounter value on DUT Egress ports : {} {} {} {}".format(p1_txmt, p2_txmt, p3_txmt, p4_txmt))
        if (abs(int(float(p2_txmt))) == 0) | (abs(int(float(p3_txmt))) == 0) | (abs(int(float(p4_txmt))) == 0):
            st.show(dut1, "show arp")
            return False
        else:
            return True
    else:
        return False



def l3_max_route_max_path_scaling_tc(max_paths, max_routes, use_config_file, family="ipv4"):
    (dut) = (data.dut)
    #count = 0
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    #intf_ip_addr = data.dut1_start_ip_addr
    #intf_ip_addr2 = data.start_ip_addr2
    #nexthop = data.nexthop_start_ip_addr
    vrf_flag = False
    member_dut1 = vars.D1T1P1
    member_dut2 = vars.D2T1P1
    # L3 INTF SCALING TEST CASE 1.1 START
    #json_path = os.getcwd()
    apply_file = False

    if apply_file is False:
        ipfeature.clear_ip_configuration(st.get_dut_names())
        vapi.clear_vlan_configuration(st.get_dut_names())
        st.banner("Started doing the needed config.")
        cmd = "config vlan range add 2 129"
        st.config(dut, cmd)
        st.config(dut2, cmd)
        command = "config vlan member add 2 {}".format(member_dut1)
        st.config(dut, command)
        command = "config vlan member add 2 {}".format(member_dut2)
        st.config(dut2, command)
        max_vlan = max_paths/4
        base_vlan = 3
        max_vlan = max_vlan - base_vlan
        v_range_t = str(base_vlan) + " " + str(base_vlan + max_vlan )
        vapi.config_vlan_range_members(dut1, v_range_t, data.dut1_ports[0])
        vapi.config_vlan_range_members(dut2, v_range_t, data.dut2_ports[0])
        base_range = 1
        max_range = 4
        max_vlan = max_paths/4
        incr_vlan = max_paths/4
        for index in range(base_range, max_range):
            base_vlan = max_vlan + 1
            max_vlan = max_vlan + incr_vlan
            #max_vlan = max_vlan + 32
            v_range_t = str(base_vlan) + " " + str(max_vlan)
            vapi.config_vlan_range_members(dut1, v_range_t, data.dut1_ports[index])
            vapi.config_vlan_range_members(dut2, v_range_t, data.dut2_ports[index])

        ip_addr = data.dut1_start_ip_addr
        ip_addr2 = data.dut2_start_ip_addr
        v6_ip_addr = data.v6_start_ip_addr
        v6_ip_addr2 = data.v6_new_dut2_start_ip_addr
        ix_vlan_val = 2
        #command = "config interface ip add "+ "Vlan" + str(data.vlan_val) + " " + ip_addr+'/24'
        if family == "ipv4":
            command1 = "config interface ip add "+ "Vlan" + str(ix_vlan_val) + " " + ip_addr
            command2 = "config interface ip add "+ "Vlan" + str(ix_vlan_val) + " " + ip_addr2
        else:
            command1 = "config interface ip add "+ "Vlan" + str(ix_vlan_val) + " " + v6_ip_addr
            command2 = "config interface ip add "+ "Vlan" + str(ix_vlan_val) + " " + v6_ip_addr2
        st.config(dut1, command1)
        st.config(dut2, command2)
        ip_addr2 = data.dut2_start_ip_addr
        base_vlan = 3
        max_vlan = max_paths + 1
        #max_vlan = 130
        for index in range(base_vlan, max_vlan):
            if family == "ipv4":
                (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")
                (_, ip_addr2) = ipfeature.increment_ip_addr(ip_addr2, "network")
                command = "config interface ip add "+ "Vlan" + str(index) + " " + ip_addr
                command_dut2 = "config interface ip add "+ "Vlan" + str(index) + " " + ip_addr2
            else:
                v6_tok = str(hex(index)[2:])
                v6_ip_addr = "2100:0:" + v6_tok + "::1/64"
                v6_ip_addr2 = "2100:0:" + v6_tok + "::2/64"
                command = "config interface ip add "+ "Vlan" + str(index) + " " + v6_ip_addr
                command_dut2 = "config interface ip add "+ "Vlan" + str(index) + " " + v6_ip_addr2
            st.config(dut, command)
            st.config(dut2, command_dut2)

    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles_2()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.2.2', gateway='10.2.2.1', arp_send_req='1')
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.2.2',  gateway='10.2.2.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='2', arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')
    if family == "ipv4":
        h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.2.3',
                  gateway='10.2.2.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='2', arp_send_req='1')
        arp_obj.show_arp(dut)
        h2=tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='10.2.2.4',
                  gateway='10.2.2.2', src_mac_addr='00:0b:01:00:00:01', vlan='1', vlan_id='2', arp_send_req='1')
        arp_obj.show_arp(dut2)
    else:
        h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr='2100:0:2::3',
                  ipv6_gateway='2100:0:2::1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='2', arp_send_req='1')
        st.show(dut, "show ndp")
        arp_obj.show_arp(dut)
        h2=tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr='2200:0:2::4',
                  ipv6_gateway='2200:0:2::2', src_mac_addr='00:0b:01:00:00:01', vlan='1', vlan_id='2', arp_send_req='1')
        st.show(dut2, "show ndp")
        arp_obj.show_arp(dut2)

    if family == "ipv4":
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        bgpfeature.create_bgp_router(dut2, data.new_as_num, '')
        dut1_neigh_ip_addr = data.neigh_ip_addr
        dut2_neigh_ip_addr = data.dut1_start_ip_addr
        #formatted_dut1_neigh_ip_addr = dut1_neigh_ip_addr.replace("/24","")
        #formatted_dut2_neigh_ip_addr = dut2_neigh_ip_addr.replace("/24","")
        formatted_dut1_neigh_ip_addr = "10.2.2.3"
        bgpfeature.create_bgp_neighbor(dut, data.as_num, formatted_dut1_neigh_ip_addr, data.remote_as_num)

        (_, dut1_neigh_ip_addr) = ipfeature.increment_ip_addr(dut1_neigh_ip_addr, "network")
        (_, dut2_neigh_ip_addr) = ipfeature.increment_ip_addr(dut2_neigh_ip_addr, "network")
        base_vlan = 3
        max_vlan = max_paths + 1
        #max_vlan = 130
        # The below neighbor config is for inter dut links ibgp
        for index in range(base_vlan, max_vlan):
            formatted_dut1_neigh_ip_addr = dut1_neigh_ip_addr.replace("/24","")
            bgpfeature.create_bgp_neighbor(dut, data.as_num, formatted_dut1_neigh_ip_addr, data.new_as_num)
            (_, dut1_neigh_ip_addr) = ipfeature.increment_ip_addr(dut1_neigh_ip_addr, "network")
            formatted_dut2_neigh_ip_addr = dut2_neigh_ip_addr.replace("/24","")
            bgpfeature.create_bgp_neighbor(dut2, data.new_as_num, formatted_dut2_neigh_ip_addr, data.as_num)
            (_, dut2_neigh_ip_addr) = ipfeature.increment_ip_addr(dut2_neigh_ip_addr, "network")

        conf_var = { 'mode'                  : 'enable',
                     'active_connect_enable' : '1',
                     'local_as'              : '200',
                     'remote_as'             : '100',
                     'remote_ip_addr'        : '10.2.2.1'
                   }
        max_route_str = str(max_routes)
        route_var = { 'mode'       : 'add',
                      'num_routes' : max_route_str,
                      'prefix'     : '121.1.1.0',
                      'as_path'    : 'as_seq:1'
                    }
                    #'num_routes' : '30000',
        ctrl_start = { 'mode' : 'start'}
        ctrl_stop = { 'mode' : 'stop'}


        # Configuring the BGP router.
        bgp_rtr1 = tgapi.tg_bgp_config(tg = tg1,
            handle    = h1['handle'],
            conf_var  = conf_var,
            route_var = route_var,
            ctrl_var  = ctrl_start)

        st.log("BGP_HANDLE: "+str(bgp_rtr1))
        # Verified at neighbor.
        st.log("BGP neighborship established.")
        st.wait(10)

        def f1(d):
            st.config(d, "show bgp ipv4 summary")
            st.config(d, "show interface status")
            st.config(d, "show ip route | head -1000")
            arp_obj.show_arp(d)

        st.banner("ARP entries before traffic is initiated on Dut1 and Dut2")
        st.exec_each([dut, dut2], f1)

        #Port Counters

        tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')
    else:
        v6_dut1_neigh_ip_addr = "2100:0:2::3"
        create_bgp_neighbor_route_map_config(dut, data.as_num, v6_dut1_neigh_ip_addr, data.routemap, vrf_flag)
        create_bgp_neighbor_route_map_config(dut2, data.new_as_num, v6_dut1_neigh_ip_addr, data.routemap, vrf_flag)
        bgpfeature.create_bgp_router(dut, data.as_num, '')
        create_bgp_neighbor_config(dut, data.as_num, v6_dut1_neigh_ip_addr, data.remote_as_num, data.routemap)
        #link_bgp_neighbor_to_routemap(dut, data.as_num, v6_dut1_neigh_ip_addr, data.routemap, vrf_flag)
        bgpfeature.create_bgp_router(dut2, data.new_as_num, '')
        base_vlan = 3
        max_vlan = max_paths + 1
        for index in range(base_vlan, max_vlan):
            v6_tok = str(hex(index)[2:])
            v6_dut1_neigh_ip_addr = "2100:0:" + v6_tok + "::2"
            v6_dut2_neigh_ip_addr2 = "2100:0:" + v6_tok + "::1"
            create_bgp_neighbor_config(dut, data.as_num, v6_dut1_neigh_ip_addr, data.new_as_num, data.routemap)
            create_bgp_neighbor_config(dut2, data.new_as_num, v6_dut2_neigh_ip_addr2, data.as_num, data.routemap)
            #bgpfeature.create_bgp_neighbor(dut, data.as_num, v6_dut1_neigh_ip_addr, data.new_as_num, family="ipv6")
            #bgpfeature.create_bgp_neighbor(dut2, data.new_as_num, v6_dut2_neigh_ip_addr2, data.as_num, family="ipv6")

        bgp_conf=tg2.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',
            active_connect_enable='1', local_as='200', remote_as='100', remote_ipv6_addr='2100:0:2::1')
        max_route_str = str(max_routes)

        bgp_route=tg2.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
            num_routes=max_route_str, prefix='3300:0:0:2::1', as_path='as_seq:1')
        tg2.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

        def f1(d):
            st.config(d, "show run bgp")
            st.config(d, "show ndp")
            st.config(d, "show bgp ipv6 summary")
            st.config(d, "show ipv6 route | head -1000")
            arp_obj.show_arp(d)
        st.banner("ARP entries before traffic is initiated on Dut1 and Dut2")
        st.exec_each([dut, dut2], f1)

        tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
            emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
            transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

        #tr1=tg1.tg_traffic_config(port_handle=tg_ph_2, mac_src='00:11:01:00:00:01', mac_dst='80:a2:35:97:eb:c1',
        # ipv6_dst_mode='increment', ipv6_dst_count=200, ipv6_dst_step='::1',ipv6_src_addr='2200:0:2::5',
        # ipv6_dst_addr='3300:0:0:2::1',  l3_protocol='ipv6', l2_encap='ethernet_ii_vlan', vlan_id='2',
        # vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed',
        # rate_pps=512000, enable_stream_only_gen='1')

    tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    ret1 = check_inter_dut_intf_traffic_counters()
    ret2 = check_end_to_end_intf_traffic_counters()
    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    st.banner("ARP entries in both DUT's after traffic is stopped")
    st.exec_each([dut, dut2], arp_obj.show_arp)

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    if family == "ipv4":
        tgapi.tg_bgp_config(tg = tg1, handle = bgp_rtr1['conf']['handle'], ctrl_var=ctrl_stop)
    else:
        tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')

    #import pdb;pdb.set_trace()
    if apply_file is False:
        ip_addr = data.dut1_start_ip_addr
        ip_addr2 = data.dut2_start_ip_addr
        st.log("Un-Config previously config")
        base_range = 2
        max_range = max_paths + 1
        for index in range(base_range, max_range):
            if family == "ipv4":
                command1 = "config interface ip remove "+ "Vlan" + str(index) + " " + ip_addr
                command2 = "config interface ip remove "+ "Vlan" + str(index) + " " + ip_addr2
                (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")
                (_, ip_addr2) = ipfeature.increment_ip_addr(ip_addr2, "network")
            else:
                v6_tok = str(hex(index)[2:])
                if index == 2:
                    v6_ip_addr2 = "2200:0:" + v6_tok + "::2/64"
                else:
                    v6_ip_addr2 = "2100:0:" + v6_tok + "::2/64"
                v6_ip_addr = "2100:0:" + v6_tok + "::1/64"
                command1 = "config interface ip remove "+ "Vlan" + str(index) + " " + v6_ip_addr
                command2 = "config interface ip remove "+ "Vlan" + str(index) + " " + v6_ip_addr2
            st.config(dut, command1)
            st.config(dut2, command2)
        max_vlan = max_paths/4
        base_vlan = 3
        max_vlan = max_vlan - base_vlan

        v_range_t = str(base_vlan) + " " + str(base_vlan + max_vlan )
        vapi.config_vlan_range_members(dut1, v_range_t, data.dut1_ports[0], config='del')
        vapi.config_vlan_range_members(dut2, v_range_t, data.dut2_ports[0], config='del')
        base_range = 1
        max_range = 4
        max_vlan = max_paths/4
        incr_vlan = max_paths/4
        for index in range(base_range, max_range):
            base_vlan = max_vlan + 1
            #max_vlan = max_vlan + 32
            max_vlan = max_vlan + incr_vlan
            v_range_t = str(base_vlan) + " " + str(max_vlan)
            vapi.config_vlan_range_members(dut1, v_range_t, data.dut1_ports[index], config='del')
            vapi.config_vlan_range_members(dut2, v_range_t, data.dut2_ports[index], config='del')
        cmd = "config vlan range del 2 129"
        st.config(dut, cmd)
        my_cmd = "no router bgp {}".format(data.as_num)
        st.vtysh_config(dut, my_cmd)
        my_cmd = "no router bgp {}".format(data.new_as_num)
        st.vtysh_config(dut2, my_cmd)

    st.debug("ret1: {} , ret2: {}".format(ret1, ret2))
    if ret1 is True and ret2 is True:
        ret = True
        st.log("Test Case PASSED")
    else:
        ret = False
        st.log("Test Case FAILED")
    st.log("operation_successful")
    return ret



def l3_ecmp_scaling_tc(max_ecmp, use_config_file):
    (dut) = (data.dut)
    count = 0
    #intf_ip_addr = data.start_ip_addr
    #intf_ip_addr2 = data.start_ip_addr2
    nexthop = data.nexthop_start_ip_addr
    member3 = vars.D1T1P3
    member4 = vars.D1T1P4
    # L3 INTF SCALING TEST CASE 1.1 START
    json_path = os.getcwd()
    apply_file = False
    if use_config_file is True:
        apply_file = True

    json_apply_path = json_path+"/routing/128_ecmp_config_db.json"
    #frr_apply_path = json_path+"/routing/64_ecmp_sr_config.frr"
    if apply_file is True:
        st.apply_files(dut, [json_apply_path])
        #st.apply_files(dut, [json_apply_path, frr_apply_path])
    max_range = data.base_val+max_ecmp
    base_range = data.base_val

    if apply_file is False:
        ipfeature.clear_ip_configuration(st.get_dut_names())
        command = "config vlan add {}".format(data.vlan_val)
        st.config(dut, command)
        command = "config vlan member add {} {}".format(data.vlan_val, member3)
        st.config(dut, command)
        ip_addr = data.start_ip_addr
        #command = "config interface ip add "+ "Vlan" + str(data.vlan_val) + " " + ip_addr+'/24'
        command = "config interface ip add "+ "Vlan" + str(data.vlan_val) + " " + ip_addr
        st.config(dut, command)
        for index in range(base_range, max_range):
            command = "config vlan add {}".format(index)
            st.config(dut, command)
            command = "config vlan member add {} {}".format(index, member3)
            st.config(dut, command)
            (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")
            command = "config interface ip add "+ "Vlan" + str(index) + " " + ip_addr
            st.config(dut, command)
        tg_vlan = 101
        command = "config vlan member del {} {}".format(tg_vlan, member3)
        st.config(dut, command)
        command = "config vlan member add {} {}".format(tg_vlan, member4)
        st.config(dut, command)

    for index in range(base_range, max_range):
      #vapi.add_member(dut, data.vlans[index], member, True)
      (_, nexthop) = ipfeature.increment_ip_addr(nexthop, "network")
      nexthop1 = nexthop
      formatted_next_hop = nexthop1.replace("/32","")
      ipfeature.create_static_route(dut, formatted_next_hop, data.static_route)
    # L3 INTF SCALING TEST CASE 1.1 END


    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    # L3 traffic streams
    #For now Spirent link with 100G is not working , so the below code from START to END just books spirent port, it will be rectified
    # once infra team provides support for RS-FEC
    #START
    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles()
    #import pdb;pdb.set_trace()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.101.10', gateway='10.2.101.1', count='8', gateway_step='0.0.1.0', netmask='255.255.255.0', vlan='1', vlan_id='101', vlan_id_count='8', intf_ip_addr_step='0.0.1.0', arp_send_req='1')
    #h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='10.2.109.10', gateway='10.2.109.1', count='8', gateway_step='0.0.1.0', netmask='255.255.255.0', vlan='1', vlan_id='109', vlan_id_count='7', intf_ip_addr_step='0.0.1.0', arp_send_req='1')
    vid_count = max_ecmp-1
    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.102.10',  gateway='10.2.102.1', src_mac_addr='00:0c:01:00:00:01', vlan='1', vlan_id='102', count=vid_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    h2=tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='10.2.101.10',  gateway='10.2.101.1', src_mac_addr='00:0d:01:00:00:01', vlan='1', vlan_id='101', arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')
    #h2=tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='10.2.109.10',  gateway='10.2.109.1', src_mac_addr='00:0c:01:00:00:01', vlan='1', vlan_id='109', vlan_id_count='8', arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')
    h3=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.100.10', gateway='10.2.100.1', netmask='255.255.255.0', vlan='1', vlan_id='100', arp_send_req='1')


    #tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h3['handle'], ip_dst_addr='200.1.0.1', ip_dst_mode='increment', ip_dst_count='200', ip_dst_step='0.0.0.1', l3_protocol='ipv4', circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1')
    asicapi.dump_l3_egress(dut)
    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst='b8:6a:97:fd:b6:06', ip_dst_mode='increment', ip_dst_count=200, ip_dst_step='0.0.0.1',ip_src_addr='10.2.100.10', ip_dst_addr='200.1.0.1',  l3_protocol='ipv4', l2_encap='ethernet_ii_vlan', vlan_id='100', vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1')

    tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    count = 0
    #Port Counters
    st.wait(20)
    st.show(dut, "show arp")
    #Port Counters
    ret = check_intf_traffic_counters()
    if ret is True:
        count = count+1
        st.log("Test Case 1.14 PASSED")

    tg1.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    h4=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.2.101.10',  gateway='10.2.101.1', src_mac_addr='00:0e:01:00:00:01', vlan='1', vlan_id='101', arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    tg_vlan = 101
    command = "config vlan member del {} {}".format(tg_vlan, member4)
    st.config(dut, command)
    command = "config vlan member add {} {}".format(tg_vlan, member3)
    st.config(dut, command)

    tg_intf_ip_addr = data.tg_start_ip_addr
    max_range = data.base_val+max_ecmp
    base_range = data.base_val+1
    for index in range(base_range, max_range):
      data.thresh = 4
      command = "config vlan member del {} {}".format(index, member3)
      st.config(dut, command)
      command = "config vlan member add {} {}".format(index, member4)
      st.config(dut, command)
      (_, tg_intf_ip_addr) = ipfeature.increment_ip_addr(tg_intf_ip_addr, "network")
      tg_intf_ip_addr_x = tg_intf_ip_addr
      tg_formatted_intf_addr = tg_intf_ip_addr_x.replace("/24","")
      tg_formatted_gw_addr = tg_intf_ip_addr_x.replace("10/24","1")
      #ping_formatted_gw_addr = tg_intf_ip_addr_x.replace("10/24","1")
      tg_vlan=index
      st.log("tg_vlan: "+str(tg_vlan))
      st.log("tg_formatted_gw_addr: "+str(tg_formatted_gw_addr))
      st.log("tg_formatted_intf_addr: "+str(tg_formatted_intf_addr))
      h2=tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=tg_formatted_intf_addr,  gateway=tg_formatted_gw_addr, src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id=tg_vlan, vlan_id_count='1', arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')
      st.wait(3)
      #output = st.show(dut, "show arp")
      #Port Counters
      ret = check_intf_traffic_counters()
      if ret is True:
          count = count+1
          st.log("Test Case 1.14 PASSED")
      else:
          st.log('Traffic test Failed')

      tg1.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
      command = "config vlan member del {} {}".format(index, member4)
      st.config(dut, command)
      command = "config vlan member add {} {}".format(index, member3)
      st.config(dut, command)
      #res1=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip=ping_formatted_gw_addr,\
      #                                                          ping_count='6', exp_count='6')


    #tg1.tg_traffic_config(mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=30,
     #                        mac_src='00:00:00:00:00:01', mac_dst='00:00:00:00:00:02', ip_src_addr ='11.11.11.2',
      #                      ip_dst_addr = '11.11.12.2')

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    asicapi.dump_l3_egress(dut)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h3['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h4['handle'], mode='destroy')
    #import pdb;pdb.set_trace()
    if use_config_file is True:
        st.clear_config(dut1)
    # This code will not be needed if apply_file is True as config gets cleared already
    if apply_file is False:
        ip_addr = data.start_ip_addr

        base_range = data.base_val - 1
        #max_range = data.base_val+max_ecmp-1
        max_range = data.base_val+max_ecmp
        for index in range(base_range, max_range):
            command = "config interface ip remove "+ "Vlan" + str(index) + " " + ip_addr
            st.config(dut, command)
            command = "config vlan member del {} {}".format(index, member3)
            st.config(dut, command)
            command = "config vlan del {}".format(index)
            st.config(dut, command)
            (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")
        #del_vlan = max_range
        #command = "config interface ip remove "+ "Vlan" + str(del_vlan) + " " + ip_addr
        #st.config(dut, command)
        #command = "config vlan member del {} {}".format(del_vlan, member4)
        #st.config(dut, command)
        #command = "config vlan del {}".format(del_vlan)
        #st.config(dut, command)


    ret = False
    st.log("count: "+str(count))
    if count >= data.thresh:
        ret = True
        st.log("Test Case PASSED")
    else:
        ret = False
        st.log("Test Case FAILED")
    st.log("operation_successful")
    return ret

@pytest.mark.l3_scale_ut_ft
def test_ft_l3_Xecmp_scaling_tc():
    (dut) = (data.dut)
    max_ecmp_4 = data.max_ecmp/32
    ipfeature.clear_ip_configuration([dut])
    #use_config_file = False
    use_config_file = False
    ret = l3_ecmp_scaling_tc(max_ecmp_4, use_config_file)
    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case  FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")



@pytest.mark.l3_scale_ut_nr
def nest_l3_32ecmp_scaling_tc():
    (dut) = (data.dut)
    max_ecmp_32 = data.max_ecmp/4
    use_config_file = True
    ipfeature.clear_ip_configuration([dut])
    ret = l3_ecmp_scaling_tc(max_ecmp_32, use_config_file)
    if ret is True:
        st.log("Test Case 1.13 PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case 1.13 FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_long_run
def test_l3_64ecmp_scaling_tc():
    max_ecmp_64 = data.max_ecmp/2
    use_config_file = True
    ret = l3_ecmp_scaling_tc(max_ecmp_64, use_config_file)
    if ret is True:
        st.log("Test Case 1.14 PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case 1.14 FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_long_run
def test_l3_128ecmp_scaling_tc():
    max_ecmp_128 = data.max_ecmp
    use_config_file = True
    ret = l3_ecmp_scaling_tc(max_ecmp_128, use_config_file)

    if ret is True:
        st.log("Test Case 1.15 PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case 1.15 FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_ft
def test_max_v4_route_with_max_paths():
    (dut) = (data.dut)
    max_ecmp_16 = data.max_ecmp/8
    ipfeature.clear_ip_configuration([dut])
    use_config_file = False
    max_routes = 100
    ret = l3_max_route_max_path_scaling_tc(max_ecmp_16, max_routes, use_config_file)
    st.debug("ret : {}".format(ret))
    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case  FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_ft
def test_max_v6_route_with_max_paths():
    (dut) = (data.dut)
    max_ecmp_16 = data.max_ecmp/8
    ipfeature.clear_ip_configuration([dut])
    #use_config_file = False
    use_config_file = False
    family = "ipv6"
    max_routes = 100
    ret = l3_max_route_max_path_scaling_tc(max_ecmp_16, max_routes, use_config_file, family)
    st.debug("ret : {}".format(ret))
    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case  FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_ft_variant
def test_max_v4_route_with_max_paths_variant():
    (dut) = (data.dut)
    max_ecmp = data.max_ecmp
    ipfeature.clear_ip_configuration([dut])
    use_config_file = False
    max_routes = 65000
    ret = l3_max_route_max_path_scaling_tc(max_ecmp, max_routes, use_config_file)
    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case  FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_ft_variant
def test_max_v6_route_with_max_paths_variant():
    (dut) = (data.dut)
    max_ecmp = data.max_ecmp
    ipfeature.clear_ip_configuration([dut])
    #use_config_file = False
    use_config_file = False
    family = "ipv6"
    max_routes = 32000
    ret = l3_max_route_max_path_scaling_tc(max_ecmp, max_routes, use_config_file, family)
    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case  FAILED")
        st.report_fail("operation_failed")
    st.report_pass("operation_successful")




@pytest.mark.l3_scale_ut
def test_l3_ecmp_4paths_on_bo_tc():
    (dut) = (data.dut)
    #count = 0
    #intf_ip_addr = data.start_ip_addr
    #intf_ip_addr2 = data.start_ip_addr2
    #nexthop = data.nexthop_start_ip_addr
    nexthop = "10.2.101.10/32"
    member1 = vars.D1T1P1
    member2 = vars.D1T1P2
    member3 = vars.D1T1P3
    member4 = vars.D1T1P4
    apply_file = False

    ipfeature.clear_ip_configuration([dut])
    max_range = data.base_val+4
    base_range = data.base_val-1
    if apply_file is False:
        command = "config vlan range add 100 105"
        st.config(dut, command)
        command = "config vlan member add 100 {}".format(member4)
        st.config(dut, command)
        command = "config vlan member add 101 {}".format(member1)
        st.config(dut, command)
        command = "config vlan member add 102 {}".format(member2)
        st.config(dut, command)
        command = "config vlan member add 103 {}".format(member3)
        st.config(dut, command)
        command = "config vlan member add 104 {}".format(member4)
        st.config(dut, command)
        #ip_addr = data.start_ip_addr
        ip_addr = "10.2.100.1/24"
        for index in range(base_range, max_range):
            command = "config interface ip add "+ "Vlan" + str(index) + " " + ip_addr
            st.config(dut, command)
            (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")


    base_range = data.base_val
    max_range = data.base_val+3
    for index in range(base_range, max_range):
      (_, nexthop) = ipfeature.increment_ip_addr(nexthop, "network")
      nexthop1 = nexthop
      formatted_next_hop = nexthop1.replace("/32","")
      ipfeature.create_static_route(dut, formatted_next_hop, data.static_route)


    data.my_dut_list = st.get_dut_names()
    #dut1 = data.my_dut_list[0]

    (tg1, tg_ph_1, tg2, tg_ph_2, tg3, tg_ph_3, tg4, tg_ph_4) = get_handles_1()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_3)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_4)

    h0=tg4.tg_interface_config(port_handle=tg_ph_4, mode='config',
         intf_ip_addr='10.2.100.10',  gateway='10.2.100.1',
         src_mac_addr='00:0d:01:00:00:01', vlan='1', vlan_id='100',
         arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config',
         intf_ip_addr='10.2.101.10',  gateway='10.2.101.1',
         src_mac_addr='00:0d:02:00:00:01', vlan='1', vlan_id='101',
         arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config',
         intf_ip_addr='10.2.102.10',  gateway='10.2.102.1',
         src_mac_addr='00:0c:01:00:00:01', vlan='1', vlan_id='102',
         arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    h3=tg3.tg_interface_config(port_handle=tg_ph_3, mode='config',
         intf_ip_addr='10.2.103.10',  gateway='10.2.103.1',
         src_mac_addr='00:0c:02:00:00:01', vlan='1', vlan_id='103',
         arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    h4=tg4.tg_interface_config(port_handle=tg_ph_4, mode='config',
         intf_ip_addr='10.2.104.10',  gateway='10.2.104.1',
         src_mac_addr='00:0a:02:00:00:01', vlan='1', vlan_id='104',
         arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')

    mac_eth = macapi.get_sbin_intf_mac(vars.D1,'eth0')
    tr1=tg4.tg_traffic_config(port_handle=tg_ph_4, mac_src='00:11:01:00:00:01',
         mac_dst=mac_eth, ip_dst_mode='increment', ip_dst_count=200,
         ip_dst_step='0.0.0.1',ip_src_addr='10.2.100.10', ip_dst_addr='200.1.0.1',
         l3_protocol='ipv4', l2_encap='ethernet_ii_vlan', vlan_id='100',
         vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed',
         rate_pps=512000, enable_stream_only_gen='1')

    tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    #count = 0
    #Port Counters
    st.wait(20)
    st.show(dut, "show arp")
    #Port Counters
    ret = check_intf_traffic_bo_counters()
    if ret is True:
        st.log("Test Case PASSED")
    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h0['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    tg3.tg_interface_config(port_handle=tg_ph_3, handle=h3['handle'], mode='destroy')
    tg4.tg_interface_config(port_handle=tg_ph_4, handle=h4['handle'], mode='destroy')

    if apply_file is False:
        base_range = data.base_val-1
        ip_addr = data.start_ip_addr
        max_range = data.base_val+4
        for index in range(base_range, max_range):
            command = "config interface ip remove "+ "Vlan" + str(index) + " " + ip_addr
            st.config(dut, command)
            (_, ip_addr) = ipfeature.increment_ip_addr(ip_addr, "network")
        command = "config vlan member del 100 {}".format(member4)
        st.config(dut, command)
        command = "config vlan member del 101 {}".format(member1)
        st.config(dut, command)
        command = "config vlan member del 102 {}".format(member2)
        st.config(dut, command)
        command = "config vlan member del 103 {}".format(member3)
        st.config(dut, command)
        command = "config vlan member del 104 {}".format(member4)
        st.config(dut, command)
        command = "config vlan range del 100 105"
        st.config(dut, command)

    if ret is True:
        st.log("Test Case PASSED")
        st.report_pass("operation_successful")
    else:
        st.log("Test Case FAILED")
        st.report_fail("operation_failed")


