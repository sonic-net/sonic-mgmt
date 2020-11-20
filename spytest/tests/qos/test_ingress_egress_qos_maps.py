import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj
import apis.system.interface as intf_obj
import apis.routing.arp as arp_obj
import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj
import apis.qos.cos as cos_obj
import apis.qos.qos as qos_obj
import apis.system.reboot as reboot_obj
import apis.switching.portchannel as pc
import apis.system.switch_configuration as switching_conf

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def qos_maps_module_hooks(request):
    # add things at the start of this module
    global vars
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:2")
    qos_maps_variables()
    qos_maps_module_config(config='yes')
    tg_config()
    yield
    # add things at the end of this module"
    qos_maps_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def qos_maps_func_hooks(request):
    # add things at the start every test case
    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    # Clean up for IP configuration is required to run the next test case. So, adding the clean up in fucntion hooks
    if st.get_func_name(request) in ['test_ft_qosmaps_l2_intf', 'test_ft_qosmaps_remove_vlan_delete_map']:
        vlan_unconfig_l2()
    if ('test_ft_qosmaps_l2_lag' in st.get_func_name(request)):
        pc_unconfig_l2()
    if ('test_ft_qosmaps_l3_lag' in st.get_func_name(request)):
        pc_unconfig_l3()
    if ('test_ft_qosmaps_l3_vlan' in st.get_func_name(request)):
        vlan_unconfig_l3()
    if request.node.name in ['test_ft_qosmaps_l3_intf', 'ft_qosmaps_tc_dscp_intf_config_reload_and_warm_boot']:
        route_unconfig_l3()


def qos_maps_module_config(config='yes'):
    if config == 'yes':
        data.mac_addr = basic_obj.get_ifconfig_ether(vars.D1)
        data.dut_rt_int_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    else:
        st.log("Clearing IP config, qos config, VLAN config and resetting")
        ipfeature.clear_ip_configuration(st.get_dut_names())
        #ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
        vlan_obj.clear_vlan_configuration(vars.D1, thread=True)
        qos_obj.clear_qos_config(vars.D1)


def qos_maps_variables():
    # global data
    data.vlan_name_1 = "Vlan10"
    data.vlan_name_2 = "Vlan20"
    data.vlan_name_3 = "Vlan40"
    data.portchannel_1 = "PortChannel100"
    data.portchannel_2 = "PortChannel200"
    data.portchannel_3 = "PortChannel300"
    data.d1_p1_pc_members = vars.D1T1P1
    data.d1_p2_pc_members = vars.D1T1P2
    data.vlan_1 = 10
    data.vlan_2 = 20
    data.vlan_3 = 40
    data.ipv4_addr = ["10.10.10.1", "10.10.10.2", "20.20.20.1", "20.20.20.2", "30.30.30.1", "30.30.30.2", "40.40.40.1",
                      "40.40.40.2"]
    data.ipv6_addr = ["1001::1", "1001::2", "2001::1", "2001::2", "3001::1", "3001::2", "4001::1", "4001::2"]
    data.subnet = 24
    data.ipv6_subnet = 64

    data.obj_name = ['tc_dscp_intf_map', 'tc_dot1p_intf_map', 'dscp_tc_intf_map', 'dot1p_tc_intf_map',
                     'dot1p_tc_lag_map', 'tc_dot1p_lag_map', 'dscp_tc_lag_map', 'tc_dscp_lag_map', 'dscp_tc_vlan_map',
                     'tc_dscp_vlan_map']
    data.tc_to_dscp_map_dict = {'0': '15', '1': '10', '2': '35', '4': '32'}
    data.updated_tc_to_dscp_map_dict = {'0': '5', '1': '20', '2': '10', '4': '15'}

    data.tc_to_dot1p_map_dict = {'0': '3', '1,4': '5', '2': '4'}
    data.updated_tc_to_dot1p_map_dict = {'0': '1', '1': '2', '2': '3', '4': '6'}

    data.dscp_to_tc_map_dict = {'10': '2', '24': '4', '32': '0'}
    data.updated_dscp_to_tc_map_dict = {'10': '3', '24': '2', '32': '4'}

    data.dot1p_to_tc_map_dict = {'0': '2', '1': '4', '2': '3'}
    data.updated_dot1p_to_tc_map_dict = {'0': '3', '1': '2', '2': '4'}

    data.vlan_table_map = {'port': data.vlan_name_3, 'map': 'tc_to_dscp_map', 'obj_name': data.obj_name[9]}

    data.tc_to_dot1p_map = "TC_TO_DOT1P_MAP"
    data.tc_to_dscp_map = "TC_TO_DSCP_MAP"
    data.dscp_to_tc_map = "DSCP_TO_TC_MAP"

    data.traffic_duration = 3
    data.rate_percent = 100
    data.tg_src_mac = "00:00:00:00:00:01"
    data.tg_dst_mac = "00:00:00:00:00:02"
    data.tg_src_mac2 = "00:00:00:00:00:03"
    data.pkts_per_burst = "300"


def tg_config():
    st.log("Getting TG handlers")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg = data.tg1

    st.log("Reset and clear statistics of TG ports")
    data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1, data.tg_ph_2])
    data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_2])

    st.log("Creating TG streams")
    data.streams = {}

    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', frame_size=64,
                                       l2_encap='ethernet_ii_vlan', vlan_user_priority=2, high_speed_result_analysis=0,
                                       vlan='enable', vlan_id=data.vlan_1, mac_src=data.tg_src_mac,
                                       mac_dst=data.tg_dst_mac,
                                       pkts_per_burst=data.pkts_per_burst)
    data.streams['l2_stream_p2'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', frame_size=64,
                                       l2_encap='ethernet_ii_vlan', vlan_user_priority=1, high_speed_result_analysis=0,
                                       vlan='enable', vlan_id=data.vlan_1, mac_src=data.tg_src_mac,
                                       mac_dst=data.tg_dst_mac,
                                       pkts_per_burst=data.pkts_per_burst)
    data.streams['l2_stream_p1'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', high_speed_result_analysis=0,
                                       mac_src=data.tg_src_mac, mac_dst=data.dut_rt_int_mac, l3_protocol='ipv4',
                                       ip_dscp="24",
                                       ip_src_addr=data.ipv4_addr[1], ip_dst_addr=data.ipv4_addr[7],
                                       pkts_per_burst=data.pkts_per_burst, port_handle2=data.tg_ph_2)
    data.streams['ipv4_stream'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', high_speed_result_analysis=0,
                                       mac_src=data.tg_src_mac, mac_dst=data.dut_rt_int_mac, l3_protocol='ipv4',
                                       ip_dscp="24",
                                       ip_src_addr=data.ipv4_addr[5], ip_dst_addr=data.ipv4_addr[7],
                                       pkts_per_burst=data.pkts_per_burst, port_handle2=data.tg_ph_2)
    data.streams['ipv4_stream_pc'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', high_speed_result_analysis=0,
                                       l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_2, vlan_user_priority=1, vlan="enable",
                                       mac_src=data.tg_src_mac, mac_dst=data.dut_rt_int_mac, l3_protocol='ipv4', ip_dscp="24",
                                       ip_src_addr=data.ipv4_addr[3], ip_dst_addr=data.ipv4_addr[7],
                                       pkts_per_burst=data.pkts_per_burst, port_handle2=data.tg_ph_2)
    data.streams['ipv4_stream_vlan_priority_vlan'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', high_speed_result_analysis=0,
                                       mac_src=data.tg_src_mac, mac_dst=data.dut_rt_int_mac, l3_protocol='ipv6', ip_dscp="24",
                                       ipv6_src_addr=data.ipv6_addr[1], ipv6_dst_addr=data.ipv6_addr[7],
                                       pkts_per_burst=data.pkts_per_burst, port_handle2=data.tg_ph_2)
    data.streams['ipv6_stream'] = stream['stream_id']

def ping_ipv6_interface(ingress_tg_ipv6, ingress_gateway_ipv6, egress_tg_ipv6, egress_gateway_ipv6):
    h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', ipv6_intf_addr=ingress_tg_ipv6, \
                                     ipv6_prefix_length="64", ipv6_gateway=ingress_gateway_ipv6,
                                     src_mac_addr='00:0a:01:01:23:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_2, mode='config', ipv6_intf_addr=egress_tg_ipv6, \
                                     ipv6_prefix_length="64", ipv6_gateway=egress_gateway_ipv6,
                                     src_mac_addr='00:0a:01:01:23:02', arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=h1['handle'],
                            dst_ip=ingress_gateway_ipv6, \
                            ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_2, dev_handle=h2['handle'],
                            dst_ip=egress_gateway_ipv6, \
                            ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    # if not arp_obj.show_ndp(vars.D1, ingress_tg_ipv6):
    #    st.report_fail("ARP_entry_dynamic_entry_fail", ingress_tg_ipv6, vars.D1)


def ping_ipv4_interface(ingress_tg_ip, ingress_gateway_ip, egress_tg_ip, egress_gateway_ip):
    h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=ingress_tg_ip, \
                                     gateway=ingress_gateway_ip, src_mac_addr=data.tg_src_mac, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=egress_tg_ip, \
                                     gateway=egress_gateway_ip, src_mac_addr=data.tg_src_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT's TGen connected IPV4 interface.
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=h1['handle'],
                            dst_ip=ingress_gateway_ip, \
                            ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    res1 = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_2, dev_handle=h2['handle'],
                             dst_ip=egress_gateway_ip, \
                             ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res1))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    if not arp_obj.show_arp(vars.D1):
        st.log("ARP table is not updated with dynamic entries")


def ping_ipv4_vlan_interface(ingress_tg_ip, ingress_gateway_ip, egress_tg_ip, egress_gateway_ip):
    h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=ingress_tg_ip, \
                                     gateway=ingress_gateway_ip, src_mac_addr=data.tg_src_mac, vlan = 1, vlan_id = data.vlan_2, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = data.tg.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=egress_tg_ip, \
                                     gateway=egress_gateway_ip, src_mac_addr=data.tg_src_mac2, vlan = 1, vlan_id = data.vlan_3, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT's TGen connected IPV4 interface.
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=h1['handle'],
                            dst_ip=ingress_gateway_ip, \
                            ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    res1 = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_2, dev_handle=h2['handle'],
                             dst_ip=egress_gateway_ip, \
                             ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res1))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    if not arp_obj.show_arp(vars.D1):
        st.log("ARP table is not updated with dynamic entries")



def configuring_ipv4_and_ipv6_address(dut, interface='', ipv6_add='', ipv6_sub='', ipv4_add='', ipv4_sub=''):
    #st.log("About to add ipv6 address on interface")
    #ip_obj.config_ip_addr_interface(dut, interface, ipv6_add, ipv6_sub, family="ipv6")
    #if not ip_obj.verify_interface_ip_address(vars.D1, interface, "{}/{}".format(ipv6_add, ipv6_sub), family="ipv6"):
    #    st.report_fail("ip_routing_int_create_fail", interface)
    st.log("About to add ipv4 address on interface")
    ip_obj.config_ip_addr_interface(dut, interface, ipv4_add, ipv4_sub, family="ipv4")
    if not ip_obj.verify_interface_ip_address(vars.D1, interface, "{}/{}".format(ipv4_add, ipv4_sub),
                                              family="ipv4"):
        st.report_fail("ip_routing_int_create_fail", interface)


def clear_intf_queue_counters():
    intf_obj.clear_interface_counters(vars.D1)
    intf_obj.clear_queue_counters(vars.D1)
    qos_obj.clear_qos_queue_counters(vars.D1)


def vlan_config_l2():
    vlan_obj.create_vlan(vars.D1, data.vlan_1)
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan_1, [vars.D1T1P1, vars.D1T1P2], tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail")
    if vlan_obj.verify_vlan_brief(vars.D1, data.vlan_1, tagged=True):
        st.report_fail("vlan_create_fail")


def vlan_unconfig_l2():
    vlan_obj.delete_vlan_member(dut=vars.D1, vlan=data.vlan_1, port_list=[vars.D1T1P1, vars.D1T1P2], tagging_mode=True)
    vlan_obj.delete_vlan(dut=vars.D1, vlan_list=[data.vlan_1])


def pc_config_l2():
    pc.create_portchannel(vars.D1, [data.portchannel_1, data.portchannel_2], static=True)
    vlan_obj.create_vlan(vars.D1, data.vlan_1)
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan_1, [data.portchannel_1, data.portchannel_2], tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail")
    pc.add_del_portchannel_member(vars.D1, data.portchannel_1, data.d1_p1_pc_members, 'add')
    pc.add_del_portchannel_member(vars.D1, data.portchannel_2, data.d1_p2_pc_members, 'add')


def pc_unconfig_l2():
    vlan_obj.delete_vlan_member(dut=vars.D1, vlan=data.vlan_1, port_list=[data.portchannel_1, data.portchannel_2],
                                tagging_mode=True)
    pc.add_del_portchannel_member(vars.D1, data.portchannel_1, data.d1_p1_pc_members, 'del')
    pc.add_del_portchannel_member(vars.D1, data.portchannel_2, data.d1_p2_pc_members, 'del')
    vlan_obj.delete_vlan(dut=vars.D1, vlan_list=[data.vlan_1])
    pc.clear_portchannel_configuration(vars.D1)


def pc_config_l3():
    pc.create_portchannel(vars.D1, [data.portchannel_1, data.portchannel_2], static=True)
    pc.add_del_portchannel_member(vars.D1, data.portchannel_1, data.d1_p1_pc_members, 'add')
    pc.add_del_portchannel_member(vars.D1, data.portchannel_2, data.d1_p2_pc_members, 'add')
    configuring_ipv4_and_ipv6_address(vars.D1, data.portchannel_1, data.ipv6_addr[4], data.ipv6_subnet,
                                      data.ipv4_addr[4], data.subnet)
    configuring_ipv4_and_ipv6_address(vars.D1, data.portchannel_2, data.ipv6_addr[6], data.ipv6_subnet,
                                      data.ipv4_addr[6], data.subnet)


def pc_unconfig_l3():
    ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    pc.add_del_portchannel_member(vars.D1, data.portchannel_1, data.d1_p1_pc_members, 'del')
    pc.add_del_portchannel_member(vars.D1, data.portchannel_2, data.d1_p2_pc_members, 'del')
    pc.clear_portchannel_configuration(vars.D1)


def vlan_config_l3():
    vlan_obj.create_vlan(dut=vars.D1, vlan_list=[data.vlan_2, data.vlan_3])
    vlan_obj.add_vlan_member(dut=vars.D1, vlan=data.vlan_2, port_list=[vars.D1T1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(dut=vars.D1, vlan=data.vlan_3, port_list=[vars.D1T1P2], tagging_mode=True)
    configuring_ipv4_and_ipv6_address(vars.D1, data.vlan_name_2, data.ipv6_addr[2], data.ipv6_subnet, data.ipv4_addr[2],
                                      data.subnet)
    configuring_ipv4_and_ipv6_address(vars.D1, data.vlan_name_3, data.ipv6_addr[6], data.ipv6_subnet, data.ipv4_addr[6],
                                      data.subnet)
    vlan_obj.show_vlan_brief(dut=vars.D1)


def vlan_unconfig_l3():
    ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    vlan_obj.delete_vlan_member(dut=vars.D1, vlan=data.vlan_2, port_list=[vars.D1T1P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut=vars.D1, vlan=data.vlan_3, port_list=[vars.D1T1P2], tagging_mode=True)
    vlan_obj.delete_vlan(dut=vars.D1, vlan_list=[data.vlan_2, data.vlan_3])
    vlan_obj.clear_vlan_configuration(vars.D1)


def route_config_l3():
    ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    configuring_ipv4_and_ipv6_address(vars.D1, vars.D1T1P1, data.ipv6_addr[0], data.ipv6_subnet, data.ipv4_addr[0],
                                      data.subnet)
    configuring_ipv4_and_ipv6_address(vars.D1, vars.D1T1P2, data.ipv6_addr[6], data.ipv6_subnet, data.ipv4_addr[6],
                                      data.subnet)


def route_unconfig_l3():
    ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')


def send_traffic_and_Verify_capture(stream, port, offset, value):
    data.tg.tg_traffic_control(action='clear_stats')
    st.log("start capturing the traffic on egress port")
    data.tg.tg_packet_control(port_handle=port, action='start')
    st.log("Sending traffic from ingress port")
    data.tg.tg_traffic_control(action='run', stream_handle=stream, enable_arp=0)
    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=stream)
    st.log("stop capturing the traffic on egress port")
    data.tg.tg_packet_control(port_handle=port, action='stop')
    pkts_captured = data.tg.tg_packet_stats(port_handle=port, format='var', output_type='hex')
    capture_result = tgapi.validate_packet_capture(tg_type=data.tg.tg_type, pkt_dict=pkts_captured,
                                                   offset_list=[offset], value_list=[value])
    if not capture_result:
        st.error("Error: dscp value is not found in captured packet")
        return False
    else:
        st.log('dscp value capture verification passed')
        return True


def send_verify_queue_counters(stream, port, queue_name, value):
    data.tg.tg_traffic_control(action='clear_stats')
    data.tg.tg_traffic_control(action='run', stream_handle=stream)
    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=stream)

    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=port, queue_name=queue_name, param_list=['pkts_count'],
                                             val_list=[value], tol_list=['20']):
        st.error('Error: qos queue counter verification failed')
        return False
    else:
        st.log('qos queue counter verification passed')
        return True


### configure, bind and unbind QOS Maps
def configure_qos_map_bind_update_clear(dut, obj_name, map_dict_name, port, map_name, update_map='no', clear_map='no'):
    if map_dict_name == 'tc_to_dscp':
        map_dict = data.tc_to_dscp_map_dict
        updated_map_dict = data.updated_tc_to_dscp_map_dict
        config_table_type = cos_obj.config_tc_to_dscp_map
    elif map_dict_name == 'tc_to_dot1p':
        map_dict = data.tc_to_dot1p_map_dict
        updated_map_dict = data.updated_tc_to_dot1p_map_dict
        config_table_type = cos_obj.config_tc_to_dot1p_map
    elif map_dict_name == 'dscp_to_tc':
        map_dict = data.dscp_to_tc_map_dict
        updated_map_dict = data.updated_dscp_to_tc_map_dict
        config_table_type = cos_obj.config_dscp_to_tc_map
    elif map_dict_name == 'dot1p_to_tc':
        map_dict = data.dot1p_to_tc_map_dict
        updated_map_dict = data.updated_dot1p_to_tc_map_dict
        config_table_type = cos_obj.config_dot1p_to_tc_map
    final_map = {'port': port, 'map': map_name, 'obj_name': obj_name}
    if update_map == 'yes':
        if not config_table_type(dut, obj_name, updated_map_dict):
            st.error("Failed to update the configured qos map of type {}".format(map_dict_name))
    elif clear_map == 'yes':
        if not cos_obj.clear_port_qos_map_all(dut, final_map):
            st.error("Failed to unbind the configured qos maps of type {} on interface {}".format(map_dict_name, port))
        if not cos_obj.clear_qos_map_table(dut, final_map):
            st.error("Failed to unconfigure the qos map table of type {}".format(map_dict_name))
    else:
        if not config_table_type(dut, obj_name, map_dict):
            st.error("Failed to configure the qos map of type {}".format(map_dict_name))
        if not cos_obj.config_port_qos_map_all(dut, final_map):
            st.error("Failed to bind the configured qos maps of type {} on interface {}".format(map_dict_name, port))

####L2 tests using physical intf and lag###
@pytest.mark.qos_map_regression
def test_ft_qosmaps_l2_intf():
    result1 = result2 = 0
    vlan_config_l2()
    #verify_qosmaps_dot1p_tc_intf
    st.banner("test case: ft_qosmaps_dot1p_tc_intf")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[3], 'dot1p_to_tc', vars.D1T1P1, 'dot1p_to_tc_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dot1p_to_tc_map', data.obj_name[3], {'0': '2', '1': '4', '2': '3'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    clear_intf_queue_counters()
    if not send_verify_queue_counters(stream=data.streams['l2_stream_p2'], port=vars.D1T1P2, queue_name="MC13",
                                      value=data.pkts_per_burst):
        st.error("Failed to verify queue counters")
        result1 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[3], 'dot1p_to_tc', vars.D1T1P1, 'dot1p_to_tc_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dot1p_to_tc_map', data.obj_name[3], {'0': '3', '1': '2', '2': '4'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    clear_intf_queue_counters()
    if not send_verify_queue_counters(stream=data.streams['l2_stream_p2'], port=vars.D1T1P2, queue_name="MC14",
                                      value=data.pkts_per_burst):
        st.error("Failed to verify queue counters")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[3], 'dot1p_to_tc', vars.D1T1P1, 'dot1p_to_tc_map',
                                        clear_map='yes')
    clear_intf_queue_counters()
    if not send_verify_queue_counters(stream=data.streams['l2_stream_p2'], port=vars.D1T1P2, queue_name="MC12",
                                      value=data.pkts_per_burst):
        st.error("Failed to verify queue counters")
        result1 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_dot1p_tc_intf', 'qos_map_test_pass', 'for dot1p_to_tc scenario on interface')
    else:
        basic_obj.get_techsupport(filename='ft_qosmaps_dot1p_tc_intf')
        st.report_tc_fail('ft_qosmaps_dot1p_tc_intf', 'qos_map_test_fail', 'for dot1p_to_tc scenario on interface')

    #verify_qosmaps_tc_dot1p_intf
    st.banner("test case: ft_qosmaps_tc_dot1p_intf")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[1], 'tc_to_dot1p', vars.D1T1P2, 'tc_to_dot1p_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dot1p_map', data.obj_name[1], {'0': '3', '1': '5', '2': '4'}):
        st.error("Failed to verify configured maps values")
        result2 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='a0'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[1], 'tc_to_dot1p', vars.D1T1P2, 'tc_to_dot1p_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dot1p_map', data.obj_name[1], {'0': '1', '1': '2', '2': '3'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='40'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[1], 'tc_to_dot1p', vars.D1T1P2, 'tc_to_dot1p_map',
                                        clear_map='yes')
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='20'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dot1p_intf', 'qos_map_test_pass', 'for tc_to_dot1p scenario on interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dot1p_intf', 'qos_map_test_fail', 'for tc_to_dot1p scenario on interface')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass", "for l2 interface.")
    else:
        st.report_fail("qos_map_test_fail", "for l2 interface.")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_l2_lag():
    result1 = result2 = 0
    pc_config_l2()
    #verify_qosmaps_dot1p_tc_lag
    st.banner("test case: ft_qosmaps_dot1p_tc_lag and ft_qosmaps_tc_dot1p_lag")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[4], 'dot1p_to_tc', data.portchannel_1, 'dot1p_to_tc_map')

    if not cos_obj.verify_qos_map_table(vars.D1, 'dot1p_to_tc_map', data.obj_name[4], {'0': '2', '1': '4', '2': '3'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[5], 'tc_to_dot1p', data.portchannel_2, 'tc_to_dot1p_map')

    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dot1p_map', data.obj_name[5], {'0': '3', '1,4': '5', '2': '4'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='a0'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="MC14", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[4], 'dot1p_to_tc', data.portchannel_1, 'dot1p_to_tc_map',
                                        update_map='yes')

    if not cos_obj.verify_qos_map_table(vars.D1, 'dot1p_to_tc_map', data.obj_name[4], {'0': '3', '1': '2', '2': '4'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[5], 'tc_to_dot1p', data.portchannel_2, 'tc_to_dot1p_map',
                                        update_map='yes')

    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dot1p_map', data.obj_name[5], {'0': '1', '1': '2', '2': '3', '4': '6'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='60'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1

    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="MC12", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[4], 'dot1p_to_tc', data.portchannel_1, 'dot1p_to_tc_map',
                                        clear_map='yes')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[5], 'tc_to_dot1p', data.portchannel_2, 'tc_to_dot1p_map',
                                        clear_map='yes')
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['l2_stream_p1'], port=data.tg_ph_2, offset=14, value='20'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1

    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="MC11", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_dot1p_tc_lag', 'qos_map_test_pass', 'for dot1p_to_tc scenario on l2 lag interface')
    else:
        st.report_tc_fail('ft_qosmaps_dot1p_tc_lag', 'qos_map_test_fail', 'for dot1p_to_tc scenario on l2 lag interface')
    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dot1p_lag', 'qos_map_test_pass', 'for tc_to_dot1p scenario on l2 lag interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dot1p_lag', 'qos_map_test_fail', 'for tc_to_dot1p scenario on l2 lag interface')
    if result1 == 0 and result2 == 0:
        st.report_tc_pass('ft_qosmaps_dot1p_tc_to_tc_dot1p_lag', 'qos_map_test_pass', 'for dot1p_tc_to_tc_dot1p scenario on lag')
    else:
        st.report_tc_fail('ft_qosmaps_dot1p_tc_to_tc_dot1p_lag', 'qos_map_test_fail', 'for dot1p_tc_to_tc_dot1p scenario on lag')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass", "for l2 lag.")
    else:
        st.report_fail("qos_map_test_fail", "for l2 lag.")

#### L3 tests using port-channel interface ###
@pytest.mark.qos_map_regression
def test_ft_qosmaps_l3_lag():
    result1 = result2 = 0
    pc_config_l3()
    ping_ipv4_interface(data.ipv4_addr[5], data.ipv4_addr[4], data.ipv4_addr[7], data.ipv4_addr[6])
    #verify_qosmaps_dscp_tc_lag()
    st.banner("test cases: ft_qosmaps_dscp_tc_lag and ft_qosmaps_tc_dscp_lag")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[6], 'dscp_to_tc', data.portchannel_1, 'dscp_to_tc_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[6], {'10': '2', '24': '4', '32': '0'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[7], 'tc_to_dscp', data.portchannel_2, 'tc_to_dscp_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[7], {'0': '15', '1': '10', '2': '35', '4': '32'}):
        st.error("Failed to verify configured maps values")
        result2 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_pc'], port=data.tg_ph_2,
                                           offset=15, value='80'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC4", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[6], 'dscp_to_tc', data.portchannel_1, 'dscp_to_tc_map',
                                        update_map='yes')

    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[6], {'10': '3', '24': '2', '32': '4'}):
        st.error("Failed to verify configured maps values")
        result1 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[7], 'tc_to_dscp', data.portchannel_2, 'tc_to_dscp_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[7], {'0': '5', '1': '20', '2': '10', '4': '15'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_pc'], port=data.tg_ph_2, offset=15, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC2", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1


    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[6], 'dscp_to_tc', data.portchannel_1, 'dscp_to_tc_map',
                                        clear_map='yes')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[7], 'tc_to_dscp', data.portchannel_2, 'tc_to_dscp_map',
                                        clear_map='yes')
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_pc'], port=data.tg_ph_2,
                                           offset=15, value='60'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC0", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_dscp_tc_lag', 'qos_map_test_pass', 'for dscp_to_tc scenario on l3 lag interface')
    else:
        st.report_tc_fail('ft_qosmaps_dscp_tc_lag', 'qos_map_test_fail', 'for dscp_to_tc scenario on l3 lag interface')
    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_lag', 'qos_map_test_pass', 'for tc_to_dscp scenario on l3 lag interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dscp_lag', 'qos_map_test_fail', 'for tc_to_dscp scenario on l3 lag interface')
    if result1 == 0 and result2 == 0:
        st.report_tc_pass('ft_qosmaps_dscp_tc_to_tc_dscp_lag', 'qos_map_test_pass', 'for dscp_tc_to_tc_dscp_lag scenario on l3 lag interface')
    else:
        st.report_tc_fail('ft_qosmaps_dscp_tc_to_tc_dscp_lag', 'qos_map_test_fail', 'for dscp_tc_to_tc_dscp_lag scenario on l3 lag interface')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass", "for l3 lag interface.")
    else:
        st.report_fail("qos_map_test_fail", "for l3 lag interface.")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_l3_intf():
    result1 = result2 = 0
    route_config_l3()
    ping_ipv4_interface(data.ipv4_addr[1], data.ipv4_addr[0], data.ipv4_addr[7], data.ipv4_addr[6])
    #verify_qosmaps_dscp_tc_intf
    st.banner("test case: ft_qosmaps_dscp_tc_intf, ft_qosmaps_tc_dscp_intf, ft_qosmaps_tc_dscp_intf_linkflap")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[2], 'dscp_to_tc', vars.D1T1P1, 'dscp_to_tc_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[2], {'10': '2', '24': '4', '32': '0'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[0], {'0': '15', '1': '10', '2': '35', '4': '32'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream'], port=data.tg_ph_2, offset=15, value='80'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC4", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[2], 'dscp_to_tc', vars.D1T1P1, 'dscp_to_tc_map', update_map='yes')

    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[2], {'10': '3', '24': '2', '32': '4'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[0], {'0': '5', '1': '20', '2': '10', '4': '15'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream'], port=data.tg_ph_2, offset=15, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC2", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    st.log("performing link flap")
    intf_obj.interface_operation(vars.D1, vars.D1T1P2, operation="shutdown", skip_verify=True)
    st.wait(1)
    intf_obj.interface_operation(vars.D1, vars.D1T1P2, operation="startup", skip_verify=True)
    st.wait(3)
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream'], port=data.tg_ph_2, offset=15, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_intf_linkflap', 'qos_map_test_pass', 'for tc_to_dscp link flap scenario on interface')
    else:
        basic_obj.get_techsupport(filename='ft_qosmaps_tc_dscp_intf_linkflap')
        st.report_tc_fail('ft_qosmaps_tc_dscp_intf_linkflap', 'qos_map_test_fail', 'for tc_to_dscp link flap scenario on interface')

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[2], 'dscp_to_tc', vars.D1T1P1, 'dscp_to_tc_map',
                                        clear_map='yes')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map',
                                        clear_map='yes')
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream'], port=data.tg_ph_2, offset=15, value='60'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC0", param_list=['pkts_count'], val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_dscp_tc_intf', 'qos_map_test_pass', 'for dscp_to_tc scenario on interface')
    else:
        basic_obj.get_techsupport(filename='ft_qosmaps_dscp_tc_intf')
        st.report_tc_fail('ft_qosmaps_dscp_tc_intf', 'qos_map_test_fail', 'for dscp_to_tc scenario on interface')

    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_intf', 'qos_map_test_pass', 'for tc_to_dscp scenario on interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dscp_intf', 'qos_map_test_fail', 'for tc_to_dscp scenario on interface')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass", "for l3 interface.")
    else:
        st.report_fail("qos_map_test_fail", "for l3 interface.")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_l3_vlan():
    result1 = result2 = result3 = 0
    vlan_config_l3()
    ping_ipv4_vlan_interface(data.ipv4_addr[3], data.ipv4_addr[2], data.ipv4_addr[7], data.ipv4_addr[6])
    #verify_qosmaps_dscp_tc_vlan()
    st.banner("test case: ft_qosmaps_dscp_tc_vlan and ft_qosmaps_tc_dscp_vlan")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[8], 'dscp_to_tc', data.vlan_name_2, 'dscp_to_tc_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[8], {'10': '2', '24': '4', '32': '0'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[9], {'0': '15', '1': '10', '2': '35', '4': '32'}):
        st.error("Failed to verify configured maps values")
        result2 += 1

    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2,
                                           offset=19, value='80'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC4", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[8], 'dscp_to_tc', data.vlan_name_2, 'dscp_to_tc_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[8], {'10': '3', '24': '2', '32': '4'}):
        st.error("Failed to verify configured maps values")
        result1 += 1

    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map',
                                        update_map='yes')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[9], {'0': '5', '1': '20', '2': '10', '4': '15'}):
        st.error("Failed to verify configured maps values")
        result2 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2, offset=19, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC2", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    st.log("performing unbind and binding of qos map")
    if not cos_obj.clear_port_qos_map_all(vars.D1, data.vlan_table_map):
        st.error("Failed to unbind the configured qos map")
        result3 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2,
                                           offset=19, value='60'):
        st.error("Failed to verify dscp value in captured packet")
        result3 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC2", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result3 += 1

    if not cos_obj.config_port_qos_map_all(vars.D1, data.vlan_table_map):
        st.error("Failed to bind the configured qos map")
        result3 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2, offset=19, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result3 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC2", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result3 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[8], 'dscp_to_tc', data.vlan_name_2, 'dscp_to_tc_map', clear_map='yes')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map', clear_map='yes')
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2, offset=19, value='60'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
        result3 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC1", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
        result3 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_dscp_tc_vlan', 'qos_map_test_pass', 'for dscp_to_tc scenario on vlan interface')
    else:
        st.report_tc_fail('ft_qosmaps_dscp_tc_vlan', 'qos_map_test_fail', 'for dscp_to_tc scenario on vlan interface')

    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_vlan', 'qos_map_test_pass', 'for tc_to_dscp scenario on vlan interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dscp_vlan', 'qos_map_test_fail', 'for tc_to_dscp scenario on vlan interface')
    if result3 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_bind_unbind_multiple_times', 'qos_map_test_pass', 'for tc_to_dscp bind and unbind for multiple times scenario on vlan interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dscp_bind_unbind_multiple_times', 'qos_map_test_fail', 'for tc_to_dscp bind and unbind for multiple times scenario on vlan interface')
    if not (result1 or result2 or result3):
        st.report_pass("qos_map_test_pass", "for l3 vlan interface.")
    else:
        st.report_fail("qos_map_test_fail", "for l3 vlan interface.")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_running_config_verify():
    result1 = 0
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[2], 'dscp_to_tc', vars.D1T1P1, 'dscp_to_tc_map')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map')

    if not cos_obj.verify_qos_map_table(vars.D1, 'dscp_to_tc_map', data.obj_name[2], {'10': '2', '24': '4', '32': '0'}):
        st.error("Failed to verify configured maps values")
        result1 = +1
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[0], {'0': '15', '1': '10', '2': '35'}):
        st.error("Failed to verify configured maps values")
        result1 = +1

    ############## verifying running config
    dscp_d1_in_attr_list, tc_d1_in_list = ["10", "24", "32"], ["2", "4", "0"]
    for dscp_d1_attr, tc_d1_val in zip(dscp_d1_in_attr_list, tc_d1_in_list):
        if not switching_conf.verify_running_config(vars.D1, data.dscp_to_tc_map, data.obj_name[2],
                                                    dscp_d1_attr, tc_d1_val):
            st.error("verification of qos maps config in running-config failed")
            result1 = +1

    dscp_d1_in_attr_list, tc_d1_in_list = ["0", "1", "2"], ["15", "10", "35"]
    for dscp_d1_attr, tc_d1_val in zip(dscp_d1_in_attr_list, tc_d1_in_list):
        if not switching_conf.verify_running_config(vars.D1, data.tc_to_dscp_map, data.obj_name[0],
                                                    dscp_d1_attr, tc_d1_val):
            st.error("verification of qos maps config in running-config failed")
            result1 = +1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map',
                                        update_map='yes')

    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[0], {'0': '5', '1': '20', '2': '10'}):
        st.error("Failed to verify updated maps values")
        result1 = +1
    dscp_d1_in_attr_list, tc_d1_in_list = ["0", "1", "2"], ["5", "20", "10"]
    for dscp_d1_attr, tc_d1_val in zip(dscp_d1_in_attr_list, tc_d1_in_list):
        if not switching_conf.verify_running_config(vars.D1, data.tc_to_dscp_map, data.obj_name[0],
                                                    dscp_d1_attr, tc_d1_val):
            st.error("TestCheckFail verification of qos maps config in running-config failed")
            result1 = +1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[0], 'tc_to_dscp', vars.D1T1P2, 'tc_to_dscp_map',
                                        clear_map='yes')
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[2], 'dscp_to_tc', vars.D1T1P1, 'dscp_to_tc_map',
                                        clear_map='yes')
    if result1 == 0:
        st.report_pass("qos_map_running_config_verify", "successful")
    else:
        st.report_fail("qos_map_running_config_verify", "failed")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_remove_vlan_delete_map():
    result1 = result2 = 0
    vlan_config_l2()
    st.banner("test cases: ft_qosmaps_delete_applied_map and ft_qosmaps_delete_vlan_when_map_applied")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[9], {'0': '15', '1': '10', '2': '35'}):
        st.error("Failed to verify configured maps values")
        result1 += 1

    if cos_obj.clear_qos_map_table(vars.D1, data.vlan_table_map, skip_error = True, error_msg = 'given instance is in use'):
        result1 += 1
        basic_obj.get_techsupport(filename='ft_qosmaps_delete_applied_map')
        st.error("TestCheckError Able to delete the vlan when qos map is applied on it")
    else:
        st.log("Negative check passed. verified unable to delete the qos map when map is binded on interface.")
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_delete_applied_map', 'qos_map_test_pass', 'for trying to delete binded map when it is already applied on vlan interface')
    else:
        st.report_tc_fail('ft_qosmaps_delete_applied_map', 'qos_map_test_fail', 'for trying to delete binded map when it is already applied on vlan interface')

    if vlan_obj.delete_vlan(dut=vars.D1, vlan_list=[data.vlan_3]):
        result2 += 1
        st.error("TestCheckError Able to delete the vlan when qos map is applied on it")
    else:
        st.log("Negative check passed. verified unable to delete the vlan when qos map binded on interface.")
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map', clear_map='yes')

    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_delete_vlan_when_map_applied', 'qos_map_test_pass', 'for trying to delete vlan when it is binded on vlan interface scenario')
    else:
        st.report_tc_fail('ft_qosmaps_delete_vlan_when_map_applied', 'qos_map_test_fail', 'for trying to delete vlan when it is binded on vlan interface scenario')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass",
                       "when trying to delete vlan and configued tc_dscp map when it is already binded on interface.")
    else:
        st.report_fail("qos_map_test_fail",
                       "when trying to delete vlan and configured tc_dscp map when it is already binded on interface.")

@pytest.mark.qos_map_regression
def test_ft_qosmaps_tc_dscp_intf_config_reload_and_warm_boot():
    result1 = result2 = 0
    vlan_config_l3()
    ping_ipv4_vlan_interface(data.ipv4_addr[3], data.ipv4_addr[2], data.ipv4_addr[7], data.ipv4_addr[6])
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map')
    if not cos_obj.verify_qos_map_table(vars.D1, 'tc_to_dscp_map', data.obj_name[9], {'0': '15', '1': '10', '2': '35', '4': '32'}):
        st.error("Failed to verify configured maps values")
        result1 += 1
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2,
                                           offset=19, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result1 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC1", param_list=['pkts_count'], val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    st.log("performing Config save")
    reboot_obj.config_save(vars.D1)
    st.banner("Performing warm-reboot operation --STARTED")
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    st.wait(10)
    st.banner("Performing warm-reboot operation --COMPLETED")
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2,
                                           offset=19, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result1 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC1", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result1 += 1
    if result1 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_warmboot', 'qos_map_test_pass', 'for warm reboot scenario on vlan interface')
    else:
        basic_obj.get_techsupport(filename='ft_qosmaps_tc_dscp_warmboot')
        st.report_tc_fail('ft_qosmaps_tc_dscp_warmboot', 'qos_map_test_fail', 'for warm reboot scenario on vlan interface')
    st.log("performing Config save")
    reboot_obj.config_save(vars.D1)
    st.log("performing config-reload")
    reboot_obj.config_reload(vars.D1)
    st.wait(10)
    clear_intf_queue_counters()
    if not send_traffic_and_Verify_capture(stream=data.streams['ipv4_stream_vlan_priority_vlan'], port=data.tg_ph_2,
                                           offset=19, value='28'):
        st.error("Failed to verify dscp value in captured packet")
        result2 += 1
    if not qos_obj.verify_qos_queue_counters(dut=vars.D1, port=vars.D1T1P2, queue_name="UC1", param_list=['pkts_count'],
                                             val_list=[data.pkts_per_burst], tol_list=['20']):
        st.error("Failed to verify queue counters")
        result2 += 1
    configure_qos_map_bind_update_clear(vars.D1, data.obj_name[9], 'tc_to_dscp', data.vlan_name_3, 'tc_to_dscp_map',
                                        clear_map='yes')

    if result2 == 0:
        st.report_tc_pass('ft_qosmaps_tc_dscp_config_reload', 'qos_map_test_pass', 'for config reload scenario on vlan interface')
    else:
        st.report_tc_fail('ft_qosmaps_tc_dscp_config_reload', 'qos_map_test_fail', 'for config reload scenario on vlan interface')
    if not (result1 or result2):
        st.report_pass("qos_map_test_pass", "for l3 vlan interface.")
    else:
        st.report_fail("qos_map_test_fail", "for l3 vlan interface.")
