"""
This file contains the list of Port Mirroring tests
Author: Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
"""
import pytest

from spytest import st, tgapi, SpyTestDict, poll_wait
from spytest.utils import random_vlan_list

import apis.system.mirroring as mirror
import apis.switching.vlan as vlanapi
import apis.switching.portchannel as portchannelapi
import apis.system.basic as basic
import apis.system.interface as intf
import apis.common.asic as asicapi
import apis.routing.ip as ip
import apis.system.gnmi as gnmi
import apis.qos.acl_dscp as acl_dscp
from apis.qos.qos import clear_qos_queue_counters
from apis.system.reboot import config_save


from utilities.parallel import exec_all, ensure_no_exception, exec_foreach

mirror_data = SpyTestDict()

def mirroring_variables():
    mirror_data.clear()
    mirror_data.session_name = "Mirror1"
    mirror_data.session_name1 = "Mirror2"
    mirror_data.session_name2 = "Mirror3"
    mirror_data.session_name3 = "Mirror4"
    mirror_data.session_name4 = "Mirror5"
    mirror_data.rate_pps = 100
    mirror_data.pkts_per_burst = 100
    mirror_data.source_interface = vars.D1T1P1
    mirror_data.mirror_interface = vars.D1D2P1
    mirror_data.source_interface_D2=vars.D2D1P1
    mirror_data.source_interface_D1 = vars.D1T1P2
    mirror_data.mirror_interface_D2=vars.D2T1P2
    mirror_data.second_source=vars.D1D2P3
    mirror_data.second_source_D2_second_port = vars.D2D1P2
    mirror_data.source_interface_D2_first = vars.D2T1P1
    mirror_data.max_mirror_intf_list = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    mirror_data.CPU_interface = "CPU"
    mirror_data.direction_list = ["rx","tx","both","name"]
    mirror_data.vlan = str(random_vlan_list()[0])
    mirror_data.source_mac ="00:00:02:00:00:01"
    mirror_data.destination_mac = "00:00:01:00:00:01"
    mirror_data.source_mac2 = "00:00:03:00:00:01"
    mirror_data.destination_mac2 = "00:00:05:00:00:01"
    mirror_data.port_channel_name ="PortChannel7"
    mirror_data.in_acl_table_name= 'mirror_policy_in'
    mirror_data.eg_acl_table_name = 'mirror_policy_eg'
    mirror_data.description = 'Mirror_ACLV4_CREATION'
    mirror_data.in_stage = 'INGRESS'
    mirror_data.eg_stage = 'EGRESS'
    mirror_data.in_acl_rule = "Mirror_IN_Rule1"
    mirror_data.eg_acl_rule = "Mirror_EG_Rule2"
    mirror_data.priority = '999'
    mirror_data.type = 'monitoring'
    mirror_data.gre_type= "0x88ee"
    mirror_data.dscp = "50"
    mirror_data.ttl = "60"
    mirror_data.queue = "0"
    mirror_data.ip_D1T1P1 = "11.1.1.1"
    mirror_data.ip_T1D1P1 = "11.1.1.2"
    mirror_data.ip_D1T1P2 = "12.1.1.1"
    mirror_data.ip_T1D1P2 = "12.1.1.2"
    mirror_data.ip_D1D2P1 = "13.1.1.1"
    mirror_data.ip_D2D1P1 = "13.1.1.2"
    mirror_data.ip_D2T1P1 = "15.1.1.1"
    mirror_data.ip_T1D2P1 = "15.1.1.2"
    mirror_data.subnet_mask = "24"
    mirror_data.sub_mask = "255.255.255.0"
    mirror_data.ip_list_d1 = ["11.1.1.1", "12.1.1.1", "13.1.1.1"]
    mirror_data.ip_list_d2 = ["13.1.1.2", "15.1.1.1"]
    mirror_data.port_list_d1 = [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1]
    mirror_data.port_list_d2 = [vars.D2D1P1, vars.D2T1P1]
    mirror_data.ip_route = ["15.1.1.0", "11.1.1.0"]
    mirror_data.port_list_d1_1 = [vars.D1T1P2, vars.D1D2P1]
    mirror_data.mask = "32"
    mirror_data.src_ip_mask = "{}/{}".format(mirror_data.ip_T1D1P1, mirror_data.mask)
    mirror_data.dst_ip_mask = "{}/{}".format(mirror_data.ip_T1D1P2, mirror_data.mask)
    mirror_data.rate_pps = 10000
    mirror_data.pkts_per_burst = 1000
    mirror_data.range = 3
    mirror_data.flag = 1
    mirror_data.source_ip = '11.1.1.2'
    mirror_data.destination_ip = '15.1.1.2'
    mirror_data.mirror_type =["span", "erspan"]
    mirror_data.dut_ip = "127.0.0.1"
    mirror_data.username = "admin"
    mirror_data.password = "broadcom"
    mirror_data.insecure = " "
    mirror_data.ip_D1PoCh1 = "101.1.1.1"
    mirror_data.ip_D2PoCh1 = "101.1.1.2"
    mirror_data.dut_list = [vars.D1, vars.D2]


@pytest.fixture(scope="module", autouse=True)
def mirror_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2", "D2T1:1", "D1D2:4")
    mirroring_variables()
    [_, exceptions] = exec_all(True, [[tg_init], [mirror_module_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)
    yield
    mirror_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def mirror_func_hooks(request):
    vlan_config()
    yield
    if st.get_func_name(request) in ['test_ft_mirroring_erspan_vlan','test_ft_mirroring_on_vlan_rx',
                                      'test_ft_mirroring_erspan_span_check','test_ft_mirroring_erspan']:
        mirror_acl_unconfig()
    st.log("Clearing or unconfiguring the mirror session")
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name,True],
                                        [mirror.delete_session, vars.D2, mirror_data.session_name,True]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name1, True],
                                      [mirror.delete_session, vars.D2, mirror_data.session_name1, True]])
    ensure_no_exception(exceptions)
    vlanapi.clear_vlan_configuration([vars.D1,vars.D2])
    portchannelapi.clear_portchannel_configuration([vars.D1,vars.D2])
    ip.clear_ip_configuration([vars.D1,vars.D2],family='ipv4',thread=True)


def mirror_module_prolog():
    [_,exceptions] = exec_all(True, [[basic.service_operations_by_systemctl, vars.D1, "lldp", "stop"],
                                        [basic.service_operations_by_systemctl, vars.D2, "lldp", "stop"]])
    ensure_no_exception(exceptions)


def mirror_module_epilog():
    vlanapi.clear_vlan_configuration([vars.D1,vars.D2])
    [_,exceptions] = exec_all(True, [[basic.service_operations_by_systemctl, vars.D1, 'lldp', 'start'],
                                        [basic.service_operations_by_systemctl, vars.D2, 'lldp', 'start']])
    ensure_no_exception(exceptions)


def vlan_config():
    [out, exceptions] = exec_all(True,[[vlanapi.create_vlan, vars.D1, mirror_data.vlan],
                                       [vlanapi.create_vlan, vars.D2, mirror_data.vlan]])
    ensure_no_exception(exceptions)
    for output in out:
        if not output:
            st.report_fail("vlan_create_fail", mirror_data.vlan)


def tg_init():
    global tr1, tg, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4,tg_handler, tr2, tr3,tr4
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2, vars.T1D2P1, vars.T1D2P2])
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tg_ph_4 = tg_handler["tg_ph_4"]
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    st.log("stream configuration on	all TG's")
    tr1 = tg.tg_traffic_config(port_handle=tg_ph_1,mode='create',transmit_mode="single_burst",
                                pkts_per_burst=mirror_data.pkts_per_burst,length_mode='fixed',
                                rate_pps=mirror_data.rate_pps,frame_size=64,mac_src=mirror_data.source_mac,
                                vlan_id=mirror_data.vlan,vlan="enable", mac_dst=mirror_data.destination_mac)
    tr2 = tg.tg_traffic_config(port_handle=tg_ph_2,mode='create',transmit_mode="single_burst",
                                pkts_per_burst=mirror_data.pkts_per_burst,length_mode='fixed',
                                rate_pps=mirror_data.rate_pps,frame_size=64,mac_src=mirror_data.source_mac2,
                                vlan_id=mirror_data.vlan,vlan="enable",mac_dst=mirror_data.destination_mac2)
    tr3 = tg.tg_traffic_config(port_handle=tg_ph_3,mode='create',transmit_mode="single_burst",
                                pkts_per_burst=mirror_data.pkts_per_burst,length_mode='fixed',
                                rate_pps=mirror_data.rate_pps,frame_size=64,mac_src=mirror_data.source_mac,
                                vlan_id=mirror_data.vlan,vlan="enable",mac_dst=mirror_data.destination_mac)
    tr4 = tg.tg_traffic_config(port_handle=tg_ph_4, mode='create', transmit_mode="single_burst",
                                pkts_per_burst=mirror_data.pkts_per_burst,length_mode='fixed',
                                rate_pps=mirror_data.rate_pps,frame_size=64, mac_src=mirror_data.source_mac2,
                                vlan_id=mirror_data.vlan, vlan="enable",mac_dst=mirror_data.destination_mac2)


def mirroring_traffic_stream_config(direction="rx"):
    if direction== "rx":
        tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    if direction== "tx":
        tg.tg_traffic_control(action='run', handle=tr2['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop',handle=tr2['stream_id'])
    if direction=="both":
        tg.tg_traffic_control(action='run',handle=tr1['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop',handle=tr1['stream_id'])
        tg.tg_traffic_control(action='run',handle=tr2['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop',handle=tr2['stream_id'])
    if direction== "tx_2":
        tg.tg_traffic_control(action='run',handle=tr3['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr3['stream_id'])
    if direction=="rx_tx_2":
        tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        tg.tg_traffic_control(action='run', handle=tr3['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr3['stream_id'])
    if direction=="source_both":
        tg.tg_traffic_control(action='run', handle=tr1['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        tg.tg_traffic_control(action='run', handle=tr2['stream_id'])
        st.wait(3)
        tg.tg_traffic_control(action='stop', handle=tr2['stream_id'])
        st.wait(3)

def mirrror_acl_config():
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=mirror_data.in_acl_table_name,
                                 policy_type=mirror_data.type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P1, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P2, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=mirror_data.in_acl_rule)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria="--vlan", match_type="fields",
                                     criteria_value=mirror_data.vlan, class_name=mirror_data.in_acl_rule)
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='add',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_value=mirror_data.priority,
                                      description=mirror_data.description)
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='update',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_option='--mirror-session',
                                      priority_value="Mirror1")


def mirror_acl_unconfig():
    acl_dscp.config_flow_update_table(vars.D1, policy_name=mirror_data.in_acl_table_name, flow='del',
                                      policy_type=mirror_data.type, class_name=mirror_data.in_acl_rule)
    acl_dscp.config_classifier_table(dut=vars.D1, enable="del", class_name=mirror_data.in_acl_rule)
    acl_dscp.config_service_policy_table(dut=vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, stage='in',
                                         policy_type=mirror_data.type, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_service_policy_table(dut=vars.D1, policy_kind='unbind', interface_name=vars.D1T1P2, stage='in',
                                         policy_type=mirror_data.type, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=mirror_data.in_acl_table_name)


def mirror_erspan_tg_config():
    dut_mac = basic.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    mirror_data.tg = tgapi.get_chassis(vars)
    st.log("Creating IPv4 routing interfaces on TG ports")
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_1, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D1P1,
                                        gateway=mirror_data.ip_D1T1P1, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_2, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D1P2,
                                        gateway=mirror_data.ip_D1T1P2, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_3, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D2P1,
                                        gateway=mirror_data.ip_D2T1P1, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')

    mirror_data.tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4])
    tr5 = mirror_data.tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                      length_mode='fixed',pkts_per_burst=mirror_data.pkts_per_burst,
                                      rate_pps=mirror_data.rate_pps, l2_encap='ethernet_ii',
                                      mac_src='00:0a:01:00:00:01',
                                      mac_dst=dut_mac, l3_protocol="ipv4", ip_src_addr=mirror_data.ip_T1D1P1,
                                      ip_dst_addr=mirror_data.ip_D1T1P2,vlan_id=mirror_data.vlan, vlan="enable")
    mirror_data.tg.tg_traffic_control(action='run',handle = tr5['stream_id'])
    st.wait(5)
    mirror_data.tg.tg_traffic_control(action='stop',handle = tr5['stream_id'])
    st.wait(5)



def mirror_erspan_tg_config_portchannel():
    dut_mac = basic.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    mirror_data.tg = tgapi.get_chassis(vars)
    st.log("Creating IPv4 routing interfaces on TG ports")
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_1, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D1P1,
                                        gateway=mirror_data.ip_D1T1P1, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_2, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D1P2,
                                        gateway=mirror_data.ip_D1T1P2, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')
    mirror_data.tg.tg_interface_config(port_handle=tg_ph_3, mode='config',
                                        intf_ip_addr=mirror_data.ip_T1D2P1,
                                        gateway=mirror_data.ip_D2T1P1, netmask=mirror_data.sub_mask, count=3,
                                        arp_send_req='1')

    mirror_data.tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4])
    tr6 = mirror_data.tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                      length_mode='fixed',pkts_per_burst='1000',
                                      rate_pps='1000', l2_encap='ethernet_ii',
                                      mac_src='00:0a:01:00:00:01',
                                      mac_dst=dut_mac, l3_protocol="ipv4", ip_src_addr=mirror_data.ip_T1D1P1,
                                      ip_dst_addr=mirror_data.ip_D2PoCh1)

    mirror_data.tg.tg_traffic_control(action='run', handle =tr6['stream_id'])
    st.wait(3)
    mirror_data.tg.tg_traffic_control(action='stop', handle =tr6['stream_id'])
    st.wait(5)


def mirror_erspan_ip_config():
    st.log("Creating IP address configuration on DUT-1")
    data = dict()
    data["dut"] = [vars.D1, vars.D2]
    data[vars.D1] = list()
    data[vars.D2] = list()
    for port, ip_addr, in zip(mirror_data.port_list_d1, mirror_data.ip_list_d1):
        data[vars.D1].append({"port":port,"ip_addr":ip_addr,"subnet":mirror_data.subnet_mask})
    st.log("Creating IP address configuration on DUT-2")
    for port, ip_addr in zip(mirror_data.port_list_d2, mirror_data.ip_list_d2):
        data[vars.D2].append({"port":port,"ip_addr":ip_addr,"subnet":mirror_data.subnet_mask})
    [_, exceptions] = exec_foreach(True,data["dut"], config_ip_add_paraller, data)
    st.log("Creatting static route")

    [_, exceptions] = exec_all(True, [
        [ip.get_interface_ip_address, vars.D1,vars.D1T1P1,"ipv4"],
        [ip.get_interface_ip_address, vars.D2,vars.D2T1P1,"ipv4"]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[ip.create_static_route, vars.D1, mirror_data.ip_D2D1P1,
                                         mirror_data.ip_route[0]+'/'+mirror_data.subnet_mask],
                                        [ip.create_static_route, vars.D2, mirror_data.ip_D1D2P1,
                                         mirror_data.ip_route[1]+'/'+mirror_data.subnet_mask]])
    ensure_no_exception(exceptions)


def config_ip_add_paraller(dut, params):
    if params:
        for data in params[dut]:
            ip.config_ip_addr_interface(dut, data["port"], data["ip_addr"], data["subnet"])


def mirroring_erspan():
    mirror_erspan_ip_config()
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type=mirror_data.mirror_type[1], src_ip=mirror_data.ip_D1T1P1,
                          dst_ip=mirror_data.ip_T1D2P1, gre_type=mirror_data.gre_type, dscp=mirror_data.dscp,
                          ttl=mirror_data.ttl, queue=mirror_data.queue)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=mirror_data.in_acl_table_name,
                                 policy_type=mirror_data.type)
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=mirror_data.in_acl_rule)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria='--src-ip', match_type="fields",
                                     criteria_value="{}/{}".format(mirror_data.ip_T1D1P1, 32),
                                     class_name=mirror_data.in_acl_rule)
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='add',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_value=mirror_data.priority,
                                      description=mirror_data.description)
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='update',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_option='--mirror-session',
                                      priority_value=mirror_data.session_name)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P1, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P2, service_policy_name=mirror_data.in_acl_table_name)
    if not mirror.verify_session(vars.D1, mirror_type="erspan", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")

    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)

    mirror_erspan_tg_config()

    receive_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface, "rx_ok")
    st.log("receive_counters_from_tg = {} ".format(receive_counters_from_tg))
    receive_count_int_value = int(receive_counters_from_tg[mirror_data.source_interface]['rx_ok'])
    st.log("receive_count_int_value = {} ".format(receive_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2_first,
                                                                      "tx_ok")
    st.log("tx_counters_from_mirrored_port = {} ".format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(
        tx_counters_from_mirrored_port[mirror_data.source_interface_D2_first]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} ".format(tx_counters_from_mirrored_port_int_value))

    if tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value):
        st.log("tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value). Some rx pkts did not get mirrored")
        st.report_fail("mirror_erspan_func_status", "failed")

    return True


def mirroring_clear():
    st.log("Clearing or unconfiguring the mirror session")
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name,True],
                                        [mirror.delete_session, vars.D2, mirror_data.session_name,True]])
    ensure_no_exception(exceptions)
    vlanapi.clear_vlan_configuration([vars.D1, vars.D2])
    portchannelapi.clear_portchannel_configuration([vars.D1, vars.D2])
    ip.clear_ip_configuration([vars.D1, vars.D2], family='ipv4', thread=True)


def mirroring_on_port_rx():
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,mirror_type="span",
                                     destination_ifname=mirror_data.second_source,
                                     source_ifname=mirror_data.source_interface,rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D1,mirror_type="span",session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add",tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="rx")
    data = {"module_type":"mirror","direction":"rx","source":[vars.D1T1P1,"rx_ok"], "destination":[vars.D1T1P2,"tx_ok"],
    "mirrored_port":[vars.D1D2P3,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D1,data):
        st.log("Mirroring with port functionality is not working on rx direction after erpsan config and unconfig")
        return  False
    return True


def debug_cmd_list():
    [_, exceptions] = exec_all(True, [[intf.show_interface_counters_all,vars.D1],
                                        [intf.show_interface_counters_all,vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[vlanapi.show_vlan_config, vars.D1,mirror_data.vlan],
                                        [vlanapi.show_vlan_config, vars.D2,mirror_data.vlan]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[mirror.show_session, vars.D1, mirror_data.session_name],
                                        [mirror.show_session, vars.D2, mirror_data.session_name]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[ip.show_ip_route, vars.D1, "ipv4"],
                                        [ip.show_ip_route, vars.D2, "ipv4"]])
    ensure_no_exception(exceptions)



def cpu_counter_check(dut, mirror_pkts, queue='MC0', percent=0.99):
    CPU_output = intf.show_queue_counters(dut, 'CPU', queue=queue)
    st.log("CPU o/p is  :{}".format(CPU_output))
    CPU_output_value = int(CPU_output[0]['pkts_count'].replace(",", "")) + int(CPU_output[0]['pkts_drop'].replace(",", ""))
    st.log("CPU counters o/p is : {}".format(CPU_output_value))
    if not CPU_output_value >= percent * mirror_pkts:
        return False
    return True


@pytest.mark.test_mirroring_on_port_rx
def test_ft_mirroring_on_port_rx():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port ingress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type="span",destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface,rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D1,mirror_type="span",session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add",tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="rx")
    data = {"module_type":"mirror","direction":"rx","source":[vars.D1T1P1,"rx_ok"], "destination":[vars.D1T1P2,"tx_ok"],
    "mirrored_port":[vars.D1D2P1,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D1,data):
        st.report_fail("mirror_prt_func_with_dir_as_rx_not_working")
    st.report_pass("mirroring_with_port_rx_working_fine")


@pytest.mark.test_mirroring_on_port_tx
def test_ft_mirroring_on_port_tx():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror.delete_session(vars.D1, mirror_session=mirror_data.session_name,skip_err_check=True)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[1])
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add",tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="tx")
    data = {"module_type":"mirror","direction_type":"tx","source":[vars.D1T1P1,"tx_ok"],
            "destination":[vars.D1T1P2,"rx_ok"],"mirrored_port":[vars.D1D2P1,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D1,data):
        st.report_fail("mirror_prt_func_with_dir_as_tx_not_working")
    st.report_pass("mirroring_with_port_tx_working_fine")


@pytest.mark.test_mirroring_on_port_both
def test_ft_mirroring_on_port_both():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port both ingress and egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    report_flag = 1
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add", tagged=False, skip_verify=False)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="both")
    data = {"module_type": "mirror_both", "source": [vars.D1T1P1, "rx_ok"], "destination": [vars.D1T1P2, "tx_ok"],
            "mirrored_port": [vars.D1D2P1, "tx_ok"]}
    if not intf.verify_interface_counters(vars.D1, data):
        report_flag = 0
    if not report_flag:
        st.report_tc_fail("test_ft_mirroring_on_port_both", "mirroring_with_port_both_working_fine", "failed")
    else:
        st.report_tc_pass("test_ft_mirroring_on_port_both", "mirroring_with_port_both_working_fine", "passed")
    report_flag = 1
    config_save(vars.D1)
    st.log("Performing fast Reboot")
    st.reboot(vars.D1, "fast")
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="both")
    data = {"module_type": "mirror_both", "source": [vars.D1T1P1, "rx_ok"], "destination": [vars.D1T1P2, "tx_ok"],
            "mirrored_port": [vars.D1D2P1, "tx_ok"]}
    if not intf.verify_interface_counters(vars.D1, data):
        report_flag = 0
    if not report_flag:
        st.report_tc_fail("test_ft_mirroring_on_port_both", "mirroring_with_port_both_working_fine", "failed")
    else:
        st.report_tc_pass("test_ft_mirroring_on_port_both", "mirroring_with_port_both_working_fine", "passed")
    if not report_flag:
        st.report_fail("mirror_prt_func_with_dir_as_both_not_working")
    else:
        st.report_pass("mirroring_with_port_both_working_fine")


@pytest.mark.test_mirroring_on_CPU_both
def test_ft_mirroring_on_CPU_both():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port both ingress and egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """

    mirror.delete_session(vars.D1, mirror_session=mirror_data.session_name, skip_err_check=True)
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add", tagged=False, skip_verify=False)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.CPU_interface,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    intf.clear_interface_counters(vars.D1)
    clear_qos_queue_counters(vars.D1)
    intf.show_queue_counters(vars.D1, 'CPU')
    mirroring_traffic_stream_config(direction="both")
    # data = {"module_type": "mirror_both", "source": [vars.D1T1P1, "rx_ok"], "destination": [vars.D1T1P2, "tx_ok"],
    #         "mirrored_port": [vars.D1D2P1, "tx_ok"]}
    if not poll_wait(cpu_counter_check, 20, vars.D1, 2*mirror_data.pkts_per_burst, percent=0.98):
        intf.show_interfaces_counters(vars.D1)
        intf.show_queue_counters(vars.D1, 'CPU')
        intf.clear_queue_counters(vars.D1, interfaces_list=['CPU'])
        st.report_fail("mirroring_destination_CPU_both_working_fine","port","Failed")
    st.report_pass("mirroring_destination_CPU_both_working_fine","port","Success")


@pytest.mark.test_mirroring_on_prtchannel_rx
def test_ft_mirroring_on_portchannel_rx():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port as portchannel ingress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    [_, exceptions] = exec_all(True, [[mirror.show_session_all, vars.D1, None],
                                        [mirror.show_session_all, vars.D2, None]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name, True],
                                        [mirror.delete_session, vars.D2, mirror_data.session_name, True]])
    ensure_no_exception(exceptions)
    portchannelapi.config_portchannel(vars.D1,vars.D2,mirror_data.port_channel_name,[vars.D1D2P1,vars.D1D2P2],
                                      [vars.D2D1P1,vars.D2D1P2],config="add")

    [out, exceptions] = exec_all(True,[[vlanapi.config_vlan_members, vars.D1, mirror_data.vlan,
                                        [vars.D1T1P1,mirror_data.port_channel_name],"add",False,False],
                                       [vlanapi.config_vlan_members, vars.D2, mirror_data.vlan,
                                        [vars.D2T1P1,mirror_data.port_channel_name],"add",False,False]])
    ensure_no_exception(exceptions)
    for output in out:
        if not output:
            st.report_fail("vlan_config_member_add_Fail", mirror_data.vlan)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D2, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface_D2,
                          source_ifname=mirror_data.port_channel_name, rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D2, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    mirroring_traffic_stream_config(direction="rx")
    intf.show_interface_counters_all(vars.D1)
    data = {"source":[mirror_data.port_channel_name,"rx_ok"], "destination":[vars.D2T1P1,"tx_ok"],
            "mirrored_port":[vars.D2T1P2,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D2,data):
        st.report_fail("mirror_prt_channel_func_with_dir_as_rx_not_working")
    st.report_pass("mirroring_with_port_channel_rx_working_fine")


@pytest.mark.test_mirroring_on_prtchannel_tx
def test_ft_mirroring_on_portchannel_tx():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port as portchannel egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    [_, exceptions] = exec_all(True, [[mirror.show_session_all, vars.D1, None],
                                        [mirror.show_session_all, vars.D2, None]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name, True],
                                        [mirror.delete_session, vars.D2, mirror_data.session_name, True]])
    ensure_no_exception(exceptions)
    portchannelapi.config_portchannel(vars.D1,vars.D2,mirror_data.port_channel_name,[vars.D1D2P1,vars.D1D2P2],
                                      [vars.D2D1P1,vars.D2D1P2],config="add")
    [out, exceptions] = exec_all(True, [
        [vlanapi.config_vlan_members, vars.D1, mirror_data.vlan, [vars.D1T1P1, mirror_data.port_channel_name], "add",
         False, False],
        [vlanapi.config_vlan_members, vars.D2, mirror_data.vlan, [vars.D2T1P1, mirror_data.port_channel_name], "add",
         False, False]])
    ensure_no_exception(exceptions)
    for output in out:
        if not output:
            st.report_fail("vlan_config_member_add_Fail", mirror_data.vlan)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D2, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface_D2,
                          source_ifname=mirror_data.port_channel_name, rx_tx=mirror_data.direction_list[1])
    if not mirror.verify_session(vars.D2, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [
        [intf.show_interface_counters_all, vars.D1],
        [intf.show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    # intf.show_interface_counters_all(vars.D1)
    # intf.show_interface_counters_all(vars.D2)
    mirroring_traffic_stream_config(direction="tx_2")
    data = {"source":[mirror_data.port_channel_name,"tx_ok"], "destination":[vars.D2T1P1,"rx_ok"],
    "mirrored_port":[vars.D2T1P2,"tx_ok"]}
    intf.show_interface_counters_all(vars.D1)
    if not intf.verify_interface_counters(vars.D2,data):
        st.report_fail("mirror_prt_func_with_dir_as_tx_not_working")
    st.report_pass("mirroring_with_port_tx_working_fine")


@pytest.mark.test_mirroring_on_prtchannel_both
def test_ft_mirroring_on_portchannel_both():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port as portchannel both ingress and egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    [_, exceptions] = exec_all(True, [[mirror.show_session_all, vars.D1, None],
                                        [mirror.show_session_all, vars.D2, None]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[mirror.delete_session, vars.D1, mirror_data.session_name, True],
                                        [mirror.delete_session, vars.D2, mirror_data.session_name, True]])
    ensure_no_exception(exceptions)
    portchannelapi.config_portchannel(vars.D1,vars.D2,mirror_data.port_channel_name,[vars.D1D2P1,vars.D1D2P2],
                                      [vars.D2D1P1,vars.D2D1P2],config="add")
    [out, exceptions] = exec_all(True, [
        [vlanapi.config_vlan_members, vars.D1, mirror_data.vlan, [vars.D1T1P1, mirror_data.port_channel_name], "add",
         False, False],
        [vlanapi.config_vlan_members, vars.D2, mirror_data.vlan, [vars.D2T1P1, mirror_data.port_channel_name], "add",
         False, False]])
    ensure_no_exception(exceptions)
    for output in out:
        if not output:
            st.report_fail("vlan_config_member_add_Fail", mirror_data.vlan)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D2, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface_D2,
                          source_ifname=mirror_data.port_channel_name, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D2, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [
        [intf.show_interface_counters_all, vars.D1],
        [intf.show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    mirroring_traffic_stream_config(direction="rx_tx_2")
    data = {"source":[mirror_data.port_channel_name,"tx_ok"], "destination":[vars.D2T1P1,"rx_ok"],
    "mirrored_port":[vars.D2T1P2,"tx_ok"]}
    intf.show_interface_counters_all(vars.D1)
    if not intf.verify_interface_counters(vars.D2,data):
        st.report_fail("mirror_prt_func_with_dir_as_both_not_working")
    st.report_pass("mirroring_with_port_both_working_fine")


@pytest.mark.test_mirroring_on_prtchannel_CPU_both
def test_ft_mirroring_on_portchannel_CPU_both():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port as portchannel both ingress and egress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    portchannelapi.config_portchannel(vars.D1, vars.D2, mirror_data.port_channel_name, [vars.D1D2P1, vars.D1D2P2],
                                      [vars.D2D1P1, vars.D2D1P2], config="add")
    [out, exceptions] = exec_all(True, [
        [vlanapi.config_vlan_members, vars.D1, mirror_data.vlan, [vars.D1T1P1, mirror_data.port_channel_name], "add",
         False, False],
        [vlanapi.config_vlan_members, vars.D2, mirror_data.vlan, [vars.D2T1P1, mirror_data.port_channel_name], "add",
         False, False]])
    ensure_no_exception(exceptions)
    for output in out:
        if not output:
            st.report_fail("vlan_config_member_add_Fail", mirror_data.vlan)
    st.log("Creation and Verification of Monitor session")
    portchannelapi.verify_portchannel(vars.D1, mirror_data.port_channel_name)
    mirror.create_session(vars.D2, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.CPU_interface,
                          source_ifname=mirror_data.port_channel_name, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D2, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [
        [intf.show_interface_counters_all, vars.D1],
        [intf.show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    clear_qos_queue_counters(vars.D1)
    intf.show_queue_counters(vars.D2, 'CPU')
    mirroring_traffic_stream_config(direction="rx_tx_2")
    if not poll_wait(cpu_counter_check, 20, vars.D2, 2*mirror_data.pkts_per_burst, percent=0.98):
        exec_all(True, [[intf.show_interfaces_counters, vars.D1], [intf.show_interfaces_counters, vars.D2]])
        intf.show_queue_counters(vars.D2, 'CPU')
        st.report_fail("mirroring_destination_CPU_both_working_fine","port","Failed")
    st.report_pass("mirroring_destination_CPU_both_working_fine","port","Success")


@pytest.mark.test_mirroring_on_prtchannel_mem_stat
def test_ft_mirroring_on_portchannel_mem_stat():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that mirror session goes in-active state when source port-channel has no members
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """

    portchannelapi.config_portchannel(vars.D1,vars.D2,mirror_data.port_channel_name,[vars.D1D2P1,vars.D1D2P2],
                                      [vars.D2D1P1,vars.D2D1P2],config="add")
    vlanapi.show_vlan_config(vars.D1,vlan_id=mirror_data.vlan)
    [_, exceptions] = exec_all(True, [
        [vlanapi.config_vlan_members, vars.D1,mirror_data.vlan,[vars.D1T1P1, vars.D1T1P2,
                                                                mirror_data.port_channel_name],"add",False,False],
        [vlanapi.config_vlan_members, vars.D2,mirror_data.vlan,[vars.D2T1P1,
                                                                mirror_data.port_channel_name],"add",False,False]])
    ensure_no_exception(exceptions)
    st.log("Creation and Verification of Monitor session")
    mirror.create_session(vars.D2, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface_D2,
                          source_ifname=mirror_data.port_channel_name, rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D2, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    portchannelapi.delete_portchannel_member(vars.D2,mirror_data.port_channel_name,[vars.D2D1P1,vars.D2D1P2])
    st.wait(10)
    if not mirror.verify_session_all(vars.D2, mirror_type="span",
                                     session_name=mirror_data.session_name,span_status="inactive"):
        st.report_fail("mirror_stat_prtchannel_inactive")
    st.report_pass("mirror_stat_prtchannel_status_pass")


@pytest.mark.test_mirroring_on_port_negative
def test_ft_mirroring_on_port_negative():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the negative scenarios in the mirroring functionality
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    ngtve1 = mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                                   destination_ifname=mirror_data.mirror_interface,
                                   source_ifname=mirror_data.mirror_interface,
                                   rx_tx=mirror_data.direction_list[0], skip_err_check=True)
    if ngtve1:
        st.report_fail("mirror_negative_case_same_dest_sourece_fail")
    portchannelapi.config_portchannel(vars.D1, vars.D2, mirror_data.port_channel_name, [vars.D1D2P1, vars.D1D2P2],
                                      [vars.D2D1P1, vars.D2D1P2], config="add")
    ngtve2 = mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                                   destination_ifname=mirror_data.port_channel_name,
                                   source_ifname=mirror_data.second_source,
                                   rx_tx=mirror_data.direction_list[0], skip_err_check=True)
    if ngtve2:
        st.report_fail("mirror_negative_case_same_dest_prtchannel_fail")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface, skip_err_check=True,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[0])
    ngtve3 = mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                                   destination_ifname=mirror_data.source_interface,
                                   source_ifname=mirror_data.second_source, rx_tx=mirror_data.direction_list[0],
                                   skip_err_check=True)
    portchannelapi.clear_portchannel_configuration([vars.D1, vars.D2])
    if ngtve3:
        st.report_fail("mirror_config_as_source_and_dst_with_same_intf_fail")
    st.report_pass("mirror_with_negative_scenarios_pass")


@pytest.mark.test_mirroring_erspan
def test_ft_mirroring_erspan():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the negative scenarios in the mirroring functionality
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror_erspan_ip_config()
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type=mirror_data.mirror_type[1], src_ip=mirror_data.ip_D1T1P1,
                          dst_ip=mirror_data.ip_T1D2P1, gre_type=mirror_data.gre_type, dscp=mirror_data.dscp,
                          ttl=mirror_data.ttl, queue=mirror_data.queue)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=mirror_data.in_acl_table_name,
                                 policy_type=mirror_data.type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P1, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=mirror_data.type, stage='in',
                                         interface_name=vars.D1T1P2, service_policy_name=mirror_data.in_acl_table_name)
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=mirror_data.in_acl_rule)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria='--src-ip', match_type="fields",
                                     class_name=mirror_data.in_acl_rule,
                                     criteria_value="{}/{}".format(mirror_data.ip_T1D1P1, 32))
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='add',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_value=mirror_data.priority,
                                      description=mirror_data.description)
    acl_dscp.config_flow_update_table(vars.D1,policy_name=mirror_data.in_acl_table_name,flow='update',policy_type=mirror_data.type,
                                      class_name=mirror_data.in_acl_rule, priority_option='--mirror-session',
                                      priority_value=mirror_data.session_name)
    if not mirror.verify_session(vars.D1, mirror_type="erspan", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    mirror_erspan_tg_config()

    receive_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface, "rx_ok")
    st.log("receive_counters_from_tg = {} " . format(receive_counters_from_tg))
    receive_count_int_value = int(receive_counters_from_tg[mirror_data.source_interface]['rx_ok'])
    st.log("receive_count_int_value = {} " .format(receive_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2_first, "tx_ok")
    st.log("tx_counters_from_mirrored_port = {} " . format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(tx_counters_from_mirrored_port[mirror_data.source_interface_D2_first]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} " . format(tx_counters_from_mirrored_port_int_value))

    if tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value):
        st.log("tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value). Some rx pkts did not get mirrored")
        st.report_fail("mirror_erspan_func_status","failed")
    st.report_pass("mirror_erspan_func_status","Passed")


@pytest.mark.test_mirroring_erspan_span
def test_ft_mirroring_erspan_span_check():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    if not mirroring_erspan():
        st.report_fail("mirror_erspan_func_status","failed")
    mirror_acl_unconfig()
    mirroring_clear()
    st.log("Cleared ERSPAN config and did config of SPAN and checking functionality")
    vlanapi.create_vlan(vars.D1,mirror_data.vlan)
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    tg_init()
    if not mirroring_on_port_rx():
        st.report_fail("mirror_prt_func_with_dir_as_rx_not_working")
    mirroring_clear()
    st.log("Cleared SPAN config and did config of ERPSAN and checking functionality")
    mirror_erspan_tg_config()
    if not mirroring_erspan():
        st.report_fail("mirror_erspan_func_status","failed")
    st.report_pass("mirror_erspan_span_func_pass")


@pytest.mark.test_mirroring_erspan_port
def test_ft_mirroring_erspan_port():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror_erspan_ip_config()
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type=mirror_data.mirror_type[1], src_ip=mirror_data.ip_D1T1P1,
                          dst_ip=mirror_data.ip_T1D2P1, gre_type=mirror_data.gre_type, dscp=mirror_data.dscp,
                          ttl=mirror_data.ttl, queue=mirror_data.queue,src_port=mirror_data.source_interface,
                          direction=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="erspan", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [[intf.clear_interface_counters, vars.D1],
                                        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    mirror_erspan_tg_config()


    receive_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface, "rx_ok")
    st.log("receive_counters_from_tg = {} ".format(receive_counters_from_tg))
    receive_count_int_value = int(receive_counters_from_tg[mirror_data.source_interface]['rx_ok'])
    st.log("receive_count_int_value = {} ".format(receive_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2_first,"tx_ok")
    st.log("tx_counters_from_mirrored_port = {} ".format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(
    tx_counters_from_mirrored_port[mirror_data.source_interface_D2_first]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} ".format(tx_counters_from_mirrored_port_int_value))

    if tx_counters_from_mirrored_port_int_value < int(0.98 * receive_count_int_value):
        st.log(
        "tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value). Some rx pkts did not get mirrored")
        st.report_fail("mirror_erspan_func_status", "failed")
    st.report_pass("mirror_erspan_mode_status", "port", "pass")


@pytest.mark.test_mirroring_erspan_portchnl
def test_ft_mirroring_erspan_port_chnl():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    debug_cmd_list()
    mirror_erspan_ip_config()
    portchannelapi.config_portchannel(vars.D1, vars.D2, mirror_data.port_channel_name, [vars.D1D2P2],
                                      [vars.D2D1P2], config="add")

    st.log("Configure needed IP addresses on the port channel between D1 and D2")
    st.log("This is needed to send traffic via port channel")
    [_, exceptions] = exec_all(True, [[ip.config_ip_addr_interface, vars.D1,mirror_data.port_channel_name,
                                         mirror_data.ip_D1PoCh1,mirror_data.subnet_mask,"ipv4",'add'],
                                        [ip.config_ip_addr_interface, vars.D2,mirror_data.port_channel_name,
                                         mirror_data.ip_D2PoCh1,mirror_data.subnet_mask,"ipv4",'add']])
    ensure_no_exception(exceptions)
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type=mirror_data.mirror_type[1], src_ip=mirror_data.ip_D1T1P1,
                          dst_ip=mirror_data.ip_T1D2P1, gre_type=mirror_data.gre_type, dscp=mirror_data.dscp,
                          ttl=mirror_data.ttl, queue=mirror_data.queue,src_port=mirror_data.port_channel_name,
                          direction=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="erspan", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    [_, exceptions] = exec_all(True, [[intf.clear_interface_counters, vars.D1],
                                        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [
        [intf.clear_interface_counters, vars.D1],
        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    debug_cmd_list()
    mirror_erspan_tg_config_portchannel()

    receive_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface, "rx_ok")
    st.log("receive_counters_from_tg = {} ".format(receive_counters_from_tg))
    receive_count_int_value = int(receive_counters_from_tg[mirror_data.source_interface]['rx_ok'])
    st.log("receive_count_int_value = {} ".format(receive_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2_first,
                                                                      "tx_ok")
    st.log("tx_counters_from_mirrored_port = {} ".format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(
        tx_counters_from_mirrored_port[mirror_data.source_interface_D2_first]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} ".format(tx_counters_from_mirrored_port_int_value))

    if tx_counters_from_mirrored_port_int_value < int(0.98 * receive_count_int_value):
        st.log(
            "tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value). Some rx pkts did not get mirrored")
        st.report_fail("mirror_erspan_func_status", "failed")
    st.report_pass("mirror_erspan_mode_status","portchannel","pass")


@pytest.mark.test_mirroring_erspan_vlan
def test_ft_mirroring_erspan_vlan():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror_erspan_ip_config()
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,
                          mirror_type=mirror_data.mirror_type[1], src_ip=mirror_data.ip_D1T1P1,
                          dst_ip=mirror_data.ip_T1D2P1, gre_type=mirror_data.gre_type, dscp=mirror_data.dscp,
                          ttl=mirror_data.ttl, queue=mirror_data.queue)
    if not mirror.verify_session(vars.D1, mirror_type="erspan", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    mirrror_acl_config()
    [_, exceptions] = exec_all(True, [[intf.clear_interface_counters, vars.D1],
                                        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    mirror_erspan_tg_config()

    receive_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface, "rx_ok")
    st.log("receive_counters_from_tg = {} ".format(receive_counters_from_tg))
    receive_count_int_value = int(receive_counters_from_tg[mirror_data.source_interface]['rx_ok'])
    st.log("receive_count_int_value = {} ".format(receive_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2_first,
                                                                      "tx_ok")
    st.log("tx_counters_from_mirrored_port = {} ".format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(
        tx_counters_from_mirrored_port[mirror_data.source_interface_D2_first]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} ".format(tx_counters_from_mirrored_port_int_value))

    if tx_counters_from_mirrored_port_int_value < int(0.98 * receive_count_int_value):
        st.log(
            "tx_counters_from_mirrored_port_int_value < int(0.98*receive_count_int_value). Some rx pkts did not get mirrored")
        st.report_fail("mirror_erspan_func_status", "failed")
    st.report_pass("mirror_erspan_mode_status", "vlan","pass")


@pytest.mark.test_mirroring_max_session
def test_ft_mirroring_max_session():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port ingress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirroring_clear()
    data = {"cli_ype":"rest","data": [{"name":mirror_data.session_name,"dst_port":mirror_data.max_mirror_intf_list[0],
              "src_port":mirror_data.source_interface,"direction":mirror_data.direction_list[0]},
            {"name":mirror_data.session_name1,"dst_port":mirror_data.max_mirror_intf_list[1],
             "src_port":mirror_data.source_interface,"direction":mirror_data.direction_list[0]},
            {"name":mirror_data.session_name2,"dst_port":mirror_data.max_mirror_intf_list[2],
             "src_port":mirror_data.source_interface,"direction":mirror_data.direction_list[0]},
            {"name":mirror_data.session_name3,"dst_port":mirror_data.max_mirror_intf_list[3],
             "src_port":mirror_data.source_interface,"direction":mirror_data.direction_list[0]}],"action": "config"}
    data_verify = {"cli_ype":"rest","data": [{"name":mirror_data.session_name,
                                              "dst_port":mirror_data.max_mirror_intf_list[0],
                                              "src_port":mirror_data.source_interface,
                                              "direction":mirror_data.direction_list[0]},
                                             {"name":mirror_data.session_name1,
                                              "dst_port":mirror_data.max_mirror_intf_list[1],
                                              "src_port":mirror_data.source_interface,
                                              "direction":mirror_data.direction_list[0]},
                                             {"name":mirror_data.session_name2,
                                              "dst_port":mirror_data.max_mirror_intf_list[2],
                                              "src_port":mirror_data.source_interface,
                                              "direction":mirror_data.direction_list[0]},
                                             {"name":mirror_data.session_name3,
                                              "dst_port":mirror_data.max_mirror_intf_list[3],
                                              "src_port":mirror_data.source_interface,
                                              "direction":mirror_data.direction_list[0]}],"action": "config"}
    data_delete= {"cli_ype": "rest", "action": "unconfig"}
    mirror.config_max_sessions(vars.D1, data=data)
    if not mirror.verify_max_sessions(vars.D1,data=data_verify):
        st.report_fail("mirror_max_sessions_not_formed")
    vlan_config()
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add",tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    tg_init()
    mirroring_traffic_stream_config(direction="rx")
    data = {"module_type":"mirror","direction":"rx","source":[vars.D1T1P1,"rx_ok"], "destination":[vars.D1T1P2,"tx_ok"],
    "mirrored_port":[vars.D1D2P1,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D1,data):
        st.report_fail("mirror_func_with_max_session_status","failed")
    mirror.config_max_sessions(vars.D1, data=data_delete)
    st.report_pass("mirror_func_with_max_session_status","passed")


@pytest.mark.test_mirroring_gnmi
def test_ft_mirroring_gnmi():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the port mirroring(SPAN) can be cofigure via GNMI and check the functionality
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirroring_clear()
    json_content={"sonic-mirror-session:sonic-mirror-session"
                  :{"MIRROR_SESSION":{"MIRROR_SESSION_LIST":[{"name":mirror_data.session_name,
                                                              "dst_port":mirror_data.mirror_interface,
                                                              "src_port":mirror_data.source_interface,
                                                              "direction":mirror_data.direction_list[0]}]}}}

    gnmi_set_out = gnmi.gnmi_set(vars.D1,"/sonic-mirror-session:sonic-mirror-session/", json_content,
                  ip_address= mirror_data.dut_ip, insecure=mirror_data.insecure, mode='-update')
    st.log(gnmi_set_out)
    rpc_error="rpc error:"
    if rpc_error in gnmi_set_out :
        st.report_fail("mirroring_gnmi_get_or_set_operation_has_invalid_values","set")
    gnmi_get_out = gnmi.gnmi_get(vars.D1,"/sonic-mirror-session:sonic-mirror-session",
                                 ip_address= mirror_data.dut_ip,insecure=mirror_data.insecure, mode='-update')
    st.log("gnmi_get_out is :{}".format(gnmi_get_out))
    gnmi_get_out_value_mir_list = gnmi_get_out["sonic-mirror-session:sonic-mirror-session"]['MIRROR_SESSION']
    gnmi_get_mirror_name_output = gnmi_get_out_value_mir_list['MIRROR_SESSION_LIST'][-0]['name']
    st.log("gNMI get name output is :{}".format(gnmi_get_mirror_name_output))
    if not gnmi_get_mirror_name_output == mirror_data.session_name:
        st.report_fail("mirroring_gnmi_get_or_set_operation_has_invalid_values","get")
    vlan_config()
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add", tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    mirroring_traffic_stream_config(direction="rx")
    data = {"module_type": "mirror", "direction": "rx", "source": [vars.D1T1P1, "rx_ok"],
            "destination": [vars.D1T1P2, "tx_ok"],
            "mirrored_port": [vars.D1D2P1, "tx_ok"]}
    if not intf.verify_interface_counters(vars.D1, data):
        st.report_fail("mirroring_after_gnmi_config_status","Fail")
    st.report_pass("mirroring_after_gnmi_config_status","Pass")

@pytest.mark.test_mirroring_on_port_muilpe_source
def test_ft_mirroring_on_port_mutiple_source():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a source port can be deleted independently from other source port
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name1, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface_D1, rx_tx=mirror_data.direction_list[0])
    if not mirror.verify_session(vars.D1, mirror_type="span",
                                     session_name=mirror_data.session_name1):
        st.report_fail("mirror_session_verification_failed")
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                    config="add",tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    tg_init()
    mirroring_traffic_stream_config(direction="both")
    data = {"module_type": "mirror_both", "direction": "rx", "source": [vars.D1T1P1, "rx_ok"],
            "destination": [vars.D1T1P2, "rx_ok"],
             "mirrored_port":[vars.D1D2P1,"tx_ok"]}
    if not intf.verify_interface_counters(vars.D1,data):
        st.report_fail("mirroring_with_multi_source_verify_pass_fail","rx","fail")
    st.report_pass("mirroring_with_multi_source_verify_pass_fail","rx","pass")


@pytest.mark.test_mirroring_on_port_muilpe_source_both
def test_ft_mirroring_on_port_mutiple_source_dir_both():
    mirror.show_session_all(vars.D1, session_name=None)
    mirror.create_session(vars.D1, session_name=mirror_data.session_name, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="span", session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    mirror.create_session(vars.D1, session_name=mirror_data.session_name1, mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface,
                          source_ifname=mirror_data.source_interface_D1, rx_tx=mirror_data.direction_list[2])
    if not mirror.verify_session(vars.D1, mirror_type="span",
                                 session_name=mirror_data.session_name1):
        st.report_fail("mirror_session_verification_failed")

    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                    config="add", tagged=False, skip_verify=False)
    intf.clear_interface_counters(vars.D1)
    intf.show_interface_counters_all(vars.D1)
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    tr9 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst",
                               pkts_per_burst=1, length_mode='fixed',
                               rate_pps=1, frame_size=64, mac_src=mirror_data.source_mac,
                               vlan_id=mirror_data.vlan, vlan="enable", mac_dst=mirror_data.destination_mac)
    tr10 = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode="single_burst",
                               pkts_per_burst=1, length_mode='fixed',
                               rate_pps=1, frame_size=64, mac_src=mirror_data.destination_mac,
                               vlan_id=mirror_data.vlan, vlan="enable", mac_dst=mirror_data.source_mac)
    tg.tg_traffic_control(action='run', handle=tr9['stream_id'])
    st.wait(1)
    tg.tg_traffic_control(action='stop', handle=tr9['stream_id'])
    tg.tg_traffic_control(action='run', handle=tr10['stream_id'])
    st.wait(1)
    tg.tg_traffic_control(action='stop', handle=tr10['stream_id'])

    tg.tg_traffic_config(mode='modify', stream_id=tr9['stream_id'], pkts_per_burst=1000,rate_pps=1000)
    tg.tg_traffic_control(action='run', handle=tr9['stream_id'])
    st.wait(3)
    tg.tg_traffic_control(action='stop', handle=tr9['stream_id'])

    tg.tg_traffic_config(mode='modify', stream_id=tr10['stream_id'], pkts_per_burst=1000, rate_pps=1000)
    tg.tg_traffic_control(action='run', handle=tr10['stream_id'])
    st.wait(3)
    tg.tg_traffic_control(action='stop', handle=tr10['stream_id'])
    source_1_rx = [vars.D1T1P1, "rx_ok"]
    source_2_rx = [vars.D1T1P2, "rx_ok"]
    source_1_tx = [vars.D1T1P1, "tx_ok"]
    source_2_tx = [vars.D1T1P2, "tx_ok"]
    mirror_1_cntr = [vars.D1D2P1,"tx_ok"]
    output = intf.show_interface_counters_all(vars.D1)
    if not output:
        st.log("Output not found")
        st.report_fail("interface_counters_not_found")
    source_1_cntr_rx, source_2_cntr_rx, source_1_cntr_tx, source_2_cntr_tx = 0, 0, 0, 0

    for data in output:
        if data["iface"] == source_1_rx[0]:
            source_1_cntr_rx = data[source_1_rx[1]]
        if data["iface"] == source_2_rx[0]:
            source_2_cntr_rx = data[source_2_rx[1]]
        if data["iface"] == source_1_tx[0]:
            source_1_cntr_tx = data[source_1_tx[1]]
        if data["iface"] == source_2_tx[0]:
            source_2_cntr_tx = data[source_2_tx[1]]
        if data["iface"] == mirror_1_cntr[0]:
            mirror_1_cntr = data[mirror_1_cntr[1]]

    source_1_cntr_rx = int(source_1_cntr_rx.replace(",", ""))
    source_2_cntr_rx = int(source_2_cntr_rx.replace(",", ""))
    source_1_cntr_tx = int(source_1_cntr_tx.replace(",", ""))
    source_2_cntr_tx = int(source_2_cntr_tx.replace(",", ""))
    mirror_1_cntr    = int(mirror_1_cntr.replace(",", ""))
    st.log('source 1 rx counter is {}'.format(source_1_cntr_rx))
    st.log('source 2 rx counter is {}'.format(source_2_cntr_rx))
    st.log('source 1 tx counter is {}'.format(source_1_cntr_tx))
    st.log('source 2 tx counter is {}'.format(source_2_cntr_tx))
    st.log('Mirror 1 counter is is {}'.format(mirror_1_cntr))

    if not (source_1_cntr_tx+source_2_cntr_tx+source_1_cntr_rx+source_2_cntr_rx) >= 0.98 *(mirror_1_cntr):
        st.log("CHECK -- (source_1_cntr_tx+source_2_cntr_tx+source_1_cntr_rx+source_2_cntr_rx) >= 0.98 * 2"
               " * (mirror_1_cntr) FAILED ")
        st.report_fail("mirroring_with_multi_source_verify_pass_fail","both","fail")
    st.report_pass("mirroring_with_multi_source_verify_pass_fail","both","pass")


@pytest.mark.test_mirroring_on_vlan_rx
def test_ft_mirroring_on_vlan_rx():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that a mirror can be created using a source port as vlan ingress packets only.
    Reference Test Bed : 2IXIA-D1 --- D2-2IXIA
    """
    mirror.create_session(vars.D1, session_name=mirror_data.session_name,mirror_type="span",
                          destination_ifname=mirror_data.mirror_interface)
    if not mirror.verify_session(vars.D1,mirror_type="span",session_name=mirror_data.session_name):
        st.report_fail("mirror_session_verification_failed")
    mirrror_acl_config()
    vlanapi.config_vlan_members(vars.D1, vlan_list=[mirror_data.vlan], port_list=[vars.D1T1P1, vars.D1T1P2],
                                config="add",tagged=False, skip_verify=False)
    [_, exceptions] = exec_all(True, [[intf.clear_interface_counters, vars.D1],
                                        [intf.clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[intf.show_interface_counters_all, vars.D1],
                                        [intf.show_interface_counters_all, vars.D2]])
    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    tr5 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst",
                         pkts_per_burst=mirror_data.pkts_per_burst, length_mode='fixed',
                         rate_pps=mirror_data.rate_pps, frame_size=64, mac_src=mirror_data.source_mac,
                         vlan_id=mirror_data.vlan, vlan="enable", mac_dst=mirror_data.destination_mac)
    tg.tg_traffic_control(action='run', handle=tr5['stream_id'])
    st.wait(3)
    tg.tg_traffic_control(action='stop', handle=tr5['stream_id'])
    intf.show_interface_counters_all(vars.D1)
    st.exec_each(mirror_data.dut_list, intf.clear_interface_counters)
    st.exec_each(mirror_data.dut_list, asicapi.clear_counters)
    st.exec_each(mirror_data.dut_list, intf.show_interface_counters_all)
    tg.tg_traffic_config(mode='modify', stream_id=tr5['stream_id'], transmit_mode='continuous')
    tg.tg_traffic_control(action='run',handle=tr5['stream_id'])

    st.log("Performing Config save")
    config_save(vars.D1)
    st.log("Performing warm Reboot")
    st.reboot(vars.D1, "warm")

    tg.tg_traffic_control(action='stop', handle=tr5['stream_id'])
    st.wait(3)
    destination_counters_from_tg = intf.get_interface_counter_value(vars.D1, mirror_data.source_interface_D1, "tx_ok")
    st.log("receive_counters_from_tg = {} ".format(destination_counters_from_tg))
    destination_count_int_value = int(destination_counters_from_tg[mirror_data.source_interface_D1]['tx_ok'])
    st.log("receive_count_int_value = {} ".format(destination_count_int_value))

    tx_counters_from_mirrored_port = intf.get_interface_counter_value(vars.D1, mirror_data.mirror_interface,
                                                                      "tx_ok")
    st.log("tx_counters_from_mirrored_port = {} ".format(tx_counters_from_mirrored_port))
    tx_counters_from_mirrored_port_int_value = int(
        tx_counters_from_mirrored_port[mirror_data.mirror_interface]['tx_ok'])
    st.log("tx_counters_from_mirrored_port_int_value = {} ".format(tx_counters_from_mirrored_port_int_value))

    st.log(" About to get Rx Counters of Dut2 interface connected to mirror interface of Dut1 ")
    rx_count_D2_connected_to_mirror_interface = intf.get_interface_counter_value(vars.D2, mirror_data.source_interface_D2, "rx_ok")
    st.log("Rx Counters of Dut2 interface connected to mirror interface of Dut1 = {} ".format(rx_count_D2_connected_to_mirror_interface))
    rx_count_D2_connected_to_mirror_interface_int_value = int(rx_count_D2_connected_to_mirror_interface[mirror_data.source_interface_D2]['rx_ok'])
    st.log("Rx Counters of Dut2 interface connected to mirror interface of Dut1 integer value = {} ".format(rx_count_D2_connected_to_mirror_interface_int_value))
    st.exec_each(mirror_data.dut_list, asicapi.dump_counters)
    st.wait(5)
    st.exec_each(mirror_data.dut_list, intf.show_interface_counters_all)
    st.exec_each(mirror_data.dut_list, asicapi.dump_counters)

    if tx_counters_from_mirrored_port_int_value < int(0.98 * destination_count_int_value):
        st.log("tx_counters_from_mirrored_port_int_value < int(0.98*destination_count_int_value)")
        [_, exceptions] = exec_all(True, [[basic.service_operations_by_systemctl, vars.D1, "lldp", "stop"],
                                            [basic.service_operations_by_systemctl, vars.D2, "lldp", "stop"]])
        ensure_no_exception(exceptions)
        st.report_fail("mirror_vlan_func_with_dir_as_rx_not_working")
    [_, exceptions] = exec_all(True, [[basic.service_operations_by_systemctl, vars.D1, "lldp", "stop"],
                                        [basic.service_operations_by_systemctl, vars.D2, "lldp", "stop"]])
    ensure_no_exception(exceptions)
    st.report_pass("mirroring_with_vlan_rx_working_fine")
