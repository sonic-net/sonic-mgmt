import pytest
import random

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list, filter_and_select

import apis.qos.acl_dscp as acl_dscp
from apis.qos.acl import clear_acl_config, create_acl_rule, create_acl_table
from apis.switching.vlan import create_vlan, add_vlan_member, clear_vlan_configuration
from apis.switching.portchannel import create_portchannel, delete_portchannel, add_portchannel_member, \
    delete_portchannel_member
from apis.routing.ip import config_ip_addr_interface
from apis.system.interface import clear_interface_counters, poll_for_interfaces, show_interface_counters_all
from apis.system.port import shutdown, noshutdown
import apis.qos.acl as acl_obj
import utilities.common as utils
from utilities.parallel import ensure_no_exception
data = SpyTestDict()


def initialize_variables():
    data.acl_ipv4_table_name = "acl_table_v4"
    data.acl_ipv4_table_name_1 = "acl_table_v4_1"
    data.acl_ipv4_table_name_2 = "acl_table_v4_2"
    data.acl_ipv4_table_name_3 = "acl_table_v4_3"
    data.acl_ipv6_table_name = "acl_table_v6"
    data.acl_mac_table_name = "acl_table_l2"
    data.rule_name = "rule_1"
    data.rule_name2 = "rule2"
    data.type_ipv4 = "L3"
    data.type_ipv6 = "L3V6"
    data.type_mac = "L2"
    data.acl_type_ipv4 = "ip"
    data.acl_type_ipv6 = "ipv6"
    data.acl_type_mac = "mac"
    data.policy_name_1 = "policy1"
    data.policy_name_2 = "policy2"
    data.policy_name_3 = "policy3"
    data.policy_name_4 = "policy4"
    data.policy_type = "qos"
    data.class_name_1 = "class1"
    data.class_name_2 = "class2"
    data.class_name_3 = "class3"
    data.class_name_4 = "class4"
    data.class_name_5 = "class5"
    data.max_creation = random.randint(5, 128)
    data.class_type = "acl"
    data.flow_priority = ["300", "200", "100"]
    data.flow_priority_verify = ["600", "500", "400"]
    data.port_channel = "PortChannel24"
    data.vlan_1 = str(random_vlan_list()[0])
    data.vlan_name = "Vlan" + data.vlan_1
    data.class_criteria = ["--acl", "--police"]
    data.class_no_criteria = ["--no-acl", "--no-police"]
    data.police_1 = [500000, 62500, 550000, 68750]
    data.police_2 = [500000, 62500, 0, 0]
    data.police_3 = [500000, 65200, 550000, 68750]
    data.stage = ['in', 'out']
    data.ipAddr = "1.1.1.1"
    data.subnetMask = "24"
    data.ipv6Addr = "2001::1"
    data.subnetMaskv6 = "64"
    data.max_sections = 64
    data.flag = 1
    data.tg_src_mac = "00:00:00:ab:cd:ef"
    data.tg_dst_mac = "00:00:00:ab:cd:f0"
    data.tg_mac_mask = "ff:ff:ff:ff:ff:ff"
    data.tg_src_ipAddr = "1.1.1.2"
    data.tg_dst_ipAddr = "1.1.1.3"
    data.tg_src_ipv6Addr = "2001::2"
    data.tg_dst_ipv6Addr = "2001::3"
    data.traffic_duration = 5


def portchannel_create():
    create_portchannel(vars.D1, data.port_channel)
    create_portchannel(vars.D2, data.port_channel)
    add_portchannel_member(vars.D1, data.port_channel, [vars.D1D2P1, vars.D1D2P2])
    add_portchannel_member(vars.D2, data.port_channel, [vars.D2D1P1, vars.D2D1P2])


def portchannel_delete():
    delete_portchannel_member(vars.D1, data.port_channel, [vars.D1D2P1, vars.D1D2P2])
    delete_portchannel_member(vars.D2, data.port_channel, [vars.D2D1P1, vars.D2D1P2])
    delete_portchannel(vars.D1, data.port_channel)
    delete_portchannel(vars.D2, data.port_channel)


def vlan_create_and_add_members():
    create_vlan(vars.D1, data.vlan_1)
    add_vlan_member(vars.D1, data.vlan_1, [vars.D1T1P1, vars.D1T1P2, data.port_channel], tagging_mode=True)
    create_vlan(vars.D2, data.vlan_1)
    add_vlan_member(vars.D2, data.vlan_1, [vars.D2T1P1, data.port_channel], tagging_mode=True)


def vlan_config_delete():
    clear_vlan_configuration([vars.D1, vars.D2])


def ipv4_ipv6_intf_create():
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipAddr, subnet=data.subnetMask,
                             family="ipv4")
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipv6Addr,
                             subnet=data.subnetMaskv6, family="ipv6")


def ipv4_ipv6_intf_delete():
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipAddr,
                             subnet=data.subnetMask, family="ipv4", config='remove')
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipv6Addr,
                             subnet=data.subnetMaskv6, family="ipv6", config='remove')


def simple_policy_classifier_flow_create():
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name='single_rate', policy_type=data.policy_type)
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name='class_single_rate',
                                     acl_type=data.type_ipv4, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name='class_single_rate', acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name)
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name='single_rate', class_name='class_single_rate',
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name='single_rate', policy_type=data.policy_type,
                                      class_name='class_single_rate', priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])


def simple_policy_classifier_flow_delete():
    acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name='single_rate', class_name='class_single_rate')
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name='single_rate')
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name='class_single_rate')


def policy_classifier_flow_create(dut):
    acl_dscp.config_policy_table(dut, enable='create', policy_name=data.policy_name_1, policy_type=data.policy_type)
    acl_dscp.config_policy_table(dut, enable='create', policy_name=data.policy_name_2, policy_type=data.policy_type)
    acl_dscp.config_policy_table(dut, enable='create', policy_name=data.policy_name_3, policy_type=data.policy_type)
    acl_dscp.config_classifier_table(dut, enable='create', class_name=data.class_name_1, match_type=data.class_type)
    acl_dscp.config_classifier_table(dut, enable='create', class_name=data.class_name_2, match_type=data.class_type)
    acl_dscp.config_classifier_table(dut, enable='create', class_name=data.class_name_3, match_type=data.class_type)
    acl_dscp.config_classifier_table(dut, enable='yes', class_name=data.class_name_1,acl_type=data.acl_type_mac,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_mac_table_name)
    acl_dscp.config_classifier_table(dut, enable='yes', class_name=data.class_name_2, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name)
    acl_dscp.config_classifier_table(dut, enable='yes', class_name=data.class_name_3, acl_type=data.acl_type_ipv6,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv6_table_name)
    acl_dscp.config_flow_update_table(dut, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_1,
                                      policy_type=data.policy_type, match_type=data.class_type,
                                      priority_value=data.flow_priority[2], description="classification_L2_traffic")
    acl_dscp.config_flow_update_table(dut, flow='add', policy_name=data.policy_name_2, class_name=data.class_name_2,
                                      policy_type=data.policy_type, match_type=data.class_type,
                                      priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(dut, flow='add', policy_name=data.policy_name_3, class_name=data.class_name_3,
                                      policy_type=data.policy_type, match_type=data.class_type,
                                      priority_value=data.flow_priority[0], description="classification_L3V6_traffic")
    acl_dscp.config_flow_update_table(dut, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_1, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, match_type=data.class_type,
                                      priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])
    acl_dscp.config_flow_update_table(dut, flow='update', policy_name=data.policy_name_2,
                                      class_name=data.class_name_2, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, match_type=data.class_type,
                                      priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])
    acl_dscp.config_flow_update_table(dut, flow='update', policy_name=data.policy_name_3,
                                      class_name=data.class_name_3, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])


def policy_classifier_flow_delete(dut):
    acl_dscp.config_flow_update_table(dut, flow='del', policy_name=data.policy_name_1, class_name=data.class_name_1)
    acl_dscp.config_flow_update_table(dut, flow='del', policy_name=data.policy_name_2, class_name=data.class_name_2)
    acl_dscp.config_flow_update_table(dut, flow='del', policy_name=data.policy_name_3, class_name=data.class_name_3)
    acl_dscp.config_policy_table(dut, enable='del', policy_name=data.policy_name_1)
    acl_dscp.config_policy_table(dut, enable='del', policy_name=data.policy_name_2)
    acl_dscp.config_policy_table(dut, enable='del', policy_name=data.policy_name_3)
    acl_dscp.config_classifier_table(dut, enable='del', class_name=data.class_name_1)
    acl_dscp.config_classifier_table(dut, enable='del', class_name=data.class_name_2)
    acl_dscp.config_classifier_table(dut, enable='del', class_name=data.class_name_3)


def initialize_module_config():
    portchannel_create()
    vlan_create_and_add_members()
    ipv4_ipv6_intf_create()
    [_, exceptions] = utils.exec_all(True, [[policy_classifier_flow_create, vars.D1], [policy_classifier_flow_create, vars.D2]])
    ensure_no_exception(exceptions)


def clear_module_config():

    vlan_config_delete()
    portchannel_delete()
    policy_classifier_flow_delete(vars.D2)
    #[_, exceptions] = utils.exec_all(True, [[policy_classifier_flow_delete, vars.D1], [policy_classifier_flow_delete, vars.D2]])
    #ensure_no_exception(exceptions)
    [_, exceptions] = utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    ensure_no_exception(exceptions)


def v4_in_acl(dut):

    create_acl_table(dut, name=data.acl_ipv4_table_name, stage='INGRESS', type=data.type_ipv4, description='L3 ACL',
                     ports=[])
    create_acl_rule(dut, table_name=data.acl_ipv4_table_name, acl_type=data.type_ipv4, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'), DST_IP="{}/{}".format('1.1.1.3', '32'))


def v4_eg_acl(dut):
    create_acl_table(dut, name=data.acl_ipv4_table_name, stage='EGRESS', type=data.type_ipv4, description='L3 ACL',ports=[])
    create_acl_rule(dut, table_name=data.acl_ipv4_table_name, acl_type=data.type_ipv4, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'),
                    DST_IP="{}/{}".format('1.1.1.3', '32'))


def mac_in_acl(dut):
    create_acl_table(dut, name=data.acl_mac_table_name, stage='INGRESS', type=data.type_mac, description='L2 ACL',
                     ports=[])
    create_acl_rule(dut, table_name=data.acl_mac_table_name, rule_name='rule_1', acl_type=data.type_mac,
                    priority=data.flow_priority[2], packet_action='FORWARD',
                    SRC_MAC="{}/{}".format(data.tg_src_mac, data.tg_mac_mask),
                    DST_MAC="{}/{}".format(data.tg_dst_mac, data.tg_mac_mask))


def mac_eg_acl(dut):
    create_acl_table(dut, name=data.acl_mac_table_name, stage='EGRESS', type=data.type_mac, description='L2 ACL',
                     ports=[])

    create_acl_rule(dut, table_name=data.acl_mac_table_name, rule_name='rule_1', acl_type=data.type_mac,
                    priority=data.flow_priority[2], packet_action='FORWARD',
                    SRC_MAC="{}/{}".format(data.tg_src_mac, data.tg_mac_mask),
                    DST_MAC="{}/{}".format(data.tg_dst_mac, data.tg_mac_mask))


def v6_in_acl(dut):
    create_acl_table(dut, name=data.acl_ipv6_table_name, stage='INGRESS', type=data.type_ipv6,
                     description='L3V6 ACL', ports=[])
    create_acl_rule(dut, table_name=data.acl_ipv6_table_name, acl_type=data.type_ipv6, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_IPV6="{}/{}".format('2001::2', '128'),
                    DST_IPV6="{}/{}".format('2001::3', '128'))


def v6_eg_acl(dut):
    create_acl_table(dut, name=data.acl_ipv6_table_name, stage='EGRESS', type=data.type_ipv6,
                     description='L3V6 ACL', ports=[])

    create_acl_rule(dut, table_name=data.acl_ipv6_table_name, rule_name='rule_1', acl_type=data.type_ipv6,
                    priority=data.flow_priority[2], packet_action='FORWARD', SRC_IPV6="{}/{}".format('2001::2', '128'),
                    DST_IPV6="{}/{}".format('2001::3', '128'))


def delete_acl_table(dut):
    clear_acl_config(vars.D1, acl_type=data.acl_type_ipv4, acl_table_name=data.acl_ipv4_table_name)
    clear_acl_config(vars.D1, acl_type=data.acl_type_ipv6, acl_table_name=data.acl_ipv6_table_name)
    clear_acl_config(vars.D1, acl_type=data.acl_type_mac, acl_table_name=data.acl_mac_table_name)
    clear_acl_config(vars.D1, acl_type=data.acl_type_ipv4, acl_table_name=data.acl_ipv4_table_name)
    clear_acl_config(vars.D1, acl_type=data.acl_type_ipv6, acl_table_name=data.cl_ipv6_table_name)
    clear_acl_config(vars.D1, acl_type=data.acl_type_mac, acl_table_name=data.acl_mac_table_name)


def config_dut1():
    create_portchannel(vars.D1, data.port_channel)
    v4_in_acl(vars.D1)
    mac_in_acl(vars.D1)
    v6_in_acl(vars.D1)
    add_portchannel_member(vars.D1, data.port_channel, [vars.D1D2P1, vars.D1D2P2])
    create_vlan(vars.D1, data.vlan_1)
    add_vlan_member(vars.D1, data.vlan_1, [vars.D1T1P1, vars.D1T1P2, data.port_channel], tagging_mode=True)
    policy_classifier_flow_create(vars.D1)


def config_dut2():
    create_portchannel(vars.D2, data.port_channel)
    v4_in_acl(vars.D2)
    v6_in_acl(vars.D2)
    mac_in_acl(vars.D2)
    add_portchannel_member(vars.D2, data.port_channel, [vars.D2D1P1, vars.D2D1P2])
    create_vlan(vars.D2, data.vlan_1)
    add_vlan_member(vars.D2, data.vlan_1, [vars.D2T1P1, data.port_channel], tagging_mode=True)
    policy_classifier_flow_create(vars.D2)


def tg_config():
    st.log("Creating TG streams")
    data.streams = {}
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', frame_size=64, rate_percent=10,
                                       l2_encap='ethernet_ii_vlan',
                                       vlan='enable', vlan_id=data.vlan_1, mac_src=data.tg_src_mac,
                                       mac_dst=data.tg_dst_mac,
                                       pkts_per_burst='12000')
    data.streams['l2_stream'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', rate_percent=10, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', l4_protocol="tcp",
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv4',
                                       ip_src_addr=data.tg_src_ipAddr, ip_dst_addr=data.tg_dst_ipAddr,
                                       pkts_per_burst='12000')
    data.streams['ipv4_stream'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous',
                                       length_mode='fixed', rate_percent=10, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', l4_protocol="tcp",
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv4',
                                       ip_src_addr=data.tg_src_ipAddr, ip_dst_addr=data.tg_dst_ipAddr)
    data.streams['ipv4_linerate_stream'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous',
                                       length_mode='fixed', rate_pps=12000, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', l4_protocol="tcp",
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv4',
                                       ip_src_addr=data.tg_src_ipAddr, ip_dst_addr=data.tg_dst_ipAddr)
    data.streams['ipv4_stream2'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', rate_percent=10, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', l4_protocol="tcp",
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv6',
                                       ipv6_src_addr=data.tg_src_ipv6Addr, ipv6_dst_addr=data.tg_dst_ipv6Addr,
                                       pkts_per_burst='12000')
    data.streams['ipv6_stream'] = stream['stream_id']


@pytest.fixture(scope="module", autouse=True)
def acl_ratelimit_module_hook(request):
    global vars
    vars = st.ensure_min_topology('D1T1:2', 'D1D2:2', 'D2T1:1')
    initialize_variables()
    st.log("Getting TG handlers")

    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    data.tg = data.tg1

    utils.exec_all(True, [utils.ExecAllFunc(tg_config), utils.ExecAllFunc(config_dut1), utils.ExecAllFunc(config_dut2)],
                   first_on_main=True)

    yield
    clear_module_config()


def func_in_bind_cleanup(dut, policy):

    intf_name = [vars.D1T1P1, "Switch", data.vlan_name]
    for intf in intf_name:
        bind_policy_and_verify_status(dut, intf, data.stage[0], policy, 'del')


def func_eg_bind_cleanup(dut, policy):

    intf_name = [vars.D1T1P2, "Switch", data.vlan_name]
    for intf in intf_name:
        bind_policy_and_verify_status(dut, intf, data.stage[1], policy, 'del')


def func_in_portchannel_bind_cleanup(dut, policy):

    bind_policy_and_verify_status(dut, data.port_channel, data.stage[0], policy, 'del')


def func_eg_portchannel_bind_cleanup(dut, policy):

    bind_policy_and_verify_status(dut, data.port_channel, data.stage[1], policy, 'del')


@pytest.fixture(scope="function", autouse=True)
def acl_ratelimit_func_hooks(request):

    if st.get_func_name(request) == "test_ft_verify_acl_rate_limit_priority_over_intf":
        policy_classifier_flow_delete(vars.D1)

    yield
    data.flag = 1
    if st.get_func_name(request) in "test_ft_acl_ipv4_in_rate_limit_intf_vlan":
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_ipv6_in_rate_limit_intf_vlan":
        func_in_bind_cleanup(vars.D1, data.policy_name_3)
    elif st.get_func_name(request) in "test_ft_acl_l2_in_rate_limit_intf_vlan":
        func_in_bind_cleanup(vars.D1, data.policy_name_1)
    elif st.get_func_name(request) in "test_ft_acl_ipv4_eg_rate_limit_intf_vlan":
        func_eg_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_ipv6_eg_rate_limit_intf_vlan":
        func_eg_bind_cleanup(vars.D1, data.policy_name_3)
    elif st.get_func_name(request) in "test_ft_acl_l2_eg_rate_limit_intf_vlan":
        func_eg_bind_cleanup(vars.D1, data.policy_name_1)
    elif st.get_func_name(request) in "test_ft_acl_ipv4_in_rate_limit_port_channel":
        func_in_portchannel_bind_cleanup(vars.D2, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_ipv6_in_rate_limit_port_channel":
        func_in_portchannel_bind_cleanup(vars.D2, data.policy_name_3)
    elif st.get_func_name(request) in "test_ft_acl_l2_in_rate_limit_port_channel":
        func_in_portchannel_bind_cleanup(vars.D2, data.policy_name_1)
    elif st.get_func_name(request) in "test_ft_acl_ipv4_eg_rate_limit_port_channel":
        func_eg_portchannel_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_ipv6_eg_rate_limit_port_channel":
        func_eg_portchannel_bind_cleanup(vars.D1, data.policy_name_3)
    elif st.get_func_name(request) in "test_ft_acl_l2_eg_rate_limit_port_channel":
        func_eg_portchannel_bind_cleanup(vars.D1, data.policy_name_1)
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_unbind_interface":
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_verify_acl_line_rate_traffic":
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_shut_noshut_interface":
        bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'del')
        simple_policy_classifier_flow_delete()
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_nonexist_policy":
        acl_dscp.config_service_policy_table(vars.D1, skip_error=True, interface_name=vars.D1T1P1, stage=data.stage[0],
                                             service_policy_name='test_non_exist', policy_kind='unbind')
        acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name="test_non_exist",class_name=data.class_name_5)
        acl_dscp.config_policy_table(vars.D1, enable='del', policy_name="test_non_exist")
        acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_5)
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_remove_policy":
        acl_dscp.config_classifier_table(vars.D1, enable='del', class_name='class_single_rate')
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_singlepolicy_multiflow_config":
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
        acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_1,
                                          class_name=data.class_name_2)
        acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_2,
                                          class_name=data.class_name_3)
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_policy_scalability":

        for element in range(1, data.max_sections + 2):
            classifier_name = data.class_name_2 + str(element)
            acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name='test', class_name=classifier_name)
            acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=classifier_name)
        acl_dscp.config_policy_table(vars.D1, enable='del', policy_name='test')
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_warm_reboot":
        bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'del')
        simple_policy_classifier_flow_delete()
    elif st.get_func_name(request) in "test_ft_verify_acl_rate_limit_priority_over_intf":

        func_in_bind_cleanup(vars.D1, data.policy_name_1)
        func_in_bind_cleanup(vars.D1, data.policy_name_2)
        func_in_bind_cleanup(vars.D1, data.policy_name_3)
        policy_classifier_flow_delete(vars.D1)
        acl_obj.delete_acl_table(vars.D1, acl_type="ip", acl_table_name=[data.acl_ipv4_table_name_1, data.acl_ipv4_table_name_2 ])
    elif st.get_func_name(request) in "test_ft_acl_rate_limit_section_priority":
        func_in_bind_cleanup(vars.D1, data.policy_name_1)
        acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_1,
                                          class_name=data.class_name_1)
        acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_1,
                                          class_name=data.class_name_2)
        acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_1)
        acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_2)
        acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name_1)
        #policy_classifier_flow_create(vars.D1)


def bind_policy_and_verify_status(dut, intf_name, direction, policy_name, config):
    if config == "add":
        st.log("############### Bind policy to '{}' ###############".format(intf_name))

        acl_dscp.config_service_policy_table(dut, interface_name=intf_name, stage=direction,
                                             service_policy_name=policy_name, policy_kind='bind')
        match = [{'flow_state': '(Active)'}]
        if not acl_dscp.verify(dut, service_policy_interface=intf_name, verify_list=match):
            st.error("policy '{}' is inactive ".format(policy_name))
            st.report_fail("Flow_operation_failed")
    else:
        st.log("############### Unbind policy from '{}' ###############".format(intf_name))
        acl_dscp.config_service_policy_table(dut, interface_name=intf_name, stage=direction,
                                             service_policy_name=policy_name, policy_kind='unbind')


def verify_traffic(dut, src_intf, dst_intf, stage):
    st.log("Fetching interfaces statistics")
    counter_output = show_interface_counters_all(dut)
    if not counter_output:
        st.report_fail("interface_counters_not_found")
    ingress_rx_cnt = filter_and_select(counter_output, ['rx_ok'], {'iface': src_intf})[0]['rx_ok']
    ingress_rx_drp_cnt = filter_and_select(counter_output, ['rx_drp'], {'iface': src_intf})[0]['rx_drp']
    egress_tx_cnt = filter_and_select(counter_output, ['tx_ok'], {'iface': dst_intf})[0]['tx_ok']
    egress_tx_drp_cnt = filter_and_select(counter_output, ['tx_drp'], {'iface': dst_intf})[0]['tx_drp']

    st.log("Verifying traffic sent from port {} is 95% of traffic received on the port{}".format(src_intf, dst_intf))
    st.log("Traffic sent: {}".format(ingress_rx_cnt))
    st.log("Traffic dropped at ingress: {}".format(ingress_rx_drp_cnt))
    st.log("Traffic received: {}".format(egress_tx_cnt))
    st.log("Traffic dropped at egress: {}".format(egress_tx_drp_cnt))

    if stage == 'in':
        if (int(ingress_rx_drp_cnt.replace(',', '')) == 0):
            st.log("Ingress traffic is not rate-limited on {}".format(src_intf))
            data.flag = 0
    elif stage == 'out':
        if (int(egress_tx_drp_cnt.replace(',', '')) == 0):
            st.log("Egress traffic is not rate-limited on {}".format(dst_intf))
            data.flag = 0
    elif stage == 'None':
        if not (int(ingress_rx_drp_cnt.replace(',', '')) == 0):
            st.log("Ingress traffic is not rate-limited on {}".format(src_intf))
            data.flag = 0
        if not (int(egress_tx_drp_cnt.replace(',', '')) == 0):
            st.log("Egress traffic is not rate-limited on {}".format(dst_intf))
            data.flag = 0

    if not (95 * (int(ingress_rx_cnt.replace(',', '')) - int(ingress_rx_drp_cnt.replace(',', '')))) / 100 <= (
            int(egress_tx_cnt.replace(',', '')) + int(egress_tx_drp_cnt.replace(',', ''))):
        st.log("Traffic verification failed")
        data.flag = 0


def verify_policy_stats(dut, interface_name):
    """
    match = [{'green_pkts_val': 985, 'yellow_pkts_val': 16, 'red_pkts_val':199}]
    if not acl_dscp.verify(dut,service_policy_interface=interface_name,verify_list=match, cli_type="click"):
        st.error("flow stats are incorrect for'{}' ".format(interface_name))
        st.report_fail("Flow_operation_failed")
    """


def policy_flow_test_ipv4(dut, interface_name, policy_name, stage, src_intf, dst_intf, line_rate_traffic=False):

    bind_policy_and_verify_status(dut, interface_name, stage, policy_name, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(dut)
    st.log("Sending traffic from ingress ports")
    if line_rate_traffic:
        data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_linerate_stream']])
    else:
        data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    if line_rate_traffic:
        data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_linerate_stream']])
    else:
        data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(dut, src_intf, dst_intf, stage)
    verify_policy_stats(dut, interface_name)


def policy_flow_test_ipv6(dut, interface_name, policy_name, stage, src_intf, dst_intf):

    bind_policy_and_verify_status(dut, interface_name, stage, policy_name, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(dut)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv6_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv6_stream']])

    verify_traffic(dut, src_intf, dst_intf, stage)
    verify_policy_stats(dut, interface_name)


def policy_flow_test_mac(dut, interface_name, policy_name, stage, src_intf, dst_intf):

    bind_policy_and_verify_status(dut, interface_name, stage, policy_name, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(dut)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['l2_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['l2_stream']])

    verify_traffic(dut, src_intf, dst_intf, stage)
    verify_policy_stats(dut, interface_name)


@pytest.mark.regression55664
def test_ft_acl_ipv4_in_rate_limit_intf_vlan():
    policy_flow_test_ipv4(vars.D1, 'Switch', data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[0], data.policy_name_2, 'del')
    policy_flow_test_ipv4(vars.D1, data.vlan_name, data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[0], data.policy_name_2, 'del')
    policy_flow_test_ipv4(vars.D1, vars.D1T1P1, data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_2, 'del')
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv6_in_rate_limit_intf_vlan():
    policy_flow_test_ipv6(vars.D1, 'Switch', data.policy_name_3, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[0], data.policy_name_3, 'del')
    policy_flow_test_ipv6(vars.D1, data.vlan_name, data.policy_name_3, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[0], data.policy_name_3, 'del')
    policy_flow_test_ipv6(vars.D1, vars.D1T1P1, data.policy_name_3, data.stage[0], vars.D1T1P1, vars.D1T1P2)

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_l2_in_rate_limit_intf_vlan():
    policy_flow_test_mac(vars.D1, 'Switch', data.policy_name_1, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[0], data.policy_name_1, 'del')
    policy_flow_test_mac(vars.D1, data.vlan_name, data.policy_name_1, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[0], data.policy_name_1, 'del')
    policy_flow_test_mac(vars.D1, vars.D1T1P1, data.policy_name_1, data.stage[0], vars.D1T1P1, vars.D1T1P2)

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv4_eg_rate_limit_intf_vlan():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        v4_eg_acl(vars.D1)
        policy_flow_test_ipv4(vars.D1, 'Switch', data.policy_name_2, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[1], data.policy_name_2, 'del')
        policy_flow_test_ipv4(vars.D1, data.vlan_name, data.policy_name_2, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[1], data.policy_name_2, 'del')
        policy_flow_test_ipv4(vars.D1, vars.D1T1P2, data.policy_name_2, data.stage[1], vars.D1T1P1, vars.D1T1P2)

        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv6_eg_rate_limit_intf_vlan():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        v6_eg_acl(vars.D1)
        policy_flow_test_ipv6(vars.D1, 'Switch', data.policy_name_3, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[1], data.policy_name_3, 'del')
        policy_flow_test_ipv6(vars.D1, data.vlan_name, data.policy_name_3, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[1], data.policy_name_3, 'del')
        policy_flow_test_ipv6(vars.D1, vars.D1T1P2, data.policy_name_3, data.stage[1], vars.D1T1P1, vars.D1T1P2)

        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_l2_eg_rate_limit_intf_vlan():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        mac_eg_acl(vars.D1)
        policy_flow_test_mac(vars.D1, 'Switch', data.policy_name_1, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[1], data.policy_name_1, 'del')
        policy_flow_test_mac(vars.D1, data.vlan_name, data.policy_name_1, data.stage[1], vars.D1T1P1, vars.D1T1P2)
        bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[1], data.policy_name_1, 'del')
        policy_flow_test_mac(vars.D1, vars.D1T1P2, data.policy_name_1, data.stage[1], vars.D1T1P1, vars.D1T1P2)

        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression67856
def test_ft_acl_ipv4_in_rate_limit_port_channel():
    policy_flow_test_ipv4(vars.D2, data.port_channel, data.policy_name_2, data.stage[0], data.port_channel, vars.D2T1P1)
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv6_in_rate_limit_port_channel():
    policy_flow_test_ipv6(vars.D2, data.port_channel, data.policy_name_3, data.stage[0], data.port_channel, vars.D2T1P1)
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_l2_in_rate_limit_port_channel():
    policy_flow_test_mac(vars.D2, data.port_channel, data.policy_name_1, data.stage[0], data.port_channel, vars.D2T1P1)
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv4_eg_rate_limit_port_channel():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        policy_flow_test_ipv4(vars.D1, data.port_channel, data.policy_name_2, data.stage[1], vars.D1T1P1, data.port_channel)
        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_ipv6_eg_rate_limit_port_channel():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        policy_flow_test_ipv6(vars.D1, data.port_channel, data.policy_name_3, data.stage[1], vars.D1T1P1,data.port_channel)
        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_l2_eg_rate_limit_port_channel():
    if vars.hwsku[vars.D1].lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        st.error("Egress ACL rate limit is not supported for this platform {}".format(vars.hwsku[vars.D1]))
        st.report_unsupported('egress_acl_rate_limit_unsupported_platform', vars.hwsku[vars.D1])
    else:
        policy_flow_test_mac(vars.D1, data.port_channel, data.policy_name_1, data.stage[1], vars.D1T1P1, data.port_channel)
        if data.flag == 0:
            st.report_fail("Flow_operation_failed")
        else:
            st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_shut_noshut_interface():
    simple_policy_classifier_flow_create()

    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])
    if data.flag == 0:
        clear_acl_config(vars.D1, data.acl_ipv4_table_name)
        bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'del')
        st.report_fail("Flow_operation_failed")

    shutdown(vars.D1, [vars.D1T1P1])
    st.wait(3)
    noshutdown(vars.D1, [vars.D1T1P1])
    st.wait(3)

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_unbind_interface():
    policy_flow_test_ipv4(vars.D1, 'Switch', data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[0], data.policy_name_2, 'del')
    policy_flow_test_ipv4(vars.D1, vars.D1T1P1, data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2)
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_2, 'del')
    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, stage='None')
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_nonexist_policy():
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name='test', policy_type=data.policy_type)
    acl_dscp.config_flow_update_table(vars.D1, skip_error=True, flow='add', policy_name='test',
                                      class_name='test_non_exist', policy_type=data.policy_type,
                                      priority_value=data.flow_priority[1], description="classification_L3_traffic")

    acl_dscp.config_service_policy_table(vars.D1, skip_error=True, interface_name=vars.D1T1P1, stage=data.stage[0],
                                         service_policy_name='test', policy_kind='bind')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, stage='None')
    acl_dscp.config_service_policy_table(vars.D1, interface_name=vars.D1T1P1, stage=data.stage[0],
                                         service_policy_name='test', policy_kind='unbind')
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name='test')
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_5, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_5, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name)
    acl_dscp.config_flow_update_table(vars.D1, skip_error=True, flow='add', policy_name='test_non_exist',
                                      class_name=data.class_name_5, policy_type=data.policy_type,
                                      priority_value=data.flow_priority[1], description="classification_L3_traffic")

    acl_dscp.config_service_policy_table(vars.D1, skip_error=True, interface_name=vars.D1T1P1, stage=data.stage[0],
                                         service_policy_name='test_non_exist', policy_kind='bind')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, stage='None')

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_remove_policy():
    simple_policy_classifier_flow_create()
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'del')
    acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name='single_rate',
                                      class_name='class_single_rate')
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name='single_rate')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, stage='None')

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_singlepolicy_multiflow_config():

    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_2,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_2, class_name=data.class_name_3,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[0], description="classification_L3V6_traffic")

    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_2, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])

    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_2,
                                      class_name=data.class_name_3, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])

    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_1, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_1, 'del')

    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_2, 'add')
    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv6_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv6_stream']])

    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_policy_scalability():
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name='test', policy_type=data.policy_type)
    st.log("############### Test started for creating maximum Recommended classifiers ###############")
    for element in range(1, data.max_sections + 2):
        classifier_name = data.class_name_2 + str(element)
        acl_name = data.acl_ipv4_table_name + str(element)
        acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=classifier_name,
                                         acl_type=data.type_ipv4, match_type=data.class_type,
                                         description="checking_MAX_CLI")
        create_acl_table(vars.D1, name=acl_name, stage='INGRESS', type=data.type_ipv4, description='L3 ACL', ports=[])

        acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=classifier_name, acl_type=data.acl_type_ipv4,
                                         match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=acl_name)
        acl_dscp.config_flow_update_table(vars.D1, skip_error=True, flow='add', policy_name='test',
                                          class_name=classifier_name, policy_type=data.policy_type,
                                          priority_value=element, description="classification_L3_traffic")
    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_acl_rate_limit_warm_reboot():
    simple_policy_classifier_flow_create()
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], 'single_rate', 'add')
    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream2']])

    st.reboot(vars.D1, "warm")
    poll_for_interfaces(vars.D1, 90)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream2']])
    verify_traffic(vars.D1, vars.D1T1P1, vars.D1T1P2, data.stage[0])

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression
def test_ft_verify_acl_line_rate_traffic():
    policy_flow_test_ipv4(vars.D1, vars.D1T1P1, data.policy_name_2, data.stage[0], vars.D1T1P1, vars.D1T1P2, line_rate_traffic=True)

    if data.flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.regression87699
def test_ft_verify_acl_rate_limit_priority_over_intf():

    create_acl_table(vars.D1, name=data.acl_ipv4_table_name_1, stage='INGRESS', type=data.type_ipv4,
                     description='L3 ACL',
                     ports=[])
    create_acl_table(vars.D1, name=data.acl_ipv4_table_name_2, stage='INGRESS', type=data.type_ipv4,
                     description='L3 ACL',
                     ports=[])

    create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name_1, rule_name='rule_1', acl_type=data.type_ipv4,
                    priority=data.flow_priority[2], packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'),
                    DST_IP="{}/{}".format('1.1.1.3', '32'))
    create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name_2, rule_name='rule_1', acl_type=data.type_ipv4,
                    priority=data.flow_priority[2], packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'),
                    DST_IP="{}/{}".format('1.1.1.3', '32'))
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_1, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_2, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_3, policy_type=data.policy_type)

    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_1, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_2, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_3, match_type=data.class_type)

    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_1, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_2, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name_1)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_3, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name_2)

    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_1,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_2, class_name=data.class_name_2,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_3, class_name=data.class_name_3,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")

    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_1, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_2,
                                      class_name=data.class_name_2, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_3,
                                      class_name=data.class_name_3, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])

    bind_policy_and_verify_status(vars.D1, 'Switch', data.stage[0], data.policy_name_1, 'add')
    bind_policy_and_verify_status(vars.D1, data.vlan_name, data.stage[0], data.policy_name_2, 'add')
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_3, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])
    show_interface_counters_all(vars.D1)
    intf_output = acl_dscp.get(vars.D1, interface_name = vars.D1T1P1, value = 'match_pkts_val')
    st.log(intf_output)
    switch_output = acl_dscp.get(vars.D1, interface_name = 'Switch', value = 'match_pkts_val')
    st.log(switch_output)
    vlan_output = acl_dscp.get(vars.D1, interface_name = data.vlan_name, value = 'match_pkts_val')
    st.log(vlan_output)
    if not (int(intf_output)==12000 and int(switch_output)==0 and int(vlan_output)==0):
        st.report_fail('priority_check_failed')

    st.report_pass("test_case_passed")


@pytest.mark.regression87699
def test_ft_acl_rate_limit_section_priority():
    """Procedure:
    1) Create 2 ipv4 ACL tables acl1,acl2 with same acl rules different priority.
    2) Config classifiers class1,class2 and add acl1 to class1, acl2 to class2.
    3) Create a policy with the created classifiers and bind it to interface
    4) Send matched traffic

    Expected results:
    1) Verify ipv4 acl tables created with rules successfully
    2) Verify that classifier created successfully as per configured
    3) Verify that rate-limiting policy successfully bind to interface
    4) Verify  hit counters as per configured priority rule """


    create_acl_table(vars.D1, name=data.acl_ipv4_table_name_1, stage='INGRESS', type=data.type_ipv4,
                                      description='L3 ACL',
                                      ports=[])
    create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name_1, rule_name=data.rule_name2,acl_type=data.type_ipv4,
                                     priority=data.flow_priority[1], packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'),
                                     DST_IP="{}/{}".format('1.1.1.3', '32'))
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_1, policy_type=data.policy_type)

    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_1, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_2, match_type=data.class_type)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_1, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_2, acl_type=data.acl_type_ipv4,
                                     match_type=data.class_type, class_criteria=data.class_criteria[0], criteria_value=data.acl_ipv4_table_name_1)

    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_1,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[0], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_2,
                                      policy_type=data.policy_type, priority_value=data.flow_priority[1], description="classification_L3_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_1, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_1[0], priority_value_2=data.police_1[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_1[2], priority_value_4=data.police_1[3])
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_2, priority_option=data.class_criteria[1],
                                      priority_value_1=data.police_3[0], priority_value_2=data.police_3[1],
                                      policy_type=data.policy_type, priority_value_3=data.police_3[2], priority_value_4=data.police_3[3])
    bind_policy_and_verify_status(vars.D1, vars.D1T1P1, data.stage[0], data.policy_name_1, 'add')

    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)

    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['ipv4_stream']])
    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['ipv4_stream']])
    show_interface_counters_all(vars.D1)
    intf_output = acl_dscp.get(vars.D1, interface_name=vars.D1T1P1, value='match_pkts_val', full_output=True)
    st.log(intf_output)
    fail_flag = False
    for value in intf_output:
        if not (int(value["match_pkts_val"]))==12000:
            fail_flag = True
        else:
            fail_flag = False
            break
    if fail_flag:
        st.report_fail("Flow_operation_failed")
    st.report_pass("test_case_passed")

