import pytest
import random
from utilities.parallel import exec_all, ensure_no_exception
from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list
import apis.system.reboot as reboot_api
import apis.qos.acl_dscp as acl_dscp
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.qos.acl as acl_obj
from apis.routing.ip import config_ip_addr_interface
from apis.qos.acl import create_acl_table, create_acl_rule, apply_acl_config

import tests.qos.acl.acl_json_config as acl_data

data = SpyTestDict()

def initialize_variables():
    data.policy_name_1 = "policy1"
    data.policy_name_2 = "policy2"
    data.policy_name_3 = "policy3"
    data.policy_name_4 = "policy4"
    data.policy_name = "policy"
    data.class_name = "class"
    data.policy_type = "qos"
    data.class_name_1 = "class1"
    data.class_name_2 = "class2"
    data.class_name_3 = "class3"
    data.class_name_4 = "class4"
    data.max_creation = random.randint(5, 128)
    data.class_type = ["fields", "acl"]
    data.flow_priority = ["400", "300", "200", "100"]
    data.dscp = ["10", "14", "30", "22"]
    data.pcp = ["5", "2", "3"]
    data.invalid_pcp_dscp = ["65", "8"]
    data.tcp = ["fin", "syn"]
    data.ethertype = ["1558", "6550"]
    data.port_channel = ["PortChannel24", "PortChannel33"]
    data.vlan_1 = str(random_vlan_list()[0])
    data.vlan_name = "Vlan" + data.vlan_1
    data.class_criteria_1 = ["--src-ip", "--dst-ip", "--src-ipv6", "--dst-ipv6", "--src-mac", "--dst-mac", "--src-port",
                             "--dst-port"]
    data.class_criteria_2 = ["--acl", "--tcp-flags", "--ip-proto", "--ether-type", "--set-pcp", "--set-dscp"]
    data.class_no_criteria_1 = ["--no-src-ip", "--no-dst-ip", "--no-src-ipv6", "--no-dst-ipv6", "--no-src-mac",
                                "--no-dst-mac", "--no-src-port", "--no-dst-port"]
    data.class_no_criteria_2 = ["--no-acl", "--no-tcp-flags", "--no-ip-proto", "--no-ether-type", "--no-set-pcp",
                                "--no-set-dscp"]
    data.stage = ['in', 'out']
    data.proto = ["25", "125"]
    data.src_port = ["1220", "3450"]
    data.dst_port = ["3003", "1500"]
    data.max_classifiers = 128
    data.max_policies = 128
    data.polling_interval = 70

    data.ipAddr = "1.1.1.1"
    data.subnetMask = "24"
    data.ipv6Addr = "2001::1"
    data.subnetMaskv6 = "64"
    data.type_ipv4 = "L3"
    data.type_ipv6 = "L3V6"
    data.type_mac = "L2"
    data.acl_ipv4_table_name = "acl_table_v4"
    data.acl_ipv6_table_name = "acl_table_v6"
    data.acl_mac_table_name = "acl_table_l2"
    data.type_ACL = ['L3', 'L3V6']
    data.stage_ACL = 'INGRESS'
    data.any_ACL = 'ipv6any'
    data.expCount = '1000'
    data.pktrate_ACL = '1000'
    data.pktactionFWD = 'FORWARD'
    data.pktactionDRP = 'drop'
    data.tg_src_mac = "00:00:00:ab:cd:ef"
    data.tg_dst_mac = "00:00:00:ab:cd:f0"
    data.tg_mac_mask = "ff:ff:ff:ff:ff:ff"
    data.src_ipAddr = "1.1.1.2/32"
    data.src_ipv6Addr = "2001::2/128"
    data.tg_src_ipAddr = "1.1.1.2"
    data.tg_dst_ipAddr = "1.1.1.3"
    data.tg_src_ipv6Addr = "2001::2"
    data.tg_dst_ipv6Addr = "2001::3"
    data.traffic_duration = 5
    data.pkts_per_burst = 1200
    data.tcp_protocol = 'tcp' if st.get_ui_type(vars.D1) != 'click' else '6'

@pytest.fixture(scope="module", autouse=True)
def acl_dscp_module_hook(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    initialize_variables()
    [_, exceptions] = exec_all(True, [[create_trafficStreams], [acl_dscp_pre_config]], first_on_main=True)
    ensure_no_exception(exceptions)

    yield

    ipv4_ipv6_intf_delete()
    vlan_obj.delete_vlan_member(vars.D1, data.vlan_1, port_list=vars.D1T1P1,tagging_mode=True)
    vlan_obj.delete_vlan_member(vars.D1, data.vlan_1, port_list=vars.D1T1P2,tagging_mode=True)
    vlan_obj.delete_vlan(vars.D1, data.vlan_1)
    pc_obj.delete_portchannel(vars.D1, data.port_channel[1])
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name_1)
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name_2)
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name_3)
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name_4)
    acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=data.policy_name)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_1)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_2)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_3)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_4)


def acl_dscp_pre_config():
    vlan_obj.create_vlan(vars.D1, data.vlan_1)
    vlan_obj.add_vlan_member(vars.D1, data.vlan_1, port_list=vars.D1T1P1, tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, data.vlan_1, port_list=vars.D1T1P2, tagging_mode=True)
    vlan_obj.verify_vlan_config(vars.D1, data.vlan_1, tagged=[vars.D1T1P1, vars.D1T1P2])
    pc_obj.create_portchannel(vars.D1, data.port_channel[1])
    ipv4_ipv6_intf_create()

    st.log("############### Test started for policy/classifier/flow creation ###############")

    st.log('creating IPv4 ACL table and binding to the ports in ingress direction')
    data.acl_config = {}
    data.acl_config['ACL_TABLE'] = {}
    data.acl_config['ACL_TABLE'][data.acl_ipv4_table_name] = acl_data.acl_json_config_d1['ACL_TABLE'][
        'L3_IPV4_EGRESS']
    st.log('Creating ACL table')
    apply_acl_config(vars.D1, data.acl_config)
    st.log('Creating ACL rules with src_ip dst_ip port  and action as forward')
    create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_IP="{}/{}".format('1.1.1.2', '32'),
                    DST_IP="{}/{}".format('1.1.1.3', '32'),acl_type='ip')

    st.log('creating L2 ACL table and binding to the ports in ingress direction')
    create_acl_table(vars.D1, name=data.acl_mac_table_name, stage='INGRESS', type=data.type_mac, description='L2 ACL',
                     ports=[])
    st.log('Creating ACL rules with src_mac dst_mac port  and action as forward')
    create_acl_rule(vars.D1, table_name=data.acl_mac_table_name, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_MAC="{}/{}".format(data.tg_src_mac, data.tg_mac_mask),acl_type='mac',
                    DST_MAC="{}/{}".format(data.tg_dst_mac, data.tg_mac_mask))

    st.log('creating IPv6 ACL table and binding to the ports in ingress direction')
    create_acl_table(vars.D1, name=data.acl_ipv6_table_name, stage='INGRESS', type=data.type_ipv6,
                     description='L3V6 ACL', ports=[])
    st.log('Creating ACL rules with src_ipv6 dst_ipv6 port  and action as forward')
    create_acl_rule(vars.D1, table_name=data.acl_ipv6_table_name, rule_name='rule_1', priority=data.flow_priority[2],
                    packet_action='FORWARD', SRC_IPV6="{}/{}".format('2001::2', '128'), acl_type='ipv6',
                    DST_IPV6="{}/{}".format('2001::3', '128'))

    st.log("creating policies")
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_1, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_2, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_3, policy_type=data.policy_type)
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_4, policy_type=data.policy_type)

    st.log("creating classifiers")
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name,
                                     match_type=data.class_type[0])
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_1,
                                     match_type=data.class_type[1])
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_2,
                                     match_type=data.class_type[1])
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_3,
                                     match_type=data.class_type[1])
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_4,
                                     match_type=data.class_type[0])
    acl_dscp.config_classifier_table(vars.D1, class_name=data.class_name, class_criteria=data.class_criteria_2[2],
                                     criteria_value=data.tcp_protocol, enable='yes',match_type=data.class_type[0])
    acl_dscp.config_classifier_table(vars.D1, class_name=data.class_name, class_criteria=data.class_criteria_1[6],
                                     criteria_value=data.src_port[1], enable='yes',match_type=data.class_type[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=data.vlan_name,
                                         stage=data.stage[0], service_policy_name=data.policy_name)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=data.port_channel[1],
                                         stage=data.stage[0], service_policy_name=data.policy_name)


@pytest.mark.test_acl_dscp_basic
def test_ft_dscp_basic_config():
    flag = 1
    match = [{'policy_name': data.policy_name_4}]

    if not acl_dscp.verify(vars.D1, 'policy', verify_list=match):
        st.error("policy details are incorrect '{}' ".format(data.policy_name_4))
        flag = 0

    if flag == 0:
        st.report_fail("policy_operation_failed")
    else:
        st.report_pass("policy_operation_successful")


def ipv4_ipv6_intf_create():
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipAddr, subnet=data.subnetMask,
                             family="ipv4")
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipv6Addr, subnet=data.subnetMaskv6,
                             family="ipv6")


def ipv4_ipv6_intf_delete():
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipAddr, subnet=data.subnetMask,
                             family="ipv4", config='remove')
    config_ip_addr_interface(vars.D1, interface_name=data.vlan_name, ip_address=data.ipv6Addr, subnet=data.subnetMaskv6,
                             family="ipv6", config='remove')


def add_port_to_acl_table(config, table_name, port):
    config['ACL_TABLE'][table_name]['ports'].append(port)


def create_trafficStreams():
    st.log("Getting TG handlers")

    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg = data.tg1

    st.log("Creating TG streams")
    data.streams = {}
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', frame_size=64,
                                       l2_encap='ethernet_ii_vlan', vlan_user_priority=6,high_speed_result_analysis=0,
                                       vlan='enable', vlan_id=data.vlan_1, mac_src=data.tg_src_mac,
                                       mac_dst=data.tg_dst_mac,
                                       pkts_per_burst=data.pkts_per_burst)
    data.streams['l2_stream'] = stream['stream_id']

    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', vlan_user_priority=6,high_speed_result_analysis=0,
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv4',
                                       ip_src_addr=data.tg_src_ipAddr, ip_dst_addr=data.tg_dst_ipAddr,l4_protocol='tcp',
                                       pkts_per_burst=data.pkts_per_burst)
    data.streams['ipv4_stream'] = stream['stream_id']

    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', vlan_user_priority=6,
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv6',high_speed_result_analysis=0,
                                       ipv6_src_addr=data.tg_src_ipv6Addr, ipv6_dst_addr=data.tg_dst_ipv6Addr,l4_protocol='tcp',
                                       pkts_per_burst=data.pkts_per_burst)
    data.streams['ipv6_stream'] = stream['stream_id']

    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                       length_mode='fixed', l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan_1, vlan='enable', l4_protocol='tcp', vlan_user_priority=6,high_speed_result_analysis=0,
                                       mac_src=data.tg_src_mac, mac_dst=data.tg_dst_mac, l3_protocol='ipv4',
                                       ip_src_addr=data.tg_src_ipAddr, ip_dst_addr=data.tg_dst_ipAddr,
                                       pkts_per_burst=data.pkts_per_burst, tcp_dst_port=data.dst_port[0],
                                       tcp_src_port=data.src_port[0], tcp_syn_flag=1)
    data.streams['ipv4_SRC_Port_stream'] = stream['stream_id']


def send_verify_traffic(stream, tx_port, interface, dscp, direction='ingress'):
    data.tg.tg_traffic_control(action='clear_stats')
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='clear_interface', interface_name=interface,skip_error=True)
    st.log("Sending traffic from {} ports".format(direction))
    data.tg.tg_traffic_control(action='run', stream_handle=stream, enable_arp=0)
    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=stream)
    acl_dscp.show(vars.D1, interface_name=interface)
    st.log("Adding delay to achieve the consistency of counters received in the show command")
    st.wait(2 * data.traffic_duration)
    counters = acl_dscp.get(vars.D1, interface_name=interface, value='match_pkts_val')
    stats_tg1 = data.tg.tg_traffic_stats(port_handle=tx_port, mode="aggregate")
    total_tx_tg1 = int(stats_tg1[tx_port]['aggregate']['tx']['total_pkts'])
    st.log("total_tx_tg1: {}".format(total_tx_tg1))
    st.log("counters received are :{}".format(counters))
    if not int(total_tx_tg1) <= int(counters):
        st.error("Traffic with DSCP value '{}' is not received ".format(dscp))
        return False
    return True


@pytest.mark.test_acl_dscp_pcp
def test_acl_dscp_pcp_traffic_func():
    flag = 1

    st.log('###############Binding IPv4 ACL with DSCP value of 14 in Egress direction ###############')
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=data.vlan_name,
                                         stage=data.stage[0], policy_type=data.policy_type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=data.port_channel[1],
                                         stage=data.stage[0], policy_type=data.policy_type)

    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_2, class_name=data.class_name_2,
                                      priority_value=data.flow_priority[1], policy_type=data.policy_type, description="classification_IPV4_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_2,policy_type=data.policy_type,
                                      class_name=data.class_name_2, priority_option=data.class_criteria_2[5],
                                      priority_value=data.dscp[1])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_2,
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_ipv4_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1,
                                         stage=data.stage[0], policy_type=data.policy_type,)

    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P2, stage=data.stage[1],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_2)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P2, verify_list=match):
        st.report_fail("policy_operation_failed")
        flag = 0

    st.log("start capturing the traffic from egress port")
    data.tg.tg_packet_control(port_handle=data.tg_ph_2, action='start')
    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ipv4_stream'], enable_arp=0)
    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop',stream_handle=data.streams['ipv4_stream'])
    st.log("stop capturing the traffic from egress port")
    data.tg.tg_packet_control(port_handle=data.tg_ph_2, action='stop')
    pkts_captured = data.tg.tg_packet_stats(port_handle=data.tg_ph_2, format='var', output_type='hex')
    capture_result = tgapi.validate_packet_capture(tg_type=data.tg.tg_type, pkt_dict=pkts_captured, offset_list=[19],
                                             value_list=['38'])

    if not capture_result:
        st.error("Traffic with DSCP value '{}' is not received ".format(data.dscp[1]))
        st.generate_tech_support(vars.D1,"test_acl_dscp_pcp_traffic_capture")
        flag = 0

    st.log('###############Binding L2 ACL with DSCP value of 10###############')
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.policy_name_1, policy_type=data.policy_type)
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_1,
                                      priority_value=data.flow_priority[1], policy_type=data.policy_type, description="classification_L2_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1, policy_type=data.policy_type,
                                      class_name=data.class_name_1, priority_option=data.class_criteria_2[5],
                                      priority_value=data.dscp[0])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_1,acl_type='mac',
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_mac_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_1)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy1 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['l2_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[0])

    if not result:
        st.generate_tech_support(vars.D1, "test_L2ACL_DSCP_10_Fail")
        flag = 0

    st.log('###############Binding L2 ACL with PCP value of 2 ###############')
    acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_1,
                                      policy_type=data.policy_type, class_name=data.class_name_1)
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_1, class_name=data.class_name_1,
                                      priority_value=data.flow_priority[1], policy_type=data.policy_type,
                                      description="classification_L2_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_1,
                                      class_name=data.class_name_1, priority_option=data.class_criteria_2[4],
                                      policy_type=data.policy_type, priority_value=data.pcp[1])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_1,acl_type='mac',
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_mac_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1,
                                         policy_type=data.policy_type, stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1,
                                         stage=data.stage[0], policy_type=data.policy_type,
                                         service_policy_name=data.policy_name_1)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed")
        flag = 0
    result = send_verify_traffic(data.streams['l2_stream'], data.tg_ph_1, vars.D1T1P1, data.pcp[1])

    if not result:
        st.generate_tech_support(vars.D1, "test_L2ACL_PCP_2_Fail")
        flag = 0

    st.log('###############Binding IPv6 ACL with DSCP value of 30###############')
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_3, class_name=data.class_name_3,
                                      priority_value=data.flow_priority[1], policy_type=data.policy_type,
                                      description="classification_IPV6_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_3,
                                      class_name=data.class_name_3, priority_option=data.class_criteria_2[5],
                                      policy_type=data.policy_type, priority_value=data.dscp[2])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_3,acl_type='ipv6',
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_ipv6_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1,
                                         policy_type=data.policy_type, stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_3)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy3 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv6_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[2])
    if not result:
        st.generate_tech_support(vars.D1, "test_IPV6ACL_DSCP_30_Fail")
        flag = 0

    st.log('###############Binding IPv4 ACL with DSCP value of 14###############')
    st.log('creating IPv4 ACL table and binding to the ports in ingress direction')
    data.acl_config['ACL_TABLE'][data.acl_ipv4_table_name] = acl_data.acl_json_config_v4_l3_traffic['ACL_TABLE'][
        'L3_IPV4_INGRESS']
    st.log('Creating ACL table')
    apply_acl_config(vars.D1, data.acl_config)
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_2, class_name=data.class_name_2,
                                      priority_value=data.flow_priority[1], policy_type=data.policy_type,
                                      description="classification_IPV4_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_2,
                                      class_name=data.class_name_2, priority_option=data.class_criteria_2[5],
                                      policy_type=data.policy_type, priority_value=data.dscp[1])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_2,
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_ipv4_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type, stage=data.stage[0])

    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=data.policy_type,interface_name=vars.D1T1P1, stage=data.stage[0],
                                         service_policy_name=data.policy_name_2)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy2 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[1])
    if not result:
        flag = 0

    if flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.test_acl_dscp_fields
def test_acl_dscp_fields_traffic_func():
    flag = 1
    acl_dscp.config_classifier_table(vars.D1, class_name=data.class_name_4, class_criteria=data.class_criteria_2[2],
                                     criteria_value=data.tcp_protocol, enable='yes',match_type=data.class_type[0])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_4,
                                     class_criteria=data.class_criteria_1[6], criteria_value=data.src_port[0],match_type=data.class_type[0])
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_4, policy_type=data.policy_type,
                                      class_name=data.class_name_4,
                                      priority_value=data.flow_priority[1], description="SRCPort_TCP_FLAG_traffic")
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)
    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_SRC_Port_stream'], data.tg_ph_1, vars.D1T1P1, data.src_port[0])
    if not result:
        flag = 0
    st.log("Adding TCP Flag to the classifier and checking the traffic flow")
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_4,class_criteria=data.class_criteria_2[1], criteria_value=data.tcp[1]
                                     ,match_type=data.class_type[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)
    match = [{'tcp_flags_type': data.tcp[1]}]
    if not acl_dscp.verify(vars.D1, 'classifier', verify_list=match):
        st.error("classifier details are not matching '{}' ".format(data.tcp[1]))
        flag = 0
    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0
    result = send_verify_traffic(data.streams['ipv4_SRC_Port_stream'], data.tg_ph_1, vars.D1T1P1, data.tcp[1])

    if not result:
        st.generate_tech_support(vars.D1, "test_IPV4_SRCPORT_Fail")
        flag = 0

    st.log("Deleting TCP Flag to the classifier and checking the traffic flow")
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_4,class_criteria=data.class_no_criteria_2[1], criteria_value=data.tcp[1]
                                     ,match_type=data.class_type[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)
    match = [{'src_port_val': data.src_port[0]}]
    if not acl_dscp.verify(vars.D1, 'classifier', verify_list=match):
        st.error("classifier details are not matching '{}' ".format(data.src_port[0]))
        flag = 0

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_SRC_Port_stream'], data.tg_ph_1, vars.D1T1P1, data.src_port[0])
    if not result:
        flag = 0

    st.log("Testing the Priority flow configured")
    acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_4, policy_type=data.policy_type,
                                      class_name=data.class_name_4)
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=data.class_name_4)
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name="class5", match_type=data.class_type[0])
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_4, class_name="class5",
                                      priority_value=data.flow_priority[0],policy_type=data.policy_type,
                                      description="classification_IPV4_traffic")
    acl_dscp.config_classifier_table(vars.D1, class_name='class5', class_criteria=data.class_criteria_2[2],
                                     criteria_value=data.tcp_protocol, enable='yes',match_type=data.class_type[0])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name="class5",
                                     class_criteria=data.class_criteria_2[1], criteria_value=data.tcp[1],match_type=data.class_type[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0], service_policy_name=data.policy_name_4)
    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_SRC_Port_stream'], data.tg_ph_1, vars.D1T1P1, data.tcp[1])
    if not result:
        flag = 0
    acl_dscp.config_flow_update_table(vars.D1, flow='del', policy_name=data.policy_name_4, policy_type=data.policy_type,
                                      class_name='class5')
    acl_dscp.config_classifier_table(vars.D1, enable='del', class_name="class5")

    st.log('###############Binding IPv4 ACL with DSCP value of 22###############')
    acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=data.class_name_4,
                                     match_type=data.class_type[1])
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name_4, policy_type=data.policy_type, class_name=data.class_name_4,
                                      priority_value=data.flow_priority[1], description="classification_IPV4_traffic")
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_4, policy_type=data.policy_type,
                                      class_name=data.class_name_4, priority_option=data.class_criteria_2[5],
                                      priority_value=data.dscp[3])
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_name=data.class_name_4,
                                     class_criteria=data.class_criteria_2[0], criteria_value=data.acl_ipv4_table_name,match_type=data.class_type[1])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', policy_type=data.policy_type,
                                         interface_name=vars.D1T1P1, stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[3])
    if not result:
        st.generate_tech_support(vars.D1, "test_IPV4_DSCP_22_Fail")
        flag = 0

    st.log('###############Updating the Existing flow wih new PCP value of 3 ###############')
    acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name_4, policy_type=data.policy_type,
                                      class_name=data.class_name_4, priority_option=data.class_criteria_2[4],
                                      priority_value=data.pcp[2])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_stream'], data.tg_ph_1, vars.D1T1P1, data.pcp[2])
    if not result:
        st.generate_tech_support(vars.D1, "test_IPV4_PCP_3_Fail")
        flag = 0

    st.log('###############Deleting the Existing PCP value 3 and checking the Existing DSCP flow ###############')
    acl_dscp.config_flow_update_table(vars.D1, flow='update_del', policy_name=data.policy_name_4,policy_type=data.policy_type,
                                      class_name=data.class_name_4, priority_option=data.class_no_criteria_2[4])
    match = [{'pcp_val': data.pcp[2]}]
    if acl_dscp.verify(vars.D1, policy_name=data.policy_name_4, verify_list=match):
        st.error("pcp value  '{}' is not removed".format(data.pcp[2]))
        flag = 0

    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, stage=data.stage[0],
                                         policy_type=data.policy_type, service_policy_name=data.policy_name_4)

    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[3])
    if not result:
        flag = 0

    if flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.test_acl_dscp_save_reload
def test_acl_dscp_ft_save_reload_func():
    flag = 1
    st.log("########## Verify after warm reboot ############")
    reboot_api.config_save(vars.D1)
    st.reboot(vars.D1, "warm")
    st.wait(data.polling_interval)
    vlan_obj.verify_vlan_config(vars.D1, data.vlan_1, tagged=[vars.D1T1P1, vars.D1T1P2])
    match = [{'src_port_val': data.src_port[1]}]
    if not acl_dscp.verify(vars.D1, 'classifier', verify_list=match):
        st.error("classifier details are incorrect after save and reload'{}' ".format(data.src_port[1]))
        flag = 0

    st.log("Checking the IPV4 traffic with DSCP configuration after reload with policy4")
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='clear_interface', interface_name=vars.D1T1P1,policy_type=data.policy_type,
                                         skip_error=True)
    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy4 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['ipv4_stream'], data.tg_ph_1, vars.D1T1P1, data.dscp[3])
    if not result:
        st.generate_tech_support(vars.D1, "test_IPV4_DSCP_Fail_after_reload")
        flag = 0

    st.log("Checking the L2 traffic with PCP configuration after reload with policy1")
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1,policy_type=data.policy_type,
                                         stage=data.stage[0])
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=vars.D1T1P1, policy_type=data.policy_type,
                                         stage=data.stage[0], service_policy_name=data.policy_name_1)
    match = [{'flow_state': '(Active)'}]
    if not acl_dscp.verify(vars.D1, service_policy_interface=vars.D1T1P1, verify_list=match):
        st.report_fail("policy_operation_failed", "policy1 is not active")
        flag = 0

    result = send_verify_traffic(data.streams['l2_stream'], data.tg_ph_1, vars.D1T1P1, data.pcp[1])
    if not result:
        flag = 0

    if flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.test_acl_dscp_negative
def test_ft_acl_dscp_negative_func():
    flag = 1
    st.log("checking negative tests")
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=data.vlan_name,
                                            stage=data.stage[0], service_policy_name=data.policy_name,
                                            skip_error=True)
    if acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', interface_name=data.vlan_name,
                                            stage=data.stage[0], service_policy_name=data.policy_name_1,
                                            skip_error=True, policy_type=data.policy_type,):
        st.error("Interface is accepting second policy '{}' of  same type qos".format(data.policy_name))
        flag = 0
    acl_dscp.config_flow_update_table(vars.D1, flow='add', policy_name=data.policy_name, class_name=data.class_name,
                                      priority_value=data.flow_priority[0], policy_type=data.policy_type,
                                      description="Negative_check")

    if acl_dscp.config_flow_update_table(vars.D1, flow='update', policy_name=data.policy_name, policy_type=data.policy_type,
                                         class_name=data.class_name, priority_option=data.class_criteria_2[5],
                                         priority_value=data.invalid_pcp_dscp[0], skip_error=True):
        st.error("Invalid  dscp value {} is accepted by the DUT".format(data.invalid_pcp_dscp[0]))
        flag = 0

    st.log("checking Mutually Exclusive Header fields")
    acl_dscp.config_classifier_table(vars.D1, class_name=data.class_name, class_criteria=data.class_criteria_1[0],
                                     criteria_value=data.src_ipAddr, enable='yes',match_type=data.class_type[0],skip_error=True)
    acl_dscp.config_classifier_table(vars.D1, class_name=data.class_name, class_criteria=data.class_criteria_1[2],
                                     criteria_value=data.src_ipv6Addr, enable='yes',match_type=data.class_type[0],skip_error=True)
    match = [{'class_name': data.class_name, 'src_ip_val': data.src_ipAddr}]
    if st.get_ui_type() == 'klish':
        match = [{'class_name': data.class_name, 'src_ip_val': data.tg_src_ipAddr}]
    if not acl_dscp.verify(vars.D1, 'classifier', verify_list=match):
        st.error("classifier details are not matching '{}' ".format(data.src_ipAddr))
        flag = 0

    st.log("checking ACL funtionality without matching ACL with the classifier")
    acl_dscp.config_service_policy_table(vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, stage=data.stage[0])
    add_port_to_acl_table(data.acl_config, data.acl_ipv4_table_name, vars.D1T1P1)
    apply_acl_config(vars.D1, data.acl_config)
    st.log("Sending traffic from ingress ports")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ipv4_stream'])

    st.wait(data.traffic_duration)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['ipv4_stream'])
    acl_rule_counters = acl_obj.show_acl_counters(vars.D1, acl_table=data.acl_ipv4_table_name)
    for rule in acl_rule_counters:
        if rule['packetscnt'] == 0:
            st.error("ACL Traffic is not forwarded when no ACL is applied to the classifier")
            flag = 0

    if flag == 0:
        st.report_fail("Flow_operation_failed")
    else:
        st.report_pass("Flow_operation_successful")


@pytest.mark.scale
def test_ft_classifier_max_creation():
    """
    creating maximum Recommended classifiers
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :return:

    """
    st.log("############### Test started for creating maximum Recommended classifiers ###############")
    flag = 1
    for element in range(1, data.max_classifiers + 1):
        element = data.class_name_2 + str(element)
        acl_dscp.config_classifier_table(vars.D1, enable='create', class_name=element, match_type=data.class_type[0],
                                         description="checking_MAX_CLI")

    classifier_max = data.class_name_2 + str(data.max_classifiers)
    match = [{'match_type': 'fields', 'class_name': classifier_max}]
    if not acl_dscp.verify(vars.D1, match_type=data.class_type[0], class_name=classifier_max, verify_list=match):
        st.error("Failed to create class name '{}' ".format(classifier_max))
        flag = 0

    st.log("############### Test started for deleting maximum classifiers creation #################")
    for element in range(1, data.max_classifiers + 1):
        element = data.class_name_2 + str(element)
        acl_dscp.config_classifier_table(vars.D1, enable='del', class_name=element)
    match = [{'match_type': 'fields'}]
    if not acl_dscp.verify(vars.D1, match_type=data.class_type[0], class_name=data.class_name, verify_list=match):
        st.error("Failed to delete classifier name '{}' ".format(data.class_name_1))
        flag = 0

    if flag == 0:
        st.report_fail("classifier_opeartion_failed")
    else:
        st.report_pass("classifier_opeartion_successful")


@pytest.mark.scale
def test_ft_policy_max_creation():
    """
    creating maximum Recommended policies
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :return:

    """
    st.log("############### Test started for creating maximum Recommended policies ###################")
    flag = 1
    for element in range(1, data.max_policies + 1):
        element_str = data.policy_name_4 + str(element)
        acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=element_str, policy_type=data.policy_type)

    policy_max = data.policy_name_4 + str(data.max_policies)
    match = [{'policy_name': policy_max}]
    if not acl_dscp.verify(vars.D1, policy_name=policy_max, verify_list=match):
        st.error("Failed to create policy name '{}' ".format(policy_max))
        flag = 0

    st.log("############### Test started for deleting maximum policies #################")
    for element in range(1, data.max_policies + 1):
        element = data.policy_name_4 + str(element)
        acl_dscp.config_policy_table(vars.D1, enable='del', policy_name=element)
    match = [{'policy_name': data.policy_name}]
    if not acl_dscp.verify(vars.D1, policy_name=data.policy_name, verify_list=match):
        st.error("Failed to delete policy name {}".format(data.policy_name))
        flag = 0

    if flag == 0:
        st.report_fail("policy_operation_failed")
    else:
        st.report_pass("policy_operation_successful")