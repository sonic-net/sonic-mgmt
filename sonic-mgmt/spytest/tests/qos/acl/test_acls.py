import pprint
import pytest
import json

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.switching.vlan as vlan_obj
import apis.qos.acl as acl_obj
import tests.qos.acl.acl_json_config as acl_data
import tests.qos.acl.acl_rules_data as acl_rules_data
import tests.qos.acl.acl_utils as acl_utils
import apis.switching.portchannel as pc_obj
import apis.routing.ip as ipobj
import apis.system.gnmi as gnmiapi
from apis.system.interface import clear_interface_counters,get_interface_counters
from apis.system.rest import rest_status

from utilities.parallel import ensure_no_exception
import utilities.common as utils

YANG_MODEL = "sonic-acl:sonic-acl"
pp = pprint.PrettyPrinter(indent=4)

vars = dict()
data = SpyTestDict()
data.rate_pps = 100
data.pkts_per_burst = 10
data.tx_timeout = 2
data.TBD = 10
data.portChannelName = "PortChannel001"
data.tg_type = 'ixia'
data.cli_type = "click"


def print_log(msg):
    log_start = "\n================================================================================\n"
    log_end = "\n================================================================================"
    st.log("{} {} {}".format(log_start, msg, log_end))


def get_handles():
    '''
    ######################## Topology ############################

               +---------+                  +-------+
               |         +------------------+       |
      TG1 -----|  DUT1   |  portchannel     |  DUT2 +----- TG2
               |         +------------------+       |
               +---------+                  +-------+

    ##############################################################
    '''
    global vars, tg_port_list
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:1")
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D1P2")
    if tg1.tg_type == 'stc': data.tg_type = 'stc'
    tg_port_list = [tg_ph_1, tg_ph_2, tg_ph_3]
    tg1.tg_traffic_control(action="reset", port_handle=tg_ph_1)
    tg2.tg_traffic_control(action="reset", port_handle=tg_ph_2)
    tg3.tg_traffic_control(action="reset", port_handle=tg_ph_3)
    return (tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3)


def acl_delete(dut):
    if st.is_community_build(dut):

        names = acl_obj.show_acl_table(dut)
        acl_name = list()
        for name in names:
            acl_name.append(name.keys())
        print("acl name", str(acl_name))
        for name in acl_name:
            for i in name:
                if "Name" in i:
                    pass
                else:
                    acl_obj.delete_acl_table(dut, acl_table_name=i)

    else:
        acl_obj.delete_acl_table(dut)


def apply_module_configuration():
    print_log("Applying module configuration")

    data.vlan = str(random_vlan_list()[0])
    data.dut1_lag_members = [vars.D1D2P1, vars.D1D2P2]
    data.dut2_lag_members = [vars.D2D1P1, vars.D2D1P2]

    # create portchannel
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D1, data.portChannelName, cli_type=data.cli_type),
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D2, data.portChannelName, cli_type=data.cli_type),
    ])

    # add portchannel members
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members, data.cli_type),
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members, data.cli_type),
    ])

    # create vlan
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.create_vlan, vars.D1, data.vlan, data.cli_type),
        utils.ExecAllFunc(vlan_obj.create_vlan, vars.D2, data.vlan, data.cli_type),
    ])

    # add vlan members
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.add_vlan_member, vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2,
                          data.portChannelName], True, cli_type=data.cli_type),
        utils.ExecAllFunc(vlan_obj.add_vlan_member, vars.D2, data.vlan, [vars.D2T1P1, data.portChannelName], True,
                          cli_type=data.cli_type),
    ])




def clear_module_configuration():
    print_log("Clearing module configuration")

    # delete vlan members
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.delete_vlan_member, vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2,
                          data.portChannelName], cli_type=data.cli_type),
        utils.ExecAllFunc(vlan_obj.delete_vlan_member, vars.D2, data.vlan, [vars.D2T1P1, data.portChannelName],
                          cli_type=data.cli_type),
    ])

    # delete portchannel members
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members,
                          data.cli_type),
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members,
                          data.cli_type),
    ])
    # delete portchannel
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D1, data.portChannelName, data.cli_type),
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D2, data.portChannelName, data.cli_type),
    ])
    # delete vlan
    utils.exec_all(True, [
        utils.ExecAllFunc(vlan_obj.delete_vlan, vars.D1, data.vlan, data.cli_type),
        utils.ExecAllFunc(vlan_obj.delete_vlan, vars.D2, data.vlan, data.cli_type),
    ])
    # delete acl tables and rules
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)


def add_port_to_acl_table(config, table_name, port):
    config['ACL_TABLE'][table_name]['ports'] = []
    config['ACL_TABLE'][table_name]['ports'].append(port)


def change_acl_rules(config, rule_name, attribute, value):
    config["ACL_RULE"][rule_name][attribute] = value


def apply_acl_config(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def create_streams(tx_tg, rx_tg, rules, match, mac_src, mac_dst,dscp=None,pcp=None, dei=None,ether_type_val=None):
    # use the ACL rule definitions to create match/non-match traffic streams
    # instead of hardcoding the traffic streams
    my_args = {
        'port_handle': data.tgmap[tx_tg]['handle'], 'mode': 'create', 'frame_size': '128',
        'transmit_mode': 'continuous', 'length_mode': 'fixed',
        'l2_encap': 'ethernet_ii_vlan',
        'vlan_id': data.vlan, 'vlan': 'enable', 'rate_pps': data.rate_pps,
        'high_speed_result_analysis': 0, 'mac_src': mac_src, 'mac_dst': mac_dst,
        'port_handle2': data.tgmap[rx_tg]['handle']
    }
    if dscp:
        my_args.update({"ip_dscp": dscp})
    if pcp:
        my_args.update({"vlan_user_priority": pcp})
    if dei:
        my_args.update({"vlan_cfi": dei})
    if ether_type_val:
        my_args.update({"l2_encap": 'ethernet_ii'})
        my_args.update({"ethernet_value": ether_type_val})

    for rule, attributes in rules.items():
        if ("IP_TYPE" in attributes) or ("ETHER_TYPE" in attributes):
            continue
        if match in rule:
            params = {}
            tmp = dict(my_args)
            for key, value in attributes.items():
                params.update(acl_utils.get_args(key, value, attributes, data.rate_pps, data.tg_type))
            tmp.update(params)
            stream = data.tgmap[tx_tg]['tg'].tg_traffic_config(**tmp)
            stream_id = stream['stream_id']
            s = {}
            s[stream_id] = attributes
            s[stream_id]['TABLE'] = rule
            data.tgmap[tx_tg]['streams'].update(s)


def transmit(tg):
    print_log("Transmitting streams")
    data.tgmap[tg]['tg'].tg_traffic_control(action='clear_stats', port_handle=tg_port_list)
    data.tgmap[tg]['tg'].tg_traffic_control(action='run', stream_handle = list(data.tgmap[tg]['streams'].keys()),
                                            duration=1)


def verify_acl_hit_counters(dut, table_name):
    result = True
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name)
    for rule in acl_rule_counters:
        if rule['packetscnt'] == 0:
            return False
    return result


def verify_packet_count(tx, tx_port, rx, rx_port, table):
    st.log("#######################################################################")
    st.log("# Validating stream statistics, by invoking 'validate_tgen_traffic'   #")
    st.log("# API, this API presently returns boolean status checking each stream #")
    st.log("# statistics. Jira(SONIC-6791) is raised to enhance the API to report #")
    st.log("# status for individual stream statistic. Revisit this module after   #")
    st.log("# the fix to improve further execution time.                          #")
    st.log("#######################################################################")
    result = True
    tg_tx = data.tgmap[tx]
    tg_rx = data.tgmap[rx]
    exp_ratio = 0
    action = "DROP"
    for s_id, attr in tg_tx['streams'].iteritems():
        if table in attr['TABLE']:
            if attr["PACKET_ACTION"] == "FORWARD":
                exp_ratio = 1
                action = "FORWARD"
            else:
                exp_ratio = 0
                action = "DROP"
            traffic_details = {
                '1': {
                    'tx_ports': [tx_port],
                    'tx_obj': [tg_tx["tg"]],
                    'exp_ratio': [exp_ratio],
                    'rx_ports': [rx_port],
                    'rx_obj': [tg_rx["tg"]],
                    'stream_list': [[s_id]]
                },
            }
            result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                            comp_type='packet_count')
            result = result and result1
            if result1:
                if action == "FORWARD":
                    msg = "Traffic successfully forwarded for the rule: {}".format(json.dumps(attr))
                    print_log(msg)
                else:
                    msg = "Traffic successfully dropped for the rule: {}".format(json.dumps(attr))
                    print_log(msg)
            else:
                if action == "FORWARD":
                    msg = "Traffic failed to forward for the rule: {}".format(json.dumps(attr))
                    print_log(msg)
                else:
                    msg = "Traffic failed to drop for the rule: {}".format(json.dumps(attr))
                    print_log(msg)
    return result


def initialize_topology():
    print_log("Initializing Topology")
    (tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3) = get_handles()
    data.tgmap = {
        "tg1": {
            "tg": tg1,
            "handle": tg_ph_1,
            "streams": {}
        },
        "tg2": {
            "tg": tg2,
            "handle": tg_ph_2,
            "streams": {}
        },
        "tg3": {
            "tg": tg3,
            "handle": tg_ph_3,
            "streams": {}
        }
    }
    data.vars = vars

@pytest.fixture(scope="module", autouse=True)
def acl_v4_module_hooks(request):
    # initialize topology
    initialize_topology()

    # apply module configuration
    apply_module_configuration()
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "REDIRECT:" + vars.D1T1P2)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_EGRESS|macrule3", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_d1, "L2_MAC_EGRESS|macrule4", "VLAN", data.vlan)
    acl_config1 = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config1, 'L3_IPV4_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L3_IPV4_EGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config1, 'L2_MAC_EGRESS', vars.D1T1P1)
    acl_config2 = acl_data.acl_json_config_d2
    add_port_to_acl_table(acl_config2, 'L3_IPV6_INGRESS', vars.D2T1P1)
    add_port_to_acl_table(acl_config2, 'L3_IPV6_EGRESS', vars.D2T1P1)

    def config_dut1():
        apply_acl_config(vars.D1, acl_config1)

    def config_dut2():
        apply_acl_config(vars.D2, acl_config2)

    def tg_config():
    # create streams
        print_log('Creating streams')
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L3_IPV4_INGRESS", \
                       mac_src="00:0a:01:00:00:01", mac_dst="00:0a:01:00:11:02", dscp=62)
        create_streams("tg1", "tg2", acl_config2['ACL_RULE'], "L3_IPV6_EGRESS", \
                       mac_src="00:0a:01:00:00:01", mac_dst="00:0a:01:00:11:02")
        create_streams("tg2", "tg1", acl_config2['ACL_RULE'], "L3_IPV6_INGRESS", \
                       mac_src="00:0a:01:00:11:02", mac_dst="00:0a:01:00:00:01")
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L3_IPV4_EGRESS", \
                       mac_src="00:0a:01:00:11:02", mac_dst="00:0a:01:00:00:01",dscp=61)
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L2_MAC_INGRESS|macrule1", \
                       mac_src="00:0a:01:00:00:03", mac_dst="00:0a:01:00:11:04", pcp=4, dei=1)
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L2_MAC_EGRESS|macrule3", \
                       mac_src="00:0a:01:00:11:04", mac_dst="00:0a:01:00:00:03", pcp=4, dei=1)
        create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L2_MAC_INGRESS|macrule2", \
                       mac_src="00:0a:01:00:00:05", mac_dst="00:0a:01:00:11:06", pcp=4, dei=1,ether_type_val=0x0800)
        create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L2_MAC_EGRESS|macrule4", \
                       mac_src="00:0a:01:00:11:06", mac_dst="00:0a:01:00:00:05", pcp=4, dei=1)
        print_log('Completed module configuration')

    utils.exec_all(True, [utils.ExecAllFunc(tg_config), utils.ExecAllFunc(config_dut1), utils.ExecAllFunc(config_dut2)],
                   first_on_main=True)

    yield
    clear_module_configuration()


def verify_rule_priority(dut, table_name):
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name, acl_rule='PermitAny')
    if len(acl_rule_counters) == 1:
        if (int(acl_rule_counters[0]['packetscnt']) != 0):
            print_log("ACL Rule priority test failed")
            return False
        else:
            return True
    else:
        return True


@pytest.mark.acl_test
def test_ft_acl_ingress_ipv4():
    '''
    IPv4 Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L2_MAC_INGRESS')
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L2_MAC_EGRESS')
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    print_log('Verifing IPv4 Ingress ACL hit counters')
    result2 = verify_acl_hit_counters(vars.D1, "L3_IPV4_INGRESS")
    result3 = verify_rule_priority(vars.D1, "L3_IPV4_INGRESS")
    stats1 = data.tgmap['tg3']['tg'].tg_traffic_stats(port_handle=data.tgmap['tg3']['handle'], mode='aggregate')
    total_rx1 = int(stats1[data.tgmap['tg3']['handle']]['aggregate']['rx']['total_pkts'])
    st.log("total_rx1={}".format(total_rx1))
    if total_rx1 > 100:
        print_log("Traffic successfully redirected")
    else:
        st.report_fail("test_case_failed")
    acl_utils.report_result(result1 and result2 and result3)


@pytest.mark.acl_test6789
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_acl_ingress_ipv6():
    '''
    IPv6 Ingress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    transmit('tg2')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    print_log('Verifing IPv6 Ingress ACL hit counters')

    result2 = verify_acl_hit_counters(vars.D2, "L3_IPV6_INGRESS")
    result3 = verify_rule_priority(vars.D2, "L3_IPV6_INGRESS")
    acl_utils.report_result(result1 and result2 and result3)

@pytest.mark.acl_test
def test_ft_acl_egress_ipv4():
    '''
    IPv4 Egress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    print_log('Verifing IPv4 Egress ACL hit counters')
    result2 = verify_acl_hit_counters(vars.D1, "L3_IPV4_EGRESS")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test678
def test_ft_acl_egress_ipv6():
    '''
    IPv6 Egress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    transmit('tg1')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    print_log('Verifing IPv6 Egress ACL hit counters')
    result2 = verify_acl_hit_counters(vars.D2, "L3_IPV6_EGRESS")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_ft_mac_acl_port():
    '''
    MAC Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    print_log('Creating MAC ACL table and apply on Port ')
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_INGRESS')
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_EGRESS')
    acl_config = acl_data.acl_json_config_port_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_EGRESS|macrule3", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_EGRESS|macrule4", "VLAN", data.vlan)
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    transmit('tg1')
    print_log('Verifying MAC Ingress packet count')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    print_log('Verifying MAC Ingress ACL hit counters')
    result2 = verify_acl_hit_counters(vars.D1, "L2_MAC_INGRESS")
    transmit('tg2')
    print_log('Verifying MAC Ingress packet count')
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    print_log('Verifing MAC Egress ACL hit counters')
    result4 = verify_acl_hit_counters(vars.D1, "L2_MAC_EGRESS")
    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_testacl2
def test_ft_acl_port_channel_ingress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_ingress_configv6
    add_port_to_acl_table(acl_config, 'L3_IPV6_INGRESS', data.portChannelName)
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test6
def test_ft_acl_port_channel_egress():
    '''
    IPv6 Egress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    print_log('Creating Egress ACL table and apply on Port channel')
    # SONiC supports only one egress table for Switch
    # so deleting already created Egress rule. Revisit this test case,
    # when the support is added
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_EGRESS')
    acl_config = acl_data.acl_json_egress_configv6
    add_port_to_acl_table(acl_config, 'L3_IPV6_EGRESS', data.portChannelName)
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test8
def test_ft_acl_port_channel_V4_egress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recived at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    acl_obj.delete_acl_table(vars.D2, acl_table_name='L3_IPV4_EGRESS')
    acl_obj.delete_acl_table(vars.D2, acl_table_name='L3_IPV4_INGRESS')
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_egress_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', data.portChannelName)
    apply_acl_config(vars.D2, acl_config)
    st.wait(2)

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    acl_utils.report_result(result1)



@pytest.mark.acl_test678
def test_ft_acl_vlan_v6_egress():
    '''
    IPv6 Egress ACL is applied on DUT2 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''

    # Creating Ingress ACL table and rules
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    print_log('Creating Egress ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_v6_egress_vlan
    add_port_to_acl_table(acl_config, 'L3_IPV6_EGRESS', "Vlan{}".format(data.vlan))
    apply_acl_config(vars.D2, acl_config)
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    st.wait(2)
    transmit('tg1')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV6_EGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test
def test_ft_acl_vlan_v6_ingress():
    '''
    IPv6 Egress ACL is applied on DUT2 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''

    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_v6_ingress_vlan
    add_port_to_acl_table(acl_config, 'L3_IPV6_INGRESS', "Vlan{}".format(data.vlan))
    apply_acl_config(vars.D2, acl_config)
    st.wait(2)

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test
def test_ft_acl_vlan_V4_ingress():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_ingress_vlan_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', "Vlan{}".format(data.vlan))
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', "Vlan{}".format(data.vlan))
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "FORWARD")
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    transmit('tg2')
    result2 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1,  "L3_IPV4_EGRESS")
    acl_utils.report_result(result1 and result2)

@pytest.mark.acl_test
def test_ft_acl_port_channel_V4_ingress():
    '''
    IPv6 Ingress ACL is applied on DUT1 port channel
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''
    # deleting same streams are used for both IPv6 and PortChannel test
    # to avoid conflicts, delete IPv6 rules
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_ingress_configv4
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', data.portChannelName)
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "DROP")
    apply_acl_config(vars.D2, acl_config)
    st.wait(2)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    acl_utils.report_result(result1)

@pytest.mark.acl_test678
def test_ft_v4_acl_switch():
    '''
    IPv4 Ingress ACL is applied on DUT1 Switch
    Traffic is sent on TG Port #1 and received at TG Port #2 for ingress
    Traffic is sent on TG Port #2 and received at TG Port #1 for egress
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    print_log('Creating ACL table and apply on switch')
    acl_config = acl_data.acl_json_config_v4_switch
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', "Switch")
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', "Switch")
    change_acl_rules(acl_data.acl_json_config_d1, "L3_IPV4_INGRESS|rule6", "PACKET_ACTION", "DROP")
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    transmit('tg1')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    result2 = verify_acl_hit_counters(vars.D1, "L3_IPV4_INGRESS")
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    transmit('tg2')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS")
    result4 = verify_acl_hit_counters(vars.D1, "L3_IPV4_EGRESS")

    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_test
def test_ft_mac_acl_switch():
    '''
    IPv4 Ingress ACL is applied on switch
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules

    print_log('Creating ACL table and apply on switch')
    acl_config = acl_data.acl_json_config_switch_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', "Switch")
    apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_rule(vars.D1)
    st.wait(2)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    result2 = verify_acl_hit_counters(vars.D1, "L2_MAC_INGRESS")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_ft_mac_acl_switch_egress():
    '''
    IPv4 Egress ACL is applied on switch
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''

    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules

    print_log('Creating ACL table and apply on switch')
    acl_config1 = acl_data.acl_json_config_switch_d3_egress
    add_port_to_acl_table(acl_config1, 'L2_MAC_EGRESS', "Switch")
    apply_acl_config(vars.D1, acl_config1)
    acl_obj.show_acl_rule(vars.D1)
    st.wait(2)
    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    result2 = verify_acl_hit_counters(vars.D1, "L2_MAC_EGRESS")

    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_ft_mac_acl_vlan():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on VLAN')
    acl_config = acl_data.acl_json_config_vlan_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', "Vlan{}".format(data.vlan))
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', "Vlan{}".format(data.vlan))
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    result2 = verify_acl_hit_counters(vars.D1, "L2_MAC_INGRESS")
    transmit('tg2')
    result3 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS")
    result4 = verify_acl_hit_counters(vars.D1, "L2_MAC_EGRESS")
    acl_utils.report_result(result1 and result2 and result3 and result4)


@pytest.mark.acl_test
def test_ft_mac_acl_portchannel():
    '''
    IPv4 Ingress ACL is applied on DUT1 vlan
    Traffic is sent on TG Port #1
    Traffic is received at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating Ingress ACL table and apply on Port channel')
    acl_config = acl_data.acl_json_config_portchannel_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', data.portChannelName)
    change_acl_rules(acl_data.acl_json_config_portchannel_d3, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_portchannel_d3, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    apply_acl_config(vars.D2, acl_config)
    st.wait(2)

    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    result2 = verify_acl_hit_counters(vars.D2, "L2_MAC_INGRESS")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_ft_acl_loader():
    '''
        ACL rule update using config-loader
        ACL rule add
        check for rule upgrade
    '''
    data.v4_in_tab = 'L3_IPV4_INGRESS'
    data.v4_eg_tab = 'L3_IPV4_EGRESS'
    data.v6_in_tab = 'L3_IPV6_INGRESS'
    data.v6_eg_tab = 'L3_IPV6_EGRESS'
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    acl_config = acl_data.acl_json_config_table
    add_port_to_acl_table(acl_config, data.v4_in_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v4_eg_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v6_in_tab, vars.D1T1P1)
    add_port_to_acl_table(acl_config, data.v6_eg_tab, vars.D1T1P2)
    apply_acl_config(vars.D1, acl_config)
    data.json_data = acl_rules_data.multiple_acl_rules
    data.json_data1 = acl_rules_data.add_acl_rules
    acl_obj.show_acl_table(vars.D1)
    st.log('Configure acl rules using "acl-loader update"')
    acl_obj.config_acl_loader_update(vars.D1, 'full', data.json_data, config_type="acl_update")
    rule_update = acl_obj.get_acl_rule_count(vars.D1)
    st.log('Add acl rules using "acl-loader add" to existing rules')
    acl_obj.config_acl_loader_update(vars.D1, 'add', data.json_data1, config_type="acl_add")
    rule_add = acl_obj.get_acl_rule_count(vars.D1)
    if (rule_add[data.v4_in_tab] > rule_update[data.v4_in_tab]
            and rule_add[data.v6_in_tab] > rule_update[data.v6_in_tab]
            and rule_add[data.v4_eg_tab] > rule_update[data.v4_eg_tab]
            and rule_add[data.v6_eg_tab] > rule_update[data.v6_eg_tab]):
        print_log("New rules successfully added using acl-loader")
    else:
        st.report_fail('test_case_failed')
    print_log('Configure acl rules using "config acl update"')
    acl_obj.config_acl_loader_update(vars.D1, 'full', data.json_data)
    config_acl_full = acl_obj.get_acl_rule_count(vars.D1)
    if (config_acl_full[data.v4_in_tab] < rule_add[data.v4_in_tab]
            and config_acl_full[data.v6_in_tab] < rule_add[data.v6_in_tab]
            and config_acl_full[data.v4_eg_tab] < rule_add[data.v4_eg_tab]
            and config_acl_full[data.v6_eg_tab] < rule_add[data.v6_eg_tab]):
        print_log("Successfully added rules using 'config acl update'")
    else:
        st.report_fail('test_case_failed')
    print_log('Add acl rules using "config acl add" to existing rules')
    acl_obj.config_acl_loader_update(vars.D1, 'add', data.json_data1)
    config_acl_add = acl_obj.get_acl_rule_count(vars.D1)
    if not(config_acl_add[data.v4_in_tab] > config_acl_full[data.v4_in_tab]
            and config_acl_add[data.v6_in_tab] > config_acl_full[data.v6_in_tab]
            and config_acl_add[data.v4_eg_tab] > config_acl_full[data.v4_eg_tab]
            and config_acl_add[data.v6_eg_tab] > config_acl_full[data.v6_eg_tab]):
        print_log("Failed to add new rules using config acl")
        st.report_fail('test_case_failed')
    else:
        print_log("New rules successfully added using config acl")
    st.report_pass("test_case_passed")


@pytest.mark.acl_test
def test_ft_acl_icmpv6():
    '''
        TC_id: ft_acl_v6_in_intf
        Description: Verify that ipv6 ingress acl works fine when bound to interface
    '''
    ipv6_src_address = "2001::2"
    ipv6_src_address1 = "2001::3"
    data.af_ipv6 = "ipv6"
    utils.exec_all(True, [
        utils.ExecAllFunc(ipobj.config_ip_addr_interface, vars.D1, "Vlan" + str(data.vlan), ipv6_src_address, 96,
                          family=data.af_ipv6),
        utils.ExecAllFunc(ipobj.config_ip_addr_interface, vars.D2, "Vlan" + str(data.vlan), ipv6_src_address1, 96,
                          family=data.af_ipv6),
    ])
    if not ipobj.ping(vars.D1, ipv6_src_address ,family='ipv6', count=3):
        st.report_fail("ping_fail",ipv6_src_address )
    else:
        st.log("Successfully forwarded icmp packet")
    utils.exec_all(True, [
        utils.ExecAllFunc(ipobj.delete_ip_interface, vars.D1, "Vlan" + str(data.vlan), ipv6_src_address, 96,
                          family=data.af_ipv6),
        utils.ExecAllFunc(ipobj.delete_ip_interface, vars.D2, "Vlan" + str(data.vlan), ipv6_src_address1, 96,
                          family=data.af_ipv6),
    ])
    st.report_pass("ping_success")


@pytest.mark.acl_testacl1
def test_ft_mac_acl_port_adv():
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    acl_obj.config_hw_acl_mode(vars.D1, counter='per-interface-rule')
    acl_config = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_rule(vars.D1)
    transmit('tg1')
    st.wait(5)
    if not acl_obj.verify_acl_stats(vars.D1, 'L2_MAC_INGRESS', 'macrule1'):
        st.report_fail("test_case_failed")
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule')
    st.report_pass("test_case_passed")


@pytest.mark.acl_testacl1
def test_ft_acl_ingress_ipv4_adv():
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    acl_obj.config_hw_acl_mode(vars.D1, counter='per-interface-rule')
    acl_config = acl_data.acl_json_config_d1
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', vars.D1T1P1)
    apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_table(vars.D1)
    transmit('tg1')
    st.wait(5)
    if not acl_obj.verify_acl_stats(vars.D1, 'L3_IPV4_INGRESS',"rule5"):
        st.report_fail("test_case_failed")
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    acl_obj.config_hw_acl_mode(vars.D1, counter='per-rule')
    st.report_pass("test_case_passed")


@pytest.mark.acl_testacl222
def test_ft_mac_acl_prioirty_ingress():
    '''
    MAC and IPv4 Ingress ACL is applied on DUT1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''

    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on port')
    acl_config = acl_data.acl_json_config_priority
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    transmit('tg1')
    #transmit('tg2')
    print_log('Check acl priority to verify packets are forwarded when MAC and IPv4 ACLs rules are in "forward" ')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule1")
    print_log('Check acl priority to verify packets are dropped when MAC acl rule is forward and IPv4 ACL \
                rule is in "drop" ')
    result2 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule4")
    verify_acl_hit_counters(vars.D1, "L2_MAC_INGRESS")
    print_log('Verify ACL hit counters on IPv4)" ')
    result3 = verify_acl_hit_counters(vars.D1, "L3_IPV4_INGRESS")
    acl_utils.report_result(result1 and result2 and result3)

@pytest.mark.acl_test
def test_ft_mac_acl_prioirty_egress():
    '''
    MAC and IPv4 Ingress ACL is applied on DUT1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    # Creating Ingress ACL table and rules
    print_log('Creating ACL table and apply on port')
    acl_config = acl_data.acl_json_config_priority
    add_port_to_acl_table(acl_config, 'L3_IPV4_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L3_IPV4_EGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    apply_acl_config(vars.D1, acl_config)
    st.wait(2)
    transmit('tg2')
    print_log('Check acl priority to verify packets are dropped when MAC rule is drop and \
                IPv4 ACLs rules are in "forward" ')
    result1 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1,  "L3_IPV4_EGRESS|rule1")
    result2 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L2_MAC_EGRESS|rule1")
    print_log('Check acl priority to verify packets are dropped when MAC rule is drop and \
                    IPv4 ACLs rules are in "drop" ')
    result3 = verify_packet_count('tg2', vars.T1D2P1,'tg1', vars.T1D1P1,  "L3_IPV4_EGRESS|rule2")
    print_log('Verify ACL hit counters on IPv4)" ')
    result4 = verify_acl_hit_counters(vars.D1,"L2_MAC_EGRESS")
    verify_acl_hit_counters(vars.D1, "L3_IPV4_EGRESS")
    acl_utils.report_result(result2 and result3 and result4)


@pytest.mark.acl_test678
def test_ft_acl_mac():
    print_log('Creating MAC ACL table and apply on Port ')
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_INGRESS')
    acl_obj.delete_acl_table(vars.D1, acl_table_name='L3_IPV4_EGRESS')
    acl_config = acl_data.acl_json_config_port_d3
    add_port_to_acl_table(acl_config, 'L2_MAC_INGRESS', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'L2_MAC_EGRESS', vars.D1T1P1)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule1", "VLAN", data.vlan)
    change_acl_rules(acl_data.acl_json_config_port_d3, "L2_MAC_INGRESS|macrule2", "VLAN", data.vlan)
    apply_acl_config(vars.D1, acl_config)
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    st.wait(2)
    transmit('tg1')
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    print_log('Verifying MAC Ingress packet count')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L2_MAC_INGRESS")
    [output, exceptions] = utils.exec_all(True,
                                          [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    ensure_no_exception(exceptions)
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    print_log('Verifying MAC Ingress ACL hit counters')
    transmit('tg2')
    result2 = verify_acl_hit_counters(vars.D1, "L2_MAC_INGRESS")
    [output, exceptions] = utils.exec_all(True,
                                          [[get_interface_counters, vars.D1, vars.D1T1P1],
                                           [get_interface_counters, vars.D2, vars.D2T1P1]])
    ensure_no_exception(exceptions)
    print_log('Verifying MAC Ingress packet count')

    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_acl_rest():
    acl_aclname = "L3_IPV4_INGRESS"
    acl_aclname1 = "L3_IPV4_EGRESS"
    acl_rulename = "rule2"
    acl_rulename1 = "rule2"
    acl_in_stage = 'INGRESS'
    acl_eg_stage = 'EGRESS'
    acl_src_interface = vars.D1T1P1
    acl_priority = 2000
    acl_priority1 = 4000
    acl_ip_protocol = 17
    acl_src_ip = "5.5.5.5/16"
    acl_dst_ip = "9.9.9.9/16"
    acl_src_ip1 = "88.67.45.9/32"
    acl_dst_ip1 = "12.12.12.12/16"
    acl_l4_src_port_range = "100-500"
    acl_pkt_action = "FORWARD"
    acl_pkt_action_drop = "DROP"
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    rest_url = "/restconf/data/{}".format(YANG_MODEL)
    ACL_TABLE = {"ACL_TABLE_LIST": [
        {"aclname": acl_aclname, "stage": acl_in_stage, "type": "L3", "ports": [acl_src_interface]},
        {"aclname": acl_aclname1, "stage": acl_eg_stage, "type": "L3", "ports": [acl_src_interface]}]
    }
    ACL_RULE = {"ACL_RULE_LIST": [{"aclname": acl_aclname, "rulename": acl_rulename, "PRIORITY": acl_priority,
                                   "PACKET_ACTION": acl_pkt_action,
                                   "IP_PROTOCOL": acl_ip_protocol, "L4_SRC_PORT_RANGE": acl_l4_src_port_range,
                                   "SRC_IP": acl_src_ip, "DST_IP": acl_dst_ip},
                                  {"aclname": acl_aclname1, "rulename": acl_rulename1, "PRIORITY": acl_priority1,
                                   "PACKET_ACTION": acl_pkt_action_drop, "IP_PROTOCOL": acl_ip_protocol,
                                   "SRC_IP": acl_src_ip1, "DST_IP": acl_dst_ip1}
                                  ]}
    Final_dict = {'sonic-acl:sonic-acl': {'ACL_TABLE': ACL_TABLE, 'ACL_RULE': ACL_RULE}}
    st.log("#################")
    st.log(Final_dict)
    if not Final_dict:
        st.report_fail("operation_failed_msg", 'to form acl data')
    op = st.rest_modify(vars.D1, rest_url, Final_dict)
    if not rest_status(op['status']):
        st.report_fail("operation_failed")
    response = st.rest_read(vars.D1, rest_url)
    if response and response["status"] == 200:
        data1 = response["output"][YANG_MODEL]["ACL_TABLE"]["ACL_TABLE_LIST"]
        if not data1:
            st.log("DATA IN RESPONSE IS EMPTY -- {}".format(data1))
        else:
            data2 = response["output"][YANG_MODEL]["ACL_RULE"]["ACL_RULE_LIST"]
            if not data2:
                st.log("DATA IN RESPONSE IS EMPTY -- {}".format(data2))
    else:
        st.log("RESPONSE -- {}".format(response))
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule2")
    transmit('tg2')
    result2 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV4_EGRESS|rule2")
    acl_utils.report_result(result1 and result2)


@pytest.mark.acl_test
def test_ft_acl_gnmi():
    """Verify that ipv4 acls working fine on gNMI"""
    acl_aclname = "L3_IPV4_INGRESS"
    acl_rulename = "rule2"
    acl_in_stage = 'INGRESS'
    acl_priority = 2000
    acl_ip_protocol = 17
    acl_pkt_action = "FORWARD"
    acl_l4_src_port_range = "100-500"
    acl_src_ip = "5.5.5.5/16"
    acl_dst_ip = "9.9.9.9/16"
    acl_src_interface = vars.D1T1P1
    [output, exceptions] = utils.exec_all(True,
                                          [[acl_delete, vars.D1], [acl_delete, vars.D2]])
    ensure_no_exception(exceptions)
    xpath = "/sonic-acl:sonic-acl/"
    ACL_TABLE = {"ACL_TABLE_LIST": [
        {"aclname": acl_aclname, "stage": acl_in_stage, "type": "L3", "ports": [acl_src_interface]}]}
    ACL_RULE = {"ACL_RULE_LIST": [{"aclname": acl_aclname, "rulename": acl_rulename, "PRIORITY": acl_priority,
                                   "PACKET_ACTION": acl_pkt_action,
                                   "IP_PROTOCOL": acl_ip_protocol, "L4_SRC_PORT_RANGE": acl_l4_src_port_range,
                                   "SRC_IP": acl_src_ip, "DST_IP": acl_dst_ip},
                                  ]}
    json_content = {'sonic-acl:sonic-acl': {'ACL_TABLE': ACL_TABLE, 'ACL_RULE': ACL_RULE}}
    gnmi_set_out = gnmiapi.gnmi_set(vars.D1, xpath, json_content)
    if not gnmi_set_out:
        st.report_fail("error_string_found", ' ', ' ')
    gnmi_get_out = gnmiapi.gnmi_get(vars.D1, xpath)
    if "rpc error:" in gnmi_get_out:
        st.report_fail("error_string_found", 'rpc error:', ' ')
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule2")
    acl_utils.report_result(result1)


@pytest.mark.acl_testklish
def test_ft_acl_klish():
    """Verify that ipv4 acls working fine on klish_cli"""
    acl_aclname = "L3_IPV4_INGRESS"
    acl_rulename = "rule2"
    acl_obj.delete_acl_table(vars.D1)
    acl_obj.create_acl_rule(vars.D1,table_name=acl_aclname ,rule_name=acl_rulename,l4_protocol= 17, SRC_IP="5.5.5.5/16",
                            DST_IP = "9.9.9.9/16", packet_action = "permit", cli_type="klish")
    acl_obj.config_access_group(vars.D1,table_name=acl_aclname, port = vars.D1T1P1,
                                access_group_action= "in", config = "yes")
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS|rule2")
    acl_obj.config_access_group(vars.D1, table_name=acl_aclname, port=vars.D1T1P1,
                                access_group_action="in", config="no")
    acl_obj.delete_acl_table(vars.D1,acl_aclname,cli_type="klish")
    acl_utils.report_result(result1)