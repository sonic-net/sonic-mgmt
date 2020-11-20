##############################################################################
#Script Title : Policy Based Routing
#Author       : Sooriya/ Naveen Nagaraju
#Mail-id      : Sooriya.Gajendrababu@broadcom.com
###############################################################################

import pytest
from spytest import st, tgapi
from pbr_vars import data
from pbr_utils import *
import apis.routing.bgp as bgp_api
import apis.switching.mac as mac_api
from spytest.utils import poll_wait


def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2","D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]

    for dut in data.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]
    data.d1tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.d2tg_ports = [vars.D2T1P1,vars.D2T1P2]
    handles = tgapi.get_handles(vars, [vars.T1D1P1,vars.T1D1P2, vars.T1D2P1, vars.T1D2P2])
    data.tg1 = data.tg2 = handles["tg1"]
    data.tgd1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tgd2_ports = [vars.T1D2P1, vars.T1D2P2]
    data.tgd1_handles = [handles["tg_ph_1"], handles["tg_ph_2"]]
    data.tgd2_handles = [handles["tg_ph_3"], handles["tg_ph_4"]]
    data.tg_handles = data.tgd1_handles + data.tgd2_handles
    data.src_mac = {}
    data.src_mac[data.tgd1_handles[0]] = '00:00:00:11:11:33'
    data.src_mac[data.tgd1_handles[1]] = '00:00:00:11:22:33'
    data.src_mac[data.tgd2_handles[0]] = '00:00:00:22:11:33'
    data.src_mac[data.tgd2_handles[1]] = '00:00:00:22:22:33'
    data.dst_mac_l2 = '00:00:00:55:55:55'
    data.scale_complete = False

    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 1
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 0.2


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    if st.get_ui_type(data.dut1) == 'click':
        st.report_unsupported("test_execution_skipped", "PBR not supported for ui_type - click")
    result = pbr_base_config()
    if result is False:
        st.report_fail('test_execution_skipped','Error in module config')
    yield
    pbr_base_deconfig()


@pytest.fixture(scope="function")
def egress_fixture(request,prologue_epilogue):
    vlan_api.create_vlan(data.dut2,data.d1tg_vlan_id)
    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[1],data.lag_intf], True],
                          [vlan_api.add_vlan_member, data.dut2, data.d1tg_vlan_id, [data.d2tg_ports[1],data.lag_intf], True]])

    yield
    st.log("###### CLEANUP #######")
    utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[1],data.lag_intf], True],
                          [vlan_api.delete_vlan_member, data.dut2, data.d1tg_vlan_id, [data.d2tg_ports[1],data.lag_intf], True]])
    vlan_api.delete_vlan(data.dut2,data.d1tg_vlan_id)

def test_pbr_egress(egress_fixture):
    tc_list = ['FtOpSoRoPbr3211','FtOpSoRoPbr3212','FtOpSoRoPbr3213','FtOpSoRoPbr3221','FtOpSoRoPbr3222','FtOpSoRoPbr3223']
    err_list=[];tc_result=True
    for tc in tc_list: data[tc] = True
    tech_support = True

    #####################################################
    st.banner("Send L2 unknown unicast traffic ")
    #####################################################

    data.tg1.tg_traffic_control(action='run',stream_handle=[data.stream_handles['pbr_ipv4_l2_stream']])

    #####################################################
    st.banner("Apply policy on ingress interface and verify Traffic gets flooded only to D2T2")
    #####################################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_l2_acl,
                                             policy_kind='bind', policy_type='forwarding')

    result = verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd1_ports[1],exp_ratio=0)
    if not result:
        err = "L2 unknown unicast getting flooded to D1T2"
        failMsg(err, tech_support, tc_name=str(get_tc_name()));err_list.append(err);tc_result = False;
        tech_support =False
    result = verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd2_ports[1])
    if not result:
        err = "L2 unknown unicast traffic not forwarded as per policy map to D2T2"
        failMsg(err, tech_support, tc_name=str(get_tc_name()));err_list.append(err);tc_result = False;
        tech_support =False

    #######################################################
    st.banner("Verify Service policy")
    #######################################################
    match = {'policy_name': data.policy_l2_acl, 'class_name': data.class_l2_acl, 'next_hop_interface': data.lag_intf, 'selected': 'Selected'}
    result = acl_dscp_api.verify(data.dut1, service_policy_interface=data.d1tg_vlan_intf, verify_list=[match])
    if not result:
        err = "Next hop egress interface not selected"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tc_result=False;err_list.append(err);data['FtOpSoRoPbr3211'] =False
        tech_support = False

    result = verify_policy_counters_incrementing(data.policy_l2_acl,[data.class_l2_acl],interface=data.d1tg_vlan_intf)
    if not result:
        err = "Policy counters did not increment"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));err_list.append(err);tc_result=False;data['FtOpSoRoPbr3211'] =False
        tech_support = False

    if data['FtOpSoRoPbr3211']:
        st.report_tc_pass('FtOpSoRoPbr3211','tc_passed')

    #####################################################
    st.banner("Configure static mac destined to D1T2")
    #####################################################
    mac_api.config_mac(data.dut1,data.dst_mac_l2,data.d1tg_vlan_id,data.d1tg_ports[1])


    #####################################################
    st.banner("Verify Traffic still forwards only to D2T2 as per policy map for known unicast traffic")
    #####################################################


    result = verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd1_ports[1],exp_ratio=0)
    if not result:
        err = "L2 known unicast getting flooded to D1T2"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));err_list.append(err);tc_result=False;data['FtOpSoRoPbr3212'] =False
        tech_support = False
    result = verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd2_ports[1])
    if not result:
        err = "L2 known unicast traffic not forwarded as per policy map to D2T2"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));err_list.append(err);tc_result=False;data['FtOpSoRoPbr3212'] =False
        tech_support =False

    #######################################################
    st.banner("Verify Service policy")
    #######################################################
    match = {'policy_name': data.policy_l2_acl, 'class_name': data.class_l2_acl, 'next_hop_interface': data.lag_intf,
             'selected': 'Selected'}
    result = acl_dscp_api.verify(data.dut1, service_policy_interface=data.d1tg_vlan_intf, verify_list=[match])
    if not result:
        err = "Next hop egress interface not selected"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));  tc_result = False;err_list.append(err);
        data['FtOpSoRoPbr3212'] = False
        tech_support = False

    #####################################################
    st.banner("Remove policy from interface and verify traffic gets forwarded to D1T2 as per mac table")
    #####################################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_l2_acl,
                                             policy_kind='unbind', policy_type='forwarding')

    result = verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd1_ports[1])
    if not result:
        err = "L2 known unicast traffic not forwarded to D1T2 after unbinding policy map"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tc_result=False;err_list.append(err);data['FtOpSoRoPbr3212'] =False
        tech_support = False
    if data['FtOpSoRoPbr3212']:
        st.report_tc_pass('FtOpSoRoPbr3212', 'tc_passed')
        st.report_tc_pass('FtOpSoRoPbr3213','tc_passed')

    data.tg1.tg_traffic_control(action='stop',stream_handle=[data.stream_handles['pbr_ipv4_l2_stream']])
    #####################################################
    st.banner("Bind policy map with classifier fields and verify it gets forwarded only to D1T2")
    #####################################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_l2_fields,
                                             policy_kind='bind', policy_type='forwarding')

    #####################################################
    st.banner("Verify Multicast and Broadcast  stream gets flooded as per policy table only to D1T2")
    #####################################################
    data.tg1.tg_traffic_control(action='run',stream_handle=[data.stream_handles['multicast'],data.stream_handles['broadcast']])

    if  not verify_traffic(src_port=data.tgd1_ports[0],dest_port=data.tgd1_ports[1]):
        err = 'Multicast/Broadcast stream not forwarded to D1T2 as per policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));err_list.append(err);tc_result=False;data['FtOpSoRoPbr3223'] = False
        tech_support = False

    if not verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd2_ports[1],exp_ratio=0):
        err = 'Multicast/Broadcast stream getting forwarded to D2T2 with policy map applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));err_list.append(err);tc_result=False;data['FtOpSoRoPbr3223'] = False
        tech_support=False
    #######################################################
    st.banner("Verify Service policy")
    #######################################################

    match = {'policy_name': data.policy_l2_fields, 'class_name': data.class_l2_fields, 'next_hop_interface': data.d1tg_ports[1],
             'selected': 'Selected'}


    result = acl_dscp_api.verify(data.dut1, service_policy_interface=data.d1tg_vlan_intf, verify_list=[match])
    if not result:
        err = "Next hop egress interface not selected"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;  tc_result = False;err_list.append(err);
        data['FtOpSoRoPbr3223'] = False


    #####################################################
    st.banner("Modfiy Policy map to set nexthop interface to Portchannel")
    #####################################################

    acl_dscp_api.config_flow_update_table(data.dut1, flow='update', policy_name=data.policy_l2_fields,
                                          policy_type='forwarding',
                                          class_name=data.class_l2_fields, flow_priority=10,
                                          priority_option='interface',
                                          set_interface=data.d1tg_ports[1],config='no')
    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_l2_fields,
                                          policy_type='forwarding',
                                          class_name=data.class_l2_fields, flow_priority=10,
                                          priority_option='interface',
                                          set_interface=data.lag_intf)
    #####################################################
    st.banner("Verify Broadcast/Multicast frame starts forwarding only to D2T2")
    #####################################################
    if not verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd2_ports[1]):
        err = 'Broadcast/Multicast stream not forwarded to D2T2 as per updated policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;
        err_list.append(err);
        tc_result = False;
        data['FtOpSoRoPbr3223'] = False

    if not verify_traffic(src_port=data.tgd1_ports[0], dest_port=data.tgd1_ports[1], exp_ratio=0):
        err = 'Broadcast/Multicast stream getting forwarded to D1T2 with policy map applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;
        err_list.append(err);
        tc_result = False;
        data['FtOpSoRoPbr3223'] = False

    if data['FtOpSoRoPbr3223']:
        st.report_tc_pass('FtOpSoRoPbr3223','tc_passed')
    #####################################################
    st.banner("Bind policy map with mac acl configured with ethertype ip and verify traffic gets dropped")
    #####################################################

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_l2_fields,
                                         match_type='fields',
                                         class_criteria=['--ether-type'], criteria_value=['ip'])

    #####################################################
    st.banner("Verify L2 Traffic gets flooded to all ports since policy will not match")
    #####################################################

    if not verify_traffic(data.tg1,src_port=data.tgd1_ports[0],dest_port=[data.tgd1_ports[1],data.tgd2_ports[1]],exp_ratio=1):
        err ="L2 traffic did not flood to all ports since service policy do not match with ethertype"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;
        err_list.append(err);
        tc_result = False;
        data['FtOpSoRoPbr3222'] = False

    if data['FtOpSoRoPbr3222']:
        st.report_tc_pass('FtOpSoRoPbr3222','tc_passed')
        st.report_tc_pass('FtOpSoRoPbr3221','tc_passed')


    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_l2_fields,
                                             policy_kind='unbind', policy_type='forwarding')

    data.tg1.tg_traffic_control(action='stop',stream_handle=[data.stream_handles['multicast'], data.stream_handles['broadcast']])

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def phy_port_fixture(request,prologue_epilogue):
    #######################################
    st.banner("Pre-Config: Change D1T1 from L2 to L3")
    #######################################
    ip_api.delete_ip_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ip_list[0], data.mask_v4)
    ip_api.delete_ip_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')
    vlan_api.delete_vlan_member(data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[0]], True)
    ip_api.config_ip_addr_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ip_list[0], data.mask_v4)
    ip_api.config_ip_addr_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')

    yield
    #######################################
    st.banner("Post-Config: Revert D1T1 from L3 to L2")
    #######################################
    ip_api.delete_ip_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ip_list[0], data.mask_v4)
    ip_api.delete_ip_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')
    vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[0]], True)
    ip_api.config_ip_addr_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ip_list[0], data.mask_v4)
    ip_api.config_ip_addr_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')


def test_pbr_001(phy_port_fixture):
    #################################################
    st.banner("Verify all Policy and Classifier configuration are applied")
    #################################################
    tc_list = ['FtOpSoRoPbr311','FtOpSoRoPbr3233','FtOpSoRoPbr3234','FtOpSoRoPbr3236','FtOpSoRoPbr32313']
    for tc in tc_list: data[tc] = True
    if  verify_base_policy(match_type='filter') and verify_base_classifier(match_type='filter') :
       st.report_tc_pass('FtOpSoRoPbr311','tc_passed')

    param_dict = {'interface':data.d1tg_ports[0],
                  'policy_name':data.policy_class_port,
                  'nh_sequence':[data.vlan_ip_list[1],data.phy_ip_list[1]],
                  'nh_sequence_ipv6':[data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                  'nh_flap_sequence':[data.d1d2_ports[2],data.d1d2_ports[3]],
                  'nh_vrf_sequence':[data.access_vrf,data.phy_vrf]}

    result,err = verify_pbr_basic_001(type='bgp',scope='port',verify_null=True,param_dict=param_dict,dut_counters=False)
    if data['FtOpSoRoPbr32313']:
        st.report_tc_pass('FtOpSoRoPbr32313','tc_passed')
    if result:
        st.report_tc_pass("FtOpSoRoPbr3233", "tc_passed")
        st.report_tc_pass("FtOpSoRoPbr3234", "tc_passed")
        st.report_tc_pass("FtOpSoRoPbr3236", "tc_passed")
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err)


def test_pbr_002(prologue_epilogue):

    param_dict = {'interface':None,
                  'policy_name':data.policy_class_global,
                  'nh_sequence':[data.vlan_ip_list[1],data.lag_ip_list[1]],
                  'nh_sequence_ipv6':[data.vlan_ipv6_list[1],data.lag_ipv6_list[1]],
                  'nh_flap_sequence':[data.d1d2_ports[2],data.lag_intf],
                  'nh_vrf_sequence':[data.access_vrf,'']}

    result,err = verify_pbr_basic_001(type='static',scope='global',verify_null=False,param_dict=param_dict,dut_counters=True)
    if result:
        st.report_tc_pass("FtOpSoRoPbr3231", "tc_passed")
        st.report_tc_pass("FtOpSoRoPbr3237", "tc_passed")
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err)


def test_pbr_003(prologue_epilogue):

    param_dict = {'interface':data.d1tg_vlan_intf,
                  'policy_name':data.policy_class_vlan,
                  'nh_sequence':[data.phy_ip_list[1],data.lag_ip_list[1]],
                  'nh_sequence_ipv6':[data.phy_ipv6_list[1],data.lag_ipv6_list[1]],
                  'nh_flap_sequence':[data.d1d2_ports[3],data.lag_intf],
                  'nh_vrf_sequence':[data.phy_vrf,'']}

    result,err = verify_pbr_basic_001(type='ospf',scope='vlan',verify_null=False,param_dict=param_dict,dut_counters=False)
    if result:
        st.report_tc_pass('FtOpSoRoPbr3232', "tc_passed")
        st.report_tc_pass('FtOpSoRoPbr3235', "tc_passed")
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err)



def test_pbr_004(prologue_epilogue):
    tc_list = ['FtOpSoRoPbr3238']
    err_list = [];tc_result=True
    tech_support=True
    config_static_routes()
    run_traffic()

    #######################################################
    st.banner("Bind policy with deny access-list {} to Vlan interface".format(data.policy_class_deny))
    #######################################################

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_deny,
                                             policy_kind='bind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)
    #######################################################
    st.banner("Verify policy configs applied on VLan interface")
    ######################################################

    match =[{'policy_name':data.policy_class_deny,'interface':data.d1tg_vlan_intf}]
    result = acl_dscp_api.verify(data.dut1,policy_name=data.policy_class_deny,verify_list=match)
    if not result:
        err ='Policy configs are not applied to Vlan interface'
        tc_result=False;failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err)

    #######################################################
    st.banner("Send Traffic matching the deny access-list and verify Traffic uses routing table nexthop interface ")
    #######################################################

    result = verify_traffic()
    if not result:
        err ='Traffic dropped with deny access-list mapped to service policy'
        tc_result=False;failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err)


    #################################################################
    st.banner("Verify policy counters did not increment")
    #################################################################
    result = verify_policy_counters_incrementing(data.policy_class_deny,flow_list=[data.class_deny_ip,data.class_deny_ipv6],
                                                 interface =data.d1tg_vlan_intf,increment=False)
    if not result:
        err = "Policy counters incremented for flows matching deny acl rules"
        tc_result = False; failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err)

    #######################################################
    st.banner("Un-Bind policy {} from Vlan interface".format(data.policy_class_deny))
    #######################################################


    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_deny,
                                             policy_kind='unbind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)

    run_traffic(action='stop')
    config_static_routes('no')

    if not tc_result:
        st.report_fail("test_case_failure_message",err_list[0])
    else:
        st.report_pass('test_case_passed')




def test_pbr_005(prologue_epilogue):
    tc_list = ['FtOpSoRoPbr3239','FtOpSoRoPbr32310','FtOpSoRoPbr3245']
    tc_result=True;err_list=[]
    tech_support=True

    #######################################################
    st.banner("Apply {}(deny) to vlan interface and {} at switch level".format(data.policy_class_deny,data.policy_class_global))
    #######################################################

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_global,
                                             policy_kind='bind', policy_type='forwarding')


    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_deny,
                                             policy_kind='bind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_port,
                                             policy_kind='bind', policy_type='forwarding',interface_name=data.d1tg_ports[0])




    #######################################################
    st.banner("Verify service policy configurations applied")
    #######################################################

    match =[{'interface_name': data.d1tg_ports[0], 'stage': 'ingress', 'policy_type': 'forwarding', 'policy_name':data.policy_class_port},
            {'interface_name': data.d1tg_vlan_intf, 'stage': 'ingress', 'policy_type': 'forwarding', 'policy_name': data.policy_class_deny},
            {'interface_name': 'Switch', 'stage': 'ingress', 'policy_type': 'forwarding', 'policy_name': data.policy_class_global}]


    result = acl_dscp_api.verify(data.dut1,'service_policy_summary',verify_list=match)
    if not result:
        err = "service policy summary verification Failed"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err); tc_result = False

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_port,
                                             policy_kind='unbind', policy_type='forwarding',interface_name=data.d1tg_ports[0])
    #######################################################
    st.banner("Start both IP and IPv6 traffic matching access-list")
    #######################################################

    run_traffic()


    #######################################################
    st.banner("Verify VLan level policy gets applied and traffic gets dropped")
    ######################################################


    result =verify_traffic(exp_ratio=0)
    if not result:
        err = 'Traffic did not drop with deny access-list policy applied at Vlan level'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False

    #######################################################
    st.banner("Unbind Vlan deny policy and verify Nexthop configured at Switch level kicks in")
    #######################################################

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_deny,
                                             policy_kind='unbind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)


    #######################################################
    st.banner("Verify Traffic gets forwarded as per nexthop and check policy map counters")
    #######################################################


    result = verify_selected_next_hop(scope='global', policy=data.policy_class_global, flow_list=[data.class_permit_ip,data.class_permit_ipv6],
                                      nh_list=[data.vlan_ip_list[1],data.vlan_ipv6_list[1]], nh_vrf=[data.access_vrf]*2,check_counters=False)
    if not result:
        err = 'Nexthop configured with policy applied at switch level did not take effect'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False

    result =verify_traffic()
    if not result:
        err = 'Traffic not forwarded with Switch level permit policy applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False

    #######################################################
    st.banner("Change Lag vlan from access to trunk and verify traffic continues to flow")
    #######################################################
    vlan_api.delete_vlan_member(data.dut1,vlan=data.access_vlan_id,port_list=[data.d1d2_ports[2]],tagging_mode=False)
    vlan_api.delete_vlan_member(data.dut2, vlan=data.access_vlan_id, port_list=[data.d2d1_ports[2]], tagging_mode=False)

    vlan_api.add_vlan_member(data.dut1,vlan=data.access_vlan_id,port_list=[data.d1d2_ports[2]],tagging_mode=True)
    vlan_api.add_vlan_member(data.dut2, vlan=data.access_vlan_id, port_list=[data.d2d1_ports[2]], tagging_mode=True)
    st.wait(2,'wait for arp/nd to resolve')
    if not verify_traffic():
        err = "Traffic dropped After changing nexthop vlan interface from access to Trunk"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False
    else:
        st.report_tc_pass('FtOpSoRoPbr3239','tc_passed')
    #######################################################
    st.banner("Clear ARP/ND and verify traffic flow")
    #######################################################

    arp.clear_arp_table(data.dut1)
    arp.clear_ndp_table(data.dut1)

    if not verify_traffic():
        err = "Traffic not resumed after doing clear ARP and ND table"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False
    else:
        st.report_tc_pass('FtOpSoRoPbr32310','tc_passed')

    #######################################################
    st.banner("Unbind policy map")
    #######################################################

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_global,
                                             policy_kind='unbind', policy_type='forwarding')

    vlan_api.delete_vlan_member(data.dut1,vlan=data.access_vlan_id,port_list=[data.d1d2_ports[2]],tagging_mode=True)
    vlan_api.delete_vlan_member(data.dut2, vlan=data.access_vlan_id, port_list=[data.d2d1_ports[2]], tagging_mode=True)
    vlan_api.add_vlan_member(data.dut1,vlan=data.access_vlan_id,port_list=[data.d1d2_ports[2]],tagging_mode=False)
    vlan_api.add_vlan_member(data.dut2, vlan=data.access_vlan_id, port_list=[data.d2d1_ports[2]], tagging_mode=False)

    run_traffic(action='stop')

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')



@pytest.fixture(scope="function")
def control_fixture(request,prologue_epilogue):
    ################################################
    st.banner("Configure Deny ACL matching OSPF/BGP pkts")
    ################################################
    acl_api.create_acl_table(data.dut1, name='deny_ctrl_pkt', stage='INGRESS', type='ip', ports=[])
    acl_api.create_acl_rule(data.dut1, acl_type='ip', rule_name='deny_ctrl_pkt', rule_seq='10', packet_action='deny',
                            table_name='deny_ctrl_pkt',
                            src_ip='any', dst_ip='224.0.0.5', host_2='host',
                            l4_protocol='ip')
    acl_api.create_acl_rule(data.dut1, acl_type='ip', rule_name='deny_ctrl_pkt', rule_seq='20', packet_action='deny',
                            table_name='deny_ctrl_pkt',
                            src_ip=data.lag_ip_list[1], dst_ip=data.lag_ip_list[0], host_1='host', host_2='host',
                            l4_protocol='ip')
    acl_api.create_acl_rule(data.dut1, acl_type='ip', rule_name='deny_ctrl_pkt', rule_seq='30', packet_action='permit',
                            table_name='deny_ctrl_pkt', src_ip='any', dst_ip='any', l4_protocol='ip')

    ##################################################
    st.banner("Conigure classifier and policy to match this deny acl")
    ##################################################
    acl_dscp_api.config_classifier_table(data.dut1, enable='create', class_name='class_deny_ctrl', match_type='acl',
                                         class_criteria='acl', criteria_value='deny_ctrl_pkt', acl_type='ip')

    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_null',
                                          policy_type='forwarding',
                                          class_name='class_deny_ctrl', priority_option='interface',
                                          set_interface='null',flow_priority=10)

    yield

    #####################################
    st.banner("CLEANUP")
    #####################################
    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name='policy_null',
                                             policy_kind='unbind', policy_type='forwarding',
                                             interface_name=data.lag_vlan_intf)
    acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_null',
                                          policy_type='forwarding',
                                          class_name='class_deny_ctrl')
    acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name='policy_null')
    acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name='class_deny_ctrl', match_type='acl')
    acl_api.delete_acl_table(data.dut1, acl_table_name='deny_ctrl_pkt', acl_type='ip')


def test_pbr_008(control_fixture):
    tc_list = ['FtOpSoRoPbr32314']
    ############################################
    st.banner("Bind service policy with null interface to {}".format(data.d1tg_vlan_intf))
    ############################################
    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name='policy_null',
                                             policy_kind='bind', policy_type='forwarding',
                                             interface_name=data.lag_vlan_intf)

    ############################################
    st.banner("Verify Service poliy state ")
    ############################################
    match = {'policy_name': 'policy_null', 'class_name': 'class_deny_ctrl', 'next_hop_interface': 'null', 'flow_state': '(Active)'}
    result = retry_api(acl_dscp_api.verify, data.dut1, service_policy_name='policy_null', verify_list=[match], retry_count=5, delay=1)
    if not result:
        st.report_fail('test_case_failure_message','service policy incorrect')

    ############################################
    st.banner("CLear bgp and ospf sessions")
    ############################################
    bgp_api.clear_ip_bgp(data.dut1)
    port_api.shutdown(data.dut1,[data.d1d2_ports[0],data.d1d2_ports[1]])
    port_api.noshutdown(data.dut1, [data.d1d2_ports[0], data.d1d2_ports[1]])
    ############################################
    st.banner("Verify OSPF and BGP control packets do not drop because of null interface in policy")
    ############################################
    result = retry_api(ip_bgp.check_bgp_session, data.dut1, nbr_list=[data.lag_ip_list[1]], state_list=['Established'])
    if not result:
        st.report_fail('test_case_failure_message','BGP session went down after policy with null interface applied')

    result = retry_api(ospf_api.verify_ospf_neighbor_state, data.dut1, ospf_links = [data.lag_vlan_intf],
                       states = ['Full'],vrf='default',retry_count=6,delay=10)
    if not result:
        st.report_fail('test_case_failure_message','OSPF session went down after policy with null interface applied')

    st.report_pass('test_case_passed')

def test_pbr_009(prologue_epilogue):
    tc_list = ['FtOpSoRoPbr3247','FtOpSoRoPbr32312','FtOpSoRoPbr3249','FtOpSoRoPbr32311']
    tc_result=True;err_list=[]
    tech_support=True
    for tc in tc_list: data[tc] = True

    run_traffic()
    ################################################
    st.banner("Bind {} to Vlan interface".format(data.policy_class_vlan))
    ################################################
    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_vlan,
                                             policy_kind='bind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)

    ################################################
    st.banner("Verify Nexthop is selected as per policy applied to Vlan interface")
    ################################################

    result = verify_selected_next_hop(scope='vlan', policy=data.policy_class_vlan,
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.phy_ip_list[1], data.phy_ipv6_list[1]],
                                      nh_vrf=[data.phy_vrf]*2,interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err='Nexthop not selected as per service policy applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False

    if not verify_traffic():
        err='Traffic not forwarded with service policy applied at Vlan level'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False

    ################################################
    st.banner("Modify the TTL values to 1 and verify traffic gets dropped at ingress itself")
    ################################################

    run_traffic(action='stop')
    data.tg1.tg_traffic_config(mode='modify',stream_id=data.stream_handles['pbr_ipv4_tcp_stream'],ip_ttl=1)
    data.tg1.tg_traffic_config(mode='modify',stream_id=data.stream_handles['pbr_ipv6_tcp_stream'], ipv6_hop_limit=1)
    run_traffic()

    if not verify_traffic(exp_ratio=0):
        err = 'Traffic not dropped with TTL value set to 1'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False;data['FtOpSoRoPbr32312']=False

    if data['FtOpSoRoPbr32312']:
        st.report_tc_pass('FtOpSoRoPbr32312','tc_passed')

    run_traffic(action='stop')
    data.tg1.tg_traffic_config(mode='modify',stream_id=data.stream_handles['pbr_ipv4_tcp_stream'],ip_ttl=10)
    data.tg1.tg_traffic_config(mode='modify',stream_id=data.stream_handles['pbr_ipv6_tcp_stream'], ipv6_hop_limit=64)
    run_traffic()

    ################################################
    st.banner("Modify access-list rule from permit to deny and verify gets dropped")
    ################################################
    if 'rest' in st.get_ui_type():
        v4_str = '/32';
        v6_str = '/128'
    else:
        v4_str = v6_str = ''

    acl_api.delete_acl_rule(data.dut1,acl_type='ip',acl_table_name=data.ip_permit_acl,acl_rule_name=data.ip_permit_acl,rule_seq='10')
    acl_api.create_acl_rule(data.dut1, acl_type='ip', rule_name=data.ip_permit_acl, rule_seq='10', packet_action='deny',
                            table_name=data.ip_permit_acl,
                            src_ip=data.d1tg_ip_list[1]+v4_str, dst_ip=data.d2tg_ip_list[1]+v4_str, host_1='host', host_2='host',
                            l4_protocol='ip')
    acl_api.delete_acl_rule(data.dut1, acl_type='ipv6', acl_table_name=data.ipv6_permit_acl,
                            acl_rule_name=data.ipv6_permit_acl, rule_seq='10')
    acl_api.create_acl_rule(data.dut1, acl_type='ipv6', rule_name=data.ipv6_permit_acl, rule_seq='10',
                            packet_action='deny', table_name=data.ipv6_permit_acl,
                            src_ip=data.d1tg_ipv6_list[1]+v6_str, dst_ip=data.d2tg_ipv6_list[1]+v6_str, host_1='host', host_2='host',
                            l4_protocol='ipv6')


    ################################################
    st.banner("Verify Traffic gets dropped after changing acl rule from permit to deny")
    ################################################

    if not verify_traffic(exp_ratio=0):
        err ='Traffic not dropped after modifying acl rule from permit to deny'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False

    ################################################
    st.banner("Revert back the acl rule to permit and verify traffic gets forwarded")
    ################################################

    acl_api.delete_acl_rule(data.dut1, acl_type='ip', acl_table_name=data.ip_permit_acl,
                            acl_rule_name=data.ip_permit_acl, rule_seq='10')
    acl_api.delete_acl_rule(data.dut1, acl_type='ipv6', acl_table_name=data.ipv6_permit_acl,
                            acl_rule_name=data.ipv6_permit_acl, rule_seq='10')
    acl_api.create_acl_rule(data.dut1, acl_type='ip', rule_name=data.ip_permit_acl, rule_seq='10',
                            packet_action='permit', table_name=data.ip_permit_acl,
                            src_ip=data.d1tg_ip_list[1]+v4_str, dst_ip=data.d2tg_ip_list[1]+v4_str, host_1='host', host_2='host',
                            l4_protocol='ip')
    acl_api.create_acl_rule(data.dut1, acl_type='ipv6', rule_name=data.ipv6_permit_acl, rule_seq='10',
                            packet_action='permit', table_name=data.ipv6_permit_acl,
                            src_ip=data.d1tg_ipv6_list[1]+v6_str, dst_ip=data.d2tg_ipv6_list[1]+v6_str, host_1='host', host_2='host',
                            l4_protocol='ipv6')

    ################################################
    st.banner("Verify Nexthop selected as per service policy after changing rule to permit")
    ################################################

    result = verify_selected_next_hop(scope='vlan', policy=data.policy_class_vlan,
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.phy_ip_list[1], data.phy_ipv6_list[1]],
                                      interface=data.d1tg_vlan_intf,
                                      nh_vrf=[data.phy_vrf,data.phy_vrf],check_counters=
                                      False)
    if not result:
        err='Nexthop not selected as per service policy applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False

    ################################################
    st.banner("Modify Nexthop lookup mode to optimised ")
    ################################################
    acl_api.config_hw_acl_mode(data.dut1,counter='per-rule')

    result = verify_selected_next_hop(scope='vlan', policy=data.policy_class_vlan,
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.phy_ip_list[1], data.phy_ipv6_list[1]],
                                      nh_vrf=[data.phy_vrf,data.phy_vrf],interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err='Nexthop not selected as per service policy applied with optimised lookup mode'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False;data['FtOpSoRoPbr3249']=False

    if not verify_traffic():
        err='Traffic not forwarded with service policy applied at Vlan level with optimised lookup mode'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False;data['FtOpSoRoPbr3249']=False

    run_traffic(action='stop')
    acl_api.config_hw_acl_mode(data.dut1, counter='per-interface-rule')
    if data['FtOpSoRoPbr3249']:
        st.report_tc_pass('FtOpSoRoPbr3249','tc_passed')

    """
    ################################################
    st.banner("Modify traffic stream to send data < 64 bytes and verify traffic gets dropped at ingress interface itself")
    ################################################

    intf_api.interface_properties_set(data.dut1, interfaces_list=data.d1d2_ports[3], property='mtu', value='1550')
    data.tg1.tg_traffic_config(mode='modify',length_mode='fixed',frame_size='60',
                               stream_id=[data.stream_handles['pbr_ipv4_tcp_stream'],data.stream_handles['pbr_ipv6_tcp_stream']])

    run_traffic(action='start')
    st.wait(5)
    run_traffic(action='stop')

    if not verify_traffic(comp_type='oversize_count',exp_ratio=0):
        err = 'Runt traffic not dropped with service policy applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;tc_result=False;err_list.append(err);data['FtOpSoRoPbr32311']=False


    """
    ################################################
    st.banner("Send Jumbo frames and verify traffic gets forwarded  with nexthop selected as per policy ")
    ################################################

    data.tg1.tg_traffic_config(mode='modify',length_mode='fixed',frame_size='2000',
                               stream_id=data.stream_handles['pbr_ipv4_tcp_stream'])
    run_traffic(action='start',version='ipv4')
    st.wait(5)
    run_traffic(action='stop',version='ipv4')

    if not verify_traffic(comp_type='oversize_count'):
        err = 'Jumbo traffic dropped with service policy applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;tc_result = False;err_list.append(err);
        data['FtOpSoRoPbr32311'] = False

    if data['FtOpSoRoPbr32311']:
        st.report_tc_pass('FtOpSoRoPbr32311','tc_passed')

    acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=data.policy_class_vlan,
                                             policy_kind='unbind', policy_type='forwarding',interface_name=data.d1tg_vlan_intf)
    data.tg1.tg_traffic_config(mode='modify',length_mode='fixed',frame_size='128',
                               stream_id=data.stream_handles['pbr_ipv4_tcp_stream'])
    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_pbr_010(prologue_epilogue):
    tc_list =['FtOpSoRoPbr3241','FtOpSoRoPbr3242','FtOpSoRoPbr3248','FtOpSoRoPbr32315']
    for tc in tc_list: data[tc] =True
    err_list=[];tc_result=True
    tech_support =True
    advertise_routes('static')

    #########################################################
    st.banner("Bind Classifier Field policy to interface and start TCP traffic matching Classifier")
    ########################################################
    run_traffic()
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_class_fields_tcp,
                                             policy_kind='bind', policy_type='forwarding')

    ###########################################################
    st.banner("Verify nexthop selection under service policy and Traffic forwarding")
    ###########################################################
    result = verify_selected_next_hop(scope='vlan',policy=data.policy_class_fields_tcp,flow_list=[data.class_fields_tcp_ip,data.class_fields_tcp_ipv6],
                                      nh_list=[data.vlan_ip_list[1],data.vlan_ipv6_list[1]],
                                      nh_vrf=[data.access_vrf,data.access_vrf],
                                      interface=data.d1tg_vlan_intf)
    if not result:
        err = 'WIth Classifier mathcing fields, nexthop not selected as per service policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);tc_result=False;data['FtOpSoRoPbr3241']=False


    if not verify_traffic():
        err = 'WIth Classifier mathcing fields,Traffic getting dropped'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err);
        tc_result = False; data['FtOpSoRoPbr3241'] = False
    run_traffic(action='stop')

    if data['FtOpSoRoPbr3241']:
        st.report_tc_pass('FtOpSoRoPbr3241','tc_passed')

    ###################################################################
    st.banner("Send IP/IPv6 UDP traffic and verify it uses routing table nexthop since it is non-PBR flow")
    ###################################################################
    data['FtOpSoRoPbr32315'] = True
    run_traffic(protocol='udp')

    ###################################################################
    st.banner("Verify Traffic gets forwarded via routing table and policy counters do not increment")
    ###################################################################

    result =verify_traffic()
    if not result:
        err ='Traffic not forwarded via routing table entries for non-PBR flow'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False

    result = verify_policy_counters_incrementing(data.policy_class_fields_tcp,flow_list=[data.class_fields_tcp_ip,data.class_fields_tcp_ipv6],
                                        increment=False,interface=data.d1tg_vlan_intf)

    if not result:
        err ='Policy counters getting incremented for non-PBR UDP flow'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False


    if data['FtOpSoRoPbr32315']:
        st.report_tc_pass('FtOpSoRoPbr32315','tc_passed')
    ###################################################################
    st.banner("Modify classifer rules to match UDP traffic")
    ###################################################################

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ip,
                                         match_type='fields',
                                         class_criteria=['--no-src-port', '--no-dst-port', '--no-tcp-flags','--no-ip-proto'],
                                         criteria_value=[data.src_tcp, data.dst_tcp,'syn not-psh','tcp'])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ipv6,
                                         match_type='fields',
                                         class_criteria=['--no-src-port', '--no-dst-port', '--no-tcp-flags','--no-ip-proto'],
                                         criteria_value=[data.src_tcp, data.dst_tcp,'syn not-psh','tcp'])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ip,
                                         match_type='fields',
                                         class_criteria=['ip-proto', 'src-port', 'dst-port'],
                                         criteria_value=['udp', data.src_udp, data.dst_udp])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ipv6,
                                         match_type='fields',
                                         class_criteria=['ip-proto', 'src-port', 'dst-port'],
                                         criteria_value=['udp', data.src_udp, data.dst_udp])

    ###################################################################
    st.banner("Verify UDP traffic gets forwarded via nexthop selected on service-policy")
    ###################################################################

    result = verify_selected_next_hop(scope='port', policy=data.policy_class_fields_tcp, flow_list=[data.class_fields_tcp_ip,data.class_fields_tcp_ipv6],
                                      nh_list=[data.vlan_ip_list[1],data.vlan_ipv6_list[1]], nh_vrf=[data.access_vrf]*2,interface=data.d1tg_vlan_intf)
    if not result:
        err = 'Nexthop not selected as per service policy for UDP traffic'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False

    withdraw_routes('static')
    run_traffic(action='stop',protocol='udp')

    ###################################################################
    st.banner("Start TCP traffic and verify non-PBR tcp traffic gets dropped since no routing entry is present")
    ###################################################################
    run_traffic(action='start')
    if not verify_traffic(exp_ratio=0):
        err ='TCP traffic not dropped with policy matching UDP packets applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False
    else:
        st.report_tc_pass('FtOpSoRoPbr3248','tc_passed')

    ###################################################################
    st.banner("Revert back the classifier configs to tcp flows")
    ###################################################################
    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ip,
                                         match_type='fields',
                                         class_criteria=['--no-src-port', '--no-dst-port','--no-ip-proto'],
                                         criteria_value=[data.src_udp, data.dst_udp,'udp'])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ipv6,
                                         match_type='fields',
                                         class_criteria=['--no-src-port', '--no-dst-port','--no-ip-proto'],
                                         criteria_value=['udp', data.src_udp, data.dst_udp,'udp'])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ip,
                                         match_type='fields',
                                         class_criteria=['ip-proto', 'src-port', 'dst-port',
                                                         'tcp-flags'],
                                         criteria_value=['tcp', data.src_tcp, data.dst_tcp, 'syn not-psh'])

    acl_dscp_api.config_classifier_table(data.dut1, enable='update', class_name=data.class_fields_tcp_ipv6,
                                         match_type='fields',
                                         class_criteria=['ip-proto', 'src-port', 'dst-port',
                                                         'tcp-flags'],
                                         criteria_value=['tcp', data.src_tcp, data.dst_tcp, 'syn not-psh'])

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_class_fields_tcp,
                                             policy_kind='unbind', policy_type='forwarding')
    run_traffic('stop')

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_pbr_011(prologue_epilogue):
    tc_list =['FtOpSoRoPbr3243','FtOpSoRoPbr3244','FtOpSoRoPbr32410','FtOpSoRoPbr3246']
    err_list=[];tc_result=True
    tech_support=True
    for tc in tc_list: data[tc] = True

    ###############################################
    st.banner("Apply all types of policy map to interface and start Traffic")
    ###############################################

    run_traffic()

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_vrf',
                                             policy_kind='bind', policy_type='forwarding')
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_qos',
                                             policy_kind='bind', policy_type='qos')
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_monitoring',
                                             policy_kind='bind', policy_type='monitoring')


    ###############################################
    st.banner("Verify all policy types are applied ")
    ###############################################

    match_list = [{'stage': 'ingress', 'policy_type': 'qos', 'policy_name': 'policy_qos'},
                  { 'stage': 'ingress', 'policy_type': 'monitoring', 'policy_name': 'policy_monitoring'},
                  {'stage': 'ingress', 'policy_type': 'forwarding', 'policy_name': 'policy_vrf'}]

    result = acl_dscp_api.verify(data.dut1,'service_policy_summary',verify_list=match_list)
    if not result:
        err = "service policy summary verification Failed"
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False;err_list.append(err); tc_result = False


    ###############################################
    st.banner("Verify L3 forwarding uses nexthop on default-vrf as per policy")
    ###############################################

    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf', flow_list=[data.class_permit_ip,data.class_permit_ipv6],
                                      nh_list=[data.lag_ip_list[1],data.lag_ipv6_list[1]], nh_vrf=[data.vrf_list[0]]*2,interface=data.d1tg_vlan_intf,
                                      check_counters=False)
    if not result:
        err = 'Nexthop not selected as per policy with all types of policies applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False;data['FtOpSoRoPbr3246'] = False

    if not verify_traffic():
        err = 'Traffic did not forward with all policy types applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err); tc_result = False;data['FtOpSoRoPbr3246'] =False

    if data.FtOpSoRoPbr3246:
        st.report_tc_pass('FtOpSoRoPbr3246','tc_passed')


    ###############################################
    st.banner("With traffic running, Change the Vrf  for D1T1 from default to {}".format(data.phy_vrf))
    ###############################################
    #Remove ip/ipv6
    ip_api.delete_ip_interface(data.dut1,interface_name=data.d1tg_vlan_intf,ip_address=data.d1tg_ip_list[0],subnet=data.mask_v4)
    ip_api.delete_ip_interface(data.dut1, interface_name=data.d1tg_vlan_intf, ip_address=data.d1tg_ipv6_list[0],
                               subnet=data.mask_v6,family='ipv6')
    vrf_api.bind_vrf_interface(data.dut1,intf_name=data.d1tg_vlan_intf,vrf_name=data.phy_vrf)
    #add back ip/ipv6 address
    ip_api.config_ip_addr_interface(data.dut1,interface_name=data.d1tg_vlan_intf,ip_address=data.d1tg_ip_list[0],subnet=data.mask_v4)
    ip_api.config_ip_addr_interface(data.dut1, interface_name=data.d1tg_vlan_intf, ip_address=data.d1tg_ipv6_list[0],
                               subnet=data.mask_v6,family='ipv6')

    ###############################################
    st.banner("Verify Traffic forwards with default-vrf nexthop since it has highest priority ")
    ###############################################

    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf',
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.lag_ip_list[1], data.lag_ipv6_list[1]],
                                      nh_vrf=[data.vrf_list[0]] * 2,interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err = 'Nexthop not selected as per policy map'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;

    if not verify_traffic():
        err = 'Traffic did not forward with policy map applied'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;


    ###############################################
    st.banner("Shutdown default and {} nexthops and verify traffic takes {} nexthop though"
              " nexthop-vrf is not configured (uses src-interface vrf)".format(data.access_vrf,data.phy_vrf))
    ###############################################

    port_api.shutdown(data.dut1,data.d1d2_ports[0:3])

    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf',
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.phy_ip_list[1], data.phy_ipv6_list[1]],
                                      nh_vrf=['',''],
                                      interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err = 'Nexthop lookup not selected after moving interface from default to user-vrf'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;

    if not verify_traffic():
        err = 'Traffic did not forward after moving interface from default to user-vrf'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;


    ###############################################
    st.banner("Bring back all other nexthops and verify default-vrf nexthop is selected back")
    ###############################################

    port_api.noshutdown(data.dut1,data.d1d2_ports[0:3])
    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf',
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.lag_ip_list[1], data.lag_ipv6_list[1]],
                                      nh_vrf=[data.vrf_list[0]] * 2,
                                      interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err = 'Nexthop not selected as per policy map'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;


    ###############################################
    st.banner("Delete default-vrf nexthop rule from policy and verify it uses {} nexthop".format(data.access_vrf))
    ###############################################
    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                          policy_type='forwarding',
                                          class_name=data.class_permit_ip, flow_priority=10, priority_option='next-hop',
                                          next_hop=[data.lag_ip_list[1]], vrf_name=['default'],
                                          next_hop_priority=[30],config='no')
    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                          policy_type='forwarding',
                                          class_name=data.class_permit_ipv6, flow_priority=10,
                                          priority_option='next-hop',next_hop=[data.lag_ipv6_list[1]],
                                          vrf_name=['default'], next_hop_priority=[40], version='ipv6',config='no')

    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf',
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.vlan_ip_list[1], data.vlan_ipv6_list[1]],
                                      nh_vrf=[data.access_vrf]*2,check_counters=False,
                                      interface=data.d1tg_vlan_intf)
    if not result:
        err = 'Nexthop not selected ,After deleting active best nexthop from policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;data.FtOpSoRoPbr32410 =False

    if not verify_traffic():
        err = 'Traffic not forwarded,After deleting active best nexthop from policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;data.FtOpSoRoPbr32410=False

    ###############################################
    st.banner("Re-add default-vrf nexthop rule with higher priority and verify traffic switches to this nexthop")
    ###############################################
    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                          policy_type='forwarding',
                                          class_name=data.class_permit_ip, flow_priority=10, priority_option='next-hop',
                                          next_hop=[data.lag_ip_list[1]], vrf_name=['default'],
                                          next_hop_priority=[30],config='yes')
    acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                          policy_type='forwarding',
                                          class_name=data.class_permit_ipv6, flow_priority=10,
                                          priority_option='next-hop',next_hop=[data.lag_ipv6_list[1]],
                                          vrf_name=['default'], next_hop_priority=[40], version='ipv6',config='yes')

    result = verify_selected_next_hop(scope='vlan', policy='policy_vrf',
                                      flow_list=[data.class_permit_ip, data.class_permit_ipv6],
                                      nh_list=[data.lag_ip_list[1], data.lag_ipv6_list[1]],
                                      nh_vrf=[data.vrf_list[0]]*2,check_counters=False,
                                      interface=data.d1tg_vlan_intf)
    if not result:
        err = 'default vrf nexthop not selected after readding it to policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;data.FtOpSoRoPbr32410 =False

    if not verify_traffic():
        err = 'Traffic not forwarded, after  delete and readding  nexthop rules to policy'
        failMsg(err,tech_support,tc_name=str(get_tc_name()));tech_support=False; err_list.append(err);tc_result = False;data.FtOpSoRoPbr32410=False

    if data.FtOpSoRoPbr32410:
        st.report_tc_pass('FtOpSoRoPbr32410','tc_passed')

    ###############################################
    st.banner("Revert back D1T1 port to default vrf and delete policy")
    ###############################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_vrf',
                                             policy_kind='unbind', policy_type='forwarding')
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_qos',
                                             policy_kind='unbind', policy_type='qos')
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name='policy_monitoring',
                                             policy_kind='unbind', policy_type='monitoring')

    ip_api.delete_ip_interface(data.dut1,interface_name=data.d1tg_vlan_intf,ip_address=data.d1tg_ip_list[0],subnet=data.mask_v4)
    ip_api.delete_ip_interface(data.dut1, interface_name=data.d1tg_vlan_intf, ip_address=data.d1tg_ipv6_list[0],subnet=data.mask_v6,family='ipv6')
    vrf_api.bind_vrf_interface(data.dut1,intf_name=data.d1tg_vlan_intf,vrf_name=data.phy_vrf,config='no')
    #add back ip/ipv6 address
    ip_api.config_ip_addr_interface(data.dut1,interface_name=data.d1tg_vlan_intf,ip_address=data.d1tg_ip_list[0],subnet=data.mask_v4)
    ip_api.config_ip_addr_interface(data.dut1, interface_name=data.d1tg_vlan_intf, ip_address=data.d1tg_ipv6_list[0],subnet=data.mask_v6,family='ipv6')

    run_traffic(action='stop')


    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_tc_pass('FtOpSoRoPbr3243','tc_passed')
        st.report_tc_pass('FtOpSoRoPbr3244','tc_passed')
        st.report_pass('test_case_passed')




@pytest.fixture(scope="function")
def trigger_fixture(request,prologue_epilogue):
    scope_list = ['port','vlan','global']
    import random
    data.scope_trigger = scope_list[random.randint(0, (len(scope_list) - 1))]
    if data.scope_trigger == 'port':
        #######################################
        st.banner("Pre-Config: Change D1T1 from L2 to L3")
        #######################################
        ip_api.delete_ip_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ip_list[0], data.mask_v4)
        ip_api.delete_ip_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')
        vlan_api.delete_vlan_member(data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[0]], True)
        ip_api.config_ip_addr_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ip_list[0], data.mask_v4)
        ip_api.config_ip_addr_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')

    yield

    if data.scope_trigger == 'port':
        run_traffic(action='stop', scope='phy')
        #######################################
        st.banner("Post-Config: Revert D1T1 from L3 to L2")
        #######################################
        ip_api.delete_ip_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ip_list[0], data.mask_v4)
        ip_api.delete_ip_interface(data.dut1, data.d1tg_ports[0], data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')
        vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, [data.d1tg_ports[0]], True)
        ip_api.config_ip_addr_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ip_list[0], data.mask_v4)
        ip_api.config_ip_addr_interface(data.dut1, data.d1tg_vlan_intf, data.d1tg_ipv6_list[0], data.mask_v6,family='ipv6')
    else:
        run_traffic(action='stop')



def test_pbr_012(trigger_fixture):
    if data.scope_trigger == 'port':
        run_traffic(scope='phy')
    else:
        run_traffic()
    result,err = pbr_trigger_case()
    if not result:
        failMsg(err)
        st.report_fail('test_case_failure_message',err)

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def scale_fixture(prologue_epilogue):
    scale_base_config()
    yield
    data.scale_complete = True
    st.log("CLEANUP")
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_names[0],
                                             policy_kind='unbind', policy_type='forwarding')
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.scale_streams)

    scale_base_deconfig()


def test_pbr_scale(scale_fixture):
    tc_list =['FtOpSoRoPbr341','FtOpSoRoPbr342','FtOpSoRoPbr351']
    for tc in tc_list: data[tc]=True
    tc_result=True;err_list=[]

    ##########################################
    st.banner("Apply policy {} to vlan level".format(data.policy_names[0]))
    ##########################################
    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_names[0],
                                             policy_kind='bind', policy_type='forwarding')

    ##########################################
    st.banner("Verify max {} classifiers configured".format(data.max_classifier))
    ##########################################
    v4_str = '/32' if st.get_ui_type() != 'klish' else ''
    match_field = []
    for policy_name,class_name,src_ip in zip(data.policy_names[1:],data.classifier_names[1:],data.src_ip_list[1:]):
        match_field.append(
        {'class_name':class_name, 'match_type': 'fields','src_ip_val': str(src_ip)+v4_str})

    for class_name,src_ip in zip(data.classifier_names[0:64],data.src_ip_list[0:64]):
       match_field.append(
        {'class_name': class_name, 'match_type': 'fields', 'src_ip_val': str(src_ip)+v4_str})

    result = poll_wait(acl_dscp_api.verify, 10, data.dut1, match_type='fields', verify_list=match_field)
    if not result:
        err = 'Scale Classifier verification failed '
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Verify max {} policies configured".format(data.max_policy))
    ##########################################

    match_policy =[]
    for policy,class_name in zip(data.policy_names[1:],data.classifier_names[1:]):
        match_policy.append({'policy_name':policy,'class_name':class_name,'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf})

    for class_name in data.classifier_names[0:64]:
        match_policy.append(
            {'class_name': class_name, 'policy_name': data.policy_names[0],'priority_val': '10', 'next_hop': data.vlan_ip_list[1],
             'next_hop_vrf':data.access_vrf})
    result = poll_wait(acl_dscp_api.verify, 10, data.dut1,'policy', verify_list=match_policy)
    if not result:
        err = 'Scale Classifier verification failed '
        st.report_fail('test_case_failure_message',err)


    ##########################################
    st.banner("Send Traffic and verify Nexthop selection")
    ##########################################
    data.tg1.tg_traffic_control(action='run', stream_handle=data.scale_streams)



    result = verify_selected_next_hop(scope='vlan', policy=data.policy_names[0],
                                      flow_list=data.classifier_names[0:64],
                                      nh_list=[data.vlan_ip_list[1]]*data.max_policy_sections,
                                      nh_vrf=[data.access_vrf]*data.max_policy_sections,
                                      interface=data.d1tg_vlan_intf,check_counters=True)
    if not result:
        err = 'Nexthop not selected as per policy map with Scale config'
        st.report_fail('test_case_failure_message',err)

    if not verify_traffic():
        err = 'Traffic Failed with max policy and classifier configured'
        st.report_fail('test_case_failure_message',err)

    ##############################################
    st.banner("Unbind service policy and verify traffic gets dropped ")
    ##############################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_names[0],
                                             policy_kind='unbind', policy_type='forwarding')

    if not verify_traffic(exp_ratio=0):
        err = 'Traffic not dropped after unbinding policy '
        st.report_fail('test_case_failure_message',err)

    ##############################################
    st.banner("Rebind service policy and verify traffic gets forwarded as per service policy ")
    ##############################################

    acl_dscp_api.config_service_policy_table(data.dut1, interface_name=data.d1tg_vlan_intf, service_policy_name=data.policy_names[0],
                                             policy_kind='bind', policy_type='forwarding')

    result = verify_selected_next_hop(scope='vlan', policy=data.policy_names[0],
                                      flow_list=data.classifier_names[0:64],
                                      nh_list=[data.vlan_ip_list[1]]*data.max_policy_sections,
                                      nh_vrf=[data.access_vrf]*data.max_policy_sections,
                                      interface=data.d1tg_vlan_intf,check_counters=False)
    if not result:
        err = 'Nexthop not selected as per policy map with Scale config after unbind/binding service policy'
        st.report_fail('test_case_failure_message',err)

    if not verify_traffic():
        err = 'Traffic Failed with max policy and classifier configured after unbind/bind service policy'
        st.report_fail('test_case_failure_message',err)

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])

    st.report_pass('test_case_passed')



