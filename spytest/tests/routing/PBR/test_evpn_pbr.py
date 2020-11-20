##############################################################################
# Script Title : PBR Over VxLAN
# Author       : Raghukumar and Nagappa
# Mail-id      : raghukumar.thimmareddy@broadcom.com, nagappa.chincholi@broadcom.com
###############################################################################

import pytest
from spytest import st
from evpn_pbr_vars import data
from evpn_pbr_utils import *
import apis.system.reboot as reboot_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
import apis.switching.mac as mac_api



def initialize_topology_vars():
    global vars
    vars = st.ensure_min_topology("D1D3:3","D1D4:3","D1D5:3","D1D6:3","D2D3:3","D2D4:3","D2D5:3","D2D6:4","D4D7:4","D3T1:2","D6T1:1","D3CHIP=TD3","D4CHIP=TD3","D5CHIP=TD3","D6CHIP=TD3")
    create_glob_vars()
    vars = st.get_testbed_vars()
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped", "Skipping cli mode CLICK")

    data.dut_list = st.get_dut_names()
    data.rtr_list = data.dut_list[0:-1]
    data.leaf_list = data.rtr_list[2:]
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    data.dut5 = data.dut_list[4]
    data.dut6 = data.dut_list[5]
    data.dut7 = data.dut_list[6]

    data.d1d3_ports = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3]
    data.d3d1_ports = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3]
    data.d4d1_ports = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3]
    data.d1d5_ports = [vars.D1D5P1, vars.D1D5P2, vars.D1D5P3]
    data.d5d1_ports = [vars.D5D1P1, vars.D5D1P2, vars.D5D1P3]
    data.d1d6_ports = [vars.D1D6P1, vars.D1D6P2, vars.D1D6P3]
    data.d6d1_ports = [vars.D6D1P1, vars.D6D1P2, vars.D6D1P3]

    data.d2d3_ports = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]
    data.d2d5_ports = [vars.D2D5P1, vars.D2D5P2, vars.D2D5P3]
    data.d5d2_ports = [vars.D5D2P1, vars.D5D2P2, vars.D5D2P3]
    data.d2d6_ports = [vars.D2D6P1, vars.D2D6P2, vars.D2D6P3]
    data.d6d2_ports = [vars.D6D2P1, vars.D6D2P2, vars.D6D2P3]

    data.d3d7_ports = [vars.D3D7P1, vars.D3D7P2, vars.D3D7P3, vars.D3D7P4]
    data.d7d3_ports = [vars.D7D3P1, vars.D7D3P2, vars.D7D3P3, vars.D7D3P4]
    data.d4d7_ports = [vars.D4D7P1, vars.D4D7P2, vars.D4D7P3, vars.D4D7P4]
    data.d7d4_ports = [vars.D7D4P1, vars.D7D4P2, vars.D7D4P3, vars.D7D4P4]

    data.d3d4_ports = [vars.D3D4P1, vars.D3D4P2, vars.D3D4P3]
    data.d4d3_ports = [vars.D4D3P1, vars.D4D3P2, vars.D4D3P3]

    data.d7t1_ports = [vars.D7T1P1, vars.D7T1P2]
    data.d5t1_ports = [vars.D5T1P1, vars.D5T1P2]
    data.d6t1_ports = [vars.D6T1P1, vars.D6T1P2]

    data.t1d7_ports = [vars.T1D7P1, vars.T1D7P2]
    data.t1d5_ports = [vars.T1D5P1, vars.T1D5P2]
    data.t1d6_ports = [vars.T1D6P1, vars.T1D6P2]

    data.d3t1_ports = [vars.D3T1P1, vars.D3T1P2]
    data.d4t1_ports = [vars.D4T1P1, vars.D4T1P2]

    data.policy_list_1 = [data.policy_class_leaf1, data.policy_class_leaf2, data.policy_class_leaf2vni,
                          data.policy_class_leaf3, data.policy_class_leaf4]
    data.interface_list_1 = [data.leaf1_dict["tenant_vlan_int"][0], data.leaf2_dict["tenant_vlan_int"][1], data.vlan_vrf1, data.vlan_vrf1,
                             data.vlan_vrf1]
    data.dut_list_1 = [data.dut3, data.dut4, data.dut4, data.dut5, data.dut6]
    data.dut_list_1 = [data.dut3, data.dut4, data.dut4, data.dut5, data.dut6]
    data.policy_list_2 = [data.policy_class_leaf1, data.policy_class_leaf3, data.policy_class_leaf4]
    data.interface_list_2 = [data.leaf1_dict["tenant_vlan_int"][0], data.vlan_vrf1, data.vlan_vrf1]
    data.dut_list_2 = [data.dut3, data.dut5, data.dut6]
    data.policy_list_3 = [data.policy_class_leaf1, data.policy_class_leaf4]
    data.interface_list_3 = [data.leaf1_dict["tenant_vlan_int"][0], data.vlan_vrf1]
    data.dut_list_3 = [data.dut3, data.dut6]
    data.protocol = ["udp", "tcp"]
    data.class_map_list = []
    data.tech_support_on_fail = True


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    result = evpn_pbr_base_config()
    if result is False:
        st.report_fail("Error in module config -Either VxLAN tunnel status,BGP neighborship or PBR policy is not correct")
    yield
    evpn_pbr_base_unconfig()
        
@pytest.fixture(scope="function")
def cleanup_fixture_01(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for test function 01")
    #######################################


def test_pbr_vxlan_01(cleanup_fixture_01):
    ##tc_list = ['FtOpSoRoPbrvxlan01','FtOpSoRoPbrvxlan02','FtOpSoRoPbrvxlan03']
    err_list = []
    tc_result = True
    # Start traffic streams one by one  (v4)
    # Verify Policy counters on all Leaf nodes
    # Validate the PBR path and counter values for all the streams
    # Verify policy counters are incremented on all leaf node
    # Validate traffic statistcs

    ###################################################################################################
    st.banner("Verify policy configs applied on respectives interfaces on all the leaf nodes")
    ###################################################################################################
    dict_list = []
    policy_list = [data.policy_class_leaf1, data.policy_class_leaf2, data.policy_class_leaf3, data.policy_class_leaf4]
    interface_list = [data.leaf1_dict["tenant_vlan_int"][0], data.leaf2_dict["tenant_vlan_int"][1], data.vlan_vrf1, data.vlan_vrf1]
    dut_list = [data.dut3, data.dut4, data.dut5, data.dut6]
    for policy_name, intf in zip(policy_list, interface_list):
        match = [{'policy_name': policy_name, 'interface': intf}]
        dict_list += [{'policy_name': policy_name, 'verify_list': match}]

    [result1, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut4, data.dut5, data.dut6],
                                                   acl_dscp_api.verify, dict_list)
    match = [{'policy_name': data.policy_class_leaf2vni, 'interface': data.vlan_vrf1}]
    result2 = acl_dscp_api.verify(data.dut4, policy_name=data.policy_class_leaf2vni, verify_list=match)
    if False in [result1, result2]:
        err = 'One or more Policy configs are not applied to interfaces'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
        err_list.append(err)

    stream_list = stream_dict["v4"]
    for streams, protocol in zip(stream_list, data.protocol):
        ###################################################################################################
        st.banner("Clear service policy counters on all the leaf nodes")
        ###################################################################################################
        clear_policy_counters()

        #############################################################################################
        st.banner(
            "Send Traffic matching the access-list {} for {} protocol".format(data.leaf1_leaf2_udp443tcp_acl, protocol))
        ##############################################################################################
        start_traffic(stream_han_list=streams)
        st.wait(5)
        result = verify_traffic()
        if result is False:
            err = 'Traffic is not forwarded using the Class Map {} and Policy Map {}'.format(
                data.class_leaf12_udp443tcp_acl, data.policy_class_leaf1)
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
            err_list.append(err)

        start_traffic(action="stop")

        st.wait(5)
        #############################################################
        st.banner("Verify policy counters on all leaf nodes for the matching the access-list {} ".format(
            data.leaf1_leaf2_udp443tcp_acl))
        #############################################################
        result = verify_policy_counters()
        if result is False:
            err = "Policy counters verfiication failed on one or more Leaf nodes"
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
            err_list.append(err)

    #### For Stream3
    ###################################################################################################
    st.banner("Clear service policy counters on all the leaf nodes")
    ###################################################################################################
    clear_policy_counters()

    ########################################################################
    st.banner("Send Traffic matching the access-list {} ".format(data.leaf1_leaf3_ipprefix20))
    ########################################################################
    start_traffic(stream_han_list=stream_dict["v4_diff"][0])
    st.wait(5)
    result = verify_traffic()
    if result is False:
        err = 'Traffic is not forwarded using the Class Map {} and Policy Map {}'.format(data.class_leaf13_ipprefix20,
                                                                                         data.policy_class_leaf1)
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
        err_list.append(err)

    start_traffic(action="stop")

    #############################################################
    st.banner("Verify policy counters on leaf1, leaf3 and leaf4 nodes for the matching the access-list {} ".format(
        data.leaf1_leaf3_ipprefix20))
    #############################################################
    dict1 = {'policy': data.policy_class_leaf1, 'flow_list': [data.class_leaf13_ipprefix20],
             'interface': data.leaf1_dict["tenant_vlan_int"][0], 'increment': True}
    dict2 = {'policy': data.policy_class_leaf3, 'flow_list': [data.class_leaf3_ip], 'interface': data.vlan_vrf1,
             'increment': True}
    dict3 = {'policy': data.policy_class_leaf4, 'flow_list': [data.class_leaf4_ip], 'interface': data.vlan_vrf1,
             'increment': True}

    [result1, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut5, data.dut6],
                                                   verify_policy_counters_incrementing, [dict1, dict2, dict3])
    if result is False:
        err = "Policy counters verfiication failed on one or more Leaf nodes"
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
        err_list.append(err)

    #### For Stream4
    ###################################################################################################
    st.banner("Clear service policy counters on all the leaf nodes")
    ###################################################################################################
    clear_policy_counters()

    ########################################################################
    st.banner("Send Traffic matching the access-list {} ".format(data.leaf1_leaf4))
    ########################################################################
    start_traffic(stream_han_list=stream_dict["v4_diff"][1])
    st.wait(5)
    result = verify_traffic()
    if result is False:
        err = 'Traffic is not forwarded using the Class Map {} and Policy Map {}'.format(data.class_leaf14,
                                                                                         data.policy_class_leaf1)
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
        err_list.append(err)

    start_traffic(action="stop")

    #############################################################
    st.banner(
        "Verify policy counters on leaf1 and leaf4 nodes for the matching the access-list {} ".format(data.leaf1_leaf4))
    #############################################################
    dict1 = {'policy': data.policy_class_leaf1, 'flow_list': [data.class_leaf14],
             'interface': data.leaf1_dict["tenant_vlan_int"][0], 'increment': True}
    dict2 = {'policy': data.policy_class_leaf4, 'flow_list': [data.class_leaf4_ip], 'interface': data.vlan_vrf1,
             'increment': True}

    [result1, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut6], verify_policy_counters_incrementing,
                                                   [dict1, dict2])
    if result1 is False:
        err = "Policy counters verfiication failed on one or more Leaf nodes"
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_01')
        err_list.append(err)

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def cleanup_fixture_02(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for test function 02")
    #######################################


def test_pbr_vxlan_02(cleanup_fixture_02):
    tc_list = ['FtOpSoRoPbrvxlan04','FtOpSoRoPbrvxlan05','FtOpSoRoPbrvxlan06']
    err_list = []
    tc_result = True
    # Start traffic streams one by one  (v6)
    # Verify Policy counters on all Leaf nodes
    # Validate the PBR path and counter values for all the streams
    # Verify policy counters are incremented on all leaf node
    # Validate traffic statistcs

    stream_list = stream_dict["v6"]
    data.protocol = ['udp', 'tcp', 'udp']
    for streams, protocol in zip(stream_list, data.protocol):
        ###################################################################################################
        st.banner("Clear service policy counters on all the leaf nodes")
        ###################################################################################################
        clear_policy_counters()

        #############################################################################################
        st.banner("Send Traffic matching the access-list {} for {} protocol".format(data.leaf1_leaf2_udp443tcp_aclv6,
                                                                                    protocol))
        ##############################################################################################
        start_traffic(stream_han_list=streams)
        st.wait(5)
        result = verify_traffic()
        if result is False:
            err = 'Traffic is not forwarded using the Class Map {} and Policy Map {}'.format(
                data.class_leaf12_udp443tcp_aclv6, data.policy_class_leaf1)
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_02')
            err_list.append(err)

        start_traffic(action="stop")

        st.wait(5)
        #############################################################
        st.banner("Verify policy counters on all leaf nodes for the matching the access-list {} ".format(
            data.leaf1_leaf2_udp443tcp_aclv6))
        #############################################################
        dict1 = {'policy': data.policy_class_leaf1, 'flow_list': [data.class_leaf12_udp443tcp_aclv6],
                 'interface': data.leaf1_dict["tenant_vlan_int"][0], 'increment': True}
        dict2 = {'policy': data.policy_class_leaf2, 'flow_list': [data.class_leaf24_ipv6any_acl],
                 'interface': data.leaf2_dict["tenant_vlan_int"][1], 'increment': True}
        dict3 = {'policy': data.policy_class_leaf4, 'flow_list': [data.class_leaf4_ipv6], 'interface': data.vlan_vrf1,
                 'increment': True}

        [result1, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut4, data.dut6],
                                                       verify_policy_counters_incrementing, [dict1, dict2, dict3])
        result2 = verify_policy_counters_incrementing(data.dut4, data.policy_class_leaf2vni,
                                                      flow_list=[data.class_leafvniaclv6], interface=data.vlan_vrf1,
                                                      increment=True)
        if False in [result1, result2]:
            err = "Policy counters verfiication failed on one or more Leaf nodes"
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_02')
            err_list.append(err)

            ###
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')
    
    
@pytest.fixture(scope="function")
def cleanup_fixture_04(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for test function 04")
    #######################################
    st.banner("bind PBR rules on Leaf1 node")
    acl_dscp_api.config_service_policy_table(data.dut3, service_policy_name=data.policy_class_leaf1,policy_kind='bind', policy_type='forwarding',interface_name=data.leaf1_dict["tenant_vlan_int"][0])   
    
    start_traffic(action="stop")
        
def test_pbr_vxlan_04(cleanup_fixture_04):
    tc_list = ['FtOpSoRoPbrvxlan07']
    err_list = []
    tc_result = True
    # Start traffic streams for both (v4v6)
    # Verify Policy counters on all Leaf nodes (with PBR rules)
    # Remove/Unbind PBR rules on Leaf1 node
    # Validate traffic statistcs end to end
    
    ###################################################################################################
    st.banner("Clear service policy counters on all the leaf nodes")
    ###################################################################################################
    clear_policy_counters()

    ########################################################################
    st.banner("Send Traffic for all the streams")
    ########################################################################
    start_traffic(stream_dict["all"])
    st.wait(10)
    result = verify_policy_counters()
    if result is False:
        err = "Policy counters were not incremented as expected on one or more Leaf nodes."
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_04')
        err_list.append(err)
    
    start_traffic(action="stop")
    clear_policy_counters()
    ########################################################################
    st.banner("Unbind PBR rules on Leaf1 node")
    ########################################################################        
    acl_dscp_api.config_service_policy_table(data.dut3, service_policy_name=data.policy_class_leaf1,policy_kind='unbind', policy_type='forwarding',interface_name=data.leaf1_dict["tenant_vlan_int"][0])    
    
    start_traffic(stream_dict["all"])
    st.wait(5)
    result = verify_traffic()   
    if result is False:
        err = "Traffic is not forwarded using routes in leaf1 node"
        tc_result = False;
        err_list.append(err)
    
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')
            

@pytest.fixture(scope="function")
def cleanup_fixture_05(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for test function 05")
    #######################################
    ip_api.delete_static_route(data.dut3, next_hop= data.leaf1_dict["tenant_v4_ip"][3], static_ip= data.route_list[2],vrf =data.vrf1)
    ip_api.delete_static_route(data.dut3, next_hop= data.leaf1_dict["tenant_ipv6_list"][4], static_ip= data.route_list_6[3],family = 'ipv6',vrf =data.vrf1)
    vlan_api.delete_vlan_member(data.dut3,data.leaf1_dict['tenant_vlan_list'][3],data.d3t1_ports[1],True)
    vlan_api.add_vlan_member(data.dut3,data.leaf1_dict['tenant_vlan_list'][3],data.d3t1_ports[0],True)    
        
def test_pbr_vxlan_05(cleanup_fixture_05):
    tc_list = ['FtOpSoRoPbrvxlan08']
    err_list = []
    tc_result = True
    # Start traffic -default route streams for IPv4 and IPv6
    # Verify Policy counters on all Leaf nodes
    # Validate traffic statistcs end to end
    
    ############################################################################
    vlan_api.delete_vlan_member(data.dut3,data.leaf1_dict['tenant_vlan_list'][3],data.d3t1_ports[0],True)
    vlan_api.add_vlan_member(data.dut3,data.leaf1_dict['tenant_vlan_list'][3],data.d3t1_ports[1],True)
    #ip_api.config_ip_addr_interface(data.dut3, leaf1_dict['tenant_vlan_int'][3], leaf1_dict['tenant_ip_list'][3], mask_24)
    #ip_api.config_ip_addr_interface(data.dut3, leaf1_dict['tenant_vlan_int'][3], leaf1_dict['tenant_ipv6_list'][3], mask_v6, family='ipv6')
    arp.add_static_arp(data.dut3, data.leaf1_dict["tenant_v4_ip"][3], data.tg_dest_mac_list[3], interface=data.leaf1_dict["tenant_vlan_int"][3])
    mac_api.config_mac(data.dut3,mac=data.tg_dest_mac_list[3],vlan=data.leaf1_dict["tenant_vlan_list"][3],intf=data.d3t1_ports[1])
    arp.config_static_ndp(data.dut3,data.leaf1_dict["tenant_ipv6_list"][4], data.tg_dest_mac_list[3],interface=data.leaf1_dict["tenant_vlan_int"][3])
    mac_api.config_mac(data.dut3,data.tg_dest_mac_list[3],data.leaf1_dict["tenant_vlan_list"][3],data.d3t1_ports[1])        
    ip_api.create_static_route(data.dut3, next_hop= data.leaf1_dict["tenant_v4_ip"][3], static_ip= data.route_list[2],vrf =data.vrf1)
    ip_api.create_static_route(data.dut3, next_hop= data.leaf1_dict["tenant_ipv6_list"][4], static_ip= data.route_list_6[3],family = 'ipv6',vrf =data.vrf1)
    
    ###################################################################################################
    st.banner("Clear service policy counters on all the leaf nodes")
    ###################################################################################################
    clear_policy_counters()

    ########################################################################
    st.banner("Send Traffic for default route  streams")
    ########################################################################
    start_traffic(stream_dict["difaultRoute"])
    st.wait(10)
    result = verify_policy_counters()
    if result is True:
        err = "Policy counters were incremented on one or more Leaf nodes."
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_05')
        err_list.append(err)
        
    result =verify_traffic(tx_port=tg_dict['d3_tg_port1'], rx_port=tg_dict['d3_tg_port2'])          
    if result is False:
        err = 'Traffic is not forwarded using the default route in the routing table'
        tc_result = False;err_list.append(err);st.generate_tech_support(dut=None,name='test_pbr_vxlan_05')
                
    start_traffic(action="stop")
    
    
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')
    
@pytest.fixture(scope="function")
def cleanup_fixture_03(request, prologue_epilogue):
    yield
    vlan_api.add_vlan_member(data.dut4, data.client_dict["tenant_vlan_list"][0], data.po_leaf2, True)
    start_traffic(action="stop")


def test_pbr_vxlan_triggers(cleanup_fixture_03):
    tc_list = ['FtOpSoRoPbrvxlan09','FtOpSoRoPbrvxlan10','FtOpSoRoPbrvxlan11','FtOpSoRoPbrvxlan12','FtOpSoRoPbrvxlan13','FtOpSoRoPbrvxlan14','FtOpSoRoPbrvxlan15']
    trigger_list = ['fast_reboot','reboot_spine','warm_boot','bgp_docker','clear_bgp','config_reload','ip_unreachable']

    tc_result=True;err_list=[];tech_support=data.tech_support_on_fail

    
    ###################################################################################################
    # Start traffic streams with Leaf2 as next hop over tunnel
    # Verify Policy counters on Leaf2
    # Bring down Leaf2 IP reachability by removing vlan membership from ports
    # Clear policy counters on Leaf2 , Leaf3
    # Verify policy counters are not incremented on Leaf2
    # Poicy counters on Leaf3 are incremented
    # Validate traffic statistcs

    ###################################################################################################
    st.banner("Start traffic streams with Leaf2 as next hop over tunnel.")
    ###################################################################################################
    start_traffic(stream_dict["all"])
    st.wait(10)
    result = verify_policy_counters()
    if result is False:
        err = "Policy counters were not incremented as expected on one or more Leaf nodes."
        tc_result = False;
        err_list.append(err)
    clear_policy_counters()

    # Bring down Leaf2 IP address reachability
    reboot_api.config_save(data.dut4)
    reboot_api.config_save(data.dut2)

    ##########################################
    st.banner("## Step - Trigger fast reboot ##")
    ##########################################
    # Verify policy counters are not incremented on Leaf2 and increment on other leaf nodes
    def leaf1():
        dut = data.dut3
        policy = data.policy_class_leaf1
        intf = data.leaf1_dict["tenant_vlan_int"][0]
        flow_list = data.class_leaf12_udp443tcp_acl
        incr_flag = True
        return verify_policy_counters_incrementing(dut, policy, [flow_list], intf, incr_flag)
    def leaf2():
        dut = data.dut4
        policy = data.policy_class_leaf2
        intf = data.vlan_vrf1
        flow_list = data.class_leaf23_ipany_acl
        incr_flag = True
        return verify_policy_counters_incrementing(dut, policy, [flow_list], intf, incr_flag)

    def leaf3():
        dut = data.dut5
        policy = data.policy_class_leaf3
        intf = data.vlan_vrf1
        flow_list = data.class_leaf3_ip
        incr_flag = True
        return verify_policy_counters_incrementing(dut, policy, [flow_list], intf, incr_flag)

    def leaf4():
        dut = data.dut6
        policy = data.policy_class_leaf4
        intf = data.vlan_vrf1
        flow_list = data.class_leaf4_ip
        incr_flag = True
        return verify_policy_counters_incrementing(dut, policy, [flow_list], intf, incr_flag)

    tc = '' ; err = ''
    for trigger,tc in zip(trigger_list,tc_list):
        if trigger == 'clear_bgp':
            ##########################################
            st.banner("## Step - Trigger clear bgp ##")
            ##########################################
            bgp_api.clear_ip_bgp_vtysh(data.dut3)
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])
        elif trigger == 'fast_reboot':
            ##########################################
            st.banner("## Step - Trigger fast reboot Leaf2 ##")
            ##########################################
            st.reboot(data.dut4, "fast")
            st.wait(20)
            #[res, exceptions] = st.exec_all([[leaf1], [leaf3], [leaf4]])
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])

        elif trigger == 'reboot_spine':
            ##########################################
            st.banner("## Step - Reboot spine2 ##")
            ##########################################
            reboot_api.config_save(data.dut2)
            st.reboot(data.dut2, "fast")
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])
        elif trigger == 'warm_boot':
            ##########################################
            st.banner("## Step - Trigger warm reboot ##")
            ##########################################
            reboot_api.config_warm_restart(data.dut4,oper = "enable", tasks = ["system", "bgp"])
            st.reboot(data.dut4, 'warm')
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])
        elif trigger == 'config_reload':
            ##########################################
            st.banner("## Step - Trigger Config Reload ##")
            ##########################################
            reboot_api.config_reload(data.dut4)
            #st.reboot(data.dut4, 'warm')
            st.wait(10)
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])
        elif trigger == 'bgp_docker':
            ##########################################
            st.banner("## Step - Trigger bgp docker restart ##")
            ##########################################
            basic_api.service_operations_by_systemctl(data.dut4, "bgp", "restart")
            st.wait(2)
            result = utils_obj.retry_api(basic_api.get_system_status, data.dut4, service = 'bgp', retry_count=20, delay=2)
            if result is False:
                err = "Policy counters verfiication failed after bgp docker restart"
                st.report_fail('test_case_failure_message', err)
            [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])

        elif trigger == 'ip_unreachable':
            ##########################################
            st.banner("## Step - Trigger Bring down next hop on Leaf2 ##")
            ##########################################
            vlan_api.delete_vlan_member(data.dut4, data.client_dict["tenant_vlan_list"][0], data.po_leaf2, True)
            [res, exceptions] = st.exec_all([[leaf1], [leaf3], [leaf4]])
            #[res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])

        if False in set(res):
            err = "Policy counters verfiication failed on one or more Leaf nodes after {}.".format(trigger)
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_triggers')
            err_list.append(err)

        # Verify traffic stats
        if not verify_traffic(tx_port=tg_dict['d3_tg_port1'], rx_port=tg_dict['d6_tg_port1']):
            err = "Traffic validation failed after trigger {}.".format(trigger)
            tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_triggers')
            err_list.append(err)
        if tc_result is False:
            err ='Testcase failed after trigger {}'.format(trigger)
            st.report_fail('test_case_failure_message',err)
        else:
            st.report_tc_pass(tc,'tc_passed')

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')
    
@pytest.fixture(scope="function")            
def cleanup_fixture_host_move(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for Host move testcase")
    #######################################
    acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                          policy_type='forwarding',
                                          class_name=data.class_leaf12_udp443tcp_acl, flow_priority=10,
                                          priority_option='next-hop',
                                          next_hop=[data.leaf2_dict['tenant_v4_ip'][2]],
                                          next_hop_priority=[3000])

    acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                          policy_type='forwarding',
                                          class_name=data.class_leaf12_udp443tcp_aclv6, flow_priority=10,
                                          priority_option='next-hop',
                                          next_hop=[data.leaf2_dict['tenant_v6_ip'][2]],
                                          next_hop_priority=[3000], version='ipv6')
                                              
                                                  
    vlan_api.add_vlan_member(data.dut4, data.client_dict["tenant_vlan_list"][2], data.po_leaf2, True)
    start_traffic(action="stop")

def test_pbr_vtep_host_move(cleanup_fixture_host_move):
    tc_list = ['FtOpSoRoPbrvxlan16']
    tc_result=True;err_list=[];tech_support=data.tech_support_on_fail

    ###################################################################################################
    st.banner("Verify traffic from Leaf1 is forwarded directly to Leaf3 when Leaf2 next hop is unreachable")
    ###################################################################################################
    # Configure SAG on Vlan210 on Leaf2 and Leaf3
    # Configure PBR next hop as IP of host-A connected to Leaf2
    # Verify Policy counters on Leaf2
    # Bring down host-A connectivity from Leaf2 by removing vlan membership on client
    # Configure host-A on Tgen connected to Leaf3
    # Verify policy counters are not incremented on Leaf2 and Leaf3
    # Poicy counters on Leaf3 are incremented and on Leaf2 not incremented
    # Validate traffic statistics
    acl_dscp_api.config_flow_update_table(data.dut3, flow='add', policy_name=data.policy_class_leaf1,
                                          policy_type='forwarding',
                                          class_name=data.class_leaf12_udp443tcp_acl, flow_priority=10,
                                          priority_option='next-hop',
                                          next_hop=[data.leaf2_dict['tenant_v4_ip'][2]],
                                          next_hop_priority=[3000])

    acl_dscp_api.config_flow_update_table(data.dut3, flow='add', policy_name=data.policy_class_leaf1,
                                          policy_type='forwarding',
                                          class_name=data.class_leaf12_udp443tcp_aclv6, flow_priority=10,
                                          priority_option='next-hop',
                                          next_hop=[data.leaf2_dict['tenant_v6_ip'][2]],
                                          next_hop_priority=[3000], version='ipv6')

    ###################################################################################################
    st.banner("Start traffic streams with Leaf2 as next hop over tunnel.")
    ###################################################################################################
    start_traffic(stream_dict["all"])
    st.wait(10)
    result = verify_policy_counters()
    if result is False:
        err = "Policy counters were not incremented as expected on one or more Leaf nodes."
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vtep_host_move')
        err_list.append(err)

    ###################################################################################################
    st.banner("Initiate host move from Leaf2 to Leaf3.")
    ###################################################################################################

    vlan_api.delete_vlan_member(data.dut4, data.client_dict["tenant_vlan_list"][2], data.po_leaf2, True)
    tg_dict["tg"].tg_arp_control(handle=stream_dict["hosts"][0], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["hosts"][1], arp_target='all')

    # Verify ARP and ND table after host move
    result = verify_policy_counters()
    if result is False:
        err = "Policy counters were not incremented as expected on one or more Leaf nodes."
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vtep_host_move')
        err_list.append(err)

    if not verify_traffic(tx_port=tg_dict['d3_tg_port1'], rx_port=tg_dict['d6_tg_port1']):
        err = "Traffic validation failed after host move."
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vtep_host_move')
        err_list.append(err)

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')
    
@pytest.fixture(scope="function")
def cleanup_fixture_06(request, prologue_epilogue):
    yield
    #######################################
    st.banner("ClEANUP....Starts for test function 06")
    #######################################
    

def test_pbr_vxlan_06(cleanup_fixture_06):
    tc_list = ['FtOpSoRoPbrvxlan18','FtOpSoRoPbrvxlan19','FtOpSoRoPbrvxlan20']
    err_list = []
    tc_result = True
    # Extend Vlan110 accross vtep
    # Start traffic from Leaf1 and stop
    # Verify vxlan evpn remote mac on Leaf2, Leaf3 and Leaf4
    # Start traffic from Leaf3 and Stop, Verify vxlan evpn remote mac on Leaf1, Leaf2 and Leaf4
    # Again start traffic from Leaf1 and stop, Verify vxlan evpn remote mac on Leaf2, Leaf3 and Leaf4
    # Again start traffic from Leaf3 and Verify vxlan evpn remote mac on Leaf1, Leaf2 and Leaf4
    # Validate MAC Dampening move after this step
    
    st.banner("Verification of Mac move across vxlan tunnel and  MAC Dampening move")   
    ###################################################################################################
    vlan =data.leaf1_dict["tenant_vlan_list"][0]
    data.mac_remote ="00:01:01:00:00:01"
    def leaf1():
        dut = data.dut3
        vtep_name = data.vtep_names[0]
        evpn.config_bgp_evpn(dut, local_as=data.dut3_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='max-moves 2 time 300')
        evpn.config_bgp_evpn(dut, local_as=data.dut3_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='freeze 120')        
        
    def leaf2():
        dut = data.dut4
        vtep_name = data.vtep_names[1]
        vlan_api.create_vlan(dut, vlan)
        vlan_api.add_vlan_member(dut,vlan,[data.d4t1_ports[0]],True)
        evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
    
    def leaf3():
        dut = data.dut5
        vtep_name = data.vtep_names[2]
        vlan_api.create_vlan(dut, vlan)
        vlan_api.add_vlan_member(dut,vlan,[data.d5t1_ports[0]],True)
        evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
        evpn.config_bgp_evpn(dut, local_as=data.dut5_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='max-moves 2 time 300')
        evpn.config_bgp_evpn(dut, local_as=data.dut5_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='freeze 120')        
        
    def leaf4():
        dut = data.dut6
        vtep_name = data.vtep_names[3]
        vlan_api.create_vlan(dut, vlan)
        vlan_api.add_vlan_member(dut,vlan,[data.d6t1_ports[0]],True)
        evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)       
    
    [res, exceptions] = st.exec_all([[leaf1],[leaf2], [leaf3], [leaf4]])
        
    data.dut5_gw_mac = basic_api.get_ifconfig(data.dut5, data.leaf1_dict["tenant_vlan_int"][0])[0]['mac']
    #######################################################
    st.banner("Create L3 stream on Leaf3 connected TG")
    #######################################################   
    stream = tg_dict["tg"].tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut5_gw_mac, rate_pps=1000, mode='create', port_handle=tg_dict['d5_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous', 
                                  ip_src_addr=data.leaf3_dict["tenant_v4_ip"],
                                  ip_dst_addr=data.leaf4_dict["tenant_v4_ip"], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf3_dict["tenant_ip_list"][0])
    stream10 = stream['stream_id']
    st.log("Ipv4 {} is created for Tgen port {}".format(stream10, vars.T1D5P1))
    stream_dict["leaf3"] =[stream10]        
    
    ###########################################################    
    st.banner("Step01:Start traffic on leaf1 for Vlan110")
    ###########################################################
    start_traffic(stream_han_list=stream_dict["v4"][0])
    st.wait(5)
    start_traffic(action="stop")
    
    st.banner("Verify vxlan evpn remote mac on Leaf2 ")
    result = evpn.verify_vxlan_evpn_remote_mac_id(dut=data.dut4, vni=data.leaf1_dict["tenant_vlan_list"][0],
                vlan=data.leaf1_dict["tenant_vlan_int"][0],
                rvtep=data.loopback2_ip_list[2], type="dynamic",
                identifier=data.loopback2_ip_list[2], mac =data.mac_remote)             
    
    if result is False:    
        err = 'MACs from leaf1 not learned successfully in leaf2'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    ########################################################    
    st.banner("Step02:Start traffic on leaf3 for Vlan110")
    ########################################################
    start_traffic(stream_han_list=stream_dict["leaf3"][0])
    st.wait(5)
    start_traffic(action="stop")
    
    st.banner("Verify vxlan evpn remote mac on Leaf2 ")    
    result = evpn.verify_vxlan_evpn_remote_mac_id(dut=data.dut4, vni=data.leaf1_dict["tenant_vlan_list"][0],
                vlan=data.leaf1_dict["tenant_vlan_int"][0],
                rvtep=data.loopback2_ip_list[4], type="dynamic",
                identifier=data.loopback2_ip_list[4], mac =data.mac_remote)             
    
    if result is False:    
        err = 'MACs from leaf3 not learned successfully in leaf2'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    ##############################################################  
    st.banner("Step03:Start traffic on leaf1 for Vlan110")
    ##############################################################
    start_traffic(stream_han_list=stream_dict["v4"][0])
    st.wait(5)
    start_traffic(action="stop")
    
    st.banner("Verify vxlan evpn remote mac on Leaf2")        
    result = evpn.verify_vxlan_evpn_remote_mac_id(dut=data.dut4, vni=data.leaf1_dict["tenant_vlan_list"][0],
                vlan=data.leaf1_dict["tenant_vlan_int"][0],
                rvtep=data.loopback2_ip_list[2], type="dynamic",
                identifier=data.loopback2_ip_list[2], mac =data.mac_remote)             
    
    if result is False:    
        err = 'MACs from leaf1 not learned successfully in leaf2'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    ####################################################### 
    st.banner("Step04:Start traffic on leaf3 for Vlan110")
    #######################################################
    start_traffic(stream_han_list=stream_dict["leaf3"][0])
    st.wait(5)
    start_traffic(action="stop")
    
    st.banner("Verify vxlan evpn remote mac on Leaf2")
    result = evpn.verify_vxlan_evpn_remote_mac_id(dut=data.dut4, vni=data.leaf1_dict["tenant_vlan_list"][0],
                vlan=data.leaf1_dict["tenant_vlan_int"][0],
                rvtep=data.loopback2_ip_list[4], type="dynamic",
                identifier=data.loopback2_ip_list[4], mac =data.mac_remote)             
    
    if result is True:    
        err = 'MACs from leaf3 learned successfully in leaf2- MAC Dampening Failed'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    ###############################################################
    st.banner("Wait for 120 sec for MAC freeze time to be over -The mac disabeled ports are enabled again")
    ###############################################################
    st.wait(120)
    st.banner("Verify vxlan evpn remote mac on Leaf3")
    result = evpn.verify_vxlan_evpn_remote_mac_id(dut=data.dut5, vni=data.leaf1_dict["tenant_vlan_list"][0],
                vlan=data.leaf1_dict["tenant_vlan_int"][0],
                rvtep=data.loopback2_ip_list[2], type="dynamic",
                identifier=data.loopback2_ip_list[2], mac =data.mac_remote)
    
    if result is False:    
        err = 'MAC from Leaf1 not learned on leaf3 after freeze time of 120 sec is over'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    ##################################################################################
    st.banner("Step05:Remove duplicate address-detection and config MAC dampening threshold,interval on both leaf1 and leaf3")
    ##################################################################################
    def leaf1():
        dut = data.dut3
        evpn.config_bgp_evpn(dut, local_as=data.dut3_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='max-moves 2 time 300',config='no')
        evpn.config_bgp_evpn(dut, local_as=data.dut3_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='freeze 120',config='no')
        mac_api.configure_macmove_threshold(dut,count=5)
        mac_api.configure_macmove_threshold(dut,interval=20,cli_type='click')
        
    def leaf3():
        dut = data.dut5
        evpn.config_bgp_evpn(dut, local_as=data.dut5_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='max-moves 2 time 300',config='no')
        evpn.config_bgp_evpn(dut, local_as=data.dut5_AS,config_type_list =["dup_addr_detection"],dup_addr_detection='freeze 120',config='no')    
        mac_api.configure_macmove_threshold(dut,count=5)
        mac_api.configure_macmove_threshold(dut,interval=20,cli_type='click')
        
    [res, exceptions] = st.exec_all([[leaf1],[leaf3]])
    
    stream_dict["MAC-Dampening"] =[stream_dict["v4"][0],stream_dict["leaf3"][0]]
    ####################################################### 
    st.banner("Step06:Start traffic on both leaf1 and leaf3")
    #######################################################
    start_traffic(stream_han_list=stream_dict["MAC-Dampening"]) 
    
    st.wait(60)
    ############################################################################### 
    st.banner("Step07:Verify MAC Dampening disabled ports on both the leaf nodes")
    ###############################################################################  
    result1 = mac_api.verify_mac_dampening_disabled_ports(data.dut3, port_list = [data.d3t1_ports[0]])  
    result2 = mac_api.verify_mac_dampening_disabled_ports(data.dut5, port_list = [data.d5t1_ports[0]])
    
    if False in [result1,result2]:
        err = 'MAC Dampening Failed - Ports are not disabled for MAC learning'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)
    
    start_traffic(action="stop")
    ##############################################################################
    st.banner("clear mac dampening disabled ports ")
    ##############################################################################
    mac_api.clear_mac_dampening(data.dut3)
    mac_api.clear_mac_dampening(data.dut5)
    
    ############################################################################### 
    st.banner("Step08:Verify MAC Dampening disabled ports on both the leaf nodes")
    ###############################################################################  
    result1 = mac_api.verify_mac_dampening_disabled_ports(data.dut3, port_list = [data.d3t1_ports[0]])  
    result2 = mac_api.verify_mac_dampening_disabled_ports(data.dut5, port_list = [data.d5t1_ports[0]])
    
    if True in [result1,result2]:
        err = 'MAC Dampening Failed- Disabled ports are not cleared'
        tc_result = False;st.generate_tech_support(dut=None,name='test_pbr_vxlan_06')
        err_list.append(err)        
        
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')         
        
        
def verify_policy_counters():
    #################################################################
    #################################################################
    dict1 = {'policy': data.policy_class_leaf1, 'flow_list': [data.class_leaf12_udp443tcp_acl],
             'interface': data.leaf1_dict["tenant_vlan_int"][0], 'increment': True}
    dict2 = {'policy': data.policy_class_leaf2, 'flow_list': [data.class_leaf23_ipany_acl],
             'interface': data.leaf2_dict["tenant_vlan_int"][1], 'increment': True}
    dict3 = {'policy': data.policy_class_leaf3, 'flow_list': [data.class_leaf3_ip], 'interface': data.vlan_vrf1,
             'increment': True}
    dict4 = {'policy': data.policy_class_leaf4, 'flow_list': [data.class_leaf4_ip], 'interface': data.vlan_vrf1,
             'increment': True}

    [result1, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut4, data.dut5, data.dut6],
                                                   verify_policy_counters_incrementing, [dict1, dict2, dict3, dict4])
    result2 = verify_policy_counters_incrementing(data.dut4, data.policy_class_leaf2vni,
                                                  flow_list=[data.class_leafvniacl], interface=data.vlan_vrf1,
                                                  increment=True)
    if False in [result1, result2]:
        st.error("Policy counters not incremented for flows matching acl rules")
        return False

    return True
    
    
def clear_policy_counters():
    ############################################
    for policy_name, intf, dut in zip(data.policy_list_1, data.interface_list_1, data.dut_list_1):
        acl_dscp_api.config_service_policy_table(dut, policy_kind='clear_policy', service_policy_name=policy_name)

    
    
