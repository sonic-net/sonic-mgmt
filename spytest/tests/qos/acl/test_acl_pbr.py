import pytest
from spytest import st, tgapi

from apis.system import port
import apis.qos.acl as acl_obj
import apis.routing.ip as ipfeature
import apis.switching.mac as mapi
import apis.routing.arp as arp_obj

@pytest.fixture(scope="module", autouse=True)
def common_config(request):
    global dut1, r1_tg_ports1, r1_tg_ports2
    global tg_r1_hw_port1, tg_r1_hw_port2
    global tg1, tg2, tg_dut1_p1_handle, tg_dut1_p2_handle
    global r1tg1_1_ipAddr, r1tg2_1_ipAddr
    global nextHop_ip, nextHop_ipv6
    global static_macAdd
    global r1tg1_1_ipv6Addr, r1tg2_1_ipv6Addr
    global subnetMask, subnetMaskv6
    global Vlan, maskACL
    global acl_table_name, acl_table_namev6
    global description, descriptionv6
    global type, typev6
    global stage, expCount, pktrate, pktAction
    global srpIP, dstIP, srpIPv6, dstIPv6
    global rule_list, priority_list
    vars = st.ensure_min_topology("D1T1:2")
    dut1 = vars.D1
    r1_tg_ports1 = vars.D1T1P1
    r1_tg_ports2 = vars.D1T1P2
    tg_r1_hw_port1 = vars.T1D1P1
    tg_r1_hw_port2 = vars.T1D1P2
    tg1, tg_dut1_p1_handle = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_dut1_p2_handle = tgapi.get_handle_byname("T1D1P2")
    r1tg1_1_ipAddr  = '30.30.30.1'
    r1tg2_1_ipAddr  = '20.20.20.1'
    nextHop_ip  = '20.20.20.100'
    nextHop_ipv6  = '3001::100'
    static_macAdd ='00:0a:01:00:11:02'
    r1tg1_1_ipv6Addr  = '2001::10'
    r1tg2_1_ipv6Addr  = '3001::10'
    subnetMask  = '24'
    subnetMaskv6  = '64'
    Vlan ='100'
    maskACL = '32'
    acl_table_name = 'ACL0'
    acl_table_namev6 = 'ACL1'
    description = 'IPv4_ACL_redirect_port'
    descriptionv6 = 'IPv6_ACL_redirect_port'
    type = 'L3'
    typev6 = 'L3V6'
    stage = 'INGRESS'
    expCount = '1000'
    pktrate = '1000'
    pktAction ='redirect:'
    srpIP ='1.1.1.3'
    dstIP ='3.3.3.1'
    srpIPv6 ='1234::1'
    dstIPv6 ='5001::1'
    rule_list =['rule_1', 'rule_2', 'rule_3', 'rule_4', 'rule_5', 'rule_6', 'rule_7', 'rule_8','rule_9','rule_10']
    priority_list =['10', '9', '8', '7', '6', '5', '4', '3', '2', '1']

    st.log("Bring Up the required topology for the test to run")
    port.noshutdown(dut1, [r1_tg_ports1,r1_tg_ports2])
    ipfeature.config_ip_addr_interface(dut1, interface_name=r1_tg_ports1, ip_address=r1tg1_1_ipAddr, subnet=subnetMask, family="ipv4")
    ipfeature.config_ip_addr_interface(dut1, interface_name=r1_tg_ports2, ip_address=r1tg2_1_ipAddr, subnet=subnetMask, family="ipv4")
    ipfeature.config_ip_addr_interface(dut1, interface_name=r1_tg_ports1, ip_address=r1tg1_1_ipv6Addr, subnet=subnetMaskv6, family="ipv6")
    ipfeature.config_ip_addr_interface(dut1, interface_name=r1_tg_ports2, ip_address=r1tg2_1_ipv6Addr, subnet=subnetMaskv6, family="ipv6")

    st.log("Create static arp on dut1")
    arp_obj.add_static_arp(dut1, nextHop_ip, static_macAdd)
    st.log("Create static ndp on dut1")
    arp_obj.config_static_ndp(dut1, nextHop_ipv6, static_macAdd,r1_tg_ports2)

    st.log("Get the device MAC- dut1")
    routing_mac = mapi.get_sbin_intf_mac(dut1, r1_tg_ports1)

    st.log("Create host on the Traffic generator")
    create_trafficStreams(tg1, tg2, tg_dut1_p1_handle, tg_dut1_p2_handle,rate=pktrate, rule='forward',dstMAC =routing_mac)

    yield
    # add things at the end of this module"
    arp_obj.delete_static_arp(dut1, nextHop_ip, static_macAdd)
    arp_obj.clear_ndp_table(dut1)
    st.log("Delete  interface config on dut1")
    ipfeature.delete_ip_interface(dut1, interface_name=r1_tg_ports1, ip_address=r1tg1_1_ipAddr, subnet=subnetMask, family="ipv4")
    ipfeature.delete_ip_interface(dut1, interface_name=r1_tg_ports2, ip_address=r1tg2_1_ipAddr, subnet=subnetMask, family="ipv4")
    ipfeature.delete_ip_interface(dut1, interface_name=r1_tg_ports1, ip_address=r1tg1_1_ipv6Addr, subnet=subnetMaskv6, family="ipv6")
    ipfeature.delete_ip_interface(dut1, interface_name=r1_tg_ports2, ip_address=r1tg2_1_ipv6Addr, subnet=subnetMaskv6, family="ipv6")
    port.shutdown(dut1, [r1_tg_ports1,r1_tg_ports2])


@pytest.fixture(scope="function", autouse=True)
def common_func_hooks(request):
    #########
    global vars
    vars = st.get_testbed_vars()
    yield
    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

def test_fuctPBR_01():
    global vars
    vars = st.get_testbed_vars()
    final_result = True

    st.log('This test covers StSoSeConf014 StSoSeConf015 StSoSeVer014 StSoSeVer015')
    st.log('creating IPv4 ACL table and binding to the ports in Ingress direction')
    acl_obj.create_acl_table(dut1, name=acl_table_name, stage=stage, type=type,description=description, ports=[r1_tg_ports1])
    acl_obj.create_acl_table(dut1, name=acl_table_namev6, stage=stage, type=typev6,description=descriptionv6, ports=[r1_tg_ports1])

    st.log('Creating ACL rules with src_ip dst_ip port  and action as forward drop')
    acl_obj.create_acl_rule(dut1, table_name=acl_table_name, rule_name=rule_list[0],priority=priority_list[0], packet_action=pktAction+r1_tg_ports2, SRC_IP="{}/{}".format(srpIP, maskACL),DST_IP="{}/{}".format(dstIP, maskACL))
    acl_obj.create_acl_rule(dut1, table_name=acl_table_name, rule_name=rule_list[9],priority=priority_list[9],packet_action='drop', IP_TYPE='ipv4any')
    acl_obj.create_acl_rule(dut1, table_name=acl_table_namev6, rule_name=rule_list[0],priority=priority_list[0],packet_action=pktAction+r1_tg_ports2, SRC_IPV6="{}/{}".format(srpIPv6, '128'),DST_IPV6="{}/{}".format(dstIPv6, '128'))
    acl_obj.create_acl_rule(dut1, table_name=acl_table_namev6, rule_name=rule_list[9],priority=priority_list[9],packet_action='drop', IP_TYPE='ipv6any')


    start_stop_traffic(tg1, tg2, tg_dut1_p1_handle, tg_dut1_p2_handle)
    traffic_details = {'1': {'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[[1,0,1,0]], 'rx_ports':[vars.T1D1P2], 'rx_obj':[tg2], 'stream_list' : [[stream_id1,stream_id2,stream_id3,stream_id4]] }}
    test1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if test1 is False:
        st.error("Traffic Verification Failed")
        final_result = False

    t1=t2=t3=t4=t5=t6=t7=t8=t9=t10=True
    t1 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_name,rule_name=rule_list[0], packet_count=expCount)
    t2 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_name,rule_name=rule_list[9], packet_count=expCount)
    t3 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_namev6,rule_name=rule_list[0], packet_count=expCount)
    t4 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_namev6,rule_name=rule_list[9], packet_count=int(expCount)+16)

    if False in list(set([t1, t2, t3, t4])):
        tc=[t1, t2, t3, t4].index(False)
        print("TC failed for rule : "+str((tc+1)))
        st.error("ACL stats validation Failed")
        final_result = False
    else:
        st.log('ACL stats validation Passed')

    st.log('Removing the ACL table config')
    acl_obj.delete_acl_table(dut=dut1, acl_table_name=acl_table_name)
    acl_obj.delete_acl_table(dut=dut1, acl_table_name=acl_table_namev6)

    if final_result:
        st.log("PBR-Test : Validation of PBR REDIRECT_TO_PORT interface Passed")
        st.report_pass('test_case_passed')
    else:
        st.error("PBR-Test : Validation of PBR REDIRECT_TO_PORT interface failed")
        st.report_fail('test_case_failed')

def test_fuctPBR_02():
    global description
    global descriptionv6
    global vars
    vars = st.get_testbed_vars()
    final_result = True
    description = 'IPv4_ACL_redirect_NH'
    descriptionv6 = 'IPv6_ACL_redirect_NH'

    st.log('This test covers StSoSeConf014 StSoSeConf015 StSoSeVer014 StSoSeVer015')
    st.log('creating IPv4 static route')
    ipfeature.create_static_route(dut1, static_ip =srpIP, next_hop =nextHop_ip, shell='')
    ipfeature.create_static_route(dut1, static_ip =srpIPv6, next_hop =nextHop_ipv6, shell='',family='ipv6')

    st.log('creating IPv4 ACL table and binding to the ports in Ingress direction')
    acl_obj.create_acl_table(dut1, name=acl_table_name, stage=stage, type=type,description=description, ports=[r1_tg_ports1])
    acl_obj.create_acl_table(dut1, name=acl_table_namev6, stage=stage, type=typev6,description=descriptionv6, ports=[r1_tg_ports1])

    st.log('Creating ACL rules with src_ip dst_ip port  and action as forward drop')
    acl_obj.create_acl_rule(dut1, table_name=acl_table_name, rule_name=rule_list[0],priority=priority_list[0], packet_action=pktAction+nextHop_ip+'|'+r1_tg_ports2, SRC_IP="{}/{}".format(srpIP, maskACL),DST_IP="{}/{}".format(dstIP, maskACL))
    acl_obj.create_acl_rule(dut1, table_name=acl_table_name, rule_name=rule_list[9],priority=priority_list[9],packet_action='drop', IP_TYPE='ipv4any')
    acl_obj.create_acl_rule(dut1, table_name=acl_table_namev6, rule_name=rule_list[0],priority=priority_list[0],packet_action=pktAction+nextHop_ipv6+'|'+r1_tg_ports2, SRC_IPV6="{}/{}".format(srpIPv6, '128'),DST_IPV6="{}/{}".format(dstIPv6, '128'))
    acl_obj.create_acl_rule(dut1, table_name=acl_table_namev6, rule_name=rule_list[9],priority=priority_list[9],packet_action='drop', IP_TYPE='ipv6any')

    #acl_obj.create_acl_rule(dut1, table_name=acl_table_name, rule_name=rule_list[0],priority=priority_list[0], packet_action=pktAction+nextHop_ip+'|'+r1_tg_ports2, SRC_IP="{}/{}".format(srpIP, maskACL),DST_IP="{}/{}".format(dstIP, maskACL))
    start_stop_traffic(tg1, tg2, tg_dut1_p1_handle, tg_dut1_p2_handle)
    traffic_details = {'1': {'tx_ports':[vars.T1D1P1], 'tx_obj':[tg1], 'exp_ratio':[[1,0,1,0]], 'rx_ports':[vars.T1D1P2], 'rx_obj':[tg2], 'stream_list' : [[stream_id1,stream_id2,stream_id3,stream_id4]] }}
    test1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if test1 is False:
        st.error("Traffic Verification Failed")
        final_result = False

    t1=t2=t3=t4=t5=t6=t7=t8=t9=t10=True
    t1 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_name,rule_name=rule_list[0], packet_count=expCount)
    t2 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_name,rule_name=rule_list[9], packet_count=expCount)
    t3 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_namev6,rule_name=rule_list[0], packet_count=expCount)
    t4 =acl_obj.verify_acl_stats(dut1,table_name=acl_table_namev6,rule_name=rule_list[9], packet_count=int(expCount)+16)

    if False in list(set([t1, t2, t3, t4])):
        tc=[t1, t2, t3, t4].index(False)
        print("TC failed for rule : "+str((tc+1)))
        st.error("ACL stats validation Failed")
        final_result = False
    else:
        st.log('ACL stats validation Passed')

    st.log('Deleting IPv4/v6 static route')
    ipfeature.delete_static_route(dut1, static_ip =srpIP, next_hop =nextHop_ip,shell='')
    ipfeature.delete_static_route(dut1, static_ip =srpIPv6, next_hop =nextHop_ipv6,shell='',family='ipv6')

    st.log('Removing the ACL table config')
    acl_obj.delete_acl_table(dut=dut1, acl_table_name=acl_table_name)
    acl_obj.delete_acl_table(dut=dut1, acl_table_name=acl_table_namev6)

    if final_result:
        st.log("PBR-Test:Validation of PBR REDIRECT_TO_Next-Hop interface Passed")
        st.report_pass('test_case_passed')
    else:
        st.error("PBR-Test : Validation of PBR REDIRECT_TO_Next-Hop interface failed")
        st.report_fail('test_case_failed')

def create_trafficStreams(tg1, tg2, tg_ph_1, tg_ph_2, rate=1000, protocol = 'ipv4', rule = "forward",dstMAC=None):
    """
    This proc is used to create traffic streams required for the test

    :param tg1: TG chassis
    :param tg2: TG chassis
    :param tg_ph_1: TG port handle 1
    :param tg_ph_2: TG port handle 2
    :
    :
    :return:
    """
    # printing arguments passed to function
    saved_args = locals()
    st.log("Valiating traffic with following parameters: \n\t")
    for k, v in saved_args.items():
        st.log("\t{}: {}".format(k, v))
    for action in ['reset', 'clear_stats']:
        tg1.tg_traffic_control(action=action, port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action, port_handle=tg_ph_2)

    stream_tg1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='multi_burst',
                      length_mode='fixed', port_handle2=tg_ph_2, rate_pps=rate, mac_src='00.00.00.11.12.53',
                      mac_dst=dstMAC, ip_src_addr =srpIP, ip_dst_addr=dstIP, l3_protocol='ipv4',
                      pkts_per_burst = '4', burst_loop_count = pktrate)

    stream_tg2 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='multi_burst',
                      length_mode='fixed', port_handle2=tg_ph_2, rate_pps=rate, mac_src='00.00.00.11.12.53',
                      mac_dst=dstMAC, ip_src_addr ='192.168.3.10', ip_dst_addr='171.2.1.100',
                      l3_protocol='ipv4', pkts_per_burst = '4', burst_loop_count = pktrate)

    stream_tg3 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='multi_burst',
                      length_mode='fixed', port_handle2=tg_ph_2, rate_pps=rate, mac_src='00.00.00.11.12.53',
                      mac_dst=dstMAC, ipv6_src_addr =srpIPv6, ipv6_dst_addr=dstIPv6, l3_protocol='ipv6',
                      pkts_per_burst = '4', burst_loop_count = pktrate)

    stream_tg4 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='multi_burst',
                      length_mode='fixed', port_handle2=tg_ph_2, rate_pps=rate, mac_src='00.00.00.11.12.53',
                      mac_dst=dstMAC, ipv6_src_addr ='4851::1', ipv6_dst_addr='5632::1',
                      l3_protocol='ipv6', pkts_per_burst = '4', burst_loop_count = pktrate)
    global stream_id1, stream_id2, stream_id3, stream_id4
    stream_id1 = stream_tg1['stream_id']
    stream_id2 = stream_tg2['stream_id']
    stream_id3 = stream_tg3['stream_id']
    stream_id4 = stream_tg4['stream_id']

def start_stop_traffic(tg1, tg2, tg_ph_1, tg_ph_2):
    st.log('Clear stats on both the ports and start traffic')
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    tg1.tg_traffic_control(action='run', port_handle=tg_ph_1)
    st.wait(5)

    st.log('Stop the traffic and verify the stats')
    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    st.wait(5)
