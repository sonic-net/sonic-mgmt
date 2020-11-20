import pytest

from spytest import st, tgapi

import apis.qos.cos as qos_map
import apis.system.switch_configuration as sw_conf
import apis.routing.arp as arp
import apis.routing.ip as ip
import apis.switching.vlan as sw_vla

from tests.qos.qos_map import *

@pytest.fixture(scope="module", autouse=True)
def qos_module_hooks(request):
    global vars, tg, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4
    global d1_p1, d1_p2, d2_p1, d2_p2, d1_d2_p1, d2_d1_p1
    vars = st.ensure_min_topology("D1T1:2","D2T1:2","D1D2:1")
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    _,   tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    _,   tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    _,   tg_ph_4 = tgapi.get_handle_byname("T1D2P2")
    tg = tg1
    d1_p1, d1_p2 = vars.D1T1P1, vars.D1T1P2
    d2_p1, d2_p2 = vars.D2T1P1, vars.D2T1P2
    d1_d2_p1, d2_d1_p1 = vars.D1D2P1, vars.D2D1P1
    yield


@pytest.fixture(scope="function")
def qos_vlan_hooks(request):
    sw_vla.create_vlan(dut=vars.D1,vlan_list=[vlan_id])
    sw_vla.add_vlan_member(dut=vars.D1,vlan=vlan_id,port_list=[d1_p1,d1_p2],tagging_mode=True)
    yield
    sw_vla.delete_vlan_member(dut=vars.D1,vlan=vlan_id,port_list=[d1_p1,d1_p2])
    sw_vla.delete_vlan(dut=vars.D1,vlan_list=[vlan_id])


@pytest.fixture(scope="function")
def qos_ip_hooks(request):
    d1_tg_p2_mac = basic.get_ifconfig(vars.D1, d1_p2)[0]['mac']
    for intf,addr in zip([d1_p1,d1_p2],[dut_ip_addr_1,dut_ip_addr_2]):
        ip.config_ip_addr_interface(dut=vars.D1, interface_name=intf, ip_address=addr,
                subnet='24')
    arp.add_static_arp(dut=vars.D1, ipaddress=tg_ip_addr_2, macaddress=d1_tg_p2_mac,
                interface=vars.D1T1P2)
    yield
    arp.delete_static_arp(dut=vars.D1, ipaddress=tg_ip_addr_2)
    for intf, addr in zip([d1_p1, d1_p2], [dut_ip_addr_1,dut_ip_addr_2]):
        ip.delete_ip_interface(dut=vars.D1, interface_name=intf, ip_address=addr, subnet='24')


@pytest.fixture(scope="function")
def qos_arp_hooks(request):
    for intf,addr in zip([d1_p1,d1_p2],[dut_ip_addr_1,dut_ip_addr_2]):
        ip.config_ip_addr_interface(dut=vars.D1, interface_name=intf, ip_address=addr,
                subnet='24')
    yield
    for intf, addr in zip([d1_p1, d1_p2], [dut_ip_addr_1,dut_ip_addr_2]):
        ip.delete_ip_interface(dut=vars.D1, interface_name=intf, ip_address=addr, subnet='24')


@pytest.fixture(scope="function")
def qos_sched_hooks(request):
    result = check_port_speed(dut=vars.D1, in_port1=vars.D1T1P1, in_port2=vars.D1T1P2,
                out_port=vars.D1D2P1)
    if not result:
        st.report_env_fail("")

    for dut in [vars.D1, vars.D2]:
        sw_vla.create_vlan(dut=dut,vlan_list=[vlan_id])
    sw_vla.add_vlan_member(dut=vars.D1,vlan=vlan_id,port_list=[d1_p1,d1_p2,d1_d2_p1],
        tagging_mode=True)
    sw_vla.add_vlan_member(dut=vars.D2,vlan=vlan_id,port_list=[d2_p1,d2_p2,d2_d1_p1],
        tagging_mode=True)
    yield
    sw_vla.delete_vlan_member(dut=vars.D1,vlan=vlan_id,port_list=[d1_p1,d1_p2,d1_d2_p1])
    sw_vla.delete_vlan_member(dut=vars.D2,vlan=vlan_id,port_list=[d2_p1,d2_p2,d2_d1_p1])
    for dut in [vars.D1, vars.D2]:
        sw_vla.delete_vlan(dut=dut,vlan_list=[vlan_id])


@pytest.mark.st
def test_StSoQosConf011(qos_vlan_hooks):
    success = True
    st.log("testcase to verify TC to queue map")

    clear_tgen_stats('start')
    clear_qos_queue_counters(vars.D1)
    st.log("configure tc to queue map")
    qos_map.config_tc_to_queue_map(vars.D1,obj_name,tc_to_queue_map_1)
    bind_qos_map_port(vars.D1,"tc_to_queue_map",obj_name,d1_p1)

    clear_qos_config(dut=vars.D1)
    st.log("modify TC 2,5 to queue 5,2 respectively")
    qos_map.config_tc_to_queue_map(vars.D1,obj_name,tc_to_queue_map_2)
    bind_qos_map_port(vars.D1, "tc_to_queue_map", obj_name, d1_p1)
    st.log("verify modified qos map for TC 2,5 in running config")
    for tc,que in zip(tc2,qval2):
        if not sw_conf.verify_running_config(vars.D1,tc_queue_map,obj_name,tc,que):
            st.error("modification of TC {} to queue {} fails".format(tc,que))

    st.log("create stream with COS value 2 and 5")
    for pcp,rate in zip(queue_list,rate_list):
        create_stream(handle=tg_ph_1,type='l2',pcp=pcp,rate=rate)

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1,tg_ph_2])
    st.log("Verify traffic and qos queue counters after modifying TC 2,5")
    if not verify_queue_traffic_and_counter('packet_count', mqueue_list,rate_list,exp_list2):
        st.error("traffic or counter verification failed after modifying TC values 2,5")
        success = False

    clear_qos_config(dut=vars.D1)
    st.log("revert TC 2,5 values")
    qos_map.config_tc_to_queue_map(vars.D1,obj_name,tc_to_queue_map_1)
    bind_qos_map_port(vars.D1, "tc_to_queue_map", obj_name, d1_p1)
    st.log("verify reverted qos map in running config")
    for tc,que in zip(tc1,qval1):
        if not sw_conf.verify_running_config(vars.D1,tc_queue_map,obj_name,tc,que):
            st.error("reverting tc value {} to queue {} fails".format(tc,que))

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1,tg_ph_2])
    st.log("Verify traffic and qos queue counters after reverting TC 2,5")
    if not verify_queue_traffic_and_counter('packet_count',mqueue_list,rate_list,exp_list1):
        st.error("traffic or counter verification failed after reverting TC values 2,5")
        success = False
    clear_tgen_stats('end')
    clear_qos_config(dut=vars.D1)

    if success:
        st.report_pass("test_case_id_passed","StSoQosConf011")
    else:
        st.report_fail("test_case_id_failed","StSoQosConf011")


@pytest.mark.st
def test_StSoQosConf012(qos_ip_hooks):
    success = True
    st.log("testcase to verify DSCP to TC map")

    clear_tgen_stats('start')
    st.log("configure DSCP to TC map")
    qos_map.config_dscp_to_tc_map(dut=vars.D1,obj_name=obj_name,dscp_to_tc_map_dict=dscp_to_tc_map_1)
    create_qos_json(dut=vars.D1, block_name=port_qos_map, sub_block=d1_p1,dict_input=dscp_bind_port)

    clear_qos_config(dut=vars.D1)
    st.log("modify DSCP 20,46 to queue 2,4 respectively")
    qos_map.config_dscp_to_tc_map(dut=vars.D1, obj_name=obj_name, dscp_to_tc_map_dict=dscp_to_tc_map_2)
    create_qos_json(dut=vars.D1, block_name=port_qos_map, sub_block=d1_p1, dict_input=dscp_bind_port)
    st.log("verify modified qos map for DSCP 20,46 in running config")
    for dscp,tc in zip(dscp_val_2,tc_val_2):
        if not sw_conf.verify_running_config(vars.D1,dscp_tc_map,obj_name,dscp,tc):
            st.error("modification of DSCP {} fails".format(dscp))

    st.log("create stream with DSCP value 20 and 46")
    for dscp,rate in zip(dscp_list,rate_list):
        create_stream(type='l3',handle=tg_ph_1,rate=rate,dscp=dscp)

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1,tg_ph_2])
    st.log("Verify traffic and qos queue counters after modifying DSCP 20,46")
    if not verify_queue_traffic_and_counter('packet_count', dscp_queue_list2,rate_list,exp_list1):
        st.error("traffic or counter verification failed after modifying DSCP values 20,46")
        success = False

    clear_qos_config(dut=vars.D1)
    st.log("revert DSCP 20,46 values")
    qos_map.config_dscp_to_tc_map(dut=vars.D1, obj_name=obj_name, dscp_to_tc_map_dict=dscp_to_tc_map_1)
    create_qos_json(dut=vars.D1, block_name=port_qos_map, sub_block=d1_p1, dict_input=dscp_bind_port)
    st.log("verify reverted qos map in running config")
    for dscp,tc in zip(dscp_val_3,tc_val_3):
        if not sw_conf.verify_running_config(vars.D1,dscp_tc_map,obj_name,dscp,tc):
            st.error("reverting DSCP {} fails".format(dscp))

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1,tg_ph_2])
    st.log("Verify traffic and qos queue counters after reverting DSCP 20,46")
    if not verify_queue_traffic_and_counter('packet_count',dscp_queue_list1,rate_list,exp_list1):
        st.error("traffic or counter verification failed after reverting DSCP values 20,46")
        success = False
    clear_tgen_stats('end')
    clear_qos_config(dut=vars.D1)

    if success:
        st.report_pass("test_case_id_passed","StSoQosConf012")
    else:
        st.report_fail("test_case_id_failed","StSoQosConf012")


@pytest.mark.st
def test_StSoQoSVer004(qos_sched_hooks):
    success = True
    st.log("testcase to verify strict priority and DWRR scheduling")

    clear_tgen_stats('start')
    st.log("create json file with mix of SP and DWRR scheduler config")
    for sched,input in zip([sched_0,sched_1,sched_2,sched_3],
                [sched_strict,sched_dwrr_1,sched_dwrr_2,sched_dwrr_3]):
        create_qos_json(dut=vars.D1, block_name="SCHEDULER", sub_block=sched,
                    dict_input=input)

    st.log("apply SP and DWRR scheduler configuration to queue")
    for queue,input in zip(["5-7","4","3","0-2"],
                           [sched_bind_0,sched_bind_1,sched_dwrr_2,sched_dwrr_3]):
        create_qos_json(dut=vars.D1, block_name="QUEUE", sub_block=d1_p1 + "|" + queue,
                    dict_input=input)

    st.log("create stream with COS value 6 and 7 for strict priority scheduling")
    for pcp,han,smac,dmac in zip(['6','7'],[tg_ph_1,tg_ph_2],smac_list,dmac_list):
        create_stream(handle=han, type='sp_scheduling',pcp=pcp,src_mac=smac,dst_mac=dmac)
    for han,smac,dmac in zip([tg_ph_3,tg_ph_4],dmac_list,smac_list):
        create_stream(handle=han,type='sp_scheduling',rate='1',src_mac=smac,dst_mac=dmac)

    st.log("Verify traffic and qos queue counters for strict priority scheduling")
    if not verify_queue_traffic_and_counter(field='packet_count',qname_list=strict_pri_queue,
                rate_list=rate_list,val_list=exp_list1,type='sp_scheduling'):
        st.error("traffic or counter verification failed for strict priority scheduling")
        success = False

    clear_tgen_stats('end')
    st.log("create stream with COS value 5 and 4 SP and DWRR scheduling")
    for pcp,han,smac,dmac in zip(['5','4'],[tg_ph_1,tg_ph_2],smac_list,dmac_list):
        create_stream(handle=han,type='sp_dwrr_scheduling',pcp=pcp,src_mac=smac,dst_mac=dmac)
    for han,smac,dmac in zip([tg_ph_3,tg_ph_4],dmac_list,smac_list):
        create_stream(handle=han,type='sp_dwrr_scheduling',rate='1',src_mac=smac,dst_mac=dmac)

    st.log("Verify traffic and qos queue counters for SP and DWRR scheduling")
    if not verify_queue_traffic_and_counter(field='packet_count',qname_list=strict_dwrr_queue,
                rate_list=rate_list,val_list=exp_list1,type='sp_dwrr_scheduling'):
        st.error("traffic or counter verification failed for SP/DWRR scheduling")
        success = False

    clear_tgen_stats('end')
    st.log("create stream with COS value 4 and 3 for DWRR scheduling")
    for pcp,han,smac,dmac in zip(['4','3'],[tg_ph_1,tg_ph_2],smac_list,dmac_list):
        create_stream(handle=han,type='dwrr_scheduling',pcp=pcp,src_mac=smac,dst_mac=dmac)
    for han,smac,dmac in zip([tg_ph_3,tg_ph_4],dmac_list,smac_list):
        create_stream(handle=han,type='dwrr_scheduling',rate='1',src_mac=smac,dst_mac=dmac)

    st.log("Verify traffic and qos queue counters for DWRR scheduling")
    if not verify_queue_traffic_and_counter(field='packet_count',qname_list=dwrr_queue,
                rate_list=rate_list,val_list=exp_list1,type='dwrr_scheduling'):
        st.error("traffic or counter verification failed for DWRR scheduling")
        success = False
    clear_tgen_stats('end')
    clear_qos_config(dut=vars.D1)

    if success:
        st.report_pass("test_case_id_passed","StSoQoSVer004")
    else:
        st.report_fail("test_case_id_failed","StSoQoSVer004")


@pytest.mark.st1
def test_StSoQoSVer008(qos_sched_hooks):
    success = True
    st.log("testcase to verify WRED")

    clear_tgen_stats('start')
    st.log("create json file with WRED config")
    create_qos_json(dut=vars.D1, block_name=wred_profile, sub_block=wred_obj,
                    dict_input=wred_input)
    st.log("apply WRED config to queue")
    create_qos_json(dut=vars.D1, block_name="QUEUE", sub_block=d1_p1 + "|" + "3",
                    dict_input=wred_bind)

    st.log("create stream with COS value 3")
    for pcp,han,smac,dmac in zip(['3','3'],[tg_ph_1,tg_ph_2],smac_list,dmac_list):
        create_stream(handle=han,type='wred',pcp=pcp,src_mac=smac,dst_mac=dmac)
    for han,smac,dmac in zip([tg_ph_3,tg_ph_4],dmac_list,smac_list):
        create_stream(handle=han,type='wred',rate='1',src_mac=smac,dst_mac=dmac)

    st.log("Verify traffic and WRED counters, drop should be due to WRED")
    if not verify_queue_traffic_and_counter(field='packet_count',qname_list=['3'],
                rate_list=rate_list,val_list=exp_list1,type='wred'):
        st.error("traffic or WRED verification failed for queue 3")
        success = False

    clear_tgen_stats('end')
    st.log("create stream with COS value 4")
    for pcp,han,smac,dmac in zip(['4','4'],[tg_ph_1,tg_ph_2],smac_list,dmac_list):
        create_stream(handle=han,type='wred',pcp=pcp,src_mac=smac,dst_mac=dmac)
    for han,smac,dmac in zip([tg_ph_3,tg_ph_4],dmac_list,smac_list):
        create_stream(handle=han,type='wred',rate='1',src_mac=smac,dst_mac=dmac)

    st.log("Verify traffic and WRED counters, this time drop should"
                "not be due to WRED")
    if not verify_queue_traffic_and_counter(field='packet_count',qname_list=['4'],
                rate_list=rate_list,val_list=exp_list1,type='wred'):
        st.error("traffic or WRED verification failed for queue 4")
        success = False
    clear_qos_config(dut=vars.D1)

    if success:
        st.report_pass("test_case_id_passed","StSoQoSVer008")
    else:
        st.report_fail("test_case_id_failed","StSoQoSVer008")


@pytest.mark.st1
def test_StSoQoSVer007(qos_arp_hooks):
    success = True
    st.log("testcase to verify COPP for ARP request")

    clear_tgen_stats('start')
    st.log('sending ARP for 1000 pkts/sec, expecting drop')
    if not verify_copp_arp_asic_bcm(dut=vars.D1,queue='4',value='5000',tol='1000',rate='1000'):
        st.error('CPU counter check for sending ARP 1000 pkts/sec failed')
        success = False

    if success:
        st.report_pass("test_case_id_passed","StSoQoSVer007")
    else:
        st.report_fail("test_case_id_failed","StSoQoSVer007")


@pytest.mark.st
def test_StSoQoSVer001(qos_ip_hooks):
    success = True
    st.log("testcase to verify TC to queue using incoming DSCP value")

    clear_tgen_stats('start')
    st.log("configure tc to queue map")
    qos_map.config_tc_to_queue_map(vars.D1, obj_name, tc_to_queue_map_1)
    bind_qos_map_port(vars.D1, "tc_to_queue_map", obj_name, d1_p1)

    st.log("modify TC 2,5 to queue 5,2 respectively")
    qos_map.config_tc_to_queue_map(vars.D1, obj_name, tc_to_queue_map_2)
    st.log("verify modified qos map for TC 2,5 in running config")
    for tc, que in zip(tc2, qval2):
        if not sw_conf.verify_running_config(vars.D1, tc_queue_map, obj_name, tc, que):
            st.error("modifying TC {} to queue {} fails".format(tc,que))
            success = False

    st.log("create stream with DSCP value 20 and 46")
    for dscp, rate in zip(dscp_list, rate_list):
        create_stream(type='l3', handle=tg_ph_1, rate=rate, dscp=dscp)

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1, tg_ph_2])
    st.log("Verify traffic and qos queue counters after modifying TC 2,5")
    if not verify_queue_traffic_and_counter('packet_count', dscp_queue_list4, rate_list, exp_list2):
        st.error("traffic or counter verification failed after modifying TC values 2,5")
        success = False

    st.log("revert TC 2,5 values")
    qos_map.config_tc_to_queue_map(vars.D1, obj_name, tc_to_queue_map_1)
    st.log("verify reverted qos map in running config")
    for tc, que in zip(tc1, qval1):
        if not sw_conf.verify_running_config(vars.D1, tc_queue_map, obj_name, tc, que):
            st.error("reverting TC {} to queue {} fails".format(tc,que))
            success = False

    tg.tg_traffic_control(action="clear_stats", port_handle=[tg_ph_1, tg_ph_2])
    st.log("Verify traffic and qos queue counters after reverting TC 2,5")
    if not verify_queue_traffic_and_counter('packet_count', dscp_queue_list3, rate_list, exp_list1):
        st.error("traffic or counter verification failed after reverting TC values 2,5")
        success = False
    clear_tgen_stats('end')

    if success:
        st.report_pass("verify_queue_counter_pass")
    else:
        st.report_fail("verify_queue_counter_fail")


@pytest.mark.st
def test_StSoQoSVer003(qos_sched_hooks):
    success = True
    st.log("testcase to verify PFC")

    clear_tgen_stats('start')
    clear_qos_queue_counters(vars.D1)
    st.log("configure PFC enable for queue 2")
    create_qos_json(dut=vars.D1, block_name=port_qos_map, sub_block=d2_d1_p1,
                    dict_input=pfc_bind)

    st.log("create stream with COS value 2")
    for src_mac,dst_mac,handle,pcp in zip(smac_list,dmac_list,[tg_ph_1,tg_ph_2],['2','2']):
        tg.tg_traffic_config(mac_src=src_mac, mac_dst=dst_mac,
            rate_percent=rate_percent, mode='create', port_handle=handle, transmit_mode='continuous',
            l2_encap='ethernet_ii_vlan', vlan_id=vlan_id, vlan_user_priority=pcp)
    for src_mac,dst_mac,handle,pcp in zip(dmac_list,smac_list,[tg_ph_3,tg_ph_4],['1','1']):
        tg.tg_traffic_config(mac_src=src_mac, mac_dst=dst_mac,
            rate_percent='10', mode='create', port_handle=handle, transmit_mode='continuous',
            l2_encap='ethernet_ii_vlan', vlan_id=vlan_id, vlan_user_priority=pcp)

    tg.tg_traffic_control(action='run', port_handle=[tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4])

    '''
    verify_pfc_counters(dut,port_mode,port,queue)

    verify_traffic(field='packet_rate',type='pfc')

    clear_tgen_stats('end')
    st.log("create stream with COS value 3")
    for src_mac,dst_mac,handle,pcp in zip():
        tg.tg_traffic_config(mac_src=src_mac, mac_dst=dst_mac,
            rate_percent=rate_percent, mode='create', port_handle=handle, transmit_mode='continuous',
            l2_encap='ethernet_ii_vlan', vlan_id=vlan, vlan_user_priority=pcp, duration='5')

    verify_pfc_counters(dut,port_mode,port,queue)

    verify_traffic(field='packet_rate',type='pfc')

    clear_tgen_stats('end')
    '''
    if success:
        st.report_pass("test_case_id_passed","StSoQoSVer003")
    else:
        st.report_fail("test_case_id_failed","StSoQoSVer003")
