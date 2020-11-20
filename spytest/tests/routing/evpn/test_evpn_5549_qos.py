import pytest
from spytest import st, tgapi
import apis.routing.evpn as Evpn
from evpn_qos import *
from utilities import parallel,utils
import apis.system.port as port_obj
import apis.qos.qos as Qos
import apis.system.reboot as reboot_api
import apis.switching.mac as Mac
import apis.qos.acl_dscp as dscp

@pytest.fixture(scope="module", autouse=True)
def evpn_qos_hooks(request):
    global vars
    create_glob_vars()
    vars = st.get_testbed_vars()
    api_list = [[create_stream],[create_evpn_5549_config]]
    parallel.exec_all(True, api_list, True)
    st.log("verify BGP EVPN neighborship for all nodes ")
    result = st.exec_all([[spine_verify_evpn],[leaf1_verify_evpn],[leaf2_verify_evpn],[leaf3_verify_evpn]])
    if result[0].count(False) > 0:
        st.error("########## BGP EVPN neighborship is NOT UP on all spine and leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    st.log("verify vxlan tunnel status on leaf nodes")
    result=st.exec_all([[leaf1_verify_vxlan],[leaf2_verify_vxlan],[leaf3_verify_vxlan]])

    if result[0].count(False) > 0:
        st.error("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")
    yield

    #cleanup_l2vni()
    #cleanup_l3vni()
    #cleanup_vxlan()
    #cleanup_evpn_5549()
    #reboot_api.config_save(evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"], "vtysh")


@pytest.fixture(scope="function")
def l2_uniform_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],

                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "uniform"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "uniform"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    input1 = {'map_name': "dscpToTc", 'dscp': '0', 'tc': '5'}
    parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4],Qos.config_qos_dscp_tc,[input1]*3)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input3,input4,input5])

    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["l2_1"] + stream_dict["l2_2"]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name':
                      intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input6,input7,input8])
    input9 = {'map_name': "dscpToTc", 'dscp': '0', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input9] * 3)


def test_FtOpSoRoEvpnQos321(l2_uniform_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS uniform mode for L2 forwarded traffic without IP header")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["l2_1"] + stream_dict["l2_2"])
    hdrMsg("Verify L2 tagged traffic sent from first Tgen port of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["l2_1"],rx_stream_list=stream_dict["l2_2"]):
        st.log("######## PASS: tagged traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: tagged traffic b/w Tgen port1 of DUT2 and DUT3 failed ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos321")

    hdrMsg("verify traffic towards DUT3 is queued into UC5 in DUT1")
    if not verify_queuing(vars.D1,[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],"UC5"):
        success=False
        st.error("######## FAIL: traffic towards DUT3 is NOT queued to UC5 in DUT1 ########")
    else:
        st.log("######### traffic is queued to UC5 as expected ##########")

    hdrMsg("verify traffic towards Tgen is queued into UC5 in DUT3")
    if not verify_queuing(vars.D3,[vars.D3T1P1],"UC5",val_list=["5000"],tol_list=["4000"]):
        success=False
        st.error("######## FAIL: traffic towards Tgen is NOT queued to UC5 in DUT3")
    else:
        st.log("######### traffic is queued to UC5 as expected ##########")

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos321")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos321")


@pytest.fixture(scope="function")
def l3_uniform_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "uniform"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "uniform"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    input1 = {'map_name': "dscpToTc", 'dscp': '32', 'tc': '6'}
    input2 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '5'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D4], Qos.config_qos_dscp_tc, [input2]*2)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input3,input4,input5])

    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input6,input7,input8])
    input9 = {'map_name': "dscpToTc", 'dscp': '32', 'config': 'no'}
    input10 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D4], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos323(l3_uniform_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS uniform mode for L3 forwarded traffic")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='start')
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
        st.report_tc_pass("FtOpSoRoEvpnQos3218", "tc_passed")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos323")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos323")

    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='stop')
    pkts_captured1 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d3_tg_ph1"],
                                                   format='var', output_type='hex',var_num_frames=tg_dict["cap_frames"])
    pkts_captured2 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d4_tg_ph2"],
                                                   format='var', output_type='hex',var_num_frames=tg_dict["cap_frames"])

    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT4"],["UC6","UC5"],["32","40"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D4],["IPv4","IPv6"],["UC6","UC5"],["32","40"],
                                            [[vars.D3T1P1],[vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto,queue,dscp,dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured1,
                                     offset_list=[30, 19],value_list=[evpn_dict["leaf1"]["tenant_v4_ip"][0], '80'],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 80 for IPv4 tenant traffic #########")
    else:
        success=False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 80 for IPv4 tenant traffic ########")

    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured2,
                                     offset_list=[14, 15,22,23,37],value_list=["65","00","20","02","02"],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 50 for IPv6 tenant traffic #########")
    else:
        success=False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 50 for IPv6 tenant traffic ########")

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos323")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos323")


@pytest.fixture(scope="function")
def l2_pipe_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "40"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "40"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "40"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    input1 = {'map_name': "dscpToTc", 'dscp': '40', 'tc': '3'}
    parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4],Qos.config_qos_dscp_tc,[input1]*3)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input3,input4,input5])

    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["l2_1"] + stream_dict["l2_2"]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input6,input7,input8])
    input9 = {'map_name': "dscpToTc", 'dscp': '40', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input9] * 3)


def test_FtOpSoRoEvpnQos326(l2_pipe_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS pipe mode for L2 forwarded traffic without IP header")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["l2_1"] + stream_dict["l2_2"])
    hdrMsg("Verify L2 tagged traffic sent from first Tgen port of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["l2_1"],rx_stream_list=stream_dict["l2_2"]):
        st.log("######## PASS: tagged traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: tagged traffic b/w Tgen port1 of DUT2 and DUT3 failed ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos326")
    st.wait(15)
    for to_dut,queue,port in zip(["DUT3"],["UC3"],[[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4]]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1".format(to_dut,queue))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: traffic towards {} are NOT queued to {} "
                     " in DUT1 ########".format(to_dut,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,queue,port in zip([vars.D3],["UC3"],[[vars.D3T1P1]]):
        hdrMsg("verify traffic towards Tgen is queued into {} in {}".format(queue,dut))
        if not verify_queuing(dut,port,queue,val_list=["5000"],tol_list=["4000"]):
            success=False
            st.error("######## FAIL: traffic towards Tgen are NOT queued to {}"
                     " in {} ########".format(queue,dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos326")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos326")



@pytest.fixture(scope="function")
def l3_pipe_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "10"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "10"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "10"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])
    input1 = {'map_name': "dscpToTc", 'dscp': '10', 'tc': '4'}
    input2 = {'map_name': "dscpToTc", 'dscp': '10', 'tc': '5'}
    input3 = {'map_name': "dscpToTc", 'dscp': '10', 'tc': '6'}
    parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4],Qos.config_qos_dscp_tc,[input1,input2,input3])

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input4 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input6 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input4,input5,input6])

    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])
    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input7 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input9 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input7,input8,input9])
    input9 = {'map_name': "dscpToTc", 'dscp': '10', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input9] * 3)


def test_FtOpSoRoEvpnQos328(l3_pipe_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS pipe mode for L3 forwarded traffic")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='start')
    for han in [han_dict["v4_host1"], han_dict["v4_host2"], han_dict["v6_host3"], han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"], rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success = False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos328")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"], rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"], rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success = False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos328")
    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='stop')
    pkts_captured1 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d3_tg_ph1"],
                                                   format='var', output_type='hex', var_num_frames=tg_dict["cap_frames"])
    pkts_captured2 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d4_tg_ph2"],
                                                   format='var', output_type='hex', var_num_frames=tg_dict["cap_frames"])

    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC4"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC5", "UC6"], ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured1,
                                     offset_list=[30, 19], value_list=[evpn_dict["leaf1"]["tenant_v4_ip"][0], '80'],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 80 for IPv4 tenant traffic #########")
    else:
        success = False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 80 for IPv4 tenant traffic ########")

    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured2,
                                     offset_list=[14, 15, 22, 23,37], value_list=["65", "00", "20", "02","02"],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 50 for IPv6 tenant traffic #########")
    else:
        success = False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 50 for IPv6 tenant traffic ########")

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos328")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos328")


@pytest.fixture(scope="function")
def mode_change_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1,input2,input3])

    input={'map_name': "dscpToTc", 'dscp': '0', 'tc': '2'}
    parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)

    input4 = {'map_name': "dscpToTc", 'dscp': '32', 'tc': '6'}
    input5 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '1'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input4]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D4], Qos.config_qos_dscp_tc, [input5]*2)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input6 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input7 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input6,input7,input8])

    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                  stream_dict["v6_3"] + stream_dict["v6_4"]])
    input9 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input10 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input11 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input9,input10,input11])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input12 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input13 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input14 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input12,input13,input14])

    input = {'map_name': "dscpToTc", 'dscp': '0', 'tc': '2', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)

    input15 = {'map_name': "dscpToTc", 'dscp': '32', 'config': 'no'}
    input16 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input15] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D4], Qos.config_qos_dscp_tc, [input16] * 2)


def test_FtOpSoRoEvpnQos3211(mode_change_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by changing the mode from pipe to uniform")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3211")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3211")

    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC2"] * 2, ["0"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC2"]*2, ["0"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Change the qos mode from PIPE to uniform")
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "uniform"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "uniform"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    hdrMsg("Verify queuing after changing mode from PIPE to uniform")
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after changing QOS mode ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after changing QOS mode########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3211")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after changing QOS mode########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after changing QOS mode########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3211")
    hdrMsg("Verify queuing after changing mode from PIPE to uniform")
    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC6","UC1"], ["32","40"],
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 after changing mode to uniform ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue)) 
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC6","UC1"], ["32","40"],
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after changing mode to uniform ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3211")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3211")


@pytest.fixture(scope="function")
def pipe_change_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1,input2,input3])

    for input in [{'map_name': "dscpToTc", 'dscp': '0', 'tc': '2'},
              {'map_name': "dscpToTc", 'dscp': '10', 'tc': '3'}]:
        parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input6 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input7 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input6,input7,input8])

    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                  stream_dict["v6_3"] + stream_dict["v6_4"]])
    input9 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input10 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input11 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input9,input10,input11])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input12 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input13 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input14 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input12,input13,input14])

    for input in [{'map_name': "dscpToTc", 'dscp': '0', 'tc': '2', 'config': 'no'},
              {'map_name': "dscpToTc", 'dscp': '10', 'tc': '3', 'config': 'no'}]:
        parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)


def test_FtOpSoRoEvpnQos3212(pipe_change_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by changing the pipe mode DSCP value")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3212")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3212")

    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC2"] * 2, ["0"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC2"]*2, ["0"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Change the PIPE DSCP value to 10")
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "10"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "10"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "10"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after changing PIPE dscp value########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after "
                 "changing PIPE dscp value########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3212")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after changing PIPE dscp value########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after "
                 "changing PIPE dscp value########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3212")
    hdrMsg("Verify queuing after changing PIPE DSCP value to 10")
    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC3"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 after changing DSCP value to 10 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC3"]*2, ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after changing DSCP value to 10 ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3212")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3212")


@pytest.fixture(scope="function")
def pipe_clear_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],tg_dict["d3_tg_ph1"],
                                                                        tg_dict["d3_tg_ph2"],tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "10"}
    input2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "20"}
    input3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1,input2,input3])

    input = {'map_name': "dscpToTc", 'dscp': '10', 'tc': '3'}
    parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input6 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input7 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input6,input7,input8])

    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                  stream_dict["v6_3"] + stream_dict["v6_4"]])
    input9 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input10 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input11 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input9,input10,input11])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input12 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input13 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input14 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input12,input13,input14])

    input = {'map_name': "dscpToTc", 'dscp': '10', 'tc': '3', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2, vars.D3, vars.D4], Qos.config_qos_dscp_tc, [input] * 4)


def test_FtOpSoRoEvpnQos3214(pipe_clear_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by clearing the BGP session")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3214")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3214")

    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC3"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC3"]*2, ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Clear the BGP session in DUT2")
    Bgp.clear_ip_bgp_vtysh(vars.D2)
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf3"]["loop_ip_list"][1]],
                 exp_status_list=['oper_up'] * 2, retry_count=6, delay=5):
        st.log("########## PASS: VXLAN tunnel is UP in D2 after clearing BGP ##########")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel is DOWN in D2 after clearing BGP ##########")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after clearing BGP session########")
    else:

        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after clearing BGP session########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3214")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after clearing BGP session########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after clearing BGP session########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3214")
    hdrMsg("Verify queuing after clearing BGP session")
    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC3"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 after clearing BGP ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC3"]*2, ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after clearing BGP ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3214")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3214")


def test_FtOpSoRoEvpnQos3216(pipe_clear_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by shutting down all the links b/w leaf and spine")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3216")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3216")

    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC3"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC3"]*2, ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("shutdown all the links b/w DUT1 and DUT2")
    port_obj.shutdown(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4])
    st.wait(5)
    hdrMsg("Enable back all the links b/w DUT1 and DUT2")
    port_obj.noshutdown(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4])

    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf2"]["loop_ip_list"][1]],
                 exp_status_list=['oper_up'] * 2, retry_count=6, delay=5):
        st.log("########## PASS: VXLAN tunnel is UP in D2 after enabling back links towards D1 ##########")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel is DOWN in D2 after enabling back links towards D1 ##########")
    hdrMsg("verify VXLAN interface o/p after enabling back links towards D1")
    if Evpn.verify_vxlan_qos_mode(vars.D2, vtep_name=evpn_dict["leaf1"]["vtepName"], qos_mode="pipe", pipe_dscp="10"):
        st.log("########## PIPE DSCP value 10 found in VxLAN interface o/p after "
               "enabling back link towards D1 ##########")
        st.report_tc_pass("FtOpSoRoEvpnQos311", "tc_passed")
    else:
        success = False
        st.error("########## PIPE DSCP value 10 NOT found in VxLAN interface o/p after"
                 " enabling back link towards D1 ##########")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after enabling back links b/w DUT1 and DUT2########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after enabling back links b/w DUT1 and DUT2########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3216")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after enabling back links b/w DUT1 and DUT2 ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after enabling back links b/w DUT1 and DUT2########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3216")
    hdrMsg("Verify queuing after enabling back links b/w DUT1 and DUT2")
    for proto, to_dut, queue, dscp, port in zip(["IPv4", "IPv6"], ["DUT3", "DUT4"], ["UC3"] * 2, ["10"] * 2,
                                                [[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                                 [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto, to_dut, dscp))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 after enabling back the links ########".format(proto, to_dut, queue, dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut, proto, queue, dscp, port in zip([vars.D3, vars.D4], ["IPv4", "IPv6"], ["UC3"]*2, ["10"] * 2,
                                             [[vars.D3T1P1], [vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto, dscp, dut))
        if not verify_queuing(dut, port, queue):
            success = False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after enabling back the links ########".format(proto, queue, dscp, dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3216")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3216")


@pytest.fixture(scope="function")
def uniform_clear_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],tg_dict["d3_tg_ph1"],
                                                                        tg_dict["d3_tg_ph2"],tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "uniform"}
    input2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "uniform"}
    input3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1,input2,input3])

    input4 = {'map_name': "dscpToTc", 'dscp': '32', 'tc': '6'}
    input5 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '5'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input4]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D4], Qos.config_qos_dscp_tc, [input5]*2)

    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D4D1P1,evpn_dict["leaf3"]["pch_intf_list"][0],vars.D4D1P4]):
        input6 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input7 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D4], Qos.bind_qos_map, [input6,input7,input8])

    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                  stream_dict["v6_3"] + stream_dict["v6_4"]])
    input9 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input10 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input11 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input9,input10,input11])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input12 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input13 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input14 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input12,input13,input14])

    input15 = {'map_name': "dscpToTc", 'dscp': '32', 'config': 'no'}
    input16 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input15] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D4], Qos.config_qos_dscp_tc, [input16] * 2)


def test_FtOpSoRoEvpnQos3213(uniform_clear_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by removing source VTEP interface")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3213")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3213")

    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT4"],["UC6","UC5"],["32","40"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D4],["IPv4","IPv6"],["UC6","UC5"],["32","40"],
                                            [[vars.D3T1P1],[vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto,queue,dscp,dut))

    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("removing loopback interface from D2")
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][0], loopback_name="Loopback1", config="no")

    st.log("### verify VXLAN tunnel status in D4 ###")
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                 src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1]], exp_status_list=['oper_down'],
                 retry_count=3, delay=5):
        st.log("##### VXLAN tunnel towards D2 is DOWN in D4 as expected #####")
    else:
        success = False
        st.error("########## VXLAN tunnel towards D2 is NOT DOWN in D4 ##########")

    st.log("### add back the removed loopback interface {} in D2 ###".format("Loopback1"))
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][0], loopback_name="Loopback1")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0], interface_name="Loopback1",
                                ip_address=evpn_dict["leaf1"]["loop_ip_list"][1], subnet='32')
    st.wait(2)
    st.log("### verify VxLAN tunnel status in D4 ###")
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                     src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1]], exp_status_list=['oper_up'] * 2,
                     retry_count=3, delay=5):
        st.log("##### VxLAN tunnel towards D2 UP now in D4 #####")
    else:
        success=False
        st.error("########## VxLAN tunnel towards D2 NOT UP in D4 ##########")
    hdrMsg("verify VXLAN interface details after adding back loopback")
    if Evpn.verify_vxlan_qos_mode(vars.D2, vtep_name= evpn_dict["leaf1"]["vtepName"], qos_mode="uniform"):
        st.log("########## PASS: Uniform mode found in VxLAN interface o/p as expected ##########")
    else:
        success=False
        st.error("########## FAIL: Uniform mode NOT found in VxLAN interface o/p ##########")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after adding back loopback interface ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after adding back loopback interface########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3213")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after adding back loopback interface########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after adding back loopback interface########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3213")
    hdrMsg("Verify traffic queuing after adding back loopback interface")
    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT4"],["UC6","UC5"],["32","40"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " "
                     "DSCP {} in DUT1 after adding back loopback interface ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D4],["IPv4","IPv6"],["UC6","UC5"],["32","40"],
                                            [[vars.D3T1P1],[vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after adding back loopback interface ########".format(proto,queue,dscp,dut))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3213")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3213")


def test_FtOpSoRoEvpnQos3215(uniform_clear_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS by clearing the EVPN session")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    for han in [han_dict["v4_host1"],han_dict["v4_host2"],han_dict["v6_host3"],han_dict["v6_host4"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3215")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3215")

    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT4"],["UC6","UC5"],["32","40"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D4],["IPv4","IPv6"],["UC6","UC5"],["32","40"],
                                            [[vars.D3T1P1],[vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto,queue,dscp,dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=stream_dict["v4_1"] + stream_dict["v4_2"] +
                                                 stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("clearing the EVPN session in DUT2")
    Evpn.clear_bgp_evpn(vars.D2, "*")

    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf2"]["loop_ip_list"][1]],
                 exp_status_list=['oper_up'] * 2, retry_count=6, delay=5):
        st.log("########## PASS: VXLAN tunnel is UP in D2 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel is DOWN in D2 after clearing EVPN ##########")
    hdrMsg("verify VXLAN interface details after clearing EVPN")
    if Evpn.verify_vxlan_qos_mode(vars.D2, vtep_name= evpn_dict["leaf1"]["vtepName"], qos_mode="uniform"):
        st.log("########## PASS: Uniform mode found in VxLAN interface o/p as expected ##########")
    else:
        success = False
        st.error("########## FAIL: Uniform mode NOT found in VxLAN interface o/p ##########")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_dict["v4_1"] + stream_dict["v4_2"] + stream_dict["v6_3"] + stream_dict["v6_4"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v4_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after clearing EVPN session ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 after clearing EVPN session ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3215")

    hdrMsg("Verify L3 forwarded IPv6 traffic sent from Tgen port2 of DUT2 and DUT4")
    if verify_traffic(tx_port=tg_dict["d2_tg_port2"],rx_port=tg_dict["d4_tg_port2"],
                      tx_stream_list=stream_dict["v6_3"],rx_stream_list=stream_dict["v6_4"]):
        st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed after clearing EVPN session ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 after clearing EVPN session ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3215")
    hdrMsg("Verify queuing after clearing EVPN session")
    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT4"],["UC6","UC5"],["32","40"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 after clearing EVPN ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D4],["IPv4","IPv6"],["UC6","UC5"],["32","40"],
                                            [[vars.D3T1P1],[vars.D4T1P2]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} after clearing EVPN ########".format(proto,queue,dscp,dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3215")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3215")


@pytest.fixture(scope="function")
def tc322_uniform_fixture(request, evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "uniform"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "uniform"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])

    input1 = {'map_name': "dscpToTc", 'dscp': '30', 'tc': '3'}
    input2 = {'map_name': "dscpToTc", 'dscp': '40', 'tc': '5'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input1] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D4], Qos.config_qos_dscp_tc, [input2] * 2)

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input3 = {'intf_name': intf1, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        input4 = {'intf_name': intf2, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input3, input4, input5])

    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1]]])

    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])

    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf3"]["intf_list_tg"][1]]])

    yield
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf3"]["intf_list_tg"][1]]])
    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1]]])

    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])
    start_traffic(action="stop", stream_han_list=[stream_dict["l2_5"] + stream_dict["l2_6"] +
                                              stream_dict["l2_7"] + stream_dict["l2_8"] +
                                              stream_dict["l2_9"] + stream_dict["l2_10"] +
                                              stream_dict["l2_11"] + stream_dict["l2_12"]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                               [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                               [vars.D4D1P1, evpn_dict["leaf3"]["pch_intf_list"][0], vars.D4D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D4], Qos.bind_qos_map, [input6, input7, input8])
    input9 = {'map_name': "dscpToTc", 'dscp': '30', 'config': 'no'}
    input10 = {'map_name': "dscpToTc", 'dscp': '40', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D4], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos322(tc322_uniform_fixture):
    success = True
    tg = tg_dict["tg"]
    for header in ["IPv4", "IPv6"]:
        hdrMsg("test scenario: Test VxLAN QOS uniform mode for known L2 forwarded traffic with {}"
               " header".format(header))
        clear_intf_counters()
        tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='start')
        if header == "IPv4":
            for han in [han_dict["l2_host1"], han_dict["l2_host2"], han_dict["l2_host3"], han_dict["l2_host4"]]:
                tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
            start_traffic(stream_dict["l2_5"] + stream_dict["l2_6"] + stream_dict["l2_7"] + stream_dict["l2_8"])
            hdrMsg("Verify tagged traffic with {} header sent from Tgen port1 of"
               " DUT2 and DUT3".format(header))
            if verify_traffic(tx_stream_list=stream_dict["l2_5"], rx_stream_list=stream_dict["l2_6"]):
                st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos322")
            hdrMsg("Verify L2 untagged traffic with {} header sent from Tgen port2 of "
                   "DUT2 and DUT4".format(header))

            if verify_traffic(tx_port=tg_dict["d2_tg_port2"], rx_port=tg_dict["d4_tg_port2"],
                              tx_stream_list=stream_dict["l2_7"], rx_stream_list=stream_dict["l2_8"]):
                st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos322")
            start_traffic(action="stop", stream_han_list=[stream_dict["l2_5"] + stream_dict["l2_6"] +
                                                          stream_dict["l2_7"] + stream_dict["l2_8"]])
        else:
            for han in [han_dict["l2_host5"], han_dict["l2_host6"], han_dict["l2_host7"], han_dict["l2_host8"]]:
                tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
            start_traffic(stream_dict["l2_9"] + stream_dict["l2_10"] + stream_dict["l2_11"] + stream_dict["l2_12"])
            if verify_traffic(tx_stream_list=stream_dict["l2_9"], rx_stream_list=stream_dict["l2_10"]):
                st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos322")
            if verify_traffic(tx_port=tg_dict["d2_tg_port2"], rx_port=tg_dict["d4_tg_port2"],
                              tx_stream_list=stream_dict["l2_11"], rx_stream_list=stream_dict["l2_12"]):
                st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos322")
            start_traffic(action="stop", stream_han_list=[stream_dict["l2_9"] + stream_dict["l2_10"] +
                                                          stream_dict["l2_11"] + stream_dict["l2_12"]])

        hdrMsg("verify tagged traffic towards DUT3 is queued into UC3 in DUT1")
        if not verify_queuing(vars.D1, [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4], "UC3",
                              val_list=["3500"],tol_list=["2500"]):
            success = False
            st.error("######## FAIL: {} traffic towards DUT3 are NOT queued to UC3".format(header))
        else:
            st.log("######### traffic is queued to UC3 as expected ##########")
        hdrMsg("verify untagged traffic towards DUT4 is queued into UC5 in DUT1")
        if not verify_queuing(vars.D1, [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4], "UC5",
                              val_list=["3500"],tol_list=["2500"]):
            success = False
            st.error("######## FAIL: {} traffic towards DUT4 are NOT queued to UC5".format(header))
        else:
            st.log("######### traffic is queued to UC5 as expected ##########")
        for dut, port, queue,dname in zip([vars.D3, vars.D4], [[vars.D3T1P1], [vars.D4T1P2]],
                                          ["UC3", "UC5"],["DUT3","DUT4"]):
            hdrMsg("verify traffic towards Tgen is queued into {} in {}".format(queue,dname))
            if not verify_queuing(dut, port, queue,val_list=["5000"],tol_list=["4000"]):
                success = False
                st.error("######## FAIL: {} traffic towards TGEN is NOT queued to {} in"
                         " {}".format(header, queue, dname))
            else:
                st.log("######### traffic is queued to {} as expected ##########".format(queue))
        tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='stop')
        pkts_captured1 = tg.tg_packet_stats(port_handle=tg_dict["d3_tg_ph1"], format='var', output_type='hex',
                                            var_num_frames=tg_dict["cap_frames"])
        pkts_captured2 = tg.tg_packet_stats(port_handle=tg_dict["d4_tg_ph2"], format='var', output_type='hex',
                                            var_num_frames=tg_dict["cap_frames"])
        if header == "IPv4":
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured1, offset_list=[30, 19],
                                       value_list=[evpn_dict["leaf1"]["tenant_v4_ip"][0], '78'], var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT3 Rx shows payload TOS hex as 78 for "
                       "L2 forwarded tagged traffic with IPv4 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT3 Rx NOT showing payload TOS hex as 78 for L2 forwarded "
                        "tagged traffic with IPv4 header ########")
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2, offset_list=[26, 15],
                                   value_list=[evpn_dict["leaf1"]["tenant_v4_ip_2"][0], 'A0'], var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT4 Rx shows payload TOS hex as A0 for "
                       "L2 forwarded untagged traffic with IPv4 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT4 Rx NOT showing payload TOS hex as A0 for L2 forwarded "
                         "untagged traffic with IPv4 header ########")
        else:
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured1, offset_list=[18, 19, 26,27,41],
                               value_list=["67", "80", "20","01","02"],var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT3 Rx shows payload TOS hex as 78 for "
                       "L2 forwarded tagged traffic with IPv6 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT3 Rx NOT showing payload TOS hex as 78 for L2 forwarded "
                         "tagged traffic with IPv6 header ########")
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2, offset_list=[14, 15, 22,23,37],
                           value_list=["6A", "00", "20","02","02"], var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT4 Rx shows payload TOS hex as A0 for "
                       "L2 forwarded untagged traffic with IPv6 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT4 Rx NOT showing payload TOS hex as A0 for L2 forwarded "
                         "untagged traffic with IPv6 header ########")
        tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                            tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                            tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
        st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                     [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos322")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos322")


@pytest.fixture(scope="function")
def tc327_pipe_fixture(request, evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp" : "20"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp" : "30"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp" : "40"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])

    input1 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '2'}
    input2 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '3'}
    input3 = {'map_name': "dscpToTc", 'dscp': '40', 'tc': '5'}
    input4 = {'map_name': "dscpToTc", 'dscp': '40', 'tc': '6'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input1,input2])
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input3,input4])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1, evpn_dict["leaf1"]["pch_intf_list"][0], vars.D2D1P4]):
        input3 = {'intf_name': intf1, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        input4 = {'intf_name': intf2, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D2], Qos.bind_qos_map, [input3, input4, input5])
    for interface in [vars.D1D4P1, evpn_dict["spine1"]["pch_intf_list"][2], vars.D1D4P4]:
        Qos.bind_qos_map(vars.D1,interface,map_type="dscp-tc", map_name="dscpToTc")

    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1]]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])
    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf3"]["intf_list_tg"][1]]])
    yield
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf3"]["intf_list_tg"][1]]])
    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1]]])

    st.exec_all([[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])
    start_traffic(action="stop", stream_han_list=[stream_dict["l2_5"] + stream_dict["l2_6"] +
                                              stream_dict["l2_7"] + stream_dict["l2_8"] +
                                              stream_dict["l2_9"] + stream_dict["l2_10"] +
                                              stream_dict["l2_11"] + stream_dict["l2_12"]])
    input_1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input_3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1, input_2, input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                               [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                               [vars.D2D1P1, evpn_dict["leaf1"]["pch_intf_list"][0], vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D2], Qos.bind_qos_map, [input6, input7, input8])
    for interface in [vars.D1D4P1, evpn_dict["spine1"]["pch_intf_list"][2], vars.D1D4P4]:
        Qos.bind_qos_map(vars.D1, interface, map_type="dscp-tc", config="no")
    input9 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    input10 = {'map_name': "dscpToTc", 'dscp': '40', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos327(tc327_pipe_fixture):
    success = True
    tg = tg_dict["tg"]
    for header in ["IPv4", "IPv6"]:
        hdrMsg("test scenario: Test VxLAN QOS pipe mode for known L2 forwarded traffic with {}"
               " header".format(header))
        clear_intf_counters()
        tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='start')
        if header == "IPv4":
            for han in [han_dict["l2_host1"], han_dict["l2_host2"], han_dict["l2_host3"], han_dict["l2_host4"]]:
                tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
            start_traffic(stream_dict["l2_5"] + stream_dict["l2_6"] + stream_dict["l2_7"] + stream_dict["l2_8"])
            hdrMsg("Verify tagged traffic with {} header sent from Tgen port1 of"
               " DUT2 and DUT3".format(header))
            if verify_traffic(tx_stream_list=stream_dict["l2_5"], rx_stream_list=stream_dict["l2_6"]):
                st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos327")
            hdrMsg("Verify L2 untagged traffic with {} header sent from Tgen port2 of "
                   "DUT2 and DUT4".format(header))
            if verify_traffic(tx_port=tg_dict["d2_tg_port2"], rx_port=tg_dict["d4_tg_port2"],
                              tx_stream_list=stream_dict["l2_7"], rx_stream_list=stream_dict["l2_8"]):
                st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
                debug_traffic()
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos327")
            start_traffic(action="stop", stream_han_list=[stream_dict["l2_5"] + stream_dict["l2_6"] +
                                                          stream_dict["l2_7"] + stream_dict["l2_8"]])
        else:
            for han in [han_dict["l2_host5"], han_dict["l2_host6"], han_dict["l2_host7"], han_dict["l2_host8"]]:
                tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
            start_traffic(stream_dict["l2_9"] + stream_dict["l2_10"] + stream_dict["l2_11"] + stream_dict["l2_12"])
            if verify_traffic(tx_stream_list=stream_dict["l2_9"], rx_stream_list=stream_dict["l2_10"]):
                st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos327")
            if verify_traffic(tx_port=tg_dict["d2_tg_port2"], rx_port=tg_dict["d4_tg_port2"],
                              tx_stream_list=stream_dict["l2_11"], rx_stream_list=stream_dict["l2_12"]):
                st.log("######## PASS: Traffic b/w Tgen port2 of DUT2 and DUT4 passed ########")
            else:
                success = False
                st.error("######## FAIL: traffic verification b/w Tgen port2 of DUT2 and DUT4 ########")
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos327")
            start_traffic(action="stop", stream_han_list=[stream_dict["l2_9"] + stream_dict["l2_10"] +
                                                          stream_dict["l2_11"] + stream_dict["l2_12"]])

        hdrMsg("verify tagged traffic towards DUT3 is queued into UC2 in DUT1")
        if not verify_queuing(vars.D1, [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4], "UC2",
                              val_list=["3500"],tol_list=["2500"]):
            success = False
            st.error("######## FAIL: {} traffic towards DUT3 are NOT queued to UC2 in DUT1".format(header))
        else:
            st.log("######### traffic is queued to UC2 as expected ##########")  
        hdrMsg("verify untagged traffic towards DUT2 is queued into UC5 in DUT1")
        if not verify_queuing(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], "UC5",
                              val_list=["3500"],tol_list=["2500"]):
            success = False
            st.error("######## FAIL: {} traffic towards DUT2 are NOT queued to UC5 in DUT1".format(header))
        else:
            st.log("######### traffic is queued to UC5 as expected ##########")
        for dut, port, queue,dname in zip([vars.D3, vars.D2], [[vars.D3T1P1], [vars.D2T1P2]],
                                          ["UC3", "UC6"],["DUT3","DUT2"]):
            hdrMsg("verify traffic towards Tgen is queued into {} in {}".format(queue,dname))
            if not verify_queuing(dut, port, queue,val_list=["5000"],tol_list=["4000"]):
                success = False
                st.error("######## FAIL: {} traffic towards TGEN is NOT queued to {} in"
                         " {}".format(header, queue, dname))
            else:
                st.log("######### traffic is queued to {} as expected ##########".format(queue))
        tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph2"]], action='stop')
        pkts_captured1 = tg.tg_packet_stats(port_handle=tg_dict["d3_tg_ph1"], format='var', output_type='hex',
                                            var_num_frames=tg_dict["cap_frames"])
        pkts_captured2 = tg.tg_packet_stats(port_handle=tg_dict["d4_tg_ph2"], format='var', output_type='hex',
                                            var_num_frames=tg_dict["cap_frames"])
        if header == "IPv4":
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured1, offset_list=[30, 19],
                                       value_list=[evpn_dict["leaf1"]["tenant_v4_ip"][0], '78'],
                                             var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT3 Rx shows payload TOS hex as 78 for "
                       "L2 forwarded tagged traffic with IPv4 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT3 Rx NOT showing payload TOS hex as 78 for L2 forwarded "
                        "tagged traffic with IPv4 header ########")
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2, offset_list=[26, 15],
                                   value_list=[evpn_dict["leaf1"]["tenant_v4_ip_2"][0], 'A0'],
                                             var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT4 Rx shows payload TOS hex as A0 for "
                       "L2 forwarded untagged traffic with IPv4 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT4 Rx NOT showing payload TOS hex as A0 for L2 forwarded "
                         "untagged traffic with IPv4 header ########")
        else:
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured1, offset_list=[18, 19, 26,27,41],
                               value_list=["67", "80", "20","01","02"],var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT3 Rx shows payload TOS hex as 78 for "
                       "L2 forwarded tagged traffic with IPv6 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT3 Rx NOT showing payload TOS hex as 78 for L2 forwarded "
                         "tagged traffic with IPv6 header ########")
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2, offset_list=[14, 15, 22,23,37],
                           value_list=["6A", "00", "20","02","02"], var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT4 Rx shows payload TOS hex as A0 for "
                       "L2 forwarded untagged traffic with IPv6 header #########")
            else:
                success = False
                st.error("######## FAIL: DUT4 Rx NOT showing payload TOS hex as A0 for L2 forwarded "
                         "untagged traffic with IPv6 header ########")
        tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                            tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                            tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
        st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                     [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos327")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos327")


@pytest.fixture(scope="function")
def arp_uniform_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "uniform"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "uniform"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "uniform"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])
    input1 = {'map_name': "dscpToTc", 'dscp': '0', 'tc': '5'}
    input2 = {'map_name': "dscpToTc", 'dscp': '16', 'tc': '2'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input2]*2)
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for interface in [vars.D1D3P1, evpn_dict["spine1"]["pch_intf_list"][1], vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1, interface, map_type="dscp-tc", map_name="dscpToTc")
    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["arp"] + stream_dict["nd"]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1, evpn_dict["leaf1"]["pch_intf_list"][0], vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for interface in [vars.D1D3P1, evpn_dict["spine1"]["pch_intf_list"][1], vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1, interface, map_type="dscp-tc", config="no")
    input9 = {'map_name': "dscpToTc", 'dscp': '16', 'config': 'no'}
    input10 = {'map_name': "dscpToTc", 'dscp': '0', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], Qos.config_qos_dscp_tc, [input9] * 2)
    parallel.exec_parallel(True, [vars.D1,vars.D3], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos324(arp_uniform_fixture):
    success = True
    tg = tg_dict["tg"]
    for proto in ["ARP","ND"]:
        st.exec_all([[Mac.clear_mac,vars.D2],[Mac.clear_mac,vars.D3],[Mac.clear_mac,vars.D4]])
        st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                     [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
        hdrMsg("test scenario: Test VxLAN QOS uniform mode for {}".format(proto))
        clear_intf_counters()
        if proto == "ND":
            tg.tg_packet_control(port_handle=tg_dict["d2_tg_ph1"], action='start')
            st.log("######## initiate ND from D3 Tgen port1 ########")
            start_traffic(stream_han_list=[stream_dict["nd"]])
            st.wait(5)
            if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][0],
                                            mac_addr=evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][0],
                                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                            dest_ip=evpn_dict["leaf2"]["loop_ip_list"][1]):
                st.log("########## MAC {} present in D2; ND solicitation from D3 to D2 "
                       "sent ##########".format(evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][0]))
            else:
                success = False
                st.error("########## FAIL: MAC {} NOT present in D2, ND solicitation from D3 to D2"
                         " NOT sent ##########".format(evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][0]))
            tg.tg_packet_control(port_handle=tg_dict["d2_tg_ph1"], action='stop')
            st.wait(10)
            if not verify_queuing(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], "UC2"):
                success = False
                st.error("######## FAIL: {} towards DUT2 is not queued into UC2 in "
                             "DUT1 ########".format(proto))
            else:
                st.log("######### ND is queued to UC2 as expected ##########")
            if not verify_queuing(vars.D2,[vars.D2T1P1] , "MC12"):
                success = False
                st.error("######## FAIL: {} towards TGEN is not queued into MC12 in DUT2".format(proto))
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos324")
            else:
                st.log("######### {} traffic is queued to MC12 as expected ##########".format(proto))
            pkts_captured2 = tg.tg_packet_stats(port_handle=tg_dict["d2_tg_ph1"], format='var', output_type='hex',
                                                var_num_frames=tg_dict["cap_frames"])
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2,
                                             offset_list=[16, 17, 18, 19, 26, 27, 41],
                                             value_list=["86", "DD", "64", "00", "30", "02", "02"],
                                             var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT2 Rx shows payload DSCP as 16 for ND ########")
            else:
                success = False
                st.error("######## FAIL: DUT2 Rx NOT showing payload DSCP as 16 for ND ########")
        else:
            st.log("######## initiate ARP from D2 Tgen port1 ########")
            start_traffic(stream_han_list=[stream_dict["arp"]])
            st.wait(5)
            if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][1],
                                    mac_addr=evpn_dict["leaf1"]["tenant_mac_v4_colon"],
                                    vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf1"]["loop_ip_list"][1]):
                st.log("########## MAC {} present in D3;ARP request from D2 to D3 "
                       "sent ##########".format(evpn_dict["leaf1"]["tenant_mac_v4_colon"]))
            else:
                success=False
                st.log("########## FAIL: MAC {} NOT present in D3, ARP request from D2 to D3"
                       " is not sent ##########".format(evpn_dict["leaf1"]["tenant_mac_v4_colon"]))
            st.wait(10)
            if not verify_queuing(vars.D1, [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4], "UC5"):
                success = False
                st.error("######## FAIL: {} towards DUT3 is NOT queued into UC5 in "
                             "DUT1 ########".format(proto))
            else:
                st.log("######### {} traffic is queued to UC5 as expected ##########".format(proto))
            if not verify_queuing(vars.D3,[vars.D3T1P1] , "MC15"):
                success = False
                st.error("######## FAIL: {} towards TGEN is not queued into MC15 in DUT3".format(proto))
            else:
                st.log("######### {} traffic is queued to MC15 as expected ##########".format(proto))

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos324")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos324")


@pytest.fixture(scope="function")
def arp_pipe_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"],tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"],tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"],tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "30"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "48"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])
    input1 = {'map_name': "dscpToTc", 'dscp': '30', 'tc': '3'}
    input2 = {'map_name': "dscpToTc", 'dscp': '30', 'tc': '2'}
    input3 = {'map_name': "dscpToTc", 'dscp': '48', 'tc': '6'}
    input4 = {'map_name': "dscpToTc", 'dscp': '48', 'tc': '5'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1,input2])
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input3,input4])
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name': intf3, "map_type": "dscp-tc", "map_name": "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for interface in [vars.D1D3P1, evpn_dict["spine1"]["pch_intf_list"][1], vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1, interface, map_type="dscp-tc", map_name="dscpToTc")
    yield
    start_traffic(action="stop",stream_han_list=[stream_dict["arp"] + stream_dict["nd_2"]])
    input_1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input_3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input_1,input_2,input_3])

    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1, evpn_dict["leaf1"]["pch_intf_list"][0], vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3, vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for interface in [vars.D1D3P1, evpn_dict["spine1"]["pch_intf_list"][1], vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1, interface, map_type="dscp-tc", config="no")
    input9 = {'map_name': "dscpToTc", 'dscp': '30', 'config': 'no'}
    input10 = {'map_name': "dscpToTc", 'dscp': '48', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1,vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    parallel.exec_parallel(True, [vars.D1,vars.D2], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos329(arp_pipe_fixture):
    success = True
    tg = tg_dict["tg"]
    for proto in ["ARP", "ND"]:
        st.exec_all([[Mac.clear_mac, vars.D2], [Mac.clear_mac, vars.D3], [Mac.clear_mac, vars.D4]])
        st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                     [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
        hdrMsg("test scenario: Test VxLAN QOS pipe mode for {}".format(proto))
        clear_intf_counters()
        if proto == "ND":
            tg.tg_packet_control(port_handle=tg_dict["d2_tg_ph1"], action='start')
            st.log("######## initiate ND from D3 Tgen port1 ########")
            start_traffic(stream_han_list=[stream_dict["nd_2"]])
            st.wait(15)
            if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][0],
                                            mac_addr=evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][1],
                                            vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                            dest_ip=evpn_dict["leaf2"]["loop_ip_list"][1]):
                st.log("########## MAC {} present in D2; ND solicitation from D3 to D2 "
                       "sent ##########".format(evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][1]))
            else:
                success = False
                st.error("########## FAIL: MAC {} NOT present in D2, ND solicitation from D3 to D2"
                         " sent ##########".format(evpn_dict["leaf2"]["tenant_mac_v6_colon_2"][1]))
            tg.tg_packet_control(port_handle=tg_dict["d2_tg_ph1"], action='stop')
            if not verify_queuing(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], "UC6",
                                  val_list=["5000"],tol_list=["4000"]):
                success = False
                st.error("######## FAIL: {} towards DUT2 is not queued into UC6 in "
                         "DUT1 ########".format(proto))
            else:
                st.log("######### ND is queued to UC6 as expected ##########")
            if not verify_queuing(vars.D2, [vars.D2T1P1], "MC15"):
                success = False
                st.error("######## FAIL: {} towards TGEN is not queued into MC15 in DUT2".format(proto))
                st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos329")
            else:
                st.log("######### {} traffic is queued to MC15 as expected ##########".format(proto))
            pkts_captured2 = tg.tg_packet_stats(port_handle=tg_dict["d2_tg_ph1"], format='var', output_type='hex',
                                                var_num_frames=tg_dict["cap_frames"])
            if tgapi.validate_packet_capture(tg_type=tg.tg_type, pkt_dict=pkts_captured2,
                                             offset_list=[16, 17, 18, 19, 26, 27, 41],
                                             value_list=["86", "DD", "69", "00", "30", "02", "02"],
                                             var_num_frames=tg_dict["cap_frames"]):
                st.log("######### PASS: DUT2 Rx shows payload TOS hex as 90 for ND ########")
            else:
                success = False
                st.error("######## FAIL: DUT2 Rx NOT showing payload TOS hex as 90 for ND ########")
        else:
            st.log("######## initiate ARP from D2 Tgen port1 ########")
            start_traffic(stream_han_list=[stream_dict["arp"]])
            st.wait(15)
            if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][1],
                                            mac_addr=evpn_dict["leaf1"]["tenant_mac_v4_colon"],
                                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][1]):
                st.log("########## MAC {} present in D3;ARP request from D2 to D3 "
                       "sent ##########".format(evpn_dict["leaf1"]["tenant_mac_v4_colon"]))
            else:
                success = False
                st.log("########## FAIL: MAC {} NOT present in D3, ARP request from D2 to D3"
                       " is not sent ##########".format(evpn_dict["leaf1"]["tenant_mac_v4_colon"]))
            if not verify_queuing(vars.D1, [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4], "UC3",
                                  val_list=["5000"],tol_list=["4000"]):
                success = False
                st.error("######## FAIL: {} towards DUT3 is NOT queued into UC3 in "
                         "DUT1 ########".format(proto))
            else:
                st.log("######### {} traffic is queued to UC3 as expected ##########".format(proto))
            if not verify_queuing(vars.D3, [vars.D3T1P1], "MC12"):
                success = False
                st.error("######## FAIL: {} towards TGEN is not queued into MC12 in DUT3".format(proto))
            else:
                st.log("######### {} traffic is queued to MC12 as expected ##########".format(proto))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos329")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos329")


def test_FtOpSoRoEvpnQos325(l2_uniform_fixture):
    success = True
    tg = tg_dict["tg"]
    st.exec_all([[Mac.clear_mac,vars.D2],[Mac.clear_mac,vars.D3],[Mac.clear_mac,vars.D4]])
    hdrMsg("test scenario: Test VxLAN QOS uniform mode for BUM")
    clear_intf_counters()
    start_traffic(stream_dict["l2_1"])
    st.wait(5)
    traffic_details = {
        '1': {
            'tx_ports': [tg_dict["d2_tg_port1"]],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d3_tg_port1"]],
            'rx_obj': [tg],
            'stream_list': [(stream_dict["l2_1"])]
        },
        '2': {
            'tx_ports': [tg_dict["d2_tg_port1"]],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d4_tg_port1"]],
            'rx_obj': [tg],
            'stream_list': [(stream_dict["l2_1"])]
        },
    }
    hdrMsg("Verify BUM traffic from Tgen port1 of DUT2 towards D3 & D4")
    if tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate",
                             comp_type="packet_count", tolerance_factor=1):
        st.log("######## PASS: BUM Traffic from Tgen port1 of DUT2 towards DUT3 & DUT$ passed ########")
    else:
        success=False
        st.error("######## FAIL: BUM Traffic from Tgen port1 of DUT2 towards DUT3/DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos325")
    hdrMsg("verify BUM traffic egerss via \"MC12\" n DUT2")
    if not verify_queuing(vars.D2,[vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4] , "MC12",
                      val_list=["10000"],tol_list=["1000"]):
        success = False
        st.error("######## FAIL: BUM traffic is not queued into MC12 in DUT2")
    else:
        st.log("######### traffic is queued to MC12 as expected ##########")
    for port,queue,todut in zip([[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                 [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]],
                                ["UC5"]*2,["DUT3","DUT4"]):
        hdrMsg("verify BUM traffic towards {} is queued into {} in DUT1".format(todut,queue))
        if not verify_queuing(vars.D1,port,queue):
            success = False
            st.error("######## FAIL: BUM towards {} is not queued into {} in "
                     "DUT1 ########".format(todut,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D4],[[vars.D3T1P1],[vars.D4T1P2]],["MC15"]*2,["DUT3","DUT4"]):
        hdrMsg("verify BUM traffic towards TGEN is queued into {} in {}".format(queue,dname))
        if not verify_queuing(dut,port,queue):
            success = False
            st.error("######## FAIL: BUM towards TGEN is not queued into {} in {}".format(queue,dname))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos325")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos325")


def test_FtOpSoRoEvpnQos3210(l2_pipe_fixture):
    success = True
    tg = tg_dict["tg"]
    st.exec_all([[Mac.clear_mac,vars.D2],[Mac.clear_mac,vars.D3],[Mac.clear_mac,vars.D4]])
    hdrMsg("test scenario: Test VxLAN QOS pipe mode for BUM")
    clear_intf_counters()
    start_traffic(stream_dict["l2_1"])
    st.wait(5)
    traffic_details = {
        '1': {
            'tx_ports': [tg_dict["d2_tg_port1"]],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d3_tg_port1"]],
            'rx_obj': [tg],
            'stream_list': [(stream_dict["l2_1"])]
        },
        '2': {
            'tx_ports': [tg_dict["d2_tg_port1"]],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d4_tg_port1"]],
            'rx_obj': [tg],
            'stream_list': [(stream_dict["l2_1"])]
        },
    }
    hdrMsg("Verify BUM traffic from Tgen port1 of DUT2 towards D3 & D4")
    if tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate",
                             comp_type="packet_count", tolerance_factor=1):
        st.log("######## PASS: BUM Traffic from Tgen port1 of DUT2 towards DUT3 & DUT$ passed ########")
    else:
        success=False
        st.error("######## FAIL: BUM Traffic from Tgen port1 of DUT2 towards DUT3/DUT4 ########")
        debug_traffic()
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3210")
    hdrMsg("verify BUM traffic egerss via \"MC12\" n DUT2")
    if not verify_queuing(vars.D2,[vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4] , "MC12",
                      val_list=["10000"],tol_list=["1000"]):
        success = False
        st.error("######## FAIL: BUM traffic is not queued into MC12 in DUT2")
    else:
        st.log("######### traffic is queued to MC12 as expected ##########")
    for port,queue,todut in zip([[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                 [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3,vars.D1D4P4]],
                                ["UC3"]*2,["DUT3","DUT4"]):
        hdrMsg("verify BUM traffic towards {} is queued into {} in DUT1".format(todut,queue))
        if not verify_queuing(vars.D1,port,queue):
            success = False
            st.error("######## FAIL: BUM towards {} is not queued into {} in "
                     "DUT1 ########".format(todut,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D4],[[vars.D3T1P1],[vars.D4T1P2]],["MC13"]*2,["DUT3","DUT4"]):
        hdrMsg("verify BUM traffic towards TGEN is queued into {} in {}".format(queue,dname))
        if not verify_queuing(dut,port,queue):
            success = False
            st.error("######## FAIL: BUM towards TGEN is not queued into {} in "
                     "{} ########".format(queue,dname))   
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3210")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3210")


@pytest.fixture(scope="function")
def mixed_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "uniform"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "20"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    input1 = {'map_name': "dscpToTc", 'dscp': '32', 'tc': '4'}
    input2 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '2'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input2]*2)
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name' : intf3, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]: 
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc")    
    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    input1 = {"vtep_name" : evpn_dict["leaf1"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input2 = {"vtep_name" : evpn_dict["leaf2"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    input3 = {"vtep_name" : evpn_dict["leaf3"]["vtepName"], "qos_mode" : "pipe", "pipe_dscp" : "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1,input2,input3])
    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"} 
        parallel.exec_parallel(True, [vars.D1, vars.D3,vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc",config="no")
    input9 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input9] * 2)
    input10 = {'map_name': "dscpToTc", 'dscp': '32', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input10] * 2)    


def test_FtOpSoRoEvpnQos341_2(mixed_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS with warm reboot")
    clear_intf_counters()
    for han in [han_dict["v4_host2"],han_dict["v6_host1"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v6_2"])

    hdrMsg("Verify traffic from Tgen port1 of DUT2 towards D3 Tgen port1")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"], rx_stream_list=stream_dict["v6_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: Traffic b/w Tgen port1 of DUT2 and DUT3 failed ########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos341")

    for port,dname,queue in zip([[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                 [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]],
                                ["DUT3","DUT2"],["UC4","UC2"]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1".format(dname,queue))
        if not utils.retry_api(verify_queuing,vars.D1, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards {} is NOT queued to {} in DUT1".format(dname,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D2],[[vars.D3T1P1],[vars.D2T1P1]],["UC4","UC2"],["DUT3","DUT2"]):
        hdrMsg("verify traffic towards TGEN is queued into {} in {}".format(queue,dname))
        if not utils.retry_api(verify_queuing,dut, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards TGEN is NOT queued into {} in {}".format(queue,dname))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    hdrMsg("configure graceful restart in all nodes")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp_graceful_restart,
                           [{"local_asn": evpn_dict["spine1"]["local_as"], "config": 'add',"preserve_state" : "yes"},
                            {"local_asn": evpn_dict["leaf1"]["local_as"], "config": 'add', "preserve_state" : "yes"},
                            {"local_asn": evpn_dict["leaf2"]["local_as"], "config": 'add', "preserve_state" : "yes"},
                            {"local_asn": evpn_dict["leaf3"]["local_as"], "config": 'add', "preserve_state" : "yes"}])
    hdrMsg("######## clearing BGP neighbors after configuring graceful restart ###########")
    st.exec_all([[Bgp.clear_ip_bgp_vtysh, vars.D1], [Bgp.clear_ip_bgp_vtysh, vars.D2],
                          [Bgp.clear_ip_bgp_vtysh, vars.D3], [Bgp.clear_ip_bgp_vtysh, vars.D4]])
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                 retry_count=6, delay=5):
        st.log("##### VXLAN tunnel towards D3 is UP as expected after clearing BGP#####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D3 is DOWN after clearing BGP ##########")
    reboot_api.config_save(vars.D2)
    reboot_api.config_save(vars.D2,shell="vtysh")
    st.reboot(vars.D2, 'warm')
    st.wait(30)
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                 retry_count=3, delay=30):
        st.log("##### VXLAN tunnel towards D3 is UP as expected after warm reboot #####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D3 is DOWN after warm reboot ##########")
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    hdrMsg("Verify traffic from Tgen port1 of DUT2 towards D3 Tgen port1")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"], rx_stream_list=stream_dict["v6_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after warm reboot########")
    else:
        success=False
        st.error("######## FAIL: Traffic b/w Tgen port1 of DUT2 and DUT3 failed after warm reboot########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos341")
    for port,dname,queue in zip([[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                 [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]],
                                ["DUT3","DUT2"],["UC4","UC2"]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1 after warm reboot".format(dname,queue))
        if not utils.retry_api(verify_queuing,vars.D1, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards {} is NOT queued to {} in DUT1 "
                     "after warm reboot".format(dname,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D2],[[vars.D3T1P1],[vars.D2T1P1]],["UC4","UC2"],["DUT3","DUT2"]):
        hdrMsg("verify traffic towards TGEN is queued into {} in {} after warm reboot".format(queue,dname))
        if not utils.retry_api(verify_queuing,dut, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards TGEN is NOT queued into {} in "
                     "{} after warm reboot".format(queue,dname))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if success:
        st.report_tc_pass("FtOpSoRoEvpnQos341", "tc_passed")
    hdrMsg("test scenario: Test VxLAN QOS with config reload")
    reboot_api.config_reload(vars.D2)
    st.wait(30)
    if utils.retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                 src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                 retry_count=3, delay=30):
        st.log("##### VXLAN tunnel towards D3 is UP as expected after config reload #####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D3 is DOWN after config reload ##########")
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    start_traffic(stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    hdrMsg("Verify traffic from Tgen port1 of DUT2 towards D3 Tgen port1")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"], rx_stream_list=stream_dict["v6_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed after config reload########")
    else:
        success=False
        st.error("######## FAIL: Traffic b/w Tgen port1 of DUT2 and DUT3 failed after config reload########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos341")
    for port,dname,queue in zip([[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                 [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]],
                                ["DUT3","DUT2"],["UC4","UC2"]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1 after config reload".format(dname,queue))
        if not utils.retry_api(verify_queuing,vars.D1, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards {} is NOT queued to {} in DUT1 "
                     "after config reload".format(dname,queue))
        else:
            st.log("######### traffic is queued to {} as expected after config reload ##########".format(queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D2],[[vars.D3T1P1],[vars.D2T1P1]],["UC4","UC2"],["DUT3","DUT2"]):
        hdrMsg("verify traffic towards TGEN is queued into {} in {} after config reload".format(queue,dname))
        if not utils.retry_api(verify_queuing,dut, port_list=port, queue=queue,retry_count=3, delay=10):
            success = False
            st.error("######## FAIL: traffic towards TGEN is NOT queued into {} in "
                     "{} after config reload".format(queue,dname))
        else:
            st.log("######### traffic is queued to {} as expected after config reload ##########".format(queue))
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos341_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos341_2")


@pytest.fixture(scope="function")
def scale_fixture(request, evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "uniform"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "20"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    input1 = {'map_name': "dscpToTc", 'dscp': '0', 'tc': '1'}
    input2 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '2'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1]*2)
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input2]*2)
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name' : intf3, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc")
    hdrMsg(" \n####### Create 4K vlans in D2 and D3 ##############\n")
    st.exec_all([[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "600 4020", "add", "False"],
                          [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "600 4020", "add", "False"]])

    hdrMsg(" \n####### Bind tenant L2 VLANs to port in D2 and D3 ##############\n")
    st.exec_all([[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "600 4020",
                           evpn_dict["leaf1"]["intf_list_tg"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "600 4020",
                           evpn_dict["leaf2"]["intf_list_tg"][0], 'add', 'False']])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni in D2 and D3 #######/n")
    ############################################################################################
    st.exec_all([
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "600", "600", '3419'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "600", "600", '3419']])
    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["scale_1"] + stream_dict["scale_2"]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3,vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc",config="no")
    input9 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input9] * 2)
    input10 = {'map_name': "dscpToTc", 'dscp': '0', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input10] * 2)

    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni in D3,D4 and D6 #######/n")
    ############################################################################################
    st.exec_all([
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "600", "600", '3419', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "600", "600", '3419', 'no']])
    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port in D3,D4 and D6 ##############\n")
    ############################################################################################
    st.exec_all([[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "600 4020",
                           evpn_dict["leaf1"]["intf_list_tg"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "600 4020",
                           evpn_dict["leaf2"]["intf_list_tg"][0], 'del']])
    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs in D2 and D3 ##############\n")
    ############################################################################################
    st.exec_all([[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "600 4020", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "600 4020", 'del']])


def test_FtOpSoRoEvpnQos331(scale_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS for max number of 4K VLANs")
    st.wait(360, "need to wait for some time for all 4K Vxlan net devices to be online")
    clear_intf_counters()
    start_traffic(stream_dict["scale_1"] + stream_dict["scale_2"])

    hdrMsg("Verify traffic from Tgen port1 of DUT2 towards D3 Tgen port1")
    if verify_traffic(tx_stream_list=stream_dict["scale_1"], rx_stream_list=stream_dict["scale_2"]):
        st.log("######## PASS: Traffic from Tgen port1 of DUT2 towards DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: Traffic from Tgen port1 of DUT2 towards DUT3 ########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos331")

    for port,dname,queue in zip([[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                 [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]],
                                ["DUT3","DUT2"],["UC1","UC2"]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1".format(dname,queue))
        if not verify_queuing(vars.D1, port, queue):
            success = False
            st.error("######## FAIL: traffic towards {} is NOT queued to {} in DUT1".format(dname,queue))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,port,queue,dname,queue1 in zip([vars.D3,vars.D2],[[vars.D3T1P1],[vars.D2T1P1]],
                                           ["UC1","UC2"],["DUT3","DUT2"],["MC11","MC12"]):
        hdrMsg("verify traffic towards TGEN is queued into {} in {}".format(queue,dname))
        if verify_queuing(dut, port, queue,val_list=["5000"],tol_list=["4000"]) or \
                verify_queuing(dut, port, queue1,val_list=["5000"],tol_list=["4000"]):
            st.log("######### traffic is queued to {} or {} as expected ######"
                   "####".format(queue, queue1))
        else:
            success = False
            st.error("######## FAIL: traffic towards TGEN is NOT queued into {} or {} "
                     "in {}".format(queue, queue1, dname))
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos331")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos331")


@pytest.fixture(scope="function")
def icmp_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "uniform"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "20"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    input1 = {'map_name': "dscpToTc", 'dscp': '46', 'tc': '5'}
    input2 = {'map_name': "dscpToTc", 'dscp': '46', 'tc': '1'}
    input3 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '2'}
    input4 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '6'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1,input2])
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input3,input4])
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name' : intf3, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc")
    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4ping_1"] + stream_dict["v6ping_1"]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3,vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc",config="no")

    input9 = {'map_name': "dscpToTc", 'dscp': '46', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    input10 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos3217(icmp_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS for ping packet in both PIPE and Uniform mode")
    clear_intf_counters()
    start_traffic(stream_dict["v4ping_1"] + stream_dict["v6ping_1"])

    hdrMsg("Verify traffic from Tgen port1 of DUT2 towards D3 Tgen port1")
    if verify_traffic(tx_stream_list=stream_dict["v4ping_1"] ,rx_stream_list=stream_dict["v6ping_1"]):
        st.log("######## PASS: ping traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: ping traffic b/w Tgen port1 of DUT2 and DUT3 failed ########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3217")
    for port,dname,queue in zip([[vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4],
                                 [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]],
                                ["DUT3","DUT2"],["UC5","UC2"]):
        hdrMsg("verify traffic towards {} is queued into {} in DUT1".format(dname,queue))
        if verify_queuing(vars.D1, port, queue) or verify_queuing(vars.D1, port, queue,
                                                                          val_list=["10000"],tol_list=["1000"]):
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
        else:
            success = False
            st.error("######## FAIL: traffic towards {} is NOT queued to {} in DUT1".format(dname, queue))
    for dut,port,queue,dname in zip([vars.D3,vars.D2],[[vars.D3T1P1],[vars.D2T1P1]],["UC1","UC6"],["DUT3","DUT2"]):
        hdrMsg("verify traffic towards TGEN is queued into {} in {}".format(queue,dname))
        if verify_queuing(dut, port, queue) or verify_queuing(dut, port,
                                                                      queue,val_list=["10000"],tol_list=["1000"]):
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
        else:
            success = False
            st.error("######## FAIL: traffic towards TGEN is NOT queued into {} in {}".format(queue, dname))

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnQos3217")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3217")


@pytest.fixture(scope="function")
def remark_fixture(request,evpn_qos_hooks):
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d2_tg_ph1"], tg_dict["d2_tg_ph2"],
                                                                        tg_dict["d3_tg_ph1"], tg_dict["d3_tg_ph2"],
                                                                        tg_dict["d4_tg_ph1"], tg_dict["d4_tg_ph2"]])
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "uniform"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "20"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "30"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    for acl,ip_type,dut,cname,pname,intf_name,intf2 in zip(["aclDscp","aclDscpv6"],["ip","ipv6"],[vars.D2,vars.D3],
                                                     ["classDscp","classDscpv6"],["polDscp","polDscpv6"],
                                                     ["Vlan 200", "Vlan 300"],["Vlan200", "Vlan300"]):
        aclObj=ip.AccessList(acl,ip_type)
        aclObj.add_match_permit_sequence("any")
        aclObj.config_command_string()
        aclObj.execute_command(dut)
        cli_type = st.get_ui_type(dut)
        if cli_type in ["rest-put","rest-patch"]:
            dscp.config_classifier_table(dut=dut,class_name=cname, acl_type=ip_type,enable="add",
                                         class_criteria=['acl'],criteria_value=[acl],match_type="acl")
        else:
            dscp.config_classifier_table(dut=dut,class_name=cname, acl_type=ip_type,enable="add",
                                                             class_criteria=['acl'],criteria_value=[acl])
        dscp.config_policy_table(dut,policy_name=pname,policy_type="qos",enable="create")
        if cli_type in ["rest-put","rest-patch"]:
            dscp.config_flow_update_table(dut,policy_name=pname,class_name=cname,flow="add",
                    flow_priority="48",priority_option=["dscp"],priority_value="48",
                    policy_type="qos")
            dscp.config_service_policy_table(dut,interface_name=intf2,service_policy_name=pname,
                    policy_kind="bind")
        else:
            dscp.config_flow_update_table(dut,policy_name=pname,class_name=cname,flow="add",
                    flow_priority="48",priority_option=["dscp"],priority_value="48")
            dscp.config_service_policy_table(dut,interface_name=intf_name,service_policy_name=pname,
                    policy_kind="bind")
    input1 = {'map_name': "dscpToTc", 'dscp': '48', 'tc': '6'}
    input2 = {'map_name': "dscpToTc", 'dscp': '48', 'tc': '5'}
    input3 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '2'}
    input4 = {'map_name': "dscpToTc", 'dscp': '20', 'tc': '1'}
    parallel.exec_parallel(True, [vars.D1,vars.D3],Qos.config_qos_dscp_tc,[input1,input2])
    parallel.exec_parallel(True, [vars.D1,vars.D2],Qos.config_qos_dscp_tc,[input3,input4])
    for intf1,intf2,intf3 in zip([vars.D1D2P1,evpn_dict["spine1"]["pch_intf_list"][0],vars.D1D2P4],
                                 [vars.D3D1P1,evpn_dict["leaf2"]["pch_intf_list"][0],vars.D3D1P4],
                                 [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input3 = {'intf_name' : intf1, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input4 = {'intf_name' : intf2, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        input5 = {'intf_name' : intf3, "map_type" : "dscp-tc", "map_name" : "dscpToTc"}
        parallel.exec_parallel(True, [vars.D1,vars.D3,vars.D2], Qos.bind_qos_map, [input3,input4,input5])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc")
    yield
    start_traffic(action="stop", stream_han_list=[stream_dict["v4_1"] + stream_dict["v6_2"]])
    input1 = {"vtep_name": evpn_dict["leaf1"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input2 = {"vtep_name": evpn_dict["leaf2"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    input3 = {"vtep_name": evpn_dict["leaf3"]["vtepName"], "qos_mode": "pipe", "pipe_dscp": "0"}
    parallel.exec_parallel(True, [vars.D2, vars.D3, vars.D4], Evpn.config_vxlan_qos_mode, [input1, input2, input3])
    for acl,ip_type,dut,cname,pname,intf_name in zip(["aclDscp","aclDscpv6"],["ip","ipv6"],[vars.D2,vars.D3],
                                                     ["classDscp","classDscpv6"],["polDscp","polDscpv6"],
                                                     ["Vlan 200", "Vlan 300"]):
        dscp.config_service_policy_table(dut,interface_name=intf_name,service_policy_name=pname,
                                         policy_kind="unbind")
        dscp.config_policy_table(dut,policy_name=pname,policy_type="qos",enable="del")
        dscp.config_classifier_table(dut=vars.D2,class_name="classDscp", acl_type="ip",enable="del")
        aclObj.unconfig_command_string()
        aclObj.execute_command(dut,config="no")
    for intf1, intf2, intf3 in zip([vars.D1D2P1, evpn_dict["spine1"]["pch_intf_list"][0], vars.D1D2P4],
                                   [vars.D3D1P1, evpn_dict["leaf2"]["pch_intf_list"][0], vars.D3D1P4],
                                   [vars.D2D1P1,evpn_dict["leaf1"]["pch_intf_list"][0],vars.D2D1P4]):
        input6 = {'intf_name': intf1, "map_type": "dscp-tc", "config": "no"}
        input7 = {'intf_name': intf2, "map_type": "dscp-tc", "config": "no"}
        input8 = {'intf_name': intf3, "map_type": "dscp-tc", "config": "no"}
        parallel.exec_parallel(True, [vars.D1, vars.D3,vars.D2], Qos.bind_qos_map, [input6,input7,input8])
    for intf1 in [vars.D1D3P1,evpn_dict["spine1"]["pch_intf_list"][1],vars.D1D3P4]:
        Qos.bind_qos_map(vars.D1,intf_name=intf1,map_type="dscp-tc",map_name="dscpToTc",config="no")

    input9 = {'map_name': "dscpToTc", 'dscp': '48', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D3], Qos.config_qos_dscp_tc, [input9] * 2)
    input10 = {'map_name': "dscpToTc", 'dscp': '20', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], Qos.config_qos_dscp_tc, [input10] * 2)


def test_FtOpSoRoEvpnQos3219(remark_fixture):
    success = True
    hdrMsg("test scenario: Test VxLAN QOS with ACL DSCP remarking")
    st.exec_all([[Intf.clear_queue_counters, vars.D1], [Intf.clear_queue_counters, vars.D2],
                 [Intf.clear_queue_counters, vars.D3], [Intf.clear_queue_counters, vars.D4]])
    clear_intf_counters()
    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d2_tg_ph1"]], action='start')
    for han in [han_dict["v4_host2"],han_dict["v6_host1"]]:
        tg_dict["tg"].tg_arp_control(handle=han, arp_target='all')
    start_traffic(stream_dict["v4_1"] + stream_dict["v6_2"])
    hdrMsg("Verify L3 forwarded IPv4 traffic sent from Tgen port1 of DUT2 and DUT3")
    if verify_traffic(tx_stream_list=stream_dict["v4_1"],rx_stream_list=stream_dict["v6_2"]):
        st.log("######## PASS: Traffic b/w Tgen port1 of DUT2 and DUT3 passed ########")
    else:
        success=False
        st.error("######## FAIL: traffic verification b/w Tgen port1 of DUT2 and DUT3 ########")
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnQos3219")
    tg_dict["tg"].tg_packet_control(port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d2_tg_ph1"]], action='stop')
    pkts_captured1 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d3_tg_ph1"],
                                                   format='var', output_type='hex',var_num_frames=tg_dict["cap_frames"])
    pkts_captured2 = tg_dict["tg"].tg_packet_stats(port_handle=tg_dict["d2_tg_ph1"],
                                                   format='var', output_type='hex',var_num_frames=tg_dict["cap_frames"])

    for proto,to_dut,queue,dscp,port in zip(["IPv4","IPv6"],["DUT3","DUT2"],["UC6","UC2"],["48","20"],
                                            [[vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4],
                                             [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]]):
        hdrMsg("verify {} traffic towards {} is queued by outer DSCP value {} in DUT1".format(proto,to_dut,dscp))
        if not verify_queuing(vars.D1,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards {} are NOT queued to {} as per outer"
                     " DSCP {} in DUT1 ########".format(proto,to_dut,queue,dscp))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    for dut,proto,queue,dscp,port in zip([vars.D3,vars.D2],["IPv4","IPv6"],["UC5","UC1"],["48","20"],
                                            [[vars.D3T1P1],[vars.D2T1P1]]):
        hdrMsg("verify {} traffic towards Tgen is queued by outer header DSCP value {} in {}".format(proto,dscp,dut))
        if not verify_queuing(dut,port,queue):
            success=False
            st.error("######## FAIL: {} traffic towards Tgen are NOT queued to {} as per outer"
                     " DSCP {} in {} ########".format(proto,queue,dscp,dut))
        else:
            st.log("######### traffic is queued to {} as expected ##########".format(queue))
    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured1,
                                     offset_list=[30, 19],value_list=[evpn_dict["leaf1"]["tenant_v4_ip"][0], 'C0'],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 0xC0 for IPv4 tenant traffic #########")
    else:
        success=False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 0xC0 for IPv4 tenant traffic ########")

    if tgapi.validate_packet_capture(tg_type=tg_dict["tg"].tg_type, pkt_dict=pkts_captured2,
                                     offset_list=[18, 19,26,27,41],value_list=["6C","00","30","01","02"],
                                     var_num_frames=tg_dict["cap_frames"]):
        st.log("######### PASS: DUT3 Rx shows payload TOS as 0xC0 for IPv6 tenant traffic #########")
    else:
        success=False
        st.error("######## FAIL: DUT3 Rx NOT showing payload TOS as 0xC0 for IPv6 tenant traffic ########")
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnQos3219")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnQos3219")
