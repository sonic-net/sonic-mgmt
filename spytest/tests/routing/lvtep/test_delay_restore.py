import pytest
import datetime
from spytest import st, utils
from spytest.dicts import SpyTestDict
import apis.routing.evpn as Evpn
from apis.system import basic
import apis.system.reboot as reboot
import apis.routing.ip as Ip
import apis.switching.mac as Mac
from utilities import parallel
from evpn_rlvtep import *
from evpn_rlvtep_underlay_base_cfg import *
import apis.switching.portchannel as pch
import apis.system.interface as Intf
scale = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def evpn_underlay_hooks(request):
    global vars
    create_glob_vars()
    vars = st.get_testbed_vars()
    api_list = [[create_stream_delay_restore], [config_evpn_lvtep_5549]]
    parallel.exec_all(True, api_list, True)
    st.log("verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                            mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                            mclag_intfs=1)

    st.log("verify MC LAG interface status in LVTEP nodes")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up",
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up",
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("verify SAG IP status in LVTEP nodes")
    sag.verify_sag(evpn_dict["leaf_node_list"][0], total=1, mac=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status='enable',
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0])

    sag.verify_sag(evpn_dict["leaf_node_list"][1], total=1, mac=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status='enable',
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0])

    sag.verify_sag(evpn_dict["leaf_node_list"][0], total=1, status='enable',ip_type='ipv6',
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0])

    sag.verify_sag(evpn_dict["leaf_node_list"][1], total=1, status='enable',ip_type='ipv6',
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0])

    verify1 = {"identifier": evpn_dict["spine1"]["loop_ip_list"][1],
                "neighbor": data.leaf_spine1_ipv6_list,
                "updown": ["up", "up", "up", "up"]}

    verify2 = {"identifier": evpn_dict["spine2"]["loop_ip_list"][1],
                "neighbor": data.leaf_spine2_ipv6_list,
                "updown": ["up", "up", "up", "up"]}

    st.log("verify BGP EVPN neighborship for Spine nodes ")
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Evpn.verify_bgp_l2vpn_evpn_summary,
                           [verify1,verify2])

    verify1 = {"identifier": evpn_dict["leaf1"]["loop_ip_list"][1],
                "neighbor": [data.spine1_ipv6_list[0],data.spine2_ipv6_list[0]],
                "updown": ["up", "up"]}

    verify2 = {"identifier": evpn_dict["leaf2"]["loop_ip_list"][1],
                "neighbor": [data.spine1_ipv6_list[1],data.spine2_ipv6_list[1]],
                "updown": ["up", "up"]}

    verify3 = {"identifier": evpn_dict["leaf3"]["loop_ip_list"][1],
                "neighbor": [data.spine1_ipv6_list[2],data.spine2_ipv6_list[2]],
                "updown": ["up", "up"]}

    verify4 = {"identifier": evpn_dict["leaf4"]["loop_ip_list"][1],
                "neighbor": [data.spine1_ipv6_list[3],data.spine2_ipv6_list[3]],
                "updown": ["up", "up"]}

    st.log("verify BGP EVPN neighborship for Leaf nodes")
    result=parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.verify_bgp_l2vpn_evpn_summary,
                           [verify1,verify2,verify3,verify4])
    if result[0].count(False) > 0:
        st.error("########## BGP EVPN neighborship is NOT UP on all spine and leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    st.log("Verify vxlan tunnel status")
    result = utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if result[0].count(False) > 0:
        st.error("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    yield
    
    linktrack_unconfig()
    cleanup_mclag()
    cleanup_l3vni()
    cleanup_l2vni()
    cleanup_vxlan()
    cleanup_evpn_5549()
    cleanup_5549_underlay_mclag()
    reboot.config_save(evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"], "vtysh")

@pytest.mark.cli
def test_underlay(request):
    success = True
    hdrMsg("TC ID: test_underlay; TC SUMMARY : LVTEP discovery with Loopback as VTEP")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=evpn_dict["leaf1"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf1"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_underlay FAIL step 1 - Verify VRF VNI map for LVTEP node 1")
        success = False
    else:
        hdrMsg("PASS at step 1 - Verify VRF VNI map for LVTEP node 1")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf2"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf2"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_underlay FAIL step 2 - Verify VRF VNI map for LVTEP node 2")
        success = False
    else:
        hdrMsg("PASS at step 2 - Verify VRF VNI map for LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        hdrMsg("test_underlay FAIL step 3 - Verify Leaf 3 system MAC in LVTEP node 2")
        success = False
    else:
        hdrMsg("PASS step 3 - Verify Leaf 3 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        hdrMsg("test_underlay FAIL step 4 - Verify Leaf 4 system MAC in LVTEP node 2")
        success = False
    else:
        hdrMsg("PASS step 4 - Verify Leaf 4 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=[evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf1"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf1"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_underlay FAIL step 5 - Verify VLAN VNI map in LVTEP node 2")
        success = False
    else:
        hdrMsg("PASS at step 5 - Verify VLAN VNI map in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf3"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf3"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_underlay FAIL step 6 - Verify VLAN VNI map in LVTEP node 1")
        success = False
    else:
        hdrMsg("PASS at step 6 - Verify VLAN VNI map in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_underlay FAIL step 7 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        hdrMsg("PASS at step 7 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf3"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_underlay FAIL step 8 - Verify IPv4 Prefix route in LVTEP node 2")
        success = False
    else:
        hdrMsg("PASS at step 8 - Verify IPv4 Prefix route in LVTEP node 2")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_underlay FAIL step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")
        success = False
    else:
        hdrMsg("PASS at step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_underlay FAIL step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        hdrMsg("PASS at step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")

    tg = tg_dict['tg']
    hdrMsg(" \n####### step 11: Verify L2 unicast traffic for orphon port  ####\n")
    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    ############################################################################################
    hdrMsg(" \n####### step 12: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress="00:02:66:00:00:01")

    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    ############################################################################################
    hdrMsg(" \n####### step 13: Save the config before applying config reload on LVTEP node 2 ##############\n")
    ############################################################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][1],"conf_reload")
    st.wait(5,"Waiting for 5 secs after config reload")
    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf2"]["intf_list_tg"][0]))

    ############################################################################################
    hdrMsg("\n# step 14: Getting L2 traffic loss for LVTEP Node 2 orphon port without linktrack & delay restore #\n")
    ############################################################################################
    if check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]) or not check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_1"])

    evpn_dict["l2_traffic_loss_orphon"] = get_traffic_stream_loss_inpkts(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0])
    get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],tg_dict['d4_tg_ph1'])

    ############################################################################################
    hdrMsg("\n# step 15: Clear stats and start the traffic from LVTEP CCEP port #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])

    ############################################################################################
    hdrMsg("\n####### step 16: Start L2 traffic through CCEP ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_2"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    ############################################################################################
    hdrMsg("\n# step 17: Finding the LVTEP node which Rx traffic on MLAG client before rebooting it #\n")
    ############################################################################################
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0])
        res = False
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[0]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        config_save_and_reboot(evpn_dict["leaf_node_list"][1])
        res = False
        carrier = "standby_node"
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[1],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    ############################################################################################
    hdrMsg("\n# step 18: Getting L2 traffic loss for LVTEP Node CCEP port without linktrack & delay restore #\n")
    ############################################################################################
    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_2"])

    evpn_dict["l2_traffic_loss_ccep"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["l2_372_2"][0])

    if evpn_dict["l2_traffic_loss_ccep"] < 0:
        evpn_dict["l2_traffic_loss_ccep"] = 0

    if carrier == "standby_node":
        hdrMsg("Traffic has passed through Stanby node for L2 traffic stream l2_372_2")
        evpn_dict["l2_traffic_loss_ccep"] = evpn_dict["l2_traffic_loss_ccep"] + 250000
    get_traffic_stream_loss_inpkts(tg_dict["d6_tg_ph1"],stream_dict["l2_372_2"][1],tg_dict["d7_tg_ph1"])

    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])
    ############################################################################################
    hdrMsg(" \n####### step 19: Start L2 BUM traffic b/w LVTEP CCEP to Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32337"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    ############################################################################################
    hdrMsg(" \n####### step 20: Save the config before rebooting LVTEP node which Rx BUM traffic ##############\n")
    ############################################################################################
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"normal")
        res = False
        carrier = "standby_node"
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"normal")
        res = False
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    ############################################################################################
    hdrMsg("\n# step 21: Getting BUM traffic loss in LVTEP nodes without linktrack & delay restore #\n")
    ############################################################################################
    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32337"])

    evpn_dict["bum_traffic_loss_ccep"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["l2_32337"][0])

    if evpn_dict["bum_traffic_loss_ccep"] < 0:
        evpn_dict["bum_traffic_loss_ccep"] = 0

    if carrier == "standby_node":
        hdrMsg("Traffic has passed through Stanby node for BUM traffic stream l2_32337")
        evpn_dict["bum_traffic_loss_ccep"] = evpn_dict["bum_traffic_loss_ccep"] + 250000
    ############################################################################################
    hdrMsg("\n# step 22: Clear stats and start the traffic from LVTEP node 2 #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    ############################################################################################
    hdrMsg(" \n####### step 23: Start L3 Unicast traffic b/w LVTEP CCEP to Leaf 4 ##############\n")
    ############################################################################################
    tg.tg_arp_control(handle=stream_dict["v4host_3237_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3237_2"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_2"], arp_target='all')

    tg.tg_traffic_control(action="run", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"restart_swss")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][0]):
            st.error("LVTEP node 1 is not in ready state")
        res = False
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"restart_swss")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][1]):
            st.error("LVTEP node 2 is not in ready state")
        res = False
        carrier = "standby_node"
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    ############################################################################################
    hdrMsg("\n# step 24: Verify L3 traffic loss b/w LVTEP CCEP port towards Leaf 4 across SwSS restart #\n")
    ############################################################################################
    if check_traffic_duration(t1,250,vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,250,vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])

    ############################################################################################
    hdrMsg("\n# step 25: Getting L3 traffic loss for 3 streams through LVTEP CCEP across SwSS restart without linktrack & delay restore #\n")
    ############################################################################################
    evpn_dict["l3_traffic_loss_ccep1"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3237"][0])
    evpn_dict["l3_traffic_loss_ccep2"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][0])
    evpn_dict["l3_traffic_loss_ccep3"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][1])

    if evpn_dict["l3_traffic_loss_ccep1"] < 0:
        evpn_dict["l3_traffic_loss_ccep1"] = 0
    if evpn_dict["l3_traffic_loss_ccep2"] < 0:
        evpn_dict["l3_traffic_loss_ccep2"] = 0
    if evpn_dict["l3_traffic_loss_ccep3"] < 0:
        evpn_dict["l3_traffic_loss_ccep3"] = 0

    get_traffic_stream_loss_inpkts(tg_dict["d6_tg_ph1"],stream_dict["ipv4_3237"][1],tg_dict["d7_tg_ph1"])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (evpn_dict["l3_traffic_loss_ccep1"] > evpn_dict["l3_traffic_loss_ccep2"]) and \
        (evpn_dict["l3_traffic_loss_ccep1"] > evpn_dict["l3_traffic_loss_ccep3"]):
        evpn_dict["l3_traffic_loss_ccep"] = evpn_dict["l3_traffic_loss_ccep1"]
    elif (evpn_dict["l3_traffic_loss_ccep2"] > evpn_dict["l3_traffic_loss_ccep1"]) and \
        (evpn_dict["l3_traffic_loss_ccep2"] > evpn_dict["l3_traffic_loss_ccep3"]):
        evpn_dict["l3_traffic_loss_ccep"] = evpn_dict["l3_traffic_loss_ccep2"]
    else:
        evpn_dict["l3_traffic_loss_ccep"] = evpn_dict["l3_traffic_loss_ccep3"]

    if carrier == "standby_node":
        hdrMsg("Traffic has passed through Stanby node for L3 traffic stream ipv4_3237 & ipv4_3238 across SwSS restart")
        evpn_dict["l3_traffic_loss_ccep"] = evpn_dict["l3_traffic_loss_ccep"] + 250000
   
    ############################################################################################
    hdrMsg(" \n####### step 26: Start L2 bidirectional traffic b/w LVTEP 1 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32311"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")

    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf1 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf1 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    ############################################################################################
    hdrMsg(" \n####### step 27: Save the config before rebooting LVTEP node 1 ##############\n")
    ############################################################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][0],"fast")

    if check_traffic_duration(t1,350,vars.D3,evpn_dict["leaf1"]["intf_list_tg"][0]) or not check_traffic_duration(t1,350,vars.D3,evpn_dict["leaf1"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32311"])

    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[1],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf1"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf1"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf1"]["intf_list_tg"][0]))

    ############################################################################################
    hdrMsg("\n# step 28: Getting L2 traffic loss for LVTEP Node 1 orphon port without linktrack & delay restore #\n")
    ############################################################################################
    evpn_dict["l2_traffic_loss_orphon_fastreboot"] = get_traffic_stream_loss_inpkts(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0])
    get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_32311"][1],tg_dict['d3_tg_ph1'])

    ############################################################################################
    hdrMsg("\n# step 29: Clear stats and start the traffic from LVTEP CCEP port #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d6_tg_ph1"]])

    ############################################################################################
    hdrMsg(" \n####### step 30: Start L3 Unicast traffic b/w LVTEP CCEP to Leaf 4 ##############\n")
    ############################################################################################
    tg.tg_arp_control(handle=stream_dict["v4host_3237_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3237_2"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_2"], arp_target='all')
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])

    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"normal")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][0]):
            st.error("LVTEP node 1 is not in ready state")
        res = False
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"normal")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][1]):
            st.error("LVTEP node 2 is not in ready state")
        res = False
        carrier = "standby_node"
        for i in range(1,50):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    ############################################################################################
    hdrMsg("\n# step 31: Verify L3 traffic loss b/w LVTEP CCEP port towards Leaf 4 across DUT reload #\n")
    ############################################################################################
    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])

    ############################################################################################
    hdrMsg("\n# step 32: Getting L3 traffic loss for 3 streams through LVTEP CCEP across DUT reload without linktrack & delay restore #\n")
    ############################################################################################
    evpn_dict["l3_traffic_loss_ccep11"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3237"][0])
    evpn_dict["l3_traffic_loss_ccep12"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][0])
    evpn_dict["l3_traffic_loss_ccep13"] = get_traffic_stream_loss_inpkts(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][1])

    if evpn_dict["l3_traffic_loss_ccep11"] < 0:
        evpn_dict["l3_traffic_loss_ccep11"] = 0
    if evpn_dict["l3_traffic_loss_ccep12"] < 0:
        evpn_dict["l3_traffic_loss_ccep12"] = 0
    if evpn_dict["l3_traffic_loss_ccep13"] < 0:
        evpn_dict["l3_traffic_loss_ccep13"] = 0

    get_traffic_stream_loss_inpkts(tg_dict["d6_tg_ph1"],stream_dict["ipv4_3237"][1],tg_dict["d7_tg_ph1"])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (evpn_dict["l3_traffic_loss_ccep11"] > evpn_dict["l3_traffic_loss_ccep12"]) and \
        (evpn_dict["l3_traffic_loss_ccep11"] > evpn_dict["l3_traffic_loss_ccep13"]):
        evpn_dict["l3_traffic_loss_ccep_reload"] = evpn_dict["l3_traffic_loss_ccep11"]
    elif (evpn_dict["l3_traffic_loss_ccep12"] > evpn_dict["l3_traffic_loss_ccep11"]) and \
        (evpn_dict["l3_traffic_loss_ccep12"] > evpn_dict["l3_traffic_loss_ccep13"]):
        evpn_dict["l3_traffic_loss_ccep_reload"] = evpn_dict["l3_traffic_loss_ccep12"]
    else:
        evpn_dict["l3_traffic_loss_ccep_reload"] = evpn_dict["l3_traffic_loss_ccep13"]

    if carrier == "standby_node":
        hdrMsg("Traffic has passed through Stanby node for L3 traffic stream ipv4_3237 & ipv4_3238 across DUT reload")
        evpn_dict["l3_traffic_loss_ccep_reload"] = evpn_dict["l3_traffic_loss_ccep_reload"] + 250000

    ############################################################################################
    hdrMsg(" \n####### step 33: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress="00:02:66:00:00:01")

    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    ############################################################################################
    hdrMsg(" \n####### step 34: Save the config before applying reboot on LVTEP node 2 ##############\n")
    ############################################################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][1],"normal")
    st.wait(5,"Waiting for 5 secs after system reboot")
    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf2"]["intf_list_tg"][0]))

    ############################################################################################
    hdrMsg("\n# step 35: Getting L2 traffic loss for LVTEP Node 2 orphon port without linktrack & delay restore #\n")
    ############################################################################################
    if check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]) or not check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_1"])

    evpn_dict["l2_traffic_loss_orphon_reboot"] = get_traffic_stream_loss_inpkts(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0])
    get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],tg_dict['d4_tg_ph1'])

    ############################################################################################
    hdrMsg("\n# step 36: Clear stats and start the traffic from LVTEP CCEP port #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])

    current_stream_dict["stream"] = stream_dict["l2_372_1"]
    current_stream_dict["stream"] = stream_dict["l2_372_2"]
    current_stream_dict["stream"] = stream_dict["l2_32337"]
    current_stream_dict["stream"] = stream_dict["ipv4_3237"]
    current_stream_dict["stream"] = stream_dict["ipv4_3238"]
    current_stream_dict["stream"] = stream_dict["l2_32311"]

    if success:
        st.report_pass("test_case_id_passed","test_underlay")
    else:
        st.report_fail("test_case_id_failed","test_underlay")


def test_DelayRestoreL2Ucast(Linktrack_fixture):
    success = True
    hdrMsg("TC ID: test_DelayRestoreL2Ucast Verify delay restore with L2 unicast through CEP & CCEP across startup")
    techsupport_not_gen = True
    hdrMsg("Step 1: verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if not Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        linktrack_config()

    hdrMsg("Step 4: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 6: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg("Step 7: verify link state tracking status in LVTEP node 1 and LVTEP node 2")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="2",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["intf_list_tg"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="2",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Ucast FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 8: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])

    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress="00:02:66:00:00:01")

    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    tg = tg_dict['tg']
    ############################################################################################
    hdrMsg(" \n####### step 9: Save the config before applying config reload LVTEP node 2 ##############\n")
    ############################################################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][1],"conf_reload")
    st.wait(5,"Waiting for 5 secs after config reload")

    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf2"]["intf_list_tg"][0]))

    if check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]) or not check_traffic_duration(t1,250,vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_1"])

    if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
        success=False
    if not delay_restore_check(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],domain="2"):
        success=False
        debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 10: Verify L2 traffic loss b/w LVTEP 2 orphon port and Leaf 4 across config reload #\n")
    ############################################################################################
    if check_traffic_loss_per_stream(tg_dict["d4_tg_ph1"],stream_dict["l2_372_1"][0],evpn_dict["l2_traffic_loss_orphon"]+100000):
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id l2_372_1 in TC test_DelayRestoreL2Ucast")
        st.report_tc_pass("Drt322","tc_passed")
        st.report_tc_pass("Drt346","tc_passed")
    else:
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id l2_372_1 in TC test_DelayRestoreL2Ucast")
        success=False
        hdrMsg("INFO: To debug L2 unicast traffic loss from Leaf4 to LVTEP N2, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],tg_dict["d4_tg_ph1"])
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
        debug_delay_restore(evpn_dict["leaf_node_list"][1])

    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        hdrMsg("DEBUG: Collecting show tech support for test_DelayRestoreL2Ucast_l2_372_1")
        basic.get_techsupport(dut=[vars.D3,vars.D4,vars.D6],filename='test_DelayRestoreL2Ucast_l2_372_1')

    ############################################################################################
    hdrMsg("\n# step 11: Clear stats and start the traffic from LVTEP node 2 #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])
    
    ############################################################################################
    hdrMsg("\n# step 16: Clear stats and start the traffic from LVTEP node 1  #\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32311"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")

    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf1 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf1 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    ###########################################################
    hdrMsg("STEP 17: Performing LVTEP node 1 reload")
    ##########################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][0],"fast")

    hdrMsg("STEP 18: Check the system status after fast reload")
    if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][0]):
        st.error("LVTEP node 1 is not in ready state")
        success=False

    res = False
    for i in range(1,100):
        for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
        if res:
            break
    if not res:
        hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf1"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf1"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf1"]["intf_list_tg"][0]))

    if check_traffic_duration(t1,350,vars.D3,evpn_dict["leaf1"]["intf_list_tg"][0]) or not check_traffic_duration(t1,350,vars.D3,evpn_dict["leaf1"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32311"])

    if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
        success=False
    if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["intf_list_tg"][0],domain="2"):
        success=False
        debug_delay_restore(evpn_dict["leaf_node_list"][0])
    ############################################################################################
    hdrMsg("\n# step 19: Verify L2 traffic loss b/w LVTEP 1 orphon port and Leaf 4 config across fast reload #\n")
    ############################################################################################
    if check_traffic_loss_per_stream(tg_dict["d3_tg_ph1"],stream_dict["l2_32311"][0],evpn_dict["l2_traffic_loss_orphon_fastreboot"]):
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id l2_32311 in TC test_DelayRestoreL2Ucast")
        st.report_tc_pass("Drt342","tc_passed")
    else:
        hdrMsg("FAIL: Observed traffic loss is not less than Expected for stream-id l2_32311 in TC test_DelayRestoreL2Ucast")
        success=False
        hdrMsg("INFO: To debug L2 unicast traffic loss from leaf4 to LVTEP N1, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_32311"][1],tg_dict["d3_tg_ph1"])
        techsupport_not_gen = True
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        hdrMsg("DEBUG: Collecting show tech support for test_DelayRestoreL2Ucast_l2_32311")
        basic.get_techsupport(dut=[vars.D3,vars.D4,vars.D6],filename='test_DelayRestoreL2Ucast_l2_32311')

    ############################################################################################
    hdrMsg("\n# step 20: Clear stats and start the traffic from LVTEP CCEP port towards Leaf 4  #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d6_tg_ph1"]])

    start_traffic(stream_han_list=stream_dict["l2_372_2"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    ############################################################################################
    hdrMsg("\n# step 21: Finding the LVTEP node which Rx traffic on MLAG client before rebooting it #\n")
    ############################################################################################
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0])
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1])
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_2"])

    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        hdrMsg("Verify the session status and delay restore timer left in LVTEP N1")
        if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][0])
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        hdrMsg("Verify the session status and delay restore timer left in LVTEP N2")
        if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][1],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 22: Verify L2 traffic loss b/w LVTEP CCEP port towards Leaf 4 across node reboot #\n")
    ############################################################################################
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["l2_372_2"][0],evpn_dict["l2_traffic_loss_ccep"]+100000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id l2_372_2 in TC test_DelayRestoreL2Ucast")
        success=False
        hdrMsg("INFO: To debug L2 traffic loss from Leaf4 to LVTEP CCEP, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_372_2"][1],tg_dict["d7_tg_ph1"])
        techsupport_not_gen = True
        debug_lvtep_trafic()
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id l2_372_2 in TC test_DelayRestoreL2Ucast")
        st.report_tc_pass("Drt3211","tc_passed")

    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d3_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (not success) and techsupport_not_gen:
        hdrMsg("DEBUG: Refer show tech support collected at the end of TC for test_DelayRestoreL2Ucast_l2_372_2")
    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = stream_dict["l2_372_1"]
    current_stream_dict["stream"] = stream_dict["l2_372_2"]
    current_stream_dict["stream"] = stream_dict["l2_32311"]

    if success:
        st.report_pass("test_case_id_passed","test_DelayRestoreL2Ucast")
    else:
        st.report_fail("test_case_id_failed","test_DelayRestoreL2Ucast")


def test_DelayRestoreBum(Linktrack_fixture):
    success = True
    techsupport_not_gen = True
    hdrMsg("TC ID: test_DelayRestoreL2Bum Verify delay restore behavior with L2 BUM through CCEP port across startup")
    hdrMsg("Step 1: verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if not Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        linktrack_config()

    hdrMsg("Step 4: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 6: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg("Step 7: verify link state tracking status in LVTEP node 1 and LVTEP node 2")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="2",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["intf_list_tg"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="2",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL2Bum FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 8: Start L2 BUM traffic b/w LVTEP CCEP to Leaf 4 ##############\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    start_traffic(stream_han_list=stream_dict["l2_32337"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    tg = tg_dict['tg']
    ############################################################################################
    hdrMsg(" \n####### step 9: Save the config before rebooting LVTEP node which Rx BUM traffic ##############\n")
    ############################################################################################
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"normal")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"normal")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32337"])

    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][0])
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 10: Verify BUM traffic loss b/w LVTEP CCEP port and Leaf 4 across node reboot #\n")
    ############################################################################################
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["l2_32337"][0],evpn_dict["bum_traffic_loss_ccep"]+200000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id l2_32337 in TC test_DelayRestoreBum")
        success=False
        hdrMsg("INFO: To debug BUM traffic loss from Leaf 4 to LVTEP CCEP, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_32337"][1],tg_dict["d7_tg_ph1"])
        debug_lvtep_trafic()
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id l2_32337 in TC test_DelayRestoreBum")
        st.report_tc_pass("Drt328","tc_passed")
    ############################################################################################
    hdrMsg("\n# step 11: Clear stats and start the traffic from LVTEP node 2 #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (not success) and techsupport_not_gen:
        hdrMsg("DEBUG: Refer show tech support collected at the end of TC for test_DelayRestoreBum_l2_32337")
    ############################################################################################
    hdrMsg("\n# step 13: Verify the delay restore timer configured in LVTEP nodes #\n")
    ############################################################################################
    mclag.verify_domain(dut=evpn_dict["leaf_node_list"][0],domain_id=2, session_status='up', local_ip="3.4.1.0", \
        peer_ip="3.4.1.1",delay_restore_timer=evpn_dict["del_res_timer"],cli_type="klish")
    mclag.verify_domain(dut=evpn_dict["leaf_node_list"][1],domain_id=2, session_status='up', local_ip="3.4.1.1", \
        peer_ip="3.4.1.0",delay_restore_timer=evpn_dict["del_res_timer"],cli_type="klish")

    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = stream_dict["l2_32337"]

    if success:
        st.report_pass("test_case_id_passed","test_DelayRestoreBum")
    else:
        st.report_fail("test_case_id_failed","test_DelayRestoreBum")


def test_DelayRestoreL3Ucast(Linktrack_fixture):
    success = True
    hdrMsg("TC ID: test_DelayRestoreL3Ucast Verify delay restore with L3 unicast traffic across startup")
    techsupport_not_gen = True

    hdrMsg("Step 1: verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if not Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        linktrack_config()

    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer=evpn_dict["l3_del_res_timer"],cli_type="klish")
    mclag.config_domain(evpn_dict["leaf_node_list"][1],"2",delay_restore_timer=evpn_dict["l3_del_res_timer"],cli_type="klish")

    hdrMsg("Step 4: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 6: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg("Step 7: verify link state tracking status in LVTEP node 1 and LVTEP node 2")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="2",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["intf_list_tg"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="2",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DelayRestoreL3Ucast FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 8: Start L3 Unicast traffic b/w LVTEP CCEP to Leaf 4 ##############\n")
    ############################################################################################
    tg = tg_dict['tg']
    tg.tg_arp_control(handle=stream_dict["v4host_3237_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3237_2"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3238_2"], arp_target='all')

    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    tg.tg_traffic_control(action="run", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])
    t1 = datetime.datetime.now()
    st.wait(15,"Waiting for 15 sec before config save and reboot")

    ############################################################################################
    hdrMsg(" \n####### step 9: Verify L3 traffic after SwSS restart of LVTEP node ##############\n")
    ############################################################################################
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"restart_swss")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][0]):
            st.error("LVTEP node 1 is not in ready state")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"restart_swss")
        hdrMsg("STEP: Check the system status after SwSS restart")
        if not basic_obj.poll_for_system_status(evpn_dict["leaf_node_list"][1]):
            st.error("LVTEP node 2 is not in ready state")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    if check_traffic_duration(t1,250,vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,250,vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])

    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][0])
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 10: Verify L3 traffic loss b/w LVTEP CCEP port towards Leaf 4 across swss restart #\n")
    ############################################################################################
    st.wait(2,"Waiting for TG stats to be populated")
    hdrMsg("######## SwSS Restart Result for the stream with stream id ipv4_3237 [0] L3 Traffic STRM 1 #####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3237"][0],evpn_dict["l3_traffic_loss_ccep"]+225000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3237-0 during fast reboot in TC test_DelayRestoreL3Ucast")
        success=False
        hdrMsg("INFO: To debug traffic loss from Leaf4 to LVTEP CCEP 1st stream, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["ipv4_3237"][1],tg_dict["d7_tg_ph1"])
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3237-0 during fast reboot in TC test_DelayRestoreL3Ucast")
        st.report_tc_pass("Drt344","tc_passed")

    hdrMsg("######## SwSS Restart Result for the stream with stream id ipv4_3238 [0] L3 Traffic STRM 2 #####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][0],evpn_dict["l3_traffic_loss_ccep"]+200000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3238-0 during fast reboot in TC test_DelayRestoreL3Ucast")
        success=False
        hdrMsg("INFO: Traffic loss from Leaf4 to LVTEP CCEP 2nd stream with src address 120.1.1.101")
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3238-0 during fast reboot in TC test_DelayRestoreL3Ucast")

    hdrMsg("######## SwSS Restart Result for the stream with stream id ipv4_3238 [1] L3 Traffic STRM 3 #####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][1],evpn_dict["l3_traffic_loss_ccep"]+200000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3238-1 during fast reboot in TC test_DelayRestoreL3Ucast")
        success=False
        hdrMsg("INFO: Traffic loss from Leaf4 to LVTEP CCEP 3rd stream with src address 120.1.1.102")
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3238-1 during fast reboot in TC test_DelayRestoreL3Ucast")

    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        debug_lvtep_trafic()
        hdrMsg("DEBUG: Collecting show tech support for test_DelayRestoreL3Ucast_restart_swss")
        basic.get_techsupport(dut=[vars.D3,vars.D4,vars.D6],filename='test_DelayRestoreL3Ucast_restart_swss')
    ############################################################################################
    hdrMsg("\n# step 11: Clear stats and start the traffic from LVTEP node 2 #\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    start_traffic(stream_han_list=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])
    t1 = datetime.datetime.now()
    #start_traffic(stream_han_list=stream_dict["ipv4_3238"])

    ############################################################################################
    hdrMsg("\n# step 13: Verify the delay restore timer configured in LVTEP nodes #\n")
    ############################################################################################
    mclag.verify_domain(dut=evpn_dict["leaf_node_list"][0],domain_id=2, session_status='up', local_ip="3.4.1.0", \
        peer_ip="3.4.1.1",delay_restore_timer=evpn_dict["l3_del_res_timer"],cli_type="klish")
    mclag.verify_domain(dut=evpn_dict["leaf_node_list"][1],domain_id=2, session_status='up', local_ip="3.4.1.1", \
        peer_ip="3.4.1.0",delay_restore_timer=evpn_dict["l3_del_res_timer"],cli_type="klish")
    ############################################################################################
    hdrMsg(" \n####### step 14: Save the config before reboot of LVTEP node  ###\n")
    ############################################################################################
    st.wait(15,"Waiting for 15 sec before config save and reboot")
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][0],"normal")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[0],data.leafs_spine2_port_lst1[0],data.leaf1_po_list[0],data.leaf1_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][0],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][0],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N1, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        config_save_and_reboot(evpn_dict["leaf_node_list"][1],"normal")
        res = False
        for i in range(1,100):
            for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
                if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                    res = True
                    hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                    break
                else:
                    st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up, retrying..")
            if res:
                break
        if not res:
            hdrMsg("FAIL: LVTEP N2, Uplink tracked port or/and Vxlan tunnel one or both not come up after waiting")

    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D7,evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["ipv4_3237"]+stream_dict["ipv4_3238"])

    if any(x in leaf1_rx[0]['rx_bps'] for x in rate):
        st.log("D3 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][0])
    elif any(x in leaf2_rx[0]['rx_bps'] for x in rate):
        st.log("D4 receives traffic from mclag client")
        if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
            success=False
        if not delay_restore_check(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0],domain="2"):
            success=False
            debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 15: Verify L3 traffic loss after normal reboot of LVTEP node #\n")
    ############################################################################################
    hdrMsg("######## Node Reboot Result for the stream with stream id ipv4_3237 [0] L3 Traffic STRM 1 #####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3237"][0],evpn_dict["l3_traffic_loss_ccep_reload"]+210000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3237-0 during reboot in TC test_DelayRestoreL3Ucast")
        success=False
        hdrMsg("INFO: To debug traffic loss from Leaf 4 to LVTEP CCEP Port for stream-id ipv4_3237-1, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["ipv4_3237"][1],tg_dict["d7_tg_ph1"])
        techsupport_not_gen=True
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3237-0 during reboot in TC test_DelayRestoreL3Ucast")
        st.report_tc_pass("Drt341","tc_passed")

    hdrMsg("######## Node Reboot Result for the stream with stream id ipv4_3238 [0] L3 Traffic STRM 2 #####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][0],evpn_dict["l3_traffic_loss_ccep_reload"]+210000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3238-0 during reboot in TC test_DelayRestoreL3Ucast")
        success=False
        techsupport_not_gen=True
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3238-0 during reboot in TC test_DelayRestoreL3Ucast")
        st.report_tc_pass("Drt321","tc_passed")

    hdrMsg("######## Node Reboot Result for the stream with stream id ipv4_3238 [1] L3 Traffic stram 3 ####")
    if not check_traffic_loss_per_stream(tg_dict["d7_tg_ph1"],stream_dict["ipv4_3238"][1],evpn_dict["l3_traffic_loss_ccep_reload"]+210000):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id ipv4_3238-1 during reboot in TC test_DelayRestoreL3Ucast")
        success=False
        techsupport_not_gen=True
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id ipv4_3238-1 during reboot in TC test_DelayRestoreL3Ucast")

    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d7_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (not success) and techsupport_not_gen:
        hdrMsg("DEBUG: Refer the show tech support at the end of TC for test_DelayRestoreL3Ucast_reboot")
        debug_lvtep_trafic()
    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = stream_dict["ipv4_3237"]
    current_stream_dict["stream"] = stream_dict["ipv4_3238"]
   
    if success:
        st.report_pass("test_case_id_passed","test_DelayRestoreL3Ucast")
    else:
        st.report_fail("test_case_id_failed","test_DelayRestoreL3Ucast")

def test_DeReOrphonPo(Linktrack_fixture):
    success = True
    hdrMsg("TC ID:test_DeReOrphonPo Verify delay restore behavior when traffic is passed through orphon port channel interface")
    techsupport_not_gen = True

    hdrMsg("Step 1: verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if not Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        linktrack_config()

    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer=evpn_dict["orphanpo_del_res_timer"],cli_type="klish")
    mclag.config_domain(evpn_dict["leaf_node_list"][1],"2",delay_restore_timer=evpn_dict["orphanpo_del_res_timer"],cli_type="klish")

    hdrMsg("Step 4: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        hdrMsg("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        hdrMsg("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 6: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="2",description="uplink_protection"):
        hdrMsg("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg(" test_DeReOrphonPo FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg(" \n### Step 4 Remove the ohphon port from vlans before adding ad member port to orphon PortChannel 100  ###\n")
    for vlan1,vlan2 in zip([evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], \
        evpn_dict["leaf1"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]], \
            [evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], \
                evpn_dict["leaf2"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]):
        utils.exec_all(True,[[Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][0],
                              vlan1,evpn_dict["leaf1"]["intf_list_tg"][0],True],
                             [Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][1],
                              vlan2,evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    hdrMsg(" \n### Step 5 Creating the orphon port PortChannel 100 and conigure its vlan membership ###\n")
    utils.exec_all(True,[[pch.create_portchannel,evpn_dict["leaf_node_list"][0],"PortChannel100",False,"",True],
                    [pch.create_portchannel,evpn_dict["leaf_node_list"][1],"PortChannel100",False,"",True]
                    ])

    hdrMsg(" \n### Step 7 Configuring the orphon port PortChannel 100 vlan membership ###\n")
    utils.exec_all(True,[
               [pch.add_portchannel_member,evpn_dict["leaf_node_list"][0],"PortChannel100",evpn_dict["leaf1"]["intf_list_tg"][0]],
               [pch.add_portchannel_member,evpn_dict["leaf_node_list"][1],"PortChannel100",evpn_dict["leaf2"]["intf_list_tg"][0]]
               ])
    utils.exec_all(True,[
               [Vlan.add_vlan_member,evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100"],
               [Vlan.add_vlan_member,evpn_dict["leaf_node_list"][1],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100"]
               ])

    hdrMsg("\n## Step 3 Configuring link track upstream orphon port as port channel before its member port added to verify forearding reference ##\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3],evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"2",downinterface="PortChannel100")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][3],"2",
        description="uplink_protection")

    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3],evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"2",downinterface="PortChannel100")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["intf_list_spine"][3],"2",
        description="uplink_protection")

    hdrMsg(" \n### Step 6 Checking LVTEP node linktrack status for exitsing orphon port PortChannel 100 ####\n")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="2",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="2",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        hdrMsg("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 8: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])

    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    t1 = datetime.datetime.now()
    st.wait(10,"Waiting for 10 sec before config save and reboot")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress="00:02:44:00:00:01")
    Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress="00:02:66:00:00:01")

    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["intf_list_tg"][0], "rx_bps")
    leaf4_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3],
                                         evpn_dict["leaf4"]["intf_list_tg"][0], "rx_bps")
    rate = [' KB/s', ' MB/s']
    carrier = "active_node"
    if any(x in leaf2_rx[0]['rx_bps'] for x in rate) and any(x in leaf4_rx[0]['rx_bps'] for x in rate):
        st.log("PASS: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")
    else:
        st.log("FAIL: Leaf2 Rx traffic through orphan port & Leaf4 Rx traffic through orphan port")

    tg = tg_dict['tg']
    ############################################################################################
    hdrMsg(" \n####### step 14: Save the config before rebooting LVTEP node 2  ###\n")
    ############################################################################################
    config_save_and_reboot(evpn_dict["leaf_node_list"][1])

    res = False
    for i in range(1,20):
        for intf in [data.leafs_spine1_port_lst1[1],data.leafs_spine2_port_lst1[1],data.leaf2_po_list[0],data.leaf2_po_list[1]]:
            if underlay_linkstatus_check(evpn_dict["leaf_node_list"][1],intf) and tunnel_status_check(evpn_dict["leaf_node_list"][1],"6.6.6.2"):
                res = True
                hdrMsg("PASS: Uplink tracked port came Up and Vxlan tunnel also came up")
                break
            else:
                st.wait(1,"Uplink tracked port or/and Vxlan tunnel one or both not come up")
        if res:
            break

    res = False
    for i in range(1,5):
        if Intf.interface_status_show(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0]):
            res = True
            hdrMsg("INFO: Downlink tracked port {} status check".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
            break
        else:
            st.wait(1,"Downlink tracked port {} not come up, Retrying".format(evpn_dict["leaf2"]["intf_list_tg"][0]))
        if res:
            break
    if not res:
        hdrMsg("FAIL: Downlink tracked port {} not come up after waiting".format(evpn_dict["leaf2"]["intf_list_tg"][0]))

    if check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]) or not check_traffic_duration(t1,evpn_dict["traffic_duration"],vars.D4,evpn_dict["leaf2"]["intf_list_tg"][0]):
        tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_372_1"])

    if not delay_restore_check(evpn_dict["leaf_node_list"][1],"PortChannel100",domain="2"):
        success=False
    if not session_status_check(evpn_dict["leaf_node_list"][1],domain="2"):
        success=False
        debug_delay_restore(evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n# step 15: Verify L2 traffic loss b/w LVTEP 2 orphon port-channel and Leaf 4 across node reload #\n")
    ############################################################################################
    if not check_traffic_loss_per_stream(tg_dict["d4_tg_ph1"],stream_dict["l2_372_1"][0],evpn_dict["l2_traffic_loss_orphon_reboot"]):
        hdrMsg("FAIL: Observed traffic loss is not less than expected for stream-id l2_372_1 in TC test_DeReOrphonPo")
        success=False
        hdrMsg("INFO: To debug traffic loss from Leaf 4 to LVTEP 2 orphon port, printing the stream result")
        get_traffic_stream_loss_inpkts(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],tg_dict["d4_tg_ph1"])
    else:
        hdrMsg("PASS: Expected and Observed traffic loss for stream-id l2_372_1 in TC test_DeReOrphonPo")
        st.report_tc_pass("Drt323","tc_passed")

    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d4_tg_ph1"], tg_dict["d6_tg_ph1"]])

    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        hdrMsg("DEBUG: Collecting show tech support for test_DeReOrphonPo_l2_372_1")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
        basic.get_techsupport(dut=[vars.D3,vars.D4,vars.D6],filename='test_DeReOrphonPo_l2_372_1')

    hdrMsg(" \n## Step 29: removing link track downstream orphon port channel after deleting portchannel to check forwarding reference ##\n")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][3],
        "2","no",description="uplink_protection",downinterface="PortChannel100")

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["intf_list_spine"][3],
        "2","no",description="uplink_protection",downinterface="PortChannel100")

    ############################################################################################
    hdrMsg("\n## step 24 : Removing the orphon port PortChannel100 associated config ##\n")
    ############################################################################################
    utils.exec_all(True,[
           [Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100",False],
           [Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][1],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100",False]
           ])
    utils.exec_all(True,[
           [pch.delete_portchannel_member,evpn_dict["leaf_node_list"][0],"PortChannel100",evpn_dict["leaf1"]["intf_list_tg"][0]],
           [pch.delete_portchannel_member,evpn_dict["leaf_node_list"][1],"PortChannel100",evpn_dict["leaf2"]["intf_list_tg"][0]]
           ])

    ############################################################################################
    hdrMsg("\n## step 25 : Remove member port of orphon port PortChannel100 and associate the tenant vlans to restore module config ##\n")
    ############################################################################################
    for vlan1,vlan2 in zip([evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], \
        evpn_dict["leaf1"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]], \
            [evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], \
                evpn_dict["leaf2"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]):
        utils.exec_all(True,[[Vlan.add_vlan_member,evpn_dict["leaf_node_list"][0],
                              vlan1,evpn_dict["leaf1"]["intf_list_tg"][0],True],
                             [Vlan.add_vlan_member,evpn_dict["leaf_node_list"][1],
                              vlan2,evpn_dict["leaf2"]["intf_list_tg"][0],True]])
    ######################################################################
    hdrMsg("\n## step 27 : Removing the orphon port PortChannel100  ##\n")
    ######################################################################
    utils.exec_all(True,[[pch.delete_portchannel,evpn_dict["leaf_node_list"][0],"PortChannel100"],
                [pch.delete_portchannel,evpn_dict["leaf_node_list"][1],"PortChannel100"]
                ])
    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = stream_dict["l2_372_1"]

    if success:
        st.report_pass("test_case_id_passed","test_DeReOrphonPo")
    else:
        st.report_fail("test_case_id_failed","test_DeReOrphonPo")

def test_DeReTimerCheck(Linktrack_fixture):
    success = True
    hdrMsg("TC ID: test_DeReTimerCheck Verify delay restore non zero timer hold down the down links till timer reset")
    techsupport_not_gen = True

    hdrMsg("Step 1: verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if not Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2",description="uplink_protection"):
        linktrack_config()

    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer=evpn_dict["del_res_timer"],cli_type="klish")

    config_save_and_reboot(evpn_dict["leaf_node_list"][0],"normal")

    if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
        success=False
        debug_delay_restore(evpn_dict["leaf_node_list"][0])
    else:
        hdrMsg("PASS: LVTEP N1 user defined delay restore timers value retianed across reboot")
        st.report_tc_pass("Drt311","tc_passed")

    if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
        success=False

    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer="80",cli_type="klish")
    ############################################################################################
    hdrMsg("\n####### step 24 : Verify the delay restore timer in LVTEP nodes ##############\n")
    ############################################################################################
    if not mclag.verify_domain(dut=evpn_dict["leaf_node_list"][0],domain_id=2, local_ip="3.4.1.0", \
        peer_ip="3.4.1.1",delay_restore_timer="80",delay_restore_left_timer="",cli_type="klish"):
        hdrMsg("FAIL: LVTEP N1 user defined delay restore timers value 80 sec")
        success=False
    else:
        hdrMsg("PASS: LVTEP N1 user defined delay restore timers value of 80 sec verified")
        st.report_tc_pass("Drt312","tc_passed")

    ############################################################################################
    hdrMsg("\n####### step 25 : Remove the delay restore timer in LVTEP nodes ##############\n")
    ############################################################################################
    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer="80",cli_type="klish",config="del")
    mclag.config_domain(evpn_dict["leaf_node_list"][1],"2",delay_restore_timer="80",cli_type="klish",config="del")

    ############################################################################################
    hdrMsg("\n####### step 26 : Verify the default delay restore timer in LVTEP nodes ##############\n")
    ############################################################################################
    if not mclag.verify_domain(dut=evpn_dict["leaf_node_list"][0],domain_id=2, session_status='up', local_ip="3.4.1.0", \
        peer_ip="3.4.1.1",delay_restore_timer="300",delay_restore_left_timer="",cli_type="klish"):
        hdrMsg("FAIL: LVTEP N1 Default delay restore timers value of 300 sec ")
        success=False
    else:
        hdrMsg("PASS: LVTEP N1 Default delay restore timers value of 300 sec verified")

    if not mclag.verify_domain(dut=evpn_dict["leaf_node_list"][1],domain_id=2, session_status='up', local_ip="3.4.1.1", \
        peer_ip="3.4.1.0",delay_restore_timer="300",delay_restore_left_timer="",cli_type="klish"):
        hdrMsg("FAIL: LVTEP N2 Default delay restore timers value of 300 sec ")
        success=False
    else:
        hdrMsg("PASS: LVTEP N2 Default delay restore timers value of 300 sec verified")

    if (not success) and techsupport_not_gen:
        hdrMsg("DEBUG: Refer the show tech support at the end of TC for test_DeReTimerCheck")
    else:
        st.report_tc_pass("Drt327","tc_passed")
        st.report_tc_pass("Drt3210","tc_passed")

    if success:
        st.report_pass("test_case_id_passed","test_DeReTimerCheck")
    else:
        st.report_fail("test_case_id_failed","test_DeReTimerCheck")

@pytest.fixture(scope="function")
def Linktrack_fixture(request,evpn_underlay_hooks):
    yield

    #############################################################################################
    hdrMsg("\n####### Clear mac in LVTEP and SVTEP ##############\n")
    #############################################################################################
    utils.exec_all(True, [[Intf.clear_interface_counters,dut] for dut in [vars.D3,vars.D4,vars.D6,vars.D7]])
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")

def config_save_and_reboot(dut,reboot_type="normal"):
    dut_li = list(dut) if isinstance(dut, list) else [dut]
    for dut1 in dut_li:
        if evpn_dict['cli_mode'] == "click":
            hdrMsg("INFO: Configure routing mode split in click mode before config save")
            Bgp.enable_docker_routing_config_mode(dut1)
            reboot.config_save(dut1,cli_type="klish")
        elif evpn_dict['cli_mode'] == "klish":
            reboot.config_save(dut1,shell="vtysh")
        hdrMsg("INFO: Saving the config.. ")
        reboot.config_save(dut1)
        hdrMsg("INFO: Perform {} reboot".format(reboot_type))
        if reboot_type == "normal":
            st.reboot(dut1)
        elif reboot_type == "fast":
            st.reboot(dut1,'fast')
        elif reboot_type == "conf_reload":
            reboot.config_reload(dut1)
        elif reboot_type == "restart_swss":
            basic.service_operations_by_systemctl(dut1, 'swss', 'restart')
    return True


def underlay_linkstatus_check(dut,interface,ip_ver="ipv6"):
    result = False
    max_range = 2
    for i in range(1,max_range+1):
        intf_status=[]
        intf_status = Ip.get_interface_ip_address(dut, interface_name=interface, family=ip_ver,cli_type="klish")
        if isinstance(intf_status,list) and len(intf_status) != 0:
            intf = intf_status[0]
            if intf['interface'] == interface and intf['status'] in "up/up":
                result = True
                hdrMsg("PASS: Underlay link has come Up fine ")
                break
            else:
                st.wait(2,"Underlay link has not come Up yet, interface {} shows staus {}".format(intf['interface'],intf['status']))
        elif isinstance(intf_status,bool):
            st.wait(2,"show command does not show any O/P")
        elif len(intf_status) == 0:
            st.wait(2,"Underlay link is not listed yet..")
    if not result:
        hdrMsg("FAIL: Underlay link has not come up after waiting {} sec".format(max_range*2))
    return result

def tunnel_status_check(dut,tnl_dst_ip):
    result = False
    cli_type = st.get_ui_type(dut)
    max_range = 39
    for i in range(1,max_range+1):
        tnl_list = Evpn.get_tunnel_list(dut,type=cli_type)
        if isinstance(tnl_list,list) and len(tnl_list) > 1:
            for tunl in tnl_list:
                if tunl == tnl_dst_ip and Evpn.verify_vxlan_tunnel_status(dut,evpn_dict["leaf1"]["loop_ip_list"][2],[tnl_dst_ip],['oper_up']):
                    result = True
                    hdrMsg("PASS: Vxlan Tunnel has come Up fine ")
                    break
                else:
                    st.wait(2,"Match not found, Remote vtep ip {}, vtep status {}, Retrying".format(tunl,"is not oper_up"))
            if result:
                break
        elif len(tnl_list) == 1 and tnl_list[0] == "":
            st.wait(2,"show command does not show any O/P")
    if not result:
        hdrMsg("FAIL:Vxlan tunnel did not come up after waiting {} sec".format(max_range*2))
    return result

def check_traffic_loss_per_stream(tg_port_ph,stream_id,exp_loss_pkts=40,dest_tg_ph=''):
    global vars
    tg = tg_dict['tg']
    tx_stats = tg_dict["tg"].tg_traffic_stats(mode='streams',streams=stream_id,port_handle=tg_port_ph)
    tx_count = tx_stats[tg_port_ph]['stream'][stream_id]['tx']['total_pkts']
    if tg_dict["tg"].tg_type == 'stc':
        rx_count = tx_stats[tg_port_ph]['stream'][stream_id]['rx']['total_pkts']
    if tg_dict["tg"].tg_type == 'ixia':
        if dest_tg_ph == '':
            dest_tg_ph = tg_dict['d6_tg_ph1']
        rx_count = tx_stats[dest_tg_ph]['stream'][stream_id]['rx']['total_pkts']
    obs_pkts_cnt = int(tx_count) - int(rx_count)
    hdrMsg("Stream based traffic result for the STREAM-ID {}".format(stream_id))
    st.log("Tx Pkts : {}, Rx Pkts : {}, Total Pkts loss : {} ".format(tx_count,rx_count,obs_pkts_cnt))
    st.log("Observed Traffic loss or No of pkts lost = {} pkts".format(obs_pkts_cnt))
    st.log("Expected Traffic loss or No of pkts lost = {} pkts".format(exp_loss_pkts))
    hdrMsg("Stream Tx Stats result for the STREAM-ID {} is {}".format(stream_id,tx_stats))

    if obs_pkts_cnt <= exp_loss_pkts:
        st.log("INFO: Observed Trafic loss {} is less than or equal to exp traffic loss {} pkts".format(obs_pkts_cnt,exp_loss_pkts))
        return True
    else:
        st.log("INFO: Observed Trafic loss {} is NOT less than or equal to exp traffic loss {} pkts, \
            difference is {}".format(obs_pkts_cnt,exp_loss_pkts,obs_pkts_cnt-exp_loss_pkts))
        return False

def get_traffic_stream_loss_inpkts(tg_port_ph,stream_id,dest_tg_ph=''):
    global vars
    tg = tg_dict['tg']
    tx_stats = tg_dict["tg"].tg_traffic_stats(mode='streams',streams=stream_id,port_handle=tg_port_ph)
    tx_count = tx_stats[tg_port_ph]['stream'][stream_id]['tx']['total_pkts']
    if tg_dict["tg"].tg_type == 'stc':
        rx_count = tx_stats[tg_port_ph]['stream'][stream_id]['rx']['total_pkts']
    if tg_dict["tg"].tg_type == 'ixia':
        if dest_tg_ph == '':
            dest_tg_ph = tg_dict['d6_tg_ph1']
        rx_count = tx_stats[dest_tg_ph]['stream'][stream_id]['rx']['total_pkts']
    pkts_cnt = int(tx_count) - int(rx_count)
    hdrMsg("Stream based traffic result for the STREAM-ID {}".format(stream_id))
    st.log("Tx Pkts : {}, Rx Pkts : {}, Total Pkts loss : {} ".format(tx_count,rx_count,pkts_cnt))
    st.log("Observed Traffic loss seen in NO of Pkts = {} pkts".format(pkts_cnt))
    hdrMsg("Stream Tx Stats result for the STREAM-ID {} is {}".format(stream_id,tx_stats))
    return pkts_cnt

def check_traffic_duration(t1,interval,dut,intf1):
    for i in range(1,interval):
        t2 = datetime.datetime.now()
        time1 = t2-t1
        duration = time1.seconds
        if int(duration) >= interval:
            hdrMsg("{} seconds elapsed since traffic started as per time stmap, so lets stop the trafic stream.".format(duration))
            return True
        else:
            st.wait(1,"{} seconds elapsed since traffic started as per time stmap, retry no is {}, retrying. ".format(duration,i))
            if "PortChannel" in intf1:
                pch.get_portchannel_list(dut)
            else:
                Intf.interface_status_show(dut,interfaces=intf1)
                Evpn.get_port_counters(dut,intf1, "rx_bps")
    return False

