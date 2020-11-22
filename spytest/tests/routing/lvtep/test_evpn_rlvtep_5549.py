import pytest

from spytest import st, utils
from spytest.dicts import SpyTestDict
import apis.system.interface as Intf
import apis.routing.evpn as Evpn
import apis.routing.ip_bgp as ip_bgp
from apis.system import basic
from apis.system import port
import apis.system.reboot as reboot_api
import apis.system.reboot as reboot
import apis.switching.mac as Mac
from apis.routing import arp
import apis.routing.arp as arp_api
import apis.routing.ip as Ip
from utilities import parallel

from evpn_rlvtep import *
from evpn_rlvtep_underlay_base_cfg import *

scale = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def evpn_underlay_hooks(request):
    global vars
    create_glob_vars()
    vars = st.get_testbed_vars()
    api_list = [[create_stream_lvtep_5549], [config_evpn_lvtep_5549]]
    parallel.exec_all(True, api_list, True)
    create_stream_mclag_5549()

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

    cleanup_mclag()
    cleanup_l3vni()
    cleanup_l2vni()
    cleanup_vxlan()
    cleanup_evpn_5549()
    cleanup_5549_underlay_mclag()
    reboot.config_save(evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"], "vtysh")

@pytest.mark.cli
def test_FtOpSoRoEvpn5549LvtepFt3231(request):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3231; TC SUMMARY : LVTEP discovery with Loopback as VTEP")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=evpn_dict["leaf1"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf1"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 1 - Verify VRF VNI map for LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 1 - Verify VRF VNI map for LVTEP node 1")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf2"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf2"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 2 - Verify VRF VNI map for LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 2 - Verify VRF VNI map for LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 3 - Verify Leaf 3 system MAC in LVTEP node 2")
        success = False
    else:
        st.log("PASS step 3 - Verify Leaf 3 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 4 - Verify Leaf 4 system MAC in LVTEP node 2")
        success = False
    else:
        st.log("PASS step 4 - Verify Leaf 4 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=[evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf1"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf1"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 5 - Verify VLAN VNI map in LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 5 - Verify VLAN VNI map in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf3"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf3"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 6 - Verify VLAN VNI map in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 6 - Verify VLAN VNI map in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 7 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 7 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf3"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 8 - Verify IPv4 Prefix route in LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 8 - Verify IPv4 Prefix route in LVTEP node 2")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")
        success = False
    else:
        st.log("PASS at step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3231 FAIL step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS at step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt3231")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt3231")

def test_FtOpSoRoEvpn5549LvtepFt32311(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32311; TC SUMMARY : L2 Traffic to orphan port from remote leaf nodes")

    st.log("verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32311"])
    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D3P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32311 FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Verify mac count in LVTEP nodes ##############\n")
    ############################################################################################
    D3_mac_cnt = Mac.get_mac_count(vars.D3)
    if D3_mac_cnt >= 2:
        st.log("PASS: Mac count in Leaf1 is "+ str(D3_mac_cnt))
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32311 FAIL: Mac count in Leaf1 not as expected. Expected:2. Found: "+ str(D3_mac_cnt))
        success=False

    ############################################################################################
    hdrMsg("\n####### Verify mac learning ##############\n")
    ############################################################################################
    mac_lst = mac_list_from_bcmcmd_l2show(vars.D3)
    mac_list = filter_mac_list(vars.D3,"00:02:33:00:00:")
    if len(mac_list) == 1:
        st.log("PASS: Local macs learnt from LVTEP Node 1 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32311 FAIL: Mac count in LVTEP Node 1 is not as expected. Expected:1. Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpn5549LvtepFt32311 FAIL: The MACs learnt on LVTEP node 1 is :"+ mac_lst[0])
        success=False

    if D3_mac_cnt < 2 or len(mac_list) != 1:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = stream_dict["l2_32311"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32311")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32311")

def test_FtOpSoRoEvpn5549LvtepFt3232(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3232; TC SUMMARY: L2 Traffic from single node leaf node to MLAG leaf node")

    st.log("verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_3281"])
    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    ############################################################################################
    hdrMsg("\n####### Verify mac count in LVTEP nodes ##############\n")
    ############################################################################################
    if retry_api(verify_mac_count, vars.D3, mac_count=30, retry_count=3, delay=5):
        st.log("PASS: Mac count in D3 is at least 30 as expected")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Mac count in D3 not as expected. Expected at least:30")
        success=False
        mac_status=False

    if retry_api(verify_mac_count, vars.D4, mac_count=30, retry_count=3, delay=5):
        st.log("PASS: Mac count in D4 is at least 30 as expected")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Mac count in D4 not as expected. Expected at least:30")
        success=False
        mac_status=False

    ############################################################################################
    hdrMsg("\n####### Verify Local mac learning in LVTEP node##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:02:77:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Local macs with pattern 00:02:77:00:00:* in D3 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Local Mac count with pattern 00:02:77:00:00:* in D3 is not"
               " as expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: local MACs with pattern 00:02:77:00:00:* in D3 is not 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:77:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: MAC wit pattern 00:02:77:00:00:* is 15 in D4 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Local Mac with pattern 00:02:77:00:00:* in D4 is not as"
               " expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: local MAC with pattern 00:02:77:00:00:* is not 15 in D4")
        success=False
        mac_status=False

    ############################################################################################
    hdrMsg("\n####### Verify Remote mac learning in LVTEP node ##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote EVPN macs with pattern 00:02:66:00:00:* in D3 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Remote EVPN Mac with pattern 00:02:66:00:00:* in D3 is not"
               " as expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: remote MACs with pattern 00:02:66:00:00:* in D3 is NOT 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote EVPN MAC with pattern 00:02:66:00:00:* in D4 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: Remote EVPN with pattern 00:02:66:00:00:* in D4 is not"
               " as expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpn5549LvtepFt3232 FAIL: remote MAC with pattern 00:02:66:00:00:* in D4 is not 15")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"]=stream_dict["l2_3281"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt3232")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt3232")

def test_FtOpSoRoEvpn5549LvtepFt32331_2(Tgencleanup_fixture):
    global vars
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32331; TC SUMMARY:MAC Move detection in an MLAG cluster")
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32332; TC SUMMARY:MAC Move detection between MLAG leaf node and a remote leaf node")

    tg = tg_dict['tg']
    st.log("### Step 1 start L2 traffic from first tgen port of Leaf3 and Leaf4 ###")
    tg.tg_traffic_control(action="run", stream_handle=[stream_dict["l2_32331_1"],stream_dict["l2_32331_2"]])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    st.log("### Step 2 verify evpn remote mac table in Leaf2 and Leaf4 ###")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf3"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("########## MACs from leaf3 not learned in leaf4, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("##### MACs from leaf3 learned successfully in leaf4, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf3"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("########## Step 3 MACs from leaf3 not learned in LVTEP N2, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("##### Step 3 MACs from leaf3 learned successfully in LVTEP N2, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf4"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("########## Step 4 MACs from leaf4 not learned in LVTEP N2, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("##### Step 4 MACs from leaf4 learned successfully in LVTEP N2, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf3"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("##### Step 5 MACs from leaf4 not learned in LVTEP N1, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("##### Step 5 MACs from leaf4 learned successfully in LVTEP N1, passed #####")

    ktx1 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["intf_list_tg"][0], "tx_bps")
    ktx2 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["intf_list_tg"][0], "tx_bps")
    st.log("### verify traffic received in first tgen port of Leaf3 and Leaf4 ###")
    if " KB/s" in ktx1[0]['tx_bps'] and " KB/s" in ktx2[0]['tx_bps']:
       st.log("##### Step 6 traffic verification passed before dynamic mac movement #####")
    elif " MB/s" in ktx1[0]['tx_bps'] and " MB/s" in ktx2[0]['tx_bps']:
       st.log("##### Step 6 traffic verification passed before dynamic mac movement #####")
    else:
         success=False
         hdrMsg("## Step 6 traffic test FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 before dynamic mac movement ##########")

    st.log("### Step 7 stop the traffic started in Leaf3 ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32331_1"])

    st.log("### Step 8 start Leaf3's same traffic from LVTEP MLAG port ###")
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32331_3"])

    '''
    st.log("### Step 9 verify evpn remote mac table after mac movement ###")
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf4"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("########## leaf2 not advertising the moved MACs of leaf3 to leaf4, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("##### MACs moved from leaf3, now advertised by leaf2 to leaf4, passed #####")

    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf4"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("### Step 10 Mac {} not advertised by leaf2 to leaf4, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########"
                 .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        st.log("### Step 10 Mac {} advertised by leaf2 to leaf4, passed #####"
               .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    '''
    if retry_api(Evpn.verify_bgp_l2vpn_evpn_route_type_macip,vars.D6, evpn_type_2_prefix="[2]:[0]:[48]:["+
                                           evpn_dict["leaf3"]["tenant_mac_l2_colon"]+"]",retry_count=5, delay=2,
                                           status_code="*>", next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        st.log("Step 11 nexthop for MAC {} updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                     evpn_dict["leaf2"]["loop_ip_list"][2]))
    else:
        success=False
        hdrMsg("Step 11 nexthop for MAC {} not updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                           evpn_dict["leaf2"]["loop_ip_list"][2]))

    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="1"):
        success = False
        hdrMsg("### Step 12 leaf3 still advertising the moved mac to leaf4, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("## Step 12 No MACs are advertised by leaf3 to leaf4 now as expected, passed #####")

    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="1"):
        success = False
        hdrMsg("## Step 13 leaf3 still advertising the moved mac to LVTEP N2, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("## Step 13 leaf3 not advertising the moved mac to leaf2 as expected, passed #####")

    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="1"):
        success = False
        hdrMsg("### Step 14 leaf3 still advertising the moved mac to LVTEP N2, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("### Step 14 leaf3 not advertising the moved mac to leaf2 as expected, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf4"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("### Step 15 leaf4 MACs are not learned in LVTEP N2, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("### Step 15 leaf4 MACs are learned in leaf2 as expected, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1]):
        success = False
        hdrMsg("### Step 16 leaf4 MACs are not learned in VLTEP N1, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("### Step 16 leaf4 MACs are learned in leaf1 as expected, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D5, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1],
                                                mac=evpn_dict["leaf4"]["tenant_mac_l2_colon"]):
        success = False
        hdrMsg("### Step 17 leaf4 MACs are not learned in leaf3, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("### Step 17 leaf4 MACs are learned successfully in leaf3, passed #####")
    '''
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D5, vni=evpn_dict["leaf3"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("### step 18 leaf2 not advertising moved MACs to leaf3, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########")
    else:
        st.log("### Step 18 leaf2 advertising moved MACs to leaf3 as expected, passed #####")
    '''
    st.log("### Step 19 verify no traffic received in leaf3 ###")
    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["intf_list_tg"][0], "tx_bps")
    if " KB/s" not in ktx[0]['tx_bps'] or " MB/s" not in ktx[0]['tx_bps']:
        st.log("##### NO traffic received in leaf3 as expected, passed #####")
    else:
        success=False
        hdrMsg("########## some traffic {} still coming to leaf3 which is"
                 " not expected, FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 ##########".format(ktx))
    hdrMsg("\n####### Step 20: Verify local mac learning in LVTEP nodes ##############\n")
    #if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],
    #                        vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
    #                        port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
    #    hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32331_2 FAIL: Local mac not learnt in LVTEP Node 1 ")
    #    success=False
    #    debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    #else:
    #    st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],retry_count=5, delay=2,
                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0]) or retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],
                            retry_count=5, delay=2,
                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        st.log("PASS: Step 21 Local mac learnt in LVTEP Nodes")
    else:
        hdrMsg("Step 21 test_FtOpSoRoEvpn5549LvtepFt32331_2 FAIL: Local mac not learnt in LVTEP Nodes")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ktx1 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["intf_list_tg"][0], "tx_bps")
    ktx2 = Evpn.get_port_counters(evpn_dict["mlag_client"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "tx_bps")
    st.log("### verify traffic received by MLAG client and Leaf4 ###")
    if " KB/s" in ktx1[0]['tx_bps'] and " KB/s" in ktx2[0]['tx_bps']:
        st.log("### Step 22 traffic verification passed after dynamic mac movement #####")
    elif " MB/s" in ktx1[0]['tx_bps'] and " MB/s" in ktx2[0]['tx_bps']:
        st.log("### Step 22 traffic verification passed after dynamic mac movement #####")
    elif int(float(ktx1[0]['tx_bps'].split(" ")[0])) > 1000 and int(float(ktx2[0]['tx_bps'].split(" ")[0])) > 1000:
        st.log("### Step 22 traffic verification passed after dynamic mac movement #####")
    else:
        success=False
        hdrMsg("Step 22 traffic verification FAIL test_FtOpSoRoEvpn5549LvtepFt32331_2 after dynamic mac movement,L4 & MLAG shows egress rate {} & {}:".format(ktx1,ktx2))

    tg.tg_traffic_control(action="stop", stream_handle=[stream_dict["l2_32331_2"],stream_dict["l2_32331_3"]])
    Mac.clear_mac(vars.D5)

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549LvtepFt32331_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549LvtepFt32331_2")

def test_FtOpSoRoEvpn5549LvtepFt32333_2(Tgencleanup_fixture):
    global vars
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32333; TC SUMMARY: MAC flapping b/w client to orphon port")
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32338; TC SUMMARY: Duplicate MAC detection should not be supported with in MLAG cluster nodes")

    tg = tg_dict['tg']
    st.log("### start L2 traffic from MLAG client port ###")
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32333_1"])

    mac_status = True
    hdrMsg("\n####### Step 1: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 2 ")

    hdrMsg("\n####### Step 2: Verify remote mac learning in SVTEP node ##############\n")
    if Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    st.log("### Stop the same traffic and start from LVTEP Node 2 orphon port ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32333_1"])
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32333_2"])

    hdrMsg("\n####### Step 3: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 2 ")
    hdrMsg("\n####### Step 4: Verify remote mac learning in SVTEP node ##############\n")
    if Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    st.log("### Stop the same traffic from LVTEP N2 orphon and start from LVTEP Node 1 orphon port ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32333_2"])
    Mac.clear_mac(vars.D3)
    Mac.clear_mac(vars.D4)
    Mac.clear_mac(vars.D6)
    Mac.clear_mac(vars.D7)
    st.wait(2)
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32333_3"])

    hdrMsg("\n####### Step 5: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 2 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 1 ")

    hdrMsg("\n####### Step 6: Verify remote mac learning in SVTEP node ##############\n")
    if Evpn.verify_mac(evpn_dict["leaf_node_list"][3],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32333_3"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549LvtepFt32333_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549LvtepFt32333_2")


def test_FtOpSoRoEvpn5549LvtepFt32318(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32318; TC SUMMARY:Flapping ;\
                   of the keepalive link when the traffic is on")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: MC LAG interface status check in LVTEP N2")

    st.log("Step 5: Start L2 IPv6 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32337"])

    hdrMsg("\n####### Step 6: Verify L2 BUM traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    tg = tg_dict['tg']

    traffic_details1 = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [2],
            'rx_ports': [tg_dict['d3_tg_port1']],
            'rx_obj': [tg],
        },
        '2': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [2],
            'rx_ports': [tg_dict['d4_tg_port1']],
            'rx_obj': [tg],
        },
    }

    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Step 7 Traffic verification passed from SVTEP to LVTEP BUM and LOCAL LVTEP BUM")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: Step 7 Traffic from SVTEP to BUM and LOCAL LVTEP BUM ")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Step 8: shutdown the peer link in LVTEP node 1 ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["iccpd_dintf_list"][0]])
    st.wait(2)

    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Traffic verification from SVTEP to LVTEP BUM and LOCAL LVTEP BUM after peer link down ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32318 FAIL: Traffic from SVTEP to LVTEP BUM and LOCAL LVTEP BUM after peer link down")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    ############################################################################################
    hdrMsg("\n###### Step 9: Bringup the peer link in LVTEP node 1 ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["iccpd_dintf_list"][0]])
    current_stream_dict["stream"] = stream_dict["l2_32337"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32318")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32318")

def test_FtOpSoRoEvpn5549LvtepFt32343(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32343; TC SUMMARY:Verify BUM path;\
                   selection per tunnel for multiple VLANs carrying BUM traffic")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: MC LAG interface status check in LVTEP N2")

    new_vlan = "451"
    st.log("Create a new VLAN 451 to use as L3 SAG VLAN for Vrf")
    utils.exec_all(True,[[Vlan.create_vlan,evpn_dict["leaf_node_list"][0],new_vlan],
            [Vlan.create_vlan,evpn_dict["leaf_node_list"][1],new_vlan],
            [Vlan.create_vlan,evpn_dict["mlag_client"][0],new_vlan],
            [Vlan.create_vlan,evpn_dict["leaf_node_list"][3],new_vlan]])

    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
            new_vlan, evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
            [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
            new_vlan, evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True],
            [Vlan.add_vlan_member, evpn_dict["mlag_client"][0],
            new_vlan, evpn_dict["mlag_tg_list"][0],True],
            [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
            new_vlan, evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    Vlan.add_vlan_member(evpn_dict["mlag_client"][0],new_vlan, evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True)

    st.log("config new sag vlan membershp for mc-lag iccpd link for data forwarding over mc-lag")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], new_vlan,
                        evpn_dict['leaf1']['iccpd_pch_intf_list'][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], new_vlan,
                        evpn_dict['leaf2']['iccpd_pch_intf_list'][0],True]])

    st.log("Add new SAG vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], new_vlan,new_vlan],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],new_vlan,new_vlan],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],new_vlan,new_vlan]])

    st.log("Step 4: Send IPv6 L2 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    '''
    create_stream("l2",port_han_list=[tg_dict['d7_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,
        src_mac_list=['00:10:16:01:01:01','00:10:16:06:01:01'],dst_mac_list=['00:10:16:06:01:02','00:10:16:01:01:02'],
        src_ip_list=['1001::100','1001::200'],dst_ip_list=['1001::201','1001::101'],
        src_ip_step_list=['00::2','00::2'],dst_ip_step_list=['00::2','00::2'],dst_ip_count_list=['2','2'],
        vlan_id_list=[evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
        src_mac_count_list=['2','2'],dst_mac_count_list=['1','1'])
    '''
    st.log("Step 5: Start L2 IPv6 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32343"])

    hdrMsg("\n####### Step 6: Verify L2 BUM traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic test L2 IPv6 BUM traffic b/w LVTEP to SVTEP with L3 SAG")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Traffic test L2 IPv6 BUM traffic b/w LVTEP to SVTEP with L3 SAG")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 7: Verify local mac learning in LVTEP nodes for new vlan ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:01:01:02",
                            vlan=new_vlan,
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:01:01:02",
                            vlan=new_vlan,
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Local mac not learnt in LVTEP Node 2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 2 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:02",
                            vlan=new_vlan,dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],
                            type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Remote mac not learnt in LVTEP Node 1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in LVTEP Node 1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:02",
                            vlan=new_vlan,dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],
                            type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Remote mac not learnt in LVTEP Node 2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in LVTEP Node 2 ")

    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:16:06:01:02",
                            vlan=new_vlan,
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Local mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32343 FAIL: Local mac not learnt in Leaf4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    leaf1_rx = [];
    leaf2_rx = [];
    leaf1_tx = 0;
    leaf2_tx = 0
    leaf1_rx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                                       interface=evpn_dict["leaf1"]["mlag_pch_intf_list"][0], property="rx_bps",
                                       cli_type="click")
    leaf2_rx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                                       interface=evpn_dict["leaf2"]["mlag_pch_intf_list"][0], property="rx_bps",
                                       cli_type="click")
    leaf1_rx_kb = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],
                                         evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx_kb = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],
                                         evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")

    lvtep_bum_forwarder_port1 = "";
    lvtep_bum_forwarder_port2 = ""
    num_path = 0
    hdrMsg("\n####### Step 8: Verify BUM traffic from LVTEP to SVTEP ##############\n")
    if " KB/s" in leaf1_rx_kb[0]['rx_bps'] or " MB/s" in leaf1_rx_kb[0]['rx_bps']:
        st.log("D3 receives traffic from mclag client")
        intf_list = evpn_dict["leaf1"]["pch_intf_list"] + [vars.D3D1P1,vars.D3D2P1]
        num_path, interf = verify_bum_forwarder(vars.D3, intf_list)
        if int(num_path) <= 2 and int(num_path) != 0:
            st.log("PASS: BUM traffic goes through one or two paths as expected")
            leaf1_bum_port = interf
            leaf1_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                                               interface=leaf1_bum_port, property="tx_bps", cli_type="click")

            if leaf1_tx >= int(float(leaf1_rx[0]['rx_bps'])) - 10:
                hdrMsg("PASS: BUM traffic is passed as per local bias in D3 before flapping"
                       "Tx rate: {}, Rx rate: {}".format(leaf1_tx, int(float(leaf1_rx[0]['rx_bps']))))
            else:
                hdrMsg("FAIL: BUM traffic is not passed as per local bias "
                       "in D3 before flapping, Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),
                                                                             str(leaf1_rx[0]['rx_bps'])))
                success = False

            port.shutdown(evpn_dict["leaf_node_list"][0], [leaf1_bum_port])
            st.wait(4)
            num_path, interf = verify_bum_forwarder(vars.D3, intf_list)
            if int(num_path) <= 2:
                st.log("PASS: BUM traffic goes through only one or two paths after shutting down the BUM link as expected")
                leaf1_bum_port1 = interf
                leaf1_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                                                   interface=leaf1_bum_port1, property="tx_bps", cli_type="click")
                if leaf1_tx >= int(float(leaf1_rx[0]['rx_bps'])) - 10:
                    hdrMsg("PASS: BUM traffic is passed as per local bias in D3 after flap"
                           "Tx rate: {}, Rx Rate {}".format(leaf1_tx, int(float(leaf1_rx[0]['rx_bps']))))
                else:
                    hdrMsg("FAIL: BUM traffic is not passed as per "
                           "local bias in D3 after flap, \
                                 Tx: {} and Rx: {}".format(str(leaf1_tx), str(leaf1_rx[0]['rx_bps'])))
                    success = False
            else:
                st.error("FAIL: BUM traffic takes more than one path or nothing after flapping the BUM link from D3")
                success = False
            port.noshutdown(evpn_dict["leaf_node_list"][0], [leaf1_bum_port])
        else:
            st.error("FAIL: BUM traffic takes more than one path or nothing from D3")
            success = False
    if " KB/s" in leaf2_rx_kb[0]['rx_bps'] or " MB/s" in leaf2_rx_kb[0]['rx_bps']:
        st.log("D4 receives traffic from mclag client")
        intf_list = evpn_dict["leaf2"]["pch_intf_list"] + [vars.D4D1P1, vars.D4D2P1]
        num_path, interf = verify_bum_forwarder(vars.D4, intf_list)
        if int(num_path) <= 2:
            st.log("PASS: BUM traffic goes through one or two paths as expected")
            leaf2_bum_port = interf
            leaf2_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                                               interface=leaf2_bum_port, property="tx_bps", cli_type="click")
            if leaf2_tx >= int(float(leaf2_rx[0]['rx_bps'])) - 10:
                hdrMsg("PASS: BUM traffic is passed as per local bias in D4 before flapping"
                       "Tx rate: {}, Rx rate: {}".format(leaf2_tx, int(float(leaf2_rx[0]['rx_bps']))))
            else:
                hdrMsg("FAIL: BUM traffic is not passed as per local bias "
                       "in D4 before flapping, Tx rate: {} and Rx rate: {}".format(str(leaf2_tx),
                                                                                   str(leaf2_rx[0]['rx_bps'])))
                success = False

            port.shutdown(evpn_dict["leaf_node_list"][1], [leaf2_bum_port])
            st.wait(4)
            num_path, interf = verify_bum_forwarder(vars.D4, intf_list)
            if int(num_path) <= 2:
                st.log("PASS: BUM traffic goes through one or two paths after flapping the BUM link as expected")
                leaf2_bum_port1 = interf
                leaf2_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                                                   interface=leaf2_bum_port1, property="tx_bps", cli_type="click")
                if leaf2_tx >= int(float(leaf2_rx[0]['rx_bps'])) - 10:
                    hdrMsg("PASS: BUM traffic is passed as per local bias in D4 after flapping"
                           "Tx rate: {}, Rx rate: {}".format(leaf2_tx, int(float(leaf2_rx[0]['rx_bps']))))
                else:
                    hdrMsg("FAIL: BUM traffic is not passed as per "
                           "local bias in D4 after flapping, \
                                  Tx rate: {} and Rx rate: {}".format(str(leaf2_tx), str(leaf2_rx[0]['rx_bps'])))
                    success = False
            else:
                st.error("FAIL: BUM traffic takes more than one path or nothing after flapping the BUM link from D4")
                success = False
            port.noshutdown(evpn_dict["leaf_node_list"][1], [leaf2_bum_port])
        else:
            st.error("FAIL: BUM traffic takes more than one path or nothing from D4")
            success = False

    st.log("Remove new SAG vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], new_vlan,new_vlan,"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],new_vlan,new_vlan,"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],new_vlan,new_vlan,"1", "no"]])

    st.log("Delete the new VLAN 451 to use as L3 SAG VLAN for Vrf")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
            new_vlan, evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
            new_vlan, evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0],
            new_vlan, evpn_dict["mlag_tg_list"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
            new_vlan, evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    Vlan.delete_vlan_member(evpn_dict["mlag_client"][0],new_vlan, evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True)

    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
            new_vlan, evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
            new_vlan, evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Delete new L3 SAG VLAN from Leaf node and L2 SW")
    utils.exec_all(True,[[Vlan.delete_vlan,evpn_dict["leaf_node_list"][0],new_vlan],
            [Vlan.delete_vlan,evpn_dict["leaf_node_list"][1],new_vlan],
            [Vlan.delete_vlan,evpn_dict["mlag_client"][0],new_vlan],
            [Vlan.delete_vlan,evpn_dict["leaf_node_list"][3],new_vlan]])
    current_stream_dict["stream"] = stream_dict["l2_32343"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32343")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32343")


@pytest.fixture(scope="function")
def Tgencleanup_fixture(request,evpn_underlay_hooks):
    yield

    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    ############################################################################################
    hdrMsg("\n####### Clear mac in LVTEP and SVTEP ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Intf.clear_interface_counters,dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])


def test_FtOpSoRoEvpn5549LvtepFt32313(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32313; TC SUMMARY:Symmetric Traffic to orphan port from remote leaf nodes")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL step 1 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 1 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf2"]["loop_ip_list"][2],
                       ip_address=evpn_dict["leaf2"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL step 2 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 2 - Verify IPv4 Prefix route in LVTEP node 1")

    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut4_gateway_mac = basic.get_ifconfig(vars.D4, vars.D4T1P1)[0]['mac']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    st.log("Step 5: Start L3 IPv4 traffic b/w LVTEP orphon port to SVTEP")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_32313_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_32313_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_32313"])
    st.wait(5, "Waiting for 5 sec before verify stats for stream id ipv4_32313")

    ###################################################################################
    hdrMsg("\n####### Step 6: Verify L3 traffic b/w LVTEP orphon port to SVTEP #########\n")
    ####################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["ipv4_32313"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv4_32313"][1],dest_tg_ph=tg_dict['d4_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-N2 to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL: Traffic verification failed b/w LVTEP-N2 To SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N2")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL: Traffic verification failed b/w SVTEP to LVTEP-N2")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 7: Verify local mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:00:14:04:04:01",
                            vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Local mac learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False

    hdrMsg("\n####### Step 8: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:00:14:06:04:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32313 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv4_32313"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32313")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32313")

def test_FtOpSoRoEvpn5549LvtepFt32312(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32312; TC SUMMARY:Asymmetric Traffic to orphan port from remote leaf nodes")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32312 FAIL step 1 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS step 1 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf2"]["loop_ip_list"][2],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32312 FAIL step 2 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS at step 2 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")

    st.log("Step 3: create VLANs for L3 tenant interfaces in LVTEP nodes ")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 4: Bind tenant L3 VLANs to TG port in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    st.log("Step 5: Extend the L3 tenant vlan in LVTEP nodes towards Leaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 6: Getting the router MAC for the L3 Traffic")
    dut4_gateway_mac = basic.get_ifconfig(vars.D4, vars.D4T1P1)[0]['mac']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_32312_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_32312_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_32312"])

    ###################################################################################
    hdrMsg("\n####### Step 9: Verify L3 traffic b/w LVTEP orphon port to SVTEP #########\n")
    ####################################################################################
    if verify_traffic(tx_port=vars.T1D4P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed b/w LVTEP orphon port to SVTEP")
        #debug_lvtep_trafic()
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32312 FAIL Traffic b/w LVTEP orphon port to SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 10: Verify local mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:14:04:06:01",
                            vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Local mac learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32312 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False

    hdrMsg("\n####### Step 11: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:14:06:06:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32312 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 13: Remove the L3 tenant vlan extension in leaf and leaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"1","no"]])

    st.log("Step 14: Remove binding of tenant L3 VLANs to TG port in LVTEP nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                         [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    st.log("Step 15: Remove VLANs for L3 tenant interfaces in LVTEP nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                         [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])
    current_stream_dict["stream"] = stream_dict["ipv6_32312"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32312")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32312")

def test_FtOpSoRoEvpn5549LvtepFt32316(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32316; TC SUMMARY:Traffic forwarding to ;\
                   silent hosts connected to MLAG leaf node on an MLAG leaf port;")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: MC LAG interface status check in LVTEP N2")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL step 3 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 3 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL step 4 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 4 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL Step 5 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 5 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")


    st.log("Step 4: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    st.log("Step 5: send uni-directional traffic from Leaf 4")
    tg = tg_dict['tg']

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL step 3 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 3 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL step 4 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 4 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL Step 5 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 5 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")


    st.log("Step 4: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    st.log("Step 5: send uni-directional traffic from Leaf 4")
    tg = tg_dict['tg']
    tg.tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["ipv4_3281_2"])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)

    st.log("########## Step 6: Verify LVTEP receives L3 unicast traffic ##########")
    traffic_details = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict['d7_tg_port1']],
            'rx_obj': [tg],
        }
    }

    ###################################################################################
    hdrMsg("\n####### Step 7: Verify L3 ipv6 slient host traffic from SVTEP to LVTEP MLAG #########\n")
    ####################################################################################
    if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Step 7 Traffic verification passed from SVTEP to LVTEP MLAG")
        #debug_lvtep_trafic()
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: Step 7 Traffic verification failed from SVTEP to LVTEP MLAG")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    ###################################################################################
    st.log("########## Step 8: verify LVTEP Orphon port NOT Rx L3 traffic ##########")
    ###################################################################################
    traffic_details1 = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [0],
            'rx_ports': [tg_dict['d3_tg_port1']],
            'rx_obj': [tg],
        },
    }
    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Step 8: Traffic verification passed from SVTEP to LVTEP Orphon port")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: Step 8: Traffic verification failed from SVTEP to LVTEP Orphon por")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### Step 9: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:66:14:06:01:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32316 FAIL: Remote mac not learnt in Leaf4")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv4_3281_2"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32316")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32316")


def test_FtOpSoRoEvpn5549LvtepFt32317(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32317; TC SUMMARY:Traffic forwarding to ;\
                   silent hosts connected to MLAG leaf node on an orphon port;")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv6",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],type="B",selected=">",fib="*",
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32317 FAIL step 1 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 1 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv6",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],type="B",selected=">",fib="*",
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32317 FAIL step 2 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 2 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv6",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32317 FAIL Step 3 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 3 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")


    st.log("Step 4: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    tg = tg_dict['tg']
    han1 = tg.tg_interface_config(port_handle=tg_dict["d4_tg_ph1"], mode='config',
                                ipv6_intf_addr='4001::11', ipv6_gateway='4001::1', vlan='1',
                                vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],ipv6_prefix_length="96",
                                vlan_id_step='0',arp_send_req='1', ipv6_gateway_step='::',
                                ipv6_intf_addr_step='::1', count=1, src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v6"])
    tg.tg_arp_control(handle=han1["handle"], arp_target='all')
    tg.tg_arp_control(handle=stream_dict["v6host_32317"], arp_target='all')
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["ipv6_32317"])

    if tg_dict["tg"].tg_type == 'stc':
        st.wait(10)
    elif tg_dict["tg"].tg_type == 'ixia':
        st.wait(5)

    st.log("########## Verify LVTEP receives L3 unicast traffic ##########")
    traffic_details = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict['d4_tg_port1']],
            'rx_obj': [tg],
        }
    }

    ###################################################################################
    hdrMsg("\n####### Step 5: Verify L3 ipv6 slient host traffic from SVTEP to LVTEP orphon port #########\n")
    ####################################################################################
    traffic_status = True
    result = False
    for i in range(5):
        if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",tolerance_factor=2):
            result = True
            break
        else:
            hdrMsg(" \n####### retry traffic verification as loss % is more than 2% b/w D6 towards D4\n")
            st.wait(2)
            continue
    if result:
        st.log("########## Traffic verification passed from SVTEP to LVTEP N2 orphon port  ##########")
    else:
        success = False
        traffic_status = False
        st.log("########## FAIL: Traffic verification failed from SVTEP to LVTEP N2 orphon port #######")

    ###################################################################################
    st.log("########## Step 6: verify LVTEP MLAG Client NOT Rx L3 traffic ##########")
    ###################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv6_32317"],dest_tg_ph=tg_dict['d7_tg_ph1'])
    if loss_prcnt >= 0.95:
        st.log("PASS: Step 6 Traffic verification passed from SVTEP to LVTEP NOT Rx by MLAG client")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32317 FAIL: Step 6 Traffic from SVTEP to LVTEP NOT Rx by MLAG client")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ###################################################################################
    hdrMsg("\n####### Step 7: Verify remote mac learning in SVTEP node ##############\n")
    ###################################################################################
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:00:14:06:01:02",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Step 7 Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32317 FAIL: Step 7 Remote mac not learnt in Leaf4")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv6_32317"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32317")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32317")

def test_FtOpSoRoEvpn5549LvtepFt32336(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32336; TC SUMMARY: Vxlan tunnel flapping in an MLAG cluster")

    hdrMsg("Step 3: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 4: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: MC LAG interface status check in LVTEP N1")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: MC LAG interface status check in LVTEP N2")

    st.log("Step 7: Start L2 IPv6 BUM traffic b/w LVTEP orphon port & SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32336"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(7,"wait for 7 seconds before verifying stream results")

    hdrMsg("\n####### Step 8: Verify L2 BUM traffic verification #########\n")
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32336"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32336"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-N1 to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Traffic verification failed b/w LVTEP-N1 To SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N1")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Traffic verification failed b/w SVTEP to LVTEP-N1")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf1"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][3],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    #hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    #if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not learnt in Leaf1 ")
    #    success=False
    #else:
    #    st.log("PASS: Remote Mac learnt in Leaf1 ")

    #if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not learnt in Leaf2 ")
    #    success=False
    #else:
    #    st.log("PASS: Remote Mac learnt in Leaf2 ")

    ############################################################################################
    hdrMsg("\n###### Step 12: Shutdown the LVTEP N1 orphon port forwarding traffic to SVTEP ######\n")
    ############################################################################################
    #port.shutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["intf_list_tg"][0]])
    Vlan.delete_vlan_member(evpn_dict["leaf_node_list"][0],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True)

    hdrMsg("\n####### Step 13: Verify local mac learning in LVTEP nodes ##############\n")
    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf1"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac still resent in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac withdrawn in Leaf1 ")

    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac still present in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac withdrawn in Leaf2 ")

    hdrMsg("\n####### Step 14: Verify remote mac learning in SVTEP node ##############\n")
    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][3],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac still present in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac withdrawn in Leaf4 ")

    hdrMsg("\n####### Step 15: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

    ############################################################################################
    hdrMsg("\n###### Step 16: Bring up LVTEP N1 orphon port forwarding traffic to SVTEP ######\n")
    ############################################################################################
    #port.noshutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["intf_list_tg"][0]])
    Vlan.add_vlan_member(evpn_dict["leaf_node_list"][0],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf1"]["intf_list_tg"][0],True)
    st.wait(2)

    hdrMsg("\n####### Step 17: Verify local mac learning in LVTEP nodes after TG port is up ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")


    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n Step 18: Bring down vxlan tunnel in LVTEP N1 by shuting down all uplinks \n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
        port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])
        if " KB/s" in ktx[0]['tx_bps'] or " MB/s" in ktx[0]['tx_bps']:
            st.log("INFO: LVTEP N1 L2 traffic forwader port is : {}".format(interface1))

    #hdrMsg("\n####### Step 19: Verify remote mac learning in SVTEP node ##############\n")
    #if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:16:01:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
    #                        dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not present in Leaf4")
    #    success=False
    #else:
    #    st.log("PASS: Remote mac present in Leaf4 as LVTEP other peer is still Up")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac not present in LVTEP N2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac withdrawn in Leaf2 ")

    st.wait(10)
    hdrMsg("\n Step 20: Check the mac in LVTEP peer node \n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32336 FAIL: Remote mac still learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac withdrawn in Leaf1 ")

    hdrMsg("\n Step 21: Bring up vxlan tunnel in LVTEP N1 by bringing up all the uplinks")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32336"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32336")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32336")

def test_FtOpSoRoEvpn5549LvtepFt3234_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3234; TC SUMMARY : Asymmetric routing from Single node leaf node to MLAG leaf node")
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3235; TC SUMMARY : Asymmetric routing from MLAG leaf node to single node leaf node")
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3253; TC SUMMARY : Verify L3 traffic from LVTEP to SVTEP using IPv4 SAG and vice versa")
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt3254; TC SUMMARY : Verify L3 traffic from LVTEP to SVTEP using IPv6 SAG and vice versa")

    st.log("Step 1: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    st.log("Step 3: Start L3 IPv4 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    st.log("Step 4: Verify L3 IPv4 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: IPv4 Traffic PASS from SVTEP TO LVTEP and vice versa")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL: IPv4 Traffic failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Stop L3 IPv4 traffic from MLAG client port to Leaf 4")
    start_traffic(action="stop", stream_han_list=stream_dict["ipv4_3281"])
    
    st.log("Step 3.1: Start L3 IPv6 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_3281"])

    st.log("Step 4.1: Verify L3 IPv6 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: IPv6 Traffic verification passed from SVTEP TO LVTEP ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL: IPv6 Traffic failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Stop L3 IPv6 traffic from MLAG client port to Leaf 4")
    start_traffic(action="stop", stream_han_list=stream_dict["ipv6_3281"])
    
    st.log("Step 5: create VLANs for L3 tenant interfaces in LVTEP nodes ")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 6: Bind tenant L3 VLANs to TG port in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    st.log("Step 7: Extend the L3 tenant vlan in LVTEP nodes towards Leaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 8: Configure non default L3 RT import and export under Vrf1 in leaf 1 and Leaf4")
    dict1 = {"config": "yes","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0],
             "l3_export_rt":"33:33","l3_import_rt":"44:44","local_as":evpn_dict["leaf1"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict2 = {"config": "yes","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0],
             "l3_export_rt":"44:44","l3_import_rt":"33:33","local_as":evpn_dict["leaf2"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict3 = {"config": "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],
             "l3_export_rt":"66:66","l3_import_rt":"33:33","local_as":evpn_dict["leaf4"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]], Evpn.config_bgp_evpn, [dict1,dict2,dict3])

    dict1 = {"config": "yes","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0],
             "l3_import_rt":"66:66","local_as":evpn_dict["leaf1"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict2 = {"config": "yes","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0],
             "l3_import_rt":"66:66","local_as":evpn_dict["leaf2"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict3 = {"config": "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],
             "l3_import_rt":"44:44","local_as":evpn_dict["leaf4"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]], Evpn.config_bgp_evpn, [dict1,dict2,dict3])

    st.log(" Step 9: Verify Leaf 1 tenant IPv4 prefix route in Leaf 1 ")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],
                                vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL Step 9 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log("Step 9 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],
                                vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL Step 9 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log("Step 9 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")

    st.log(" Verify SAG IPv6 prefix route in Leaf 4 towards Leaf 3 ")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0],
                                type="C",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL step 2 - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 7 PASSED - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL Step 6 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 6 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],
                                vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL Step 6 - Verify SAG tenant IPv4 prefix route in Leaf 1 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 6 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 1 towards LVTEP SAG")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",type="C",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL step 2 - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 7 PASSED - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")

    st.log("Step 11: Start L3 IPv4 and IPv6 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    st.log("Step 12: Verify L3 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP and vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt3234_2 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 13: Remove non default L3 RT import and export under Vrf1 in leaf 1 and Leaf4")
    dict1 = {"config": "no","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0],
             "l3_export_rt":"33:33","l3_import_rt":"44:44","local_as":evpn_dict["leaf1"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict2 = {"config": "no","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0],
             "l3_export_rt":"44:44","l3_import_rt":"33:33","local_as":evpn_dict["leaf2"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict3 = {"config": "no","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],
             "l3_export_rt":"66:66","l3_import_rt":"33:33","local_as":evpn_dict["leaf4"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]], Evpn.config_bgp_evpn, [dict1,dict2,dict3])

    dict1 = {"config": "no","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0],
             "l3_import_rt":"66:66","local_as":evpn_dict["leaf1"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict2 = {"config": "no","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0],
             "l3_import_rt":"66:66","local_as":evpn_dict["leaf2"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    dict3 = {"config": "no","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],
             "l3_import_rt":"44:44","local_as":evpn_dict["leaf4"]['local_as'],"config_type_list": ["vrf_rd_rt"]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]], Evpn.config_bgp_evpn, [dict1,dict2,dict3])

    st.log("Step 14: Remove the L3 tenant vlan extension in leaf and leaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"1","no"]])

    st.log("Step 15: Remove binding of tenant L3 VLANs to TG port in LVTEP nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                         [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    st.log("Step 16: Remove VLANs for L3 tenant interfaces in LVTEP nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                         [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])
    current_stream_dict["stream"] = stream_dict["ipv4_3281"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt3234_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt3234_2")

def test_FtOpSoRoEvpn5549LvtepFt32314(Lvtep_5549_32314_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549LvtepFt32314; TC SUMMARY: Traffic through SAG within the MLAG")

    st.log("verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    ############################################################################################
    hdrMsg(" \n####### Configure L3 streams on MCLAG- Leaf1 orphan port and MCLAG client TGEN##############\n")
    ############################################################################################
    arp.add_static_arp(evpn_dict["leaf_node_list"][0],'30.1.1.100','00:00:14:06:01:01' , interface="Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.add_static_arp(evpn_dict["leaf_node_list"][1],'30.1.1.100','00:00:14:06:01:01' , interface="Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.add_static_arp(evpn_dict["leaf_node_list"][0], '120.1.1.100','00:00:14:11:01:01',
                       interface="Vlan{}".format(evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]))
    Mac.config_mac(evpn_dict["leaf_node_list"][0], '00:00:14:06:01:01',evpn_dict['leaf1']["tenant_l3_vlan_list"][0],evpn_dict["leaf1"]["intf_list_tg"][0])
    Mac.config_mac(evpn_dict["leaf_node_list"][1], '00:00:14:06:01:01',evpn_dict['leaf1']["tenant_l3_vlan_list"][0],evpn_dict["leaf2"]["iccpd_pch_intf_list"][0])
    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_32314_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_32314_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_32314"])
    ############################################################################################
    hdrMsg("\n####### Verify L3 traffic within MCLAG peers ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D3P1,rx_port=vars.T1D7P1):
        st.log("PASS: Traffic verification passed ")
        #debug_lvtep_trafic()
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_mclag_uniqueip()
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][1])

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:00:14:11:01:01",
                           vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                           port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32314 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:00:14:11:01:01",
                           vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                           port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],retry_count=3, delay=2):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32314 FAIL: remote mac not learnt in LVTEP Node 2")
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 2 ")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:00:14:06:01:01",
                           vlan=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],retry_count=3, delay=2,
                           port=evpn_dict["leaf1"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32314 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    ############################################################################################
    hdrMsg("\n####### Delete and Re-add SAG  IP from LVTEP nodes ##############\n")
    ############################################################################################

    dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], "mask":"24","config":"remove"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_ip, [dict1]*4)

    dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], "mask":"24","config":"add"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], sag.config_sag_ip, [dict1]*4)
    st.wait(10)
    ############################################################################################
    hdrMsg("\n####### Verify L3 traffic within MCLAG peers after delete/re-add SAG IP from LVTEP peers ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D3P1,rx_port=vars.T1D7P1):
        st.log("PASS: Traffic verification passed ")
        #debug_lvtep_trafic()
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][1])

    ############################################################################################
    hdrMsg("\n####### Delete and Re-add SAG  MAC from LVTEP nodes ##############\n")
    ############################################################################################

    dict1 = {"mac": evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], "config": "remove"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_mac, [dict1]*4)

    dict1 = {"mac": evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], "config": "add"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], sag.config_sag_mac, [dict1]*4)
    st.wait(12)
    ############################################################################################
    hdrMsg("\n####### Verify L3 traffic within MCLAG peers after delete/re-add SAG MAC from LVTEP peers ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D3P1, rx_port=vars.T1D7P1):
        st.log("PASS: Traffic verification passed ")
        #debug_lvtep_trafic()
    else:
        success = False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])

    st.log("\n #### Stopping the traffic stream ####\n")
    start_traffic(action="stop", stream_han_list=stream_dict["ipv4_32314"])

    st.log("\n #### Remove static arp, arp,mac ####\n")
    arp.delete_static_arp(evpn_dict["leaf_node_list"][0], '30.1.1.100',
                          "Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.delete_static_arp(evpn_dict["leaf_node_list"][1], '30.1.1.100',
                          "Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.delete_static_arp(evpn_dict["leaf_node_list"][0], '120.1.1.100',
                          "Vlan{}".format(evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]))
    Mac.delete_mac(evpn_dict["leaf_node_list"][0], '00:00:14:06:01:01', evpn_dict['leaf1']["tenant_l3_vlan_list"][0])
    Mac.delete_mac(evpn_dict["leaf_node_list"][1], '00:00:14:06:01:01', evpn_dict['leaf1']["tenant_l3_vlan_list"][0])

    ############################################################################################
    hdrMsg("\n####### Start and Verify BiDirectional L2 traffic within MCLAG peers ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32314"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(5,"wait for 5 seconds before verifying stream results")

    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32314"][0],dest_tg_ph=tg_dict['d7_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_32314"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-N1 to LVTEP MLAG client")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32314 FAIL: Traffic verification failed b/w LVTEP-N1 to LVTEP MLAG client")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP MLAG client to LVTEP-N1")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32314 FAIL: Traffic verification failed b/w LVTEP MLAG client to LVTEP-N1")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])

    current_stream_dict["stream"] = stream_dict["l2_32314"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt32314")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt32314")

def test_FtOpSoRoEvpn5549LvtepFt372(Linktrack_fixture):
    success = True
    hdrMsg("TC ID: FtOpSoRoEvpn5549LvtepFt372; TC SUMMARY : To verify the track port functionality of both mclag and orphan port interface while flapping the upstream interfaces")

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

    hdrMsg(" \n####### Step 2 Enabling up link tracking on LVTEP nodes ##############\n")
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='yes')
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='yes')

    hdrMsg(" \n####### Step 3 Configuring the up link tracking ports ##############\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3], \
        evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"10",
            downinterface=evpn_dict["leaf1"]["intf_list_tg"][0])

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0], \
        "track1",evpn_dict["leaf1"]["intf_list_spine"][3],"10",description="uplink_protection")

    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3], \
        evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"10",
            downinterface=evpn_dict["leaf2"]["intf_list_tg"][0])

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1", \
        evpn_dict["leaf2"]["intf_list_spine"][3],"10",description="uplink_protection")

    hdrMsg("Step 4: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 6: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="10",description="uplink_protection"):
        st.log("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="10",description="uplink_protection"):
        st.log("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg("Step 7: verify link state tracking status in LVTEP node 1 and LVTEP node 2")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["intf_list_tg"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="10",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 8: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    st.wait(5, "Waiting for 5 sec before verify stats for stream id l2_372_1")

    ############################################################################################
    hdrMsg("\n####### step 9: Verify L2 traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_1")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_1 - LVTEP 2 orphon port and Leaf 4")
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],dest_tg_ph=tg_dict['d4_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### step 10: Start L2 traffic b/w LVTEP 1 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32311"])
    st.wait(5, "Waiting for 5 sec before verify stats for stream id l2_32311")

    ############################################################################################
    hdrMsg("\n####### step 11: Verify L2 traffic b/w LVTEP 1 & 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.2 and loss_prcnt2 < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_1 & l2_32311")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_1 & l2_32311")
        hdrMsg("step 11: Stream l2_32311 loss% ={}, l2_372_1 loss% ={}".format(loss_prcnt1,loss_prcnt2))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32311"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### step 12: Start L2 bidirectional traffic b/w LVTEP CCEP port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_2"])
    st.wait(5, "Waiting for 5 sec before verify stats for stream id l2_372_2")

    ############################################################################################
    hdrMsg("\n####### step 13: Verify L2 bidirectional traffic b/w LVTEP CCEP port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_372_2"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_2")
        hdrMsg("Stream l2_372_2 loss% ={}".format(loss_prcnt))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_2"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### step 14: shutting down the linktrack upstream interfaces in LVTEP Node 1 ##########\n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])

    st.wait(2)
    st.log(" step 15: verify MC LAG interface status in LVTEP node 1 after uplink ports are down")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                    mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                    mclag_intf_local_state="Down", mclag_intf_peer_state="Up", \
                    mclag_intf_l3_status='No',isolate_peer_link='Yes',traffic_disable='Yes'):
        st.log("PASS: MC LAG domain status check in LVTEP N1 after uplink failure")
    else:
        success=False
        hdrMsg("step 15 FtOpSoRoEvpn5549LvtepFt372 FAIL: MC LAG domain status check in LVTEP N1 after uplink failure")

    st.log(" step 16: verify linktrack status upstream down and downstream disabled state after uplink made down")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",
                    description="uplink_protection",timeout="10",
                    direction=["Upstream"]*2+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                    evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["intf_list_tg"][0],
                    evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                    direction_state=["Down","Down","Disabled","Disabled"],retry_count=5, delay=1):
        st.log("PASS: step 16: Linktrack Downstream status is Disabled in LVTEP N1")
    else:
        success=False
        hdrMsg("step 16: FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack Downstream status is not Disabled in LVTEP N1")
    ############################################################################################
    hdrMsg("\n### Step 17: Verify if L2 traffic goes through other MLAG peer node after LVTEP Node 1 uplink down ###\n")
    ############################################################################################
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.4 and loss_prcnt2 < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_1 & l2_32311")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_1 & l2_32311")
        hdrMsg("step 17-a: Stream l2_32311 loss% ={}, l2_372_1 loss% ={}".format(loss_prcnt1,loss_prcnt2))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32311"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],dest_tg_ph=tg_dict['d4_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_372_2"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_2")
        hdrMsg("step 17-b Stream l2_372_2 loss% ={}".format(loss_prcnt))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_2"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### step 18: Bringing up the shutdown upstream interfaces in LVTEP Node 1 ##########\n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    st.wait(2)
    hdrMsg("step 19: verify link state tracking status in LVTEP node 1 and LVTEP node 2 after uplink comes up")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",
                        description="uplink_protection",timeout="10",direction=["Upstream"]*4+["Downstream"]*2,
                        interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["intf_list_tg"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=7, delay=2):
        st.log("step 19 PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg("step 19 FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack status not Up in LVTEP N1 after 10 sec since uplink comes up with linktrack timeout value configred as 2 sec")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",
                        description="uplink_protection",timeout="10",direction=["Upstream"]*4+["Downstream"]*2,
                        interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=7, delay=2):
        st.log("step 20 PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg("step 20 FtOpSoRoEvpn5549LvtepFt372 FAIL: Linktrack status is not Up in LVTEP N2")

    if not session_tunnel_status_check(evpn_dict["leaf_node_list"][0],domain=tg_dict['mlag_domain_id']):
        success=False

    ############################################################################################
    hdrMsg("\n### step 21: Verify L2 traffic b/w LVTEP 1 & 2 orphon port and Leaf 4 after LVTEP Node 1 uplink bring up ###\n")
    ############################################################################################
    st.wait(10)
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.41 and loss_prcnt2 < 0.2:
        st.log("PASS: Traffic verification passed for stream id l2_372_1 & l2_32311")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_1 & l2_32311")
        hdrMsg("step 21-a: Stream l2_32311 loss% ={}, l2_372_1 loss% ={}".format(loss_prcnt1,loss_prcnt2))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32311"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_1"][1],dest_tg_ph=tg_dict['d4_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_372_2"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.41:
        st.log("PASS: Traffic verification passed for stream id l2_372_2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt372 FAIL: Traffic verification failed for stream id l2_372_2")
        hdrMsg("step 21-b Stream l2_372_2 loss% ={}".format(loss_prcnt))
        get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_372_2"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### step 22 : Stop traffic ##############\n")
    ############################################################################################
    current_stream_dict["stream"] = [stream_dict["l2_372_1"] + stream_dict["l2_32311"] + stream_dict["l2_372_2"]]
    hdrMsg(" \n####### Step 23: Removing uplink tracking ports ##############\n")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][7],
        "2","no",description="uplink_protection")

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["pch_intf_list"][1],
        "2","no",downinterface=evpn_dict["leaf2"]["intf_list_tg"][0])
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt372")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt372")

def test_FtOpSoRoEvpn5549LvtepFt373(Linktrack_fixture):
    success = True
    hdrMsg("TC ID: FtOpSoRoEvpn5549LvtepFt373; TC SUMMARY: To verify the track port functionality of both mclag and orphan port portchannel while flapping the upstream interfaces")

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

    hdrMsg(" \n####### Step 2 Enabling up link tracking on LVTEP nodes ##############\n")
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='yes')
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='yes')

    hdrMsg(" \n### Step 3 Creating the orphon port PortChannel 100 and conigure its vlan membership ###\n")
    utils.exec_all(True,[[pch.create_portchannel,evpn_dict["leaf_node_list"][0],"PortChannel100",False,"",True],
                    [pch.create_portchannel,evpn_dict["leaf_node_list"][1],"PortChannel100",False,"",True]
                    ])

    hdrMsg("\n## Step 4 Configuring link track upstream orphon port as port channel before its member port added to verify forearding reference ##\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3],evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"10",downinterface="PortChannel100")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][3],"10",
        description="uplink_protection")

    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3],evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"10",downinterface="PortChannel100")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["intf_list_spine"][3],"10",
        description="uplink_protection")

    hdrMsg(" \n### Step 5 Remove the ohphon port from vlans before adding ad member port to orphon PortChannel 100  ###\n")
    for vlan1,vlan2 in zip([evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], \
        evpn_dict["leaf1"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]], \
            [evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], \
                evpn_dict["leaf2"]["l3_vni_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]):
        utils.exec_all(True,[[Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][0],
                              vlan1,evpn_dict["leaf1"]["intf_list_tg"][0],True],
                             [Vlan.delete_vlan_member,evpn_dict["leaf_node_list"][1],
                              vlan2,evpn_dict["leaf2"]["intf_list_tg"][0],True]])

    hdrMsg(" \n### Step 6 Checking LVTEP node linktrack status for non exitsing orphon port PortChannel 100 ####\n")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Down","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="10",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Down","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N2")

    hdrMsg(" \n### Step 7 Configuring the orphon port PortChannel 100 vlan membership ###\n")
    utils.exec_all(True,[
               [pch.add_portchannel_member,evpn_dict["leaf_node_list"][0],"PortChannel100",evpn_dict["leaf1"]["intf_list_tg"][0]],
               [pch.add_portchannel_member,evpn_dict["leaf_node_list"][1],"PortChannel100",evpn_dict["leaf2"]["intf_list_tg"][0]]
               ])
    utils.exec_all(True,[
               [Vlan.add_vlan_member,evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100"],
               [Vlan.add_vlan_member,evpn_dict["leaf_node_list"][1],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],"PortChannel100"]
               ])

    hdrMsg("Step 7: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 8: verify MC LAG interface status in LVTEP node 1 and LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                        mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                        mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                        mclag_intf_l3_status='No',isolate_peer_link='Yes',
                        traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 9: verify link state tracking summary in LVTEP node 1 and LVTEP node 2")
    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="10",description="uplink_protection"):
        st.log("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="10",description="uplink_protection"):
        st.log("PASS: Linktrack summary status in LVTEP N2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack summary status in LVTEP N2")

    hdrMsg("Step 10: verify link state tracking status in LVTEP node 1 and LVTEP node 2")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="10",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N2")

    ############################################################################################
    hdrMsg(" \n####### step 11: Start L2 bidirectional traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_1"])
    st.wait(5)
    ############################################################################################
    hdrMsg("\n####### step 12: Verify L2 traffic b/w LVTEP 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Traffic verification failed b/w LVTEP 2 orphon port and Leaf 4")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### step 13: Start L2 traffic b/w LVTEP 1 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32311"])
    st.wait(5)
    ############################################################################################
    hdrMsg("\n####### step 14: Verify L2 traffic b/w LVTEP 1 & 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.2 and loss_prcnt2 < 0.2:
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Traffic verification failed ")
        hdrMsg("Stream l2_32311 loss% ={}, l2_372_1 loss% ={}".format(loss_prcnt1,loss_prcnt2))
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### step 15: Start L2 bidirectional traffic b/w LVTEP CCEP port and Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_372_2"])
    st.wait(5)
    ############################################################################################
    hdrMsg("\n####### step 16: Verify L2 bidirectional traffic b/w LVTEP CCEP port and Leaf 4 ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_372_2"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Traffic verification failed ")
        hdrMsg("step 16 Stream l2_372_1 loss% ={}".format(loss_prcnt))
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### step 17: shutting down the linktrack upstream interfaces in LVTEP Node 1 ##########\n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])

    st.wait(2)
    st.log(" step 18: verify MC LAG interface status in LVTEP node 1 after uplink ports are down")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                    mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                    mclag_intf_local_state="Down", mclag_intf_peer_state="Up", \
                    mclag_intf_l3_status='No',isolate_peer_link='Yes',traffic_disable='Yes'):
        st.log("PASS: MC LAG domain status check in LVTEP N1 after uplink failure")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: MC LAG domain status check in LVTEP N1 after uplink failure")

    st.log(" step 18: verify link uplink down and ownlink disabled status after uplink ports are down")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                    direction=["Upstream"]*2+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                    evpn_dict["leaf1"]["intf_list_spine"][7],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                    direction_state=["Down","Down","Disabled","Disabled"],retry_count=7, delay=1):
        st.log("PASS: step 13: Linktrack Downstream status is Disabled in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack Downstream status is not Disabled in LVTEP N1")
    ############################################################################################
    hdrMsg("\n####### Step 19: Verify if L2 traffic goes through other MLAG peer node ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt < 0.2:
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: L2 Traffic verification not passing through other LVTEP peer node ")
        hdrMsg("step 19 Stream l2_372_1 loss% ={}".format(loss_prcnt))
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### step 20: Bringing up the shutdown upstream interfaces in LVTEP Node 1 ##########\n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    st.wait(2)
    hdrMsg("step 21: verify link state tracking status in LVTEP node 1 and LVTEP node 2 after uplinks comes up")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=7, delay=2):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N1 after waiting for 50 sec with linktrack timeout 2 sec")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="10",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Up","Up"],retry_count=7, delay=2):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N2")

    if not session_tunnel_status_check(evpn_dict["leaf_node_list"][0],domain=tg_dict['mlag_domain_id']):
        success=False

    ############################################################################################
    hdrMsg("\n####### step 22: Verify L2 traffic b/w LVTEP 1 & 2 orphon port and Leaf 4 ##############\n")
    ############################################################################################
    techsupport_not_gen = True
    current_stream_dict["stream"] = [stream_dict["l2_372_1"] + stream_dict["l2_32311"] + stream_dict["l2_372_2"]]
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32311"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["l2_372_1"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt3 = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_372_2"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.3 and loss_prcnt2 < 0.2 and loss_prcnt3 < 0.31:
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("FtOpSoRoEvpn5549LvtepFt373 FAIL: Traffic verification failed ")
        hdrMsg("Stream l2_32311 loss% ={}, l2_372_1 loss% ={}, & l2_372_2 loss% = {}".format(loss_prcnt1,loss_prcnt2,loss_prcnt3))
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='FtOpSoRoEvpn5549LvtepFt373')

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

    hdrMsg(" \n### Step 26 Checking LVTEP node linktrack status after deleting vlan membership of PortChannel 100 ####\n")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="uplink_protection",timeout="10",
                        direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                        evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                        evpn_dict["leaf1"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Down","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="uplink_protection",
                        timeout="10",direction=["Upstream"]*4+["Downstream"]*2,interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                        evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                        evpn_dict["leaf2"]["pch_intf_list"][1],"PortChannel100",evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                        direction_state=["Up","Up","Up","Up","Down","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg(" FtOpSoRoEvpn5549LvtepFt373 FAIL: Linktrack status is not Up in LVTEP N2")

    hdrMsg(" \n## Step 27: removing link track downstream orphon port channel after deleting portchannel to check forwarding reference ##\n")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][3],
        "2","no",description="uplink_protection",downinterface="PortChannel100")

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["intf_list_spine"][3],
        "2","no",description="uplink_protection",downinterface="PortChannel100")

    ######################################################################
    hdrMsg("\n## step 28 : Removing the orphon port PortChannel100  ##\n")
    ######################################################################
    utils.exec_all(True,[[pch.delete_portchannel,evpn_dict["leaf_node_list"][0],"PortChannel100"],
                [pch.delete_portchannel,evpn_dict["leaf_node_list"][1],"PortChannel100"]
                ])

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549LvtepFt373")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549LvtepFt373")

def test_FtOpSoRoLvtep5549Ft3281_3(Tgencleanup_fixture):

    success = True
    tc_list = ["test_FtOpSoRoLvtep5549Ft3281","test_FtOpSoRoLvtep5549Ft32111","test_FtOpSoRoLvtep5549Ft32114"]
    tc_list_summary = ["Verify RFC 5549 underlay with BFD enabled running traffic across IPv6 link specific trigger",
                       "Verify underlay ECMP with IPv4 and IPv6 traffic",
                       "Verify change in underlay ECMP path to single path and vice versa"]

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict['leaf1']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='8')
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict['leaf2']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='8')

    st.wait(2,"Waiting for 8 ECMP paths configured to come into effect")
    make_global_vars()
    globals().update(data)

    for dut in [vars.D3,vars.D4]:
        Ip.show_ip_route(dut)

    intf_list = data.leaf1_po_list+[vars.D3D1P1, vars.D3D2P1]
    intf_list2 = data.leaf2_po_list+[vars.D4D1P1, vars.D4D2P1]
    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_3281"])

    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Step 2 - Verify ECMP for L2 Traffic #########\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: L2 Traffic is load balanced for more than 1 path from D3 and D4 as expected')
        st.report_tc_pass("test_FtOpSoRoEvpn5549LvtepFt32114", "tc_passed")
    else:
        st.error('FAIL: L2 Traffic not passing through more than 1 path from D3/D4')
        success = False

    ############################################################################################
    hdrMsg("\n####### Step 3 - Cleanup L2 stream and create IPv4 stream #########\n")
    ############################################################################################
    start_traffic(action="stop", stream_han_list=stream_dict["l2_3281"])

    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])
    #dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D6T1P1)[0]['mac'])

    st.log("Step 5: Start L3 IPv4 and IPv6 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    ############################################################################################
    hdrMsg(" \n####### Step 4 - Verify ECMP for IPv4 Traffic #########\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list,dut="",rate=65.0)
    num_of_paths2 = check_ecmp(intf_list2,dut=vars.D4,rate=65.0)

    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: IPv4 Traffic is load balanced for more than 1 path from D3 and D4 as expected')
        st.report_tc_pass("test_FtOpSoRoEvpn5549LvtepFt32111", "tc_passed")
    else:
        st.error('FAIL: IPv4 Traffic not passing through more than 1 path from D3/D4')
        success = False
    
    ############################################################################################
    hdrMsg("\n########## Step 5 - Clear ARP table in Dut3 ############\n")
    ############################################################################################
    arp_api.clear_arp_table(vars.D3)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n###### Step 6 - Verify traffic ######\n")
    ############################################################################################
    for i in range(3):
        result = verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1)
        if result is False:
            hdrMsg(" \n####### retry traffic verification after clear ARP #####\n")
            continue
        else:
            break
    if result:
        st.log("PASS: Traffic verification passed after clear arp.")
    else:
        success = False
        st.error("FAIL: Traffic verification failed after clear arp.")
        debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][3])
        st.report_fail("test_case_id_failed", "test_FtOpSoRoLvtep5549Ft3281")

    ############################################################################################
    hdrMsg(" \n####### Step 7 - Cleanup IPv4 stream and create IPv6 stream #########\n")
    ############################################################################################
    start_traffic(action="stop", stream_han_list=stream_dict["ipv4_3281"])
    #create_stream("ipv6", rate=10000, src_ip_count_list=['15','15'], dst_ip_count_list=['15','15'], dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    st.log("Send IPv6 traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_3281"])
    ############################################################################################
    hdrMsg(" \n####### Step 8 - Verify ECMP for IPv6 Traffic #########\n")
    ############################################################################################

    num_of_paths = check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: Ipv6 Traffic is load balanced for more than 1 path from D3 and D4 as expected')
    else:
        st.error('FAIL: Ipv6 Traffic not passing through more than 1 path from D3/D4')
        success = False

    ############################################################################################
    hdrMsg("\n########## Step 9 - Clear ND table in Dut3 ############\n")
    ############################################################################################
    arp_api.clear_ndp_table(vars.D3)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n###### Step 10 - Verify traffic ######\n")
    ############################################################################################
    for i in range(3):
        result = verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1)
        if result is False:
            hdrMsg(" \n####### retry traffic verification after clear ND #####\n")
            continue
        else:
            break
    if result:
        st.log("PASS: Traffic verification passed after clear ND")
    else:
        success = False
        st.error("FAIL: Traffic verification failed after clear ND")
        debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][3])
        st.report_fail("test_case_id_failed", "test_FtOpSoRoLvtep5549Ft3281")

    start_traffic(action="stop", stream_han_list=stream_dict["ipv6_3281"])
    hdrMsg("\n###### Start L2,Ipv4 and IPv6 traffic again ######\n")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l2_3281"] + stream_dict["ipv4_3281"] + stream_dict["ipv6_3281"])

    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed with L2 and L3 streams.")
    else:
        success=False
        st.error("FAIL: Traffic verification failed with L2 and L3 streams")

    ############################################################################################
    hdrMsg("\n###### Step 13 - Flap the link between leaf1 and Spine1 10 times ######\n")
    ############################################################################################
    for i in range(0,10):
        port.shutdown(evpn_dict["leaf_node_list"][0],[vars.D3D1P1])
        port.noshutdown(evpn_dict["leaf_node_list"][0],[vars.D3D1P1])

    ############################################################################################
    hdrMsg("\n###### Step 17 - Shut the physical intf member of PO and verify traffic ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["spine_node_list"][0],[vars.D1D3P2, vars.D1D3P3])

    ############################################################################################
    hdrMsg("\n###### Step 18 - Verify traffic ######\n")
    ############################################################################################

    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed after PO down")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after PO down")

    ############################################################################################
    hdrMsg("\n###### Step 19 - Unshut the PO and verify ECMP ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["spine_node_list"][0],[vars.D1D3P2, vars.D1D3P3])
    st.wait(6)

    ############################################################################################
    hdrMsg("\n###### Step 20 - Verify ECMP after interface flap ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: Traffic is load balanced for more than 1 path from D3 and D4 after interface flap')
    else:
        st.error('FAIL: Traffic not passing through more than 1 path from D3/D4 after interface flap')
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n########## Step 21 - Change the max path for bgp to 1 ############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict['leaf1']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='1')
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict['leaf2']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='1')
    st.wait(2)
    for dut in [vars.D3,vars.D4]:
        Ip.show_ip_route(dut)
   
    if evpn_dict['cli_mode'] == "klish":
        st.wait(20,"Waiting for the klish show command to reflect correct Tx Rate for uplink ports after max-path change")

    ############################################################################################
    hdrMsg("\n###### Step 22 - Verify traffic flows through only 1 path ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list,"")
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths == 1 and num_of_paths2 == 1:
        st.log('PASS: Traffic is going through only 1 path from D3 and D4 as expected')
    else:
        st.error('FAIL: Traffic not passing through 1 path from D3/D4 after max path change to 1')
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][3])
        success = False

    ############################################################################################
    hdrMsg("\n########## Step 23 - Change the max path for bgp to 8 ############\n")
    ############################################################################################

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict['leaf1']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='8')
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict['leaf2']['local_as'],
                   config_type_list=["max_path_ebgp"], max_path_ebgp='8')
    st.wait(2)
    for dut in [vars.D3,vars.D4]:
        Ip.show_ip_route(dut)
    ############################################################################################
    hdrMsg("\n###### Step 24 - Verify ECMP ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: Traffic is load balanced for more than 1 path from D3 and D4 as expected')
    else:
        st.error('FAIL: Traffic not passing through more than 1 path from D3/D4')
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])
        success = False

    ############################################################################################
    hdrMsg("\n########## Step 25 - Clear bgp evpn neighbor ############\n")
    ############################################################################################
    Evpn.clear_bgp_evpn(vars.D3, "*")
    st.wait(5)

    ############################################################################################
    hdrMsg("\n###### Step 26 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed clear bgp evpn neighbor ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear bgp evpn neighbor")

    ############################################################################################
    hdrMsg("\n########## Step 27 - Clear bgp neighbor ############\n")
    ############################################################################################
    st.log("clear bgp neighbors")
    Bgp.clear_ip_bgp_vtysh(vars.D4)
    st.wait(5)
    ############################################################################################
    hdrMsg("\n###### Step 28 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed after clear bgp")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear bgp")

    ############################################################################################
    hdrMsg("\n###### Step 29 - Verify ECMP ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths >= 2 or num_of_paths2 >= 2:
        st.log('PASS: after clear BGP, Traffic is load balanced for more than 1 path from D3 and D4 as expected')
    else:
        st.error('FAIL: after clear BGP, Traffic not passing through more than 1 path from D3/D4')
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])
        success = False
    current_stream_dict["stream"] = stream_dict["l2_3281"] + stream_dict["ipv4_3281"] + stream_dict["ipv6_3281"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoLvtep5549Ft3281")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoLvtep5549Ft3281")


def test_FtOpSoRoLvtep5549Ft32113_3(Tgencleanup_fixture):
    success = True
    tc_list = ["test_FtOpSoRoLvtep5549Ft32113"]
    tc_list_summary = ["Verify underlay ECMP for BUM traffic and triggers"]

    make_global_vars()
    globals().update(data)
    tg = tg_dict['tg']
    intf_list = data.leaf1_po_list+[vars.D3D1P1, vars.D3D2P1]
    intf_list2 = data.leaf2_po_list+[vars.D4D1P1, vars.D4D2P1]
    st.log("Step 1: Send IPv6 L2 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32113"])

    traffic_details1 = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict['d7_tg_port1']],
            'rx_obj': [tg],
        },
        '2': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [2],
            'rx_ports': [tg_dict['d3_tg_port1']],
            'rx_obj': [tg],
        },
        '3': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [2],
            'rx_ports': [tg_dict['d4_tg_port1']],
            'rx_obj': [tg],
        },
    }

    ############################################################################################
    hdrMsg("\n####### Step 2: Verify L2 BUM traffic is not load balanced #########\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths + num_of_paths2 <= 2:
        st.log('PASS: BUM Traffic takes 1 path from D3/D4 as expected')
    else:
        st.error('test_FtOpSoRoLvtep5549Ft32113_3 FAIL: BUM Traffic takes more than 1 path from D3/D4')
        success = False

    ############################################################################################
    hdrMsg("\n###### Step 3 - Flap the link between LVTEP and Spine1 10 times ######\n")
    ############################################################################################
    if num_of_paths <= 2:
        for i in range(0,10):
            port.shutdown(evpn_dict["leaf_node_list"][0],[vars.D3D1P1])
            port.noshutdown(evpn_dict["leaf_node_list"][0],[vars.D3D1P1])

    if num_of_paths2 <= 2:
        for i in range(0,10):
            port.shutdown(evpn_dict["leaf_node_list"][1],[vars.D4D1P1])
            port.noshutdown(evpn_dict["leaf_node_list"][1],[vars.D4D1P1])
    ############################################################################################
    hdrMsg("\n###### Step 4 - Verify traffic ######\n")
    ############################################################################################
    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP BUM and LOCAL LVTEP BUM")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpn5549LvtepFt32113 FAIL: Traffic from SVTEP to BUM and LOCAL LVTEP BUM ")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Step 6 - Verify ECMP after interface flap ######\n")
    ############################################################################################
    num_of_paths = check_ecmp(intf_list)
    num_of_paths2 = check_ecmp(intf_list2, dut=vars.D4)
    st.log("total path D3:" + str(num_of_paths) + ', D4:' + str(num_of_paths2))
    if num_of_paths + num_of_paths2 <= 2:
        st.log('PASS: BUM traffic takes 1 path from D3 and D4 as expected after flap')
    else:
        st.error('test_FtOpSoRoLvtep5549Ft32113_3 FAIL: BUM traffic takes more than 1 path from D3/D4 after flap')
        success = False
    current_stream_dict["stream"] = stream_dict["l2_32113"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoLvtep5549Ft32113")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoLvtep5549Ft32113")

'''
def test_FtOpSoRoLvtep5549Ft3273(Ft3273_fixture):

    success = True
    tc_list = ["test_FtOpSoRoLvtep5549Ft3273"]
    tc_list_summary = ["Verify scale no of VRFs used for L3 VNI is 1000"]

    make_global_vars()
    globals().update(data)
    tg = tg_dict['tg']


    st.log('###### ----- Taking backup for unconfig ------######')

    Bgp.enable_docker_routing_config_mode(vars.D3)
    reboot_api.config_save(vars.D3)
    st.vtysh(vars.D3,"copy running-config startup-config")
    #st.reboot(vars.D3)

    Bgp.enable_docker_routing_config_mode(vars.D4)
    reboot_api.config_save(vars.D4)
    st.vtysh(vars.D4,"copy running-config startup-config")
    #st.reboot(vars.D4)

    Bgp.enable_docker_routing_config_mode(vars.D5)
    reboot_api.config_save(vars.D5)
    st.vtysh(vars.D5,"copy running-config startup-config")
    #st.reboot(vars.D5)

    Bgp.enable_docker_routing_config_mode(vars.D6)
    reboot_api.config_save(vars.D6)
    st.vtysh(vars.D6,"copy running-config startup-config")
    #st.reboot(vars.D6)

#    cmd = 'cp /etc/sonic/config_db.json /etc/sonic/default.json'

#    utils.exec_all(True,[[st.config,vars.D3,cmd], [st.config,vars.D4,cmd], [st.config,vars.D5,cmd], [st.config,vars.D6,cmd]])
    src_path = '/etc/sonic/config_db.json'
    dst_path = '/etc/sonic/default.json'
    utils.exec_all(True,[[basic.copy_file_to_local_path,vars.D3,src_path,dst_path], [basic.copy_file_to_local_path,vars.D4,src_path,dst_path], [basic.copy_file_to_local_path,vars.D5,src_path,dst_path], [basic.copy_file_to_local_path,vars.D6,src_path,dst_path]])

    ###############################################################################################################################



    st.log('###### ----- Loading json file with vrf and IP address config ------######')

    curr_path = os.getcwd()
    json_file_dut3 = curr_path+"/routing/lvtep/vrf_scale_dut3.json"
    st.apply_files(vars.D3, [json_file_dut3])

    json_file_dut4 = curr_path+"/routing/lvtep/vrf_scale_dut4.json"
    st.apply_files(vars.D4, [json_file_dut4])

    json_file_dut5 = curr_path+"/routing/lvtep/vrf_scale_dut5.json"

    st.apply_files(vars.D5, [json_file_dut5])

    json_file_dut6 = curr_path+"/routing/lvtep/vrf_scale_dut6.json"

    st.apply_files(vars.D6, [json_file_dut6])

    utils.exec_all(True,[[st.apply_files,vars.D3,[json_file_dut3]], [st.apply_files,vars.D4,[json_file_dut4]], [st.apply_files,vars.D5,[json_file_dut5]], [st.apply_files,vars.D6,[json_file_dut6]]])


    ############################################################################################
    hdrMsg(" \n####### Create tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0],"1 1000",'add','False'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1],"1 1000","add", "False"], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"1 1000","add", "False"], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"1 1000","add", "False"]])

    ############################################################################################
    hdrMsg(" \n####### Bind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0],"1 1000",evpn_dict["leaf1"]["intf_list_tg"][0],"add", "False"], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1],"1 1000",evpn_dict["leaf2"]["intf_list_tg"][0],"add", "False"], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"1 1000",evpn_dict["leaf3"]["intf_list_tg"][0],"add", "False"], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"1 1000",evpn_dict["leaf4"]["intf_list_tg"][0],"add", "False"]])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "1","1",'1000'], [evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "1","1",'1000'], [evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "1","1",'1000'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "1","1",'1000']]):
        st.log('Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')
    ############################################################################################
    hdrMsg(" \n####### Add Vrf to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    st.log("Add Vrf to VNI map on all leaf nodes")
    if Evpn.map_vrf_vni(evpn_dict["leaf_node_list"][0],"Vrf-"+'2', '2', vtep_name='vtep'+'2'):
        st.log('Vrf to Vni mapping is created.')
        for i in range(1,1000):
            parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.map_vrf_vni, "Vrf-"+str(i), str(i), vtep_name='vtep'+str(i))
    else:
        success=False
        st.error('FAIL: Vrf to Vni mapping failed.')

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni='999',
                                vrf='999',total_count="2"):
        hdrMsg("FAIL - Verify VRF VNI map for LVTEP node 1")
        success = False
    else:
        st.log("PASS - Verify VRF VNI map for LVTEP node 1")

@pytest.fixture(scope="function")
def Ft3273_fixture(request,evpn_underlay_hooks):

    yield

    start_traffic(action='stop')

    st.log("Reset TGEN")
    reset_tgen()

    delete_host()

    st.log('###### ----- Laoding back the config_db file ------######')
    #cmd = 'cp /etc/sonic/default.json /etc/sonic/config_db.json'
    #utils.exec_all(True,[[st.config,vars.D3,cmd], [st.config,vars.D4,cmd], [st.config,vars.D5,cmd], [st.config,vars.D6,cmd]])
    dst_path = '/etc/sonic/config_db.json'
    src_path = '/etc/sonic/default.json'
    utils.exec_all(True,[[basic.copy_file_to_local_path,vars.D3,src_path,dst_path], [basic.copy_file_to_local_path,vars.D4,src_path,dst_path], [basic.copy_file_to_local_path,vars.D5,src_path,dst_path], [basic.copy_file_to_local_path,vars.D6,src_path,dst_path]])
    utils.exec_all(True,[[st.reboot,vars.D3,'fast'], [st.reboot,vars.D4,'fast'], [st.reboot,vars.D5,'fast'], [st.reboot,vars.D6,'fast']])

    ############################################################################################
    hdrMsg(" \n####### Unmap vlan to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "1","1",'1000','no'], [evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "1","1",'1000','no'], [evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "1","1",'1000','no'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "1","1",'1000','no']]):
        st.log('Vlan to Vni mapping is deleted.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni unmapping failed')

    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0],"1 1000",evpn_dict["leaf1"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1],"1 1000",evpn_dict["leaf2"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"1 1000",evpn_dict["leaf3"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"1 1000",evpn_dict["leaf4"]["intf_list_tg"][0]],'del'])

    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0],"1 1000",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1],"1 1000",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"1 1000",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"1 1000",'del']])
'''


@pytest.fixture(scope="function")
def Ft3277_fixture(request, evpn_underlay_hooks):
    delete_host()
    reset_tgen()
    scale.ipv6_routes_per_tg = 13000
    scale.total_ipv6_routes = int(scale.ipv6_routes_per_tg) *2
    tg = tg_dict['tg']
    #port.shutdown(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_spine"])

    hdrMsg(" \n####### Configure BGP+ routers on Leaf1 Tgen Orphan port and SVTEP orphan Tgen port##############\n")
    scale.h11 = tg.tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config', ipv6_intf_addr='3001::100',
                                 vlan_id=300, vlan='1', src_mac_addr='00:00:23:23:00:01',
                                 arp_send_req='1',ipv6_prefix_length='96', ipv6_gateway='3001::1')
    scale.h22 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config', ipv6_intf_addr='6001::100',
                                 vlan_id=600, vlan='1', src_mac_addr='00:00:24:24:00:02',
                                 arp_send_req='1',ipv6_prefix_length='96', ipv6_gateway='6001::1')

    scale.bgp_rtr1 = tg.tg_emulation_bgp_config(handle=scale.h11['handle'], mode='enable', active_connect_enable='1', local_as=1300,
                                          remote_as=300, remote_ipv6_addr='3001::1',ip_version='6')

    scale.bgp_rtr2 = tg.tg_emulation_bgp_config(handle=scale.h22['handle'], mode='enable', active_connect_enable='1', local_as=1600,
                                          remote_as=600, remote_ipv6_addr='6001::1',ip_version='6')

    hdrMsg(" \n####### Configure BGP neighbors on Leaf1 and Leaf4##############\n")
    bgp_input1 = {"addr_family":'ipv6',"local_as": evpn_dict['leaf1']['local_as'],"neighbor": '3001::100',
                  "config_type_list": ["neighbor","connect","activate"],"remote_as":1300,"connect":"3",
                  'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    bgp_input2 = {"addr_family":'ipv6',"local_as": evpn_dict['leaf4']['local_as'],"neighbor": '6001::100',
                  "config_type_list": ["neighbor","connect","activate"],"remote_as":1600,"connect":"3",
                  'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3]],
                           Bgp.config_bgp,[bgp_input1, bgp_input2])
    yield

    hdrMsg("### CLEANUP for 3277 ###")
    #port.noshutdown(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_spine"])
    bgp_input1 = {"addr_family":'ipv6',"local_as": evpn_dict['leaf1']['local_as'],"neighbor": '3001::100',
                  "config_type_list": ["neighbor"],"remote_as":1300,'config':'no',
                  'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    bgp_input2 = {"addr_family":'ipv6',"local_as": evpn_dict['leaf4']['local_as'],"neighbor": '6001::100',
                  "config_type_list": ["neighbor"],"remote_as":1600,'config':'no',
                  'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3]],
                           Bgp.config_bgp,[bgp_input1, bgp_input2])

    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr1['handle'], mode='stop')
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr2['handle'], mode='stop')
    tg.tg_interface_config(handle=scale.h11['handle'], port_handle=tg_dict["d3_tg_ph1"], mode='destroy')
    tg.tg_interface_config(handle=scale.h22['handle'], port_handle=tg_dict["d6_tg_ph1"], mode='destroy')
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3, vars.D4, vars.D5, vars.D6, vars.D7]])


def test_FtOpSoRoEvpn5549LvtepFt3277(Ft3277_fixture):
    success = True
    tg = tg_dict['tg']
    ################################################################
    st.log("Step 1: Verify initial BGP route count on user-vrf on Leaf nodes")
    ################################################################
    ipv6_route_count_initial_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0],
                                                                 vrf=evpn_dict['leaf1']['vrf_name_list'][0],
                                                                 key='ebgp',version='ipv6')
    ipv6_route_count_initial_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3],
                                                                  vrf=evpn_dict['leaf1']['vrf_name_list'][0],
                                                                  key='ebgp',version='ipv6')

    ################################################################
    st.log("Step 2: Start BGP routers on TGEN and advertise max ipv4 routes {}".format(scale.total_ipv6_routes))
    ################################################################
    scale.bgp_route = tg.tg_emulation_bgp_route_config(handle=scale.bgp_rtr1['handle'], mode='add', num_routes=scale.ipv6_routes_per_tg,
                                                 prefix='1234:1:2::', as_path='as_seq:1300',ip_version='6')

    scale.route_handle = scale.bgp_route['handle']
    scale.bgp_route_2 = tg.tg_emulation_bgp_route_config(handle=scale.bgp_rtr2['handle'], mode='add', num_routes=scale.ipv6_routes_per_tg,
                                                   prefix='3122:1:2::', as_path='as_seq:1600',ip_version='6')
    scale.route_handle_2 = scale.bgp_route_2['handle']
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr1['handle'], mode='start')
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr2['handle'], mode='start')
    st.wait(3)

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    ################################################################
    st.log("Step 3: Verify BGP sessions are up on Leaf1 and Leaf-4 nodes on user-vrf")
    ################################################################
    result = retry_api(ip_bgp.verify_bgp_neighbor,evpn_dict['bgp_node_list'][2],neighborip='3001::100',vrf=evpn_dict['leaf1']['vrf_name_list'][0],state='Established')
    if result is False:
        success = False
        st.log("########## FAIL: BGP sessiond did not come up on Leaf-1 ######## ")

    result = retry_api(ip_bgp.verify_bgp_neighbor, evpn_dict['bgp_node_list'][5], neighborip='6001::100',
                       vrf=evpn_dict['leaf1']['vrf_name_list'][0],state='Established')
    if result is False:
        success = False
        st.log("########## FAIL: BGP sessiond did not come up on Leaf-4 ######## ")

    ################################################################
    st.log("Step 4: Verify {} BGP routes installed on Leaf nodes".format(scale.total_ipv6_routes))
    ################################################################
    result = False
    for i in range(3):
        ipv6_route_count_final_leaf1=ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0],vrf=evpn_dict['leaf1']['vrf_name_list'][0],key='ebgp',version='ipv6')
        max_val = scale.total_ipv6_routes + 100
        if int(ipv6_route_count_final_leaf1) >= scale.total_ipv6_routes and int(ipv6_route_count_final_leaf1) <= max_val:
            result = True
            break
        else:
            st.wait(5, "Retry BGP routes installation check..")
            continue
    if result:
        st.log("########## Max ipv6 routes installed in LVTEP N1 ##########")
    else:
        success = False
        st.log("########## FAIL: MAX routes {} not installed on Leaf1 ##########".format(scale.total_ipv6_routes))

    ipv6_route_count_final_leaf4 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',version='ipv6')
    max_val4 = scale.total_ipv6_routes + 100
    if int(ipv6_route_count_final_leaf4) >= scale.total_ipv6_routes and int(ipv6_route_count_final_leaf4) <= max_val4:
        st.log("########## Max ipv6 routes installed ##########")
    else:
        success = False
        st.log("########## FAIL: MAX routes {} not installed on Leaf4 ##########".format(scale.total_ipv6_routes))

    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    ################################################################
    st.log("Step 5: Configure bidirectional L3 traffic for all max routes installed between D3 and D6")
    ################################################################
    stream = tg.tg_traffic_config(mac_src='00:00:23:23:00:01',enable_stream_only_gen=0 ,enable_stream=0,high_speed_result_analysis=1,
                         mac_dst=mclag_active_node_rmac, vlan='enable', vlan_id='300',
                         l2_encap='ethernet_ii_vlan', rate_pps=20000, mode='create', port_handle=tg_dict['d3_tg_ph1'],
                         transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                         l3_protocol='ipv6', ipv6_src_addr='3001::100', ipv6_dst_addr='3122:1:2:0::',
                         mac_discovery_gw='3001::1', ipv6_dst_step='0:0:0:1::0',
                         ipv6_dst_mode='increment', ipv6_dst_count=scale.ipv6_routes_per_tg)
    stream100 = stream['stream_id']

    stream = tg.tg_traffic_config(mac_src='00:00:24:24:00:02',enable_stream_only_gen=0 ,enable_stream=0,high_speed_result_analysis=1,
                         mac_dst=dut6_gateway_mac, vlan='enable', vlan_id='600',
                         l2_encap='ethernet_ii_vlan', rate_pps=20000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                         transmit_mode='continuous',port_handle2=tg_dict['d3_tg_ph1'],
                         l3_protocol='ipv6', ipv6_src_addr='6001::100', ipv6_dst_addr='1234:1:2:0::', ipv6_dst_step='0:0:0:1::0',
                         ipv6_dst_mode='increment', ipv6_dst_count=scale.ipv6_routes_per_tg, mac_discovery_gw='6001::1')
    stream101 = stream['stream_id']
    stream_dict["l3_3277"] = [stream100,stream101]
    start_traffic(stream_han_list=[stream100,stream101])
    st.wait(7,"Waiting for 7 sec before collecting stream stats after start traffic")
    result = False
    for i in range(5):
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream100,dest_tg_ph=tg_dict['d6_tg_ph1'])
        if loss_prcnt > 0.6:
            hdrMsg(" \n####### retry traffic verification as loss % is {} b/w D3 towards D6\n".format(loss_prcnt))
            st.wait(1)
            continue
        else:
            result = True
            break
    if result:
        st.log("########## traffic verification passed for max ipv6 routes installed ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after max ipv6 installed on Leaf DUTs##########")
        hdrMsg(" \n####### To debug shows the traffic loss in reverse dierction b/w D6 towards D3 #######")
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream101,dest_tg_ph=tg_dict['d3_tg_ph1'])

    ################################################################
    st.log("Step 6: Withdraw routes from TGEN ")
    ################################################################
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr1['handle'], route_handle=scale.route_handle, mode='withdraw')
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr2['handle'], route_handle=scale.route_handle_2, mode='withdraw')
    st.wait(5)
    ################################################################
    st.log("Step 7: Verify Routes are withdrwn on Leaf nodes")
    ################################################################
    result = False
    for i in range(4):
        after_withdraw_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',version='ipv6')
        if int(after_withdraw_leaf1) >= 100:
            st.log("########## FAIL: Not all IPv6 Routes withdrawn on Leaf1, retrying ##########")
            st.wait(5, "Retry IPv6 BGP routes withdrawn check..")
            continue
        else:
            result = True
            break
    if result:
        st.log("########## PASS: all IPv6 Routes withdrawn on Leaf1 ##########")
    else:
        success = False
        st.log("########## FAIL: Not all IPv6 Routes withdrawn on Leaf1 , shows {} routes still ##########".format(after_withdraw_leaf1))

    result = False
    for i in range(4):
        after_withdraw_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',version='ipv6')
        if int(after_withdraw_leaf4) >= 100:
            st.log("########## FAIL: Not all IPv6 Routes withdrawn on Leaf4, retrying ##########")
            st.wait(5, "Retry BGP IPv6 routes withdrawn check..")
            continue
        else:
            result = True
            break
    if result:
        st.log("########## PASS: all IPv6 Routes withdrawn on Leaf4 ##########")
    else:
        success = False
        st.log("########## FAIL: Not all IPv6 Routes withdrawn on Leaf4 , shows {} routes still ##########".format(after_withdraw_leaf4))

    ################################################################
    st.log("Step 8: Re-advertise routes from TGEN emulated BGP routers")
    ################################################################
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr1['handle'], route_handle=scale.route_handle, mode='readvertise')
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr2['handle'], route_handle=scale.route_handle_2, mode='readvertise')
    st.wait(30)
    ################################################################
    st.log("Step 9: Verify Routes are re-learnt on leaf node")
    ################################################################
    after_readvertise_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',version='ipv6')
    after_readvertise_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',version='ipv6')
    if int(after_readvertise_leaf1) >= scale.total_ipv6_routes and int(after_readvertise_leaf1) <= max_val:
        st.log("########## Routes are learnt after Re-advertise on Leaf1 ##########")
    else:
        success = False
        st.log("########## FAIL: Routes are not learnt after Re-advertise on Leaf1 ##########")
    if int(after_readvertise_leaf4) >= scale.total_ipv6_routes and int(after_readvertise_leaf4) <= max_val4:
        st.log("########## Routes are learnt after Re-advertise on Leaf4 ##########")
    else:
        success = False
        st.log("########## FAIL: Routes are not learnt after Re-advertise on Leaf4 ##########")
    ################################################################
    st.log("Step 10: Verify Traffic after Routes withdraw and readvertise")
    ################################################################
    result = False
    for i in range(5):
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream100,dest_tg_ph=tg_dict['d6_tg_ph1'])
        if loss_prcnt > 0.6:
            hdrMsg(" \n####### retry traffic verification as loss % is {} b/w D3 towards D6\n".format(loss_prcnt))
            st.wait(1)
            continue
        else:
            result = True
            break
    if result:
        st.log("########## traffic verification passed for max ipv6 routes installed after withdraw/readvertise ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after max ipv6 installed on Leaf DUTs after withdraw/readvertise##########")
        hdrMsg(" \n####### To debug shows the traffic loss in reverse dierction b/w D6 towards D3 #######")
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream101,dest_tg_ph=tg_dict['d3_tg_ph1'])

    current_stream_dict["stream"] = stream_dict["l3_3277"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549LvtepFt3277")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549LvtepFt3277")


@pytest.fixture(scope="function")
def Ft3276_fixture(request, evpn_underlay_hooks):
    delete_host()
    reset_tgen()
    scale.ipv4_routes_per_tg = 40500
    scale.total_ipv4_routes = int(scale.ipv4_routes_per_tg) *2
    tg = tg_dict['tg']
    #port.shutdown(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_spine"])
    hdrMsg(" \n####### COnfigure BGP routers on Leaf1 Tgen Orphan port and SVTEP orphan Tgen port##############\n")
    scale.h11 = tg.tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config', intf_ip_addr='30.1.1.150',
                                 vlan_id=300, vlan='1', gateway='30.1.1.1', src_mac_addr='00:44:23:23:00:01',
                                 arp_send_req='1', netmask='255.255.255.0')
    scale.h22 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config', intf_ip_addr='60.1.1.150',
                                 vlan_id=600, vlan='1', gateway='60.1.1.1', src_mac_addr='00:44:24:24:00:02',
                                 arp_send_req='1', netmask='255.255.255.0')

    scale.bgp_rtr1 = tg.tg_emulation_bgp_config(handle=scale.h11['handle'], mode='enable', active_connect_enable='1', local_as=1300,
                                          remote_as=300, remote_ip_addr='30.1.1.1')

    scale.bgp_rtr2 = tg.tg_emulation_bgp_config(handle=scale.h22['handle'], mode='enable', active_connect_enable='1', local_as=1600,
                                          remote_as=600, remote_ip_addr='60.1.1.1')

    hdrMsg(" \n####### Configure BGP neighbors on Leaf1 and Leaf4##############\n")
    bgp_input1 = {"local_as": evpn_dict['leaf1']['local_as'],"neighbor": '30.1.1.150', "config_type_list": ["neighbor","connect"],"remote_as":1300,'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0],"connect":"3"}
    bgp_input2 = {"local_as": evpn_dict['leaf4']['local_as'],"neighbor": '60.1.1.150', "config_type_list": ["neighbor","connect"],"remote_as":1600,'vrf_name':evpn_dict['leaf1']['vrf_name_list'][0],"connect":"3"}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3]], Bgp.config_bgp,[bgp_input1, bgp_input2])

    yield

    hdrMsg("### CLEANUP for 3276 ###")
    #port.noshutdown(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_spine"])
    bgp_input1 = {"local_as": evpn_dict['leaf1']['local_as'],"neighbor": '30.1.1.150', "config_type_list": ["neighbor"],"remote_as":1300,'config':'no','vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    bgp_input2 = {"local_as": evpn_dict['leaf4']['local_as'],"neighbor": '60.1.1.150', "config_type_list": ["neighbor"],"remote_as":1600,'config':'no','vrf_name':evpn_dict['leaf1']['vrf_name_list'][0]}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3]], Bgp.config_bgp,[bgp_input1, bgp_input2])

    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr1['handle'], mode='stop')
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr2['handle'], mode='stop')
    tg.tg_interface_config(handle=scale.h11['handle'], port_handle=tg_dict["d3_tg_ph1"], mode='destroy')
    tg.tg_interface_config(handle=scale.h22['handle'], port_handle=tg_dict["d6_tg_ph1"], mode='destroy')
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3, vars.D4, vars.D5, vars.D6, vars.D7]])

def test_FtOpSoRoEvpn5549LvtepFt3276(Ft3276_fixture):
    success = True
    tg = tg_dict['tg']
    ################################################################
    st.log("Step 1: Verify initial BGP route count on user-vrf on Leaf nodes")
    ################################################################
    ipv4_route_count_initial_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    ipv4_route_count_initial_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')

    ################################################################
    st.log("Step 2: Start BGP routers on TGEN and advertise max ipv4 routes {}".format(scale.total_ipv4_routes))
    ################################################################
    scale.bgp_route = tg.tg_emulation_bgp_route_config(handle=scale.bgp_rtr1['handle'], mode='add', num_routes=scale.ipv4_routes_per_tg,
                                                 prefix='151.1.0.0', as_path='as_seq:1300')

    scale.route_handle = scale.bgp_route['handle']
    scale.bgp_route_2 = tg.tg_emulation_bgp_route_config(handle=scale.bgp_rtr2['handle'], mode='add', num_routes=scale.ipv4_routes_per_tg,
                                                   prefix='191.1.0.0', as_path='as_seq:1600')
    scale.route_handle_2 = scale.bgp_route_2['handle']
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr1['handle'], mode='start')
    tg.tg_emulation_bgp_control(handle=scale.bgp_rtr2['handle'], mode='start')
    st.wait(3)

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    ################################################################
    st.log("Step 3: Verify BGP sessions are up on Leaf1 and Leaf-4 nodes on user-vrf")
    ################################################################
    result = retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][2], nbr_list=['30.1.1.150'],
              state_list=['Established'], retry_count=5, delay=2, vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])
    if result is False:
        success = False
        st.log("########## FAIL: BGP sessiond did not come up on Leaf-1 ######## ")

    result = retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][5], nbr_list=['60.1.1.150'],
              state_list=['Established'], retry_count=5, delay=2, vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])
    if result is False:
        success = False
        st.log("########## FAIL: BGP sessiond did not come up on Leaf-4 ######## ")

    ################################################################
    st.log("Step 4: Verify {} BGP routes installed on Leaf nodes".format(scale.total_ipv4_routes))
    ################################################################
    result = False
    for i in range(3):
        ipv4_route_count_final_leaf1=ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0],vrf=evpn_dict['leaf1']['vrf_name_list'][0],key='ebgp')
        max_val = int(ipv4_route_count_final_leaf1) + 100
        if int(ipv4_route_count_final_leaf1) >= scale.total_ipv4_routes and int(ipv4_route_count_final_leaf1) <= max_val:
            result = True
            break
        else:
            st.wait(5, "Retry BGP routes installation check..")
            continue
    if result:
        st.log("##########  Max route verification passed for max ipv4 routes installed in LVTEP N1 ##########")
    else:
        success = False
        st.log("########## FAIL: MAX routes {} not installed on Leaf1 ##########".format(scale.total_ipv4_routes))

    ipv4_route_count_final_leaf4 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    max_val4 = int(ipv4_route_count_final_leaf4) + 100
    if int(ipv4_route_count_final_leaf4) >= scale.total_ipv4_routes and int(ipv4_route_count_final_leaf4) <= max_val4:
        st.log("########## Max route verification passed for max ipv4 routes installed ##########")
    else:
        success = False
        st.log("########## FAIL: MAX routes {} not installed on Leaf4 ##########".format(scale.total_ipv4_routes))

    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    ################################################################
    st.log("Step 5: Configure bidirectional L3 traffic for all max routes installed between D3 and D6")
    ################################################################
    stream = tg.tg_traffic_config(mac_src='00:44:23:23:00:01',enable_stream_only_gen=0 ,enable_stream=0,high_speed_result_analysis=1,
                         mac_dst=mclag_active_node_rmac, vlan='enable', vlan_id='300',
                         l2_encap='ethernet_ii_vlan', rate_pps=20000, mode='create', port_handle=tg_dict['d3_tg_ph1'],
                         transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                         l3_protocol='ipv4', ip_src_addr='30.1.1.150', ip_dst_addr='191.1.0.0',
                         mac_discovery_gw='30.1.1.1', ip_dst_step='0.0.1.0',
                         ip_dst_mode='increment', ip_dst_count=scale.ipv4_routes_per_tg)
    stream102 = stream['stream_id']

    stream = tg.tg_traffic_config(mac_src='00:44:24:24:00:02',enable_stream_only_gen=0 ,enable_stream=0,high_speed_result_analysis=1,
                         mac_dst=dut6_gateway_mac, vlan='enable', vlan_id='600',
                         l2_encap='ethernet_ii_vlan', rate_pps=20000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                         transmit_mode='continuous',port_handle2=tg_dict['d3_tg_ph1'],
                         l3_protocol='ipv4', ip_src_addr='60.1.1.150', ip_dst_addr='151.1.0.0', ip_dst_step='0.0.1.0',
                         ip_dst_mode='increment', ip_dst_count=scale.ipv4_routes_per_tg, mac_discovery_gw='60.1.1.1')
    stream103 = stream['stream_id']
    stream_dict["l3_3276"]=[stream102,stream103]
    start_traffic(stream_han_list=[stream102,stream103])
    st.wait(7,"Waiting for 7 sec before collecting stream stats after start traffic")

    result = False
    for i in range(5):
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream102,dest_tg_ph=tg_dict['d6_tg_ph1'])
        if loss_prcnt > 0.6:
            hdrMsg(" \n####### retry traffic verification as loss % is {} b/w D3 towards D6\n".format(loss_prcnt))
            st.wait(1)
            continue
        else:
            result = True
            break
    if result:
        st.log("########## traffic verification passed for max ipv4 routes installed ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after max ipv4 installed on Leaf DUTs##########")
        hdrMsg(" \n####### To debug shows the traffic loss in reverse dierction b/w D6 towards D3 #######")
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream103,dest_tg_ph=tg_dict['d3_tg_ph1'])

    ################################################################
    st.log("Step 6: Withdraw routes from TGEN ")
    ################################################################
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr1['handle'], route_handle=scale.route_handle, mode='withdraw')
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr2['handle'], route_handle=scale.route_handle_2, mode='withdraw')
    st.wait(20)

    ################################################################
    st.log("Step 7: Verify Routes are withdrwn on Leaf nodes")
    ################################################################
    result = False
    for i in range(4):
        after_withdraw_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
        if int(after_withdraw_leaf1) >= 100:
            st.log("########## FAIL: Not all IPv4 Routes withdrawn on Leaf1, retrying ##########")
            st.wait(5, "Retry IPv4 BGP routes withdrawn check..")
            continue
        else:
            result = True
            break
    if result:
        st.log("########## PASS: all IPv4 Routes withdrawn on Leaf1 ##########")
    else:
        success = False
        st.log("########## FAIL: Not all IPv4 Routes withdrawn on Leaf1 , shows {} routes still ##########".format(after_withdraw_leaf1))

    result = False
    for i in range(4):
        after_withdraw_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
        if int(after_withdraw_leaf4) >= 100:
            st.log("########## FAIL: Not all IPv4 Routes withdrawn on Leaf4, retrying ##########")
            st.wait(5, "Retry IPv4 BGP routes withdrawn check..")
            continue
        else:
            result = True
            break
    if result:
        st.log("########## PASS: all IPv4 Routes withdrawn on Leaf4 ##########")
    else:
        success = False
        st.log("########## FAIL: Not all IPv4 Routes withdrawn on Leaf4 , shows {} routes still ##########".format(after_withdraw_leaf4))

    ################################################################
    st.log("Step 8: Re-advertise routes from TGEN emulated BGP routers")
    ################################################################
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr1['handle'], route_handle=scale.route_handle, mode='readvertise')
    tg.tg_bgp_routes_control(handle=scale.bgp_rtr2['handle'], route_handle=scale.route_handle_2, mode='readvertise')
    st.wait(25)
    ################################################################
    st.log("Step 9: Verify Routes are re-learnt on leaf node")
    ################################################################
    after_readvertise_leaf1 = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    after_readvertise_leaf4  = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][3], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    if int(after_readvertise_leaf1) >= scale.total_ipv4_routes and int(after_readvertise_leaf1) <= max_val:
        st.log("########## Routes are learnt after Re-advertise on Leaf1 ##########")
    else:
        success = False
        st.log("########## FAIL: Routes are not learnt after Re-advertise on Leaf1 ##########")
    if int(after_readvertise_leaf4) >= scale.total_ipv4_routes and int(after_readvertise_leaf4) <= max_val4:
        st.log("########## Routes are learnt after Re-advertise on Leaf4 ##########")
    else:
        success = False
        st.log("########## FAIL: Routes are not learnt after Re-advertise on Leaf4 ##########")
    ################################################################
    st.log("Step 10: Verify Traffic after Routes withdraw and readvertise")
    ################################################################
    result = False
    for i in range(5):
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream102,dest_tg_ph=tg_dict['d6_tg_ph1'])
        if loss_prcnt > 0.6:
            hdrMsg(" \n####### retry traffic verification as loss % is {} b/w D3 towards D6\n".format(loss_prcnt))
            st.wait(10,"wait before retrying traffic statistics verification")
            continue
        else:
            result = True
            break
    if result:
        st.log("########## traffic verification passed for max ipv4 routes installed after withdraw/readvertise ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after max ipv4 installed on Leaf DUTs after withdraw/readvertise##########")
        hdrMsg(" \n####### To debug shows the traffic loss in reverse dierction b/w D6 towards D3 #######")
        loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream103,dest_tg_ph=tg_dict['d3_tg_ph1'])

    current_stream_dict["stream"] = stream_dict["l3_3276"]

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549LvtepFt3276")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549LvtepFt3276")


@pytest.fixture(scope="function")
def Ft3271_2_fixture(request, evpn_underlay_hooks):
    delete_host()
    reset_tgen()
    hdrMsg(" \n####### Create 4K vlans in D3,D4,D6 and D7 ##############\n")
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "2 4020", "add", "False"],
                          [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "2 4020", "add", "False"],
                          [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "2 4020", "add", "False"],
                          [Vlan.config_vlan_range, evpn_dict["mlag_client"][0], "2 4020", "add", "False"]])

    hdrMsg(" \n####### Bind tenant L2 VLANs to port in D3,D4,D6 and D7 ##############\n")
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "2 4020",
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "2 4020",
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "2 4020",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "2 4020",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'add', 'False']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "2 4020",
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "2 4020",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'add', 'False'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "2 4020",
                           evpn_dict["mlag_tg_list"][0], 'add', 'False']])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni in D3,D4 and D6 #######/n")
    ############################################################################################
    if evpn_dict['cli_mode'] != "klish":
        if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
                              evpn_dict["leaf1"]["vtepName"], "2", "2", '4019'],
                            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1],
                             evpn_dict["leaf2"]["vtepName"], "2", "2", '4019'],
                            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],
                             evpn_dict["leaf4"]["vtepName"], "2", "2", '4019']]):
            st.log('Vlan to Vni mapping is created in D3,D4 and D6')
        else:
            success = False
            st.error('FAIL: Vlan to Vni mapping failed in D3/D4/D6')
    elif evpn_dict['cli_mode'] == "klish":
        utils.exec_all(True, [
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "2", "2", '98'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "2", "2", '98'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "2", "2", '98']])
        utils.exec_all(True, [
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "101", "101", '349'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "101", "101", '349'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "101", "101", '349']])
        utils.exec_all(True, [
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "451", "451", '49'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "451", "451", '49'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "451", "451", '49']])
        utils.exec_all(True, [
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "501", "501", '3520'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "501", "501", '3520'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "501", "501", '3520']])

    yield

    hdrMsg("### CLEANUP for 3271_2 ###")
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni in D3,D4 and D6 #######/n")
    ############################################################################################
    utils.exec_all(True, [
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "2", "2", '98', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "2", "2", '98', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "2", "2", '98', 'no']])
    utils.exec_all(True, [
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "101", "101", '349', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "101", "101", '349', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "101", "101", '349', 'no']])
    utils.exec_all(True, [
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "451", "451", '49', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "451", "451", '49', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "451", "451", '49', 'no']])
    utils.exec_all(True, [
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "501", "501", '3520', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "501", "501", '3520', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "501", "501", '3520', 'no']])
    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port in D3,D4 and D6 ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "2 99",
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "2 99",
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "2 99",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "2 99",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "101 449",
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "101 449",
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "101 449",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "101 449",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "451 4020",
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "451 4020",
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "451 499",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "451 4020",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "501 599",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3], "601 4020",
                           evpn_dict["leaf4"]["intf_list_tg"][0], 'del']])

    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "2 99",
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "2 99",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "2 99",
                           evpn_dict["mlag_tg_list"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "101 449",
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "101 449",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "101 449",
                           evpn_dict["mlag_tg_list"][0], 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][0], "451 4020",
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][1], "451 4020",
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], 'del'],
                          [Vlan.config_vlan_range_members, evpn_dict["mlag_client"][0], "451 4020",
                           evpn_dict["mlag_tg_list"][0], 'del']])

    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs in D3,D4 and D6 ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "2 99", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "2 99", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "2 99", 'del'],
        [Vlan.config_vlan_range, evpn_dict["mlag_client"][0], "2 99", 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "103 299", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "103 399", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "103 449", 'del'],
        [Vlan.config_vlan_range, evpn_dict["mlag_client"][0], "101 449", 'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "303 449", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "403 449", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "451 499", 'del'],
        [Vlan.config_vlan_range, evpn_dict["mlag_client"][0], "451 4020", 'del']])

    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "451 499", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "451 499", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "501 599", 'del']])

    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][0], "501 4020", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][1], "501 4020", 'del'],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3], "603 4020", 'del']])

def test_FtOpSoRoEvpn5549LvtepFt3271_2(Ft3271_2_fixture):
    success = True
    tg = tg_dict['tg']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    stream = tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"], mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],
                         rate_pps=1000, mode='create', port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='4010', transmit_mode='continuous', mac_src_count="17000",
                         mac_dst_count="17000", high_speed_result_analysis=1,mac_src_mode="increment",
                         mac_dst_mode="increment", enable_stream_only_gen=0,enable_stream=0,
                         mac_src_step="00.00.00.00.00.01",mac_dst_step="00.00.00.00.00.01",
                                  port_handle2=tg_dict["d6_tg_ph1"])
    stream105 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream105, vars.T1D7P1))
    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"],
                         rate_pps=1000, mode='create', port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='4010', transmit_mode='continuous', mac_src_count="17000",
                         mac_dst_count="17000",high_speed_result_analysis=1,mac_src_mode="increment",
                         mac_dst_mode="increment", enable_stream_only_gen=0, enable_stream=0,
                         mac_src_step="00.00.00.00.00.01",mac_dst_step="00.00.00.00.00.01",
                                  port_handle2=tg_dict["d7_tg_ph1"])
    stream106 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream106, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src="00:77:77:00:00:01", mac_dst="00:88:88:00:00:01",
                         rate_pps=1000, mode='create', port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='620', vlan_id_count='3380', vlan_id_mode="increment", vlan_id_step='1',
                         transmit_mode='continuous', mac_src_count="1", mac_dst_count="1",
                         high_speed_result_analysis=1, mac_src_mode="increment", mac_dst_mode="increment",
                         enable_stream_only_gen=0, enable_stream=0, mac_src_step="00.00.00.00.00.01",
                         mac_dst_step="00.00.00.00.00.01",port_handle2=tg_dict["d6_tg_ph1"])
    stream107 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream107, vars.T1D7P1))
    stream = tg.tg_traffic_config(mac_src="00:88:88:00:00:01", mac_dst="00:77:77:00:00:01",
                         rate_pps=1000, mode='create', port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='620', vlan_id_count='3380', vlan_id_mode="increment", vlan_id_step='1',
                         transmit_mode='continuous', mac_src_count="1", mac_dst_count="1",
                         high_speed_result_analysis=1, mac_src_mode="increment", mac_dst_mode="increment",
                         enable_stream_only_gen=0, enable_stream=0, mac_src_step="00.00.00.00.00.01",
                         mac_dst_step="00.00.00.00.00.01",port_handle2=tg_dict["d7_tg_ph1"])
    stream108 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream108, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_v4"],
                                  mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  transmit_mode='continuous', ip_src_addr="120.1.1.150",
                                    ip_src_count = 10, ip_src_step = "0.0.0.1", ip_dst_addr = "60.1.1.150",
                                    ip_dst_count = 10, ip_dst_step = "0.0.0.1", l3_protocol = 'ipv4',
                                  l3_length = '512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan = "enable",ip_src_mode = "increment", ip_dst_mode = "increment",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                                  port_handle2=tg_dict["d6_tg_ph1"])
    stream109 = stream["stream_id"]
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream109, vars.T1D7P1))
    han = tg.tg_interface_config(port_handle=tg_dict["d7_tg_ph1"], mode='config',
                                 intf_ip_addr="120.1.1.150",gateway = evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                                 vlan = '1',vlan_id =evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step = '0', arp_send_req = '1', gateway_step = '0.0.0.0',
                                 intf_ip_addr_step = '0.0.0.1', count = 10,
                                 src_mac_addr =evpn_dict["mlag_node"]["tenant_mac_v4"])
    stream_dict["v4host_3271_1"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(stream_dict["v4host_3271_1"], vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v4"],
                                  mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  transmit_mode='continuous', ip_src_addr="60.1.1.150",ip_src_count = 10,
                                  ip_src_step = "0.0.0.1", ip_dst_addr = "120.1.1.150",
                                  ip_dst_count = 10, ip_dst_step = "0.0.0.1", l3_protocol = 'ipv4',
                                  l3_length = '512',vlan_id = evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan = "enable",mac_discovery_gw = evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                                  ip_src_mode = "increment", ip_dst_mode = "increment",
                                  port_handle2=tg_dict["d7_tg_ph1"])
    stream110 = stream["stream_id"]
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream110, vars.T1D6P1))
    han = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                 intf_ip_addr="60.1.1.150",gateway = evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                                 vlan = '1',vlan_id = evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step = '0',arp_send_req = '1', gateway_step = '0.0.0.0',
                                 intf_ip_addr_step='0.0.0.1', count=10,
                                 src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v4"])
    stream_dict["v4host_3271_2"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(stream_dict["v4host_3271_2"], vars.T1D6P1))

    hdrMsg(" \n####### starting traffic from vlan 4010 ##############\n")
    st.wait(300, "need to wait for some time for all 4K Vxlan net devices to be online")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3271_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3271_2"], arp_target='all')
    stream_dict["stream_3271_2"] = [stream105,stream106,stream107,stream108,stream109,stream110]
    start_traffic(stream_han_list=[stream105,stream106,stream107,stream108,stream109,stream110])
    st.wait(60, "need to wait for some time for traffic to flow for all vlans")
    techsupport_not_gen = True
    if retry_api(verify_mac_count, vars.D6, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D6 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D6 ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D3 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D3 ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D4 ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')
    if verify_traffic():
        st.log("########## traffic verification passed before doing triggers ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed before doing triggers ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg(" \n####### verify traffic after clearing EVPN neighbor ##############\n")
    Evpn.clear_bgp_evpn(vars.D6, "*")
    Evpn.clear_bgp_evpn(vars.D3, "*")
    if retry_api(verify_mac_count, vars.D6, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D6 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D6 after clearing EVPN ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D3 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D3 after clearing EVPN ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D4 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D4 after clearing EVPN ##########")
    if verify_traffic():
        st.log("########## traffic verification passed after clearing EVPN neighbor ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing EVPN neighbor ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')
    hdrMsg(" \n####### verify traffic after clearing BGP neighbor ##############\n")
    bgp_obj.clear_ip_bgp_vtysh(vars.D6)
    bgp_obj.clear_ip_bgp_vtysh(vars.D4)
    if retry_api(verify_mac_count, vars.D6, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D6 after clearing BGP ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D6 after clearing BGP ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D3 after clearing BGP ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D3 after clearing BGP ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D4 ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP neighbor ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing BGP neighbor ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg(" \n####### verify traffic after clearing BGP EVPN table ##############\n")
    Evpn.clear_bgp_evpn(vars.D6, "*", soft_dir="in")
    Evpn.clear_bgp_evpn(vars.D4, "*", soft_dir="in")
    st.wait(10)

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP table ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing BGP table ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg(" \n####### shutting down links between leaf1 and spine ##############\n")
    port.shutdown(vars.D6, evpn_dict["leaf4"]["intf_list_spine"][0:4])
    port.shutdown(vars.D3, evpn_dict["leaf1"]["intf_list_spine"][0:4])
    st.wait(5)
    if verify_traffic():
        st.log("########## traffic verification passed after shutting down links b/w leaf1 and spine ##########")
    else:
        success = False
        st.error("########## FAIL:traffic verification failed after shutting down links b/w leaf1 and spine ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg(" \n####### Enable back links between leaf1 and spine ##############\n")
    port.noshutdown(vars.D6, evpn_dict["leaf4"]["intf_list_spine"][0:4])
    port.noshutdown(vars.D3, evpn_dict["leaf1"]["intf_list_spine"][0:4])
    st.wait(5)
    if verify_traffic():
        st.log("########## traffic verification passed after enabling back links b/w leaf1 and spine ##########")
    else:
        success = False
        st.error("########## FAIL:traffic verification failed after enabling back links b/w leaf1 and spine ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg(" \n####### clear mac in D4 and D6 ##############\n")
    Mac.clear_mac(vars.D6)
    Mac.clear_mac(vars.D4)
    st.wait(300,"waiting for ARP refresh timer to hit")

    if retry_api(verify_mac_count, vars.D6, mac_count=40700,retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found after clearing MAC in D6 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found after clearing MAC in D6 ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=40700,retry_count=4, delay=40):
        st.error("########## PASS: expected 40700 MACs found after clearing MAC in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found after clearing MAC in D4 ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    for i in range(4):
        result = verify_traffic()
        if result is False:
            hdrMsg(" \n####### retry traffic verification ##############\n")
            continue
        else:
            break
    if result:
        st.log("########## traffic verification passed after clearing MAC table ##########")
    else:
        success = False
        st.error("########## FAIL:traffic verification failed after clearing MAC table ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')
    ###########################################################
    hdrMsg("Config save")
    ###########################################################
    bgp_obj.enable_docker_routing_config_mode(vars.D3)
    mclag.config_domain(evpn_dict["leaf_node_list"][0],"2",delay_restore_timer="150",cli_type="klish")
    mclag.config_domain(evpn_dict["leaf_node_list"][1],"2",delay_restore_timer="150",cli_type="klish")
    reboot_api.config_save(vars.D3)
    reboot_api.config_save(vars.D3,shell='vtysh')
    if evpn_dict['cli_mode'] == "click":
        reboot_api.config_save(vars.D3,cli_type="klish")

    ##########################################
    hdrMsg("Perform config reload in dut3")
    ##########################################
    reboot_api.config_reload(vars.D3)
    st.wait(100)
    if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
        success=False
    if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
        success=False

    hdrMsg("Verify the tunnel is Up after the trigger")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                         src_vtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                         rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                         exp_status_list=['oper_up'], retry_count=3, delay=40):
        st.error("################## FAIL: VXLAN tunnel is NOT UP in D3/Leaf1 after config reload ##################")
        success = False
    else:
        st.log("########## VXLAN tunnel is UP as expected in D3/Leaf1 after config reload ##########")

    hdrMsg("Verify the tunnel to Leaf1 is Up on remote leaf after config reload")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][2]],
                     exp_status_list=['oper_up'], retry_count=3, delay=40):
        st.error("################## FAIL: VXLAN tunnel is NOT UP in D6/leaf4 towards D3 ##################")
        success = False
    else:
        st.log("########## VXLAN tunnel is UP as expected in D6/Leaf4 towards D3 ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg("Verify MAC table after config reload")
    if retry_api(verify_mac_count, vars.D6, mac_count=40700, retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D6 after config reload #######")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D6 after config reload #######")

    if retry_api(verify_mac_count, vars.D3, mac_count=40700, retry_count=4, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D3 after config reload #######")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D3 after config reload #######")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg("Verify traffic after config reload")
    for i in range(4):
        result = verify_traffic()
        if result is False:
            hdrMsg(" \n####### retry traffic verification ##############\n")
            continue
        else:
            break

    if result:
        st.log("########## Traffic verification passed after config reload ##########")
    else:
        success = False
        st.error("################ FAIL: Traffic verification failed after config reload #############")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    start_traffic(action="stop",stream_han_list=stream_dict["stream_3271_2"])
    tg_dict["tg"].tg_traffic_control(action='clear_stats', port_handle=[tg_dict["d6_tg_ph1"], tg_dict["d7_tg_ph1"]])
    start_traffic(stream_han_list=[stream105, stream106, stream107, stream108, stream109, stream110])
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp_graceful_restart,
                           [{"local_asn": evpn_dict["spine1"]["local_as"], "config": 'add', "preserve_state": "yes"},
                            {"local_asn": evpn_dict["spine2"]["local_as"], "config": 'add', "preserve_state": "yes"},
                            {"local_asn": evpn_dict["leaf1"]["local_as"], "config": 'add', "preserve_state": "yes"},
                            {"local_asn": evpn_dict["leaf2"]["local_as"], "config": 'add', "preserve_state": "yes"},
                            {"local_asn": evpn_dict["leaf3"]["local_as"], "config": 'add', "preserve_state": "yes"},
                            {"local_asn": evpn_dict["leaf4"]["local_as"], "config": 'add', "preserve_state": "yes"}])

    hdrMsg("######## clearing BGP neighbors after configuring graceful restart ###########")
    utils.exec_all(True,[[Bgp.clear_ip_bgp_vtysh,vars.D1],[Bgp.clear_ip_bgp_vtysh,vars.D2],
                         [Bgp.clear_ip_bgp_vtysh, vars.D3], [Bgp.clear_ip_bgp_vtysh, vars.D4],
                         [Bgp.clear_ip_bgp_vtysh, vars.D5],[Bgp.clear_ip_bgp_vtysh,vars.D6]])

    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                     src_vtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                     rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                     retry_count=6, delay=5):
        st.log("##### VXLAN tunnel towards D6 is UP in D3 as expected after clearing BGP#####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D6 is DOWN in D3 after clearing BGP ##########")
    hdrMsg(" \n####### execute BGP docker restart in D3 ##############\n")
    reboot_api.config_save(vars.D3)
    reboot.config_save(vars.D3,shell="vtysh")
    if evpn_dict['cli_mode'] == "click":
        reboot_api.config_save(vars.D3,cli_type="klish")
    basic.service_operations_by_systemctl(vars.D3, 'bgp', 'restart')
    st.wait(30)
    if not session_status_check(evpn_dict["leaf_node_list"][0],domain="2"):
        success=False
    if not delay_restore_check(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0],domain="2"):
        success=False

    hdrMsg("STEP : Check the system status")
    if not basic.poll_for_system_status(vars.D3):
        st.error("System is not in ready state")

    try:
        if not retry_api(ip_bgp.check_bgp_session,vars.D3,nbr_list=[data.leafs_spine1_port_lst1[0]],
                         state_list=['Established'],retry_count=3,delay=30):
            success = False
            basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')
            st.error("########## FAIL: BGP neighborship is not established after BGP docker restart ##########")
    except Exception as e:
        success = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')
        st.error("########## FAIL: BGP neighborship is not established after BGP docker restart ##########")

    hdrMsg("Verify the tunnel is Up in D3 after BGP docker restart")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
                     src_vtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                     rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                     exp_status_list=['oper_up'], retry_count=3, delay=10):
        st.error("################## FAIL: VXLAN tunnel is NOT UP in D3 after BGP docker restart ##################")
        success = False
    else:
        st.log("########## VXLAN tunnel is UP as expected in D3 after BGP docker restart ##########")

    hdrMsg("Verify the tunnel to D3 is Up on in D6 after BGP docker restart")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][2]],
                     exp_status_list=['oper_up'], retry_count=3, delay=10):
        st.error("################## FAIL: VXLAN tunnel is NOT UP in D6 towards D3 ##################")
        success = False
    else:
        st.log("########## VXLAN tunnel is UP as expected in D6 towards D3 ##########")
    if (not success) and techsupport_not_gen:
        techsupport_not_gen = False
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549LvtepFt3272')

    hdrMsg("Verify MAC table after BGP docker restart")
    if retry_api(verify_mac_count, vars.D6, mac_count=40700, retry_count=2, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D6 after BGP docker restart #######")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D6 after BGP docker restart #######")

    if retry_api(verify_mac_count, vars.D3, mac_count=40700, retry_count=2, delay=40):
        st.log("########## PASS: expected 40700 MACs found in D3 after BGP docker restart #######")
    else:
        success = False
        st.error("########## FAIL: expected 40700 MACs not found in D3 after BGP docker restart #######")


    traffic_details = {
        '1': {
            'tx_ports': [tg_dict["d7_tg_port1"]],
            'tx_obj': [tg_dict["tg"]],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d6_tg_port1"]],
            'rx_obj': [tg_dict["tg"]],
            'stream_list': [(stream105,stream107,stream109)]
        },
        '2': {
            'tx_ports': [tg_dict["d6_tg_port1"]],
            'tx_obj': [tg_dict["tg"]],
            'exp_ratio': [1],
            'rx_ports': [tg_dict["d7_tg_port1"]],
            'rx_obj': [tg_dict["tg"]],
            'stream_list': [(stream106,stream108,stream110)]
        },
    }
    start_traffic(action="stop",stream_han_list=stream_dict["stream_3271_2"])
    hdrMsg("Verify traffic after BGP docker restart")
    if validate_tgen_traffic(traffic_details=traffic_details, mode="streamblock",
                                       comp_type="packet_count",tolerance_factor=9):
        st.log("########## Traffic verification passed after BGP docker restart ##########")
    else:
        success = False
        st.error("################ FAIL: Traffic verification failed after BGP docker restart #############")
        #debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][3])

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549LvtepFt3271_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549LvtepFt3271_2")

@pytest.fixture(scope="function")
def Linktrack_fixture(request,evpn_underlay_hooks):
    yield
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")

    ############################################################################################
    hdrMsg("\n####### Clear mac in LVTEP and SVTEP ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Intf.clear_interface_counters,dut] for dut in [vars.D3,vars.D4,vars.D6,vars.D7]])
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])

    if evpn_dict['cli_mode'] != "klish":
        hdrMsg("\n####### Disable uplink tracking ##############\n")
        Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='no')
        Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='no')

@pytest.fixture(scope="function")
def Lvtep_5549_32314_fixture(request,evpn_underlay_hooks):
    remove_sameip_add_uniqueip()
    yield
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    remove_uniqueip_add_sameip()
    ############################################################################################
    hdrMsg("\n####### Clear mac in LVTEP and SVTEP ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])

def session_tunnel_status_check(dut,domain="2"):
    result = False
    max_range = 5
    for i in range(1,max_range+1):
        status=[]
        status = mclag.verify_domain(dut=dut,domain_id=domain,cli_type="klish",return_output="yes")
        vtep_list = Evpn.get_tunnel_list(dut,cli_type="klish")
        if isinstance(status,list) and isinstance(vtep_list,list):
            if status == [] or vtep_list == []:
                st.log("\n \n ######### Session does not exist or no tunnel exist; retry : {} ########".format(i))
                Ip.get_interface_ip_address(dut, interface_name=None, family="ipv4")
                Ip.get_interface_ip_address(dut, interface_name=None, family="ipv6")
                Vlan.show_vlan_brief(dut)
                st.wait(1)
            elif status[0]['session_status'] != "up" or evpn_dict["leaf4"]["loop_ip_list"][1] not in vtep_list:
                st.log("\n \n ######### Session status : {} ; retry : {} ########".format(status[0]['session_status'],i))
                Ip.get_interface_ip_address(dut, interface_name=None, family="ipv4")
                Ip.get_interface_ip_address(dut, interface_name=None, family="ipv6")
                Vlan.show_vlan_brief(dut)
                st.wait(1)
            elif status[0]['session_status'] == "up" and evpn_dict["leaf4"]["loop_ip_list"][1] in vtep_list:
                result = True
                Vlan.show_vlan_brief(dut)
                hdrMsg("PASS: MCLAG Session status come up and show vxlan tunnel to {} came up fine after {} secs ".format(evpn_dict["leaf4"]["loop_ip_list"][1],i*3))
                break
        elif isinstance(status,bool) or isinstance(vtep_list,list):
            st.log("#### FAIL: show vxlan tunnel is blank or session status is : {} ####".format(status))
            return result
    if not result:
        hdrMsg("FAIL: Session status or vxlan tunnel did not come up even after waiting for {} sec".format(max_range*3))
    return result


def test_FtOpSoRoEvpnLvtepFtCeta32875(request):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnLvtepFtCeta32875; TC SUMMARY: Verify the fix for the CETA defect 32875")
    hdrMsg("Step 1 Verify vxlan tunnel status before starting the test case")
    result = utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    if result[0].count(False) > 0:
        hdrMsg("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort tc test_FtOpSoRoEvpnLvtepFtCeta32875 ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFtCeta32875")

    hdrMsg("Step 2 Verify ip static anycast gateway status before starting the test case")
    if not sag.verify_sag(evpn_dict["leaf_node_list"][2], total=1, status='enable',ip_type='ipv6',
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],admin="up",oper="up",
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]):
        hdrMsg("########## SAG is not Up; Abort tc test_FtOpSoRoEvpnLvtepFtCeta32875 ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFtCeta32875")
    elif not sag.verify_sag(evpn_dict["leaf_node_list"][3], total=1, status='enable',ip_type='ipv6',
                            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],admin="up",oper="up",
                            interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]):
        hdrMsg("########## SAG is not Up; Abort tc test_FtOpSoRoEvpnLvtepFtCeta32875 ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFtCeta32875")

    hdrMsg("Step 3: Remove L3VNI addresses from SVTEP nodes so that this address is not used as ipv6 src for pings request packets")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    hdrMsg("\n####### Step 4 Create Host 1 and Host 2 connected to the nodes SVTEP 1 and SVTEP 2 respectively #####\n")
    tg = tg_dict['tg']
    host1_ip = "1201::5"
    han = tg.tg_interface_config(port_handle=tg_dict['d5_tg_ph1'], mode='config',ipv6_intf_addr=host1_ip,
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                 src_mac_addr='00:06:55:00:05:05',arp_req_retries='1',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host1 = han["handle"]
    st.log("IPv6 Host 1 {} is created for Tgen port {} connected to SVTEP 1".format(host1, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='1201::6',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                 src_mac_addr='00:06:66:00:06:06',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host2 = han["handle"]
    st.log("Ipv6 Host 2 {} is created for Tgen port {} connected to SVTEP 2".format(host2, vars.T1D6P1))

    hdrMsg("Step 5 Verify the local ND entry in SVTEP N1 & remote entry in SVTEP N2 after Host 1 sends UNSOLICITED NA")
    arp.show_ndp(evpn_dict["leaf_node_list"][2],inet6_address=host1_ip,vrf=evpn_dict["leaf1"]["vrf_name_list"][0])
    arp.show_ndp(evpn_dict["leaf_node_list"][3],inet6_address='1201::6',vrf=evpn_dict["leaf1"]["vrf_name_list"][0])
    ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],shell="",family="ipv6",distance="20",cost="0",selected=">",
            fib="*",ip_address=host1_ip+"/128",vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])

    hdrMsg("Step 6 Clear the ND entries in SVTEP N1 and SVTEP N2")
    # Here clear command is forced to click as klish command is not clearing the entry with no-refresh
    arp.clear_ndp_table(evpn_dict["leaf_node_list"][2],cli_type="click")
    arp.clear_ndp_table(evpn_dict["leaf_node_list"][3],cli_type="click")

    hdrMsg("Step 7 Verify the local ND entry cleared in SVTEP node 1 to make Host 1 as becomes silent host")
    result3 = arp.show_ndp(evpn_dict["leaf_node_list"][2],inet6_address=host1_ip,vrf=evpn_dict["leaf1"]["vrf_name_list"][0])
    if verify_empty_arp_nd_table(result3):
        st.log("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL Step 7 local ND {} found in SVTEP N1 which is not expected".format(host1_ip))
        success = False
    else:
        st.log("PASS Step 7 Verify local ND 1201::60 is cleared in SVTEP N1")

    hdrMsg("Step 8 Verify the remote ND entry withdrawn in SVTEP N2 after SVTEP N1 clears it")
    if ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],shell="",family="ipv6",distance="20",
                   cost="0",selected=">",fib="*",ip_address=host1_ip+"/128",
                   vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL Step 8 Verify Host 1 Remote ND route found in SVTEP N2")
        success = False
    else:
        st.log("Step 8 PASSED - Verify Host 1 Remote ND route is cleared in SVTEP N2")

    hdrMsg("Step 9 Ping from SVTEP 2 to Host 1 IPv6 address to trigger Neighbor Solicit packet")
    if ip.ping(vars.D6, host1_ip, family='ipv6', count=3, interface=evpn_dict["leaf4"]["vrf_name_list"][0]):
        st.log("test_FtOpSoRoEvpnLvtepFtCeta32875 Ping passed from SVTEP-2 to Host 1 ip {} which is not expected".format(host1_ip))
        success = False
    else:
        st.log("Ping failed from SVTEP-2 to Host 1 ip {} as expected".format(host1_ip))

    hdrMsg("Step 10 Verify the local ND entry learning in SVTEP node 1")
    result3 = arp.show_ndp(evpn_dict["leaf_node_list"][2],inet6_address=host1_ip,vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    if not verify_empty_arp_nd_table(result3):
        st.log("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL Step 10 Verify local ND {} not found in SVTEP N1".format(host1_ip))
        success = False
    else:
        mac3 = result3[0]['macaddress'];mac3 = mac3.replace(":",".")

        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf3"]["intf_list_tg"][0]

        if mac3 == '00.06.55.00.05.05' and result3[0]['interface'] == port1:
            st.log("PASS at Step 10 Verify local ND 1201::60 lerant in SVTEP N1")
        else:
            st.log("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL at Step 10 Verify local ND 1201::60 in SVTEP N1")
            success = False

    hdrMsg("Step 11 Verify the remote ND entry learning in SVTEP node 2")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],shell="",family="ipv6",distance="20",
                   cost="0",selected=">",fib="*",ip_address=host1_ip+"/128",
                   vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL Step 11 - Verify Host 1 Remote ND route in SVTEP N2")
        success = False
    else:
        st.log("Step 11 PASSED - Verify Host 1 Remote ND route in SVTEP N2")

    tg.tg_arp_control(handle=host2, arp_target='all')
    arp.show_ndp(evpn_dict["leaf_node_list"][3],inet6_address='1201::6',vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    stream = tg.tg_traffic_config(mac_src='00:06:55:00:05:05', mac_dst="00:06:66:00:06:06",
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d5_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr=host1_ip,ipv6_dst_addr='1201::6',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                  port_handle2=tg_dict['d6_tg_ph1'],
                                  mac_src_count=1,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=1, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=1,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream1 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:06:66:00:06:06', mac_dst="00:06:55:00:05:05",
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::6',ipv6_dst_addr=host1_ip,l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                  port_handle2=tg_dict['d5_tg_ph1'],
                                  mac_src_count=1,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=1, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=1,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream2 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))
    stream_dict["ipv6_traffic"] = [stream1,stream2]

    hdrMsg(" \n####### Step 18 Start bidirectional IPv6 SAG traffic ##############\n")
    start_traffic(stream_han_list=stream_dict["ipv6_traffic"])
    st.wait(5,"Waiting for 5 sec before verifying traffic")

    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d5_tg_ph1'],stream_dict["ipv6_traffic"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv6_traffic"][1],dest_tg_ph=tg_dict['d5_tg_ph1'])
    if loss_prcnt1 < 0.11 and loss_prcnt2 < 0.11:
        st.log("PASS: Traffic verification passed b/w Host 1 and Host 2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnLvtepFtCeta32875 FAIL: Traffic verification failed b/w Host 1 and Host 2")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    hdrMsg("Step 12: Assign IPv6 address to L3VNI interface on SVTEP nodes at the end of TC")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_name_list"][0],
            evpn_dict["leaf3"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_name_list"][0],
            evpn_dict["leaf4"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnLvtepFtCeta32875")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFtCeta32875")

