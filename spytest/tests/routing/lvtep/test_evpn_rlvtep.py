import pytest

from spytest import st, utils
import apis.system.interface as Intf
import apis.routing.evpn as Evpn
import apis.routing.ip_bgp as ip_bgp
from apis.system import basic
from apis.system import port
import apis.system.reboot as reboot
import apis.switching.mac as Mac
from apis.routing import arp
from utilities import parallel
from evpn_rlvtep import *

@pytest.fixture(scope="module", autouse=True)
def evpn_underlay_hooks(request):
    global vars
    create_glob_vars()
    vars = st.get_testbed_vars()

    api_list = [[create_stream_lvtep],[config_evpn_lvtep]]
    parallel.exec_all(True, api_list, True)
    create_stream_mclag()
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
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up",
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

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

    retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][2], nbr_list=[evpn_dict["spine1"]["loop_ip_list"][0],
                    evpn_dict["spine2"]["loop_ip_list"][0]], state_list=['Established'] * 2,retry_count=25, delay=2)

    retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][3], nbr_list=[evpn_dict["spine1"]["loop_ip_list"][0],
                    evpn_dict["spine2"]["loop_ip_list"][0]], state_list=['Established'] * 2,retry_count=25, delay=2)

    retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][4], nbr_list=[evpn_dict["spine1"]["loop_ip_list"][0],
                    evpn_dict["spine2"]["loop_ip_list"][0]], state_list=['Established'] * 2,retry_count=25, delay=2)

    retry_api(ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][5], nbr_list=[evpn_dict["spine1"]["loop_ip_list"][0],
                    evpn_dict["spine2"]["loop_ip_list"][0]], state_list=['Established'] * 2,retry_count=25, delay=2)

    st.log("verify BGP neighborship")
    utils.exec_all(True, [[ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][0],
                    [evpn_dict["leaf1"]["loop_ip_list"][0], evpn_dict["leaf2"]["loop_ip_list"][0],
                     evpn_dict["leaf3"]["loop_ip_list"][0], evpn_dict["leaf3"]["loop_ip_list"][0]],
                    ['Established']*4],
                    [ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][1],
                    [evpn_dict["leaf1"]["loop_ip_list"][0], evpn_dict["leaf2"]["loop_ip_list"][0],
                    evpn_dict["leaf3"]["loop_ip_list"][0], evpn_dict["leaf3"]["loop_ip_list"][0]],
                    ['Established'] * 4],
                    [ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][2],
                    [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                    ['Established'] * 2],
                    [ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][3],
                    [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                    ['Established'] * 2],
                    [ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][4],
                    [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                    ['Established'] * 2],
                    [ip_bgp.check_bgp_session, evpn_dict["bgp_node_list"][5],
                    [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                    ['Established'] * 2]])

    st.log("verify BGP EVPN neighborship")
    result = parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.verify_bgp_l2vpn_evpn_summary,
                           [evpn_verify1,evpn_verify2,evpn_verify3,evpn_verify4,evpn_verify5,evpn_verify6])

    if result[0].count(False) > 0:
        hdrMsg("########## BGP EVPN neighborship is NOT UP on all spine and leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    st.log("verify vxlan tunnel status")
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
        hdrMsg("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    yield

    cleanup_mclag()
    cleanup_l3vni()
    cleanup_l2vni()
    cleanup_vxlan()
    cleanup_ospf_unnumbered()
    cleanup_underlay()
    reboot.config_save(evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"], "vtysh")


@pytest.mark.cli
def test_FtOpSoRoEvpnRouterLvtepFt3231(request):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3231; TC SUMMARY : LVTEP discovery with Loopback as VTEP")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=evpn_dict["leaf1"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf1"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 1 - Verify VRF VNI map for LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 1 - Verify VRF VNI map for LVTEP node 1")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf2"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf2"]["vrf_name_list"][0],total_count="1"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 2 - Verify VRF VNI map for LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 2 - Verify VRF VNI map for LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 3 - Verify Leaf 3 system MAC in LVTEP node 2")
        success = False
    else:
        st.log("PASS step 3 - Verify Leaf 3 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="4",identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 4 - Verify Leaf 4 system MAC in LVTEP node 2")
        success = False
    else:
        st.log("PASS step 4 - Verify Leaf 4 system MAC in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][1],
                                vni=[evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf1"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf1"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 5 - Verify VLAN VNI map in LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 5 - Verify VLAN VNI map in LVTEP node 2")

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][0],
                                vni=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf3"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf3"]["l3_vni_name_list"][0]],total_count="3"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 6 - Verify VLAN VNI map in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 6 - Verify VLAN VNI map in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 7 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 7 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf3"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 8 - Verify IPv4 Prefix route in LVTEP node 2")
        success = False
    else:
        st.log("PASS at step 8 - Verify IPv4 Prefix route in LVTEP node 2")


    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")
        success = False
    else:
        st.log("PASS at step 9 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 3")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3231 FAIL step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS at step 10 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt3231")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt3231")


def test_FtOpSoRoEvpnRouterLvtepFt32311(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32311; TC SUMMARY : L2 Traffic to orphan port from remote leaf nodes")

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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32311 FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Verify mac count in LVTEP nodes ##############\n")
    ############################################################################################
    D3_mac_cnt = Mac.get_mac_count(vars.D3)
    if D3_mac_cnt >= 2:
        st.log("PASS: Mac count in Leaf1 is "+ str(D3_mac_cnt))
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32311 FAIL: Mac count in Leaf1 not as expected. Expected:2. Found: "+ str(D3_mac_cnt))
        success=False

    ############################################################################################
    hdrMsg("\n####### Verify mac learning ##############\n")
    ############################################################################################
    mac_lst = mac_list_from_bcmcmd_l2show(vars.D3)
    mac_list = filter_mac_list(vars.D3,"00:02:33:00:00:")
    if len(mac_list) == 1:
        st.log("PASS: Local macs learnt from LVTEP Node 1 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32311 FAIL: Mac count in LVTEP Node 1 is not as expected. Expected:1. Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32311 FAIL: The MACs learnt on LVTEP node 1 is :"+ mac_lst[0])
        success=False

    if D3_mac_cnt < 2 or len(mac_list) != 1:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32311"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32311")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32311")

def test_FtOpSoRoEvpnRouterLvtepFt3232(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3232; TC SUMMARY: L2 Traffic from single node leaf node to MLAG leaf node")

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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3232; TC SUMMARY: L2 Traffic from single node leaf node to MLAG leaf node")
    ############################################################################################
    hdrMsg("\n####### Verify mac count in LVTEP nodes ##############\n")
    ############################################################################################
    if retry_api(verify_mac_count, vars.D3, mac_count=30, retry_count=3, delay=5):
        st.log("PASS: Mac count in Leaf1 is at least 30")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Mac count in Leaf1 not as expected. Expected at least:30")
        success=False
        mac_status=False

    if retry_api(verify_mac_count, vars.D4, mac_count=30, retry_count=3, delay=5):
        st.log("PASS: Mac count in Leaf2 is at least 30")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Mac count in Leaf2 not as expected. Expected at least:30")
        success=False
        mac_status=False

    ############################################################################################
    hdrMsg("\n####### Verify Local mac learning in LVTEP node##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:02:77:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Local macs with pattern 00:02:77:00:00:* in D3 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Local Mac count in D3 is not as expected."
               " Expected:15 Found: "+ str(len(mac_list)))
        st.log("FAIL: Local MACs with pattern 00:02:77:00:00:* on D3 is NOT 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:77:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: local MACs  with pattern 00:02:77:00:00:* in D4 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Local Mac count in D4 is not as expected."
               " Expected:15 Found: "+ str(len(mac_list)))
        st.log("FAIL: Local MACs with pattern 00:02:77:00:00:* in D4 is NOT 15")
        success=False
        mac_status=False

    ############################################################################################
    hdrMsg("\n####### Verify Remote mac learning in LVTEP node ##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote MACs with pattern 00:02:66:00:00:* in D3 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Remote EVPN Mac count in D3 is not as expected."
               " Expected:15. Found: "+ str(len(mac_list)))
        st.log("FAIL: Remote MACs with pattern 00:02:66:00:00:* in D3 is NOT 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote MACs with pattern 00:02:66:00:00:* in D4 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Remote EVPN Mac count in D4 is not as expected."
               " Expected:15 but Found: "+ str(len(mac_list)))
        st.log("test_FtOpSoRoEvpnRouterLvtepFt3232 FAIL: Remote MACs with pattern 00:02:66:00:00:* is NOT 15 in D4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_3281"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt3232")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt3232")

def test_FtOpSoRoEvpnRouterLvtepFt3237_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3237; TC SUMMARY : Symmetric routing from MLAG leaf node to single node leaf node;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt3238; TC SUMMARY : Symmetric routing from single node leaf node to MLAG node leaf node;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt3239; TC SUMMARY : Symmetric routing from MLAG node leaf node to single node leaf node;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32310; TC SUMMARY : Symmetric routing from MLAG node leaf node to MLAG node leaf node;")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL step 1 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 1 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL step 2 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS at step 2 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    st.log("Step 5: Start L3 IPv4 and IPv6 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    ############################################################################################
    hdrMsg("\n####### Step 6: Verify L3 traffic verification should pass both direction #########\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    ############################################################################################
    hdrMsg("\n####### Verify Local mac learning in LVTEP node##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:77:14:05:01:")
    if len(mac_list) == 15:
        st.log("PASS: Local macs with pattern 00:77:14:05:01:* is 15 as expected in D3 node")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL: Local Mac with pattern 00:77:14:05:01:* is NOT 15;"
               " Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: MACs with pattern 00:77:14:05:01:* on D3 is NOT 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:77:14:05:01:")
    if len(mac_list) == 15:
        st.log("PASS: Local macs with pattern 00:77:14:05:01:* is 15 as expected in D4 node")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL: Local Mac with pattern 00:77:14:05:01:0* is NOT 15;"
               " Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: MAC with pattern 00:77:14:05:01:* on D4 is NOT 15")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D6,"00:66:14:06:01:")
    if len(mac_list) == 15:
        st.log("PASS: MAC with pattern 00:66:14:06:01:* found is 15 as expected in D6 node")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3237_2 FAIL: MAC with pattern 00:66:14:06:01:* found is NOT 15."
               " Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: MAC with pattern 00:66:14:06:01:* found in D6 node is NOT 15")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv4_3281"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt3237_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt3237_2")

def test_FtOpSoRoEvpnRouterLvtepFt3234_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3234; TC SUMMARY : Asymmetric routing from Single node leaf node to MLAG leaf node")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3235; TC SUMMARY : Asymmetric routing from MLAG leaf node to single node leaf node")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3253; TC SUMMARY : Verify L3 traffic from LVTEP to SVTEP using IPv4 SAG and vice versa")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt3254; TC SUMMARY : Verify L3 traffic from LVTEP to SVTEP using IPv6 SAG and vice versa")

    st.log("Step 3: Start L3 IPv4 traffic from MLAG client port to Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    st.log("Step 4: Verify L3 IPv4 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: IPv4 Traffic PASS from SVTEP TO LVTEP and vice versa")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: IPv4 Traffic failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Stop L3 IPv4 traffic from MLAG client port to Leaf 4")
    start_traffic(action="stop", stream_han_list=stream_dict["ipv4_3281"])

    st.log("Step 2.1: Send IPv6 L3 traffic b/w L3 to L4 with L3 tenant")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_3281"])

    st.log("Step 4.1: Verify L3 IPv6 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: IPv6 Traffic verification passed from SVTEP TO LVTEP ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: IPv6 Traffic failed b/w LVTEP To SVTEP")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 9 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log("Step 9 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],
                                vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 9 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log("Step 9 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")

    st.log(" Verify SAG IPv6 prefix route in Leaf 4 towards Leaf 3 ")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0],
                                type="C",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL step 2 - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 7 PASSED - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 6 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 6 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],
                                vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 6 - Verify SAG tenant IPv4 prefix route in Leaf 1 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 6 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 1 towards LVTEP SAG")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",type="C",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL step 2 - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 7 PASSED - Verify SAG IPv6 prefix route in Leaf 4 towards LVTEP SAG")

    st.log("Step 10: Send IPv4 L3 traffic b/w L3 to L4 with L3 tenant")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    st.log("Step 12: Verify L3 traffic from b/w LVTEP to SVTEP for Vrf1")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP and vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
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
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt3234_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt3234_2")

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

@pytest.fixture(scope="function")
def Lvtep32314_fixture(request,evpn_underlay_hooks):
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

def test_FtOpSoRoEvpnRouterLvtepFt32323_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32323; TC SUMMARY : Failure of keepalive link;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32324; TC SUMMARY : Verify Peer link failure scenario;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32329; TC SUMMARY : MAC Learning from peer node in the MLAG cluster;")

    st.log("Step 1: verify MC LAG status in LVTEP nodes before failure of keepalive link")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1)

    st.log("Step 2: verify MC LAG interface status in LVTEP nodes before failure of keepalive link")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    ############################################################################################
    hdrMsg("\n###### Step 3: Flap the peer link in LVTEP node 1 ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["iccpd_dintf_list"][0]])
    st.wait(2)
    port.noshutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["iccpd_dintf_list"][0]])
    st.wait(2)

    ############################################################################################
    hdrMsg("\n###### Step 4: Flap the peer link in LVTEP node 2 ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][1],[evpn_dict["leaf2"]["iccpd_dintf_list"][0]])
    st.wait(2)
    port.noshutdown(evpn_dict["leaf_node_list"][1],[evpn_dict["leaf2"]["iccpd_dintf_list"][0]])
    st.wait(2)

    st.log("Step 5: verify MC LAG status in LVTEP nodes after failure of keepalive link")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',mclag_intfs=1)

    st.log("Step 6: verify MC LAG interface status in LVTEP nodes after failure of keepalive link")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    ############################################################################################
    hdrMsg(" \n####### Step 7: Create L2 streams from LVTEP node 1 MLAG client port to SVTEP Leaf 4 ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_3281"])

    ############################################################################################
    hdrMsg("\n####### Step 9: Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    ############################################################################################
    hdrMsg("\n####### Step 10: Verify mac count in leaf3 ##############\n")
    ############################################################################################
    if retry_api(verify_mac_count, vars.D3, mac_count=30, retry_count=3, delay=5):
        st.log("PASS: Mac count in Leaf1 is equal/more than 30 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Mac count in D3 not as expected. Expected at least 30")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:77:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: MAC with pattern 00:02:77:00:00:* is 15 in D4 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Local Mac with pattern 00:02:77:00:00:* in D4 is"
               " not as expected. Expected:15. Found: "+ str(len(mac_list)))
        st.log("FAIL: MAC learnt with pattern 00:02:77:00:00:* in D4 is NOT 15")
        success=False
        mac_status=False

    ############################################################################################
    hdrMsg("\n####### Step 11: Verify Remote mac learning in LVTEP node ##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D3,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote EVPN macs with pattern 00:02:66:00:00:* in D3 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Remote EVPN Mac with pattern 00:02:66:00:00:* is not"
               " as expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: remote MACs with pattern 00:02:66:00:00:* is not 15 in D3")
        success=False
        mac_status=False

    mac_list = filter_mac_list(vars.D4,"00:02:66:00:00:")
    if len(mac_list) == 15:
        st.log("PASS: Remote EVPN MAC with pattern 00:02:66:00:00:* in D4 is 15 as expected.")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL: Remote EVPN Mac with patten 00:02:66:00:00:* in D4 is not"
               " as expected. Expected:15 but Found: "+ str(len(mac_list)))
        st.log("FAIL: remote MAC with pattern 00:02:66:00:00:* in D4 is not 15")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log(" Step 12: Verify SAG IPv6 prefix route in Leaf 4 towards Leaf 3 ")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0],
                                type="C",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL step 12 - Verify SAG IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log("Step 12 PASSED - Verify SAG IPv6 prefix route in Leaf 4")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 13 - Verify SAG IPv4 prefix route in Leaf 4 ")
        success = False
    else:
        st.log("Step 13 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],
                                vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL Step 14 - Verify SAG tenant IPv4 prefix route in Leaf 1 ")
        success = False
    else:
        st.log("Step 14 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 1 ")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",type="C",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt3234_2 FAIL step 15 - Verify SAG IPv6 prefix route in Leaf 4 ")
        success = False
    else:
        st.log("Step 15 PASSED - Verify SAG IPv6 prefix route in Leaf 4 ")
    current_stream_dict["stream"] = stream_dict["l2_3281"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32323_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32323_2")

def test_FtOpSoRoEvpnRouterLvtepFt32320(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32320; TC SUMMARY:Verify traffic flows through peer-link ;\
            when all MLAG ports are down and uplink tracking not enabled ;")

    st.log("Step 1: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                            mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                            mclag_intfs=1)

    st.log("Step 2: verify MC LAG isolate peer link status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("Step 3: verify MC LAG isolate peer link status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    ############################################################################################
    hdrMsg("\n###### Step 4: Shutdown the MLAG client member port in LVTEP node 1 ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["mlag_intf_list"][0]])
    st.wait(2)

    st.log("Step 5: verify MC LAG isolate peer link status in LVTEP node 2 showing isolate-peer-link flag as No")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Down", \
                            mclag_intf_l3_status='No',isolate_peer_link='No',
                               traffic_disable='No'):
        st.log("PASS: isolate-peer-link flag as No ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: isolate-peer-link flag as No ")

    hdrMsg(" \n####### Step 7: Start bidirectional traffic ##############\n")
    start_traffic(stream_han_list=stream_dict["l2_3281"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(2,"wait for 2 seconds before verifying stream results")

    hdrMsg("\n####### Step 8: Verify traffic ##############\n")
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_3281"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_3281"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed b/w LVTEP MLAG client to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Traffic verification failed b/w LVTEP MLAG client to SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed b/w SVTEP to LVTEP MLAG client")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Traffic verification failed b/w SVTEP to LVTEP MLAG client")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:02:77:00:00:01",
                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                            port=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        st.log("PASS: Local Mac 00:02:77:00:00:01 learnt in Leaf1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Local mac 00:02:77:00:00:01 not learnt in Leaf1 ")
        success=False
        mac_status=False

    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:02:77:00:00:01",
                            vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        st.log("PASS: Local mac 00:02:77:00:00:01 learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Local mac 00:02:77:00:00:01 not learnt in Leaf2")
        success=False
        mac_status=False

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:02:77:00:00:01",
                            vlan=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        st.log("PASS: Remote mac 00:02:77:00:00:01 learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Remote mac 00:02:77:00:00:01 not learnt in Leaf4")
        success=False
        mac_status=False

    hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:02:66:00:00:01",
                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        st.log("PASS: Remote Mac 00:02:66:00:00:01 learnt in Leaf1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Remote mac 00:02:66:00:00:01 not learnt in Leaf1 ")
        success=False
        mac_status=False

    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:02:66:00:00:01",
                            vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        st.log("PASS: Remote Mac 00:02:66:00:00:01 learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Remote mac 00:02:66:00:00:01 not learnt in Leaf2 ")
        success=False
        mac_status=False

    hdrMsg("\n###### Step 12: Bring up the MLAG client member port in LVTEP node 1 ######\n")
    port.noshutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["mlag_intf_list"][0]])

    hdrMsg("\n####### Step 13: Verify local mac learning in LVTEP nodes ##############\n")
    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:02:77:00:00:01",
                            vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],retry_count=6, delay=2,
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        st.log("PASS: Local Mac 00:02:77:00:00:01 learnt in Leaf1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: Local mac 00:02:77:00:00:01 not learnt in Leaf1 ")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 15: verify MC LAG isolate peer link status in LVTEP node 2 showing isolate-peer-link flag as Yes")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: isolate-peer-link flag as Yes ")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32320 FAIL: isolate-peer-link flag as Yes ")
    current_stream_dict["stream"] = stream_dict["l2_3281"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32320")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32320")


def test_FtOpSoRoEvpnRouterLvtepFt32337_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32337; TC SUMMARY: Verify BUM traffic received from VxLAN tunnel T1;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32338; TC SUMMARY: Verify BUM traffic received from peer-link;")

    hdrMsg("Step 3: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1)

    hdrMsg("Step 4: verify MC LAG interface status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    st.log("Step 5: verify MC LAG interface status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')

    st.log("Step 6: Send IPv6 L2 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32337"])
    st.wait(5,"Waiting for 5 sec before verifying traffic")

    hdrMsg("\n####### Step 8: Verify L2 BUM traffic verification b/w LVTEP MLAG client and SVTEP #########\n")
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_32337"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    if loss_prcnt1 < 0.15:
        st.log("PASS: Traffic verification passed from LVTEP TO SVTEP")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Traffic verification failed from LVTEP To SVTEP, shows drop {}".format(loss_prcnt1))
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32337"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    if loss_prcnt2 < 0.15:
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Traffic verification failed from SVTEP To LVTEP, shows drop {}".format(loss_prcnt2))

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    #hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    #if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Remote mac not learnt in Leaf1 ")
    #    success=False
    #    debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    #else:
    #    st.log("PASS: Remote Mac learnt in Leaf1 ")

    #if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Remote mac not learnt in Leaf2 ")
    #    success=False
    #    debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    #else:
    #    st.log("PASS: Remote Mac learnt in Leaf2 ")

    leaf1_rx = [];leaf2_rx =[];leaf1_tx = 0;leaf2_tx = 0
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")

    hdrMsg("\n####### Step 11: Verify BUM traffic Rx over MLAG client link ##############\n")
    if verify_traffic_pass(leaf1_rx,"rx_bps",evpn_dict['cli_mode']):
        result=False
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 1 BUM forwader port is :{} and aggregate Tx rate is :{}".format(interface1,ktx[0]['tx_bps']))
                st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 1 ")
                result=True

        if result:
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 1 ")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: BUM traffic is not passed as per local bias in LVTEP node 1 , \
                          Leaf1 Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),str(leaf1_rx[0]['rx_bps'])))
            success=False
        hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
        ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], "tx_bps")
        if " KB/s" in ktx[0]['tx_bps'] or " MB/s" in ktx[0]['tx_bps']:
            st.log("PASS: LVTEP N1 is sending the BUM traffic to N2 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: Leaf 2 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL:Leaf 2 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                success=False
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL:LVTEP N1 is not sending the BUM traffic to N2 over peer link, shows rate as :{}".format(ktx[0]['tx_bps']))
            success=False

    elif verify_traffic_pass(leaf2_rx,"rx_bps",evpn_dict['cli_mode']):
        result=False
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 2 BUM forwader port is : {} and aggregate Tx rate is : {}".format(interface1,ktx[0]['tx_bps']))
                st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 2 ")
                result=True

        if result:
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 2 ")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: BUM traffic is not passed as per local bias in LVTEP node 2 , \
                            Leaf2 Tx {} and Leaf2 Rx {}".format(ktx[0]['tx_bps'],leaf2_rx[0]['rx_bps']))
            success=False
        hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N2 ##############\n")
        ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], "tx_bps")
        if " KB/s" in ktx[0]['tx_bps'] or " MB/s" in ktx[0]['tx_bps']:
            st.log("PASS: LVTEP N2 is sending the BUM traffic to N1 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=evpn_dict["leaf1"]["intf_list_tg"][0],property="tx_bps",cli_type="click")
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: Leaf 1 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL:Leaf 1 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                success=False
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL:LVTEP N2 is not sending the BUM traffic to N1 over peer link, shows rate as : {}".format(ktx[0]['tx_bps']))
            success=False

    hdrMsg("\n####### Step 11: Verify BUM traffic Rx over VxLAN tunnel ##############\n")
    if verify_traffic_pass(leaf1_rx,"rx_bps",evpn_dict['cli_mode']):
        leaf1_rx = 0;leaf2_rx = 0
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "rx_bps")
            rx_val = leaf1_rx[0]['rx_bps'].split(" ")
            if " MB/s" in leaf1_rx[0]['rx_bps']:
                st.log("INFO: Leaf 1 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
                hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: LVTEP N1 is sending the BUM traffic to N2 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
                    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
                    tx_val = ktx[0]['tx_bps'].split(" ")
                    if verify_vxlan_traffic(ktx,tx_val,"decap"):
                        st.log("PASS: Leaf 2 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
                    else:
                        st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Leaf 2 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                        success=False
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: LVTEP N1 is not sending the BUM traffic to N2 over peer link, \
                        shows rate as : {}".format(ktx[0]['tx_bps']))
                    success=False
            elif " KB/s" in leaf1_rx[0]['rx_bps'] and float(rx_val[0]) > 1000.0:
                st.log("INFO: Leaf 1 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
                hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: LVTEP N1 is sending the BUM traffic to N2 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
                    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
                    tx_val = ktx[0]['tx_bps'].split(" ")
                    if verify_vxlan_traffic(ktx,tx_val,"decap"):
                        st.log("PASS: Leaf 2 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
                    else:
                        st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Leaf 2 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                        success=False
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: LVTEP N1 is not sending the BUM traffic to N2 over peer link, \
                        shows rate as : {}".format(ktx[0]['tx_bps']))
                    success=False

    elif verify_traffic_pass(leaf2_rx,"rx_bps",evpn_dict['cli_mode']):
        leaf1_rx = 0;leaf2_rx = 0
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "rx_bps")
            rx_val = leaf2_rx[0]['rx_bps'].split(" ")
            if " MB/s" in leaf2_rx[0]['rx_bps']:
                st.log("INFO: Leaf 2 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
                hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N2 ##############\n")
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: LVTEP N2 is sending the BUM traffic to N1 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
                    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0], "tx_bps")
                    tx_val = ktx[0]['tx_bps'].split(" ")
                    if verify_vxlan_traffic(ktx,tx_val,"decap"):
                        st.log("PASS: Leaf 1 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
                    else:
                        st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Leaf 1 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                        success=False
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: LVTEP N2 is not sending the BUM traffic to N1 over peer link, \
                        shows rate as : {}".format(ktx[0]['tx_bps']))
                    success=False
            elif " KB/s" in leaf2_rx[0]['rx_bps'] and float(rx_val[0]) > 1000.0:
                st.log("INFO: Leaf 2 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
                hdrMsg("\n####### Step 11: Verify BUM traffic Tx over MLAG peer link in LVTEP N2 ##############\n")
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: LVTEP N2 is sending the BUM traffic to N1 over peer link at the rate of : {}".format(ktx[0]['tx_bps']))
                    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0], "tx_bps")
                    tx_val = ktx[0]['tx_bps'].split(" ")
                    if verify_vxlan_traffic(ktx,tx_val,"decap"):
                        st.log("PASS: Leaf 1 BUM traffic flooding to orphon port at the rate: {}".format(ktx[0]['tx_bps']))
                    else:
                        st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: Leaf 1 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx[0]['tx_bps']))
                        success=False
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32337_2 FAIL: LVTEP N2 is not sending the BUM traffic to N1 over peer link, \
                        shows rate as : {}".format(ktx[0]['tx_bps']))
                    success=False
    current_stream_dict["stream"] = stream_dict["l2_32337"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32337_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32337_2")

def test_FtOpSoRoEvpnRouterLvtepFt32339_2(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32339; TC SUMMARY: Verify BUM traffic from SHD;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32340; TC SUMMARY: Verify BUM traffic received;\
            from MHD is flooded to SHD, other MHD, all VxLAN tunnels and peer-link;")

    st.log("Step 3: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1)

    st.log("Step 4: verify MC LAG interface status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("Step 5: verify MC LAG interface status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("Step 6: Send IPv6 L2 BUM traffic b/w LVTEP orphon port to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32339"])

    hdrMsg("\n####### Step 8: Verify L2 BUM traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D3P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Traffic verification failed b/w LVTEP To SVTEP")

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:20:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:20:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")
    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:20:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:20:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:20:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Step 12: Shutdown the LVTEP N1 orphon port forwarding traffic to SVTEP ######\n")
    ############################################################################################
    Vlan.delete_vlan_member(evpn_dict["leaf_node_list"][0],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True)

    hdrMsg("\n####### Step 13: Verify BUM traffic Rx over VxLAN tunnel ##############\n")
    leaf1_rx = 0;leaf2_rx = 0
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "rx_bps")
        if verify_traffic_pass(ktx,"rx_bps",evpn_dict['cli_mode']):
            st.log("INFO: Leaf 1 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: LVTEP N1 is sending the BUM traffic Tx over MLAG client port at the rate of : {}".format(ktx))
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N1 is not sending the BUM traffic Tx over MLAG, \
                            client port at the rate of : {}".format(ktx))
                success=False
            hdrMsg("\n####### Step 14: Verify BUM traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: LVTEP N1 is sending the BUM traffic to N2 over peer link at the rate of : {}".format(ktx))
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: Leaf 2 BUM traffic flooding to orphon port at the rate: {}".format(ktx))
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Leaf 2 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx))
                    success=False
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N1 is not sending the BUM traffic to N2 over peer link, shows rate as : {}".format(ktx))
                success=False

    for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
        rx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                        interface=interface1,property="rx_bps",cli_type="click")
        leaf2_rx = leaf2_rx + int(float(rx[0]['rx_bps']))
        if int(float(rx[0]['rx_bps'])) > 350:
            st.log("INFO: Leaf 2 BUM Rx port over Vxlan tunnel is : {}".format(interface1))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: LVTEP N2 is sending the BUM traffic Tx over MLAG client port at the rate of : {}".format(ktx))
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N2 is not sending the BUM traffic Tx over MLAG client port at the rate of : {}".format(ktx))
                success=False
            hdrMsg("\n####### Step 14: Verify BUM traffic Tx over MLAG peer link in LVTEP N2 ##############\n")
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: LVTEP N2 is sending the BUM traffic to N1 over peer link at the rate of : {}".format(ktx))
                Vlan.add_vlan_member(evpn_dict["leaf_node_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            evpn_dict["leaf1"]["intf_list_tg"][1],True)
                if evpn_dict['cli_mode'] == "klish":
                    st.wait(16,"wait for 16 seconds before verifying Tx stats on newly added port to vlan")
                ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["intf_list_tg"][1], "tx_bps")
                tx_val = ktx[0]['tx_bps'].split(" ")
                if verify_vxlan_traffic(ktx,tx_val,"decap"):
                    st.log("PASS: Leaf 1 BUM traffic flooding to orphon port at the rate: {}".format(ktx))
                else:
                    st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Leaf 1 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx))
                    success=False
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N2 is not sending the BUM traffic to N1 over peer link, shows rate as : {}".format(ktx))
                success=False

    ############################################################################################
    hdrMsg("\n###### Step 15: Bring up LVTEP N1 orphon port forwarding traffic to SVTEP ######\n")
    ############################################################################################
    Vlan.add_vlan_member(evpn_dict["leaf_node_list"][0],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True)

    ############################################################################################
    hdrMsg("\n###### Step 16: Shutdown the SVTEP TG port forwarding traffic to LVTEP Orphon port ######\n")
    ############################################################################################
    Vlan.delete_vlan_member(evpn_dict["leaf_node_list"][3],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True)

    leaf1_rx = [];leaf1_tx = 0;
    leaf1_rx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=evpn_dict["leaf1"]["intf_list_tg"][0],property="rx_bps",cli_type="click")

    hdrMsg("\n####### Step 17: Verify BUM traffic Rx over MLAG orphon port ##############\n")
    if int(float(leaf1_rx[0]['rx_bps'])) > 350:
        st.log("PASS: LVTEP Orphon port Rx traffic, shows rx rate as : {}".format(leaf1_rx[0]['rx_bps']))
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=interface1,property="tx_bps",cli_type="click")
            leaf1_tx = leaf1_tx + int(float(tx[0]['tx_bps']))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 1 BUM forwader port is : {}".format(interface1))

        if leaf1_tx >= int(float(leaf1_rx[0]['rx_bps'])) - 10:
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 1 ")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: BUM traffic is not passed as per local bias in LVTEP node 1 , \
                          Leaf1 Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),str(leaf1_rx[0]['rx_bps'])))
            success=False

        hdrMsg("\n####### Step 18: Verify BUM traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
        tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],property="tx_bps",cli_type="click")
        if int(float(tx[0]['tx_bps'])) > 350:
            st.log("PASS: LVTEP N1 is sending the BUM traffic to N2 over peer link at the rate of : {}".format(ktx))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1],evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"decap"):
                st.log("PASS: Leaf 2 BUM traffic flooding to orphon port at the rate: {}".format(ktx))
            else:
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: Leaf 2 BUM traffic not flooding to orphon port, shows rate: {}".format(ktx))
                success=False
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N1 is not sending the BUM traffic to N2 over peer link, shows rate as : {}".format(ktx))
            success=False

    else:
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32339_2 FAIL: LVTEP N1 Orphon port is not Rx traffic, shows rx rate as : {}".format(leaf1_rx[0]['rx_bps']))

    ############################################################################################
    hdrMsg("\n###### Step 19: Bring up SVTEP TG port forwarding traffic to LVTEP Orphon port ######\n")
    ############################################################################################
    Vlan.add_vlan_member(evpn_dict["leaf_node_list"][3],
           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True)
    current_stream_dict["stream"] = stream_dict["l2_32339"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32339_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32339_2")

def test_FtOpSoRoEvpnRouterLvtepFt32335(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32335; TC SUMMARY: BGP neighborship flap in an MLAG cluster")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32319; TC SUMMARY: Track the MLAG port and verify after flapping the port")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32342; TC SUMMARY: Traffic when one of the MLAG nodes down")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32326; TC SUMMARY: MLAG Error recovery")

    hdrMsg(" \n####### Enabling up link tracking on LVTEP nodes ##############\n")
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='yes')
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='yes')

    hdrMsg(" \n####### Adding up link tracking ports ##############\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3],evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"2")
    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3],evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"2")

    st.log("Step 3: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG domain status check in LVTEP N2")

    st.log("Step 4: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG interface status check in LVTEP N1")

    st.log("Step 5: verify MC LAG interface status in LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG interface status check in LVTEP N2")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][0],name="track1",timeout="2"):
        st.log("PASS: Linktrack summary status in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack summary status in LVTEP N1")

    if Evpn.verify_linktrack_summary(dut=evpn_dict["leaf_node_list"][1],name="track1",timeout="2"):
        st.log("PASS: Linktrack summary status in LVTEP N2")
        st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32335","tc_passed")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack summary status in LVTEP N2")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="",timeout="2",
                            direction=["Upstream"]*4+["Downstream"],interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                            evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                            evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                            direction_state=["Up","Up","Up","Up","Up"],retry_count=5, delay=1):
        st.log("PASS: Linktrack status is Up in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack status is not Up in LVTEP N1")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="",
                            timeout="2",direction=["Upstream"]*4+["Downstream"],interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                            evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                            evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                            direction_state=["Up","Up","Up","Up","Up"],retry_count=5,delay=1,startup_remain_time="0"):
        st.log("PASS: Linktrack status is Up in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack status is not Up in LVTEP N2")
    ############################################################################################
    hdrMsg(" \n####### Step 7: Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32335"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(5,"wait for 5 seconds before verifying stream results")

    ############################################################################################
    hdrMsg("\n####### Step 8: Verify traffic ##############\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["l2_32335"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32335"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-MLAG to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Traffic verification failed b/w LVTEP-MLAG To SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N1")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Traffic verification failed b/w SVTEP to LVTEP-MLAG")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    else:
        st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32342","tc_passed")

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):

        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### Step 11: Verify L2 unicast traffic Rx over MLAG client link ##############\n")
    leaf1_rx = [];leaf2_rx =[];leaf1_tx = 0;leaf2_tx = 0
    leaf1_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"][0], "rx_bps")
    leaf2_rx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "rx_bps")

    if verify_traffic_pass(leaf1_rx,"rx_bps",evpn_dict['cli_mode']):
        result=False
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: LVTEP N1 L2 traffic forwader port is : {}".format(interface1))
                result=True

        if result:
            st.log("PASS: L2 traffic is passed as per local bias in LVTEP node 1 ")
            st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32319","tc_passed")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: L2 traffic is not passed as per local bias in LVTEP node 1 , \
                          Leaf1 Tx {} and Leaf1 Rx {}".format(ktx[0]['tx_bps'],leaf1_rx[0]['rx_bps']))
            success=False

        hdrMsg("\n####### Step 11: Verify L2 traffic Tx over MLAG peer link in LVTEP N1 ##############\n")
        tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], "tx_bps")
        if verify_traffic_pass(tx,"tx_bps",evpn_dict['cli_mode']):
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL:LVTEP N1 is sending the L2 traffic to N2 on peer link @ the rate : {}".format(tx[0]['tx_bps']))
            success=False
        else:
            st.log("PASS: LVTEP N1 is not sending the BUM traffic to N2 over peer link, shows rate as : {}".format(tx[0]['tx_bps']))
            tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["intf_list_tg"][0], "tx_bps")
            if verify_traffic_pass(tx,"tx_bps",evpn_dict['cli_mode']):
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL:LVTEP N2 forward L2 traffic to orphon port at the rate: {}".format(tx[0]['tx_bps']))
                success=False
            else:
                st.log("PASS: LVTEP N2 forward L2 traffic to orphon port, shows rate: {}".format(tx))

        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0],interface1, "tx_bps")
            port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])
            tx_val = tx[0]['tx_bps'].split(" ")
            if " MB/s" in tx[0]['tx_bps']:
                st.log("INFO: LVTEP N1 L2 traffic forwader port is : {}".format(interface1))
            elif " KB/s" in tx[0]['tx_bps'] and float(tx_val[0]) > 1000.0:
                st.log("INFO: LVTEP N1 L2 traffic forwader port is : {}".format(interface1))

        st.wait(2)
        st.log("verify MC LAG interface status in LVTEP node 1 after uplink ports are down")
        if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Down", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                                   traffic_disable='Yes'):
            st.log("PASS: MC LAG domain status check in LVTEP N1 after uplink failure")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG domain status check in LVTEP N1 after uplink failure")
        ############################################################################################
        hdrMsg("\n####### Step 12: Verify if L2 traffic goes through other MLAG peer node ##############\n")
        ############################################################################################
        if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
            st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
            debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

        if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="",timeout="2",
                            direction=["Upstream"]*2+["Downstream"],interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                            evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                            direction_state=["Down","Down","Disabled"],retry_count=10, delay=1):
            st.log("PASS: Linktrack Downstream status is Disabled in LVTEP N1")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack Downstream status is not Disabled in LVTEP N1")

        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    elif verify_traffic_pass(leaf2_rx,"rx_bps",evpn_dict['cli_mode']):
        result=False
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if " MB/s" in ktx[0]['tx_bps']:
                st.log("INFO: LVTEP N2 L2 traffic forwader port is : {}".format(interface1))
                result=True
            elif " KB/s" in ktx[0]['tx_bps'] and float(tx_val[0]) > 1000.0:
                st.log("INFO: LVTEP N2 L2 traffic forwader port is : {}".format(interface1))
                result=True

        if result:
            st.log("PASS: L2 traffic is passed as per local bias in LVTEP node 2 ")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: L2 traffic is not passed as per local bias in LVTEP node 2 , \
                            Leaf2 Tx {} and Leaf2 Rx {}".format(ktx[0]['tx_bps'],leaf2_rx[0]['rx_bps']))
            success=False

        hdrMsg("\n####### Step 11: Verify L2 unicast traffic Tx over MLAG peer link in LVTEP N2 ##############\n")
        tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0], "tx_bps")
        if verify_traffic_pass(tx,"tx_bps",evpn_dict['cli_mode']):
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: LVTEP N2 is sending the BUM traffic to N1 over peer link at the rate of : {}".format(tx[0]['tx_bps']))
            success=False
        else:
            st.log("PASS: LVTEP N2 is not sending the L2 unicast traffic to N1 over peer link, shows rate as : {}".format(tx[0]['tx_bps']))
            tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0], "tx_bps")
            if verify_traffic_pass(tx,"tx_bps",evpn_dict['cli_mode']):
                st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL:LVTEP N1 L2 traffic forwarding to orphon port @ the rate: {}".format(tx[0]['tx_bps']))
                success=False
            else:
                st.log("PASS: LVTEP N1 L2 traffic not forwarding to orphon port, shows rate: {}".format(tx))

        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            tx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            port.shutdown(evpn_dict["leaf_node_list"][1],[interface1])
            tx_val = tx[0]['tx_bps'].split(" ")
            if " MB/s" in tx[0]['tx_bps']:
                st.log("INFO: LVTEP N2 L2 traffic forwader port is : {}".format(interface1))
            elif " KB/s" in tx[0]['tx_bps'] and float(tx_val[0]) > 1000.0:
                st.log("INFO: LVTEP N2 L2 traffic forwader port is : {}".format(interface1))

        st.wait(2)
        st.log("verify MC LAG interface status in LVTEP node 2 after uplink ports are down")
        if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Down", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                                   traffic_disable='Yes'):
            st.log("PASS: MC LAG domain status check in LVTEP N2 after uplink failure")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: MC LAG domain status check in LVTEP N2 after uplink failure")

        ############################################################################################
        hdrMsg("\n####### Step 12: Verify if L2 traffic goes through other MLAG peer node ##############\n")
        ############################################################################################
        if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
            st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
            debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

        if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="",timeout="2",
                            direction=["Upstream"]*2+["Downstream"],interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                            evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                            direction_state=["Down","Down","Disabled"],retry_count=10, delay=1):
            st.log("PASS: Linktrack Downstream status is Disabled in LVTEP N2")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack Downstream status is not Disabled in LVTEP N2")

        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            port.noshutdown(evpn_dict["leaf_node_list"][1],[interface1])
    else:
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: L2 unicast traffic is not flowing through any of MLAG member nodes ")
        success=False

    hdrMsg(" \n####### Step 14: Verify link track status after all the up links are brought up ##############\n")
    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][0],name="track1",description="",timeout="2",
                            direction=["Upstream"]*4+["Downstream"],interface=[evpn_dict["leaf1"]["intf_list_spine"][3],
                            evpn_dict["leaf1"]["intf_list_spine"][7],evpn_dict["leaf1"]["pch_intf_list"][0],
                            evpn_dict["leaf1"]["pch_intf_list"][1],evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                            direction_state=["Up","Up","Up","Up","Up"],retry_count=9, delay=2):
        st.log("PASS: Linktrack status is Up in LVTEP N1 after uplinks are up")
        st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32326","tc_passed")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack status is not Up in LVTEP N1 after uplinks are up")

    if retry_api(Evpn.verify_linktrack_group_name,evpn_dict["leaf_node_list"][1],name="track1",description="",
                            timeout="2",direction=["Upstream"]*4+["Downstream"],interface=[evpn_dict["leaf2"]["intf_list_spine"][3],
                            evpn_dict["leaf2"]["intf_list_spine"][7],evpn_dict["leaf2"]["pch_intf_list"][0],
                            evpn_dict["leaf2"]["pch_intf_list"][1],evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                            direction_state=["Up","Up","Up","Up","Up"],retry_count=9, delay=2):
        st.log("PASS: Linktrack status is Up in LVTEP N2 after uplinks are up")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32335 FAIL: Linktrack status is not Up in LVTEP N2 after uplinks are up")

    hdrMsg(" \n####### Step 16: removing up link tracking ports ##############\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3],evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"10","no")
    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3],evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"10","no")

    hdrMsg(" \n####### Step 17: disable up link tracking ##############\n")
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='no')
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='no')
    current_stream_dict["stream"] = stream_dict["l2_32335"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32335")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32335")

def test_FtOpSoRoEvpnRouterLvtepFt32336(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32336; TC SUMMARY: Vxlan tunnel flapping in an MLAG cluster")

    hdrMsg("Step 3: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 4: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: MC LAG interface status check in LVTEP N1")

    hdrMsg("Step 5: verify MC LAG interface status in LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: MC LAG interface status check in LVTEP N2")

    st.log("Step 7: Start L2 IPv6 BUM traffic b/w LVTEP orphon port & SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32336"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(5,"wait for 5 seconds before verifying stream results")

    hdrMsg("\n####### Step 8: Verify L2 BUM traffic verification #########\n")
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d3_tg_ph1'],stream_dict["l2_32336"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["l2_32336"][1],dest_tg_ph=tg_dict['d3_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-N1 to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Traffic verification failed b/w LVTEP-N1 To SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N1")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Traffic verification failed b/w SVTEP to LVTEP-N1")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf1"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][3],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    #hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    #if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not learnt in Leaf1 ")
    #    success=False
    #else:
    #    st.log("PASS: Remote Mac learnt in Leaf1 ")

    #if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:06:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
    #                        dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not learnt in Leaf2 ")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac still resent in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac withdrawn in Leaf1 ")

    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac still present in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac withdrawn in Leaf2 ")

    hdrMsg("\n####### Step 14: Verify remote mac learning in SVTEP node ##############\n")
    if retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][3],macaddress="00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac still present in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac withdrawn in Leaf4 ")

    hdrMsg("\n####### Step 15: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n Step 18: Bring down vxlan tunnel in LVTEP N1 by shuting down all uplinks \n")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                        interface=interface1,property="tx_bps",cli_type="click")
        port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])
        if int(float(tx[0]['tx_bps'])) > 350:
            st.log("INFO: LVTEP N1 L2 traffic forwader port is : {}".format(interface1))

    #hdrMsg("\n####### Step 19: Verify remote mac learning in SVTEP node ##############\n")
    #if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:16:01:01:01",
    #                        vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
    #                        dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not present in Leaf4")
    #    success=False
    #else:
    #    st.log("PASS: Remote mac present in Leaf4 as LVTEP other peer is still Up")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=9, delay=2,
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac not present in LVTEP N2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac present in Leaf2 ")

    hdrMsg("\n Step 20: Check the mac in LVTEP peer node \n")
    if retry_api_false(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic",retry_count=10, delay=2):
        st.log("PASS: Remote Mac withdrawn in Leaf1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32336 FAIL: Remote mac still learnt in Leaf1 ")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n Step 21: Bring up vxlan tunnel in LVTEP N1 by bringing up all the uplinks")
    for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
        port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])
    current_stream_dict["stream"] = stream_dict["l2_32336"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32336")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32336")

def test_FtOpSoRoEvpnRouterLvtepFt32330_3(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32330; TC SUMMARY : Verify Same RD on MLAG peer nodes;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32322; TC SUMMARY : Change the keepalive interface from vlan to physical and vice versa;\
            TC ID: test_FtOpSoRoEvpnRouterLvtepFt32321; TC SUMMARY : Flapping the ICCP protocol;")

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    if mclag_active_node_rmac == "00:00:01:02:03:04":
        hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32330_3")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: MC LAG interface status check in LVTEP N1")

    hdrMsg("Step 3: verify MC LAG interface status in LVTEP node 2")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: MC LAG interface status check in LVTEP N2")

    hdrMsg("Step 4: Verify that L3 ipv4 routes available before sending the L3 traffic from LVTEP to SVTEP")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("failed at step 4 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("passed at step 4 - Verify IPv4 Prefix route in LVTEP node 1")

    hdrMsg("Step 5: Verify that L3 ipv6 routes available before sending the L3 traffic from LVTEP to SVTEP")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("failed at step 5 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("passed at step 5 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32330","tc_passed")

    ipv4_nw = evpn_dict["leaf1"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf1"]["l3_tenant_ipv6_net"][0].split("/")


    st.log("Step 6: Verify the default auto RD is in correct state as part of base line config before test start")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 6 Verify ipv4 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N1")
        success = False
    else:
        st.log("PASS: step 6 Verify ipv4 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N1 ")

    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 7 Verify ipv6 tenant using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N1")
        success = False
    else:
        st.log("PASS: step 7 Verify ipv6 tenant using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N1 ")

    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 8 Verify ipv4 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N1")
        success = False
    else:
        st.log("PASS: step 8 Verify ipv4 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N1 ")

    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 9 Verify ipv6 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N1")
        success = False
    else:
        st.log("PASS: step 9 Verify ipv6 tenant route bgp l2vpn evpn route in Leaf 4 for LVTEP N1 ")

    if Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf1"]["l3_vni_list"][0],rvtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                         vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],rmac=mclag_active_node_rmac):
        st.log("PASS: step 10 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1 ")
    elif Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf1"]["l3_vni_list"][0],rvtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                         vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],rmac=mclag_active_node_rmac):
        st.log("PASS: step 10 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 10 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1")
        #success = False

    if Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf1"]["l3_vni_list"][0],rvtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                         vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],rmac=mclag_active_node_rmac):
        st.log("PASS: step 11 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1 ")
    elif Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf1"]["l3_vni_list"][0],rvtep=evpn_dict["leaf1"]["loop_ip_list"][2],
                         vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],rmac=mclag_active_node_rmac):
        st.log("PASS: step 11 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 11 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N1")
        #success = False

    ipv4_nw = evpn_dict["leaf2"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf2"]["l3_tenant_ipv6_net"][0].split("/")

    st.log("Step 7: Verify the default RT and RD is in correct state as part of base line config before test start")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 12 Verify ipv4 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N2")
        success = False
    else:
        st.log("PASS: step 12 Verify ipv4 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N2")

    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 13 Verify ipv6 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N2")
        success = False
    else:
        st.log("PASS: step 13 Verify ipv6 tenant route using bgp l2vpn evpn route type prefix in Leaf 4 for LVTEP N2")

    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 14 Verify ipv4 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N2")
        success = False
    else:
        st.log("PASS: step 14 Verify ipv4 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N2")

    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 15 Verify ipv6 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N2")
        success = False
    else:
        st.log("PASS: step 15 Verify ipv6 tenant route using bgp l2vpn evpn route in Leaf 4 for LVTEP N2")

    if Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf2"]["l3_vni_list"][0],
                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],
                         rmac=mclag_active_node_rmac):
        st.log("PASS: step 16 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
    elif Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf1"]["l3_vni_list"][0],
                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],
                         rmac=mclag_active_node_rmac):
        st.log("PASS: step 16 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 16 Verify ipv4 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
        #success = False

    if Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf2"]["l3_vni_list"][0],
                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],
                         rmac=mclag_active_node_rmac):
        st.log("PASS: step 17 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
    elif Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                         rt=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]+":"+evpn_dict["leaf2"]["l3_vni_list"][0],
                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0],
                         rmac=mclag_active_node_rmac):
        st.log("PASS: step 17 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL : Step 17 Verify ipv6 tenant route using bgp l2vpn evpn route detail type prefix in Leaf 4 for LVTEP N2")
        #success = False

    st.log("Step 18: Configure user configured L3 RD and verify the show bgp evpn routes on the neighbor")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_rd="1:1",config="yes", local_as=evpn_dict["leaf1"]['local_as'])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_rd="2:2",config="yes", local_as=evpn_dict["leaf2"]['local_as'])

    ipv4_nw = evpn_dict["leaf1"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf1"]["l3_tenant_ipv6_net"][0].split("/")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd="1:1",status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 19 FAIL: Verify ipv4 tenant route not showing rd 1:1 in Leaf4 from {}".format(evpn_dict["leaf_node_list"][0]))
        success = False
    else:
        st.log("Step 19: PASSED - Verify ipv4 tenant route to check manual configured LVTEP Node 1 RD in Leaf 4")

    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd="1:1",status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 20 FAIL: Verify ipv6 tenant route not showing rd 1:1 in Leaf4 from {}".format(evpn_dict["leaf_node_list"][0]))
        success = False
    else:
        st.log("Step 20: PASSED - Verify ipv6 tenant route to check manual configured LVTEP Node 1 RD in Leaf 4")
        st.report_tc_pass("test_FtOpSoRoEvpnRouterLvtepFt32322","tc_passed")

    ipv4_nw = evpn_dict["leaf2"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf2"]["l3_tenant_ipv6_net"][0].split("/")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd="2:2",status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 21 FAIL: Verify ipv4 tenant route not showing rd 2:2 in Leaf4 from {}".format(evpn_dict["leaf_node_list"][1]))
        success = False
    else:
        st.log("Step 21: PASSED - Verify ipv4 tenant route to check manual configured LVTEP Node 2 RD in Leaf 4")

    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd="2:2",status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 22 FAIL: Verify ipv6 tenant route not showing rd 2:2 in Leaf4 from {}".format(evpn_dict["leaf_node_list"][1]))
        success = False
    else:
        st.log("Step 22: PASSED - Verify ipv6 tenant route to check manual configured LVTEP Node 2 RD in Leaf 4")


    st.log("Step 23: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    st.log("Step 25: Start L3 IPv4 and IPv6 traffic b/w LVTEP to SVTEP with manual RD configured")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(3,"wait for 3 seconds so IXIA L3 traffic uses resolved ARP mac as D-MAC")
    ############################################################################################
    hdrMsg("\n####### Step 26: Verify L3 traffic  b/w LVTEP to SVTEP with manual RD configured #########\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["ipv4_3281"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv4_3281"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP-N2 to SVTEP with manual RD configured")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification fail from LVTEP-N2 to SVTEP after RD change")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N2 with manual RD configured")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification fail from SVTEP to LVTEP-N2 after RD change")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 27: Verify local mac learning in LVTEP node N1 ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:77:14:05:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    hdrMsg("\n####### Step 28: Verify local mac learning in LVTEP node N2 ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:77:14:05:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 29: Verify local mac learning in SVTEP ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:66:14:06:01:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Local mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf4 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 31: Remove the manual entry and verify the auto RD is received")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], config_type_list=["vrf_rd_rt"],
                         vrf_name="Vrf1",l3_rd="1:1",config="no", local_as=evpn_dict["leaf1"]['local_as'])

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1], config_type_list=["vrf_rd_rt"],
                         vrf_name="Vrf1",l3_rd="2:2",config="no", local_as=evpn_dict["leaf2"]['local_as'])

    ipv4_nw = evpn_dict["leaf1"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf1"]["l3_tenant_ipv6_net"][0].split("/")
    st.log("Step 32: Verify EVPN type 5 - IPv4 prefix route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 32 FAIL: Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        success = False
    else:
        st.log("Step 32 PASSED - Remove the manual entry and verify the auto RD")

    st.log("Step 33: Verify EVPN type 5 - IPv6 prefix route for auto RD")
    Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf1"]["loop_ip_list"][2])

    ipv4_nw = evpn_dict["leaf2"]["l3_tenant_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf2"]["l3_tenant_ipv6_net"][0].split("/")
    st.log("Step 34: Verify EVPN type 5 - IPv4 Route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 34 FAIL: Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        success = False
    else:
        st.log("Step 34: PASSED - Remove the manual entry and verify the auto RD for IPv4 route")

    st.log("Step 35: Verify EVPN type 5 - IPv6 Route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf2"]["loop_ip_list"][2]):
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32330_3 Step 35 FAIL: Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        success = False
    else:
        st.log("Step 35 PASSED - Remove the manual entry and verify the auto RD for IPv6 route")

    ############################################################################################
    hdrMsg("\n####### Step 37: Verify L3 traffic b/w LVTEP to SVTEP with auto RD configured #########\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["ipv4_3281"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv4_3281"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP to SVTEP with auto RD")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification failed from LVTEP to SVTEP with auto RD")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to SVTEP with auto RD")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification failed from SVTEP to SVTEP with auto RD")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 39: Remove IP address b/w Leaf 1 and Leaf 2 router port for ICCPD control path")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

    new_vlan = "151"
    st.log("Step 40: Create a new VLAN 151 to be used for ICCPD control path")
    utils.exec_all(True,[[Vlan.create_vlan,evpn_dict["leaf_node_list"][0],new_vlan],
            [Vlan.create_vlan,evpn_dict["leaf_node_list"][1],new_vlan]])

    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
            new_vlan, evpn_dict["leaf1"]["iccpd_ncintf_list"][0],True],
            [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
            new_vlan, evpn_dict["leaf2"]["iccpd_ncintf_list"][0],True]])

    st.log("Step 41: Configure IP address b/w Leaf 1 and Leaf 2 VLAN L3 interface establish ICCPD control path")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        "Vlan"+new_vlan, evpn_dict["leaf1"]["iccpd_ip_list"][0],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        "Vlan"+new_vlan, evpn_dict["leaf2"]["iccpd_ip_list"][0],'31']])

    hdrMsg("Step 42: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                            mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                            mclag_intfs=1)

    hdrMsg("Step 43: verify MC LAG interface status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    hdrMsg("Step 44: verify MC LAG interface status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    ############################################################################################
    hdrMsg("\n####### Step 46: Verify L3 traffic b/w LVTEP to SVTEP after iccpd control path flap #########\n")
    ############################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["ipv4_3281"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv4_3281"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
    traffic_status = True

    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed from LVTEP to SVTEP after iccpd control path flap")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification failed from LVTEP to SVTEP after iccpd control path flap")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to SVTEP after iccpd control path flap")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32330_3 FAIL: Traffic verification failed from SVTEP to SVTEP after iccpd control path flap")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    st.log("Step 48: Remove IP address b/w Leaf 1 and Leaf 2 VLAN L3 interface establish ICCPD control path")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        "Vlan"+new_vlan, evpn_dict["leaf1"]["iccpd_ip_list"][0],'31'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        "Vlan"+new_vlan, evpn_dict["leaf2"]["iccpd_ip_list"][0],'31']])

    st.log("Step 49: Delete VLAN membership for new L3 VNI VLAN")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
            new_vlan, evpn_dict["leaf1"]["iccpd_ncintf_list"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
            new_vlan, evpn_dict["leaf2"]["iccpd_ncintf_list"][0],True]])

    st.log("Step 50: Delete new L3 VNI VLAN on leaf 3 and 4")
    utils.exec_all(True,[[Vlan.delete_vlan,evpn_dict["leaf_node_list"][0],new_vlan],
            [Vlan.delete_vlan,evpn_dict["leaf_node_list"][1],new_vlan]])

    st.log("Step 51: Configure IP address b/w Leaf 1 and Leaf 2 to establish ICCPD control path")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

    hdrMsg("Step 52: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1)

    hdrMsg("Step 53: verify MC LAG interface status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    hdrMsg("Step 54: verify MC LAG interface status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')
    current_stream_dict["stream"] = stream_dict["ipv4_3281"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32330_3")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32330_3")

def test_FtOpSoRoEvpnRouterLvtepFt32313(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32313; TC SUMMARY:Symmetric Traffic to orphan port from remote leaf nodes")

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    if mclag_active_node_rmac == "00:00:01:02:03:04":
        hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32313")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL step 1 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 1 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf2"]["loop_ip_list"][2],
                       ip_address=evpn_dict["leaf2"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL step 2 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS at step 2 - Verify IPv4 Prefix route in LVTEP node 1")

    st.log("Step 3: Getting the router MAC for the L3 Traffic")
    dut4_gateway_mac = basic.get_ifconfig(vars.D4, vars.D4T1P1)[0]['mac']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']


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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL: Traffic verification failed b/w LVTEP-N2 To SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP-N2")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL: Traffic verification failed b/w SVTEP to LVTEP-N2")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### Step 7: Verify local mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:00:14:04:04:01",
                            vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Local mac learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL: Local mac not learnt in Leaf2")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### Step 8: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:00:14:06:04:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32313 FAIL: Remote mac not learnt in Leaf4")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv4_32313"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32313")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32313")

def test_FtOpSoRoEvpnRouterLvtepFt32312(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32312; TC SUMMARY:Asymmetric Traffic to orphan port from remote leaf nodes")

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    if mclag_active_node_rmac == "00:00:01:02:03:04":
        hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32312")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL step 1 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log("PASS step 1 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf2"]["loop_ip_list"][2],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL step 2 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 4")
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

    st.log("Step 8: Start L3 IPv6 traffic b/w LVTEP orphon port to SVTEP")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_32312_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_32312_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_32312"])
    if tg_dict["tg"].tg_type == 'ixia':
        st.wait(5,"wait for 5 seconds so IXIA L3 traffic uses resolved ARP mac as D-MAC")

    ###################################################################################
    hdrMsg("\n####### Step 9: Verify L3 traffic b/w LVTEP orphon port to SVTEP #########\n")
    ####################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d4_tg_ph1'],stream_dict["ipv6_32312"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
    loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv6_32312"][1],dest_tg_ph=tg_dict['d4_tg_ph1'])
    traffic_status = True
    if loss_prcnt < 0.11:
        st.log("PASS: Traffic verification passed b/w LVTEP orphon port to SVTEP")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL Traffic b/w LVTEP orphon port to SVTEP")

    if loss_prcnt1 < 0.11:
        st.log("PASS: Traffic verification passed b/w SVTEP to LVTEP orphan port")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL Traffic b/w SVTEP to LVTEP orphan port")

    if not traffic_status:
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 10: Verify local mac learning in LVTEP nodes ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:14:04:06:01",
                            vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Local mac learnt in Leaf2 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False

    hdrMsg("\n####### Step 11: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:14:06:06:01",
                            vlan=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                            port=evpn_dict["leaf4"]["intf_list_tg"][0],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32312 FAIL: Remote mac not learnt in Leaf4")
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
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32312")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32312")

def test_FtOpSoRoEvpnRouterLvtepFt32316(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32316; TC SUMMARY:Traffic forwarding to ;\
                   silent hosts connected to MLAG leaf node on an MLAG leaf port;")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: MC LAG interface status check in LVTEP N2")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL step 3 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 3 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL step 4 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 4 - Verify IPv4 Prefix route in LVTEP node 1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagip_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL Step 5 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 5 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")

    st.log("Step 5: send uni-directional traffic from Leaf 4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_3281_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv4_3281"])

    st.log("########## Step 6: Verify LVTEP receives L3 unicast traffic ##########")
    traffic_details = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg_dict["tg"]],
            'exp_ratio': [1],
            'rx_ports': [tg_dict['d7_tg_port1']],
            'rx_obj': [tg_dict["tg"]],
        }
    }

    ###################################################################################
    hdrMsg("\n####### Step 7: Verify L3 ipv6 slient host traffic from SVTEP to LVTEP MLAG #########\n")
    ####################################################################################
    if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Step 7 Traffic verification passed from SVTEP to LVTEP MLAG")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: Step 7 Traffic verification failed from SVTEP to LVTEP MLAG")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ###################################################################################
    st.log("########## Step 8: verify LVTEP Orphon port NOT Rx L3 traffic ##########")
    ###################################################################################
    traffic_details1 = {
        '1': {
            'tx_ports': [tg_dict['d6_tg_port1']],
            'tx_obj': [tg_dict["tg"]],
            'exp_ratio': [0],
            'rx_ports': [tg_dict['d3_tg_port1']],
            'rx_obj': [tg_dict["tg"]],
        },
    }
    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Step 8: Traffic verification passed from SVTEP to LVTEP Orphon port")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: Step 8: Traffic verification failed from SVTEP to LVTEP Orphon por")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    hdrMsg("\n####### Step 9: Verify remote mac learning in SVTEP node ##############\n")
    if Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:77:14:05:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        st.log("PASS: Remote mac learnt in Leaf4 ")
    else:
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32316 FAIL: Remote mac not learnt in Leaf4")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv4_3281"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32316")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32316")

def test_FtOpSoRoEvpnRouterLvtepFt32317(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32317; TC SUMMARY:Traffic forwarding to ;\
                   silent hosts connected to MLAG leaf node on an orphon port;")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv6",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],type="B",selected=">",fib="*",
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL step 1 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 1 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv6",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],type="B",selected=">",fib="*",
                       ip_address=evpn_dict["leaf4"]["l3_tenant_ipv6_net"][0],distance="20",cost="0"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL step 2 - Verify IPv4 Prefix route in LVTEP node 1")
        success = False
    else:
        st.log("PASS step 2 - Verify IPv4 Prefix route in LVTEP node 1")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv6",type="C",
                                interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],selected=">",fib="*",
                                ip_address=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_net"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL Step 3 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")
        success = False
    else:
        st.log("Step 3 PASSED - Verify SAG tenant IPv4 prefix route in Leaf 4 towards LVTEP SAG")


    st.log("Step 4: Getting the router MAC for the L3 Traffic")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    tg = tg_dict['tg']
    tg.tg_arp_control(handle=stream_dict["v6host_32317"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["ipv6_32317"])

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
    if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",
                             tolerance_factor=2):
        st.log("PASS: Traffic verification passed from SVTEP to LVTEP orphon port")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL: Traffic verification failed from SVTEP to LVTEP orphon port")

    ###################################################################################
    st.log("########## Step 6: verify LVTEP MLAG Client NOT Rx L3 traffic ##########")
    ###################################################################################
    loss_prcnt = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv6_32317"],dest_tg_ph=tg_dict['d7_tg_ph1'])
    if loss_prcnt >= 0.95:
        st.log("PASS: Step 6 Traffic verification passed from SVTEP to LVTEP NOT Rx by MLAG client")
    else:
        success=False
        traffic_status = False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL: Step 6 Traffic from SVTEP to LVTEP NOT Rx by MLAG client")

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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32317 FAIL: Step 7 Remote mac not learnt in Leaf4")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["ipv6_32317"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32317")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32317")

def test_FtOpSoRoEvpnRouterLvtepFt32318(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32318; TC SUMMARY:Flapping ;\
                   of the keepalive link when the traffic is on")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                               traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: MC LAG interface status check in LVTEP N2")

    st.log("Step 5: Start L2 IPv6 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32337"])

    hdrMsg("\n####### Step 6: Verify L2 BUM traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: Step 7 Traffic from SVTEP to BUM and LOCAL LVTEP BUM ")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32318 FAIL: Traffic from SVTEP to LVTEP BUM and LOCAL LVTEP BUM after peer link down")
        debug_traffic(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Step 9: Bringup the peer link in LVTEP node 1 ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["leaf_node_list"][0],[evpn_dict["leaf1"]["iccpd_dintf_list"][0]])
    current_stream_dict["stream"] = stream_dict["l2_32337"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32318")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32318")

def test_FtOpSoRoEvpnRouterLvtepFt32343(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32343; TC SUMMARY:Verify L2 unicast traffic stream chooses only single link;\
                   out of mulitple link availble for tunnel and also verify the same link switchover")

    hdrMsg("Step 1: verify MC LAG status in LVTEP nodes")
    if mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: MC LAG domain status check in LVTEP N1")

    if mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                           mclag_intfs=1):
        st.log("PASS: MC LAG domain status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: MC LAG domain status check in LVTEP N2")

    hdrMsg("Step 2: verify MC LAG interface status in LVTEP node 1")
    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N1")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: MC LAG interface status check in LVTEP N1")

    if mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No'):
        st.log("PASS: MC LAG interface status check in LVTEP N2")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: MC LAG interface status check in LVTEP N2")

    '''
    st.log("Step 4: Send L2 unicast traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    create_stream("l2",port_han_list=[tg_dict['d7_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,
        src_mac_list=['00:10:16:01:01:01','00:10:16:06:01:01'],dst_mac_list=['00:10:16:06:01:02','00:10:16:01:01:02'],
        src_ip_list=['1001::100','1001::200'],dst_ip_list=['1001::201','1001::101'],
        src_ip_step_list=['00::2','00::2'],dst_ip_step_list=['00::2','00::2'],dst_ip_count_list=['2','2'],
        vlan_id_list=[evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
        src_mac_count_list=['2','2'],dst_mac_count_list=['1','1'])
    '''
    st.log("Step 5: Start L2 unicast traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    #start_traffic(stream_han_list=stream_dict["l2_32343"])
    start_traffic(stream_han_list=stream_dict["l2_32335"])

    hdrMsg("\n####### Step 6: Verify L2 unicast traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic test L2 unicast traffic b/w LVTEP to SVTEP with L3 SAG")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Traffic test L2 unicast traffic b/w LVTEP to SVTEP with L3 SAG")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 7: Verify local mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 7: Verify remote mac learning in SVTEP node ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:16:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    hdrMsg("\n####### Step 7: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:16:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32343 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

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
    hdrMsg("\n####### Step 8: Verify L2 unicast traffic from LVTEP to SVTEP ##############\n")
    if " KB/s" in leaf1_rx_kb[0]['rx_bps'] or " MB/s" in leaf1_rx_kb[0]['rx_bps']:
        st.log("D3 receives traffic from mclag client")
        intf_list = evpn_dict["leaf1"]["pch_intf_list"] + [vars.D3D1P4, vars.D3D2P4]
        num_path, interf = verify_bum_forwarder(vars.D3, intf_list)
        if int(num_path) == 1:
            st.log("PASS: L2 unicast traffic goes through only one path as expected")
            leaf1_bum_port = interf
            leaf1_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                                               interface=leaf1_bum_port, property="tx_bps", cli_type="click")

            if leaf1_tx >= int(float(leaf1_rx[0]['rx_bps'])) - 10:
                hdrMsg("PASS: L2 unicast traffic is passed as per local bias in D3 before flapping"
                       "Tx rate: {}, Rx rate: {}".format(leaf1_tx, int(float(leaf1_rx[0]['rx_bps']))))
            else:
                hdrMsg("FAIL: L2 unicast traffic is not passed as per local bias "
                       "in D3 before flapping, Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),
                                                                             str(leaf1_rx[0]['rx_bps'])))
                success = False

            port.shutdown(evpn_dict["leaf_node_list"][0], [leaf1_bum_port])
            st.wait(2)
            result = False
            for i in range(3):
                num_path, interf = verify_bum_forwarder(vars.D3, intf_list)
                if int(num_path) == 1:
                    result = True
                    break
                else:
                    st.wait(5,"wait for 5 seconds before retrying L2 unicast path check")
                    continue
            if result:
                st.log("PASS: L2 unicast traffic goes through only one path after shutting down the previous traffic carrying link")
                leaf1_bum_port1 = interf
                leaf1_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                                                   interface=leaf1_bum_port1, property="tx_bps", cli_type="click")
                if leaf1_tx >= int(float(leaf1_rx[0]['rx_bps'])) - 10:
                    hdrMsg("PASS: L2 unicast traffic is passed as per local bias in D3 after flap"
                           "Tx rate: {}, Rx Rate {}".format(leaf1_tx, int(float(leaf1_rx[0]['rx_bps']))))
                else:
                    hdrMsg("FAIL: L2 unicast traffic is not passed as per "
                           "local bias in D3 after flap, \
                                 Tx: {} and Rx: {}".format(str(leaf1_tx), str(leaf1_rx[0]['rx_bps'])))
                    success = False
            else:
                st.error("FAIL: L2 unicast traffic takes more than one path or nothing after flapping the previous traffic carrying link from D3")
                success = False
            port.noshutdown(evpn_dict["leaf_node_list"][0], [leaf1_bum_port])
        else:
            st.error("FAIL: L2 unicast traffic takes more than one path or nothing from D3")
            success = False

    if " KB/s" in leaf2_rx_kb[0]['rx_bps'] or " MB/s" in leaf2_rx_kb[0]['rx_bps']:
        st.log("D4 receives traffic from mclag client")
        intf_list = evpn_dict["leaf2"]["pch_intf_list"] + [vars.D4D1P4, vars.D4D2P4]
        num_path, interf = verify_bum_forwarder(vars.D4, intf_list)
        if int(num_path) == 1:
            st.log("PASS: L2 unicast traffic goes through only one path as expected")
            leaf2_bum_port = interf
            leaf2_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                                               interface=leaf2_bum_port, property="tx_bps", cli_type="click")
            if leaf2_tx >= int(float(leaf2_rx[0]['rx_bps'])) - 10:
                hdrMsg("PASS: L2 unicast traffic is passed as per local bias in D4 before flapping"
                       "Tx rate: {}, Rx rate: {}".format(leaf2_tx, int(float(leaf2_rx[0]['rx_bps']))))
            else:
                hdrMsg("FAIL: L2 unicast traffic is not passed as per local bias "
                       "in D4 before flapping, Tx rate: {} and Rx rate: {}".format(str(leaf2_tx),
                                                                                   str(leaf2_rx[0]['rx_bps'])))
                success = False

            port.shutdown(evpn_dict["leaf_node_list"][1], [leaf2_bum_port])
            st.wait(2)
            result = False
            for i in range(3):
                num_path, interf = verify_bum_forwarder(vars.D4, intf_list)
                if int(num_path) == 1:
                    result = True
                    break
                else:
                    st.wait(5,"wait for 5 seconds before retrying L2 unicast path check")
                    continue
            if result:
                st.log("PASS: L2 unicast traffic goes through only one path after flapping the previous traffic carrying link")
                leaf2_bum_port1 = interf
                leaf2_tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                                                   interface=leaf2_bum_port1, property="tx_bps", cli_type="click")
                if leaf2_tx >= int(float(leaf2_rx[0]['rx_bps'])) - 10:
                    hdrMsg("PASS: L2 unicast traffic is passed as per local bias in D4 after flapping"
                           "Tx rate: {}, Rx rate: {}".format(leaf2_tx, int(float(leaf2_rx[0]['rx_bps']))))
                else:
                    hdrMsg("FAIL: L2 unicast traffic is not passed as per "
                           "local bias in D4 after flapping, \
                                  Tx rate: {} and Rx rate: {}".format(str(leaf2_tx), str(leaf2_rx[0]['rx_bps'])))
                    success = False
            else:
                st.error("FAIL: L2 unicast traffic takes more than one path or nothing after flapping previous traffic carrying link from D4")
                success = False
            port.noshutdown(evpn_dict["leaf_node_list"][1], [leaf2_bum_port])
        else:
            st.error("FAIL: L2 unicast traffic takes more than one path or nothing from D4")
            success = False
    current_stream_dict["stream"] = stream_dict["l2_32335"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32343")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32343")

def test_FtOpSoRoEvpnRouterLvtepFt32331_2(Tgencleanup_fixture):
    global vars
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32331; TC SUMMARY:MAC Move detection in an MLAG cluster")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32332; TC SUMMARY:MAC Move detection between MLAG leaf node and a remote leaf node")

    tg = tg_dict['tg']
    st.log("### Step 1 start L2 traffic from first tgen port of Leaf3 and Leaf4 ###")
    tg.tg_traffic_control(action="run", stream_handle=[stream_dict["l2_32331_1"],stream_dict["l2_32331_2"]])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    st.log("### Step 2 verify evpn remote mac table in Leaf2 and Leaf4 ###")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("########## MACs from leaf3 not learned in leaf4, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("##### MACs from leaf3 learned successfully in leaf4, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("########## Step 3 MACs from leaf3 not learned in LVTEP N2, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("##### Step 3 MACs from leaf3 learned successfully in LVTEP N2, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("########## Step 4 MACs from leaf4 not learned in LVTEP N2, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("##### Step 4 MACs from leaf4 learned successfully in LVTEP N2, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("##### Step 5 MACs from leaf4 not learned in LVTEP N1, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("##### Step 5 MACs from leaf4 learned successfully in LVTEP N1, passed #####")

    ktx1 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["intf_list_tg"][0], "tx_bps")
    ktx2 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["intf_list_tg"][0], "tx_bps")
    st.log("### verify traffic received in first tgen port of Leaf3 and Leaf4 ###")
    if " KB/s" in ktx1[0]['tx_bps'] and " KB/s" in ktx2[0]['tx_bps']:
        st.log("##### Step 6 traffic verification passed before dynamic mac movement #####")
    elif int(float(ktx1[0]['tx_bps'].split(" ")[0])) > 1000 and int(float(ktx2[0]['tx_bps'].split(" ")[0])) > 1000:
        st.log("##### Step 6 traffic verification passed before dynamic mac movement #####")
    else:
        success=False
        hdrMsg("## Step 6 traffic test FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 before dynamic mac movement ##########")
        hdrMsg("##### Step 6 Leaf 3 and Leaf 4 counters are {} and {} #####".format(ktx2,ktx1))

    st.log("### Step 7 stop the traffic started in Leaf3 ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32331_1"])

    st.log("### Step 8 start Leaf3's same traffic from Leaf2 ###")
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32331_3"])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    st.log("### Step 9 verify evpn remote mac table after mac movement ###")
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],min_total_count="10",
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("########## LVTEP not advertising the moved MACs of leaf3 to leaf4, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("##### MACs moved from leaf3, now advertised by LVTEP to leaf4, passed #####")

    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D5, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("### Step 10 Mac {} not advertised by LVTEP to leaf3, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########"
                 .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        st.log("### Step 10 Mac {} advertised by LVTEP to leaf3, passed #####"
               .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))

    if retry_api(Evpn.verify_bgp_l2vpn_evpn_route_type_macip,vars.D6, evpn_type_2_prefix="[2]:[0]:[48]:["+
                                           evpn_dict["leaf3"]["tenant_mac_l2_colon"]+"]",
                                           status_code="*>", next_hop=evpn_dict["leaf2"]["loop_ip_list"][2],retry_count=3,delay=2):
        st.log("Step 11 nexthop for MAC {} updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                     evpn_dict["leaf2"]["loop_ip_list"][2]))
    else:
        success=False
        hdrMsg("Step 11 nexthop for MAC {} not updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                           evpn_dict["leaf2"]["loop_ip_list"][2]))
    '''
    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], total_count="1"):
        success = False
        hdrMsg("### Step 12 leaf3 still advertising the moved mac to leaf4, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("## Step 12 No MACs are advertised by leaf3 to leaf4 now as expected, passed #####")

    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], total_count="1"):
        success = False
        hdrMsg("## Step 13 leaf3 still advertising the moved mac to LVTEP N2, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("## Step 13 leaf3 not advertising the moved mac to leaf2 as expected, passed #####")

    if Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], total_count="1"):
        success = False
        hdrMsg("### Step 14 leaf3 still advertising the moved mac to LVTEP N2, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("### Step 14 leaf3 not advertising the moved mac to leaf2 as expected, passed #####")
    '''
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("### Step 15 leaf4 MACs are not learned in LVTEP N2, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("### Step 15 leaf4 MACs are learned in leaf2 as expected, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D3, vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1]):
        success = False
        hdrMsg("### Step 16 leaf4 MACs are not learned in VLTEP N1, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("### Step 16 leaf4 MACs are learned in leaf1 as expected, passed #####")

    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D5, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        hdrMsg("### Step 17 leaf4 MACs are not learned in leaf3, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("### Step 17 leaf4 MACs are learned successfully in leaf3, passed #####")
    '''
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D5, vni=evpn_dict["leaf3"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][2], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][2],
                                         retry_count=3, delay=2):
        success = False
        hdrMsg("### step 18 leaf2 not advertising moved MACs to leaf3, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########")
    else:
        st.log("### Step 18 leaf2 advertising moved MACs to leaf3 as expected, passed #####")
    '''
    if evpn_dict['cli_mode'] == "klish":
        ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["intf_list_tg"][0], "tx_bps")
        if " KB/s" in ktx[0]['tx_bps'] or " MB/s" in ktx[0]['tx_bps']:
            st.log("## some traffic still coming {}, taking more time to show exact rate after klish clear counter all SW issue ###".format(ktx))

    st.log("### Step 19 verify no traffic received in leaf3 ###")
    ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["intf_list_tg"][0], "tx_bps")
    if " KB/s" not in ktx[0]['tx_bps'] or " MB/s" not in ktx[0]['tx_bps']:
        st.log("##### NO traffic received in leaf3 as expected, passed #####")
    else:
        success=False
        hdrMsg("########## some traffic still coming to leaf3 which is"
                 " {} not expected, FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 ##########".format(ktx))


    hdrMsg("\n####### Step 20: Verify local mac learning in LVTEP nodes ##############\n")
    #if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],
    #                        vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
    #                        port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
    #    hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32331_2 FAIL: Local mac not learnt in LVTEP Node 1 ")
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
        hdrMsg("Step 21 test_FtOpSoRoEvpnRouterLvtepFt32331_2 FAIL: Local mac not learnt in LVTEP Nodes")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][1],evpn_dict["leaf_node_list"][3])

    ktx1 = Evpn.get_port_counters(evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["intf_list_tg"][0], "tx_bps")
    ktx2 = Evpn.get_port_counters(evpn_dict["mlag_client"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"][0], "tx_bps")
    rate = [' KB/s', ' MB/s']
    st.log("### verify traffic received by MLAG client and Leaf4 ###")
    if any(x in ktx1[0]['tx_bps'] for x in rate) and any(x in ktx2[0]['tx_bps'] for x in rate):
        st.log("### Step 22 traffic verification passed after dynamic mac movement #####")
    elif int(float(ktx1[0]['tx_bps'].split(" ")[0])) > 1000 and int(float(ktx2[0]['tx_bps'].split(" ")[0])) > 1000:
        st.log("### Step 22 traffic verification passed after dynamic mac movement #####")
    else:
        success=False
        hdrMsg("Step 22 traffic verification FAIL test_FtOpSoRoEvpnRouterLvtepFt32331_2 after dynamic mac movement,L4 & MLAG shows egress rate {} & {}:".format(ktx1,ktx2))
    start_traffic(action="stop", stream_han_list=[stream_dict["l2_32331_2"],stream_dict["l2_32331_3"]])
    Mac.clear_mac(vars.D5)

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnRouterLvtepFt32331_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnRouterLvtepFt32331_2")

def test_FtOpSoRoEvpnRouterLvtepFt32333(Tgencleanup_fixture):
    global vars
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32333; TC SUMMARY: MAC flapping b/w client to orphon port")
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32328; TC SUMMARY: Duplicate MAC detection should not be supported with in MLAG cluster nodes")

    tg = tg_dict['tg']
    st.log("### start L2 traffic from MLAG client port ###")
    start_traffic(stream_han_list=stream_dict["l2_32333_1"])
    mac_status = True
    hdrMsg("\n####### Step 1: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    st.log("### Stop the same traffic and start from LVTEP Node 2 orphon port ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32333_1"])

    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32333_2"])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    hdrMsg("\n####### Step 3: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    st.log("### Stop the same traffic from LVTEP N2 orphon and start from LVTEP Node 1 orphon port ###")
    tg.tg_traffic_control(action="stop", stream_handle=stream_dict["l2_32333_2"])
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D6,vars.D7]])
    st.wait(2)
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32333_3"])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    hdrMsg("\n####### Step 5: Verify local mac learning in LVTEP nodes ##############\n")
    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][1],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 2 ")

    if not Evpn.verify_mac(evpn_dict["leaf_node_list"][0],macaddress=evpn_dict["leaf1"]["tenant_mac_l2_colon"],
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Local mac not learnt in LVTEP Node 1")
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
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32333 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32333_3"]

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnRouterLvtepFt32333")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnRouterLvtepFt32333")

def test_FtOpSoRoEvpnRouterLvtepFt32314(Lvtep32314_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32314; TC SUMMARY: Traffic through SAG within the MLAG")

    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    if mclag_active_node_rmac == "00:00:01:02:03:04":
        hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32314")

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

    mac_status = True
    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:00:14:11:01:01",
                           vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],retry_count=3, delay=2,
                           port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32314 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success = False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][1],macaddress="00:00:14:11:01:01",
                           vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                           port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],retry_count=3, delay=2):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32314 FAIL: remote mac not learnt in LVTEP Node 2")
        success = False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in LVTEP Node 2 ")


    if not retry_api(Evpn.verify_mac,evpn_dict["leaf_node_list"][0],macaddress="00:00:14:06:01:01",
                           vlan=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],retry_count=3, delay=2,
                           port=evpn_dict["leaf1"]["intf_list_tg"][0]):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32314 FAIL: Local mac not learnt in LVTEP Node 1 ")
        success = False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in LVTEP Node 1 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
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

    st.log("\n #### Stop the traffic stream ####\n")
    start_traffic(action="stop", stream_han_list=stream_dict["ipv4_32314"])

    st.log("\n #### Remove static arp, arp,mac  ####\n")
    arp.delete_static_arp(evpn_dict["leaf_node_list"][0], ''
                                                          '30.1.1.100',
                          "Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.delete_static_arp(evpn_dict["leaf_node_list"][1], '30.1.1.100',
                          "Vlan{}".format(evpn_dict['leaf1']["tenant_l3_vlan_list"][0]))
    arp.delete_static_arp(evpn_dict["leaf_node_list"][0], '120.1.1.100',
                          "Vlan{}".format(evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]))
    Mac.delete_mac(evpn_dict["leaf_node_list"][0], '00:00:14:06:01:01', evpn_dict['leaf1']["tenant_l3_vlan_list"][0])
    Mac.delete_mac(evpn_dict["leaf_node_list"][1], '00:00:14:06:01:01', evpn_dict['leaf1']["tenant_l3_vlan_list"][0])
#    reset_tgen()
#    delete_host()

    ############################################################################################
    hdrMsg("\n Configure bidrectional L2 streams\n")
    ############################################################################################
    tg = tg_dict['tg']
    ############################################################################################
    hdrMsg("\n####### Start and Verify BiDirectional L2 traffic within MCLAG peers ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32314"])

    if verify_traffic(tx_port=vars.T1D3P1, rx_port=vars.T1D7P1):
        st.log("PASS: Traffic verification passed ")
    else:
        success = False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][0], evpn_dict["leaf_node_list"][1])
    current_stream_dict["stream"] = stream_dict["l2_32314"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32314")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32314")

def test_FtOpSoRoEvpnRouterLvtepFtCeta28533(request):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFtCeta28533; TC SUMMARY: Verify the fix for the CETA defect 28533")
    hdrMsg("step 1 Add L2 vlan {} to VNI mapping".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]]])

    hdrMsg("step 2 config l2 tenant vlan {} membershp for mc-lag iccpd link".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
                        evpn_dict['leaf1']['iccpd_pch_intf_list'][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][1],
                        evpn_dict['leaf2']['iccpd_pch_intf_list'][0],True]])

    hdrMsg("step 3 config L2 tenant vlan {} membershp for mc-lag client interface".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][1],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True]])

    hdrMsg("step 4 Configure IP address in LVTEP N1 and LVTEP N2 for vlan {}".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0], "10.1.1.150",'24'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][1], "11.1.1.150",'24'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1], "11.1.1.150",'24']])

    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][1], "11.1.1.15",'24'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0], "10.1.1.15",'24'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], "10.1.1.15",'24']])

    hdrMsg("step 5 delete port channel for MLAG client interface b/w leaf 2 and client switch")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][1]]])

    hdrMsg("step 6 Configure the vlan in MLAG client switch so that ping request will be triggered")
    Vlan.create_vlan(evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][1])

    hdrMsg("step 7 Configure ingress and egress vlan for ping packets in MLAG client switch and LVTEP N2")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["mlag_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["mlag_intf_list"][1],True]])

    hdrMsg("step 8 Configure secondary IP address in SVTEP and primary IP in MLAG client switch")
    dict1 = {"interface_name":evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],"ip_address":"10.1.1.151", \
             "subnet":"24","family":"ipv4","config":"add","skip_error":False,"is_secondary_ip":"yes"}
    dict2 = {"interface_name":evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1],"ip_address":"11.1.1.131", \
             "subnet":"24","family":"ipv4","config":"add","skip_error":False}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][3], evpn_dict["mlag_client"][0]], \
             ip.config_ip_addr_interface,[dict1,dict2])

    dict1 = {"interface_name":evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],"ip_address":"10.1.1.152", \
             "subnet":"24","family":"ipv4","config":"add","skip_error":False,"is_secondary_ip":"yes"}
    dict2 = {"interface_name":evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],"ip_address":"10.1.1.16", \
             "subnet":"24","family":"ipv4","config":"add","skip_error":False}
    parallel.exec_parallel(True, [evpn_dict["leaf_node_list"][3], evpn_dict["mlag_client"][0]], \
             ip.config_ip_addr_interface,[dict1,dict2])

    hdrMsg("step 9 Configure static route in MLAG client switch and IP address for Vlan 100")
    ip.create_static_route(evpn_dict["mlag_client"][0],static_ip="10.1.1.0/24", \
        interface=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1],family="ipv4")

    ip.config_ip_addr_interface(evpn_dict["leaf_node_list"][3],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], \
        "10.1.1.153","24","ipv4","add",False,is_secondary_ip="yes")

    hdrMsg("step 10 Finding the common router mac")
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    tg = tg_dict["tg"]

    hdrMsg("step 11 Configure TG end host devices")
    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph2'], mode='config', intf_ip_addr='11.1.1.100',
                             gateway="11.1.1.150", vlan='1', vlan_id_step='0',enable_ping_response="1",
                             vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], arp_send_req='1',
                             gateway_step='0.0.0.1', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:11:04:04:01',src_mac_addr_step="00.00.00.00.00.01")
    host12 = han["handle"]
    han_dict["12"] = host12
    st.log("Ipv4 host {} is created for Tgen port {}".format(host12, vars.T1D4P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='10.1.1.100',
                             gateway="10.1.1.150", vlan='1', vlan_id_step='0',enable_ping_response="1",
                             vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.1', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:11:06:04:01',src_mac_addr_step="00.00.00.00.00.01")
    host13 = han["handle"]
    han_dict["13"] = host13
    st.log("Ipv4 host {} is created for Tgen port {}".format(host13, vars.T1D6P1))

    hdrMsg("step 12 verify vxlan tunnel status")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][2],
            [evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 2],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 2]])

    hdrMsg("step 13 Send ARP request from each TG deviices")
    tg.tg_arp_control(handle=host12, arp_target='all')
    tg.tg_arp_control(handle=host13, arp_target='all')

    hdrMsg("step 14 Verify the ping in the direction from LVTEP to SVTEP")
    if not verify_ping(src_obj=tg, port_handle=tg_dict["d4_tg_ph2"], dev_handle=host12, dst_ip="11.1.1.15"):
        st.log("test_FtOpSoRoEvpnRouterLvtepFtCeta28533 Ping failed from D4 concected TG dev {} to dest ip 11.1.1.15".format(host12))
        success = False
    else:
        st.log("Ping passed from D4 concected TG dev {} to dest ip 11.1.1.15".format(host12))

    hdrMsg("step 15 Verify the ping initiated from TG ports in the direction from SVTEP to LVTEP")
    if not verify_ping(src_obj=tg, port_handle=tg_dict["d6_tg_ph1"], dev_handle=host13, dst_ip="10.1.1.15"):
        st.log("test_FtOpSoRoEvpnRouterLvtepFtCeta28533 Ping failed from D6 concected TG dev {} to dest ip 10.1.1.15".format(host13))
        success = False
    else:
        st.log("Ping passed from D6 concected TG dev {} to dest ip 10.1.1.15".format(host13))

    hdrMsg("step 16 Verify the ping from LVTEP to SVTEP IP")
    for dest_ip in ["10.1.1.150","10.1.1.151","10.1.1.152","10.1.1.153"]:
        if not ip.ping(vars.D7, dest_ip, family='ipv4', count=3):
            st.log("test_FtOpSoRoEvpnRouterLvtepFtCeta28533 Ping failed from LVTEP-2 to dest ip {}".format(dest_ip))
            success = False
        else:
            st.log("Ping passed from LVTEP 2 to dest ip {}".format(dest_ip))

    hdrMsg("Step 17 Remove IP address in MCLAG client switch and LVTEP N2 for vlan {}".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    ip.delete_static_route(evpn_dict["mlag_client"][0],next_hop="",static_ip="10.1.1.0/24", \
        interface=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1],family="ipv4")

    ip.delete_ip_interface(evpn_dict["mlag_client"][0],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1], \
        "11.1.1.131","24","ipv4",False)
    ip.delete_ip_interface(evpn_dict["mlag_client"][0],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], \
        "10.1.1.16","24","ipv4",False)

    if evpn_dict['cli_mode'] != "click":
        ip.delete_ip_interface(evpn_dict["leaf_node_list"][3],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], \
            "10.1.1.151","24","ipv4",False,is_secondary_ip="yes")
        ip.delete_ip_interface(evpn_dict["leaf_node_list"][3],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], \
            "10.1.1.152","24","ipv4",False,is_secondary_ip="yes")
        ip.delete_ip_interface(evpn_dict["leaf_node_list"][3],evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], \
            "10.1.1.153","24","ipv4",False,is_secondary_ip="yes")

    hdrMsg("step 18 Remove vlan membership for LVTEP N2 and MCLAG client node")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["mlag_intf_list"][0],True],
                         [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0],
                         evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["mlag_intf_list"][1],True]])

    hdrMsg("step 19 Delete vlan in MCLAG client node")
    Vlan.delete_vlan(evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][1])

    hdrMsg("step 20 adding mc lag client ports leaf 2 and also in MCLAG client switch")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.add_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][1]]])

    hdrMsg("step 21 delete primary ip in LVTEP Node 1, LVTEP N2 and SVTEP")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0], "10.1.1.150",'24'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][1], "11.1.1.150",'24'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][1], "11.1.1.150",'24']])

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][1], "11.1.1.15",'24'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0], "10.1.1.15",'24'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0], "10.1.1.15",'24']])

    hdrMsg("step 22 Remove L2 vlan {} to VNI mapping".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],"1","no"]])

    hdrMsg("step 23 remove l2 tenant vlan {} membershp for mc-lag iccpd link".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                         [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    hdrMsg("step 24 remove L2 tenant vlan {} membershp for mc-lag client interface".format(evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]))
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                         evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                         [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                         evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True]])

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFtCeta28533")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFtCeta28533")

def test_FtOpSoRoEvpnRouterLvtepFt32327(Tgencleanup_fixture):
    success = True
    hdrMsg("TC ID: test_FtOpSoRoEvpnRouterLvtepFt32327; TC SUMMARY: BUM traffic forwarder in an MLAG leaf node")

    st.log("Step 2: verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active',
                        mclag_intfs=1)

    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'], session_status='OK',
                            local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0], peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1], \
                            peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby',
                        mclag_intfs=1)

    st.log("Step 3: verify MC LAG interface status in LVTEP node 1")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("Step 4: verify MC LAG interface status in LVTEP node 2")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=tg_dict['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("Step 5: Send IPv6 L2 BUM traffic b/w LVTEP to SVTEP with L3 SAG tenant")
    start_traffic(stream_han_list=stream_dict["l2_32337"])

    hdrMsg("\n####### Step 6: Verify L2 BUM traffic verification #########\n")
    if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
        st.log("PASS: Traffic verification passed from SVTEP TO LVTEP & vice versa as expected")
    else:
        success=False
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Traffic verification failed b/w LVTEP To SVTEP")
        debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    mac_status = True
    hdrMsg("\n####### Step 9: Verify local mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Local mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            port=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Local mac not learnt in Leaf2")
        success=False
        mac_status=False
    else:
        st.log("PASS: Local mac learnt in Leaf2 ")

    hdrMsg("\n####### Step 10: Verify remote mac learning in SVTEP node ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][3],"00:10:76:01:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf1"]["loop_ip_list"][2],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Remote mac not learnt in Leaf4")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote mac learnt in Leaf4 ")

    hdrMsg("\n####### Step 11: Verify remote mac learning in LVTEP nodes ##############\n")
    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][0],"00:10:76:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Remote mac not learnt in Leaf1 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf1 ")

    if not Mac.verify_mac_address_table(evpn_dict["leaf_node_list"][1],"00:10:76:06:01:01",
                            vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                            dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1],type="Dynamic"):
        hdrMsg("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: Remote mac not learnt in Leaf2 ")
        success=False
        mac_status=False
    else:
        st.log("PASS: Remote Mac learnt in Leaf2 ")

    if not mac_status:
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

    leaf1_rx = [];leaf2_rx =[];leaf1_tx = 0;leaf2_tx = 0
    leaf1_rx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],property="rx_bps",cli_type="click")
    leaf2_rx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                            interface=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],property="rx_bps",cli_type="click")

    lvtep_bum_forwarder_port1 = "";lvtep_bum_forwarder_port2 = ""
    hdrMsg("\n####### Step 11: Verify BUM traffic from LVTEP to SVTEP before links are down  ##############\n")
    if int(float(leaf1_rx[0]['rx_bps'])) > 350:
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=interface1,property="tx_bps",cli_type="click")
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            leaf1_tx = leaf1_tx + int(float(tx[0]['tx_bps']))
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 1 BUM forwader port is : {}".format(interface1))
                lvtep_bum_forwarder_port1 = interface1
            else:
                st.log("INFO: interface to be brought down is : {}".format(interface1))
                port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])

        if lvtep_bum_forwarder_port1 != "":
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 1 before shut")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: BUM traffic is not passed as per local bias in LVTEP node 1 before shut, \
                          Leaf1 Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),str(leaf1_rx[0]['rx_bps'])))
            success=False

    elif int(float(leaf2_rx[0]['rx_bps'])) > 350:
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                            interface=interface1,property="tx_bps",cli_type="click")
            leaf2_tx = leaf2_tx + int(float(tx[0]['tx_bps']))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 2 BUM forwader port is : {}".format(interface1))
                lvtep_bum_forwarder_port1 = interface1
            else:
                st.log("INFO: interface to be brought down is : {}".format(interface1))
                port.shutdown(evpn_dict["leaf_node_list"][0],[interface1])

        if lvtep_bum_forwarder_port1 != "":
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 2 before shut")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: BUM traffic is not passed as per local bias in LVTEP node 2 before shut, \
                            Leaf2 Tx {} and Leaf2 Rx {}".format(str(leaf2_tx),str(leaf2_rx[0]['rx_bps'])))
            success=False

    hdrMsg("\n####### Step 12: Bringing up the shutdown uplinks towards Spine ##############\n")
    if int(float(leaf1_rx[0]['rx_bps'])) > 350:
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: interface carrying Tx traffic in Leaf1 after links shut : {}".format(interface1))
            else:
                st.log("INFO: interface to be brought up is : {}".format(interface1))
                port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    elif int(float(leaf2_rx[0]['rx_bps'])) > 350:
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: interface carrying Tx traffic in Leaf2 after links shut : {}".format(interface1))
            else:
                st.log("INFO: interface to be brought up is : {}".format(interface1))
                port.noshutdown(evpn_dict["leaf_node_list"][0],[interface1])

    hdrMsg("\n####### Step 13: Verify BUM traffic from LVTEP to SVTEP after links are up  ##############\n")
    if int(float(leaf1_rx[0]['rx_bps'])) > 350:
        for interface1 in evpn_dict["leaf1"]["intf_list_spine"]:
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][0],
                            interface=interface1,property="tx_bps",cli_type="click")
            leaf1_tx = leaf1_tx + int(float(tx[0]['tx_bps']))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][0], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 1 BUM forwader port is : {}".format(interface1))
                lvtep_bum_forwarder_port2 = interface1
            else:
                st.log("INFO: Leaf 1 interface not carrying traffic is : {}".format(interface1))

        if lvtep_bum_forwarder_port2 != "":
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 1 after up")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: BUM traffic is not passed as per local bias in LVTEP node 1 after up, \
                          Leaf1 Tx {} and Leaf1 Rx {}".format(str(leaf1_tx),str(leaf1_rx[0]['rx_bps'])))
            success=False

    elif int(float(leaf2_rx[0]['rx_bps'])) > 500:
        for interface1 in evpn_dict["leaf2"]["intf_list_spine"]:
            tx = get_interfaces_counters(evpn_dict["leaf_node_list"][1],
                            interface=interface1,property="tx_bps",cli_type="click")
            leaf2_tx = leaf2_tx + int(float(tx[0]['tx_bps']))
            ktx = Evpn.get_port_counters(evpn_dict["leaf_node_list"][1], interface1, "tx_bps")
            tx_val = ktx[0]['tx_bps'].split(" ")
            if verify_vxlan_traffic(ktx,tx_val,"encap"):
                st.log("INFO: Leaf 2 BUM forwader port is : {}".format(interface1))
                lvtep_bum_forwarder_port2 = interface1
            else:
                st.log("INFO: Leaf 2 interface not carrying traffic is : {}".format(interface1))

        if lvtep_bum_forwarder_port2 != "":
            st.log("PASS: BUM traffic is passed as per local bias in LVTEP node 2 after up")
        else:
            st.log("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: BUM traffic is not passed as per local bias in LVTEP node 2 after up, \
                            Leaf2 Tx {} and Leaf2 Rx {}".format(str(leaf2_tx),str(leaf2_rx[0]['rx_bps'])))
            success=False

    if lvtep_bum_forwarder_port1 == lvtep_bum_forwarder_port2:
        st.log("INFO: LVTEP BUM forwarder port is same across link flap ")
    else:
        st.log("test_FtOpSoRoEvpnRouterLvtepFt32327 FAIL: LVTEP BUM forwarder port before link shut is {} and, \
                after flap is {}".format(lvtep_bum_forwarder_port1,lvtep_bum_forwarder_port2))
        success=False
    current_stream_dict["stream"] = stream_dict["l2_32337"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnRouterLvtepFt32327")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnRouterLvtepFt32327")

def test_FtOpSoRoEvpnLvtepFt32431(suppress="enable",sanycast="enable"):
    tg = tg_dict['tg']
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    delete_host()
    reset_tgen()
    hdrMsg("\n####### Clear ARP in LVTEP and SVTEP ##############\n")
    arp.clear_arp_table(vars.D3)
    arp.clear_arp_table(vars.D4)
    arp.clear_arp_table(vars.D7)
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])
    utils.exec_all(True, [[Intf.clear_interface_counters,dut] for dut in [vars.D3,vars.D4,vars.D6,vars.D7]])
    ret_value = verify_arp_with_sag(suppress,sanycast)

    if ret_value:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnLvtepFt32431")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFt32431")

def test_FtOpSoRoEvpnLvtepFt32225(suppress="enable",sanycast="enable"):
    tg = tg_dict['tg']
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    delete_host()
    reset_tgen()
    hdrMsg("\n####### Clear ARP in LVTEP and SVTEP ##############\n")
    arp.clear_ndp_table(vars.D3)
    arp.clear_ndp_table(vars.D4)
    arp.clear_ndp_table(vars.D7)
    utils.exec_all(True, [[Mac.clear_mac, dut] for dut in [vars.D3,vars.D4,vars.D5,vars.D6,vars.D7]])
    utils.exec_all(True, [[Intf.clear_interface_counters,dut] for dut in [vars.D3,vars.D4,vars.D6,vars.D7]])
    ret_value = verify_nd_with_sag(suppress,sanycast)

    if ret_value:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpnLvtepFt32225")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFt32225")

def verify_arp_with_sag(suppress="disable",sanycast="enable"):
    success = True
    if suppress== "enable":
        hdrMsg("TC ID: verify_arp_with_sag; TC SUMMARY: Verify ARP host to host with SAG & neigh_suppress enabled across LVTEP & SVTEP")
    else:
        hdrMsg("TC ID: verify_arp_with_sag; TC SUMMARY: Verify ARP host to host with SAG enabled & neigh_suppress disabled across LVTEP & SVTEP")

    if sanycast== "disable":
        mclag_active_node_rmac = get_mclag_lvtep_common_mac()
        if mclag_active_node_rmac == "00:00:01:02:03:04":
            hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
            st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFt32431")

    tg = tg_dict['tg']
    stream = tg.tg_traffic_config(mac_src='00:02:77:00:01:03', mac_dst="00:02:66:00:00:03",
                              rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                              ip_src_addr='120.1.1.103', ip_dst_addr='120.1.1.62', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw='120.1.1.62',
                                  mac_src_count=1,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=1,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=1,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream1 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream1, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config', intf_ip_addr='120.1.1.102',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:02:77:00:00:03')
    host1 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:02:66:00:01:03', mac_dst="00:02:77:00:00:03",
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d7_tg_ph1'],
                              ip_src_addr='120.1.1.63', ip_dst_addr='120.1.1.102', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw='120.1.1.102',
                              mac_src_count=1,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=1,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=1,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream2 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='120.1.1.62',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:02:66:00:00:03')
    host2 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))
    stream_dict["ipv4_arp_sag"] = [stream1,stream2]
    stream_dict["v4host_arp_sag_1"] = host1
    stream_dict["v4host_arp_sag_2"] = host2

    if sanycast== "disable":
        st.log("Remove SAG ipv4 on all leaf nodes")
        dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"cli_mode":evpn_dict["cli_mode"],
                "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], "mask":"24","config":"remove"}
        parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_ip, [dict1,dict1,dict1,dict1])

    if suppress== "enable":
        hdrMsg("\n####### Step 1 Enable neighbor suppression for SAG enabled vlan 450 on all nodes ##############\n")
        utils.exec_all(True,[[Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][0],
                        evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                        [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][1],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                        [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][2],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                        [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][3],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False]])

    hdrMsg("\n####### Step 2 Trigger the local ARP ressolution in LVTEP for Host 1 with src ip 120.1.1.170 ##############\n")
    tg = tg_dict['tg']
    han1 = tg.tg_interface_config(port_handle=tg_dict["d7_tg_ph1"], mode='config',
                                intf_ip_addr='120.1.1.170', gateway='120.1.1.1', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=1, src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_l2"])

    tg.tg_arp_control(handle=han1["handle"], arp_target='all')

    hdrMsg("\n####### Step 2 Trigger the local ARP ressolution in SVTEP for Host 2 with src ip 120.1.1.60 ##############\n")
    han2 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                intf_ip_addr='120.1.1.60', gateway='120.1.1.1', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=1, src_mac_addr=evpn_dict["leaf4"]["tenant_mac_l2"])
    tg.tg_arp_control(handle=han2["handle"], arp_target='all')

    if suppress== "enable":
        hdrMsg("\n####### Step 3 Verify neighbor suppression status in Leaf nodes ##############\n")
        if evpn_dict['cli_mode'] == "click":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf1"]["vtepName"]+"-450"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf2"]["vtepName"]+"-450"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf4"]["vtepName"]+"-450"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress,[dict1,dict2,dict3])
            if result[0].count(False) > 0:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 3a")

            dict1 = {"vlan":evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],"identifier":"all",
                 "status":"Not Configured","netdevice":evpn_dict["leaf1"]["vtepName"]+"-100"}
            dict2 = {"vlan":evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],"identifier":"all",
                 "status":"Not Configured","netdevice":evpn_dict["leaf2"]["vtepName"]+"-100"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],Evpn.verify_neigh_suppress,[dict1,dict2])
            if result[0].count(False) > 0:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 3b")

        if evpn_dict['cli_mode'] == "klish":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress,[dict1,dict2,dict3])
            if result[0].count(False) > 0:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 3a")

            dict1 = {"vlan":evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],"identifier":"all",
                 "status":"off"}
            dict2 = {"vlan":evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],"identifier":"all",
                 "status":"off"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],Evpn.verify_neigh_suppress,[dict1,dict2])
            if result[0].count(False) > 0:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 3b")

    st.wait(2)
    hdrMsg("\n####### Step 4 Verify the local ARP in LVTEP nodes for Host 1 address ##############\n")
    result1 = arp.show_arp(evpn_dict["leaf_node_list"][0],ipaddress="120.1.1.170",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    if not verify_empty_arp_nd_table(result1):
        st.log("verify_arp_with_sag FAIL at step 5 - Verify local ARP 120.1.1.170 not lerant in LVTEP node 1")
        success = False
    else:
        mac1 = result1[0]['macaddress'];mac1 = mac1.replace(":",".")
        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf1"]["mlag_pch_intf_list"][0]
        if mac1 == evpn_dict["mlag_node"]["tenant_mac_l2"] and result1[0]['iface'] == port1:
            st.log("PASS at step 5 - Verify local ARP 120.1.1.170 lerant in LVTEP node 1")
        else:
            st.log("verify_arp_with_sag FAIL at step 5 - Verify local ARP 120.1.1.170 lerant in LVTEP node 1")
            success = False

    result2 = arp.show_arp(evpn_dict["leaf_node_list"][1],ipaddress="120.1.1.170",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])
    if not verify_empty_arp_nd_table(result2):
        st.log("verify_arp_with_sag FAIL at step 5 - Verify local ARP 120.1.1.170 not lerant in LVTEP node 1")
        success = False
    else:
        mac2 = result2[0]['macaddress'];mac2 = mac2.replace(":",".")
        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf1"]["mlag_pch_intf_list"][0]
        if mac2 == evpn_dict["mlag_node"]["tenant_mac_l2"] and result2[0]['iface'] == port1:
            st.log("PASS at step 6 - Verify local ARP 120.1.1.170 lerant in LVTEP node 2")
        else:
            st.log("verify_arp_with_sag FAIL at step 6 - Verify local ARP 120.1.1.170 lerant in LVTEP node 2")
            success = False

    hdrMsg("\n####### Step 4 Verify the local ARP in SVTEP node for Host 2 address ##############\n")
    result3 = arp.show_arp(evpn_dict["leaf_node_list"][3],ipaddress="120.1.1.60",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    if not verify_empty_arp_nd_table(result3):
        st.log("verify_arp_with_sag FAIL at step 7 - Verify local ARP 120.1.1.60 NOT lerant in SVTEP node 2")
        success = False
    else:
        mac3 = result3[0]['macaddress'];mac3 = mac3.replace(":",".")
        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf4"]["intf_list_tg"][0]
        if mac3 == evpn_dict["leaf4"]["tenant_mac_l2"] and result3[0]['iface'] == port1:
            st.log("PASS at step 7 - Verify local ARP 120.1.1.60 lerant in SVTEP node 2")
        else:
            st.log("verify_arp_with_sag FAIL at step 7 - Verify local ARP 120.1.1.60 lerant in SVTEP node 2")
            success = False

    hdrMsg("\n####### Step 9 Verify the Remote ARP entry in LVTEP and SVTEP node ##############\n")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],shell="",family="ipv4",distance="20",
                            cost="0",selected=">",fib="*",ip_address="120.1.1.60/32",
                            vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0]):
        hdrMsg("verify_arp_with_sag FAIL Step 9 - Verify Leaf 4 remote ARP route in LVTEP N1")
        success = False
    else:
        st.log("Step 9 PASSED - Verify Leaf 4 remote ARP route in LVTEP N1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],shell="",family="ipv4",distance="20",
                            cost="0",selected=">",fib="*",ip_address="120.1.1.60/32",
                            vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0]):
        hdrMsg("verify_arp_with_sag FAIL Step 10 - Verify Leaf 4 remote ARP route in LVTEP N2")
        success = False
    else:
        st.log("Step 10 PASSED - Verify Leaf 4 remote ARP route in LVTEP N2")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],shell="",family="ipv4",distance="20",
                            cost="0",selected=">",fib="*",ip_address="120.1.1.170/32",
                            vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0]):
        hdrMsg("verify_arp_with_sag FAIL Step 11 - Verify LVTEP ARP or remote ARP route in SVTEP N2")
        success = False
    else:
        st.log("Step 11 PASSED - Verify LVTEP ARP or remote ARP route in SVTEP N2")

    if success is False:
        debug_ip_neigh()

    hdrMsg("\n Step 13 Trigger the ARP ressolution in LVTEP connected Host 1_1 with src ip 120.1.1.101 and gw ip 120.1.1.60 \n")
    h1 = tg.tg_interface_config(port_handle=tg_dict["d7_tg_ph1"], mode='config',
                                intf_ip_addr='120.1.1.101', gateway='120.1.1.60', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=1, src_mac_addr="00.02.77.00.25.23")

    hdrMsg("\n####### Start packet capture at Host 2 connected to SVTEP ##############\n")

    if suppress== "disable":
        hdrMsg("\nstep 13 Verify ARP req from Host 1_1 to Host 2 with src 120.1.1.101 & gw 120.1.1.60 flooded over tunnel from LVTEP to SVTEP as suppress is disabled\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:25:23','0806'])
            if res1 is not True:
                st.log("Retrying the pkt capture for step 13 when suppress is OFF, iteration is {}".format(i))
                continue
            else:
                break
        if not res1:
            st.log("verify_arp_with_sag FAIL at step 13 - ARP request with src 120.1.1.101 & gw 120.1.1.60 flooded over tunnel from LVTEP to SVTEP")
            success = False
        else:
            st.log("PASS at step 13 - Verify ARP request with src 120.1.1.101 & gw 120.1.1.60 sent over tunnel from LVTEP to SVTEP")
    elif suppress== "enable":
        hdrMsg("\nstep 14 Verify Host 1_1 ARP req with src 120.1.1.101 & gw 120.1.1.60 is suppressed and not sent over tunnel from LVTEP to SVTEP \n")
        res1 = True
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:25:23','0806'])
            if res1 is True:
                st.log("Retrying the pkt capture for step 14 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if res1:
            st.log("verify_arp_with_sag FAIL at step 14 - Host 1_1 ARP request with src 120.1.1.101 & gw 120.1.1.60 is suppressed at LVTEP ")
            success = False
        else:
            st.log("PASS at step 14 - Host 1_1 ARP req with src 120.1.1.101 & gw 120.1.1.60 suppressed and not sent over tunnel from LVTEP to SVTEP")

    hdrMsg("\n####### Start packet capture at Host 1_1 connected to LVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n### step 15 Verify ARP Reply response from Host 2 with src ip 120.1.1.60 is Rx by Host 1_1 connected to LVTEP ###\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 1:
                st.wait(1,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:66:00:00:01','0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 15, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 15 - ARP Reply response from Host 2 with src ip 120.1.1.60 is Rx by Host 1 connected to LVTEP")
            success = False
        else:
            st.log("PASS at step 15 - ARP Reply response from Host 2 with src ip 120.1.1.60 is Rx by Host 1 connected to LVTEP")
    elif suppress== "enable" and sanycast == "enable":
        hdrMsg("\n####### step 16 Verify Proxy ARP Reply is sent by LVTEP for ARP reqest sent by Host 1_1 with src 120.1.1.101 ######\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:66:00:00:01','0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 16, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 16 - Proxy ARP Reply is sent by LVTEP to Host 1 for target address 120.1.1.60")
            success = False
        else:
            st.log("PASS at step 16 - Proxy ARP Reply is sent by LVTEP to Host 1 for target address 120.1.1.6")

    elif suppress== "enable" and sanycast == "disable":
        hdrMsg("\n####### step 16 Verify Proxy ARP Reply is sent by LVTEP for ARP reqest sent by Host 1_1 with src 120.1.1.101 ######\n")
        res1 = False
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=[mclag_active_node_rmac,'0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 16, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 16 - Proxy ARP Reply is sent by LVTEP to Host 1 for target address 120.1.1.60")
            success = False
        else:
            st.log("PASS at step 16 - Proxy ARP Reply is sent by LVTEP to Host 1 for target address 120.1.1.6")


    if success is False:
        debug_ip_neigh()

    hdrMsg("\n Step 17 Trigger the ARP ressolution from SVTEP connected Host 2_1 with src ip 120.1.1.61 and gw ip 120.1.1.170 \n")
    h2 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                intf_ip_addr='120.1.1.61', gateway='120.1.1.170', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=1, src_mac_addr="00.02.77.00.23.25")
    hdrMsg("\n####### Start packet capture at Host 1 connected to LVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n##### step 17 Verify ARP request from Host 2_1 with src ip 120.1.1.61 to H1 flooded over tunnel from SVTEP to LVTEP as suupress is disabled ######\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:23:25','0806'])
            if res1 is not True:
                st.log("Retrying the pkt capture for step 17, iteration is {}".format(i))
                continue
            else:
                break
        if not res1:
            st.log("verify_arp_with_sag FAIL step 17 ARP request from Host 2_1 with src ip 120.1.1.61 & gw 120.1.1.170 flooded over tunnel from SVTEP to LVTEP")
            success = False
        else:
            st.log("PASS at step 17 ARP request from Host 2_1 with src ip 120.1.1.61 & gw 120.1.1.170 flooded over tunnel from SVTEP to LVTEP")

    elif suppress== "enable":
        hdrMsg("\nstep 18 Verify ARP request from Host 2_1 with src ip 120.1.1.61 & gw 120.1.1.170 is suppressed at SVTEP but not sent over tunnel\n")
        res1 = True
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:23:25','0806'])
            if res1 is True:
                st.log("Retrying the pkt capture for step 18, iteration is {}".format(i))
                continue
            else:
                break
        if res1:
            st.log("verify_arp_with_sag FAIL step 18 ARP request from Host 2_1 with src ip 120.1.1.61 & gw 120.1.1.170 is suppressed at SVTEP")
            success = False
        else:
            st.log("PASS at step 18 ARP request from Host 2_1 with src ip 120.1.1.61 & gw 120.1.1.170 is suppressed at SVTEP")

    hdrMsg("\n####### Start packet capture at Host 2 connected to SVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n### step 19 Verify ARP Reply response from Host 1 is Rx by Host 2_1 connected to SVTEP ##\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:00:01','0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 19, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 19 - ARP Reply sent by Host 1 with src ip is 120.1.1.170 is Rx by Host 2_1 having src ip 120.1.1.61")
            success = False
        else:
            st.log("PASS at step 19 - ARP Reply sent by Host 1 with src ip is 120.1.1.170 is Rx by Host 2_1 having src ip 120.1.1.6")

    elif suppress== "enable" and sanycast == "enable":
        hdrMsg("\n####### step 20 Verify Proxy ARP Reply is sent by SVTEP to Host 2_1 connected to SVTEP ##############\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            if i == 3:
                st.wait(1,"waiting for arp packet to be captured")
            if i == 4:
                st.wait(2,"waiting for arp packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=['00:02:77:00:00:01','0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 20, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 20 Proxy ARP Reply for target address 120.1.1.170 is sent by SVTEP to Host 2_1")
            success = False
        else:
            st.log("PASS at step 20 - Proxy ARP Reply for target address 120.1.1.170 is sent by SVTEP to Host 2_1")

    elif suppress== "enable" and sanycast == "disable":
        hdrMsg("\n####### step 20 Verify Proxy ARP Reply is sent by SVTEP to Host 2_1 connected to SVTEP ##############\n")
        res1 = False
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            st.wait(1)
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,16],value_list=[mclag_active_node_rmac,'0806'])
            if res2 is not True:
                st.log("Retrying the pkt capture for step 20, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_arp_with_sag FAIL at step 20 Proxy ARP Reply for target address 120.1.1.170 is sent by SVTEP to Host 2_1")
            success = False
        else:
            st.log("PASS at step 20 - Proxy ARP Reply for target address 120.1.1.170 is sent by SVTEP to Host 2_1")

    if success is False:
        debug_ip_neigh()

    hdrMsg("\n####### step 21 Verify the ping from TG Host 1 connected to LVTEP to SAG IP 120.1.1.1  ####\n")
    res3=verify_ping(src_obj=tg, port_handle=tg_dict["d7_tg_ph1"], dev_handle=h1['handle'], dst_ip='120.1.1.1')
    if not res3:
        st.log("verify_arp_with_sag FAIL at step 21 - Verify ping from LVTEP connected TG to SAG IP in vlan 450")
        success = False
    else:
        st.log("PASS at step 21 - Verify ping from LVTEP connected TG to SAG IP in vlan 450")

    hdrMsg("\n####### step 22 Verify the ping from TG Host 2 connected to SVTEP to SAG IP 120.1.1.1 #####\n")
    res4=verify_ping(src_obj=tg, port_handle=tg_dict["d6_tg_ph1"], dev_handle=h2['handle'], dst_ip='120.1.1.1')
    if not res4:
        st.log("verify_arp_with_sag FAIL at step 22 - Verify ping from SVTEP connected TG to SAG IP in vlan 450")
        success = False
    else:
        st.log("PASS at step 22 - Verify ping from SVTEP connected TG to SAG IP in vlan 450")

    if suppress == "enable" and sanycast == "enable":
        hdrMsg(" \n####### step 23 Create bidirectional IPv4 traffic within Vlan 450 using SAG GW ##############\n")
        tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_arp_sag_1"], arp_target='all')
        tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_arp_sag_2"], arp_target='all')
        hdrMsg(" \n####### step 24 Start bidirectional IPv4 SAG traffic ##############\n")
        start_traffic(stream_han_list=stream_dict["ipv4_arp_sag"])
        st.wait(5,"Waiting for 5 sec before verifying traffic")

        hdrMsg("\n####### step 25 Verify IPv4 SAG traffic from LVTEP to SVTEP ##############\n")
        loss_prcnt1 = get_traffic_loss_inpercent(tg_dict['d7_tg_ph1'],stream_dict["ipv4_arp_sag"][0],dest_tg_ph=tg_dict['d6_tg_ph1'])
        if loss_prcnt1 < 0.15:
            st.log("PASS: Traffic verification passed from LVTEP TO SVTEP")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: Traffic verification failed from LVTEP To SVTEP, shows drop {}".format(loss_prcnt1))
            debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])

        loss_prcnt2 = get_traffic_loss_inpercent(tg_dict['d6_tg_ph1'],stream_dict["ipv4_arp_sag"][1],dest_tg_ph=tg_dict['d7_tg_ph1'])
        if loss_prcnt2 < 0.15:
            st.log("PASS: Traffic verification passed from SVTEP TO LVTEP")
        else:
            success=False
            hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: Traffic verification failed from SVTEP To LVTEP, shows drop {}".format(loss_prcnt2))

        hdrMsg(" \n####### step 26 Stop bidirectional IPv4 SAG traffic ##############\n")
        start_traffic(action="stop", stream_han_list=stream_dict["ipv4_arp_sag"])

    if suppress== "enable":
        hdrMsg("\n####### step 28 Disable neighbor suppression for SAG enabled vlan 450 on all nodes ##############\n")
        utils.exec_all(True,[[Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][0],
                    evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][1],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][2],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][3],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False]])

        hdrMsg("\n####### Step 29 Verify neighbor suppression status in Leaf nodes ##############\n")
        if evpn_dict['cli_mode'] == "click":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Not Configured","netdevice":evpn_dict["leaf1"]["vtepName"]+"-450"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Not Configured","netdevice":evpn_dict["leaf2"]["vtepName"]+"-450"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Not Configured","netdevice":evpn_dict["leaf4"]["vtepName"]+"-450"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress,[dict1,dict2,dict3])
            if result[0].count(False) > 0:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 29")

        if evpn_dict['cli_mode'] == "klish":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"off"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"off"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"off"}
            result = parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress,[dict1,dict2,dict3])
            if result[0].count(False) < 3:
                success=False
                hdrMsg("test_FtOpSoRoEvpnLvtepFt32431 FAIL: show neighbor suppression is not correct at step 29")

    if sanycast== "disable":
        st.log("Adding SAG ipv4 on all leaf nodes")
        dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"cli_mode":evpn_dict["cli_mode"],
                "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], "mask":"24","config":"add"}
        parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_ip, [dict1,dict1,dict1,dict1])

    return success


def verify_nd_with_sag(suppress="disable",sanycast="enable"):
    success = True
    if suppress== "enable":
        hdrMsg("TC ID: verify_nd_with_sag; TC SUMMARY: Verify ND host to host with SAG & neigh_suppress enabled across LVTEP & SVTEP")
    else:
        hdrMsg("TC ID: verify_nd_with_sag; TC SUMMARY: Verify ND host to host with SAG enabled & neigh_suppress disabled across LVTEP & SVTEP")

    if sanycast== "disable":
        mclag_active_node_rmac = get_mclag_lvtep_common_mac()
        if mclag_active_node_rmac == "00:00:01:02:03:04":
            hdrMsg("########## MC-LAG Common Router MAC is not UP so reporting TC fail ##########")
            st.report_fail("test_case_id_failed","test_FtOpSoRoEvpnLvtepFt32225")

    tg = tg_dict['tg']
    stream = tg.tg_traffic_config(mac_src='00:06:77:01:00:03', mac_dst="00:06:66:00:00:03",
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::103',ipv6_dst_addr='1201::62',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::62',
                                  mac_src_count=1,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=1, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=1,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream1 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream1, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',ipv6_intf_addr='1201::102',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                 src_mac_addr='00:06:77:00:00:03',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host1 = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:06:66:01:00:03', mac_dst="00:06:77:00:00:03",
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::63',ipv6_dst_addr='1201::102',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::102',
                                  mac_src_count=1,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=1, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=1,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream2 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='1201::62',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                 src_mac_addr='00:06:66:00:00:03',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host2 = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))
    stream_dict["ipv6_nd_sag"] = [stream1,stream2]
    stream_dict["v6host_nd_sag_1"] = host1
    stream_dict["v6host_nd_sag_2"] = host2

    if sanycast== "disable":
        st.log("Remove SAG ipv6 on all leaf nodes")
        dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"cli_mode":evpn_dict["cli_mode"],
                "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], "mask":"96","config":"remove"}
        parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_ip,[dict1,dict1,dict1,dict1])

    if suppress== "enable":
        hdrMsg("\n####### Step 1 Enable neighbor suppression for SAG enabled vlan 450 on all nodes ##############\n")
        utils.exec_all(True,[[Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][0],
                    evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][1],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][2],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][3],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'yes',False]])

    hdrMsg("\n####### Step 2 Send ND request from Host 1 with src ip 1201::100 connected to LVTEP ##############\n")
    tg = tg_dict['tg']
    han1 = tg.tg_interface_config(port_handle=tg_dict["d7_tg_ph1"], mode='config',
                                ipv6_intf_addr='1201::100', ipv6_gateway='1201::1', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', ipv6_gateway_step='::',
                                ipv6_intf_addr_step='::1', count=1,src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_v6"])

    tg.tg_arp_control(handle=han1["handle"], arp_target='all')

    hdrMsg("\n####### Step 3 Send ND request from Host 2 with src ip 1201::60 connected to SVTEP ##############\n")
    han2 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                ipv6_intf_addr='1201::60', ipv6_gateway='1201::1', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', ipv6_gateway_step='::',
                                ipv6_intf_addr_step='::1', count=1,src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v6"])

    tg.tg_arp_control(handle=han2["handle"], arp_target='all')

    if suppress== "enable":
        hdrMsg("\n####### Step 4 Verify neighbor suppression status in Leaf nodes ##############\n")
        if evpn_dict['cli_mode'] == "click":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf1"]["vtepName"]+"-450"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf2"]["vtepName"]+"-450"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"Configured","netdevice":evpn_dict["leaf4"]["vtepName"]+"-450"}
            parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress, [dict1,dict2,dict3])
        if evpn_dict['cli_mode'] == "klish":
            dict1 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            dict2 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            dict3 = {"vlan":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"identifier":"all",
                 "status":"on"}
            parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2]+[evpn_dict["leaf_node_list"][3]],Evpn.verify_neigh_suppress, [dict1,dict2,dict3])

    st.wait(2)
    hdrMsg("\n####### Step 5 Verify the local ND for Host 1 ip 1201::100 in LVTEP nodes ##############\n")
    result1 = arp.show_ndp(evpn_dict["leaf_node_list"][0],inet6_address="1201::100",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    if not verify_empty_arp_nd_table(result1):
        st.log("verify_nd_with_sag FAIL at Step 5 - Verify local ND 1201::100 not found in LVTEP node 1")
        success = False
    else:
        mac1 = result1[0]['macaddress'];mac1 = mac1.replace(":",".")

        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf1"]["mlag_pch_intf_list"][0]

        if mac1 == evpn_dict["mlag_node"]["tenant_mac_v6"] and result1[0]['interface'] == port1:
            st.log("PASS at Step 5 - Verify local ND 1201::100 lerant in LVTEP node 1")
        else:
            st.log("verify_nd_with_sag FAIL at Step 5 - Verify local ND 1201::100 in LVTEP node 1")
            success = False

    result2 = arp.show_ndp(evpn_dict["leaf_node_list"][1],inet6_address="1201::100",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])
    if not verify_empty_arp_nd_table(result2):
        st.log("verify_nd_with_sag FAIL at Step 5 - Verify local ND 1201::100 in not found LVTEP node 2")
        success = False
    else:
        mac2 = result2[0]['macaddress'];mac2 = mac2.replace(":",".")

        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf1"]["mlag_pch_intf_list"][0]

        if mac2 == evpn_dict["mlag_node"]["tenant_mac_v6"] and result2[0]['interface'] == port1:
            st.log("PASS at Step 5 - Verify local ND 1201::100 lerant in LVTEP node 2")
        else:
            st.log("verify_nd_with_sag FAIL at Step 5 - Verify local ND 1201::100 in LVTEP node 2")
            success = False

    hdrMsg("\n####### Step 6 Verify the local ND for Host 2 ip 102::60 in SVTEP node ##############\n")
    result3 = arp.show_ndp(evpn_dict["leaf_node_list"][3],inet6_address="1201::60",vrf=evpn_dict["leaf1"]["vrf_name_list"][0])

    if not verify_empty_arp_nd_table(result3):
        st.log("verify_nd_with_sag FAIL at Step 6 - Verify local ND 1201::60 not found in SVTEP node 2")
        success = False
    else:
        mac3 = result3[0]['macaddress'];mac3 = mac3.replace(":",".")

        if evpn_dict['cli_mode'] == "klish":
            port1 = evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0]
        elif evpn_dict['cli_mode'] == "click":
            port1 = evpn_dict["leaf4"]["intf_list_tg"][0]

        if mac3 == evpn_dict["leaf4"]["tenant_mac_v6"] and result3[0]['interface'] == port1:
            st.log("PASS at Step 6 - Verify local ND 1201::60 lerant in SVTEP node 2")
        else:
            st.log("verify_nd_with_sag FAIL at Step 6 - Verify local ND 1201::60 in SVTEP node 2")
            success = False

    hdrMsg("\n####### Step 7 Verify the Remote ND entry 1201::60 in LVTEP nodes ##############\n")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],shell="",family="ipv6",distance="20",
                   cost="0",selected=">",fib="*",ip_address="1201::60/128",
                   vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0]):
        hdrMsg("verify_nd_with_sag FAIL Step 7 - Verify Leaf 4 remote ND route in LVTEP N1")
        success = False
    else:
        st.log("Step 7 PASSED - Verify Leaf 4 remote ND route in LVTEP N1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][1],shell="",family="ipv6",distance="20",
                   cost="0",selected=">",fib="*",ip_address="1201::60/128",
                   vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0]):
        hdrMsg("verify_nd_with_sag FAIL Step 8 - Verify Leaf 4 remote ND route in LVTEP N2")
        success = False
    else:
        st.log("Step 8 PASSED - Verify Leaf 4 remote ND route in LVTEP N2")

    if success is False:
        debug_ip_neigh()

    hdrMsg("\n####### Step 10 Send ND request from Host 1_1 with src ip 1201::101 & gw 1201::60 connected to LVTEP ##############\n")
    h1 = tg.tg_interface_config(port_handle=tg_dict["d7_tg_ph1"], mode='config',
                                ipv6_intf_addr='1201::101', ipv6_gateway='1201::60', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', ipv6_gateway_step='::',
                                ipv6_intf_addr_step='::1', count=1, src_mac_addr="00.06.77.00.25.23")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],shell="",family="ipv6",distance="20",
                            cost="0",selected=">",fib="*",ip_address="1201::100/128",
                            vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0]):
        hdrMsg("verify_arp_with_sag FAIL Step 10 - Verify LVTEP ND or remote ND route in SVTEP N2")
        success = False
    else:
        st.log("Step 10 PASSED - Verify LVTEP ND or remote ND route in SVTEP N2")

    hdrMsg("\n####### Start packet capture at Host 2 connected to SVTEP ##############\n")

    if suppress== "disable":
        res1 = False
        hdrMsg("\n####### Step 11 Verify ND request sent by Host 1_1 to Host 2 sent over tunnel from LVTEP to SVTEP ######\n")
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for ND packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:25:23','87'])
            if res1 is not True:
                st.log("Retrying the pkt capture for Step 11, iteration is {}".format(i))
                continue
            else:
                break
        if not res1:
            st.log("verify_nd_with_sag FAIL at Step 11 ND request from Hst 1 with src 1201::101 & gw 1201::60 sent over tunnel from LVTEP to SVTEP")
            success = False
        else:
            st.log("PASS at Step 11 - ND request from Host 1 with src 1201::101 & gw 1201::60 sent over tunnel from LVTEP to SVTE")

    elif suppress== "enable":
        res1 = True
        hdrMsg("\n####### Step 11 Verify ND request from Host 1_1 to Host 2 is suppressed and not sent over tunnel from LVTEP to SVTEP #####\n")
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:25:23','87'])
            if res1 is True:
                st.log("Retrying the pkt capture for Step 11, iteration is {}".format(i))
                continue
            else:
                break
        if res1:
            st.log("verify_nd_with_sag FAIL at Step 11  ND request from Host 1 with src 1201::101 & gw 1201::60 is suppressed at LVTEP ")
            success = False
        else:
            st.log("PASS at Step 11 ND request from Host 1 with src 1201::100 & gw 1201::60 suppressed and not sent over tunnel from LVTEP to SVTEP")

    hdrMsg("\n####### Start packet capture at Host 1_1 connected to LVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n####### Step 12 Verify ND Reply from Host 2 with src ip 1201::60 is Rx by Host 1_1 connected to LVTEP ###\n")
        res2 = False;res3 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 4:
                st.wait(1,"waiting for ND packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:66:00:00:01','88'])
            res3 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[26,58],
                   value_list=['12:01:00:00:00:00:00:00:00:00:00:00:00:00:00:60','87'])
            if res2 is not True and res3 is not True:
                st.log("Retrying the pkt capture for Step 12 when suppress is OFF, iteration is {}".format(i))
                continue
            else:
                break
            st.log("THI IS THE {} ITERATION, res2 is {} res3 is {}".format(i,res2,res3))
        if not res2 and not res3:
            st.log("verify_nd_with_sag FAIL at Step 12 Verify ND Reply from Host 2 with src ip 1201::60 is Rx by Host 1_1 connected to LVTEP")
            success = False
        else:
            st.log("PASS at Step 12 - Verify ND Reply from Host 2 with src ip 1201::60 is Rx by Host 1_1 connected to LVTEP")
            st.log("res2 and res3 values are {} and {}".format(res2,res3))

    elif suppress== "enable" and sanycast == "enable":
        hdrMsg("\n####### Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1 with src ip 1201::101  ####\n")
        res2 = True;res3 = True
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            if i == 2:
                st.wait(1,"waiting for ND packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:66:00:00:01','88'])
            if res2 is not True:
                st.log("Retrying the pkt capture for Step 12 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_nd_with_sag FAIL at Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1")
            success = False
        else:
            st.log("PASS at Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1")
    elif suppress== "enable" and sanycast == "disable":
        hdrMsg("\n####### Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1 with src ip 1201::101  ####\n")
        res2 = True;res3 = True
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h1["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=[mclag_active_node_rmac,'88'])
            if res2 is not True:
                st.log("Retrying the pkt capture for Step 12 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_nd_with_sag FAIL at Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1")
            success = False
        else:
            st.log("PASS at Step 12 Verify Proxy ND Reply is sent by LVTEP for ND request sent by Host 1_1")

    if success is False:
        debug_ip_neigh()

    hdrMsg("\n####### Step 13 Send ND request from Host 2_1 with src ip 1201::61 & gw 1201::100 which belongs Host 1 connected to LVTEP ####\n")
    h2 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                ipv6_intf_addr='1201::61', ipv6_gateway='1201::100', vlan='1',
                                vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', ipv6_gateway_step='::',
                                ipv6_intf_addr_step='::1', count=1, src_mac_addr="00.06.77.00.23.25")
    hdrMsg("\n####### Start packet capture at Host 1_1 connected to LVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n#### Step 13 Verify ND request from Host 2_1 with src ip 1201::61 & GW 1201::100 sent over tunnel from SVTEP to LVTEP ####\n")
        res1 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:23:25','87'])
            if res1 is not True:
                st.log("Retrying the pkt capture for Step 13 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if not res1:
            st.log("verify_nd_with_sag FAIL Step 13 Verify Host 2_1 ND req with src ip 1201::61 & GW 1201::100 sent over tunnel from SVTEP to LVTEP")
            success = False
        else:
            st.log("PASS at Step 13  Verify Host 2_1 ND req with src ip 1201::61 & GW 1201::100 sent over tunnel from SVTEP to LVTEP")

    elif suppress== "enable":
        hdrMsg("\n##### Step 13 Verify Host 2_1 ND req with src ip 1201::61 & GW 1201::100 is suppressed and not sent over tunnel ####\n")
        res1 = True
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d7_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d7_tg_ph1"],format='var',output_type='hex')
            res1 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:23:25','87'])
            if res1 is True:
                st.log("Retrying the pkt capture for Step 13 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if res1:
            st.log("verify_nd_with_sag FAIL at Step 13 Host 2_1 ND req with src ip 1201::61 & GW 1201::100 is suppressed and not sent over tunnel")
            success = False
        else:
            st.log("PASS Step 13 Verify Host 2_1 ND req with src ip 1201::61 & GW 1201::100 is suppressed and not sent over tunnel")

    hdrMsg("\n####### Start packet capture at Host 2 connected to SVTEP ##############\n")
    if suppress== "disable":
        hdrMsg("\n####### Step 14 Verify ND Reply sent by Host 1 is Rx by Host 2_1 for target address 1201::100 #####\n")
        res2 = False;res3 = False
        for i in range(5):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:00:01','88'])
            res3 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[26,58],
                   value_list=['12:01:00:00:00:00:00:00:00:00:00:00:00:00:01:00','87'])
            if res2 is not True and res3 is not True:
                st.log("Retrying the pkt capture for Step 14 when suppress is OFF, iteration is {}".format(i))
                continue
            else:
                break
        if not res2 and not res3:
            st.log("verify_nd_with_sag FAIL at Step 14 ND Reply sent by Host 1 is Rx by Host 2_1 for target address 1201::10")
            success = False
        else:
            st.log("PASS Step 14 Verify ND Reply sent by Host 1 is Rx by Host 2_1 for target address 1201::10")
            st.log("res2 and res3 values are {} and {}".format(res2,res3))

    elif suppress== "enable" and sanycast == "enable":
        hdrMsg("\n####### Step 14 Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::100 ###\n")
        res2 = False
        for i in range(4):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            if i == 1:
                st.wait(1,"waiting for ND packet to be captured")
            if i == 2:
                st.wait(2,"waiting for ND packet to be captured")
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=['00:06:77:00:00:01','88'])
            if res2 is not True:
                st.log("Retrying the pkt capture for Step 14 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_nd_with_sag FAIL at Step 14 - Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::10")
            success = False
        else:
            st.log("PASS at Step 14 - Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::10")

    elif suppress== "enable" and sanycast == "disable":
        hdrMsg("\n####### Step 14 Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::100 ###\n")
        res2 = False
        for i in range(3):
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='start')
            tg.tg_arp_control(handle=h2["handle"], arp_target='all')
            tg.tg_packet_control(port_handle=tg_dict["d6_tg_ph1"],action='stop')
            pkts_captured = tg.tg_packet_stats(port_handle=tg_dict["d6_tg_ph1"],format='var',output_type='hex')
            res2 = validate_packet_capture(tg_type=tg.tg_type,pkt_dict=pkts_captured,offset_list=[6,58],value_list=[mclag_active_node_rmac,'88'])
            if res2 is not True:
                st.log("Retrying the pkt capture for Step 14 when suppress is ON, iteration is {}".format(i))
                continue
            else:
                break
        if not res2:
            st.log("verify_nd_with_sag FAIL at Step 14 - Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::10")
            success = False
        else:
            st.log("PASS at Step 14 - Verify Proxy ND Reply is sent by SVTEP towards Host 2_1 for target address 1201::10")

    if success is False:
        debug_ip_neigh()

    hdrMsg("\n####### Step 15 Verify the ping from TG Host 1 src ip 1201::100 to LVTEP to SAG IP 1201::1 ##############\n")
    res3=verify_ping(src_obj=tg, port_handle=tg_dict["d7_tg_ph1"], dev_handle=h1['handle'], dst_ip='1201::1',ping_count='6', exp_count='6')
    if not res3:
        st.log("verify_nd_with_sag FAIL at Step 15 - Verify ping from TG Host 1 src ip 1201::100 to LVTEP to SAG IP 1201::")
        success = False
    else:
        st.log("PASS at Step 15 - Verify ping from TG Host 1 src ip 1201::100 to LVTEP to SAG IP 1201::")

    hdrMsg("\n####### Step 16 Verify the ping from TG Host 2 src ip 1201::60 to SVTEP to SAG IP 1201::1 ##############\n")
    res4=verify_ping(src_obj=tg, port_handle=tg_dict["d6_tg_ph1"], dev_handle=h2['handle'], dst_ip='1201::1',ping_count='6', exp_count='6')
    if not res4:
        st.log("verify_nd_with_sag FAIL at Step 16 - Verify ping from TG Host 2 src ip 1201::60 to SVTEP to SAG IP 1201::1")
        success = False
    else:
        st.log("PASS at Step 16 - Verify ping from TG Host 2 src ip 1201::60 to SVTEP to SAG IP 1201::1")

    if suppress== "enable" and sanycast == "enable":
        st.log("Step 17 Create IPv6 SAG traffic b/w LVTEP to SVTEP within Vlan 450")
        tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_nd_sag_1"], arp_target='all')
        tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_nd_sag_2"], arp_target='all')

        hdrMsg(" \n####### Step 18 Start bidirectional IPv6 SAG traffic ##############\n")
        start_traffic(stream_han_list=stream_dict["ipv6_nd_sag"])
        st.wait(5,"Waiting for 5 sec before verifying traffic")

        hdrMsg("\n####### Step 19 Verify IPv6 traffic from LVTEP to SVTEP ##############\n")
        if verify_traffic(tx_port=vars.T1D7P1,rx_port=vars.T1D6P1):
            st.log("PASS: Traffic verification passed ")
        else:
            success=False
            st.error("FAIL: Traffic verification failed ")
            debug_traffic(evpn_dict["leaf_node_list"][0],evpn_dict["leaf_node_list"][3])
        hdrMsg(" \n####### Step 20 Stop bidirectional IPv6 SAG traffic ##############\n")
        start_traffic(action="stop", stream_han_list=stream_dict["ipv6_nd_sag"])

    if suppress== "enable":
        hdrMsg("\n####### Step 21 Disable neighbor suppression for SAG enabled vlan 450 on all nodes ##############\n")
        utils.exec_all(True,[[Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][0],
                    evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][1],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][2],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False],
                    [Evpn.neigh_suppress_config,evpn_dict["leaf_node_list"][3],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],'no',False]])

    if sanycast== "disable":
        st.log("Adding SAG ipv6 on all leaf nodes")
        dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"cli_mode":evpn_dict["cli_mode"],
                "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], "mask":"96","config":"add"}
        parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_ip, [dict1,dict1,dict1,dict1])

    return success

def verify_traffic_pass(tx,bps,mode):
    val = tx[0][bps].split(" ")
    if val[1] == 'KB/s' and float(val[0]) <= 500.0:
        st.log("{} interface check, traffic not passing through the interface as {} rate shows {}".format(mode,bps,tx[0][bps]))
        return False
    elif val[1] == 'KB/s' and float(val[0]) > 500.0:
        st.log("{} interface check, traffic passing through the interface as {} rate shows {}".format(mode,bps,tx[0][bps]))
        return True
    elif val[1] == 'MB/s':
        st.log("{} interface check, traffic passing through the interface as {} rate shows {}".format(mode,bps,tx[0][bps]))
        return True
    else:
        st.log("{} interface check, traffic not passing through the interface as {} rate shows {}".format(mode,bps,tx[0][bps]))
        return False

def verify_vxlan_traffic(ktx,tx_val,type):
    if type == "decap":
        rate1 = 950.0; rate2 = 900.0
        rate =  rate2 if evpn_dict['cli_mode'] == "click" else rate1
        if " MB/s" in ktx[0]['tx_bps']:
            return True
        elif " KB/s" in ktx[0]['tx_bps'] and float(tx_val[0]) > rate:
            return True
        else:
            return False
    elif type == "encap":
        rate1 = 1000.0; rate2 = 950.0
        rate =  rate2 if evpn_dict['cli_mode'] == "click" else rate1
        if " MB/s" in ktx[0]['tx_bps']:
            return True
        elif " KB/s" in ktx[0]['tx_bps'] and float(tx_val[0]) > rate:
            return True
        else:
            return False

'''
@pytest.fixture(scope="function")
def Ft3271_fixture(request, evpn_underlay_hooks):
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

    yield

    hdrMsg("### CLEANUP for 3271 ###")
    start_traffic(action='stop')

    st.log("Reset TGEN")
    delete_host()
    reset_tgen()

    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni in D3,D4 and D6 #######/n")
    ############################################################################################
    utils.exec_all(True, [
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vtepName"], "2", "2", '98', 'no'],
        [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"], "2", "2", '98', 'no'],
        [Evpn.map_vlan_vni, evpn_d
        ict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], "2", "2", '98', 'no']])
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


def test_FtOpSoRoEvpnRouterLvtepFt3271(Ft3271_fixture):
    success = True
    tg = tg_dict['tg']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    create_stream("ipv4", dst_mac_list=[evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], dut6_gateway_mac])

    tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"], mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],
                         rate_pps=1000, mode='create', port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='620', vlan_id_count='3400', vlan_id_mode="increment", vlan_id_step='1',
                         transmit_mode='continuous', mac_src_count="1", mac_dst_count="1",
                         high_speed_result_analysis=1,mac_src_mode="increment", mac_dst_mode="increment",
                         enable_stream_only_gen=0,enable_stream=0,mac_src_step="00.00.00.00.00.01",
                         mac_dst_step="00.00.00.00.00.01")
    tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"],
                         rate_pps=1000, mode='create', port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                         vlan="enable", vlan_id='620', vlan_id_count='3400', vlan_id_mode="increment", vlan_id_step='1',
                         transmit_mode='continuous', mac_src_count="1", mac_dst_count="1",
                         high_speed_result_analysis=1,mac_src_mode="increment", mac_dst_mode="increment",
                         enable_stream_only_gen=0, enable_stream=0,mac_src_step="00.00.00.00.00.01",
                         mac_dst_step="00.00.00.00.00.01")

    hdrMsg(" \n####### starting traffic from vlans 620 to 4020 ##############\n")
    st.wait(300,"need to wait for some time for all 4K Vxlan net devices to be online")
    start_traffic()
    st.wait(60,"need to wait for some time for traffic to flow for all vlans")

    if retry_api(verify_mac_count, vars.D6, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D6 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D6 ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D3 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D3 ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D4 ##########")

    if verify_traffic():
        st.log("########## traffic verification passed after configuring 4K vlans ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after configuring 4K vlans ##########")

    hdrMsg(" \n####### verify traffic after clearing EVPN neighbor ##############\n")
    Evpn.clear_bgp_evpn(vars.D6, "*")
    Evpn.clear_bgp_evpn(vars.D3, "*")
    if retry_api(verify_mac_count, vars.D6, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D6 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D6 after clearing EVPN ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D3 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D3 after clearing EVPN ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D4 after clearing EVPN ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D4 after clearing EVPN ##########")

    if verify_traffic():
        st.log("########## traffic verification passed after clearing EVPN neighbor ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing EVPN neighbor ##########")

    hdrMsg(" \n####### verify traffic after clearing BGP neighbor ##############\n")
    bgp.clear_ip_bgp_vtysh(vars.D6)
    bgp.clear_ip_bgp_vtysh(vars.D4)
    if retry_api(verify_mac_count, vars.D6, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D6 after clearing BGP ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D6 after clearing BGP ##########")

    if retry_api(verify_mac_count, vars.D3, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D3 after clearing BGP ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D3 after clearing BGP ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D4 ##########")

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP neighbor ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing BGP neighbor ##########")

    hdrMsg(" \n####### verify traffic after clearing BGP EVPN table ##############\n")
    Evpn.clear_bgp_evpn(vars.D6, "*", soft_dir="in")
    Evpn.clear_bgp_evpn(vars.D4, "*", soft_dir="in")
    st.wait(10)

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP table ##########")
    else:
        success = False
        st.error("########## FAIL: traffic verification failed after clearing BGP table ##########")

    hdrMsg(" \n####### shutting down links between leaf1 and spine ##############\n")
    port.shutdown(vars.D6, evpn_dict["leaf4"]["intf_list_spine"][0:4])
    port.shutdown(vars.D3, evpn_dict["leaf1"]["intf_list_spine"][0:4])
    st.wait(5)
    if verify_traffic():
        st.log("########## traffic verification passed after shutting down links b/w leaf1 and spine ##########")
    else:
        success = False
        st.error("########## FAIL:traffic verification failed after shutting down links b/w leaf1 and spine ##########")

    hdrMsg(" \n####### Enable back links between leaf1 and spine ##############\n")
    port.noshutdown(vars.D6, evpn_dict["leaf4"]["intf_list_spine"][0:4])
    port.noshutdown(vars.D3, evpn_dict["leaf1"]["intf_list_spine"][0:4])
    st.wait(5)
    if verify_traffic():
        st.log("########## traffic verification passed after enabling back links b/w leaf1 and spine ##########")
    else:
        success = False
        st.error("########## FAIL:traffic verification failed after enabling back links b/w leaf1 and spine ##########")

    hdrMsg(" \n####### clear mac in D4 and D6 ##############\n")
    Mac.clear_mac(vars.D6)
    Mac.clear_mac(vars.D4)
    st.wait(300,"waiting for ARP refresh timer to hit")

    if retry_api(verify_mac_count, vars.D6, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed after clearing MAC in D6 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed after clearing MAC in D6 ##########")

    if retry_api(verify_mac_count, vars.D4, mac_count=6800,retry_count=4, delay=40):
        st.log("########## MAC count verification passed after clearing MAC in D4 ##########")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed after clearing MAC in D4 ##########")

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

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpnRouterLvtepFt3271")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpnRouterLvtepFt3271")
'''
