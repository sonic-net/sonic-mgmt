import pytest
import apis.routing.evpn as Evpn
import apis.routing.bgp as Bgp
from spytest import st, utils
from utilities import parallel
from apis.system import basic
import apis.switching.vlan as Vlan
import apis.switching.mac as Mac
from spytest.utils import filter_and_select
import utilities.utils as utils_obj
import apis.routing.ip as ip_obj
import apis.system.reboot as reboot_api
import apis.routing.arp as arp
import apis.system.port as port

from evpn import *
from evpn_underlay_base_cfg import *

@pytest.fixture(scope="module", autouse=True)
def evpn_underlay_hooks(request):
    global vars
    create_glob_vars()
    make_global_vars()
    vars = st.get_testbed_vars()
    globals().update(data)
    api_list = [[create_stream],[create_evpn_5549_config]]
    parallel.exec_all(True, api_list, True)

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

    st.log("verify vxlan tunnel status")
    result=utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][1], [evpn_dict["leaf2"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 3]])

    if result[0].count(False) > 0:
        st.error("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")
    yield
    cleanup_l2vni()
    cleanup_l3vni()
    cleanup_vxlan()
    cleanup_evpn_5549()
    reboot_api.config_save(evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"], "vtysh")

@pytest.mark.cli
def test_FtOpSoRoEvpn5549Cli311(request):
    success = True
    st.log("###Verify CLICK based VxLAN show commands###")

    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][2],
                                vni=evpn_dict["leaf1"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf1"]["vrf_name_list"][0],total_count="1"):
        success = False

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="3",identifier="all",rvtep=evpn_dict["leaf1"]["loop_ip_list"][1]):
        success = False

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][2],
                                vni=[evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf1"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf1"]["l3_vni_name_list"][0]],total_count="2"):
        success = False

    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][3],
                                vni=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf3"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf3"]["l3_vni_name_list"][0]],total_count="2"):
        success = False

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        success = False

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf1"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf1"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        success = False

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Cli311")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Cli311")

@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft3211():
    success = True
    st.log("###Verify EVPN neighborship by removing and adding back a neighbor###")
    st.log("###Step 1 : Remove a neighbor {} from leaf1###".format(data.spine1_ipv6_list[0]))
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], neighbor=data.spine1_ipv6_list[0],
            remote_as=evpn_dict['spine1']['local_as'],
            config_type_list=["activate"], config="no", local_as=evpn_dict['leaf1']['local_as'])

    st.log("###Step 2: Verify EVPN neighbor {} not present in leaf1###".format(data.spine1_ipv6_list[0]))
    if Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][0],
                                       neighbor=[data.spine1_ipv6_list[0]]):
        st.error("EVPN neighbor {} is present which is NOT expected".format(data.spine1_ipv6_list[0]))
        success=False
    else:
        st.log("EVPN neighbor {} not present as expected".format(data.spine1_ipv6_list[0]))

    st.log("###Step 3: Add back the removed neighbor {} in leaf1###".format(data.spine1_ipv6_list[0]))
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], neighbor=data.spine1_ipv6_list[0],
            remote_as=evpn_dict['spine1']['local_as'],
            config_type_list=["activate"], config="yes", local_as=evpn_dict['leaf1']['local_as'])

    st.wait(5)
    st.log("###Step 4: Verify EVPN neighbor {} is present in leaf1###".format(data.spine1_ipv6_list[0]))
    if not Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][0],
                neighbor=[data.spine1_ipv6_list[0]],updown=["up"]):
        st.error("EVPN neighbor {} is NOT present in leaf1".format(data.spine1_ipv6_list[0]))
        success=False
    else:
        st.log("EVPN neighbor {} is up as expected".format(data.spine1_ipv6_list[0]))

    if success:
        st.report_pass("test_case_id_passed","test_evpn_nbr_removal")
    else:
        st.report_fail("test_case_id_failed","test_evpn_nbr_removal")


@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft3212(Ft32214_fixture):
    success = True
    st.log("### Verify VxLAN by removing the loopback interface bound to overlay gateway ###")
    start_traffic(stream_dict["l2"])

    st.log("### remove loopback interface {} from leaf3### ".format("Loopback1"))
    if evpn_dict['cli_mode'] == "klish":
        ip.delete_ip_interface(evpn_dict["leaf_node_list"][2],"Loopback1", evpn_dict["leaf3"]["loop_ip_list"][1], '32')
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][2],loopback_name="Loopback1",config="no")

    st.log("### verify VXLAN tunnel status in leaf4 ###")
    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                 src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]], exp_status_list=['oper_down'],
                 retry_count=3, delay=5):
        st.log("##### VXLAN tunnel towards leaf3 is DOWN in leaf4 as expected #####")
    else:
        success = False
        st.error("########## VXLAN tunnel towards leaf3 is NOT DOWN in leaf4 ##########")

    st.wait(5)
    if verify_traffic(tx_port=tg_dict["d5_tg_port1"], rx_port=tg_dict["d6_tg_port1"], tx_ratio=1, rx_ratio=0):
        st.log("##### traffic verification passed when loopback interface removed #####")
    else:
        success=False
        st.error("########## traffic verification failed when loopback interface removed ##########")

    st.log("### add back the removed loopback interface {} in leaf3 ###".format("Loopback1"))
    if evpn_dict['cli_mode'] == "click":
        ip.configure_loopback(dut=evpn_dict["leaf_node_list"][2], loopback_name="Loopback1")
    if st.get_ui_type() in ["rest-put","rest-patch"]:
        ip.configure_loopback(dut=evpn_dict["leaf_node_list"][2], loopback_name="Loopback1")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2], interface_name="Loopback1",
                                ip_address=evpn_dict["leaf3"]["loop_ip_list"][1], subnet='32')
    st.wait(2)
    st.log("### verify VxLAN tunnel status in leaf4 ###")
    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]], exp_status_list=['oper_up'] * 3,
                     retry_count=3, delay=5):
        st.log("##### VxLAN tunnel towards leaf3 UP now in leaf4 #####")
    else:
        success=False
        st.error("########## VxLAN tunnel towards leaf3 NOT UP in leaf4 ##########")

    for i in range(4):
        result = verify_traffic()
        if result is False:
            continue
        else:
            st.log("##### traffic verification passed after adding loopback interface #####")
            break
    current_stream_dict["stream"] = stream_dict["l2"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3212")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3212")

def test_FtOpSoRoEvpn5549Ft3242():
    success = True

    st.log("### Verify redistribute IPv4 prefix routes via EVPN ###")

    st.log("### Step 1: Verify L3 VNI IPv4 prefix route in Leaf 3 towards Leaf 1 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf1"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 1 - Verify L3 VNI IPv4 prefix route in Leaf 3 towards Leaf 1")
        success = False
    else:
        st.log(" Test Case Step 1 PASSED - Verify L3 VNI IPv4 prefix route in Leaf 3 towards Leaf 1")

    st.log("### Step 2: Verify Leaf 1 tenant IPv4 prefix route in Leaf 3 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf1"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 2 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")


    st.log("### Step 3: Verify L3 VNI IPv4 prefix route in Leaf 1 towards Leaf 4 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],
                                vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 3 - Verify L3 VNI IPv4 prefix route in Leaf 1 towards Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Verify L3 VNI IPv4 prefix route in Leaf 1 towards Leaf 4")
    '''
    st.log("### Step 4: Verify VxLAN EVPN MAC for L3 VNI VLAN in Leaf4 ###")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=evpn_dict["leaf_node_list"][3],
                                vni=evpn_dict["leaf3"]["l3_vni_list"][0],
                                vlan=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                total_count="3",identifier="all",
                                mac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]],
                                rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error(" Test Case failed at step 4 - Verify VxLAN EVPN MAC for L3 VNI VLAN in Leaf4")
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify L3 VNI IPv4 prefix route in Leaf 1 towards Leaf 4")
    '''

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3242")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3242")

def test_FtOpSoRoEvpn5549Ft3243():
    success = True
    st.log("### Verify redistribute IPv6 prefix routes via EVPN ###")

    st.log("### Step 1: Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][2],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 1 - Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 1 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4")

    st.log("### Step 2: Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 2 - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")

    st.log("### Step 3: Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 2 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][0],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf2"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf2"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 3 - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 2")
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 1 towards Leaf 2")

    st.log("### Step 4: Verify L3 VNI IPv6 prefix route in Leaf 2 towards Leaf 1 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][1],family='ipv6',shell='vtysh',
                               vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                               interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                               nexthop="::ffff:"+evpn_dict["leaf1"]["loop_ip_list"][1],
                               ip_address=evpn_dict["leaf1"]["l3_vni_ipv6_net"][0],
                               distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 4 - Verify L3 VNI IPv6 prefix route in Leaf 2 towards Leaf ")
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 2 towards Leaf ")

    st.log("### Step 5: Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 5 - Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4")


    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3243")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3243")

def test_FtOpSoRoEvpn5549Ft3241():
    success = True
    st.log("### Verify redistribute of connected and static routes via EVPN ###")

    st.log("### Step 1: Configure static ipv4 and ipv6 route under vrf Vrf1 ###")
    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv4_static_route"],"vtysh","ipv4",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv6_static_route"],"vtysh","ipv6",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    st.log("### Step 2: Configure redist static under ipv4 and ipv6 AF in vrf Vrf1 ###")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict['leaf3']['local_as'],
                                config = 'yes',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict['leaf3']['local_as'],
                                config = 'yes',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family="ipv6")


    st.log("### Step 3: Verify Leaf 1 tenant IPv4 prefix route in Leaf 3 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["ipv4_static_route"],distance="20",
                                cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 3 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")


    st.log("### Step 4: Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["ipv6_static_route"],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 4 - Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 3 towards Leaf 4")


    st.log("### Step 5: Remove redist static under ipv4 and ipv6 AF in vrf Vrf1 ###")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                                config = 'no',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                                config = 'no',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family="ipv6")


    st.log("### Step 6: Remove static ipv4 and ipv6 route under vrf Vrf1 ###")
    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv4_static_route"],"ipv4","vtysh",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv6_static_route"],"ipv6","vtysh",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3241")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3241")

def test_FtOpSoRoEvpn5549Ft3222_5():
    tc_list = ["test_FtOpSoRoEvpn5549Ft3222","test_FtOpSoRoEvpn5549Ft3223","test_FtOpSoRoEvpn5549Ft3224",
                         "test_FtOpSoRoEvpn5549Ft3225","test_FtOpSoRoEvpn5549Ft3226"]
    tc_list_summary = ["Test VxLAN by removing and adding back RD","Test VxLAN by modifying RD",
                         "Test VxLAN by removing and adding back import RT",
                         "Test VxLAN by configuring wrong import RT",
                         "Test VxLAN by removing and adding back export RT"]
    success = True

    st.log("Step 1: Change the L2 RD to manual entry and verify same is reflected in the show bgp evpn routes on the neighbor")

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vni"],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0],vni_rd="23:23",
                         config="yes", local_as=evpn_dict["leaf3"]['local_as'])
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3], rd='23:23'):
        st.log("Evpn routes with rd 23:23 is not being received from {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {}, result: Failed".format(tc_list[0],tc_list_summary[0]))
        success = False
    else:
        st.log("Test Case Step 1 PASSED - Change the L2 RD to manual entry and verify the new RD")

    st.log("Step 2: Remove the manual entry and verify the auto RD is received.")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vni"],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0], vni_rd="23:23",
                         config="no", local_as=evpn_dict["leaf3"]['local_as'])
    param_dict = {'rd': '23:23'}
    if utils_obj.retry_parallel(Evpn.verify_bgp_l2vpn_evpn_route, dut_list=[evpn_dict["leaf_node_list"][3]],
                                dict_list=[param_dict], api_result=False, retry_count=3, delay=2):
        st.log("Evpn routes with rd 23:23 is still present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {}, result: Failed".format(tc_list[1], tc_list_summary[1]))
        success = False
    else:
        st.log("Test Case Step 2 PASSED - Remove the manual L2 RD and verify the auto RD")

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vni"],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0], vni_unconfig="yes",
                         config="no", local_as=evpn_dict["leaf3"]['local_as'])

    st.log("Step 3: Change the L2 RT to 23:23 and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vni"],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0], vni_both_rt="23:23",
                         config="yes", local_as=evpn_dict["leaf3"]['local_as'])

    if not Evpn.verify_bgp_l2vpn_evpn_vni_id(dut=evpn_dict["leaf_node_list"][2], rt=['23:23', '23:23'],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0]):
        st.log("Evpn routes with L2 RT 23:23 is not present after adding it manually on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Change L2 RT to 23:23 & verify through evpn routes")

    st.log("Step 4: Verify VxLAN tunnel status in leaf4 to leaf 3 is Up since L2 RT mis-match but L3 RT is matched")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                                           src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 1):
        st.log("VxLAN tunnel is UP in leaf4 when L2 RT mis-match but L3 RT is matched")
        st.error("Testcase: {}, Summary: {} , result:Failed".format(tc_list[3], tc_list_summary[3]))
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify VxLAN tunnel status when L2 RT mis-match but L3 RT is matched")

    st.log("Step 4: Change the L3 Route-target to 50:50 and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_both_rt="50:50",config="yes", local_as=evpn_dict["leaf3"]['local_as'])

    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix, evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],rt="50:50",
                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],
                         rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Change the L3 Route-target to 50:50 & verify through evpn routes")

    st.log("Step 4: Verify VxLAN tunnel is deleted when L2 RT and L3 RT both are mis-macthed")
    vtep_list = Evpn.get_tunnel_list(vars.D6)
    if evpn_dict["leaf3"]["loop_ip_list"][1] in vtep_list:
        st.error("FAIL: In leaf4, Vxlan tunnel found for Leaf3, not expected due to L2 RT and L3 RT mis-match")
        st.error("Testcase: {}, Summary: {} , result:Failed".format(tc_list[3], tc_list_summary[3]))
        success=False
    else:
        st.log("PASS: In leaf4, Vxlan tunnel not found or deleted when L2 RT and L3 RT both are mis-macthed")

    st.log("Step 5: Revert back the L3 RT to auto and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_both_rt="50:50",config="no", local_as=evpn_dict["leaf3"]['local_as'])

    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix,evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         rt=evpn_dict["leaf3"]["l3_vni_list"][0]+":"+evpn_dict["leaf3"]["l3_vni_list"][0],
                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],
                         rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verified the auto L3 RT through evpn routes")

    st.log("Step 5: Revert back the L2 RT to auto and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vni"],
                         vni=evpn_dict["leaf1"]['tenant_l2_vlan_list'][0], vni_both_rt="23:23",
                         config="yes", local_as=evpn_dict["leaf3"]['local_as'],vni_unconfig="yes")

    if Evpn.verify_bgp_l2vpn_evpn_vni_id(dut=evpn_dict["leaf_node_list"][2], rt=['23:23','23:23'],
                         vni=evpn_dict["leaf3"]['tenant_l2_vlan_list'][0]):
        st.log("Evpn routes with route-target 23:23 is present even after reverting back to auto RT on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result:Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verified RT 23:23 is not present after manual L2 RT removed")

    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                                           src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 1):
        st.log("VxLAN tunnel is down even when auto L2 RT and auto L3 RT is restored")
        st.error("Testcase: {}, Summary: {} , result:Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify VxLAN tunnel is Up with auto L2 and L3 RT")

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3222_5")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3222_5")

def test_FtOpSoRoEvpn5549Ft3221():
    success = True
    st.log("### Verify Test VxLAN by removing and adding back VLAN to VNI mapping while vxlan tunnel is up ###")

    st.log("Step 1: Delete L2 vlan to VNI mapping in leaf 1")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], config="no")

    st.log("Step 2: Verify vxlan tunnel is still up as L3 VNI is extended")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][1], [evpn_dict["leaf2"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 3]])

    st.log("Step 3: Add L2 vlan to VNI mapping in leaf 1")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], config="yes")

    st.log("Step 4: Remove Vrf to VNI map in leaf 1")
    Evpn.map_vrf_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vrf_name_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0],config="no", vtep_name=evpn_dict["leaf1"]["vtepName"])

    st.log("Step 5: Delete L3 vlan to VNI mapping")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], config="no")

    st.log("Step 6: Verify vxlan tunnel is up after removing L3 VNI map as L2 VNI extended")
    utils.exec_all(True, [[Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["loop_ip_list"][1], [evpn_dict["leaf2"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1],evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf3"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf4"]["loop_ip_list"][1]], ['oper_up'] * 3],
            [Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["loop_ip_list"][1], [evpn_dict["leaf1"]["loop_ip_list"][1],
            evpn_dict["leaf2"]["loop_ip_list"][1], evpn_dict["leaf3"]["loop_ip_list"][1]], ['oper_up'] * 3]])

    st.log("Step 7: Verify vxlan remote VNI id status")
    if not retry_api(Evpn.verify_vxlan_evpn_remote_vni_id, evpn_dict["leaf_node_list"][1],
                                vni=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                vlan=evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                total_count="3",identifier="all",rvtep=evpn_dict["leaf1"]["loop_ip_list"][1], retry_count=3, delay=2):
        st.error(" Test Case failed at step 7 - Verify vxlan remote VNI id status")
        success = False
    else:
        st.log(" Test Case Step 7 PASSED - Verify vxlan remote VNI id status")

    st.log("Step 8: Add L3 vlan to VNI mapping")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], config="yes")

    st.log("Step 9: Add Vrf to VNI map in leaf 1")
    Evpn.map_vrf_vni(evpn_dict["leaf_node_list"][0],evpn_dict["leaf1"]["vrf_name_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0],config="yes", vtep_name=evpn_dict["leaf1"]["vtepName"])

    st.log("Step 10: Verify vxlan VLAN VNI mapping")
    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][2],
                                vni=[evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                evpn_dict["leaf1"]["l3_vni_list"][0]],
                                vlan=[evpn_dict["leaf1"]["tenant_l2_vlan_name_list"][0],
                                evpn_dict["leaf1"]["l3_vni_name_list"][0]],total_count="2"):
        st.error(" Test Case failed at step 10 - Verify vxlan VLAN VNI mapping")
        success = False
    else:
        st.log(" Test Case Step 10 PASSED - Verify vxlan VLAN VNI mapping")

    st.log("Step 11: Verify vxlan VRF VNI mapping")
    if not Evpn.verify_vxlan_vrfvnimap(dut=evpn_dict["leaf_node_list"][2],
                                vni=evpn_dict["leaf1"]["l3_vni_list"][0],
                                vrf=evpn_dict["leaf1"]["vrf_name_list"][0],total_count="1"):
        st.error(" Test Case failed at step 11 - Verify vxlan VRF VNI mapping")
        success = False
    else:
        st.log(" Test Case Step 11 PASSED - Verify vxlan VRF VNI mapping")

    st.log("Step 12: verify L3 VNI routes in Leaf1")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 12 - Verify L3 VNI routes in Leaf 1")
        success = False
    else:
        st.log(" Test Case Step 12 PASSED - Verify L3 VNI routes in Leaf 1")

    st.log("Step 13: verify L3 VNI routes in Leaf4")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf1"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf1"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 13 - Verify L3 VNI routes in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 13 PASSED - Verify L3 VNI routes in Leaf 4")

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3221")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3221")


def test_FtOpSoRoEvpn5549Ft3244_4(Ft32211_fixture):
    tc_list = ["test_FtOpSoRoEvpn5549Ft3244","test_FtOpSoRoEvpn5549Ft3245","test_FtOpSoRoEvpn5549Ft3246",
                         "test_FtOpSoRoEvpn5549Ft3247"]
    tc_list_summary = ["Verify deletion of RD for VRF","Verify change of RD for VRF",
                         "Verify change of export RT for VRF",
                         "Verify deletion of export RT for VRF"]
    success = True
    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")
    st.log("Verify the default RT and RD is in correct state as part of base line config before test start")
    Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1])

    Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1])

    Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1])

    Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",next_hop=evpn_dict["leaf3"]["loop_ip_list"][1])

    Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],bgp_peer=data.spine1_ipv6_list[3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         rt=evpn_dict["leaf3"]["l3_vni_list"][0]+":"+evpn_dict["leaf3"]["l3_vni_list"][0],rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]])

    Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],bgp_peer=data.spine2_ipv6_list[3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         rt=evpn_dict["leaf3"]["l3_vni_list"][0]+":"+evpn_dict["leaf3"]["l3_vni_list"][0],rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]])

    st.log("Step 1: Change the RD to manual entry and verify the new RD is reflected in the show bgp evpn routes on the neighbor")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_rd="9:9",config="yes", local_as=evpn_dict["leaf3"]['local_as'])

    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd="9:9",status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("Evpn routes with rd 9:9 is not being received from {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[1],tc_list_summary[1]))
        success = False
    else:
        st.log(" Test Case Step 1 PASSED - Change the RD to manual entry and verify the new RD")

    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd="9:9",status_code="*>",next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("Evpn routes with rd 9:9 is not being received from {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[1],tc_list_summary[1]))
        success = False
    else:
        st.log(" Test Case Step 1 PASSED - Change the RD to manual entry and verify the new RD")

##    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
##   dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
##   create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
##    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("Start L3 IPv4 and IPv6 traffic from Leaf 3 to Leaf 4 after RD change")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    st.log("Step 1: Verify L3 traffic from Leaf 3 to Leaf 4 after RD change")
    if verify_traffic():
        st.log("traffic verification passed after RD changes")
    else:
        success=False
        st.error("traffic verification failed after RD changes")

    st.log("Step 2: Remove the manual entry and verify the auto RD is received")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],
                         vrf_name="Vrf1",l3_rd="9:9",config="no", local_as=evpn_dict["leaf3"]['local_as'])

    st.log("Verify EVPN type 5 - IPv4 prefix route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {}, result: Failed".format(tc_list[0], tc_list_summary[0]))
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Remove the manual entry and verify the auto RD")

    st.log("Verify EVPN type 5 - IPv6 prefix route for auto RD")
    Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1])

    st.log("Verify EVPN type 5 - IPv4 Route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {}, result: Failed".format(tc_list[1], tc_list_summary[1]))
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Remove the manual entry and verify the auto RD for IPv4 route")

    st.log("Verify EVPN type 5 - IPv6 Route for auto RD")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],evpn_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("Evpn routes with auto rd is not present after reverting to auto rd on {}".format(evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[1], tc_list_summary[1]))
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Remove the manual entry and verify the auto RD for IPv6 route")

    st.log("Step 3: Change the Route-target to 50:50 and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_both_rt="50:50",config="yes", local_as=evpn_dict["leaf3"]['local_as'])

    st.log("Verify EVPN type 5 - IPv4 prefix route for changed RT")
    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix,evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],rt="50:50",
                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],
                         rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.log("Evpn ipv4 routes with route-target 50:50 is not present after adding it manually on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Change the Route-target to 23:23 & verify through evpn routes")

    st.log("Verify EVPN type 5 - IPv6 prefix route for changed RT")
    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix,evpn_dict["leaf_node_list"][3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],rt="50:50",
                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],
                         rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.log("Evpn ipv6 routes with route-target 50:50 is not present after adding it manually on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Change the Route-target to 50:50 & verify through evpn routes")

    st.log("Step 4: Verify VxLAN tunnel status in leaf4 to leaf 3 is up even if the route-target is not matching")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                         src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                         rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                         exp_status_list=['oper_up'] * 1):
        st.log("VxLAN tunnel is not up - L3 RT mis-match but L2 RT matches")
        st.error("Testcase: {}, Summary: {} , result:Failed".format(tc_list[2], tc_list_summary[2]))
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify VxLAN tunnel is Up even though L3 RT mis-match as L2 RT matches")

    st.log("### Step 4: Verify Leaf 3 Tenant IPv4 prefix route in Leaf 4 ###")
    if ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 2 - Verify Leaf 3 tenant IPv4 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Verified Leaf 3 Tenant IPv4 prefix route not installed in Leaf 4 after RT change")

    st.log("### Step 4: Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4 ###")
    if ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 5 - Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify Leaf 3 Tenant IPv6 prefix route not installed in Leaf 4 after RT change")

    st.log("Step 5: Revert back the Route-target to auto and verify the same is reflected in the evpn routes")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",
                         l3_both_rt="50:50",config="no", local_as=evpn_dict["leaf3"]['local_as'])

    st.log("Verify EVPN type 5 - IPv4 prefix route for auto derived RT")
    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix,evpn_dict["leaf_node_list"][3],bgp_peer=data.spine2_ipv6_list[3],
                         prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         rt=evpn_dict["leaf3"]["l3_vni_list"][0]+":"+evpn_dict["leaf3"]["l3_vni_list"][0],rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.log("Evpn IPv4 routes with auto route-target is not present after reverting back to auto RT on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[3], tc_list_summary[3]))
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify VxLAN tunnel status again when RT configured back as auto")

    st.log("Verify EVPN type 5 - IPv6 prefix route for auto derived RT")
    if not retry_api(Evpn.verify_bgp_l2vpn_evpn_route_detail_type_prefix,evpn_dict["leaf_node_list"][3],bgp_peer=data.spine1_ipv6_list[3],
                         prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         rt=evpn_dict["leaf3"]["l3_vni_list"][0]+":"+evpn_dict["leaf3"]["l3_vni_list"][0],rvtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         vni_id=evpn_dict["leaf3"]["l3_vni_list"][0],rmac=evpn_dict["leaf_base_mac_list"][evpn_dict["leaf_node_list"][2]], retry_count=3, delay=2):
        st.log("Evpn IPv6 routes with auto route-target is not present after reverting back to auto RT on {}".format(
            evpn_dict["leaf_node_list"][2]))
        st.error("Testcase: {}, Summary: {} , result: Failed".format(tc_list[3], tc_list_summary[3]))
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify VxLAN tunnel status again when RT configured back as auto")

    st.log("### Step 5: Verify Leaf 3 Tenant IPv4 prefix route in Leaf 4 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at step 2 - Verify Leaf 3 tenant IPv4 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 2 PASSED - Verified Leaf 3 Tenant IPv4 prefix route installed in Leaf 4 after RT change")

    st.log("### Step 5: Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 5 - Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify Leaf 3 Tenant IPv6 prefix route installed in Leaf 4 after RT change")
    current_stream_dict["stream"] = stream_dict["l3"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3244_4")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3244_4")


def test_FtOpSoRoEvpn5549Ft3214(Ft3214_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft3214; TC SUMMARY : Test VxLAN by creating vlan after VxLAN map for that VLAN")
    success = True
    testcase_id = 'Ft3214'

    ##########################################################################################################
    hdrMsg(" \n###### Add L2 vlan to VNI mapping before vlan creation and verify system throws error #####\n")
    ##########################################################################################################
    result = Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2], vtep_name=evpn_dict["leaf3"]["vtepName"], vlan_id='200', vni_id='200',skip_error=True)
    if evpn_dict['cli_mode'] != "klish":
        expected_err ="Error: Vlan200 not configured"
    elif evpn_dict['cli_mode'] == "klish":
        if st.get_ui_type() in ["rest-put", "rest-patch"]:
            expected_err = "Resource not found"
        else:
            expected_err = "Error: No instance found for 'Vlan200'"

    if expected_err not in str(result):
        success=False
        st.error('FAIL: Vlan to Vni mapping allowed before vlan is created.')
    else:
        st.log('PASS: Vlan to Vni mapping not allowed before vlan is created.')

    ############################################################################################
    hdrMsg(" \n####### Create tenant L2 VLANs on leaf 3 and 4 ##########\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][2],"200"],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],"200"]])

    ############################################################################################
    hdrMsg(" \n####### Bind tenant L2 VLANs to port on leaf 3 and 4 #######/n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           "200", evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           "200", evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni on leaf 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],evpn_dict["leaf3"]["vtepName"], "200","200"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200"]]):
        st.log('Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')

    ############################################################################################
    hdrMsg(" \n####### Verify traffic on new vlan #######/n")
    ############################################################################################
#    create_stream("l2",port_han_list=[tg_dict['d5_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,src_mac_list=['00:10:00:05:01:01','00:10:00:06:01:01'],dst_mac_list=['00:10:00:06:01:01','00:10:00:05:01:01'],vlan_id_list=['200','200'],src_mac_count_list=['10','10'],dst_mac_count_list=['10','10'])

    st.log("start traffic from first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2_3214"])

    for i in range(4):
        result = verify_traffic()
        if result is False:
            hdrMsg(" \n####### retry traffic verification ##############\n")
            Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][2], vni="200", vlan="Vlan200",
                                                 identifier="all", rvtep=evpn_dict["leaf4"]["loop_ip_list"][1])
            Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][3], vni="200", vlan="Vlan200",
                                                 identifier="all", rvtep=evpn_dict["leaf3"]["loop_ip_list"][1])
            continue
        else:
            break

    if result:
        st.log("PASS: traffic verification passed on new vlan")
    else:
        success = False
        st.log("FAIL: traffic verification failed on new vlan")
        debug_traffic(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_3214"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3214")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3214")


@pytest.fixture(scope="function")
def Ft3214_fixture(request,evpn_underlay_hooks):
    yield
    #
    hdrMsg("### CLEANUP for 3214 ###")
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
#    st.log("Reset TGEN")
#    reset_tgen()

    st.log("Remove L2 vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],evpn_dict["leaf3"]["vtepName"], "200","200",'1',"no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'1',"no"]])
    st.log("Unbind tenant L2 VLANs to port on leaf 3 and 4")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           "200", evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           "200", evpn_dict["leaf4"]["intf_list_tg"][0],True]])
    st.log("Delete tenant L2 VLANs on leaf 3 and 4")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],"200"],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],"200"]])

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)


@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft32211(Ft32211_fixture):

    hdrMsg("TC ID: test_FtOpSoRoEvpn5549Ft32211; TC SUMMARY : Test VxLAN by removing redistribute connected from BGP")
    success = True
    testcase_id = 'Ft32211'

    ############################################################################################
    hdrMsg(" \n####### Create streams and start traffic ##############\n")
    ############################################################################################
##    create_stream("l2")

##    dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac'])
##    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])
##    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
##    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    st.log("start traffic from first tgen port of DUT5 and DUT6")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_dict["all"])

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed in the hardware as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3],test= testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Verify traffic before trigger ##############\n")
    ############################################################################################

    if verify_traffic():
        st.log("traffic verification passed before trigger ")
    else:
        success=False
        st.error("traffic verification failed before trigger")

    ############################################################################################
    hdrMsg(" \n####### Delete Redistribute connected route in bgp ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], local_as=evpn_dict['leaf4']['local_as'], config_type_list=['redist'],
                                                                                     redistribute='connected', config='no')

    ############################################################################################
    hdrMsg(" \n####### Verify tunnel down in leaf3 ##############\n")
    ############################################################################################
    if not retry_api(Evpn.verify_vxlan_tunnel_status,evpn_dict["leaf_node_list"][2],src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                    rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],exp_status_list=['oper_down'],
                                         retry_count=3, delay=2):
        st.error("VXLAN tunnel is NOT DOWN in leaf3")
        success=False
    else:
        st.log("VXLAN tunnel is DOWN as expected in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify macs are not withdrawn in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are not withdrawn as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3],test= testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Reconfigure Redistribute connected route in bgp ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], local_as=evpn_dict['leaf4']['local_as'], config_type_list=['redist'],
                                                                                     redistribute='connected')

    ############################################################################################
    hdrMsg(" \n####### Verify tunnel up in leaf3 ##############\n")
    ############################################################################################
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                    rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is DOWN in leaf3")
        success=False
    else:
        st.log("VXLAN tunnel is UP as expected in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt_3 = Mac.get_mac_count(vars.D5)
    D6_mac_cnt_3 = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are insalled as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3],test= testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Verify traffic after trigger ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("traffic verification passed after reconfiguring 'redistribute connected' cmd ")
    else:
        success=False
        st.error("traffic verification failed after reconfiguring 'redistribute connected' cmd ")
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32211")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32211")

@pytest.fixture(scope="function")
def Ft32211_fixture(request,evpn_underlay_hooks):
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield

    hdrMsg("### CLEANUP for 32211 ###")

    ############################################################################################
    hdrMsg(" \n####### Stop the traffic ##############\n")
    ############################################################################################
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

##    st.log("Reset TGEN")
##    reset_tgen()
##    delete_host()

@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft32214(Ft32214_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32214; TC SUMMARY : Test VxLAN by deleting and adding back BGP EVPN address family")
    success = True
    testcase_id = 'Ft32214'

    ############################################################################################
    hdrMsg(" \n####### Create streams and start traffic ##############\n")
    ############################################################################################
##    create_stream("l2")

##    dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac'])
##    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])
##    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
##    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    st.log("Start traffic from the first tgen port of DUT5 and DUT6")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3], test=testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Verify traffic before trigger ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("traffic verification passed before trigger ")
    else:
        success=False
        st.error("traffic verification failed before trigger")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3], test=testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Delete BGP EVPN AF in leaf4 ##############\n")
    ############################################################################################
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], neighbor=data.spine1_ipv6_list[3],
            remote_as=evpn_dict['spine1']['local_as'],
            config_type_list=["activate"], config="no", local_as=evpn_dict['leaf4']['local_as'])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], neighbor=data.spine2_ipv6_list[3],
            remote_as=evpn_dict['spine2']['local_as'],
            config_type_list=["activate",'advertise_all_vni'], config="no", local_as=evpn_dict['leaf4']['local_as'])

    st.wait(3)

    ############################################################################################
    st.log("###Verify VXLAN tunnel status in leaf3###")
    ############################################################################################

    vtep_list = Evpn.get_tunnel_list(vars.D5)
    if evpn_dict["leaf4"]["loop_ip_list"][1] in vtep_list:
        st.error("FAIL: Expected number of tunnels not found" )
        success=False
    else:
        st.log("PASS: Expected number of tunnels seen")

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt_2 = Mac.get_mac_count(vars.D5)
    D6_mac_cnt_2 = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 0:
        st.log("PASS: Remote macs are withdrawn as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:0. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3],test=testcase_id)

    ############################################################################################
    hdrMsg(" \n####### Reconfigure BGP EVPN AF in leaf4 ##############\n")
    ############################################################################################
    i=3
    for ipv6_lst1,j in zip([data.spine1_ipv6_list,data.spine2_ipv6_list],range(0,2)):
            Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3],config='yes',local_as=evpn_dict["leaf4"]["local_as"],
                config_type_list=["activate"], remote_as=data.bgp_spine_local_as[j], neighbor=ipv6_lst1[i])
            Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3],config='yes',local_as=evpn_dict["leaf4"]["local_as"],
                config_type_list=["advertise_all_vni"], remote_as=data.bgp_spine_local_as[j], neighbor=ipv6_lst1[i])
    st.wait(5)

    ############################################################################################
    hdrMsg(" \n####### Verify BGP EVPN neighborship ##############\n")
    ############################################################################################
    if not Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][3], neighbor=[data.spine1_ipv6_list[3],data.spine2_ipv6_list[3]],updown=["up", "up"],identifier=evpn_dict["leaf4"]["loop_ip_list"][1]):
        st.log("FAIL: EVPN neighbor is not up")
        success=False
    else:
        st.log("PASS: EVPN neighbor is up")

    ############################################################################################
    hdrMsg(" \n####### Verify tunnel up in leaf3 ##############\n")
    ############################################################################################
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                    rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is DOWN in leaf3")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3], test=testcase_id)
    else:
        st.log("VXLAN tunnel is UP as expected in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify routes are learnt in leaf3 ##############\n")
    ############################################################################################
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                       shell="vtysh",family="ipv4",interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                       nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                       ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.log("FAIL: Routes learnt from leaf4 not found in leaf3")
        success = False
    else:
        st.log("PASS: Routes learnt from leaf4 found in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt_3 = Mac.get_mac_count(vars.D5)
    D6_mac_cnt_3 = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Verify traffic after trigger ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("traffic verification passed after reconfiguring network cmd ")
    else:
        success=False
        st.error("traffic verification failed after reconfiguring network cmd ")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32214")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32214")

@pytest.fixture(scope="function")
def Ft32214_fixture(request,evpn_underlay_hooks):
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    hdrMsg("### CLEANUP for 32214 ###")
    ############################################################################################
#    hdrMsg(" \n####### Reset TGEN ##############\n")
    ############################################################################################
#    reset_tgen()
#    delete_host()
    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)


def test_FtOpSoRoEvpn5549Ft3229_10(Ft32215_fixture):
    st.log("########## Test VxLAN by clearing EVPN neighbor ##########")
    success = True

    st.log("########## start traffic from first tgen port of Leaf3 and Leaf4##########")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("########## verify traffic received in first tgen port of Leaf3 and Leaf4 ##########")
    if verify_traffic():
        st.log("traffic verification passed before clearing EVPN neighbors")
    else:
        success=False
        st.error("traffic verification failed before clearing EVPN neighbors")

    if evpn_dict['cli_mode'] == "klish":
        for ngbr1,ngbr2 in zip([data.leafs_spine1_port_lst1[2],data.leafs_spine2_port_lst1[2]], data.leaf3_po_list[0:2]):
            retry_api(ip_bgp.check_bgp_session,evpn_dict["leaf_node_list"][2],nbr_list=[ngbr1,ngbr2],
                state_list=['Established']*2,retry_count=5,delay=1)

        retry_api(ip_bgp.check_bgp_session,evpn_dict["leaf_node_list"][2],nbr_list=[data.spine1_ipv6_list[2],data.spine2_ipv6_list[2]],
            state_list=['Established']*2,retry_count=5,delay=1)

    output = Evpn.fetch_evpn_neigh_output(vars.D5)
    output = filter_and_select(output, {"updown"}, match={"neighbor" : data.spine1_ipv6_list[2]})
    timer1 = int(output[0]["updown"].split(":")[1])

    st.log("########## clear BGP EVPN neighbors in Leaf3 ##########")
    Evpn.clear_bgp_evpn(vars.D5, "*")
    st.wait(5)
    output = Evpn.fetch_evpn_neigh_output(vars.D5)
    output = filter_and_select(output, {"updown"}, match={"neighbor" : data.spine1_ipv6_list[2]})
    timer2 = int(output[0]["updown"].split(":")[1])

    if timer2 < timer1:
        st.log("EVPN neighbors re-established sucessfully, passed")
    else:
        success=False
        st.error("EVPN neighbors failed to reset OR re-establish the connection")

    st.log("########## verify traffic after clearing EVPN neighbors ##########")
    if verify_traffic():
        st.log("traffic verification passed after clearing EVPN neighbors")
    else:
        success=False
        st.error("traffic verification failed after clearing EVPN neighbors")

    st.log("########## clear the EVPN table external soft-in in Leaf3 ##########")
    Evpn.clear_bgp_evpn(vars.D5, "external", soft_dir="in")
    st.log("########## clear the EVPN table peerAs soft-out in Leaf3 ##########")
    Evpn.clear_bgp_evpn(vars.D5, evpn_dict["leaf4"]["rem_as_list"][0], soft_dir="out")
    Evpn.clear_bgp_evpn(vars.D5, evpn_dict["leaf4"]["rem_as_list"][1], soft_dir="out")
    st.wait(5)

    st.log("########## verify traffic after clearing EVPN table ##########")
    if verify_traffic():
        st.log("traffic verification passed after clearing EVPN table")
    else:
        success=False
        st.error("traffic verification failed after clearing EVPN table")
    current_stream_dict["stream"] = stream_dict["all"]

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3229_10")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3229_10")


def test_FtOpSoRoEvpn5549Ft32218(Ft32218_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32218; TC SUMMARY : Test VxLAN by shutting down the links towards downstream")
    success = True
    ############################################################################################
    hdrMsg(" \n####### Create tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"200 210"],
        [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"200 210"]])

    ############################################################################################
    hdrMsg(" \n####### Bind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"200 210",evpn_dict["leaf3"]["intf_list_tg"][0]],
        [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"200 210",evpn_dict["leaf4"]["intf_list_tg"][0]]])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "200","200",'10'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'10']]):
        st.log('Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')
    st.wait(30)

    ############################################################################################
    hdrMsg(" \n####### Verify Vlan evpn_remote_vni #######/n")
    ############################################################################################
    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][2],
                            vni='209',vlan='Vlan209',
                            identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        success = False
        st.error('FAIL: verification of VNI details failed')

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][3],
                            vni='209',vlan='Vlan209',
                            identifier="all",rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        success = False
        st.error('FAIL: verification of VNI details failed')

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32218"])

    ############################################################################################
    hdrMsg("\n####### Verify traffic before trigger ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed before trigger ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed before trigger")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Shutdown the link towards client from where the MACs are learnt ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][3],[evpn_dict["leaf4"]["intf_list_tg"][0]])
    st.wait(10)

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D5, tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 0:
        st.log("PASS: Remote macs of pattern {} not installed in D5 as expected".format(tg_dict['dut_6_mac_pattern']))
    else:
        st.error("FAIL: Mac pattern {} in D5 is still present".format(tg_dict['dut_6_mac_pattern']))
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n###### Unshut the link towards client from where the MACs are learnt ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["leaf_node_list"][3],[evpn_dict["leaf4"]["intf_list_tg"][0]])
    st.wait(20)
    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ########\n")
    ############################################################################################
    mac_list = filter_mac_list(vars.D5, tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed in D5 as expected.")
    else:
        st.error("FAIL: Mac pattern {} in D5 is missing".format(tg_dict['dut_6_mac_pattern']))
        success = False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32218"]

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32218")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32218")

@pytest.fixture(scope="function")
def Ft32218_fixture(request,evpn_underlay_hooks):
    yield

    hdrMsg("### CLEANUP for 32218 ###")
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "200","200",'10','no'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'10','no']]):
        st.log('Vlan to Vni mapping is deleted.')
    else:
        success=False
        st.error('FAIL: Removal of Vlan to Vni mapping failed even after vlan is created.')

    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"200 210",evpn_dict["leaf3"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"200 210",evpn_dict["leaf4"]["intf_list_tg"][0],'del']])

    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"200 210",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"200 210",'del']])



@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft32219_2(Ft32219_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32219; TC SUMMARY : Test VxLAN for static mac;\
            TC ID: FtOpSoRoEvpn5549Ft32221; TC SUMMARY : Test VxLAN for static MAC behavior across leaf nodes")

    success = True
    testcase_id = 'Ft32219_2'

    ############################################################################################
    hdrMsg(" \n####### Step 1 - Configure static mac on Leaf4 #########\n")
    ############################################################################################
    mac1 = '00:44:11:00:00:01'
    Mac.config_mac(evpn_dict["leaf_node_list"][3], mac1, evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0])
    st.wait(2)

    ############################################################################################
    hdrMsg(" \n####### Step 2 - Verify this mac is advertised to the remote VTEPs #########\n")
    ############################################################################################
    if not Evpn.verify_vxlan_evpn_remote_mac_id(evpn_dict["leaf_node_list"][2], vni="100",vlan="Vlan100",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1],type="static",identifier=evpn_dict["leaf4"]["loop_ip_list"][1],mac=mac1):
        st.log("FAIL: Static mac not found in the remote vtep")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3], test=testcase_id)
    else:
        st.log("PASS: Static mac entry found in the remote vtep")

    ############################################################################################
    hdrMsg(" \n####### Step 3 - Remove the static mac on Leaf4 #########\n")
    ############################################################################################
    Mac.delete_mac(evpn_dict["leaf_node_list"][3], mac1, evpn_dict["leaf4"]["tenant_l2_vlan_list"][0])
    st.wait(2)

    ############################################################################################
    hdrMsg(" \n####### Step 4 - Verify this mac is withdrawn from the remote VTEPs  #########\n")
    ############################################################################################
    res = Evpn.verify_vxlan_evpn_remote_mac_id(evpn_dict["leaf_node_list"][2], vni="100",vlan="Vlan100",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1],type="static",identifier=evpn_dict["leaf4"]["loop_ip_list"][1],mac=mac1)
    if res != 1:
        st.log('PASS:Match not found as expected')
    else:
        st.log("FAIL:Mac entry is still not withdrawn from the remote end.")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Step 5 - Add back the static mac on Leaf4 #########\n")
    ############################################################################################
    mac1 = '00:44:11:00:00:01'
    Mac.config_mac(evpn_dict["leaf_node_list"][3], mac1, evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0])
    st.wait(2)

    ############################################################################################
    hdrMsg(" \n####### Step 6 - Verify this mac is advertised again to the remote VTEPs #########\n")
    ############################################################################################
    if not Evpn.verify_vxlan_evpn_remote_mac_id(evpn_dict["leaf_node_list"][2], vni="100",vlan="Vlan100",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1],type="static",identifier=evpn_dict["leaf4"]["loop_ip_list"][1],mac=mac1):
        st.log("FAIL: Static mac not found in the remote vtep")
        success=False
    else:
        st.log("PASS: Static mac entry found in the remote vtep")
    ############################################################################################
    hdrMsg(" \n####### Step 7 - Verify traffic #########\n")
    ############################################################################################
#    create_stream("l2",port_han_list=[tg_dict['d5_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,src_mac_list=['00:10:00:05:01:01',mac1],dst_mac_list=[mac1,'00:10:00:05:01:01'],vlan_id_list=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf4"]["tenant_l2_vlan_list"][0]],src_mac_count_list=['1','1'],dst_mac_count_list=['1','1'])

    st.log("start traffic from first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2_32219_1"])

    if verify_traffic():
        st.log("traffic verification passed for static mac")
    else:
        success=False
        st.error("traffic verification failed on static mac")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Step 8 - Verify traffic is not flooded #########\n")
    ############################################################################################
    tg = tg_dict['tg']
    traffic_params = {'1': {'tx_ports' : [tg_dict['d5_tg_port1']], 'tx_obj' : [tg],'exp_ratio' : [0], 'rx_ports' : [tg_dict['d3_tg_port1']], 'rx_obj' : [tg]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_rate', tolernace_factor = '2')

    ############################################################################################
    hdrMsg("\n####### Step 9 - Shutdown the interface pointing towards the static mac #######\n")
    ############################################################################################
    port.shutdown(evpn_dict["leaf_node_list"][3],[evpn_dict["leaf4"]["intf_list_tg"][0]])
    st.wait(5)

    ############################################################################################
    hdrMsg(" \n####### Step 10 - Verify this mac is not withdrawn from the remote VTEPs #########\n")
    ############################################################################################
    if not Evpn.verify_vxlan_evpn_remote_mac_id(evpn_dict["leaf_node_list"][2], vni="100",vlan="Vlan100",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1],type="static",identifier=evpn_dict["leaf4"]["loop_ip_list"][1],mac=mac1):
        st.log("FAIL: Static mac not found in the remote vtep")
        success=False
    else:
        st.log("PASS: Static mac entry found in the remote vtep")

    ############################################################################################
    hdrMsg("\n####### Step 11 - Unshut the interface pointing towards the static mac #######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["leaf_node_list"][3],[evpn_dict["leaf4"]["intf_list_tg"][0]])
    st.wait(10)

    ############################################################################################
    hdrMsg("\n####### Step 12 - Verify traffic #######\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed for static mac")
    else:
        success=False
        st.error("FAIL: Traffic verification failed for static mac")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3],test= testcase_id)

    ############################################################################################
    hdrMsg("\n####### Step 13 - Receive traffic with same MAC as SMAC on remote vtep Leaf3 #######\n")
    ############################################################################################
#    reset_tgen()
#    create_stream("l2",port_han_list=[tg_dict['d5_tg_ph2']],def_param=False,src_mac_list=[mac1],dst_mac_list=['00:10:00:05:01:01'],vlan_id_list=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0]],src_mac_count_list=['1'],dst_mac_count_list=['1'])

    st.log("start traffic from first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2_32219_2"])

    ############################################################################################
    hdrMsg(" \n####### Step 14 - Verify this mac is not learnt as dynamic on the remote VTEPs  #########\n")
    ############################################################################################
    mac_lst =  Mac.get_mac_address_list(evpn_dict["leaf_node_list"][2], mac='00:44:11:00:00:01', vlan='100', type='Dynamic')
    if len(mac_lst) == 1:
        success=False
        st.error("FAIL - MAC is learned dynamically in Leaf3")
    else:
        st.log("PASS - MAC not learnt dynamically in Leaf3")

    ############################################################################################
    hdrMsg("\n####### Step 15 - Verify traffic from Leaf4 to Leaf3 #######\n")
    ############################################################################################
##    reset_tgen()
##    create_stream("l2",port_han_list=[tg_dict['d5_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,src_mac_list=['00:10:00:05:01:01',mac1],dst_mac_list=[mac1,'00:10:00:05:01:01'],vlan_id_list=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf4"]["tenant_l2_vlan_list"][0]],src_mac_count_list=['1','1'],dst_mac_count_list=['1','1'])

    st.log("start traffic from first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2_32219_1"])

    if verify_traffic():
        st.log("PASS: Traffic verification passed for static mac")
    else:
        success=False
        st.error("FAIL: Traffic verification failed for static mac")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32219_1"]+stream_dict["l2_32219_2"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32219")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32219")


@pytest.fixture(scope="function")
def Ft32219_fixture(request,evpn_underlay_hooks):
    yield

    hdrMsg("### CLEANUP for 32219 ###")

    ############################################################################################
    hdrMsg(" \n####### Remove the static mac on Leaf4 #########\n")
    ############################################################################################
    mac1 = '00:44:11:00:00:01'
    Mac.delete_mac(evpn_dict["leaf_node_list"][3], mac1, evpn_dict["leaf4"]["tenant_l2_vlan_list"][0])

    ############################################################################################
##    hdrMsg(" \n####### Reset TGEN ##############\n")
    ############################################################################################
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
##    reset_tgen()
##    delete_host()

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

@pytest.fixture(scope="function")
def Ft3248_fixture(request,evpn_underlay_hooks):
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield
    #
##    hdrMsg("### Reseting the L3 IPv4 and IPv6 traffic streams ###")
    ############################################################################################
##    hdrMsg(" \n####### Reset TGEN ##############\n")
    ############################################################################################
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
##    reset_tgen()
##    delete_host()

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

    new_vlan="999"
    hdrMsg("### CLEANUP for 3248 config ###")

    st.log("Remove Vrf to Vni map outside FRR")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][0],"config":"no", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][0],"config":"no", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Remove L3 VNI VLAN to Vni map outside FRR")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], new_vlan,
            evpn_dict["leaf3"]["l3_vni_list"][0],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            new_vlan, evpn_dict["leaf4"]["l3_vni_list"][0],"1", "no"]])

    st.log("Delete ipv4 and ipv6 address from new L3 VNI VLAN interface")
    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+new_vlan, evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+new_vlan, evpn_dict["leaf4"]["l3_vni_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+new_vlan, evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+new_vlan, evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log(" Delete IP address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log(" Delete IPv6 address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Delete VLAN membership for new L3 VNI VLAN")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
            new_vlan, evpn_dict["leaf3"]["intf_list_tg"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
            new_vlan, evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Removing Vrf binding for L3 VNI VLAN interface and L3 tenant interface")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":"Vlan"+new_vlan,"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
              "intf_name":"Vlan"+new_vlan,"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Delete BGP Vrf global config ")
    dict1 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Bgp.config_bgp,[dict1,dict2])

    st.log("Delete Vrf glovally outside FRR")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0],"config":"no"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],"config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    st.log("Delete new L3 VNI VLAN on leaf 3 and 4")
    utils.exec_all(True,[[Vlan.delete_vlan,evpn_dict["leaf_node_list"][2],new_vlan],
            [Vlan.delete_vlan,evpn_dict["leaf_node_list"][3],new_vlan]])

    hdrMsg("### Restoring the default L3 VNI config on Leaf 3 node ###")

    st.log("Configure user vrf to restore default L3 VNI VLAN")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0],"config":"yes"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],"config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    st.log("Configure user vrf binding to restore L3 tenant ips")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":"Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
              "intf_name":"Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": evpn_dict["leaf4"]["l3_vni_name_list"][0],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Restore IPv4 and IPv6 address for default L3 VNI VLAN")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Restore IPv4 and IPv6 address for L3 tenant VLAN interface")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Restore VLAN to VNI map & VRF to VNI outside FRR")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["l3_vni_list"][0],
            evpn_dict["leaf3"]["l3_vni_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf4"]["l3_vni_list"][0], evpn_dict["leaf4"]["l3_vni_list"][0]]])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][0], 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][0], 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Restore VRF to VNI under FRR")
    dict1 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
    dict2 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.config_bgp_evpn,[dict1,dict2])

    st.log("Restore BGP VRF config under FRR")
    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],'addr_family':"ipv6"}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],'addr_family':"ipv6"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])
    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])


def test_FtOpSoRoEvpn5549Ft32410_4(Ft32215_fixture):
    success = True
    hdrMsg("Covering TCs:FtOpSoRoEvpn5549Ft32410,FtOpSoRoEvpn5549Ft32411")
    hdrMsg("Covering TCs:FtOpSoRoEvpn5549Ft32413,FtOpSoRoEvpn5549Ft32414")
    hdrMsg("FtOpSoRoEvpn5549Ft32410 -Verify best route export to EVPN routing table")

##    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
##    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
##    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
##    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("Start L3 IPv4 and IPv6 traffic from Leaf 3 to Leaf 4 before start TC")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    if verify_traffic():
        st.log("traffic verification passed at the start of Ft32410_4")
    else:
        success=False
        st.error("traffic verification failed at the start of Ft32410_4")

##    start_traffic(action="stop")

    st.log("### Step 1: Configure new static route ipv4 and ipv6 route under vrf Vrf1 ###")
    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv4_static_route"],"vtysh","ipv4",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",evpn_dict["ipv6_static_route"],"vtysh","ipv6",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    st.log("### Step 2: Configure redist static under ipv4 and ipv6 AF in vrf Vrf1 ###")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                                config = 'yes',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                                config = 'yes',config_type_list =["redist"],redistribute ='static',
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family="ipv6")

    st.log("### Step 3: Verify new ipv4 route exported to Leaf 4 vrf Vrf1 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["ipv4_static_route"],distance="20",
                                cost="0",type="B",selected=">",fib="*"):
        st.error("Step 3 Failed - Verify new ipv4 route exported to Leaf 4 in vrf Vrf1")
        success = False
    else:
        st.log("Step 3 PASSED - Verify new ipv6 route exported to Leaf 4")

    st.log("### Step 3: Verify new ipv6 route exported to Leaf 4 vrf Vrf1 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["ipv6_static_route"],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error("Step 3 Failed - Verify new ipv6 route exported to Leaf 4 in vrf Vrf1")
        success = False
    else:
        st.log("Step 3 PASSED - Verify new ipv6 route exported to Leaf 4")

    ipv4_nw = evpn_dict["ipv4_static_route"].split("/")
    ipv6_nw = evpn_dict["ipv6_static_route"].split("/")

    st.log("### Step 4: Verify best ipv4 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],
                         evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine1']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 4 Failed - Verify best ipv4 route in Leaf 4 for vrf Vrf1")
        st.log("Klish run will fail for this step as metric value is not displayed")
        success = False
    else:
        st.log("Step 4 PASSED - Verify best ipv4 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 4: Verify non best ipv4 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],
                         evpn_prefix="[5]:[0]:[24]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine2']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 4 Failed - Verify non best ipv4 route in Leaf 4 for vrf Vrf1")
        st.log("Klish run will fail for this step as metric value is not displayed")
        success = False
    else:
        st.log("Step 4 PASSED - Verify non best ipv4 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 4: Verify best ipv6 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine1']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 4 Failed - Verify best ipv6 route in Leaf 4 for vrf Vrf1")
        success = False
    else:
        st.log("Step 4 PASSED - Verify best ipv6 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 4: Verify non best ipv6 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine2']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 4 Failed - Verify non best ipv6 route in Leaf 4 for vrf Vrf1")
        success = False
    else:
        st.log("Step 4 PASSED - Verify non best ipv6 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 5: Change the new ipv4 and ipv6 route with different mask in Leaf 3 ###")
    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",
                         evpn_dict["ipv4_static_route"],"ipv4","vtysh",
                         "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")
    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",
                         evpn_dict["ipv6_static_route"],"ipv6","vtysh",
                         "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")
    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",
                         "123.1.1.0/25","vtysh","ipv4",
                         "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")
    ip.create_static_route(evpn_dict["leaf_node_list"][2],"",
                         "1230::/98","vtysh","ipv6",
                         "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    hdrMsg("FtOpSoRoEvpn5549Ft32414 - Verify the new best route is exported via EVPN")

    st.log("### Step 6: Verify new best ipv4 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],
                         evpn_prefix="[5]:[0]:[25]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         status_code="*>",next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine1']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 6 Failed - Verify new best ipv4 route in Leaf 4 for vrf Vrf1")
        st.log("Klish run will fail for this step as metric value is not displayed")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new best ipv4 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 6: Verify new non best ipv4 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route(dut=evpn_dict["leaf_node_list"][3],
                         evpn_prefix="[5]:[0]:[25]:["+ipv4_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                         status_code="*",next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine2']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 6 Failed - Verify new non best ipv4 route in Leaf 4 for vrf Vrf1")
        st.log("Klish run will fail for this step as metric value is not displayed")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new non best ipv4 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 6: Verify new best ipv6 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[98]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*>",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine1']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 6 Failed - Verify new best ipv6 route in Leaf 4 for vrf Vrf1")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new best ipv6 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 6: Verify new non best ipv6 route in Leaf 4 for vrf Vrf1 ###")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[98]:["+ipv6_nw[0]+"]",
                         rd=evpn_dict["leaf3"]["l3_vni_ip_list"][0],status_code="*",
                         next_hop=evpn_dict["leaf3"]["loop_ip_list"][1],
                         path=evpn_dict['spine2']['local_as']+" "+evpn_dict['leaf3']['local_as']):
        st.error("Step 6 Failed - Verify new non best ipv6 route in Leaf 4 for vrf Vrf1")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new non best ipv6 route in Leaf 4 for vrf Vrf1")

    st.log("### Step 6: Verify new best ipv4 route under RIB in Leaf 4 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address="123.1.1.0/25",distance="20",
                                cost="0",type="B",selected=">",fib="*"):
        st.error("Step 6 Failed - Verify new best ipv4 route under RIB in Leaf 4")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new best ipv4 route under RIB in Leaf 4")

    st.log("### Step 6: Verify new best ipv6 route under RIB in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address="1230::/98",
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error("Step 6 Failed - Verify new best ipv6 route under RIB in Leaf 4")
        success = False
    else:
        st.log("Step 6 PASSED - Verify new best ipv6 route under RIB in Leaf 4")

    hdrMsg("FtOpSoRoEvpn5549Ft32413 -Verify local VRF route is preferred over the imported route")

    st.log("### Step 7: Verify same ipv4 and ipv6 route locally in Leaf 4 ###")
    ip.create_static_route(evpn_dict["leaf_node_list"][3],"",
                                "123.1.1.0/25","vtysh","ipv4",
                                "Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],"Vrf1")
    ip.create_static_route(evpn_dict["leaf_node_list"][3],"",
                                "1230::/98","vtysh","ipv6",
                                "Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],"Vrf1")
    sel_key = " "
    st.log("Step 7: Verify Leaf 3 sent remote ipv4 route is non best in Leaf 4")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address="123.1.1.0/25",distance="20",
                                cost="0",type="B",selected=sel_key,fib=" "):
        st.error("Step 7 Failed - Verify Leaf 3 sent remote ipv4 route is non best in Leaf 4")
        success = False
    else:
        st.log("Step 7 PASSED - Verify Leaf 3 sent remote ipv4 route is non best in Leaf 4")

    st.log("Step 7: Verify Leaf 3 sent remote ipv6 route is non best in Leaf 4")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address="1230::/98",
                                distance="20",cost="0",type="B",selected=sel_key,fib=" "):
        st.error("Step 7 Failed - Verify Leaf 3 sent remote ipv6 route is non best in Leaf 4")
        success = False
    else:
        st.log("Step 7 PASSED - Verify Leaf 3 sent remote ipv6 route is non best in Leaf 4")

    st.log("Step 7: Verify local Leaf 4 ipv4 route is best compared to remote one")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],
                                nexthop="",
                                ip_address="123.1.1.0/25",distance="1",
                                cost="0",type="S",selected=">",fib="*"):
        st.error("Step 7 Failed - Verify local Leaf 4 ipv4 route is best compared to remote one")
        success = False
    else:
        st.log("Step 7 PASSED - Verify local Leaf 4 ipv4 route is best compared to remote one")

    st.log("Step 7: Verify local Leaf 4 ipv6 route is best compared to remote one")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface="Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],
                                nexthop="",
                                ip_address="1230::/98",
                                distance="1",cost="0",type="S",selected=">",fib="*"):
        st.error("Step 7 Failed - Verify local Leaf 4 ipv6 route is best compared to remote one")
        success = False
    else:
        st.log("Step 7 PASSED - Verify local Leaf 4 ipv6 route is best compared to remote one")

    st.log("### Step 8: Remove static ipv4 and ipv6 route under vrf Vrf1 in Leaf 4 ###")
    ip.delete_static_route(evpn_dict["leaf_node_list"][3],"",
                                "123.1.1.0/25","ipv4","vtysh",
                                "Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],"Vrf1")

    ip.delete_static_route(evpn_dict["leaf_node_list"][3],"",
                                "1230::/98","ipv6","vtysh",
                                "Vlan"+evpn_dict['leaf4']["tenant_l3_vlan_list"][0],"Vrf1")

    st.log("### Step 8: Remove static ipv4 and ipv6 route under vrf Vrf1 in Leaf 3 ###")
    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",
                                "123.1.1.0/25","ipv4","vtysh",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    ip.delete_static_route(evpn_dict["leaf_node_list"][2],"",
                                "1230::/98","ipv6","vtysh",
                                "Vlan"+evpn_dict['leaf3']["tenant_l3_vlan_list"][0],"Vrf1")

    hdrMsg("FtOpSoRoEvpn5549Ft32411 -Verify flap of BGP VRF routes")

    st.log("### Step 9: Verify Leaf 3 tenant IPv4 prefix route in Leaf 4 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at Step 9 - Verify Leaf 3 tenant IPv4 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 9 PASSED - Verify Leaf 3 tenant ipv4 route in Leaf 4")
    st.log("### Step 9: Verify Leaf 3 tenant ipv6 route in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at Step 9 - Verify Leaf 3 tenant IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 9 PASSED - Verify Leaf 3 tenant ipv6 route in Leaf 4")

    st.log("### Step 10: shutdown the TG link to flap tenant routes in Leaf 4 ###")
    #port.shutdown(evpn_dict["leaf_node_list"][2],[evpn_dict["leaf3"]["intf_list_tg"][0]])
    Vlan.delete_vlan_member(evpn_dict["leaf_node_list"][2],
           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True)

    for i in range(10):
        ipv4_entry = ip.fetch_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",select=None,match={"ip_address":evpn_dict["leaf3"]["l3_tenant_ip_net"][0]})
        if len(ipv4_entry) == 1:
            st.log("The IPv4 route entry still exist {}".format(ipv4_entry[0]))
            if i == 9:
                st.error("The IPv4 route is still not removed after waiting for 9 sec since we removed vlan to port binding")
            continue
        else:
            break

    st.log("### Step 10: Verify Leaf 3 tenant IPv4 prefix route in Leaf 4 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.log(" Test Case Step 10 PASSED - Verify Leaf 3 tenant ipv4 route missing in Leaf 4")
    else:
        st.error(" Test Case failed at Step 10 - Verify Leaf 3 tenant IPv4 prefix route present in Leaf 4")
        success = False

    for i in range(10):
        ipv6_entry = ip.fetch_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv6",select=None,match={"ip_address":evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0]})
        if len(ipv6_entry) == 1:
            st.log("The IPv6 route entry still exist {}".format(ipv6_entry[0]))
            if i == 9:
                st.error("The IPv6 route is still not removed after waiting for 9 sec since we removed vlan to port binding")
            continue
        else:
            break

    st.log("### Step 10: Verify Leaf 3 tenant ipv6 route in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.log(" Test Case Step 10 PASSED - Verify Leaf 3 tenant ipv6 route missing in Leaf 4")
    else:
        st.error(" Test Case failed at Step 10 - Verify Leaf 3 tenant IPv6 prefix route present in Leaf 4")
        success = False

    st.log("### Step 11: Startup the TG link after flap tenant routes in Leaf 4 ###")
    #port.noshutdown(evpn_dict["leaf_node_list"][2],[evpn_dict["leaf3"]["intf_list_tg"][0]])
    Vlan.add_vlan_member(evpn_dict["leaf_node_list"][2],
           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True)

    for i in range(10):
        ipv4_entry = ip.fetch_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",select=None,match={"ip_address":evpn_dict["leaf3"]["l3_tenant_ip_net"][0]})
        if len(ipv4_entry) == 0:
            st.wait(1, "The IPv4 route entry {} not exist still in show ip route".format(evpn_dict["leaf3"]["l3_tenant_ip_net"][0]))
            if i == 9:
                st.error("The IPv4 route entry did not pouplate after waiting for 9 sec since we added vlan to port binding")
            continue
        else:
            st.log("The IPv4 route entry got populated - show ip route shows the line {}".format(ipv4_entry[0]))
            break

    st.log("### Step 11: Verify Leaf 3 tenant IPv4 prefix route in Leaf 4 after route flap ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case Step 11 failed - Verify Leaf 3 tenant IPv4 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 11 PASSED - Verify Leaf 3 tenant ipv4 route in Leaf 4 after route flap")

    for i in range(10):
        ipv6_entry = ip.fetch_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv6",select=None,match={"ip_address":evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0]})
        if len(ipv6_entry) == 0:
            st.wait(1, "The IPv6 route entry {} still not exist in show ipv6 route".format(evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0]))
            if i == 9:
                st.error("The IPv6 route entry did not pouplate after waiting for 9 sec since we added vlan to port binding")
            continue
        else:
            st.log("The IPv6 route entry got populated - show ip route shows the line {}".format(ipv6_entry[0]))
            break

    st.log("### Step 11: Verify Leaf 3 tenant ipv6 route in Leaf 4 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case Step 11 failed - Verify Leaf 3 tenant IPv6 prefix route in Leaf 4")
        success = False
    else:
        st.log(" Test Case Step 11 PASSED - Verify Leaf 3 tenant ipv6 route in Leaf 4")

##    st.log("Start L3 IPv4 and IPv6 traffic from Leaf 3 to Leaf 4")
##    start_traffic()

    if verify_traffic():
        st.log("traffic verification passed after L3 VNI config changes")
    else:
        success=False
        st.error("traffic verification failed after L3 VNI config changes")
    current_stream_dict["stream"] = stream_dict["l3"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32410_4")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32410_4")


def test_FtOpSoRoEvpn5549Ft3248_2(Ft3248_fixture):
    hdrMsg("FtOpSoRoEvpn5549Ft3248_2 - Test change/deletion of L3 VNI associated with VRF/AF")
    success = True

#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("Start L3 IPv4 and IPv6 traffic from Leaf 3 to Leaf 4 before TC starts")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    st.log("Step 1: Verify L3 traffic from Leaf 3 to Leaf 4 before TC starts")
    if verify_traffic():
        st.log("traffic verification passed after L3 VNI config changes")
    else:
        success=False
        st.error("traffic verification failed after L3 VNI config changes")

    hdrMsg("Remove Current L3 VNI config - to verify test case id FtOpSoRoEvpn5549Ft3249")

    st.log("Remove Vrf to Vni map outside FRR")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][0],"config":"no", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][0],"config":"no", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["l3_vni_list"][0],
            evpn_dict["leaf3"]["l3_vni_list"][0],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf4"]["l3_vni_list"][0], evpn_dict["leaf4"]["l3_vni_list"][0],"1", "no"]])

    st.log("Delete ipv4 and ipv6 address from L3 VNI VLAN interface")
    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log(" Delete IP address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log(" Delete IPv6 address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Removing Vrf binding for L3 VNI VLAN interface")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf4"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Delete BGP Vrf global config in FRR")
    dict1 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Bgp.config_bgp,[dict1,dict2])

    st.log("Delete Vrf globally outside FRR")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0],"config":"no"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],"config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    if evpn_dict['cli_mode'] != "klish":
        st.log("Delete global Vrf Vni mapping in FRR")
        dict1 = {'config':'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
        dict2 = {'config':'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}
        parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.config_bgp_evpn,[dict1,dict2])

    st.log("### Step 2: Verify Leaf 3 Tenant IPv4 prefix route in Leaf 4 ###")
    if ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error("Step 2 Failed - Verify Leaf 3 tenant IPv4 prefix route in Leaf 4 not installed")
        success = False
    else:
        st.log("Step 2 PASSED:Leaf 3 Tenant IPv4 prefix route not installed in Leaf 4 after L3 VNI removal")

    st.log("### Step 3: Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4 ###")
    if ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error("Step 3 Failed - Verify Leaf 3 Tenant IPv6 prefix route in Leaf 4 not installed")
        success = False
    else:
        st.log("Step 3 PASSED - Leaf 3 Tenant IPv6 prefix route not installed in Leaf 4 after L3 VNI removal")

    hdrMsg("Add New L3 VNI config - to verify test case id FtOpSoRoEvpn5549Ft3248")

    new_vlan = "999"
    st.log("Create a new VLAN 999 to use as L3 VNI VLAN for Vrf")
    utils.exec_all(True,[[Vlan.create_vlan,evpn_dict["leaf_node_list"][2],new_vlan],
            [Vlan.create_vlan,evpn_dict["leaf_node_list"][3],new_vlan]])

    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
            new_vlan, evpn_dict["leaf3"]["intf_list_tg"][0],True],
            [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
            new_vlan, evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Configure user vrf to be mapped to changed L3 VNI VLAN")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0],"config":"yes"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0],"config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":"Vlan"+new_vlan,"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
              "intf_name":"Vlan"+new_vlan,"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Configure IPv4 and IPv6 address for changed L3 VNI VLAN")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+new_vlan, evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+new_vlan, evpn_dict["leaf4"]["l3_vni_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+new_vlan, evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+new_vlan, evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Configure IPv4 and IPv6 address for tenant L3 interfaces")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
            evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
            evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])
    st.log("Configure VLAN to VNI map for changed L3 VNI VLAN")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], new_vlan,
            evpn_dict["leaf3"]["l3_vni_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            new_vlan, evpn_dict["leaf4"]["l3_vni_list"][0]]])

    st.log("Configure VRF to VNI map for changed L3 VNI VLAN")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][0],"config":"yes", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][0],"config":"yes", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Restore VRF to VNI under FRR")
    dict1 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
    dict2 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.config_bgp_evpn,[dict1,dict2])
    st.log("Restore BGP VRF config under FRR")
    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],'addr_family':"ipv6"}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],'addr_family':"ipv6"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    st.log("### Step 4: Verify Leaf 4 tenant IPv4 prefix route in Leaf 3 ###")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+new_vlan,
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],
                                distance="20",cost="0",selected=">",fib="*"):
        st.error(" Test Case failed at Step 4 - Verify Leaf 4 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 4 PASSED - Verify Leaf 4 tenant IPv4 prefix route in Leaf 3")

    st.log("### Step 5: Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3 ###")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface="Vlan"+new_vlan,
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at Step 5 - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 5 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")

    st.log("Step 6: Verify L3 already running traffic Leaf 3 to Leaf 4 after L3 VNI change")
    if verify_traffic():
        st.log("traffic verification passed after L3 VNI config changes")
    else:
        success=False
        st.error("traffic verification failed after L3 VNI config changes")
    current_stream_dict["stream"] = stream_dict["l3"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3248_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3248_2")

def test_FtOpSoRoEvpn5549Ft32217_2(Ft32217_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32217; TC SUMMARY : Test VxLAN for MAC aging and clear MAC \
            TC ID: FtOpSoRoEvpn5549Ft32226; TC SUMMARY : Test Remote macs are not aged out")
    success = True

    ############################################################################################
    hdrMsg(" \n####### Create L2 streams with multiple vlan ids ##############\n")
    ############################################################################################
#    create_stream_l2_multiVlans()

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32218"])
    ############################################################################################
    hdrMsg("\n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    if retry_api(verify_mac_count, vars.D5, mac_count=20, retry_count=3, delay=5):
        st.log("PASS: Mac count in Leaf3 is "+ str(D5_mac_cnt))
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:20. Found: "+ str(D5_mac_cnt))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Configure mac age time in Leaf3 ##############\n")
    ############################################################################################
    Mac.get_mac_agetime(vars.D5)
    Mac.config_mac_agetime(vars.D5,'10')

    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    start_traffic(action='stop', stream_han_list=stream_dict["l2_32218"])
    st.wait(10)

    ############################################################################################
    hdrMsg("\n####### Verify remote macs are not aged out in leaf3 ##############\n")
    ############################################################################################
    st.log('Verify remote macs are aged out in leaf3')
    st.wait(5)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are not aged out as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Start traffic again ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32218"])

    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Verify traffic is not flooded #########\n")
    ############################################################################################
    tg = tg_dict['tg']
    traffic_params = {'1': {'tx_ports' : [tg_dict['d5_tg_port1']], 'tx_obj' : [tg],'exp_ratio' : [0], 'rx_ports' : [tg_dict['d3_tg_port1']], 'rx_obj' : [tg]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_rate', tolernace_factor = '2')

    ############################################################################################
    hdrMsg("\n####### Restore the mac age time in Leaf3 to default ##############\n")
    ############################################################################################
    Mac.get_mac_agetime(vars.D5)
    Mac.config_mac_agetime(vars.D5,'600')

    ############################################################################################
    hdrMsg("\n####### Configure mac age time in Leaf4 to 10 seconds ##############\n")
    ############################################################################################
    Mac.get_mac_agetime(vars.D6)
    Mac.config_mac_agetime(vars.D6,'10')

    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    start_traffic(action='stop', stream_han_list=stream_dict["l2_32218"])
    st.wait(10)

    ############################################################################################
    hdrMsg("\n####### Verify macs are withdrawn from leaf3 after they are aged out from leaf4 ########\n")
    ############################################################################################
    st.log('Verifying mac count in leaf3 after mac age time expiry in leaf4')
    st.wait(10)
    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 0:
        st.log("PASS: All macs learnt from Leaf4 are withdrawn as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:0. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic again ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32218"])

    ############################################################################################
    hdrMsg("\n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: All macs are relearnt from Leaf4 as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Restore mac age time in Leaf4 to default value  ##############\n")
    ############################################################################################
    Mac.get_mac_agetime(vars.D6)
    Mac.config_mac_agetime(vars.D6,'600')

    ############################################################################################
    hdrMsg("\n####### Stop traffic ##############\n")
    ############################################################################################
    start_traffic(action='stop', stream_han_list=stream_dict["l2_32218"])
    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D6)
    st.wait(3)

    ############################################################################################
    hdrMsg("\n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    st.log('Verifying mac count in leaf3 after mac age time expiry in leaf4')
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 0:
        st.log("PASS: All macs learnt from Leaf4 are withdrawn as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:0. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Start bidirectional traffic ##############\n")
    ############################################################################################
    start_traffic(stream_han_list=stream_dict["l2_32218"])

    ############################################################################################
    hdrMsg("\n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: All macs are relearnt from Leaf4 as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n####### Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed ")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["l2_32218"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32217_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32217_2")


@pytest.fixture(scope="function")
def Ft32217_fixture(request,evpn_underlay_hooks):
    success = True
    ############################################################################################
    hdrMsg(" \n####### Create tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"200 210"], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"200 210"]])

    ############################################################################################
    hdrMsg(" \n####### Bind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"200 210",evpn_dict["leaf3"]["intf_list_tg"][0]], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"200 210",evpn_dict["leaf4"]["intf_list_tg"][0]]])

    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "200","200",'10'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'10']]):
        st.log('Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')

    yield

    hdrMsg("### CLEANUP for 32217 ###")
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
#    delete_host()
#    st.log("Reset TGEN")
#    reset_tgen()

    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "200","200",'10','no'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'10','no']]):
        st.log('Vlan to Vni mapping is deleted.')
    else:
        success=False
        st.error('FAIL: Removal of Vlan to Vni mapping failed even after vlan is created.')

    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"200 210",evpn_dict["leaf3"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"200 210",evpn_dict["leaf4"]["intf_list_tg"][0],'del']])

    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"200 210",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"200 210",'del']])


def test_FtOpSoRoEvpn5549Ft32421_3(Ft32215_fixture):
    success = True
    tc_list = ["test_FtOpSoRoEvpn5549Ft32421","test_FtOpSoRoEvpn5549Ft32422","test_FtOpSoRoEvpn5549Ft32423"]
    tc_list_summary = ["Verify IMR generation and Tunnel Membership with IPv4 Prefix route",
                       "Verify IMR generation and Tunnel Membership with IPv6 Prefix route",
                       "Verify IMR generation and Tunnel VLAN membership with RT modification"]

    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")
    ipv4_nw_1 = evpn_dict["leaf3"]["loop_ip_list"][1]
    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    tx_port=vars.T1D5P1
    rx_port=vars.T1D6P1

    hdrMsg(" STEP:1  Make sure the Vxlan tunnel is up before proceeding with the test case")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                                       src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                       rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                       exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is NOT UP in leaf3 before starting the test case")
        success = False
    else:
        st.log("VXLAN tunnel is UP as expected in leaf1")

#    create_stream("l2")
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("start traffic from first tgen port of Leaf3 and Leaf4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("verify traffic received in first tgen port of Leaf3 and Leaf4")
    if verify_traffic():
        st.log("traffic verification passed")
    else:
        success = False
        st.error("traffic verification failed before before the start of the test case")

    hdrMsg(" STEP:2  Remove both L2vni config from Leaf 3 & leaf 4 the nodes")
    cleanup_l2vni_Leaf_3_4()

    hdrMsg(" STEP:3  Verify L2vni multicast(IMR) routes are deleted from the nodes")
    dut = evpn_dict["leaf_node_list"][3]
    dict = {'evpn_type_3_prefix': "[3]:[0]:[32]:[" + ipv4_nw_1 + "]", 'status_code': "*>",
            'next_hop': evpn_dict["leaf3"]["loop_ip_list"][1]}
    if utils_obj.retry_parallel(Evpn.verify_bgp_l2vpn_evpn_route_type_multicast, dut_list=[dut],
                                    dict_list=[dict], api_result=False, retry_count=3, delay=2):
        st.error("IMR routes: {} is still present in the evpn table after deleting the L2vni config".format(ipv4_nw_1))
    else:
        st.log("As expected IMR route is not present after removing the L2 VNI config")

    hdrMsg(" STEP:4 Delete the Ipv6 prefix routes and verify the tunnel is up with Ipv4 prefix routes")
    l3vni_Ipv6_del()

    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                                       src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                       rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                       exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3 after removing the Ipv6 prefix routes")
        success=False

    hdrMsg(" STEP:5  Verify only prefix route is present and no IMR route in the evpn table\n")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                                                 evpn_type_5_prefix="[5]:[0]:[24]:[" + ipv4_nw[0] + "]",
                                                 status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni prefix routes: {} are not present in the evpn table".format(ipv4_nw[0]))

    if  Evpn.verify_bgp_l2vpn_evpn_route_type_multicast(dut=evpn_dict["leaf_node_list"][3],
                                        evpn_type_3_prefix="[3]:[0]:[32]:[" + ipv4_nw_1 + "]",
                                        status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("IMR routes: {} is present in the evpn table after configuring the L3vni config".format(ipv4_nw_1))

    else:
        st.log("As expected IMR route is not present after removing the L3 VNI config")

    st.log("start Ipv4 traffic only after removing L2vni & Ipv6 L3vni prefix routes from Leaf3 to Leaf4")

    st.log("verify traffic received in first tgen port of Leaf3 and Leaf4")
    if verify_traffic(tx_port, rx_port,tx_ratio=0.666,rx_ratio=0.666):
        st.log("traffic verification passed after removing L2vni & Ipv6 L3vni prefix routes from Leaf3 to Leaf4")
    else:
        success = False
        st.error(
            "traffic verification failed after removing L2vni & Ipv6 L3vni prefix routes from Leaf3 to Leaf4")

    hdrMsg(" STEP:6  Now remove L3 vni and verify Vxlan tunnel comes up with L2 vni IMR route#####\n")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config='remove_vni',
                         config_type_list=["vrf_vni"],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf3"]["vtepName"])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='remove_vni',
                         config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf4"]["vtepName"])

    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                         src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                         exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3")
        success=False

    hdrMsg(" STEP:7  Verify prefix routes are removed")
    if Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[24]:[" + ipv4_nw[0] + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni prefix routes: {} is still present in the evpn table even after deleting the L3vni config".format(ipv4_nw[0]))

    else:
        st.log("As expected Prefix route is not present after removing the L3 VNI config")

    hdrMsg(" STEP:8  Verify IMR route is present")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_multicast(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_3_prefix="[3]:[0]:[32]:[" + ipv4_nw_1 + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("IMR routes: {} is not present in the evpn table after deleting the L3vni config".format(ipv4_nw_1))

    hdrMsg(" STEP:9 Add back the l3 vni config and verify IMR routes are withdrawn and prefix routes are installed back")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf3"]["vtepName"])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf4"]["vtepName"])

    hdrMsg(" STEP:10 Verify the tunnel is up with prefix routes only")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                        src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                        rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                        exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3 after adding the L3vni config back")
        success=False

    hdrMsg(" STEP:11   Verify IMR route should not be present after adding the L3 vni config")
    if Evpn.verify_bgp_l2vpn_evpn_route_type_multicast(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_3_prefix="[3]:[0]:[32]:[" + ipv4_nw_1 + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("IMR routes: {} is still present in the evpn table after adding the L3vni config".format(ipv4_nw_1))

    else:
        st.log("As expected IMR route is not present after removing the L3 VNI config")

    st.log("Check Ipv4 traffic & verify only after removing flapping the L2vni &  L3vni prefix routes from Leaf3 to Leaf4")

    if verify_traffic(tx_port, rx_port,tx_ratio=0.666,rx_ratio=0.666):
        st.log("traffic verification passed after flapping the L2vni &  L3vni prefix routes from Leaf3 to Leaf4")
    else:
        success = False
        st.error(
            "traffic verification failed flapping the L2vni &  L3vni prefix routes from Leaf3 to Leaf4")

    hdrMsg(" STEP:12  Remove the Ipv4 address and add Ipv6 address, verify the tunnel is Up with V6 prefixes")
    l3vni_Ipv4_del()
    l3vni_Ipv6_add()

    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                        src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                        rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                        exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3")
        success=False

    hdrMsg(" STEP:13  Verify Ipv6 prefix route is present in the evpn table\n")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                        evpn_type_5_prefix="[5]:[0]:[96]:[" + ipv6_nw[0] + "]",
                        status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni Ipv6 prefix routes: {} are not present in the evpn table".format(ipv6_nw[0]))

    st.log("Verify Ipv6 traffic after removing L2vni & Ipv4 L3vni prefix routes from Leaf3 to Leaf4")

    if verify_traffic(tx_port, rx_port,tx_ratio=0.666,rx_ratio=0.666):
        st.log("traffic verification passed after removing L2vni & Ipv4 L3vni prefix routes from Leaf3 to Leaf4")
    else:
        success = False
        st.error(
            "traffic verification failed after removing L2vni & Ipv4 L3vni prefix routes from Leaf3 to Leaf4")

    hdrMsg(" STEP:14  Now remove L3 vni with Ipv6 prefix route and verify Vxlan tunnel comes up with L2 vni IMR route")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config='remove_vni', config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf3"]["vtepName"])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='remove_vni', config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf4"]["vtepName"])

    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                         src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                         exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3")
        success = False

    hdrMsg(" STEP:15  Verify prefix routes are removed")
    if Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_5_prefix="[5]:[0]:[96]:[" + ipv6_nw[0] + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni Ipv6 prefix routes: {} are  present in the evpn table after removing L3vni config".format(ipv6_nw[0]))

    else:
        st.log("As expected Prefix route is not present after removing the L3 VNI config")

    hdrMsg(" STEP:16  Verify IMR route is present")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_multicast(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_3_prefix="[3]:[0]:[32]:[" + ipv4_nw_1 + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("IMR routes: {} is not present in the evpn table after deleting the L3vni config".format(ipv4_nw_1))

    hdrMsg(" STEP:17 Add back the l3 vni config and verify IMR routes are withdrawn and prefix routes are installed back")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf3"]["vtepName"])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config_type_list=["vrf_vni"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf3"]["l3_vni_list"][0], vtep_name=evpn_dict["leaf4"]["vtepName"])

    hdrMsg(" STEP:18 Verify the tunnel is up with Ipv6 prefix routes only")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                         src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                         rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                         exp_status_list=['oper_up'], delay=2, retry_count=3):
        st.error("VXLAN tunnel is down on leaf3 after adding the L3vni config back with Ipv6 prefix route")
        success = False

    hdrMsg(" STEP:19 Verify IMR route should not be present after adding the L3 vni config")
    if Evpn.verify_bgp_l2vpn_evpn_route_type_multicast(dut=evpn_dict["leaf_node_list"][3],
                         evpn_type_3_prefix="[3]:[0]:[32]:[" + ipv4_nw_1 + "]",
                         status_code="*>", next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("IMR routes: {} is still present in the evpn table after adding the L3vni config".format(ipv4_nw_1))

    else:
        st.log("As expected IMR route is not present after removing the L3 VNI config")

    st.log("Verify Ipv4 traffic & verify only after removing flapping the L2vni &  Ipv4 L3vni prefix routes from Leaf3 to Leaf4")

    if verify_traffic(tx_port, rx_port,tx_ratio=0.666,rx_ratio=0.666):
        st.log("traffic verification passed after flapping the L2vni &  Ipv4 L3vni prefix routes from Leaf3 to Leaf4")
    else:
        success = False
        st.error(
            "traffic verification failed flapping the L2vni &  Ipv4 L3vni prefix routes from Leaf3 to Leaf4")
    current_stream_dict["stream"] = stream_dict["all"]

    l3vni_Ipv4_add()
    add_l2vni_Leaf_3_4()

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32421_3")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32421_3")

def test_FtOpSoRoEvpn5549Ft32220(Ft32215_fixture):

    tg = tg_dict['tg']
    success = True
    st.log("### Test VxLAN for dynamic MAC movement ###")
    st.log("### start L2 traffic from first tgen port of Leaf3 and Leaf4 ###")
    s1 = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"], mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],
                              rate_pps=1000, mode='create', port_handle=tg_dict["d5_tg_ph1"], l2_encap='ethernet_ii',
                              vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                              mac_src_count=10, mac_dst_count=10, mac_src_mode="increment", mac_dst_mode="increment",
                              mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    s2 = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"],
                              rate_pps=1000, mode='create', port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii',
                              vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                              mac_src_count=10, mac_dst_count=10, mac_src_mode="increment", mac_dst_mode="increment",
                              mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    s3=tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"], mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],
                         rate_pps=1000, mode='create', port_handle=tg_dict["d4_tg_ph1"], l2_encap='ethernet_ii',
                         vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                         mac_src_count=10, mac_dst_count=10, mac_src_mode="increment", mac_dst_mode="increment",
                         mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")

    tg.tg_traffic_control(action="run", stream_handle=[stream_dict["l2_32220_1"],stream_dict["l2_32220_2"]])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    st.log("### verify evpn remote mac table in Leaf2 and Leaf4 ###")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        st.error("########## MACs from leaf3 not learned in leaf4, failed ##########")
    else:
        st.log("##### MACs from leaf3 learned successfully in leaf4, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        st.error("########## MACs from leaf3 not learned in leaf2, failed ##########")
    else:
        st.log("##### MACs from leaf3 learned successfully in leaf2, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        st.error("########## MACs from leaf4 not learned in leaf2, failed ##########")
    else:
        st.log("##### MACs from leaf4 learned successfully in leaf2, passed #####")

    st.log("### verify traffic received in first tgen port of Leaf3 and Leaf4 ###")
    if verify_traffic():
        st.log("##### traffic verification passed before dynamic mac movement #####")
    else:
        success=False
        st.error("########## traffic verification failed before dynamic mac movement ##########")

    st.log("### stop the traffic started in Leaf3 ###")
    tg.tg_traffic_control(action="stop",stream_handle=stream_dict["l2_32220_1"])

    st.log("### start Leaf3's same traffic from Leaf2 ###")
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32220_3"])
    if vars.tgen_list[0] == 'stc-01':
        st.wait(10)
    st.log("### verify evpn remote mac table after mac movement ###")
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][1], min_total_count="10",
                                         retry_count=3, delay=2):
        success = False
        st.error("########## leaf2 not advertising the moved MACs of leaf3 to leaf4, failed ##########")
    else:
        st.log("##### MACs moved from leaf3, now advertised by leaf2 to leaf4, passed #####")

    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][1],
                                         mac=evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                         retry_count=3, delay=2):
        success = False
        st.error("########## Mac {} not advertised by leaf2 to leaf4, failed ##########"
                 .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        st.log("##### Mac {} advertised by leaf2 to leaf4, passed #####"
               .format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))

    if Evpn.verify_bgp_l2vpn_evpn_route_type_macip(dut=vars.D6, evpn_type_2_prefix="[2]:[0]:[48]:["+
                                           evpn_dict["leaf3"]["tenant_mac_l2_colon"]+"]",
                                           status_code="*>", next_hop=evpn_dict["leaf2"]["loop_ip_list"][1]):
        st.log("nexthop for MAC {} updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                     evpn_dict["leaf2"]["loop_ip_list"][1]))
    else:
        success=False
        st.error("nexthop for MAC {} not updated correctly with {}".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                                                           evpn_dict["leaf2"]["loop_ip_list"][1]))

    '''
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D6, vni=evpn_dict["leaf4"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], total_count="1",
                                         retry_count=3, delay=2):
        success = False
        st.error("########## leaf3 still advertising the moved mac to leaf4, failed ##########")
    else:
        st.log("##### No MACs are advertised by leaf3 to leaf4 now as expected, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["l3_vni_list"][0],
                                         vlan=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                         rvtep=evpn_dict["leaf3"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf3"]["loop_ip_list"][1], total_count="1"):
        success = False
        st.error("########## leaf3 still advertising the moved mac to leaf2, failed ##########")
    else:
        st.log("##### leaf3 not advertising the moved mac to leaf2 as expected, passed #####")
    '''
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D4, vni=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf2"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        st.error("########## leaf4 MACs are not learned in leaf2, failed ##########")
    else:
        st.log("##### leaf4 MACs are learned in leaf2 as expected, passed #####")
    if not Evpn.verify_vxlan_evpn_remote_mac_id(dut=vars.D5, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf4"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf4"]["loop_ip_list"][1], min_total_count="10"):
        success = False
        st.error("########## leaf4 MACs are not learned in leaf3, failed ##########")
    else:
        st.log("##### leaf4 MACs are learned successfully in leaf3, passed #####")
    if not retry_api(Evpn.verify_vxlan_evpn_remote_mac_id,vars.D5, vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                         vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0],
                                         rvtep=evpn_dict["leaf2"]["loop_ip_list"][1], type="dynamic",
                                         identifier=evpn_dict["leaf2"]["loop_ip_list"][1], min_total_count="10",
                                         retry_count=3, delay=2):
        success = False
        st.error("########## leaf2 not advertising moved MACs to leaf3, failed ##########")
    else:
        st.log("##### leaf2 advertising moved MACs to leaf3 as expected, passed #####")

    st.log("### verify no traffic received in leaf3 ###")
    result = tg.tg_traffic_stats(port_handle=tg_dict["d5_tg_ph1"], mode="aggregate")
    if vars.tgen_list[0] == 'stc-01':
        rx_rate = int(result[tg_dict["d5_tg_ph1"]]['aggregate']['rx']['pkt_rate'])
    elif vars.tgen_list[0] == 'ixia-01':
        rx_rate = int(result[tg_dict["d5_tg_ph1"]]['aggregate']['rx']['raw_pkt_rate'])
    else:
        rx_rate = 10

    if rx_rate >= 0 and rx_rate < 50:
        st.log("##### NO traffic received in leaf3 as expected, passed #####")
    else:
        success=False
        st.error("########## some traffic still coming to leaf3 which is not expected, failed ##########")
        st.exec_all([[Mac.get_mac,vars.D4],[Mac.get_mac,vars.D5],[Mac.get_mac,vars.D6]])
    if verify_traffic(tg_dict["d4_tg_port1"], tg_dict["d6_tg_port1"]):
        st.log("##### traffic verification passed after dynamic mac movement #####")
    else:
        success=False
        st.error("########## traffic verification failed after dynamic mac movement ##########")

    tg.tg_traffic_control(action="stop", stream_handle=[stream_dict["l2_32220_2"],stream_dict["l2_32220_3"]])

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32220")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32220")

@pytest.mark.new
def test_FtOpSoRoEvpn5549Ft3213(Ft32215_fixture):
    success = True
    st.log("### Test VxLAN by removing and adding back NVO name ###")
    if evpn_dict['cli_mode'] != "klish":
        st.log("### start traffic from first tgen port of Leaf3 and Leaf4 ###")
        tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
        tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
        tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
        tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
        start_traffic(stream_han_list=stream_dict["all"])

        st.log("### remove NVO from Leaf3 ###")
        output = Evpn.create_evpn_instance(vars.D5, evpn_dict["leaf3"]["nvoName"],
                             evpn_dict["leaf3"]["vtepName"], 'no',True)
        if "Error: Please delete all VLAN VNI mappings" not in str(output):
            success = False
            st.error("########## NVO deletion happens though VLAN VNI mappings exist, failed ##########")
        else:
            st.log("##### NVO deletion fails as expected, passed #####")

        st.log("### remove the L2VNI and L3VNI configs ###")
        Evpn.map_vrf_vni(vars.D5, evpn_dict["leaf3"]["vrf_name_list"][0],
                     evpn_dict["leaf3"]["l3_vni_list"][0], "no", vtep_name=evpn_dict["leaf3"]["vtepName"])
        for vlan,vni in zip([evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf3"]["l3_vni_list"][0]],
                        [evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf3"]["l3_vni_list"][0]]):
            Evpn.map_vlan_vni(vars.D5, evpn_dict["leaf3"]["vtepName"], vlan, vni,"1","no")
        output = Evpn.create_evpn_instance(vars.D5, evpn_dict["leaf3"]["nvoName"],
                                      evpn_dict["leaf3"]["vtepName"], 'no',True)
        if "Error: Please delete all VLAN VNI mappings" in str(output):
            success = False
            st.error("########## NVO deletion failed even after removing VLAN VNI mappings ##########")
        else:
            st.log("##### NVO deletion passed #####")

        st.log("### check tunnel status in Leaf3 and Leaf4 ###")
        if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1],
                                                          evpn_dict["leaf2"]["loop_ip_list"][1],
                                                          evpn_dict["leaf4"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_down'] * 3):
            st.log("##### VxLAN tunnel not exists as expected in Leaf3, passed #####")
        else:
            success = False
            st.error("########## Failed to remove xLAN tunnel in Leaf3, failed ##########")

        st.log("### check tunnel status in anyone of remote VTEP say Leaf4 ###")
        if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                                           src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_down']):
            st.log("##### In leaf4, VxLAN tunnel towards Leaf3 not exists as expected, passed #####")
        else:
            success = False
            st.error("########## In Leaf4, VxLAN tunnel towards leaf3 exists, failed ##########")

        if not verify_traffic():
            st.log("##### traffic verification failed after removing NVO as expected, passed #####")
        else:
            success=False
            st.error("########## traffic is still forwarded even after removing NVO, failed ##########")

        st.log("### Add back L2VNI and L3VNI configs ###")
        Evpn.create_evpn_instance(vars.D5, evpn_dict["leaf3"]["nvoName"],evpn_dict["leaf3"]["vtepName"])
        for vlan,vni in zip([evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf3"]["l3_vni_list"][0]],
                        [evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],evpn_dict["leaf3"]["l3_vni_list"][0]]):
            Evpn.map_vlan_vni(vars.D5, evpn_dict["leaf3"]["vtepName"], vlan, vni)
        Evpn.map_vrf_vni(vars.D5, evpn_dict["leaf3"]["vrf_name_list"][0], evpn_dict["leaf3"]["l3_vni_list"][0]
                     , vtep_name=evpn_dict["leaf3"]["vtepName"])

        st.log("### check tunnel status again in Leaf3 and Leaf4 ###")
        if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                 src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1],
                                evpn_dict["leaf2"]["loop_ip_list"][1],
                                evpn_dict["leaf4"]["loop_ip_list"][1]],
                 exp_status_list=['oper_up']*3,retry_count=3, delay=5):
            st.log("##### VxLAN tunnel is UP now as expected in Leaf3, passed #####")
        else:
            success = False
            st.error("########## Failed to bring UP VxLAN tunnel in Leaf3, failed ##########")

        st.log("### check tunnel status again in anyone of remote VTEP say Leaf4 ###")
        if Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                                           src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1],
                                                          evpn_dict["leaf2"]["loop_ip_list"][1],
                                                          evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 3):
            st.log("##### VxLAN tunnel is UP now as expected in leaf4, passed #####")
        else:
            success = False
            st.error("########## VxLAN tunnel is DOWN now in leaf4, failed ##########")

        st.wait(10)
        if verify_traffic():
            st.log("##### traffic verification passed after adding back NVO #####")
        else:
            success=False
            st.error("########## traffic verification failed after adding back NVO ##########")
    else:
        hdrMsg("This testcase doesn't support klish cli_mode for now so skipping it and reporting as pass now")
    current_stream_dict["stream"] = stream_dict["all"]

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3213")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3213")


def test_FtOpSoRoEvpn5549Ft32216(Ft32215_fixture):
    success = True
    st.log("########## Test VxLAN for broadcast traffic ##########")
    tg = tg_dict['tg']
    tg.tg_traffic_control(action="run", stream_handle=stream_dict["l2_32216"])
    st.wait(5)
    st.log("########## verify leaf2 and leaf4 receives broadcast traffic ##########")
    traffic_details = {
        '1': {
        'tx_ports': [tg_dict['d5_tg_port1']],
        'tx_obj': [tg],
        'exp_ratio': [1],
        'rx_ports': [tg_dict['d4_tg_port1'], tg_dict['d6_tg_port1']],
        'rx_obj': [tg, tg],
        }
    }
    if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",
                         tolerance_factor=2):
        st.log("########## broadcast traffic flooded to both leaf2 and leaf4, passed ##########")
    else:
        success=False
        st.log("########## FAIL: broadcast traffic not flooded to leaf2 and/or leaf4, failed ##########")

    st.log("########## remove the L2VNI from leaf4 ##########")
    Evpn.map_vlan_vni(vars.D6, evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], "1", "no")

    st.log("########## verify leaf3's mac not present now in leaf4 ##########")
    param_dict = {'vni':evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
            'vlan':evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
            'rvtep':evpn_dict["leaf3"]["loop_ip_list"][1],
            'type':"dynamic",
            'identifier':evpn_dict["leaf3"]["loop_ip_list"][1],
            'mac':evpn_dict["leaf3"]["tenant_mac_l2_colon"]}
    if not utils_obj.retry_parallel(Evpn.verify_vxlan_evpn_remote_mac_id, dut_list=[vars.D6], dict_list=[param_dict],
                     api_result=False, retry_count=3, delay=3):
        st.log("########## Mac {} not present in leaf4 as expected, passed "
               "##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        success=False
        st.log("########## FAIL: Mac {} still present in leaf4, failed "
           "##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))

    st.log("########## verify leaf4 not receiving broadcast traffic ##########")
    traffic_details1 = {
        '1': {
            'tx_ports': [tg_dict['d5_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [tg_dict['d4_tg_port1']],
            'rx_obj': [tg],
        },
        '2': {
            'tx_ports': [tg_dict['d5_tg_port1']],
            'tx_obj': [tg],
            'exp_ratio': [0],
            'rx_ports': [tg_dict['d6_tg_port1']],
            'rx_obj': [tg],
        }
    }

    if validate_tgen_traffic(traffic_details=traffic_details1, mode="aggregate", comp_type="packet_rate",
                         tolerance_factor=2):
        st.log("########## broadcast traffic verification passed after removing L2VNI from leaf4 ##########")
    else:
        success=False
        st.log("########## FAIL: broadcast traffic verification failed after removing L2VNI from leaf4 ##########")

    st.log("########## Add back the L2VNI in leaf4 ##########")
    Evpn.map_vlan_vni(vars.D6, evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf4"]["tenant_l2_vlan_list"][0])
    st.wait(10)

    st.log("########## verify broadcast traffic after adding back L2VNI in leaf4 ##########")
    if validate_tgen_traffic(traffic_details=traffic_details, mode="aggregate", comp_type="packet_rate",
                         tolerance_factor=2):
        st.log("########## broadcast traffic flooded to both leaf2 and leaf4, passed ##########")
    else:
        success = False
        st.log("########## FAIL: broadcast traffic not flooded to leaf2 and/or leaf4, failed ##########")
    current_stream_dict["stream"] = stream_dict["l2_32216"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32216")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32216")

def test_FtOpSoRoEvpn5549Ft32412(Ft32215_fixture):
    success = True
    hdrMsg("FtOpSoRoEvpn5549Ft32412 - Verify importing Routes via EVPN")

    st.log("Start L3 IPv4 and IPv6 traffic b/w L3 to L4 for Vrf1")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_dict["l3"])

    st.log("Step 1: Verify L3 traffic from b/w L3 to L4 for Vrf1")
    if verify_traffic():
        st.log("traffic verification passed b/w L3 to L4 for Vrf1")
    else:
        success=False
        st.error("traffic verification failed b/w L3 to L4 for Vrf1")
    start_traffic(action="stop", stream_han_list=stream_dict["l3"])

    st.log("Step 2: create VLANs for L3VNI on all leaf nodes")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1]]])

    st.log("Step 2: Bind L3VNI VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 2: Bind tenant L3 VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 2: Configure user vrf to be mapped to new L3 VNI VLAN")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1],"config":"yes"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1],"config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Step 2: Configure IPv4 and IPv6 address for new L3 VNI VLAN")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ip_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ip_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 2: Assign IP address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][1], evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][1], evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    st.log("Step 2: Assign IPv6 address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 2: Configure VLAN to VNI map for new L3 VNI VLAN")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"],evpn_dict["leaf1"]["l3_vni_list"][1],
            evpn_dict["leaf3"]["l3_vni_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["l3_vni_list"][1], evpn_dict["leaf4"]["l3_vni_list"][1]]])

    st.log("Step 2: Configure VRF to VNI map for new L3 VNI VLAN")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][1],"config":"yes", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][1],"config":"yes", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    if evpn_dict['cli_mode'] != "klish":
        st.log("Step 2: Configure VRF to VNI under FRR")
        dict1 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][1], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
        dict2 = {'config':'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][1], "vtep_name":evpn_dict["leaf4"]["vtepName"]}
        parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.config_bgp_evpn,[dict1,dict2])

    st.log("Step 2: Configure BGP VRF config under FRR")
    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1],'addr_family':"ipv6"}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1],'addr_family':"ipv6"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][1],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][1],
                                distance="20",cost="0",selected=">",fib="*"):
        st.error(" Test Case failed at Step 3 - Verify Leaf 4 tenant IPv4 prefix route in Vrf2")
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Verify Leaf 4 tenant IPv4 prefix route in Leaf 3 in Vrf2")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][1],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at Step 3 - Verify L3 VNI IPv6 prefix route in Leaf 4 in Vrf2")
        success = False
    else:
        st.log(" Test Case Step 3 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 4 in Vrf2")

    st.log("Step 4: Configure dynamic route leak for vrf2 route in vrf1 under FRR in leaf 3")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                          vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                          import_vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],config_type_list =["import_vrf"],config="yes")

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                          vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family='ipv6',
                          import_vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],config_type_list =["import_vrf"],config="yes")

    st.log("Step 4: Configure dynamic route leak for vrf1 route in vrf2 under FRR in leaf 4")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],local_as=evpn_dict['leaf4']['local_as'],
                          vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                          import_vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],config_type_list =["import_vrf"],config="yes")

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],local_as=evpn_dict['leaf4']['local_as'],
                          vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],addr_family='ipv6',
                          import_vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],config_type_list =["import_vrf"],config="yes")

    hdrMsg("Step 4: Send IPv4 & IPv6 L3 bi-directional traffic b/w L3 to L4 with L3 src addr in {} and L4 src addr in {}"
            .format(evpn_dict["leaf3"]["vrf_name_list"][0],evpn_dict["leaf4"]["vrf_name_list"][1]))
    hdrMsg("Stream1:IPv4 Src adr 50.1.1.101, IPv4 Dst adr 60.1.2.100 in VLAN {} from Leaf3"
            .format(evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]))
    hdrMsg("Stream2:IPv4 Src adr 60.1.2.100, IPv4 Dst adr 50.1.1.101 in VLAN {} from Leaf4"
            .format(evpn_dict["leaf4"]["tenant_l3_vlan_list"][1]))
    hdrMsg("Stream3:IPv6 Src adr 5001::101, IPv6 Dst adr 6002::100 in VLAN {} from Leaf3"
            .format(evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]))
    hdrMsg("Stream4:IPv6 Src adr 6002::100, IPv6 Dst adr 5001::101 in VLAN {} from Leaf4"
            .format(evpn_dict["leaf4"]["tenant_l3_vlan_list"][1]))
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_1_32412"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_2_32412"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_1_32412"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_2_32412"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3_32412"])

    st.log("Step 4: Verify L3 Bi-directional IPv4 and IPv6 traffic b/w L3 and L4 with dest adr pointing to leaked route")
    if verify_traffic():
        st.log("Pass: One of Bi-directional IPv4 and IPv6 traffic streams b/w L3 and L4 with leak route")
    else:
        success=False
        st.error("Fail: One of Bi-directional IPv4 and IPv6 traffic streams b/w L3 and L4 with leak route")

    st.log("Step 5: Verify the leaked ipv4 and ipv6 route in Vrf2 in Leaf 4")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],
                                distance="200",cost="0",selected=">",type="B",fib="*"):
        st.error("Failed Step 5 - Verify Vrf1 import/leaked Leaf 4 tenant IPv4 prefix route in Vrf2")
        success = False
    else:
        st.log("Step 5 PASSED - Verify Vrf1 import/leaked Leaf 4 tenant IPv4 prefix route in Vrf2")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="200",cost="0",type="B",selected=">",fib="*"):
        st.error("Failed Step 5 - Verify Vrf Vrf1 import/leaked L3 VNI IPv6 prefix route in Vrf2")
        success = False
    else:
        st.log("Step 5 PASSED - Verify Vrf Vrf1 import/leaked L3 VNI IPv6 prefix route in Vrf2")

    st.log("Step 6: Remove vrf1 import route in vrf1 under FRR in leaf 3")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                          vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                          import_vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],config_type_list =["import_vrf"],config="no")

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                          vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family='ipv6',
                          import_vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],config_type_list =["import_vrf"],config="no")

    st.log("Step 6: Remove vrf1 import route in vrf2 under FRR in leaf 4")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],local_as=evpn_dict['leaf4']['local_as'],
                          vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                          import_vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],config_type_list =["import_vrf"],config="no")

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],local_as=evpn_dict['leaf4']['local_as'],
                          vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],addr_family='ipv6',
                          import_vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],config_type_list =["import_vrf"],config="no")

    if ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                shell="vtysh",family="ipv4",type="B",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],
                                distance="200",cost="0",selected=">",fib="*"):
        st.error("Failed Step 6 - Verify Vrf1 import/leaked Leaf 4 tenant IPv4 prefix route in Vrf2 is still there even after deletion")
        success = False
    else:
        st.log("Step 6 PASSED - Verify Vrf1 import/leaked Leaf 4 tenant IPv4 prefix route in Vrf2 not there after removing the route leak")

    if ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="200",cost="0",type="B",selected=">",fib="*"):
        st.error("Failed Step 6 - Verify Vrf Vrf1 import/leaked L3 VNI IPv6 prefix route in Vrf2 is still there even after deletion")
        success = False
    else:
        st.log("Step 6 PASSED - Verify Vrf Vrf1 import/leaked L3 VNI IPv6 prefix route in Vrf2 not there after removing the route leak")

    st.log("Step 7: Remove Vrf to Vni map outside FRR")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][1],"config":"no", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][1],"config":"no", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Step 7: Remove Vlan to Vni map")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["l3_vni_list"][1],
            evpn_dict["leaf3"]["l3_vni_list"][1],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["l3_vni_list"][1],"1", "no"]])

    st.log("Step 7: Delete ipv4 and ipv6 address from L3 VNI VLAN interface")
    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ip_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ip_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 7: Delete IP address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][1], evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][1], evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    st.log("Step 7: Delete IPv6 address to L3 tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 7: Removing Vrf binding for L3 VNI VLAN interface")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf4"]["l3_vni_name_list"][1],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Step 7: Delete BGP Vrf global config in FRR")
    dict1 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Bgp.config_bgp,[dict1,dict2])

    st.log("Step 7: Delete global Vrf Vni mapping in FRR")
    dict1 = {'config':'remove_vrf','config_type_list':["vrf_vni"],
            'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1],
            'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][1], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
    dict2 = {'config':'remove_vrf','config_type_list':["vrf_vni"],
            'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1],
            'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][1], "vtep_name":evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
        Evpn.config_bgp_evpn,[dict1,dict2])

    st.log("Step 7: Delete Vrf globally outside FRR")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1],"config":"no"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1],"config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    st.log("Step 7: Remove L3 VNI VLAN binding for new Vrf2 in leaf 3 and leaf4")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 7: Remove tenant L3 VLAN binding for new Vrf2 in leaf 3 and leaf4")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 7: Delete L3 VNI VLAN used for new Vrf2 in leaf 3 and leaf4")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1]]])
    current_stream_dict["stream"] = stream_dict["l3_32412"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32412")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32412")

def test_FtOpSoRoEvpn5549Ft32426(Ft32215_fixture):
    success = True
    hdrMsg("FtOpSoRoEvpn5549Ft32426 - Verify traffic with duplicate ip across VRF")

#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
    st.log("Start L3 IPv4 and IPv6 traffic b/w L3 to L4 for Vrf1")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    st.log("Step 1: Verify L3 traffic from b/w L3 to L4 for Vrf1")
    if verify_traffic():
        st.log("traffic verification passed b/w L3 to L4 for Vrf1")
    else:
        success=False
        st.error("traffic verification failed b/w L3 to L4 for Vrf1")
    start_traffic(action="stop", stream_han_list=stream_dict["l3"])

    st.log("Step 1: create VLANs for L3VNI on all leaf nodes")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1]]])

    st.log("Step 1: Bind L3VNI VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 1: Bind tenant L3 VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 1: Configure user vrf to be mapped to new L3 VNI VLAN")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1],"config":"yes"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1],"config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"yes"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Step 1: Configure IPv4 and IPv6 address for new L3 VNI VLAN")
    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ip_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ip_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    utils.exec_all(True,[[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 1: Assign IP address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log("Step 1: Assign IPv6 address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Step 1: Configure VLAN to VNI map for new L3 VNI VLAN")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"],evpn_dict["leaf1"]["l3_vni_list"][1],
            evpn_dict["leaf3"]["l3_vni_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["l3_vni_list"][1], evpn_dict["leaf4"]["l3_vni_list"][1]]])

    st.log("Step 1: Configure VRF to VNI map for new L3 VNI VLAN")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][1],"config":"yes", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][1],"config":"yes", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Step 1: Configure BGP VRF config under FRR")
    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1],'addr_family':"ipv6"}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1],'addr_family':"ipv6"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Bgp.config_bgp, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    dict1 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4], Evpn.config_bgp_evpn, [dict1,dict2])

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                vrf_name=evpn_dict["leaf3"]["vrf_name_list"][1],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf3"]["l3_vni_name_list"][1],
                                nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf4"]["l3_tenant_ip_net"][0],
                                distance="20",cost="0",selected=">",fib="*"):
        st.error("Failed Step 2 - Verify Leaf 4 tenant IPv4 prefix route in Vrf2")
        success = False
    else:
        st.log("Step 2 PASSED - Verify Leaf 4 tenant IPv4 prefix route in Leaf 3 in Vrf2")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][1],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error("Failed at Step 2 - Verify L3 VNI IPv6 prefix route in Leaf 4 in Vrf2")
        success = False
    else:
        st.log("Step 2 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 4 in Vrf2")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],
                                distance="20",cost="0",selected=">",fib="*"):
        st.error("Failed at Step 2 - Verify Leaf 4 tenant IPv4 prefix route in Vrf1")
        success = False
    else:
        st.log("Step 2 PASSED - Verify Leaf 4 tenant IPv4 prefix route in Leaf 3 in Vrf1")

    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error("Failed at Step 2 - Verify Leaf 4 L3 VNI IPv6 tenant route in Vrf1")
        success = False
    else:
        st.log("Step 2 PASSED - Verify Leaf 4 L3 VNI IPv6 tenant route in Leaf 3 in Vrf1")

    st.log("Start L3 IPv4 and IPv6 traffic b/w L3 to L4 for Vrf2 which has duplicate ip as Vrf1")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_1_32426"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_2_32426"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_1_32426"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v6host_2_32426"], arp_target='all')
    start_traffic(stream_dict["l3_32426"])

    st.log("Step 2: Verify L3 traffic from b/w L3 to L4 for Vrf2 which has duplicate ip as Vrf1")
    if verify_traffic():
        st.log("traffic verification passed b/w L3 to L4 for Vrf2 having duplicate ip as Vrf1")
    else:
        success=False
        st.error("traffic verification failed b/w L3 to L4 for Vrf2 having duplicate ip as Vrf1")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][1],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][1],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],
                                distance="20",cost="0",selected=">",fib="*"):
        st.error("Failed at Step 3 - Verify tenant IPv4 prefix route in Vrf2")
        success = False
    else:
        st.log("Step 3 PASSED - Verify Vrf1 import/leaked Leaf 4 tenant IPv4 prefix route in Vrf2")

    st.log("Step 4: Remove Vrf to Vni map outside FRR")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf3"]["l3_vni_list"][1],"config":"no", 'vtep_name':evpn_dict["leaf3"]["vtepName"]}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
            "vni":evpn_dict["leaf4"]["l3_vni_list"][1],"config":"no", 'vtep_name':evpn_dict["leaf4"]["vtepName"]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Evpn.map_vrf_vni,[dict1,dict2])

    st.log("Step 4: Remove Vlan to Vni map")
    utils.exec_all(True,[[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["l3_vni_list"][1],
            evpn_dict["leaf3"]["l3_vni_list"][1],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["l3_vni_list"][1],"1", "no"]])

    st.log("Step 4: Delete ipv4 and ipv6 address from L3 VNI VLAN interface")
    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ip_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][1]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ip_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][1]]])

    utils.exec_all(True,[[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][1], evpn_dict["leaf3"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][1],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][1], evpn_dict["leaf4"]["l3_vni_ipv6_list"][1],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][1],"ipv6"]])

    st.log("Step 4: Remove IP address from L3VNI tenant interface on Leaf 3 and Leaf 4 node")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Step 4: Removing Vrf binding for L3 VNI VLAN interface")
    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][1],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
              "intf_name":evpn_dict["leaf4"]["l3_vni_name_list"][1],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    dict1 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][1],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],"skip_error":"yes","config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Step 4: Delete BGP Vrf global config in FRR")
    dict1 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1]}
    dict2 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            Bgp.config_bgp,[dict1,dict2])

    st.log("Step 4: Delete Vrf globally outside FRR")
    dict1 = {"vrf_name":evpn_dict["leaf3"]["vrf_name_list"][1],"config":"no"}
    dict2 = {"vrf_name":evpn_dict["leaf4"]["vrf_name_list"][1],"config":"no"}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][2:4],
            vrf.config_vrf,[dict1,dict2])

    st.log("Step 4: Delete VLAN membership for new L3 VNI VLAN")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 4: Delete VLAN membership for new L3 tenant VLAN")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0],True],
            [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 4: Delete new L3 VNI VLANs on leaf 3 and 4 to restore base line config")
    utils.exec_all(True,[[Vlan.delete_vlan,evpn_dict["leaf_node_list"][2],evpn_dict["leaf3"]["l3_vni_list"][1]],
            [Vlan.delete_vlan,evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["l3_vni_list"][1]]])
    current_stream_dict["stream"] = stream_dict["l3_32426"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32426")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32426")

def test_FtOpSoRoEvpn5549Ft32417(Ft32215_fixture):
    success = True
    hdrMsg("FtOpSoRoEvpn5549Ft32417 - Verify asymmetric IRB Forwarding in default VRF")

    leaf3_l2_tenant1_ip = "19.1.1.3"
    leaf4_l2_tenant1_ip = "19.1.1.4"
    leaf3_l2_tenant2_ip = "20.1.1.3"
    leaf4_l2_tenant2_ip = "20.1.1.4"
    l2_tenant_ipmask = "24"

    st.log("Step 1: Assign IP address to L2 VNI tenant interface on two leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
            leaf3_l2_tenant1_ip, l2_tenant_ipmask],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
            leaf4_l2_tenant1_ip,l2_tenant_ipmask]])

    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][1],
            leaf3_l2_tenant2_ip, l2_tenant_ipmask],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][1],
            leaf4_l2_tenant2_ip,l2_tenant_ipmask]])

    st.log("Extending the 2nd tenant L2 VLAN b/w leaf 3 and Leaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1]]])

    if retry_api(Evpn.verify_vxlan_evpn_remote_vni_id,evpn_dict["leaf_node_list"][2],
                                vni=evpn_dict["leaf3"]["tenant_l2_vlan_list"][1],retry_count=10, delay=1,
                                vlan=evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][1],
                                identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        st.log("PASS: Second L2 tenant got extended from Leaf 3 to Leaf 4")
    else:
        st.error("### FAIL: second L2 tenant is not extended from Leaf 3 to Leaf 4 ###")
        success = False

    if retry_api(Evpn.verify_vxlan_evpn_remote_vni_id,evpn_dict["leaf_node_list"][3],
                                vni=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],retry_count=10, delay=1,
                                vlan=evpn_dict["leaf4"]["tenant_l2_vlan_name_list"][0],
                                identifier="all",rvtep=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("PASS: First L2 tenant got extended from Leaf 4 to Leaf 3")
    else:
        st.error("### FAIL: first L2 tenant is not extended from Leaf 4 to Leaf 3 ###")
        success = False

    st.log("Step 1: Remove port membership for second tenant L2 VLAN in leaf 3 and first tenant vlan for Leaf 4")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.wait(3)

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                ip_address="19.1.1.0/24",type="C"):
        st.error("Failed at Step 2 - In L2, Verify 1st L2 tenant IP route in default Vrf")
        success = False
    else:
        st.log("Step 2 PASSED - In L3, Verify 1st L2 tenant IP route in default Vrf")


    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                ip_address="19.1.1.0/24",type="C"):
        st.error("Failed at Step 2 - In L3, Verify 1st L2 tenant IP route in default Vrf")
        success = False
    else:
        st.log("Step 2 PASSED - In L3, Verify 1st L2 tenant IP route in default Vrf")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][1],
                                ip_address="20.1.1.0/24",type="C"):
        st.error("Failed at Step 2 - In L2, Verify 2nd L2 tenant IP route in default Vrf")
        success = False
    else:
        st.log("Step 2 PASSED - In L2, Verify 2nd L2 tenant IP route in default Vrf")

    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                shell="vtysh",family="ipv4",
                                interface="Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][1],
                                ip_address="20.1.1.0/24",type="C"):
        st.error("Failed at Step 2 - In L3, Verify 2nd L2 tenant IP route in default Vrf")
        success = False
    else:
        st.log("Step 2 PASSED - In L3, Verify 2nd L2 tenant IP route in default Vrf")

    st.log("Step 2: Send IPv4 and IPv6 L3 traffic b/w L3 to L4 with L2 tenant")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_1_32417"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["v4host_2_32417"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3_32417"])

    st.log("Step 2: Verify L3 traffic from b/w L3 to L4 for Vrf2")
    if verify_traffic(tx_port=vars.T1D5P1,rx_port=vars.T1D6P2):
        st.log("traffic verification passed b/w L3 to L4 for Vrf2")
    else:
        success=False
        st.error("traffic verification failed b/w L3 to L4 for Vrf2")

    st.log("Delete L2 vlan to VNI mapping on two Leaf nodes")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
                           "1", "no"]])


    st.log("Remove IP address of L2 VNI tenant interface from two leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
        leaf3_l2_tenant1_ip, l2_tenant_ipmask],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
        leaf4_l2_tenant1_ip, l2_tenant_ipmask]])

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l2_vlan_list"][1],
        leaf3_l2_tenant2_ip, l2_tenant_ipmask],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+evpn_dict["leaf4"]["tenant_l2_vlan_list"][1],
        leaf4_l2_tenant2_ip, l2_tenant_ipmask]])

    st.log("Add back the port membership for second tenant L2 VLAN in leaf 3 and first tenant vlan for Leaf 4")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])
    current_stream_dict["stream"] = stream_dict["l3_32417"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32417")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32417")


def test_FtOpSoRoEvpn5549Ft3421(Ft32211_fixture):
    success = True
    tc_list = ["test_FtOpSoRoEvpn5549Ft3421"]
    tc_list_summary = ["Verify L2VPN EVPN configuration across cold reboot"]

    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")
    ipv4_nw_1 = evpn_dict["leaf3"]["loop_ip_list"][1]
#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    tx_port=vars.T1D5P1
    rx_port=vars.T1D6P1

    hdrMsg(" STEP:1  Make sure the Vxlan tunnel is up before starting the cold reboot")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is NOT UP in leaf3 before starting the test case")
        success = False
    else:
        st.log("VXLAN tunnel is UP as expected in leaf1")

#    create_stream("l2")
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("start traffic from first tgen port of Leaf3 and Leaf4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("Verify traffic received in first tgen port of Leaf3 and Leaf4")
    if verify_traffic():
        st.log("PASS: Traffic verification passed before the cold reboot")
    else:
        success = False
        st.error("FAIL: Traffic verification failed before before the start of the test case")
    hdrMsg("######------Performing Cold reboot with L2 Vni & L3 Vni configuration------######")
    Bgp.enable_docker_routing_config_mode(vars.D5)
    reboot_api.config_save(vars.D5)
    st.vtysh(vars.D5,"copy running-config startup-config")
    st.reboot(vars.D5)
    st.wait(3)
    ports = port.get_interfaces_all(vars.D5)
    if not ports:
        st.report_fail("operation_failed")
    else:
        st.report_pass("operation_successful")
    hdrMsg("Verify the tunnel is Up after the cold reboot")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up']):
        st.error("FAIL: VXLAN tunnel is NOT UP in leaf3 after cold reboot")
        success = False
    else:
        st.log("PASS: VXLAN tunnel is UP as expected in leaf3 after cold reboot")

    hdrMsg("Verify the tunnel to Leaf3 is Up on remote leaf after the cold reboot")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][3],
                                           src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up']):
        st.error("FAIL: VXLAN tunnel is NOT UP in leaf4 after cold reboot")
        success = False
    else:
        st.log("PASS: VXLAN tunnel is UP as expected in leaf3 after cold reboot")

    st.log("Verify traffic is being received as expected after cold reboot")
    if verify_traffic():
        st.log("PASS: Traffic verification passed after the cold reboot")
    else:
        success = False
        st.error("FAIL: Traffic verification failed after the cold reboot")
    current_stream_dict["stream"]=stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3421")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3421")


@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft32215(Ft32215_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32215; TC SUMMARY : Test VxLAN by deleting and adding back router BGP ")
    success = True
    ############################################################################################
    hdrMsg(" \n####### Create streams and start traffic ##############\n")
    st.log("Start traffic from the first tgen port of DUT5 and DUT6")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt = Mac.get_mac_count(vars.D5)
    D6_mac_cnt = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Verify traffic before trigger ##############\n")
    ############################################################################################

    if verify_traffic():
        st.log("PASS: traffic verification passed before trigger ")
    else:
        success=False
        st.error("FAIL: traffic verification failed before trigger")
        basic.get_techsupport(filename='test_FtOpSoRoEvpn5549Ft32215')
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Delete BGP in leaf4 ##############\n")
    ############################################################################################
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='remove_vni',
                         vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                         l3_vni_id=evpn_dict["leaf4"]["l3_vni_list"][0],config_type_list=["vrf_vni"],
                         vtep_name=evpn_dict["leaf4"]["vtepName"])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], config='no', config_type_list=["removeBGP"], removeBGP='yes', vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0], local_as=evpn_dict['leaf4']['local_as'])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], config='no', config_type_list = ['removeBGP'], removeBGP='yes', local_as=evpn_dict["leaf4"]["local_as"])

    st.wait(3)

    ############################################################################################
    hdrMsg(" \n####### Verify tunnel to leaf4 is deleted in leaf3 ##############\n")
    ############################################################################################

    vtep_list = Evpn.get_tunnel_list(vars.D5)
    if evpn_dict["leaf4"]["loop_ip_list"][1] in vtep_list:
        st.error("FAIL: Expected number of tunnels not found" )
        success=False
    else:
        st.log("PASS: Expected number of tunnels seen")

    if not Evpn.verify_vxlan_tunnel_count(dut=evpn_dict["leaf_node_list"][2],exp_count=2):
        st.error("FAIL: Expected number of tunnels not found" )
        success=False
    else:
        st.log("PASS: Expected number of tunnels seen")

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt_2 = Mac.get_mac_count(vars.D5)
    D6_mac_cnt_2 = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 0:
        st.log("PASS: Remote macs are withdrawn as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:0. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    ############################################################################################
    hdrMsg(" \n####### Reconfigure BGP in leaf4 ##############\n")
    ############################################################################################
    i=3
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='yes', vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0], l3_vni_id=evpn_dict["leaf4"]["l3_vni_list"][0], config_type_list=["vrf_vni"], vtep_name=evpn_dict["leaf4"]["vtepName"])
    for port_lst1 in [data.leafs_spine1_port_lst1, data.leafs_spine2_port_lst1]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["multipath-relax"])
        if evpn_dict['cli_mode'] != "klish":
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["remote-as"], remote_as='external',interface=port_lst1[i])
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["activate"], neighbor=port_lst1[i], addr_family='ipv4')
        else:
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["neighbor"], remote_as='external',neighbor=port_lst1[i])

    for j,port_lst1 in zip(range(0,2),[data.leafs_spine1_po_lst1, data.leafs_spine2_po_lst1]):
        if evpn_dict['cli_mode'] != "klish":
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["remote-as"], remote_as=data.bgp_spine_local_as[j], interface=port_lst1[i])
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["activate"], neighbor=port_lst1[i], addr_family='ipv4')
        else:
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][i],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["neighbor"], remote_as=data.bgp_spine_local_as[j], neighbor=port_lst1[i])

    for ipv6_lst1,j in zip([data.spine1_ipv6_list,data.spine2_ipv6_list],range(0,2)):
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["neighbor"], remote_as=data.bgp_spine_local_as[j],neighbor=ipv6_lst1[i])
        if evpn_dict['cli_mode'] != "klish":
            Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["activate"], neighbor=ipv6_lst1[i], addr_family='ipv4')
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["activate","advertise_all_vni"], remote_as=data.bgp_spine_local_as[j], neighbor=ipv6_lst1[i])

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["redist"], redistribute='connected')
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3],  config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["router_id"], router_id=evpn_dict['leaf4']['loop_ip_list'][0])

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["redist"], redistribute='connected',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["redist"], redistribute='connected',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],addr_family='ipv6')
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][3], config='yes', local_as=evpn_dict["leaf4"]["local_as"], config_type_list=["advertise_ipv4_vrf"],vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],advertise_ipv4='unicast')
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='yes', local_as=evpn_dict["leaf4"]["local_as"], advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"], vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config='yes', local_as=evpn_dict["leaf4"]["local_as"], advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"], vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0])
    st.wait(6)

    ############################################################################################
    hdrMsg(" \n####### Verify tunnel up in leaf3 ##############\n")
    ############################################################################################
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                    rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is DOWN in leaf3")
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    else:
        st.log("VXLAN tunnel is UP as expected in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify routes are learnt in leaf3 ##############\n")
    ############################################################################################
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                   shell="vtysh",family="ipv4",interface=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                   nexthop=evpn_dict["leaf4"]["loop_ip_list"][1],
                   ip_address=evpn_dict["leaf4"]["l3_vni_ip_net"][0],distance="20",cost="0"):
        st.log("FAIL: Routes learnt from leaf4 not found in leaf3")
        success = False
    else:
        st.log("PASS: Routes learnt from leaf4 found in leaf3")

    ############################################################################################
    hdrMsg(" \n####### Verify mac count in leaf3 ##############\n")
    ############################################################################################
    D5_mac_cnt_3 = Mac.get_mac_count(vars.D5)
    D6_mac_cnt_3 = Mac.get_mac_count(vars.D6)

    mac_lst = mac_list_from_bcmcmd_l2show(vars.D5)
    mac_list = filter_mac_list(vars.D5,tg_dict['dut_6_mac_pattern'])
    if len(mac_list) == 10:
        st.log("PASS: Remote macs are installed as expected.")
    else:
        st.error("FAIL: Mac count in Leaf3 not as expected. Expected:10. Found: "+ str(len(mac_list)))
        success=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n############# Verify traffic after trigger ##############\n")
    ############################################################################################

    if verify_traffic():
        st.log("traffic verification passed after reconfiguration of bgp")
    else:
        success=False
        st.error("Traffic verification failed after deletion and reconfiguration of bgp")
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32215")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32215")

@pytest.fixture(scope="function")
def Ft32215_fixture(request,evpn_underlay_hooks):
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield

    hdrMsg("### CLEANUP for 32215 ###")

    ############################################################################################
    hdrMsg(" \n####### Reset TGEN ##############\n")
    ############################################################################################
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
#    reset_tgen()
#    delete_host()
    ############################################################################################
    hdrMsg("\n####### Clear mac in leaf3 and leaf4 ##############\n")
    ############################################################################################
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)
    Mac.clear_mac(vars.D4)

def test_FtOpSoRoEvpn5549Ft32427_2():
    success = True
    tc_list = ["test_FtOpSoRoEvpn5549Ft32427","test_FtOpSoRoEvpn5549Ft32428"]
    tc_list_summary = ["Verify slow path Forwarding Scenarios over IP Fabric",
                         "Verify traffic forwarding to Silent Hosts connected to single node leaf node"]
    hdrMsg("TC ID: test_FtOpSoRoEvpn5549Ft32426_2; TC SUMMARY : Verify slow path Forwarding Scenarios over IP Fabric")
    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")

    hdrMsg(" STEP:1  Make sure the Vxlan tunnel is up before proceeding with the test case test_FtOpSoRoEvpn5549Ft32426_2")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is NOT UP in leaf3 before starting the test case test_FtOpSoRoEvpn5549Ft32426_2")
        success = False
    else:
        st.log("VXLAN tunnel is UP as expected in leaf1")

    hdrMsg(" STEP:2  Verify Ipv4 prefix route is present in the evpn table before the triggers\n")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                                                        evpn_type_5_prefix="[5]:[0]:[24]:[" + ipv4_nw[0] + "]",
                                                        status_code="*>",
                                                        next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni prefix routes: {} are not present in the evpn table".format(ipv4_nw[0]))
        success = False

    hdrMsg(" STEP:3  Verify Ipv6 prefix route is present in the evpn table before the triggers\n")
    if not Evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=evpn_dict["leaf_node_list"][3],
                                                        evpn_type_5_prefix="[5]:[0]:[96]:[" + ipv6_nw[0] + "]",
                                                        status_code="*>",
                                                        next_hop=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.error("L3 vni Ipv6 prefix routes: {} are not present in the evpn table".format(ipv6_nw[0]))
        success = False

    hdrMsg(" STEP:4 Ping the Ipv4 tenant adddress on Leaf 4 and make sure it works")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ip_list"][0], family='ipv4',count=3,interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:5 Ping the Ipv6 tenant adddress on Leaf 4 and make sure it works")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], family='ipv6', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:6 Trigger the clear bgp evpn neighbor and make sure ping works fine")
    Evpn.clear_bgp_evpn(vars.D5, "*")
    st.wait(5)

    hdrMsg(" STEP:7 Ping the Ipv4 tenant adddress on Leaf 4 after clear bgp evpn neighbor")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ip_list"][0], family='ipv4', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:8 Ping the Ipv6 tenant adddress on Leaf 4 after clear bgp evpn neighbor")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], family='ipv6', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:9 Flap the Uplink towards the spine and verify ping works fine")
    port.shutdown(vars.D5,evpn_dict["leaf3"]["intf_list_spine"])
    st.wait(2)

    port.noshutdown(vars.D5,evpn_dict["leaf3"]["intf_list_spine"])
    st.wait(5)

    hdrMsg(" STEP:10 Ping the Ipv4 tenant adddress on Leaf 4 after flapping the uplink")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ip_list"][0], family='ipv4', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:11 Ping the Ipv6 tenant adddress on Leaf 4 after flapping the uplink")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], family='ipv6', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:12 Remove and add back the L3 vni to vrf mapping, verify ping works fine")
    Evpn.map_vrf_vni(vars.D5, vrf_vni2['vrf_name'], vrf_vni2['vni'], config='no', vtep_name=evpn_dict["leaf3"]["vtepName"])
    Evpn.map_vlan_vni(vars.D5,evpn_dict["leaf3"]["vtepName"],evpn_dict["leaf3"]["l3_vni_list"][0], evpn_dict["leaf3"]["l3_vni_list"][0],config='no')

    hdrMsg(" STEP:13 Verify Ping fails after removing vlan to vni mapping")
    if  ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ip_list"][0], family='ipv4', count=3, interface='Vrf1'):
        st.error("ping to {} is passing even after removing vlan to vni mapping".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
    else:
        st.log('PASSED: Ping failed as expected')

    Evpn.map_vlan_vni(vars.D5, evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["l3_vni_list"][0],
                      evpn_dict["leaf3"]["l3_vni_list"][0],config='yes')
    Evpn.map_vrf_vni(vars.D5, vrf_vni2['vrf_name'], vrf_vni2['vni'], config='yes', vtep_name=evpn_dict["leaf3"]["vtepName"])

    hdrMsg(" STEP:14 Ping the Ipv4 tenant adddress on Leaf 4 after vlan to vni mapping flapping")
    if not retry_api(ip_obj.ping, vars.D5, addresses=evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                 family='ipv4',count=3, interface='Vrf1',retry_count=3, delay=5):
        st.error("ping to {} is failing ".format(evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    hdrMsg(" STEP:15 Ping the Ipv6 tenant adddress on Leaf 4 after vlan to vni mapping flapping")
    if not ip_obj.ping(vars.D5, evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], family='ipv6', count=3, interface='Vrf1'):
        st.error("ping to {} is failing even though the prefix route is in Bgp table".format(
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0]))
        success = False

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32427_2")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32427_2")

'''
def test_FtOpSoRoEvpn5549Ft3281_3(Ft3281_fixture):

    success = True
    tc_list = ["test_FtOpSoRoEvpn5549Ft3281","test_FtOpSoRoEvpn5549Ft32111","test_FtOpSoRoEvpn5549Ft32114"]
    tc_list_summary = ["Verify RFC 5549 underlay with BFD enabled running traffic across IPv6 link specific trigger",
                       "Verify underlay ECMP with IPv4 and IPv6 traffic",
                       "Verify change in underlay ECMP path to single path and vice versa"]

    make_global_vars()
    globals().update(data)

    intf_list = data.leaf3_po_list+[vars.D5D1P1, vars.D5D2P1]
    ############################################################################################
    hdrMsg(" \n####### Step 1 - Create L2 Stream #########\n")
    ############################################################################################
    create_stream('l2',rate=10000,src_mac_count_list=['15','15'],dst_mac_count_list=['15','15'])
    ############################################################################################
    hdrMsg(" \n####### Step 2 - Verify ECMP for L2 Traffic #########\n")
    ############################################################################################

    start_traffic()

    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 4:
        st.error('FAIL: Traffic not passing through the expected number of paths')
        sucess=False
    else:
        st.log('PASS: Traffic is load balanced as expected')
    ############################################################################################
    hdrMsg("\n####### Step 3 - Cleanup L2 stream and create IPv4 stream #########\n")
    ############################################################################################
    start_traffic(action="stop")
    reset_tgen()

    dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac'])
    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])

    create_stream("ipv4", rate=10000, src_ip_count_list=['15','15'], dst_ip_count_list=['15','15'], dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    ############################################################################################
    hdrMsg(" \n####### Step 4 - Verify ECMP for IPv4 Traffic #########\n")
    ############################################################################################
    start_traffic()

    num_of_paths= check_ecmp(intf_list)
    if num_of_paths < 3:
        sucess=False
        st.error('FAIL: Traffic not passing through the expected number of paths')
    else:
        st.log('PASS: Traffic is load balanced as expected')
        st.report_tc_pass("test_FtOpSoRoEvpn5549Ft32111","tc_passed")

    ############################################################################################
    hdrMsg("\n########## Step 5 - Clear ARP table in Dut5 ############\n")
    ############################################################################################
    arp_api.clear_arp_table(vars.D5)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n###### Step 6 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed after clear arp.")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear arp.")

    ############################################################################################
    hdrMsg(" \n####### Step 7 - Cleanup IPv4 stream and create IPv6 stream #########\n")
    ############################################################################################
    start_traffic(action="stop")
    reset_tgen()
    delete_host()

    create_stream("ipv6", rate=10000, src_ip_count_list=['15','15'], dst_ip_count_list=['15','15'], dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    ############################################################################################
    hdrMsg(" \n####### Step 8 - Verify ECMP for IPv6 Traffic #########\n")
    ############################################################################################

    start_traffic()

    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 3:
        st.error('FAIL: Traffic not passing through the expected number of paths for IPv6')
        sucess=False
    else:
        st.log('PASS: Traffic flowing through all 4 ECMP paths for IPv6')

    ############################################################################################
    hdrMsg("\n########## Step 9 - Clear ND table in Dut5 ############\n")
    ############################################################################################
    arp_api.clear_ndp_table(vars.D5)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n###### Step 10 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed after clear ND")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear ND")

    start_traffic(action="stop")
    ############################################################################################
    hdrMsg(" \n####### Step 11 - Add L2 and IPv4 streams #########\n")
    ############################################################################################
    create_stream('l2',rate=10000)
    create_stream("ipv4", rate=10000,dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
    ############################################################################################
    hdrMsg("\n###### Step 12 - Verify traffic ######\n")
    ############################################################################################
    start_traffic()

    if verify_traffic():
        st.log("PASS: Traffic verification passed with L2 and L3 streams.")
    else:
        success=False
        st.error("FAIL: Traffic verification failed with L2 and L3 streams")

    ############################################################################################
    hdrMsg("\n###### Step 13 - Flap the link between leaf3 and spine1 10 times ######\n")
    ############################################################################################
    for i in range(0,10):
        port.shutdown(evpn_dict["leaf_node_list"][3],[vars.D5D1P1])
        port.noshutdown(evpn_dict["leaf_node_list"][3],[vars.D5D1P1])

    port.shutdown(evpn_dict["leaf_node_list"][3],[vars.D5D1P1])

    ############################################################################################
    hdrMsg("\n###### Step 14 - Verify traffic ######\n")
    ############################################################################################
    start_traffic()

    if verify_traffic():
        st.log("PASS: Traffic verification passed after 1 NH down")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after 1 NH down")
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg("\n###### Step 15 - Unshut the interface ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["leaf_node_list"][3],[vars.D5D1P1])
    st.wait(5)

    ############################################################################################
    hdrMsg("\n###### Step 16 - Verify ECMP after interface flap ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 3:
        st.error('FAIL: Traffic not passing through the expected number of paths after repeated link flaps')
        sucess=False
    else:
        st.log('PASS: Traffic flowing through all 4 ECMP paths after repeated link flaps')
        st.report_tc_pass("test_FtOpSoRoEvpn5549Ft32114","tc_passed")

    ############################################################################################
    hdrMsg("\n###### Step 17 - Shut the physical intf member of PO and verify traffic ######\n")
    ############################################################################################
    port.shutdown(evpn_dict["spine_node_list"][0],[vars.D1D5P2, vars.D1D5P3])
    st.wait(5)
    ############################################################################################
    hdrMsg("\n###### Step 18 - Verify traffic ######\n")
    ############################################################################################

    if verify_traffic():
        st.log("PASS: Traffic verification passed after PO down")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after PO down")

    ############################################################################################
    hdrMsg("\n###### Step 19 - Unshut the PO and verify ECMP ######\n")
    ############################################################################################
    port.noshutdown(evpn_dict["spine_node_list"][0],[vars.D1D5P2, vars.D1D5P3])
    st.wait(6)

    ############################################################################################
    hdrMsg("\n###### Step 20 - Verify ECMP after interface flap ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 3:
        st.error('FAIL: Traffic not passing through the expected number of paths after interface flap.')
        sucess=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    else:
        st.log('PASS: Traffic flowing through all 4 ECMP paths after interface flap.')

    ############################################################################################
    hdrMsg("\n########## Step 21 - Change the max path for bgp to 1 ############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict['leaf3']['local_as'], config_type_list=["max_path_ebgp"], max_path_ebgp='1')

    ############################################################################################
    hdrMsg("\n###### Step 22 - Verify traffic flows through only 1 path ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)

    if num_of_paths != 1:
        st.error('FAIL: Traffic not passing through the expected number of paths after maxpath change')
        sucess=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    else:
        st.log('PASS: Traffic flowing through only 1 path as expected after maxpath change.')

    ############################################################################################
    hdrMsg("\n########## Step 21 - Change the max path for bgp to 8 ############\n")
    ############################################################################################

    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict['leaf3']['local_as'], config_type_list=["max_path_ebgp"], max_path_ebgp='8')

    ############################################################################################
    hdrMsg("\n###### Step 22 - Verify ECMP ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 3:
        st.error('FAIL: Traffic not passing through the expected number of paths')
        sucess=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    else:
        st.log('PASS: Traffic flowing through all 4 ECMP paths')

    ############################################################################################
    hdrMsg("\n########## Step 23 - Clear bgp evpn neighbor ############\n")
    ############################################################################################
    st.log("########## clear BGP EVPN neighbors in Leaf3 ##########")
    output = Evpn.fetch_evpn_neigh_output(vars.D5)
    output = filter_and_select(output, {"updown"}, match={"neighbor" : data.spine1_ipv6_list[2]})
    timer1 = int(output[0]["updown"].split(":")[1])

    Evpn.clear_bgp_evpn(vars.D5, "*")
    st.wait(5)
    output = Evpn.fetch_evpn_neigh_output(vars.D5)
    output = filter_and_select(output, {"updown"}, match={"neighbor" : data.spine1_ipv6_list[2]})
    timer2 = int(output[0]["updown"].split(":")[1])

    if timer2 < timer1:
        st.log("EVPN neighbors re-established sucessfully, passed")
    else:
        success=False
        st.error("EVPN neighbors failed to reset OR re-establish the connection")
    st.wait(3)

    ############################################################################################
    hdrMsg("\n###### Step 24 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed clear bgp evpn neighbor ")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear bgp evpn neighbor")

    ############################################################################################
    hdrMsg("\n########## Step 25 - Clear bgp neighbor ############\n")
    ############################################################################################
    st.log("clear bgp neighbors")
    Bgp.clear_ip_bgp_vtysh(vars.D5)

    st.wait(5)

    ############################################################################################
    hdrMsg("\n###### Step 26 - Verify traffic ######\n")
    ############################################################################################
    if verify_traffic():
        st.log("PASS: Traffic verification passed after clear bgp")
    else:
        success=False
        st.error("FAIL: Traffic verification failed after clear bgp")

    ############################################################################################
    hdrMsg("\n###### Step 27 - Verify ECMP ######\n")
    ############################################################################################
    num_of_paths= check_ecmp(intf_list)

    if num_of_paths < 3:
        st.error('FAIL: Traffic not passing through the expected number of paths')
        sucess=False
        debug_vxlan_cmds(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])
    else:
        st.log('PASS: Traffic flowing through all 4 ECMP paths')
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3281")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3281")


@pytest.fixture(scope="function")
def Ft3281_fixture(request,evpn_underlay_hooks):

    yield

    hdrMsg("### CLEANUP for 3281 ###")

    ############################################################################################
    hdrMsg(" \n####### Stop the traffic ##############\n")
    ############################################################################################

    st.log("Reset TGEN")
    reset_tgen()
    delete_host()
'''


@pytest.mark.ft
def test_FtOpSoRoEvpn5549Ft32227(Ft32227_fixture):
    hdrMsg("TC ID: FtOpSoRoEvpn5549Ft32227; TC SUMMARY : Test VxLAN by removing and adding back VLAN to VNI mapping which causes tunnel flap")

    success = True

    ############################################################################################
    hdrMsg(" \n####### Step 1 - Create streams and start traffic ##############\n")
    ############################################################################################
#    create_stream("l2")

#    dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac'])
#    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])

    st.log("Start traffic from the first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2"])

    ############################################################################################
    hdrMsg(" \n####### Step 2 - Verify traffic ##############\n")
    ############################################################################################
    if verify_traffic():
        st.log("##### PASS: Traffic verification passed #####")
    else:
        success=False
        st.error("########## FAIL: Traffic verification failed ##########")
    start_traffic(action="stop", stream_han_list=stream_dict["l2"])
#    reset_tgen()
    ############################################################################################
    hdrMsg(" \n####### Step 3 - Remove L2 vlan to VNI mapping ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], '1', "no"]])
    st.wait(3)

    ############################################################################################
    hdrMsg(" \n####### Step 4 - Verify tunnel to leaf4 is deleted in leaf3 ##############\n")
    ############################################################################################
    vtep_list = Evpn.get_tunnel_list(vars.D5)
    if evpn_dict["leaf4"]["loop_ip_list"][1] in vtep_list:
        st.error("FAIL: Expected number of tunnels not found in leaf3" )
        success=False
    else:
        st.log("PASS: Expected number of tunnels seen in leaf3")

    vtep_list = Evpn.get_tunnel_list(vars.D6)
    if vtep_list == []:
        st.log("PASS: No tunnel seen as expected in leaf4")
    elif vtep_list == ['']:
        st.log("PASS: No tunnel seen as expected in leaf4")
    else:
        st.error("FAIL: Atleast one tunnel seen which is not expected in leaf4" )
        success=False
    ############################################################################################
    hdrMsg(" \n####### Step 5 - Create tenant L2 VLANs on leaf3 and leaf4 ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][2],"200"],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],"200"]])

    ############################################################################################
    hdrMsg(" \n####### Step 6 - Bind tenant L2 VLANs to port on leaf3 and leaf4 ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           "200", evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           "200", evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    ############################################################################################
    hdrMsg(" \n####### Step 7 - Add new L2 vlan to VNI mapping in leaf3 and leaf4 ##############\n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],evpn_dict["leaf3"]["vtepName"], "200","200"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200"]]):
        st.log('PASS: Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')
    st.wait(5)

    ############################################################################################
    hdrMsg(" \n####### Step 8 - Verify VxLan tunnels are up ##############\n")
    ############################################################################################
    vtep_list = Evpn.get_tunnel_list(vars.D5)
    if evpn_dict["leaf4"]["loop_ip_list"][1] not in vtep_list:
        st.error("FAIL: Expected number of tunnels not found in leaf3" )
        success=False
    else:
        st.log("PASS: Expected number of tunnels seen in leaf3")

    vtep_list = Evpn.get_tunnel_list(vars.D6)
    if evpn_dict["leaf3"]["loop_ip_list"][1] not in vtep_list:
        st.error("FAIL: Vxlan Tunnel towards to Leaf 3 source VTEP not found in leaf4" )
        success=False
    else:
        st.log("PASS: Vxlan Tunnel towards to Leaf 3 source VTEP found in Leaf 4")

    ############################################################################################
    hdrMsg(" \n####### Step 9 - Verify VxLan VNI mapping ##############\n")
    ############################################################################################

    if not Evpn.verify_vxlan_evpn_remote_vni_id(dut=evpn_dict["leaf_node_list"][2],
                                vni='200',vlan='Vlan200',
                                identifier="all",rvtep=evpn_dict["leaf4"]["loop_ip_list"][1]):
        success = False

    ############################################################################################
    hdrMsg(" \n####### Step 10 - Create L2 streams with new vlan ##############\n")
    ############################################################################################

#    create_stream("l2",port_han_list=[tg_dict['d5_tg_ph1'],tg_dict['d6_tg_ph1']],def_param=False,src_mac_list=['00:10:01:05:01:01','00:10:01:06:01:01'],dst_mac_list=['00:10:01:06:01:01','00:10:01:05:01:01'],vlan_id_list=['200','200'],src_mac_count_list=['10','10'],dst_mac_count_list=['10','10'])

    ############################################################################################
    hdrMsg(" \n####### Step 11 - Start bidirectional traffic and verify traffic ##############\n")
    ############################################################################################
    st.log("start traffic from first tgen port of DUT5 and DUT6")
    start_traffic(stream_han_list=stream_dict["l2_32227"])

    if verify_traffic():
        st.log("PASS: traffic verification passed on new vlan")
    else:
        success=False
        st.error("FAIL: traffic verification failed on new vlan")
        debug_traffic(evpn_dict["leaf_node_list"][2],evpn_dict["leaf_node_list"][3])

    ############################################################################################
    hdrMsg(" \n####### Step 12 - Remove new L2 vlan to VNI mapping on leaf3 and leaf4 #########\n")
    ############################################################################################
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],evpn_dict["leaf3"]["vtepName"], "200","200",'1',"no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "200","200",'1',"no"]])

    ############################################################################################
    hdrMsg(" \n####### Step 13 - Add back old L2 vlans to VNI mappings on leaf4 #########\n")
    ############################################################################################
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],evpn_dict["leaf4"]["tenant_l2_vlan_list"][0]]])

    ############################################################################################
    hdrMsg(" \n####### Step 14 - Verify vlan to VNI mapping on leaf3 #########\n")
    ############################################################################################
    if not Evpn.verify_vxlan_vlanvnimap(dut=evpn_dict["leaf_node_list"][2],
                                vni=[evpn_dict["leaf3"]["tenant_l2_vlan_list"][0]],
                                vlan=[evpn_dict["leaf3"]["tenant_l2_vlan_name_list"][0]],
                                total_count="1"):
        success = False

    ############################################################################################
    hdrMsg(" \n####### Step 15 - Verify traffic ##############\n")
    ############################################################################################
    start_traffic(action="stop", stream_han_list=stream_dict["l2_32227"])
#    reset_tgen()
#    create_stream("l2")
    start_traffic(stream_han_list=stream_dict["l2"])

    if verify_traffic():
        st.log("##### PASS: Traffic verification passed after adding back old vlans #####")
    else:
        success=False
        st.error("########## FAIL: Traffic verification failed after adding back old vlans ##########")
    current_stream_dict["stream"] = stream_dict["l2"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32227")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32227")


@pytest.fixture(scope="function")
def Ft32227_fixture(request,evpn_underlay_hooks):
    cleanup_l3vni()
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield

    hdrMsg("### CLEANUP for 32227 ###")

    ############################################################################################
    hdrMsg(" \n####### Stop the traffic ##############\n")
    ############################################################################################
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
    setup_l3vni()

#    st.log("Reset TGEN")
#    reset_tgen()
#    delete_host()

    Mac.clear_mac(vars.D4)
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)


@pytest.fixture(scope="function")
def Ft32213_fixture(request, evpn_underlay_hooks):
    st.log("configure max path as 2")
    bgp_obj.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],
               config='yes', config_type_list=["max_path_ebgp"], max_path_ebgp='2',addr_family="ipv6")
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield

    hdrMsg("### CLEANUP for 32213 ###")
    st.log("restore max path config")
    bgp_obj.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],
               config='no', config_type_list=["max_path_ebgp"], max_path_ebgp='2',addr_family="ipv6")
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
#    reset_tgen()
#    delete_host()


def test_FtOpSoRoEvpn5549Ft32213(Ft32213_fixture):

    tg = tg_dict['tg']
    success = True
    st.log("########## Test VxLAN by clearing BGP session with max path 1 more than one ##########")
#    create_stream("l2")
#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
    st.log("########## start traffic received from first tgen port of Leaf3 and Leaf4 ##########")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("########## verify traffic received in first tgen port of Leaf3 and Leaf4 ##########")
    if verify_traffic():
        st.log("########## traffic verification passed before clearing BGP session with maxpath 1 more than"
               " one##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed before before clearing BGP session with maxpath "
               "more than one ##########")

    st.log("########## clear BGP neighbor {} in leaf3 ##########".format(data.spine1_ipv6_list[2]))
    bgp_obj.clear_ipv6_bgp_vtysh(dut=evpn_dict["leaf_node_list"][2],value=data.spine1_ipv6_list[2])

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP session ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after clearing BGP session ##########")
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32213")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32213")

def test_FtOpSoRoEvpn5549Ft32416(Ft32215_fixture):
    success = True
    hdrMsg("FtOpSoRoEvpn5549Ft32416 - Verify symmetric IRB Forwarding")

#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("Start L3 IPv4 and IPv6 traffic b/w L3 to L4 for Vrf1")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    st.log("Step 1: Verify L3 traffic from b/w L3 to L4 for Vrf1")
    if verify_traffic():
        st.log("traffic verification passed b/w L3 to L4 for Vrf1")
    else:
        success=False
        st.error("traffic verification failed b/w L3 to L4 for Vrf1")
    start_traffic(action="stop", stream_han_list=stream_dict["l3"])

    st.log("Step 2: create VLANs for L3 tenant interfaces in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 3: Bind tenant L3 VLANs to TG port in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 4: Extend the L3 tenant vlan in leaf an dleaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]])

    st.log("Step 5: Configure non default L3 RT import and export under Vrf1 in leaf 3 and Leaf4")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],l3_export_rt="33:33",
                         l3_import_rt="44:44",config="yes",local_as=evpn_dict["leaf3"]['local_as'])

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config_type_list=["vrf_rd_rt"],
                         vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],l3_export_rt="44:44",
                         l3_import_rt="33:33",config="yes",local_as=evpn_dict["leaf4"]['local_as'])

    st.log(" Step 6: Verify Leaf 1 tenant IPv4 prefix route in Leaf 3 ")
    if not ip.verify_ip_route(dut=evpn_dict["leaf_node_list"][3],
                                vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                shell="vtysh",family="ipv4",
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop=evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_net"][0],distance="20",cost="0"):
        st.error(" Test Case failed at Step 6 - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 6 PASSED - Verify Leaf 1 tenant IPv4 prefix route in Leaf 3")

    st.log(" Step 7: Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3 ")
    if not ip.verify_ip_route(evpn_dict["leaf_node_list"][3],family='ipv6',
                                shell='vtysh',vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],
                                interface=evpn_dict["leaf4"]["l3_vni_name_list"][0],
                                nexthop="::ffff:"+evpn_dict["leaf3"]["loop_ip_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_net"][0],
                                distance="20",cost="0",type="B",selected=">",fib="*"):
        st.error(" Test Case failed at step 2 - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")
        success = False
    else:
        st.log(" Test Case Step 7 PASSED - Verify L3 VNI IPv6 prefix route in Leaf 4 towards Leaf 3")


    st.log("Start L3 IPv4 and IPv6 traffic b/w L3 to L4 for Vrf1")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["l3"])

    st.log("Step 8: Verify L3 traffic from b/w L3 to L4 for Vrf1")
    if verify_traffic():
        st.log("Symmetric routing traffic L2 IPv4 and IPv6 verification passed b/w L3 to L4 for Vrf1")
    else:
        success=False
        st.error("Symmetric routing traffic L2 IPv4 and IPv6 verification failed b/w L3 to L4 for Vrf1")

    st.log("Step 9: Remove non default L3 RT import and export under Vrf1 in leaf 3 and Leaf4")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], config_type_list=["vrf_rd_rt"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],l3_export_rt="33:33",
                         l3_import_rt="44:44",config="no",local_as=evpn_dict["leaf3"]['local_as'])

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][3], config_type_list=["vrf_rd_rt"],
                         vrf_name=evpn_dict["leaf4"]["vrf_name_list"][0],l3_export_rt="44:44",
                         l3_import_rt="33:33",config="no",local_as=evpn_dict["leaf4"]['local_as'])

    st.log("Step 10: Remove the L3 tenant vlan extension in leaf an dleaf 4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"1","no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"1","no"]])

    st.log("Step 11: Remove binding of tenant L3 VLANs to TG port in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Step 12: Remove VLANs for L3 tenant interfaces in leaf 3 and leaf 4")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]])
    current_stream_dict["stream"] = stream_dict["l3"]
    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft32416")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft32416")


def test_FtOpSoRoEvpn5549Ft3261(Ft32211_fixture):

    tg = tg_dict['tg']
    success = True
    st.log("########## Test ARP is forwarded over the VxLAN tunnel ##########")

    han1 = tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], mode='config',
                                intf_ip_addr='56.56.56.5', gateway='56.56.56.6', vlan='1',
                                vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=1, src_mac_addr=evpn_dict["leaf3"]["tenant_mac_l2"])
    tg.tg_arp_control(handle=han1["handle"], arp_target='all')

    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][3],
                                    mac_addr=evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                    vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf4, ARP request from Leaf3 is forwarded over"
               " the VxLAN tunnel, passed ##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in leaf4, ARP request from Leaf3 is NOT forwarded over"
               " the VxLAN tunnel ##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))

    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][1],
                                    mac_addr=evpn_dict["leaf3"]["tenant_mac_l2_colon"],
                                    vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf2, "
               "passed ##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in "
               "leaf2 ##########".format(evpn_dict["leaf3"]["tenant_mac_l2_colon"]))

    han2 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config',
                                  intf_ip_addr='56.56.56.6', gateway='56.56.56.5', vlan='1',
                                  vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                  vlan_id_step='0', arp_send_req='1', gateway_step='0.0.0.0',
                                  intf_ip_addr_step='0.0.0.1', count=1,
                                  src_mac_addr=evpn_dict["leaf4"]["tenant_mac_l2"])
    tg.tg_arp_control(handle=han2["handle"], arp_target='all')
    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][2],
                                    mac_addr=evpn_dict["leaf4"]["tenant_mac_l2_colon"],
                                    vlan=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf3, ARP reply from Leaf4 is forwarded over"
               " the VxLAN tunnel, passed ##########".format(evpn_dict["leaf4"]["tenant_mac_l2_colon"]))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in leaf3, ARP reply from Leaf4 is NOT forwarded over"
               " the VxLAN tunnel ##########".format(evpn_dict["leaf4"]["tenant_mac_l2_colon"]))

    st.log("########## Test ND is forwarded over the VxLAN tunnel ##########")
    smac1 = incrementMac(evpn_dict["leaf3"]["tenant_mac_l2"], "00:00:00:00:00:01")
    smac2= incrementMac(evpn_dict["leaf4"]["tenant_mac_l2"], "00:00:00:00:00:01")
    smac_colon1 = incrementMac(evpn_dict["leaf3"]["tenant_mac_l2_colon"], "00:00:00:00:00:01")
    smac_colon2 = incrementMac(evpn_dict["leaf4"]["tenant_mac_l2_colon"], "00:00:00:00:00:01")
    han3 = tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], mode='config', ipv6_intf_addr="5656::5",
                                 ipv6_prefix_length='96', ipv6_gateway="5656::6", src_mac_addr=smac1,
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                 vlan_id_step='0', count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    tg.tg_arp_control(handle=han3["handle"], arp_target='all')

    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][3],mac_addr=smac_colon1,
                                    vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf3"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf4, ND from Leaf3 is forwarded over"
               " the VxLAN tunnel, passed ##########".format(smac_colon1))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in leaf4, ND from Leaf3 is NOT forwarded over"
               " the VxLAN tunnel ##########".format(smac_colon1))

    han4 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], mode='config', ipv6_intf_addr="5656::6",
                                 ipv6_prefix_length='96', ipv6_gateway="5656::5", src_mac_addr=smac2,
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0],
                                 vlan_id_step='0', count=1,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    tg.tg_arp_control(handle=han4["handle"], arp_target='all')
    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][2],mac_addr=smac_colon2,
                                    vlan=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf3, ND from Leaf4 is forwarded over"
               " the VxLAN tunnel, passed ##########".format(smac_colon2))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in leaf3, ND from Leaf4 is NOT forwarded over"
               " the VxLAN tunnel ##########".format(smac_colon2))

    if Mac.verify_mac_address_table(dut=evpn_dict["leaf_node_list"][1],mac_addr=smac_colon2,
                                    vlan=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], type="Dynamic",
                                    dest_ip=evpn_dict["leaf4"]["loop_ip_list"][1]):
        st.log("########## MAC {} present in leaf2, passed ##########".format(smac_colon2))
    else:
        success=False
        st.log("########## FAIL: MAC {} NOT present in leaf2".format(smac_colon2))

    st.log("########## Deleting Hosts ##########")
    #tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], handle=han1["handle"], mode='destroy')
    #tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], handle=han3["handle"], mode='destroy')
    #tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], handle=han2["handle"], mode='destroy')
    #tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph1"], handle=han4["handle"], mode='destroy')

    if success:
        st.report_pass("test_case_id_passed","test_FtOpSoRoEvpn5549Ft3261")
    else:
        st.report_fail("test_case_id_failed","test_FtOpSoRoEvpn5549Ft3261")


@pytest.fixture(scope="function")
def Ft32212_fixture(request, evpn_underlay_hooks):
    st.log("configure max path as 1")
    bgp_obj.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],
               config='yes', config_type_list=["max_path_ebgp"], max_path_ebgp='1')
    utils.exec_all(True, [[arp.clear_arp_table, evpn_dict["leaf_node_list"][2]],
                          [arp.clear_arp_table, evpn_dict["leaf_node_list"][3]]])
    yield

    hdrMsg("### CLEANUP for 32212 ###")
    st.log("restore max path config")
    bgp_obj.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],
               config='no', config_type_list=["max_path_ebgp"], max_path_ebgp='1')
    if current_stream_dict.get("stream",None):
        start_traffic(action='stop',stream_han_list=current_stream_dict["stream"])
        current_stream_dict.pop("stream")
#    reset_tgen()
#    delete_host()


def test_FtOpSoRoEvpn5549Ft32212(Ft32212_fixture):

    success = True
    st.log("########## Test VxLAN by clearing BGP session with max path 1 ##########")
#    create_stream("l2")
#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
    st.log("########## start traffic received from first tgen port of Leaf3 and Leaf4 ##########")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("########## verify traffic received in first tgen port of Leaf3 and Leaf4 ##########")
    if verify_traffic():
        st.log("########## traffic verification passed before clearing BGP session with maxpath 1 ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed before before clearing BGP session with maxpath 1"
               " ##########")

    st.log("########## check traffic goes through which spine ##########")
    output1 = ip.show_ip_route(dut=vars.D5)
    nexthop_1 = basic.get_ifconfig_inet6(vars.D1, vars.D1D5P1)[0].strip()
    output1 = filter_and_select(output1, ["ip_address"], {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1] + "/32",
                                                         "nexthop": nexthop_1})
    nexthop_2 = basic.get_ifconfig_inet6(vars.D2, vars.D2D5P1)[0].strip()
    output2 = ip.show_ip_route(dut=vars.D5)
    output2 = filter_and_select(output2, ["ip_address"], {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1] + "/32",
                                                         "nexthop": nexthop_2})
    if output1:
        st.log("########## route to leaf4 is pointing towards Spine1 ##########")
        shut_dut = evpn_dict["leaf_node_list"][2]
        shut_neigh = data.spine1_ipv6_list[2]
        st.log("########## clear BGP neighbor {} in leaf3 ##########".format(shut_neigh))
        bgp_obj.clear_ipv6_bgp_vtysh(dut=shut_dut,value=shut_neigh)
    elif output2:
        st.log("########## route to leaf4 is pointing towards Spine2 ##########")
        shut_dut = evpn_dict["leaf_node_list"][2]
        shut_neigh = data.spine2_ipv6_list[2]
        st.log("########## clear BGP neighbor {} in leaf3 ##########".format(shut_neigh))
        bgp_obj.clear_ipv6_bgp_vtysh(dut=shut_dut, value=shut_neigh)
    else:
        st.log("########## FAIL: route entry to {} not exists ########"
                 "##".format(evpn_dict["leaf4"]["loop_ip_list"][1] + "/32"))

    if verify_traffic():
        st.log("########## traffic verification passed after clearing BGP session ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after clearing BGP session ##########")
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32212")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32212")


def test_FtOpSoRoEvpn5549Ft32223(Ft32212_fixture):

    success = True
    st.log("########## Test VxLAN by shutting down link between leaf and spine ##########")
#    create_stream("l2")
#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac,dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
    st.log("########## start traffic received from first tgen port of Leaf3 and Leaf4 ##########")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("########## verify traffic received in first tgen port of Leaf3 and Leaf4 ##########")
    if verify_traffic():
        st.log("########## traffic verification passed before shutting down links b/w leaf & spine ##########")
    else:

        success = False
        st.log("########## FAIL: traffic verification failed before shutting down links b/w leaf & spine ##########")

    st.log("########## check traffic goes through which spine ##########")
    output1 = ip.show_ip_route(dut=vars.D5)
    nexthop_1 = basic.get_ifconfig_inet6(vars.D1, vars.D1D5P1)[0].strip()
    output1 = filter_and_select(output1, ["ip_address"], {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1] + "/32",
                                                         "nexthop": nexthop_1})
    nexthop_2 = basic.get_ifconfig_inet6(vars.D2, vars.D2D5P1)[0].strip()
    output2 = ip.show_ip_route(dut=vars.D5)
    output2 = filter_and_select(output2, ["ip_address"], {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1] + "/32",
                                                         "nexthop": nexthop_2})
    if output1:
        st.log("########## route to leaf4 is pointing via Spine1 ##########")
        shut_dut = evpn_dict["leaf_node_list"][2]
        shut_links = evpn_dict["leaf3"]["intf_list_spine"][0:4]
        st.log("########## shutdown the links b/w leaf3 and spine1 ##########")
        port.shutdown(shut_dut, shut_links)
        output3 = ip.show_ip_route(dut=vars.D5)
        output3 = filter_and_select(output3, ["ip_address"],
                                    {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1] + "32",
                                    "nexthop": nexthop_2})
        if output3:
            st.log("########## FAIL: route to leaf4 is NOT pointing to other spine2, failed ##########")
        else:
            st.log("########## route to leaf4 is pointing to other spine2, passed ##########")
    elif output2:
        st.log("########## route to leaf4 is pointing via Spine2 ##########")
        shut_dut = evpn_dict["leaf_node_list"][2]
        shut_links = evpn_dict["leaf3"]["intf_list_spine"][4:8]
        st.log("########## shutdown the links b/w leaf3 and spine2 ##########")
        port.shutdown(shut_dut, shut_links)
        output3 = ip.show_ip_route(dut=vars.D5)
        output3 = filter_and_select(output3, ["ip_address"],
                                    {"ip_address": evpn_dict["leaf4"]["loop_ip_list"][1]+"32",
                                    "nexthop": nexthop_1})
        if output3:
            st.log("########## FAIL: route to leaf4 is pointing to other spine1, failed ##########")
        else:
            st.log("########## route to leaf4 is pointing to other spine1 now, passed ##########")
    else:
        st.log("########## FAIL: route entry to {} not exists ########"
                 "##".format(evpn_dict["leaf4"]["loop_ip_list"][1] + "/32"))

    if verify_traffic():
        st.log("########## traffic verification passed after shutting down one of the spine ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after shutting down one of the spine ##########")

    if output1:
        st.log("########## bring back the shutdown links ##########")
        shut_links = evpn_dict["leaf3"]["intf_list_spine"][0:4]
        port.noshutdown(shut_dut, shut_links)
    elif output2:
        st.log("########## bring back the shutdown links ##########")
        shut_links = evpn_dict["leaf3"]["intf_list_spine"][4:8]
        port.noshutdown(shut_dut, shut_links)

    if verify_traffic():
        st.log("########## traffic verification passed after enabling the links back ##########")
    else:
        success = False
        st.log("########## FAIL: traffic verification failed after enabing the links back ##########")
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft32223")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft32223")


def test_FtOpSoRoEvpn5549Ft3411_2(Ft32215_fixture):
    success = True
    tc_list = ["test_FtOpSoRoEvpn5549Ft3411","test_FtOpSoRoEvpn5549Ft3412"]
    tc_list_summary = ["Verify L2VPN EVPN configuration across warm reboot",
                       "Test VxLAN with warm reboot"]

    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")
    ipv4_nw_1 = evpn_dict["leaf3"]["loop_ip_list"][1]
#    dut5_gateway_mac = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
#    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    tx_port=vars.T1D5P1
    rx_port=vars.T1D6P1

    hdrMsg(" STEP:1  Make sure the Vxlan tunnel is up before starting the warm reboot")
    if not Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up']):
        st.error("VXLAN tunnel is NOT UP in leaf3 before starting the test case")
        success = False
    else:
        st.log("VXLAN tunnel is UP as expected in leaf3")

#    create_stream("l2")
#    create_stream("ipv4", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])
#    create_stream("ipv6", dst_mac_list=[dut5_gateway_mac, dut6_gateway_mac])

    st.log("start traffic from first tgen port of Leaf3 and Leaf4")
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v4host_2"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_1"], arp_target='all')
    tg_dict["tg"].tg_arp_control(handle=stream_dict["l3_v6host_2"], arp_target='all')
    start_traffic(stream_han_list=stream_dict["all"])

    st.log("verify traffic received in first tgen port of Leaf3 and Leaf4")
    if verify_traffic():
        st.log("traffic verification passed before the warm reboot")
    else:
        success = False
        st.error("traffic verification failed before before the start of the test case")

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

    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                     src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                     retry_count=6, delay=5):
        st.log("##### VXLAN tunnel towards D6 is UP in D5 as expected after clearing BGP#####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D6 is DOWN in D5 after clearing BGP ##########")

    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                     retry_count=6, delay=5):
        st.log("##### VXLAN tunnel towards D5 is UP in D6 as expected after clearing BGP#####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D5 is DOWN in D6 after clearing BGP ##########")

    Bgp.enable_docker_routing_config_mode(vars.D5)
    reboot_api.config_save(vars.D5)
    st.vtysh(vars.D5,"copy running-config startup-config")
    hdrMsg("######------Performing Warm reboot with L2 Vni & L3 vni configuration------######")
    st.reboot(vars.D5, 'warm')

    hdrMsg("Verify the tunnel is Up after the warm reboot in DUT5/Leaf3")
    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                 src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                 rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                 retry_count=3, delay=10):
        st.log("##### VXLAN tunnel status after warm reboot is UP in leaf3 as expected #####")
    else:
        success = False
        st.error("########## VXLAN tunnel status is DOWN in leaf3 after warm reboot ##########")

    st.log("verify traffic is being received as expected after warm reboot")
    if verify_traffic():
        st.log("traffic verification passed after the warm reboot")
    else:
        success = False
        st.error("traffic verification failed after the warm reboot")
        debug_traffic(evpn_dict["leaf_node_list"][2], evpn_dict["leaf_node_list"][3])
    current_stream_dict["stream"] = stream_dict["all"]
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3411_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3411_2")


'''
def test_FtOpSoRoEvpn5549Ft3431_6(Ft3431_fixture):
    success = True
    testcase_id = 'Ft3431_6'

    tc_list = ["test_FtOpSoRoEvpn5549Ft3431", "test_FtOpSoRoEvpn5549Ft3441", "test_FtOpSoRoEvpn5549Ft3442",
               "test_FtOpSoRoEvpn5549Ft3443", "test_FtOpSoRoEvpn5549Ft3445", "test_FtOpSoRoEvpn5549Ft3446" ]
    tc_list_summary = ["Verify EVPN configuration across config reload after saving the configuration",
                       "Test VxLAN with SwSS docker restart",
                       "Test VxLAN with BGP docker restart",
                       "Test VxLAN with teamd docker restart",
                       "ICCP docker restart and start/stop protocol",
                       "Verify orchagent docker restart"]

    ipv4_nw = evpn_dict["leaf3"]["l3_vni_ip_net"][0].split("/")
    ipv6_nw = evpn_dict["leaf3"]["l3_vni_ipv6_net"][0].split("/")
    ipv4_nw_1 = evpn_dict["leaf3"]["loop_ip_list"][1]
    dut5_gateway_mac = str(basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac'])
    dut6_gateway_mac = str(basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac'])

    tx_port=vars.T1D5P1
    rx_port=vars.T1D6P1
    tx_port1=vars.T1D5P2
    rx_port1 = vars.T1D6P2

    ###########################################################
    hdrMsg("Step 1 : Make sure the Vxlan tunnel is up before starting the trigger")
    ############################################################
    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                     src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                     retry_count=3, delay=5):
        st.log("##### VXLAN tunnel towards D6 is UP in D5 as expected #####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D6 is DOWN in D5 ##########")

    if retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]], exp_status_list=['oper_up'],
                     retry_count=3, delay=5):
        st.log("##### VXLAN tunnel towards D5 is UP in D6 as expected #####")
    else:
        success = False
        st.error("########## FAIL: VXLAN tunnel towards D5 is DOWN in D6 ##########")

    ###########################################################
    hdrMsg("STEP 2 : Create L2 and L3 traffic streams")
    ############################################################
    create_stream_l2_multiVlans_macScale()

    ###########################################################
    hdrMsg("STEP 3 : Start the traffic and verify traffic.")
    ###########################################################
    st.wait(300, "need to wait for some time for all 4K Vxlan net devices to be online")
    st.log("Start traffic from first tgen port of Leaf3 and Leaf4")
    start_traffic([tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'],tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2']])
    st.wait(60, "need to wait for some time for traffic to flow for all vlans")

    if retry_api(verify_mac_count, vars.D6, mac_count=40000,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D6 ##########")
        st.report_tc_pass("FtOpSoRoEvpn5549Ft3431", "tc_passed")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D6 ##########")

    if retry_api(verify_mac_count, vars.D5, mac_count=40000,retry_count=4, delay=40):
        st.log("########## MAC count verification passed in D5 ##########")
        st.report_tc_pass("FtOpSoRoEvpn5549Ft3441", "tc_passed")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D5 ##########")

    st.log("Verify traffic received in tgen ports of Leaf3 and Leaf4")
    if verify_traffic(tx_port=tx_port, rx_port=rx_port) \
        and verify_traffic(tx_port=tx_port1, rx_port=rx_port1):
        st.log("PASS: Traffic verification passed before the config reload")
    else:
        success = False
        st.error("FAIL: Traffic verification failed before the start of the test case")

    ###########################################################
    hdrMsg("Step 5 : Config save")
    ###########################################################
    bgp_obj.enable_docker_routing_config_mode(vars.D5)
    reboot_api.config_save(vars.D5)
    reboot_api.config_save(vars.D5,shell='vtysh')

    ##########################################
    hdrMsg("Perform config reload in dut5")
    ##########################################
    reboot_api.config_reload(vars.D5)
    st.wait(300)

    hdrMsg("Verify the tunnel is Up after the trigger")
    if not retry_api(Evpn.verify_vxlan_tunnel_status, evpn_dict["leaf_node_list"][2],
                     src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf4"]["loop_ip_list"][1]],
                     exp_status_list=['oper_up'], retry_count=3, delay=40):
        st.error("FAIL: VXLAN tunnel is NOT UP in leaf3 after the trigger ")
        success = False
    else:
        st.log("PASS: VXLAN tunnel is UP as expected in leaf3 after the trigger ")
        st.report_tc_pass("FtOpSoRoEvpn5549Ft3442", "tc_passed")

    hdrMsg("Verify the tunnel to Leaf3 is Up on remote leaf after the trigger")
    if not retry_api(Evpn.verify_vxlan_tunnel_status,evpn_dict["leaf_node_list"][3],
                     src_vtep=evpn_dict["leaf4"]["loop_ip_list"][1],
                     rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                     exp_status_list=['oper_up'], retry_count=3, delay=40):
        st.error("FAIL: VXLAN tunnel is NOT UP in leaf4 after the trigger")
        success = False
    else:
        st.log("PASS: VXLAN tunnel is UP as expected in leaf4 after the trigger")
        st.report_tc_pass("FtOpSoRoEvpn5549Ft3443", "tc_passed")

    ###########################################################
    hdrMsg("Step 5 : Find the number of macs in Leaf3 and remote leaf node leaf4 after the trigger.")
    ###########################################################

    if retry_api(verify_mac_count, vars.D6, mac_count=40000, retry_count=4, delay=100):
        st.log("########## MAC count verification passed in D6 after the trigger - #######")
        st.report_tc_pass("FtOpSoRoEvpn5549Ft3445", "tc_passed")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D6 after the trigger - #######")

    if retry_api(verify_mac_count, vars.D5, mac_count=40000, retry_count=4, delay=100):
        st.log("########## MAC count verification passed in D5 after the trigger #######")
    else:
        success = False
        st.error("########## FAIL: MAC count verification failed in D5 after the trigger#######")

    ###########################################################
    hdrMsg("Step 6 : Verify traffic is being received as expected after the trigger. ")
    ############################################################
    result = False
    for i in range(4):
        result = verify_traffic(tx_port=tx_port,rx_port=rx_port) \
                 and verify_traffic(tx_port=tx_port1, rx_port=rx_port1)
        if result is False:
            st.wait(10,"wait for 10 seconds before retrying traffic ")
            continue
        else:
            break

    if result:
        st.log("PASS: Traffic verification passed after the trigger")
    else:
        success = False
        st.error("FAIL: Traffic verification failed after the trigger")

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoRoEvpn5549Ft3431_6")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoRoEvpn5549Ft3431_6")


@pytest.fixture(scope="function")
def Ft3431_fixture(request,evpn_underlay_hooks):
    success = True

    ############################################################################################
    hdrMsg(" \n####### Create tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"200 4000","add", "False"], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"200 4000", "add", "False"]])

    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"105 199","add", "False"], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"105 199", "add", "False"]])
    ############################################################################################
    hdrMsg(" \n####### Bind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"200 4000",evpn_dict["leaf3"]["intf_list_tg"][0],'add','False'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"200 4000",evpn_dict["leaf4"]["intf_list_tg"][0],'add','False']])

    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"105 199",evpn_dict["leaf3"]["intf_list_tg"][1],'add','False'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"105 199",evpn_dict["leaf4"]["intf_list_tg"][1],'add','False']])
    ############################################################################################
    hdrMsg(" \n####### Map vlan to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "105","105",'3895'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "105","105",'3895']]):
        st.log('Vlan to Vni mapping is created.')
    else:
        success=False
        st.error('FAIL: Vlan to Vni mapping failed even after vlan is created.')

    yield

    hdrMsg("### CLEANUP for 3431 ###")

    start_traffic([tg_dict['d5_tg_ph1'], tg_dict['d5_tg_ph2'], tg_dict['d6_tg_ph1'], tg_dict['d6_tg_ph2']],action="stop")

    st.log("Reset TGEN")
    reset_tgen([tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'],tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2']])
    Mac.clear_mac(vars.D5)
    Mac.clear_mac(vars.D6)

    ############################################################################################
    hdrMsg(" \n####### Remove mapping of new vlans to vni on leafs 3 and 4 #######/n")
    ############################################################################################
    if utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"], "105","105",'3895','no'],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3],evpn_dict["leaf4"]["vtepName"], "105","105",'3895','no']]):
        st.log('Vlan to Vni mapping is deleted.')
    else:
        success=False
        st.error('FAIL: Removal of Vlan to Vni mapping failed even after vlan is created.')

    ############################################################################################
    hdrMsg(" \n####### Unbind tenant L2 VLANs to port on all the leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"100 4000",evpn_dict["leaf3"]["intf_list_tg"][0],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"100 4000",evpn_dict["leaf4"]["intf_list_tg"][0],'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][2],"105 199",evpn_dict["leaf3"]["intf_list_tg"][1],'del'], [Vlan.config_vlan_range_members, evpn_dict["leaf_node_list"][3],"105 199",evpn_dict["leaf4"]["intf_list_tg"][1],'del']])


    ############################################################################################
    hdrMsg(" \n####### Delete tenant L2 VLANs on all leaf nodes ##############\n")
    ############################################################################################
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"100 499",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"100 499",'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"501 599",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"501 509",'del']])
    utils.exec_all(True, [[Vlan.config_vlan_range, evpn_dict["leaf_node_list"][2],"601 4000",'del'], [Vlan.config_vlan_range, evpn_dict["leaf_node_list"][3],"511 4000",'del']])
'''

