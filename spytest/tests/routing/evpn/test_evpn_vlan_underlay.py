##############################################################################
#Script Title : BGP Evpn - Vlan interface as underlay
#Author       : Nagappa
#Mail-id      : nagappa.chincholi@broadcom.com
###############################################################################

import pytest
from spytest import st
from evpn_vlan_vars import *
from evpn_vlan_vars import data
from evpn_vlan_utils import *
import apis.system.reboot as reboot_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
import apis.switching.mac as mac_api
import apis.system.port as port_api


def initialize_topology_vars():
    global vars

    create_glob_vars()
    vars = st.get_testbed_vars()
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped","Skipping cli mode CLICK")

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
    data.d1d5_ports = [vars.D1D5P1, vars.D1D5P2, vars.D1D5P3]
    data.d5d1_ports = [vars.D5D1P1, vars.D5D1P2, vars.D5D1P3]
    data.d1d6_ports = [vars.D1D6P1, vars.D1D6P2, vars.D1D6P3]
    data.d6d1_ports = [vars.D6D1P1, vars.D6D1P2, vars.D6D1P3]

    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]
    data.d2d5_ports = [vars.D2D5P1, vars.D2D5P2, vars.D2D5P3]
    data.d5d2_ports = [vars.D5D2P1, vars.D5D2P2, vars.D5D2P3]
    data.d2d6_ports = [vars.D2D6P1, vars.D2D6P2, vars.D2D6P3]
    data.d6d2_ports = [vars.D6D2P1, vars.D6D2P2, vars.D6D2P3]

    data.d3d7_ports = [vars.D3D7P1, vars.D3D7P2,vars.D3D7P3,vars.D3D7P4]
    data.d7d3_ports = [vars.D7D3P1, vars.D7D3P2,vars.D7D3P3,vars.D7D3P4]
    data.d4d7_ports = [vars.D4D7P1, vars.D4D7P2, vars.D4D7P3,vars.D4D7P4]
    data.d7d4_ports = [vars.D7D4P1, vars.D7D4P2, vars.D7D4P3,vars.D7D4P4]

    data.d3d4_ports = [vars.D3D4P1, vars.D3D4P2, vars.D3D4P3]
    data.d4d3_ports = [vars.D4D3P1, vars.D4D3P2, vars.D4D3P3]

    data.d7t1_ports = [vars.D7T1P1, vars.D7T1P2]
    data.d5t1_ports = [vars.D5T1P1, vars.D5T1P2]
    data.d6t1_ports = [vars.D6T1P1, vars.D6T1P2]

    data.t1d7_ports = [vars.T1D7P1, vars.T1D7P2]
    data.t1d5_ports = [vars.T1D5P1, vars.T1D5P2]
    data.t1d6_ports = [vars.T1D6P1, vars.T1D6P2]


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    result = evpn_vlan_base_config()
    if result is False:
        st.report_fail("Error in module config")
    yield
    evpn_vlan_base_unconfig()

def verify_data_path(tc_id):
    err_list = []
    result = check_ping_clients()
    if result is False:
        err = "Ping test between VTEPs failed."
        err_list.append(err);
        #st.generate_tech_support(dut=None,name=tc_id)
        return [False,err_list]

    st.log("Start l2 and l3 traffic between lvtep client(DUT7) and Leaf3(DUT5) and Leaf4(DUT6)")
    start_traffic(stream_han_list=stream_dict["all"])
    st.wait(4)
    start_traffic(action="stop")
    ##
    clear_stats()
    st.wait(2)
    start_traffic(stream_han_list=stream_dict["all"])
    st.wait(5)
    result = verify_traffic_stats()
    start_traffic(action="stop")
    if result is False:
        err = "Traffic test between VTEPs failed."
        err_list.append(err);
        return [False,err_list]
    return [True,err_list]

def test_evpn_vlan_underlay_001():
    tc_list = ['FtOpSoRoEvpnVlanFt001','FtOpSoRoEvpnVlanFt004','FtOpSoRoEvpnVlanFt005','FtOpSoRoEvpnVlanFt006',
               'FtOpSoRoEvpnVlanFt008','FtOpSoRoEvpnVlanFt009','FtOpSoRoEvpnVlanFt010','FtOpSoRoEvpnVlanFt018']
    tc_result = True ;err_list=[]
    # Verify Vlan interface underlay routes between spine and leaf on all leaf nodes.
    # Send traffic between lvtep and svtep.
    # Verify ping between Svtep and lvteps
    # Shutdown links to Spine
    # Send traffic and verify with default configs
    # Verify ping between Svtep and lvteps

    st.log("\n{} -  Vlan interface as underlay between lvtep nodes\n".format(tc_list[0]))

    st.log("# Step - Send traffic between lvtep and svtep. #")
    [result,err] =  verify_data_path(tc_list[0])
    if result is False:
        st.report_fail('test_case_failure_message', err)

    st.log("## Step - Shutdown all Links towards spine on Leaf1 ## \n")
    port_api.shutdown(data.dut3,data.d3d1_ports)

    st.log("## Step - Verify routes pointing to Vlan interfaces between Lvtep ##")
    result = verify_lvtep_vlanint_routes()
    if result is False :
        st.error("FAIL: Routes to Spine1 from leaf1 not found .")
    else:
        st.log('PASS: Next hop over tagged vlan interface verified .')
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.log("# Step - Verify tunnel stays up and send traffic over vxlan tunnel. #")
    result = verify_vxlan()
    if result is False :
        tc_result = False
        st.error("FAIL: Vxlan tunnel is down after switching to Vlan interface towards Leaf2 .")
    [result,err] =  verify_data_path(tc_list[0])
    if result is False:
        err = "L2/L3 vni traffic failed after switching to Vlan interfdut4_loopback_ipace towards Leaf2 ."
        st.error("FAIL: "+err) ; err_list.append(err)
        tc_result = False
    else:
        st.log('PASS: L2/L3 vni traffic verified .')
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")

    st.log("# Step - Bring up the shutdown interfaces between leaf and spine. #")
    port_api.noshutdown(data.dut3,data.d3d1_ports)
    st.wait(2)
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_002():
    tc_list = ['FtOpSoRoEvpnVlanFt002']
    tc_result = True ;err_list=[]
    # Bring down Physical router ports and link local POs between leaf and spine
    # Now traffic is routed through only vlan interfaces between leaf and spine.
    # Verify routes outgoing interfaces are Vlan interfaces .
    # Verify ping between Svtep and lvteps
    # Shutdown links to Spine
    # Send traffic and verify with default configs
    # Verify ping between Svtep and lvteps
    st.banner("\n{} - Untagged Vlan interface as underlay \n".format(tc_list[0]))
    st.banner("# Step - Shutdown physical router ports and link local ports on all Leaf nodes links towards spine.\
           Keeping only the Vlan interfaces UP.#")
    dict1 = {'portlist': [data.d3d1_ports[0],data.d3d1_ports[2]]}
    dict2 = {'portlist': [data.d4d2_ports[0],data.d4d2_ports[2]]}
    dict3 = {'portlist': [data.d5d1_ports[0],data.d5d1_ports[2],data.d5d2_ports[0],data.d5d2_ports[2]]}
    dict4 = {'portlist': [data.d6d1_ports[0],data.d6d1_ports[2],data.d6d2_ports[0],data.d6d2_ports[2]]}
    parallel.exec_parallel(True, data.leaf_list, port_api.shutdown, [dict1,dict2,dict3,dict4])
    if not verify_bgp():
        err = "FAIL: BGP neighborship between spine and leaf not up with vlan interfaces."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    # Temporary sleep
    st.wait(6)
    st.banner("## Step - Verify routes pointing to Vlan interfaces between leaf and spine ##")
    if not verify_spine_leaf_vlanint_routes():
        err = "FAIL: Routes over vlan interface between spine and leaf nodes not found ."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    else:
        st.log('PASS: Next hop over tagged vlan interface verified .')
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.banner("# Step - Send traffic between lvtep and svtep. #")
    [result,err] =  verify_data_path(tc_list[0])
    if result is False:
        err = "L2/L3 vni traffic failed over Vlan interfaces between Leaf and spine ."
        st.error("FAIL: "+err) ; err_list.append(err)
        tc_result = False
    else:
        st.log('PASS: Next hop over tagged vlan interface verified .')
        st.report_tc_pass("test_FtOpSoRoEvpnVlanFt002", "tc_passed")

    st.banner("## Step - Shutdown all Links towards spine on Leaf1 ## \n")
    port_api.shutdown(data.dut3,data.d3d1_ports)

    st.banner("## Step - Remove tagged vlan between lvtep nodes. Only untagged Vlan Int routes are available. ##")
    vlan_api.delete_vlan_member(data.dut3, vlan_l1_l2[0], iccp_lag, True)
    vlan_api.delete_vlan_member(data.dut4, vlan_l1_l2[0], iccp_lag, True)
    result = utils_obj.retry_api(ip_bgp.check_bgp_session, data.dut3, nbr_list=[dut4_3_ip_list[2]], state_list=['Established'],
                       delay=6, retry_count=15)
    if result is False:
        err ="FAIL: BGP neighborship down after deleting a vlan between lvtep nodes."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    st.banner("## Step - Verify show ip route pointing to Untagged Vlan interface as next hop ##")
    result1 = ip_api.verify_ip_route(dut=data.dut3,family="ipv4",interface=vlanInt_l1_l2[1],
                                  nexthop=dut4_3_ip_list[2], ip_address= dut5_loopback_ip[0]+ '/' + mask32,
                                     distance="20",cost="0")
    result2 = ip_api.verify_ip_route(dut=data.dut3,family="ipv4",interface=vlanInt_l1_l2[1],
                                  nexthop=dut4_3_ip_list[2], ip_address= dut6_loopback_ip[0]+ '/' + mask32,
                                     distance="20",cost="0")
    if False in [result1,result2] :
        err = "FAIL: Routes to svtep from leaf1 on untagged vlan interface not found ."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    st.banner("## Step - Verify tunnel stays up and send traffic over vxlan tunnel. ##")
    result = verify_vxlan()
    if result is False :
        st.error("FAIL: Vxlan tunnel is down after switching to Vlan interface towards Leaf2 .")
        tc_result = False

    lag  = 'PortChannel34'
    result1 = pc.verify_portchannel_member_state(data.dut7, lag, [data.d7d3_ports[3],data.d7d4_ports[3]])
    result2 = pc.verify_portchannel_member_state(data.dut3, lag, [data.d3d7_ports[3]])
    result3 = pc.verify_portchannel_member_state(data.dut4, lag, [data.d4d7_ports[3]])
    if False in [result1,result2,result3]:
        err = ("MCLAG client or its members are not up.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False

    st.banner("# Step - Send traffic between lvtep and svtep. #")
    [result,err] =  verify_data_path(tc_list[0])
    if result is False :
        err = "L2/L3 vni traffic failed after switching to Vlan interface towards Leaf2"
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    st.banner("# Step - Switch to tagged vlan member between lvtep nodes. #")
    vlan_api.add_vlan_member(data.dut3, vlan_l1_l2[0], iccp_lag, True)
    vlan_api.add_vlan_member(data.dut4, vlan_l1_l2[0], iccp_lag, True)
    vlan_api.delete_vlan_member(data.dut3, vlan_l1_l2[1], iccp_lag)
    vlan_api.delete_vlan_member(data.dut4, vlan_l1_l2[1], iccp_lag)
    st.wait(3)
    result = utils_obj.retry_api(ip_bgp.check_bgp_session, data.dut3, nbr_list=[dut4_3_ip_list[1]],
                           state_list=['Established'])
    if result is False:
        err ="FAIL: BGP neighborship down after deleting a vlan between lvtep nodes."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    result1 = ip_api.verify_ip_route(dut=data.dut3,family="ipv4",interface=vlanInt_l1_l2[0],
                                  nexthop=dut4_3_ip_list[1], ip_address= dut5_loopback_ip[0]+ '/' + mask32,
                                     distance="20",cost="0")
    result2 = ip_api.verify_ip_route(dut=data.dut3,family="ipv4",interface=vlanInt_l1_l2[0],
                                  nexthop=dut4_3_ip_list[1], ip_address= dut6_loopback_ip[0]+ '/' + mask32,
                                     distance="20",cost="0")
    if False in [result1,result2] :
        err= "FAIL: Routes to svtep from leaf1 not found on tagged vlan interface after switch from untagged."
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    st.banner("# Step - ping between lvtep client and svtep nodes. #")
    result = check_ping_clients()
    if result is False:
        err = "Ping test between VTEPs failed.";tc_result = False;err_list.append(err)
        st.error("FAIL: Routes to svtep from leaf1 not found .")
        st.generate_tech_support(dut=None,name=tc_list[0])

    st.banner("# Step - Revert back to default configs. #")
    vlan_api.add_vlan_member(data.dut3, vlan_l1_l2[1], iccp_lag)
    vlan_api.add_vlan_member(data.dut4, vlan_l1_l2[1], iccp_lag)
    st.wait(3)

    dict1 = {'portlist': data.d3d1_ports}
    dict2 = {'portlist': [data.d4d2_ports[0],data.d4d2_ports[2]]}
    dict3 = {'portlist': [data.d5d1_ports[0],data.d5d1_ports[2],data.d5d2_ports[0],data.d5d2_ports[2]]}
    dict4 = {'portlist': [data.d6d1_ports[0],data.d6d1_ports[2],data.d6d2_ports[0],data.d6d2_ports[2]]}
    parallel.exec_parallel(True, data.leaf_list, port_api.noshutdown, [dict1,dict2,dict3,dict4])
    st.wait(5)
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_011():
    err_list = []
    tc_result = True
    st.banner("\nFtOpSoRoEvpnVlanFt011 - BUM traffic over vlan interface .\n")
    utils.exec_all(True, [[mac_api.clear_mac, dut] for dut in data.dut_list[2:]])
    st.log("## Step - Verify BUM traffic before switching to Vlan interface with all Links towards spine on Leaf1 UP## \n")
    start_traffic(stream_han_list=stream_dict["BUM"])
    st.wait(5)
    result = verify_traffic_stats_bum()
    if result is False:
        err = "BUM traffic test between VTEPs failed."
        st.report_fail('test_case_failure_message',err)
    start_traffic(action="stop")

    st.log("## Step - Shutdown all Links towards spine on Leaf1 ## \n")
    port_api.shutdown(data.dut3,data.d3d1_ports)
    utils.exec_all(True, [[mac_api.clear_mac, dut] for dut in data.dut_list[2:]])

    st.log("## Step - Verify tunnel stays up and send traffic over vxlan tunnel. ##")
    result = verify_vxlan()
    if result is False :
        err = "Vxlan tunnel is down after switching to Vlan interface towards Leaf2 ."
        st.error("FAIL: "+ err); err_list.append(err)
        tc_result = False
    utils.exec_all(True, [[mac_api.clear_mac, dut] for dut in data.dut_list[2:]])

    st.log("# Step - Send BUM traffic between lvtep and svtep. #")
    start_traffic(stream_han_list=stream_dict["BUM"])
    st.wait(2)
    result = verify_traffic_stats_bum()
    if result is False :
        err = " traffic failed after switching to Vlan interface towards Leaf2."
        st.error("FAIL: "+ err); err_list.append(err)
        tc_result = False

    port_api.noshutdown(data.dut3, data.d3d1_ports)
    start_traffic(action="stop")

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_015():
    err_list = []
    tc_result = True
    tc_list = ['FtOpSoRoEvpnVlanFt015']
    st.log("\nFtOpSoRoEvpnVlanFt015 - Link state tracking with vlan underlay and mclag mac config .\n")

    link_track_name = "track_mclag"
    dut = data.dut3
    evpn.create_linktrack(dut, link_track_name, config='yes')
    evpn.update_linktrack_interface(dut, link_track_name, data.d3d1_ports[0], "2")
    result = evpn.verify_linktrack_summary(dut=dut, name=link_track_name, timeout="2")

    st.log("## Step - Shutdown all Links towards spine on Leaf1 ## \n")
    port_api.shutdown(data.dut3,data.d3d1_ports)
    st.wait(2)
    result = pc.verify_portchannel_member_state(data.dut3, orphan_lag, [data.d3d7_ports[2]])
    if result is False:
        err = " Orphan portchannel down after spine links are brought down."
        st.error("FAIL: " + err)
        err_list.append(err)
        tc_result = False

    st.log("# Step - Send traffic between lvtep and svtep. #")
    [result,err] =  verify_data_path(tc_list[0])
    if result is False:
        err = " traffic failed after switching to Vlan interface towards Leaf2."
        st.error("FAIL: "+ err); err_list.append(err)
        tc_result = False

    port_api.noshutdown(data.dut3,data.d3d1_ports)
    evpn.update_linktrack_interface(dut, link_track_name, data.d3d1_ports[0], "2", config='no')
    evpn.create_linktrack(dut, link_track_name, config='no')

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_014():
    tc_list = ['FtOpSoRoEvpnVlanFt016','FtOpSoRoEvpnVlanFt014','FtOpSoRoEvpnVlanFt017','FtOpSoRoEvpnSysMacFt006']
    tc = "FtOpSoRoEvpnSysMacFt004"
    tc_result = True ;err_list=[]
    # Verify Vlan interface underlay routes between spine and leaf on all leaf nodes.
    # Send traffic between lvtep and svtep.
    # Verify ping between Svtep and lvteps
    # Shutdown links to Spine
    # Send traffic and verify with default configs
    # Verify ping between Svtep and lvteps

    st.log("\n{} -  Vlan interface as underlay between lvtep nodes\n".format(tc_list[1]))

    st.log("## Step - Shutdown all Links towards spine on Leaf1 ## \n")
    port_api.shutdown(data.dut3,data.d3d1_ports)
    trigger_list = ['clear_bgp','bgp_docker','fast_reboot','config_reload']

    st.log("## Step - Save config ##")
    data.my_dut_list = [data.dut3, data.dut1]
    bgp_api.enable_docker_routing_config_mode(data.dut3)
    reboot_api.config_save(data.dut3)
    reboot_api.config_save(data.dut3, 'vtysh')

    for trigger,tc in zip(trigger_list,tc_list):
        if trigger == 'clear_bgp':
            st.log("## Step - Trigger clear bgp ##")
            bgp_api.clear_ip_bgp_vtysh(data.dut3)

        elif trigger == "bgp_docker":
            st.log("## Step - Trigger bgp docker restart ##")
            basic_api.service_operations_by_systemctl(data.dut3, "bgp", "restart")
            st.wait(2)
            result = utils_obj.retry_api(basic_api.get_system_status, data.dut3, service = 'bgp', retry_count=20, delay=2)
        elif trigger == "fast_reboot":
            st.log("## Step - Trigger fast reboot ##")
            st.reboot(data.dut3, "fast")
        elif trigger == "config_reload":
            st.log("## Step - Trigger config reload ##")
            reboot_api.config_reload(data.dut3)

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, data.dut3, nbr_list=[dut4_loopback_ip[0]],
                           state_list=['Established'])
        if not result:
            st.error("FAIL: BGP neighborship failed after {}.".format(trigger))

        st.log("## Step - Verify routes pointing to Vlan interfaces between Lvtep ##")
        result = verify_lvtep_vlanint_routes()
        if result is False :
            st.error("FAIL: Routes to remote svtep from leaf1 not found .")

        st.log("# Step - Verify tunnel stays up and send traffic over vxlan tunnel. #")
        result = verify_vxlan()
        if result is False :
            tc_result = False
            st.error("FAIL: Vxlan tunnel is down after switching to Vlan interface towards Leaf2 .")
        result = check_ping_clients()
        if result is False:
            err = "Ping test between VTEPs failed."
            err_list.append(err);
            tc_result = False
            st.generate_tech_support(dut=None,name=tc)

        st.log("# Step - Verify mclag system mac and gateway mac. #")

        result = verify_mclag_macs()
        if result is False:
            err = (" MCLAG system MAC and mclag gateway verification failed.")
            st.error("FAIL:" + err);
            err_list.append(err)
            tc_result = False

    st.log("# Step - Bring up the shutdown interfaces between leaf and spine. #")
    port_api.noshutdown(data.dut3,data.d3d1_ports)
    st.wait(2)
    result = check_ping_clients()
    if result is False:
        err = "Ping test between VTEPs failed."
        err_list.append(err);
        tc_result = False

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_mclag_sys_mac_001():
    err_list = []
    tc_result = True
    st.log("\nFtOpSoRoEvpnSysMacFt001- MCLAG System MAC and system gateway verification .\n")

    st.log("## Step - Verify mclag system mac and gateway mac ## \n")
    result = verify_mclag_macs()
    if result is False :
        err = (" MCLAG system MAC and mclag gateway verification failed.")
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    po_data = utils_obj.get_interface_number_from_name(client_lag)
    po_num = po_data['number']
    st.log("## Step - Verify mclag system mac on remote node partner lacp mac ## \n")
    result = pc.verify_interface_portchannel(data.dut7,channel_number=po_num,partner_mac=mclag_sys_mac)
    if result is False :
        err = (" MCLAG system MAC and mclag gateway verification failed.")
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    st.log("## Step - Modify mclag system mac and gateway mac and verify ## \n")
    sysmac1 = "10:10:10:10:11:11"
    gw1 = "10:10:10:10:22:22"
    lvtep_nodes = [data.dut3,data.dut4]
    dict1 = {'mac': mclag_gw_mac ,'config': 'del' }
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_gw_mac, [dict1]*2)

    dict1 = {'mac': gw1 }
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_gw_mac, [dict1]*2)
    dict1 = {'domain_id' : mlag_domain_id,'mac': sysmac1 }
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_mclag_system_mac, [dict1]*2)

    st.log("## Step - Verify modified mclag system mac and gateway mac ## \n")
    result = verify_mclag_macs(gw_mac=gw1,sys_mac=sysmac1)
    if result is False:
        err = (" Modified MCLAG system MAC and mclag gateway verification failed.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False
    st.wait(3)

    st.log("\n## Step - Verify updated mclag system mac on remote node partner lacp mac ## \n")
    result = pc.verify_portchannel_member_state(data.dut7, client_lag, [data.d7d3_ports[0],data.d7d4_ports[0]])
    if result is False:
        err = (" PO or its members are down after MCLAG system MAC mac is changed.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False

    result = pc.verify_interface_portchannel(data.dut7, channel_number=po_num, partner_mac=sysmac1)
    if result is False:
        err = (" Modified MCLAG system MAC and mclag gateway verification failed.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False
    st.wait(3)
    st.log("\n## Step - Verify portchannel after mclag system mac reconfiguration ## \n")
    result1 = mclag.verify_interfaces(data.dut3,domain_id=1, mclag_intf='PortChannel12', mclag_intf_local_state="Up", mclag_intf_peer_state="Up")
    result2 = mclag.verify_interfaces(data.dut4,domain_id=1, mclag_intf='PortChannel12', mclag_intf_local_state="Up", mclag_intf_peer_state="Up")
    if False in [result1,result2]:
        err = (" MCLAG towards client down after MCLAG system MAC and mclag gateway are modified .")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False
    result = check_ping_clients()
    if result is False:
        err = "Ping test between VTEPs failed."
        err_list.append(err);
        tc_result = False
        st.generate_tech_support(dut=None,name="FtOpSoRoEvpnSysMacFt001")

    dict1 = {'mac': gw1, 'config': 'del'}
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_gw_mac, [dict1] * 2)

    dict1 = {'mac': mclag_gw_mac}
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_gw_mac, [dict1] * 2)
    dict1 = {'domain_id': mlag_domain_id, 'mac': mclag_sys_mac}
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_mclag_system_mac, [dict1] * 2)

    result = verify_mclag_macs()
    if result is False:
        err = (" Revert back MCLAG system MAC and mclag gateway verification failed.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def cleanup_mclag_sys_mac_002():
    yield
    lag  = 'PortChannel34'
    ip4 = ['70.34.2.1', '70.34.2.1','70.34.2.20']
    ip6  = ["7034::1", "7034::1","7034::20"]

    def leaf1():
        dut = data.dut3
        mclag.config_interfaces(dut, mlag_domain_id, lag, config="del")
        ip_api.delete_ip_interface(dut, lag, ip4[0], mask_24)
        ip_api.delete_ip_interface(dut, lag, ip6[0], mask_v6, family='ipv6')
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=lag,config = 'no',skip_error=True)
        pc.delete_portchannel_member(dut, lag, [data.d3d7_ports[3]])
        pc.delete_portchannel(dut, lag)

    def leaf2():
        dut = data.dut4
        mclag.config_interfaces(dut, mlag_domain_id, lag, config="del")
        ip_api.delete_ip_interface(dut, lag, ip4[1], mask_24)
        ip_api.delete_ip_interface(dut, lag, ip6[1], mask_v6, family='ipv6')
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=lag,config = 'no',skip_error=True)
        pc.delete_portchannel_member(dut, lag, [data.d4d7_ports[3]])
        pc.delete_portchannel(dut, lag)

    def client():
        dut = data.dut7
        ip_api.delete_ip_interface(dut, lag, ip4[2], mask_24)
        ip_api.delete_ip_interface(dut, lag, ip6[2], mask_v6, family='ipv6')
        #vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=lag,config = 'no')
        pc.delete_portchannel_member(dut, lag, [data.d7d3_ports[3],data.d7d4_ports[3]])
        pc.delete_portchannel(dut, lag)
        ip_api.delete_static_route(dut, next_hop=ip4[0], static_ip="60.1.1.0" + '/' + mask_24)
        ip_api.delete_static_route(dut, next_hop=ip6[0], family='ipv6', static_ip="6001::0" + '/' + mask_v6)
    st.exec_all([[leaf1],[leaf2],[client]])

def test_mclag_sys_mac_002(cleanup_mclag_sys_mac_002):
    err_list = []
    tc_result = True
    st.banner("\nFtOpSoRoEvpnSysMacFt003 - MCLAG system mac with L3 PortChannel .\n")
    # Configure L3 portchannel on lvtep nodes and client
    # Verify PO status and partner id on client lag
    # Ping and verify
    lag  = 'PortChannel34'
    ip4 = ['70.34.2.1', '70.34.2.1','70.34.2.20']
    ip6  = ["7034::1", "7034::1","7034::20"]

    def leaf1():
        dut = data.dut3
        pc.create_portchannel(dut, lag)
        pc.add_portchannel_member(dut, lag, [data.d3d7_ports[3]])
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=lag)
        ip_api.config_ip_addr_interface(dut, lag, ip4[0], mask_24)
        ip_api.config_ip_addr_interface(dut, lag, ip6[0], mask_v6, family='ipv6')
        mclag.config_interfaces(dut, mlag_domain_id, lag, config="add")

    def leaf2():
        dut = data.dut4
        pc.create_portchannel(dut, lag)
        pc.add_portchannel_member(dut, lag, [data.d4d7_ports[3]])
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=lag)
        ip_api.config_ip_addr_interface(dut, lag, ip4[1], mask_24)
        ip_api.config_ip_addr_interface(dut, lag, ip6[1], mask_v6, family='ipv6')
        mclag.config_interfaces(dut, mlag_domain_id, lag, config="add")

    def client():
        dut = data.dut7
        pc.create_portchannel(dut, lag)
        pc.add_portchannel_member(dut, lag, [data.d7d3_ports[3],data.d7d4_ports[3]])
        ip_api.config_ip_addr_interface(dut, lag, ip4[2], mask_24)
        ip_api.config_ip_addr_interface(dut, lag, ip6[2], mask_v6, family='ipv6')
    st.exec_all([[leaf1],[leaf2],[client]])
    st.wait(2)

    result1 = pc.verify_portchannel_member_state(data.dut7, lag, [data.d7d3_ports[3],data.d7d4_ports[3]])
    result2 = pc.verify_portchannel_member_state(data.dut3, lag, [data.d3d7_ports[3]])
    result3 = pc.verify_portchannel_member_state(data.dut4, lag, [data.d4d7_ports[3]])
    if False in [result1,result2,result3]:
        err = (" L3 Portchannel or its members are not up.")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False

    po_data = utils_obj.get_interface_number_from_name(lag)
    po_num = po_data['number']
    result = pc.verify_interface_portchannel(data.dut7, channel_number=po_num,partner_mac=mclag_sys_mac)
    if False in [result]:
        err = (" L3 Portchannel MCLAG system mac verification failed .")
        st.error("FAIL:" + err);
        err_list.append(err)
        tc_result = False

    dut = data.dut7
    ip_api.create_static_route(dut, next_hop=ip4[0], static_ip="60.1.1.0" + '/' + mask_24)
    ip_api.create_static_route(dut, next_hop=ip6[0], family='ipv6', static_ip="6001::0" + '/' + mask_v6)
    ipv4_addr = leaf4_dict["l3_tenant_ip_list"][0]
    ip6_addr = leaf4_dict["l3_tenant_ipv6_list"][0]
    st.wait(5)
    ip_list = [ipv4_addr, ip6_addr]
    result = verify_ping_ip(dut, ip_list, ip4_v6='both',vrf=po_data['type']+po_data['number'])
    if result is False:
        err = (" Ping over L3 Portchannel with MCLAG system mac verification failed .")
        st.error("FAIL:" + err); err_list.append(err)
        tc_result = False
        st.generate_tech_support(dut=None,name="FtOpSoRoEvpnSysMacFt003")

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_004():
    tc_list = ['FtOpSoRoEvpnVlanFt003']
    tc_result = True ;err_list=[]

    # On client remove Vlan 100
    # Configure static ipv4 and ipv6 route on client to simulate asymmetric IRB route
    # Route Vlan100 traffic to Vlan200
    # Ping Leaf3 Vlan100 Ip address.
    vlan_101_ip = ['101.10.10.1','101.10.10.40','101.10.10.5']
    vlan_102_ip = ['102.10.10.1','102.10.10.40']
    vlan_101_ip6 = ['1001::1', '1001::40', '1001::5']
    vlan_102_ip6 = ['1002::1', '1002::40', '1002::5']

    vlan_int = ['Vlan101','Vlan102']

    def config_irb_topo(config='yes'):
        if config == 'yes':
            api_ip_config = ip_api.config_ip_addr_interface
            api_route_config = ip_api.create_static_route
        else:
            api_ip_config = ip_api.delete_ip_interface
            api_route_config = ip_api.delete_static_route

        def leaf1():
            # Config Vlan 101, 102  Ip address
            dut = data.dut3
            api_ip_config(dut, vlan_int[0], vlan_101_ip[0], mask_24)
            api_ip_config(dut, vlan_int[0], vlan_101_ip6[0], mask_v6, family='ipv6')
            api_ip_config(dut, vlan_int[1], vlan_102_ip[0], mask_24)
            api_ip_config(dut, vlan_int[1], vlan_102_ip6[0], mask_v6, family='ipv6')

        def leaf4():
            # Config Vlan 101, 102  Ip address
            dut = data.dut6
            api_ip_config(dut, vlan_int[0], vlan_101_ip[1], mask_24)
            api_ip_config(dut, vlan_int[0], vlan_101_ip6[1], mask_v6, family='ipv6')
            api_ip_config(dut, vlan_int[1], vlan_102_ip[1], mask_24)
            api_ip_config(dut, vlan_int[1], vlan_102_ip6[1], mask_v6, family='ipv6')
            evpn.config_bgp_evpn(dut=dut, config=config, config_type_list=["advertise_default_gw"], local_as=dut6_AS)

        def client():
            # Config Vlan 101 Ip address
            # Config static route
            dut = data.dut7
            api_ip_config(dut, vlan_int[0], vlan_101_ip[2], mask_24)
            api_ip_config(dut, vlan_int[0], vlan_101_ip6[2], mask_v6, family='ipv6')
            api_route_config(dut, next_hop=vlan_101_ip[0], static_ip="102.10.10.0" + '/' + mask_24)
            api_route_config(dut, next_hop=vlan_101_ip6[0], family='ipv6', static_ip="1002::0" + '/' + mask_v6)

        st.exec_all([[leaf1],[leaf4],[client]])

    config_irb_topo()
    ip_list = [vlan_102_ip[1], vlan_102_ip6[1]]
    result = verify_ping_ip(data.dut7, ip_list, ip4_v6='both')
    if result is False:
        st.error(" Asymmetric IRB validation failed.")
    config_irb_topo(config='no')

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_evpn_vlan_underlay_003():
    tc_list = ['FtOpSoRoEvpnVlanFt003']
    tc_result = True ;err_list=[]
    # Modify from ebgp to ibgp
    # Send traffic and verify with default configs
    # Verify ping between Svtep and lvteps
    # Shutdown links to Spine
    # Send traffic and verify with default configs
    # Verify ping between Svtep and lvteps
    # Revert back to eBGP
    st.log("\nFtOpSoRoEvpnVlanFt003 - iBGP with Vlan interface as underlay .\n")
    vlan = vni_vlan[0]
    dict1 = {'vtep_name' : vtep_names[0], 'vni' : vlan, 'vrf_name' : vrf1}
    dict2 = {'vtep_name' : vtep_names[0], 'vni' : vlan, 'vrf_name' : vrf1}
    dict3= {'vtep_name' : vtep_names[2], 'vni' : vlan, 'vrf_name' : vrf1}
    dict4 = {'vtep_name' : vtep_names[3], 'vni' : vlan, 'vrf_name' : vrf1}
    dict5 = {'vtep_name' : vtep_names[0], 'vni' : vlan, 'vrf_name' : vrf1, 'config' : 'no'}
    dict6 = {'vtep_name' : vtep_names[0], 'vni' : vlan, 'vrf_name' : vrf1, 'config' : 'no'}
    dict7= {'vtep_name' : vtep_names[2], 'vni' : vlan, 'vrf_name' : vrf1, 'config' : 'no'}
    dict8 = {'vtep_name' : vtep_names[3], 'vni' : vlan, 'vrf_name' : vrf1, 'config' : 'no'}
    parallel.exec_parallel(True, data.leaf_list, evpn.map_vrf_vni, [dict5,dict6,dict7,dict8])

    config_bgp(config='no')
    parallel.exec_parallel(True, data.leaf_list, evpn.map_vrf_vni, [dict1,dict2,dict3,dict4])
    config_ibgp()

    result = verify_bgp()
    if result is False:
        err = "iBGP neighborship  Failed to come up."
        st.report_fail('test_case_failure_message',err)
    #tunnel_static_routes()
    st.log("# Step - Verify tunnel stays up and send traffic over vxlan tunnel. #")
    result = verify_vxlan()
    if result is False :
        tc_result = False
        st.error("FAIL: Vxlan tunnel is down after switching to Vlan interface towards Leaf2 .")
    result = check_ping_clients()
    if result is False:
        err = "Ping test between VTEPs failed."
        err_list.append(err);
        tc_result = False

    st.log("Shutdown Link towards spine on Leaf1")
    port_api.shutdown(data.dut3,data.d3d1_ports)

    st.log("Verify tunnel stays up using Vlan interface via Leaf2")
    [result,err] = verify_data_path(tc_list[0])
    if result is False :
        err = "L2/L3 vni traffic failed after switching to Vlan interface towards Leaf2"
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    parallel.exec_parallel(True, data.leaf_list, evpn.map_vrf_vni, [dict5,dict6,dict7,dict8])
    config_ibgp(config='no')
    parallel.exec_parallel(True, data.leaf_list, evpn.map_vrf_vni, [dict1,dict2,dict3,dict4])
    #tunnel_static_routes(config = 'no')
    port_api.noshutdown(data.dut3,data.d3d1_ports)
    config_bgp()
    ebgp_additional_config()
    st.wait(5)
    result = verify_bgp()
    if result is False:
        err = "eBGP neighborship  Failed to come up."
        st.report_fail('test_case_failure_message',err)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_rest_mclag_system_mac_001():
    tc_list = ['FtOpSoRoEvpnVlanFt003']
    tc_result = True ;err_list=[]
    sysmac1 = "00:11:22:33:44:55"
    #ocdata = {"openconfig-mclag:mclag-domains": {"mclag-domain": [{"domain-id": 1, "config": {"domain-id": 1, "mclag-system-mac": sysmac1}}]}}
    ocdata = {"openconfig-mclag:mclag-system-mac": sysmac1}
    lvtep_nodes = [data.dut3,data.dut4]
    dict1 = {'domain_id' : mlag_domain_id,'mac': sysmac1 , 'config' : 'del'}
    parallel.exec_parallel(True, lvtep_nodes, mclag.config_mclag_system_mac, [dict1]*2)
    st.wait(4)
    dut = data.dut3
    ### REST PATCH
    #rest_url = "/restconf/data/openconfig-mclag:mclag"
    rest_url = "/restconf/data/openconfig-mclag:mclag/mclag-domains/mclag-domain={}/config/mclag-system-mac".format(mlag_domain_id)
    st.banner("REST POST operation to create the MCLAG config ")
    response = st.rest_modify(dut, path=rest_url, data=ocdata)
    st.log(response)
    if not response["status"] in [200, 201, 204]:
        err = "Failed to config MCLAG through REST API ,"
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    ### REST GET
    rest_url_read = "/restconf/data/openconfig-mclag:mclag"
    response = st.rest_read(dut, rest_url_read)
    st.log(response)
    if not response["status"] in [200, 204]:
        err = "Failed to read MCLAG config details through REST API, "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False
    if sysmac1 != response['output']['openconfig-mclag:mclag']['mclag-domains']['mclag-domain'][0]['config']['mclag-system-mac']:
        err = "MCLAG system mac configured by REST API is incorrect on DUT. "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    rest_url_del = "/restconf/data/openconfig-mclag:mclag/mclag-domains/mclag-domain={}/config/mclag-system-mac".format(mlag_domain_id)

    response = st.rest_delete(dut, rest_url_del)
    st.log(response)
    if not response["status"] in [200, 204]:
        err = "Failed to delete MCLAG config through REST API, "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    dict1 = {'domain_id': mlag_domain_id, 'mac': mclag_sys_mac}
    parallel.exec_parallel(True, [data.dut3,data.dut4], mclag.config_mclag_system_mac, [dict1] * 2)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_rest_mclag_gateway_mac_001():
    tc_list = ['FtOpSoRoEvpnVlanFt003']
    tc_result = True ;err_list=[]
    gw1 = "00:00:33:33:33:06"
    ocdata = {"openconfig-mclag:mclag-gateway-macs": { "mclag-gateway-mac": [ { "config": {"gateway-mac": gw1}}]}}

    dict1 = {'mac': mclag_gw_mac, 'config': 'del'}
    parallel.exec_parallel(True, [data.dut3,data.dut4], mclag.config_gw_mac, [dict1] * 2)

    dut = data.dut3
    ### REST PATCH
    st.log("Step Modifying MCLAG config through REST Patch operation")
    rest_patch = "/restconf/data/sonic-mclag:sonic-mclag/MCLAG_GW_MAC/MCLAG_GW_MAC_LIST"
    ocyangData = {"sonic-mclag:MCLAG_GW_MAC_LIST": [{"gw_mac": gw1, "gw_mac_en": "enable"}]}
    response = st.rest_modify(dut, path=rest_patch, data=ocyangData)
    st.log(response)
    if not response["status"] in [200, 204]:
        err = "Failed to config MCLAG gateway mac through REST API"
        st.error("FAIL:" + err);
        err_list.append(err)
        test_result = False

    ### REST GET
    st.log("Step to get MCLAG state through REST GET operation")

    rest_url_read = "/restconf/data/openconfig-mclag:mclag"
    response = st.rest_read(dut, rest_url_read)
    st.log(response)
    if not response["status"] in [200, 204]:
        err = "Failed to read MCLAG gateway config details through REST API, "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    if gw1 != response['output']['openconfig-mclag:mclag']['mclag-gateway-macs']['mclag-gateway-mac'][0]['gateway-mac']:
        err = "MCLAG gateway mac configured by REST API is incorrect on DUT. "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    rest_url_del = "/restconf/data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac={}".format(gw1)

    response = st.rest_delete(dut, rest_url_del)
    st.log(response)
    if not response["status"] in [200, 204]:
        err = "Failed to delete MCLAG gateway config through REST API, "
        st.error("FAIL:"+err); err_list.append(err)
        tc_result = False

    dict1 = {'mac': mclag_gw_mac }
    parallel.exec_parallel(True, [data.dut3, data.dut4], mclag.config_gw_mac, [dict1] * 2)

    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])


def config_sla_base(config='yes'):
    def leaf1():
        dut=data.dut3
        vlan_api.create_vlan(dut,target_vlans[0])
        vlan_api.add_vlan_member(dut,target_vlans[0],[client_lag,iccp_lag], True)
        mclag.config_uniqueip(dut, op_type='add', vlan=target_vlan_intfs[0])
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0],mclag_sla_ips_1[0], mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0], mclag_sla_ipv6_1[0], mask_v6,family='ipv6')

    def leaf2():
        dut=data.dut4
        vlan_api.create_vlan(dut,target_vlans[0])
        vlan_api.add_vlan_member(dut,target_vlans[0],[client_lag,iccp_lag], True)
        mclag.config_uniqueip(dut, op_type='add', vlan=target_vlan_intfs[0])
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0], mclag_sla_ips_2[0], mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0], mclag_sla_ipv6_2[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut,target_vlan_intfs[2],client_dict['l3_tenant_ip_list3'][1],mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[2], client_dict['l3_tenant_ipv6_list3'][1], mask_v6,family='ipv6')
        ip_api.config_ip_addr_interface(dut,target_vlan_intfs[2],mclag_sla_ips_2[2],mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[2],mclag_sla_ipv6_2[2], mask_v6,family='ipv6')


    def client():
        dut = data.dut7
        bgp_api.config_bgp(dut=dut, local_as='700',config='yes',config_type_list=[])
        vlan_api.create_vlan(dut,target_vlans[0])
        vlan_api.add_vlan_member(dut,target_vlans[0],[client_lag], True)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0], target_ips[0], mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[0], target_ipv6[0], mask_v6, family='ipv6')
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[1], target_ips[1], mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[1], target_ipv6[1], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut,target_vlan_intfs[2],client_dict['l3_tenant_ip_list2'][1],mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[2], client_dict['l3_tenant_ipv6_list2'][1], mask_v6,family='ipv6')
        ip_api.config_ip_addr_interface(dut,target_vlan_intfs[2],target_ips[2],mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[2],target_ipv6[2], mask_v6,family='ipv6')


    def leaf1_unconfig():
        dut=data.dut3
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0],mclag_sla_ips_1[0], mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0], mclag_sla_ipv6_1[0], mask_v6,family='ipv6')
        mclag.config_uniqueip(dut, op_type='del', vlan=target_vlan_intfs[0])
        vlan_api.delete_vlan_member(dut,target_vlans[0],[client_lag,iccp_lag], True)
        vlan_api.delete_vlan(dut, target_vlans[0])

    def leaf2_unconfig():
        dut = data.dut4
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0], mclag_sla_ips_2[0], mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0], mclag_sla_ipv6_2[0],mask_v6, family='ipv6')

        ip_api.delete_ip_interface(dut,target_vlan_intfs[2],mclag_sla_ips_2[2],mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[2],mclag_sla_ipv6_2[2], mask_v6,family='ipv6')

        ip_api.config_ip_addr_interface(dut,target_vlan_intfs[2],client_dict['l3_tenant_ip_list3'][1],mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[2], client_dict['l3_tenant_ipv6_list3'][1], mask_v6,family='ipv6')

        mclag.config_uniqueip(dut, op_type='del', vlan=target_vlan_intfs[0])
        vlan_api.delete_vlan_member(dut, target_vlans[0], [client_lag,iccp_lag], True)
        vlan_api.delete_vlan(dut, target_vlans[0])

    def client_unconfig():
        dut = data.dut7
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0], target_ips[0], mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[0], target_ipv6[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, target_vlan_intfs[1], target_ips[1], mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[1], target_ipv6[1], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut,target_vlan_intfs[2],target_ips[2],mask_24)
        ip_api.delete_ip_interface(dut, target_vlan_intfs[2],target_ipv6[2], mask_v6,family='ipv6')
        ip_api.config_ip_addr_interface(dut,target_vlan_intfs[2],client_dict['l3_tenant_ip_list2'][1],mask_24)
        ip_api.config_ip_addr_interface(dut, target_vlan_intfs[2], client_dict['l3_tenant_ipv6_list2'][1], mask_v6,family='ipv6')
        vlan_api.delete_vlan_member(dut, target_vlans[0], [client_lag], True)
        vlan_api.delete_vlan(dut, target_vlans[0])
        bgp_api.config_bgp(dut=dut, local_as='700', config='no',removeBGP='yes',config_type_list=[])

    if config == 'yes':
        st.exec_all([[leaf1], [leaf2], [client]])
    else:
        st.exec_all([[leaf1_unconfig], [leaf2_unconfig], [client_unconfig]])

@pytest.fixture(scope="function")
def sla_fixture(request,prologue_epilogue):
    config_sla_base()
    config_ipsla()
    yield
    config_ipsla(config='no',same_sla_id=True)
    config_sla_base('no')

def test_evpn_vlan_underlay_sla(sla_fixture):
    tc_list = ['FtOpSoRoIpSlaFt017','FtOpSoRoIpSlaFt023','FtOpSoRoIpSlaFt024','FtOpSoRoIpSlaFt025']
    tc_flag={}
    for tc in tc_list: tc_flag[tc] =True
    tc_result =True;err_list=[];tech_support=True

    ##########################################
    st.banner("Vefify SLAs comes up with Unique-ip configued over default-vrf on MLAG peers")
    ##########################################
    result = verify_ipsla(type='default')
    if not result:
        err ='one or more SLAs over default-vrf did not come up with unique ip config'
        st.error(err);tc_result=False;err_list.append(err);
        if tech_support:st.generate_tech_support(dut=None,name='FtOpSoRoIpSlaFt017')
        tech_support=False;tc_flag['FtOpSoRoIpSlaFt017']=False

    ##########################################
    st.banner("Trigger target failure and verify SLA goes down")
    ##########################################
    ip_api.delete_ip_interface(data.dut7,target_vlan_intfs[0],target_ips[0],mask_24)
    ip_api.delete_ip_interface(data.dut7, target_vlan_intfs[0], target_ipv6[0], mask_v6,family='ipv6')
    result = verify_ipsla(exp_state='Down',type='default')
    if not result:
        err = 'SLAs on default-vrf (unique-ip) did not timeout after ip addres unconfig'
        st.error(err); tc_result = False; err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt017')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt017'] = False

    ##########################################
    st.banner("Re-add ip config and verify SLA comes up on default-vrf")
    ##########################################
    ip_api.config_ip_addr_interface(data.dut7,target_vlan_intfs[0],target_ips[0],mask_24)
    ip_api.config_ip_addr_interface(data.dut7, target_vlan_intfs[0], target_ipv6[0], mask_v6,family='ipv6')
    result = verify_ipsla(type='default')
    if not result:
        err = 'SLAs did not come up on default-vrf(unique-ip)'
        st.error(err); tc_result = False; err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt017')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt017'] = False

    if tc_flag['FtOpSoRoIpSlaFt017']:
        st.report_tc_pass('FtOpSoRoIpSlaFt017','tc_passed')
    ##########################################
    st.banner("Verify SLAs on user-vrf(unique-ip)")
    ##########################################
    result = verify_ipsla(type='unique_ip')
    if not result:
        err = 'In Mlag peers,SLAs did not come up on user-vrf unique-ip'
        st.error(err); tc_result = False; err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False;tc_flag['FtOpSoRoIpSlaFt023'] = False
    ##########################################
    st.banner("Trigger target failure and verify SLa over user-vrfon unique-ip goes down")
    ##########################################
    ip_api.delete_ip_interface(data.dut7,target_vlan_intfs[2],target_ips[2],mask_24)
    ip_api.delete_ip_interface(data.dut7, target_vlan_intfs[2], target_ipv6[2], mask_v6,family='ipv6')
    result = verify_ipsla(exp_state='Down',type='unique_ip')
    if not result:
        err = 'After target failure, SLAs did not go down for unique-ip(user-vrf)'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt023'] = False
    ##########################################
    st.banner("Readd IP config and verify SLAs comes up on user-vrf(unique-ip)")
    ##########################################
    ip_api.config_ip_addr_interface(data.dut7,target_vlan_intfs[2],target_ips[2],mask_24)
    ip_api.config_ip_addr_interface(data.dut7, target_vlan_intfs[2], target_ipv6[2], mask_v6,family='ipv6')
    result = verify_ipsla(type='unique_ip')
    if not result:
        err = 'Aftre ip re-config,SLAs did not come up on unique-ip(user-vrf)'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt023'] = False

    if tc_flag['FtOpSoRoIpSlaFt023']:
        st.report_tc_pass('FtOpSoRoIpSlaFt023','tc_passed')
    """
    ##########################################
    st.banner("")
    ##########################################
    result = verify_ipsla(type='same_ip')
    if not result:
        err = ''
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt023'] = False
    ##########################################
    st.banner("")
    ##########################################
    ip_api.delete_ip_interface(data.dut7,target_vlan_intfs[1],target_ips[1],mask_24)
    ip_api.delete_ip_interface(data.dut7, target_vlan_intfs[1], target_ipv6[1], mask_v6,family='ipv6')
    result = verify_ipsla(exp_state='Down',type='same_ip')
    if not result:
        err = ''
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt023'] = False
    ##########################################
    st.banner("")
    ##########################################
    ip_api.config_ip_addr_interface(data.dut7,target_vlan_intfs[1],target_ips[1],mask_24)
    ip_api.config_ip_addr_interface(data.dut7, target_vlan_intfs[1], target_ipv6[1], mask_v6,family='ipv6')
    result = verify_ipsla(type='same_ip')
    if not result:
        err = ''
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt023')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt023'] = False

    if tc_flag['FtOpSoRoIpSlaFt023']:
        st.report_tc_pass('FtOpSoRoIpSlaFt023','tc_passed')
    """
    ##########################################
    st.banner("Verify SLAs configured with SAG-IP as src comes up on MLAg peers")
    ##########################################
    result = verify_ipsla(type='sag_ip')
    if not result:
        err = 'SLAs configured on SAG interface did not come up'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt024')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt024'] = False
    ##########################################
    st.banner("Delete iP/ipv6 address and verify SLAs over SAG interface goes down")
    ##########################################
    ip_api.delete_ip_interface(data.dut7,target_vlan_intfs[3],target_ips[3],mask_24)
    ip_api.delete_ip_interface(data.dut7, target_vlan_intfs[3], target_ipv6[3], mask_v6,family='ipv6')
    result = verify_ipsla(exp_state='Down',type='sag_ip')
    if not result:
        err = 'SLAs over SAG interface did not go down'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt024')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt024'] = False
    ##########################################
    st.banner("Re-add ip/ipv6 configs and verify SLAs over SAG interface comes up")
    ##########################################
    ip_api.config_ip_addr_interface(data.dut7,target_vlan_intfs[3],target_ips[3],mask_24)
    ip_api.config_ip_addr_interface(data.dut7, target_vlan_intfs[3], target_ipv6[3], mask_v6,family='ipv6')
    result = verify_ipsla(type='sag_ip')
    if not result:
        err = 'SLAs over SAG interface did not come up'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt024')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt024'] = False

    if tc_flag['FtOpSoRoIpSlaFt024']:
        st.report_tc_pass('FtOpSoRoIpSlaFt024','tc_passed')

    ##########################################
    st.banner("Configure SLAs on MLAG peers for same targets with same SLA-ID")
    ##########################################
    config_ipsla(config='no')
    config_ipsla(same_sla_id=True)
    ##########################################
    st.banner("Verify SLAs on MLAG peers configured with same SLA-ID comes up")
    ##########################################
    result = verify_ipsla(type='all',same_sla_id=True)
    if not result:
        err = 'SLAs configured with same ID on MLAG peers did not come up'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt025')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt025'] = False
    ##########################################
    st.banner("Trigger target failure by shutting down client lag and verify all SLAs goes down")
    ##########################################
    port_api.shutdown(data.dut7,[client_lag])
    result = verify_ipsla(exp_state='Down',type='all', same_sla_id=True)
    if not result:
        err = 'After target failure, not all SLAs went down'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt025')
        tech_support = False; tc_flag['FtOpSoRoIpSlaFt025'] = False

    ##########################################
    st.banner("Bring up client lag and verify all SLAs comes up")
    ##########################################
    port_api.noshutdown(data.dut7, [client_lag])
    result = verify_ipsla(type='all', same_sla_id=True)
    if not result:
        err = 'one or more SLAs did not come up on MLAG peers with same ID after port flap'
        st.error(err);tc_result = False;err_list.append(err);
        if tech_support: st.generate_tech_support(dut=None, name='FtOpSoRoIpSlaFt025')
        tc_flag['FtOpSoRoIpSlaFt025'] = False

    if tc_flag['FtOpSoRoIpSlaFt025']:
        st.report_tc_pass('FtOpSoRoIpSlaFt025','tc_passed')

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')

