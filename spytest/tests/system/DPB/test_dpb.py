##############################################################################
#Script Title : Dynamic breakout test script
#Author       : Naveen Nagaraju
#Mail-id      : naveen.nagaraju@broadcom.com
###############################################################################

import pytest
from spytest import st, tgapi
from dpb_vars import data
from dpb_utils import *
import apis.system.port as port_api
import apis.system.interface as intf_api
from utilities.utils import retry_api
import apis.system.lldp as lldp_api
import apis.system.mirroring as mirror_api
import apis.switching.pvst as stp_api
import apis.routing.ospf as ospf_api
import apis.system.reboot as reboot_api
import apis.system.basic as basic_api
import apis.routing.vrrp as vrrp_api
import apis.switching.mac as mac_api
import apis.system.snmp as snmp_api
from utilities import parallel
import apis.system.sflow as sflow_api
import apis.system.logging as slog_api


def initialize_topology_vars():

    vars = st.ensure_min_topology("D1D2:5", "D1T1:2","D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    all_port_list = st.get_dut_links(data.dut_list[0])
    data.d1d2_ports=[]
    data.d2d1_ports=[]
    d1d2_n_list =[]
    d2d1_n_list= []
    port_count=0
    for index_port,port_dpb in enumerate(all_port_list):
        if port_count != 0 and len(d1d2_n_list) == 1:
            break
        elif port_dpb[0] in data.d1d2_ports:
            continue
        elif port_api.verify_dpb_status(data.dut1,interface=port_dpb[0],status='Completed') and port_count == 0:
            while port_count != 4:
                data.d1d2_ports.append(all_port_list[index_port][0])
                data.d2d1_ports.append(all_port_list[index_port][2])
                index_port += 1
                port_count += 1
        elif len(d1d2_n_list) != 1:
            d1d2_n_list.append(all_port_list[index_port][0])
            d2d1_n_list.append(all_port_list[index_port][2])

    data.d1d2_ports.append(d1d2_n_list[0])
    data.d2d1_ports.append(d2d1_n_list[0])
    if len(data.d1d2_ports) != 5:
        st.banner("########## Required number of ports are not present; Expecting: 5 ports(first 4 should be DPB compatible) but actual ports are {}, Abort the suite ##########".format(data.d1d2_ports))
        st.report_fail("base_config_verification_failed")
    else:
        st.banner('The ports which will be used for this script run from dut1 are {} and dut2 are {}'.format(data.d1d2_ports,data.d2d1_ports))


    data.d1tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.d2tg_ports = [vars.D2T1P1,vars.D2T1P2]
    data.d1ports = data.d1d2_ports + data.d1tg_ports
    data.d2ports = data.d2d1_ports + data.d2tg_ports
    handles = tgapi.get_handles(vars, [vars.T1D1P1,vars.T1D1P2, vars.T1D2P1, vars.T1D2P2])

    data.tg1 = handles["tg1"]
    data.tg2 = handles["tg2"]
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
    data.dst_mac_l1 = '00:00:00:11:11:33'
    data.dst_mac_l2 = '00:00:00:22:11:33'
    data.lldp_timer = {'txinterval':5}
    data.dpb_mirror = 'dpb_mirror'
    data.direction_list = "both"
    data.mirror_type = "span"
    interface = data.d1d2_ports[2]

    st.log('Getting the actual speed of the interface to revert it back')

    if '/' in data.d1d2_ports[0]:
        pb_alias_port = st.get_other_names(data.dut1,[data.d1d2_ports[2]])
        index = int(pb_alias_port[0].replace("Ethernet", "")) + 1
        data.ifAdminStatus_oid = "1.3.6.1.2.1.2.2.1.7."+str(index)
        st.log('Getting both the standard {} and native interface {} name'.format(pb_alias_port[0],data.d1d2_ports[0]))
        data.base_speed = port_api.get_interface_breakout_param(data.dut1,interface=data.d1d2_ports[0])[0]
    else:
        index = int(interface.replace("Ethernet", "")) + 1
        data.ifAdminStatus_oid = "1.3.6.1.2.1.2.2.1.7."+str(index)
        data.base_speed = port_api.get_interface_breakout_param(data.dut1,interface=data.d1d2_ports[0])[0]

    if data.base_speed:
        st.banner('The breakout mode of the interface before the script run is:  {}'.format(data.base_speed))
    else:
        st.error("Interface between the nodes are not breakout compatible, suits cannot be run on this test bed")
        st.report_fail("Breakout check failed for the node")


    st.log('Getting the default speed to revert it back in the test scripts')
    default_speed = port_api.get_interface_breakout_mode(data.dut1,interface=data.d1d2_ports[0])
    data.def_speed = str(default_speed[0]['default_mode'][:5])
    data.def_speed_G = str(default_speed[0]['default_mode'][:6])
    st.banner('Default speed of the interface {} is {}'.format(data.d1d2_ports[0],data.def_speed))

    data.speed = []
    data.speed.append(data.def_speed)
    data.speed.append(data.base_speed)

    st.log('Supported speed for breakout is {}'.format(data.speed))


    data.v1_community = 'Sonic'
    data.cli_type = 'klish'

    data.snmp_ipaddr = st.get_mgmt_ip(data.dut1)

    platform = basic_api.get_hwsku(data.dut1).lower()
    st.get_datastore(data.dut1 , "constants", platform)
    hw_constants  = st.get_datastore(data.dut1 , "constants", platform)
    data.copp_cir_arp = hw_constants['COPP_CIR_ARP']
    data.sent_rate_pps = data.copp_cir_arp * 2
    data.collector_name_1 = "collector_1"

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
        st.report_unsupported("test_execution_skipped", "DPB not supported for ui_type - click")
    config_stream()

    yield
    dpb_base_deconfig()



def test_dpb_001(dpb_001_fixture):


    #################################################
    st.banner("FtOpSoRoDpb311: Verify the invalid interface name and speeds are rejected")
    #################################################
    tc_list = 'FtOpSoRoDpb311'
    success = True

    st.log("### Step 1: Verify breaking out invalid port should throw an error ###")

    if not port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[1],speed="4x10",skip_error=True):
        st.log(" Test Case Step 1 PASSED - As expected not able to break the invalid port ")
    else:
        success = False
        st.error("{}: failed, user is able to break an invalid port".format(tc_list))


    st.log("### Step 2: Verify breaking out with a invalid speed should throw an error ###")

    if not port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed="5x100",skip_error=True):
        st.log(" Test Case Step 2 PASSED - As expected not able to break with invalid speed ")
    else:
        success = False
        st.error("{}: failed, user is able to break with invalid speed".format(tc_list))

    st.log("### Step 3: Verify breaking out is successful with different valid speed options ###")
    for dpb_speed in data.speed:
        port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed=dpb_speed)
        if not retry_api(port_api.verify_dpb_status,data.dut1,interface=data.d1d2_ports[0],status='Completed',retry_count=12, delay=5):
            success = False
            st.error("{}: failed, user is not able to break with valid speed {}".format(tc_list,dpb_speed))
        else:
            st.log("Test Case Step 3 PASSED - As expected user is able to break with all the valid speed options")

    if success:
        st.report_pass("test_case_id_passed", "FtOpSoRoDpb311")
    else:
        st.report_fail("test_case_id_failed", "FtOpSoRoDpb311")


@pytest.fixture(scope="function")
def dpb_001_fixture():
    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations')
    st.log("Reverting the speed back to the original speed value")
    port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed=data.base_speed,skip_error="yes")
    if not retry_api(port_api.verify_dpb_status,data.dut1,interface=data.d1d2_ports[0],status='Completed',retry_count=12, delay=5):
        st.log("No change in port breakout mode since the speed is {}".format(data.base_speed))

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')


def test_dpb_003():
    #################################################
    st.banner("FtOpSoRoDpb3212: To verify the Vlan switching before and after the breakout")
    #################################################
    success = True
    tc_list = 'FtOpSoRoDpb3212'

    st.log("### Step 1: Verify the ports are part of the vlan {} before sending the traffic".format(data.d1tg_vlan_id))
    config_vlan()
    if not verify_vlan():
        success = False
        st.error("Failed: Ports are not part of the vlan at the beginning of {} test case".format(tc_list))

    st.log("### Step 2: Start the traffic on the edge ports from both the nodes")
    port_api.set_status(data.dut1,data.d1d2_ports[1:],status='shutdown')

    run_traffic(stream_handle=data.l2_streams)
    st.wait(3)

    port_api.set_status(data.dut1,data.d1d2_ports[1:],status='startup')
    st.log("### Step 3: Verify the traffic is getting switched on only one interface")
    if get_intf_count() != 1:
        success = False
        st.error("Failed: Either traffic is getting flooded or not switching aross the ports part of the vlan {}".format(data.d1tg_vlan_id))

    st.log("### Step 4: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G ],brk_verify=True):
        success = False
        st.error("Failed: user is not able to break with valid speed {}".format(data.def_speed_G))

    st.log("### Step 5: Verify the interface {} is no longer part of vlan {} after unbreaking the port".format(data.d1d2_ports[0],data.d1tg_vlan_id))
    st.wait(3)
    if vlan_api.verify_vlan_config(data.dut1,vlan_list=data.d1tg_vlan_id, tagged=data.d1d2_ports[0]):
        success = False
        st.error("Failed: Port {} is still part of the vlan even after unbreaking it".format(data.d1d2_ports[0]))

    st.log("### Step 6: Verify the traffic is getting switched on a interface {}".format(data.d1d2_ports[-1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[-1]]):
        success = False
        st.error("Failed: traffic is not getting switching on the ports {} part of the vlan {}".format(data.d1d2_ports[-1],data.d1tg_vlan_id))

    st.log("### Step 7: Break the port back and verify the port speed is set to {}".format(data.base_speed))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        st.error("Failed: user is not able to break with valid speed {}".format(data.base_speed))

    vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, data.d1d2_ports[:-1],True)
    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    st.log("### Step 8: Verify the interface {} is part of vlan {} ".format(data.d1d2_ports[0],data.d1tg_vlan_id))
    if not verify_vlan():
        success = False
        st.error("Failed: Ports are not part of the vlan")

    st.log("### Step 9: Verify the traffic is getting switched on a interface {} even after adding breakout ports as part of vlan ".format(data.d1d2_ports[-1]))
    if get_intf_count() != 1:
        success = False
        st.error("Failed: traffic is not getting switching on the ports {} part of the vlan {}".format(data.d1d2_ports[-1],data.d1tg_vlan_id))

    run_traffic(action='stop',stream_handle=data.l2_streams)
    config_vlan(config='no')


    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')



def test_dpb_002(dpb_002_fixture):

    #################################################
    st.banner("FtOpSoRoDpb3211: To verify the Vlan flooding before and after the breakout")
    st.banner("FtOpSoRoDpb32113: To verify the RPVST is working before and after the breakout")
    st.banner("FtOpSoRoDpb333: To verify the DPB functionality with fast boot")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3211','FtOpSoRoDpb32113','FtOpSoRoDpb333']
    err_list = []

    st.log("#############################################################")
    st.log("### Step 1: Configure {} on both the nodes and assign the ports part of the vlan".format(data.d1tg_vlan_id))
    config_vlan()
    if not verify_vlan():
        success = False
        err = "Step 1: Ports are not part of the vlan"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 2: Configure unknown unicast stream and send the traffic")

    run_traffic(stream_handle=data.l2_streams[0])

    st.log("#############################################################")
    st.log("### Step 3: Verify the traffic is getting flooded on all the breakout port and received on the another end")
    if not verify_flood_counters():
        success = False
        err = " Step 3: Traffic is not getting flooded on all the breakout port"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 4: Enable RPVST and verify there is one port in forwarding and rest are in discarding")

    stp_api.config_spanning_tree(data.dut1,feature='rpvst',mode="enable")
    stp_api.config_port_type(data.dut1, interface=data.d1tg_ports[0],stp_type="rpvst")
    stp_api.config_spanning_tree(data.dut2,feature='rpvst',mode="enable")
    stp_api.config_stp_parameters(data.dut1,priority='40960')

    st.log('Waiting for Rpvst to converge')
    st.wait(45)
    if not verify_stp():
        success = False
        err = "Step 4 : Spanning tree states are not as expected"
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("#############################################################")
    st.log("### Step 5: Verify the traffic is not getting flooded since the port are in discarding state")

    if not verify_forwd_counters():
        success = False
        err = "Step 5 : Traffic is getting flooded on all the breakout port"
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("#############################################################")
    st.log("### Step 6: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G ))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G ],brk_verify=True):
        success = False
        err = "Step 6  : user is not able to break with a valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 7: Verify the interface {} is no longer part of vlan {} after unbreaking the port".format(data.d1d2_ports[0],data.d1tg_vlan_id))
    if vlan_api.verify_vlan_config(data.dut1,vlan_list=data.d1tg_vlan_id, tagged=data.d1d2_ports[0]):
        success = False
        err = "Step 7 : Port is still part of the vlan even after unbreaking it"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 8: verify the traffic is now being sent and receive on the interface {} which is part of the vlan".format(data.d1d2_ports[-1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[-1]],debug='no'):
        success = False
        err = "Step 8 : Traffic is still getting flooded on the port "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 9: verify the interface state has been changed to Forwarding from discarding on the fifth port {} ".format(data.d1d2_ports[-1]))
    st.wait(20)
    if stp_api.show_stp_vlan_iface(data.dut1,vlan=data.d1tg_vlan_id, iface=data.d1d2_ports[-1])[0]['port_state'] != 'FORWARDING':
        success = False
        err = "Step 9 : STP state not as expected (FORWARDING)"
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("#############################################################")
    st.log("### Step 10: Break the port back and verify the port speed is set to {}".format(data.base_speed))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 10 : user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, data.d1d2_ports[:-1],True)
    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')

    st.log("#############################################################")
    st.log("### Step 11: Verify the interface {} is part of vlan {} ".format(data.d1d2_ports[0],data.d1tg_vlan_id))
    if not verify_vlan():
        success = False
        err = "Step 11 : Ports are not part of the vlan"
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.wait(20)

    st.log("#############################################################")
    st.log("### Step 12: Verify the STP state after unbreaking & breaking the port")
    if not verify_stp():
        success = False
        err = "Step 12 : Spanning tree states are not as expected after unbreaking & breaking the port"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("## Step 13 - Trigger fast reboot on the dut {} and verify the DPB configs are saved, traffic is being sent/received as expected. ##".format(data.dut1))
    reboot_api.config_save(data.dut1,shell='vtysh')
    st.reboot(data.dut1, "fast")

    st.log("#############################################################")
    st.log("### Step 14: Verify the STP state after unbreaking & breaking the port")
    if not verify_stp():
        success = False
        err = "Step 14 : Spanning tree states are not as expected after unbreaking & breaking the port"
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")


    st.log("#############################################################")
    st.log("### Step 15: Verify the traffic is not getting flooded since spanning tree is enabled after fast boot")

    if not verify_forwd_counters():
        success = False
        err = "Step 15 : Traffic is getting flooded on all the breakout port"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("#############################################################")
    st.log("### Step 16: Disable the spanning tree ")
    stp_api.config_spanning_tree(data.dut1,feature='rpvst',mode="disable")

    st.log("#############################################################")
    st.log("### Step 17: Verify the traffic is getting flooded on all the breakout port after disabling the spanning tree ")
    st.wait(5)
    if not verify_flood_counters():
        success = False
        err = "Step 17 : Traffic is not getting flooded on all the breakout port"
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])


@pytest.fixture(scope="function")
def dpb_002_fixture():
    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations')
    stp_api.config_spanning_tree(data.dut2,feature='rpvst',mode="disable")
    run_traffic(action='stop',stream_handle=data.l2_streams[0])
    config_vlan(config='no')



@pytest.fixture(scope="function")
def dpb_004_fixture():
    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations')
    run_traffic(action='stop',stream_handle=data.l2_streams[0])
    lldp_api.lldp_config(data.dut1,status="rx-and-tx")
    lldp_api.lldp_config(data.dut1,txinterval='',txhold='',config='no')
    lldp_api.lldp_config(data.dut2,txinterval='',txhold='',config='no')
    mirror_api.delete_session(data.dut1,  mirror_session=data.dpb_mirror)
    vlan_api.delete_vlan_member(data.dut1, data.d1tg_vlan_id, port_list = [data.d1tg_ports[0]],tagging_mode = 'True',skip_error_check='True')
    vlan_api.delete_vlan(data.dut1, data.d1tg_vlan_id)




def test_dpb_006(dpb_006_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3219: To verify the BGP before and after the breakout")
    st.banner("FtOpSoRoDpb331: To verify the DPB functionality with config reload")
    st.banner("FtOpSoRoDpb361: To verify the alias name is getting reflected in the syslog")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3219','FtOpSoRoDpb331','FtOpSoRoDpb36']
    err_list = []

    #import pdb; pdb.set_trace()

    st.log("##################################################")
    st.log("### Step 1: Configure vlan and assign the ports part of the vlan interface, assign IP address")
    router_config()

    st.log("##################################################")
    st.log("### Step 2: flap the port and verify the syslog has the interface naming standard/native as configured")
    port_api.set_status(data.dut1,data.d1d2_ports[3],status='shutdown')

    port_count = slog_api.get_logging_count(data.dut1, severity="NOTICE",filter_list=["doPortTask: Set port {} admin status to down".format(data.d1d2_ports[3])])
    if port_count == 0:
        err = 'syslog for the port down event with the expected interface alias is not reflected in the syslog'
        st.error('Step 2 DPB_FAIL: '+err);err_list.append(err)
        success = False

    port_api.set_status(data.dut1,data.d1d2_ports[3],status='startup')

    port_count = slog_api.get_logging_count(data.dut1, severity="NOTICE",filter_list=["doPortTask: Set port {} admin status to up".format(data.d1d2_ports[3])])
    if port_count == 0:
        err = 'syslog for the port up event with the expected interface alias is not reflected in the syslog'
        st.error('Step 2 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 3: Configure an Ip address on the second interface to establish BGP session")
    config_bgp()

    st.log("##################################################")
    st.log("### Step 4: Verify BGP session is up on both the interface")
    if not verify_bgp():
        err = 'BGP session didnt come up'
        st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 5: Verify the host route on dut2 is learnt on dut1 through OSPF ")

    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 6: Start the traffic and verify the packets are getting routed as expected")
    run_traffic(stream_handle=data.l3_streams)

    st.log("##################################################")
    st.log("### Step 7: Verify the traffic is being sent and received on both the nodes before DPB")
    if not verify_traffic():
        err = 'Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 7 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 8A: Verify the syslog is reflecting the right interface aliasing after the breakout")
    port_count = slog_api.get_logging_count(data.dut1, severity="NOTICE",filter_list=["doPortTask: Set port {} admin status to up".format(data.d1d2_ports[3])])
    if port_count == 0:
        err = 'syslog for the port up event with the expected interface alias is not reflected in the syslog'
        st.error('Step 8A DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 9: Verify BGP session comes up on another interface after DPB ")
    if not verify_bgp(dut1_bgp_neigh=[data.d4tg_ip_list[-1]]):
        err = 'BGP session didnt come up'
        st.error('Step 9 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 10: Verify the host routes are learnt on second interface between the nodes after DPB")

    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = ip_api.verify_ip_route(data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B')
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 10 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 11: Verify the traffic after breaking to native mode")
    if not verify_traffic():
        err = 'Traffic is getting dropped after breaking to native mode'
        st.error('Step 11 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 12: Break the port back to {} and assign the interface back to vlan interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 12 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                          [vlan_api.add_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

    port_count = slog_api.get_logging_count(data.dut1, severity="NOTICE",filter_list=["doVlanMemberTask: Add Vlan Member key: {}|{}".format(data.access_vlan_intf,data.d1d2_ports[0])])
    if port_count == 0:
        err = 'syslog for the vlan member port assignment after DPB with the expected interface alias is not reflected in the syslog'
        st.error('Step 12A DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 13: Verify BGP session comes up")
    if not verify_bgp():
        err = 'bgp session didnt come up after break and unbreak'
        st.error('Step 13 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 14: Verify the host routes are learnt on the first interface after enabling BGP")
    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 14 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 15: Verify the traffic is being sent and received after DPB and enabling BGP on the first interface")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 15 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("## Step 16 - Perform config reload on the dut {} and verify the DPB configs are saved, traffic is being sent/received as expected. ##".format(data.dut1))
    reboot_api.config_save(data.dut1,shell='vtysh')
    reboot_api.config_reload(data.dut1)


    st.log("##################################################")
    st.log("## Step 17 - Verify the BGP neighborship is Up after config reload")
    if not verify_bgp():
        err = 'BGP session didnt come up after config reload'
        st.error('Step 17 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 18: Verify the traffic is being sent and received after reboot")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 18 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")


    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])



@pytest.fixture(scope="function")
def dpb_006_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_006')

    run_traffic(action='stop',stream_handle=data.l3_streams[0])
    config_bgp(config='no')
    router_config(config='no')

def test_dpb_007(dpb_007_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3215: To verify the IPv4 routing through Static route and ping is working before and after the breakout")
    st.banner("FtOpSoRoDpb3216: To verify the IPV6 routing through Static route and ping is working before and after the breakout")
    st.banner("FtOpSoRoDpb334: To verify the DPB functionality with config reload")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3215','FtOpSoRoDpb3216','FtOpSoRoDpb334']
    err_list = []

    st.log("##################################################")
    st.log("### Step 1: Configure vlan and assign the ports part of the vlan interface, assign IP address")
    router_config(addr='V6')

    st.log("##################################################")
    st.log("### Step 2: Configure an Ip address on the second interface to add a Ipv4 & Ipv6 static route")
    st.log("### Step 3: Enable static on both the nodes")
    config_static()

    st.log("##################################################")
    st.log("### Step 4: Verify the host route on dut2 is learnt on dut1 through OSPF ")

    for ip_bgp,intf_bgp in zip(data.v4_static_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='S',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
            success = False

    for ip_bgp,intf_bgp in zip(data.v6_static_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv6',type='S',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 5: Start the traffic and verify the packets are getting routed as expected")
    run_traffic(stream_handle=data.l3_streams)
    run_traffic(stream_handle=data.l3_Ipv6_streams)

    st.log("##################################################")
    st.log("### Step 6: Verify both Ipv4 & Ipv6 traffic is being sent and received on both the nodes before DPB")
    if not verify_traffic():
        err = 'Ipv4/V6 Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 6 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 7: Verify ping is working fine for both Ipv4 & Ipv6")
    if not verify_ping():
        err = 'Ipv4/Ipv6 Ping is failing even though Static route is present'
        st.error('Step 7 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 9: Verify the host routes are learnt on second interface between the nodes after DPB")

    for ip_bgp,intf_bgp in zip(data.v4_static_routes,[data.d1d2_ports[-1]]*2):
        result = ip_api.verify_ip_route(data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='S')
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 9 DPB_FAIL: '+err);err_list.append(err)
            success = False

    for ip_bgp,intf_bgp in zip(data.v6_static_routes,[data.d1d2_ports[-1]]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv6',type='S',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 10: Verify ping is working fine for both Ipv4 & Ipv6 after DPB")
    if not verify_ping():
        err = 'Ipv4/Ipv6 Ping is failing after DPB'
        st.error('Step 10 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 11: Verify the traffic after breaking to native mode")
    if not verify_traffic():
        err = 'Traffic is getting dropped after breaking to native mode'
        st.error('Step 11 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 12: Break the port back to {} and assign the interface back to vlan interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 12 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                          [vlan_api.add_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

    st.log("##################################################")
    st.log("### Step 13: Verify ping is working fine for both Ipv4 & Ipv6 after bring back to {} speed".format(data.base_speed))
    if not verify_ping():
        err = 'Ipv4/Ipv6 Ping is failing after breakout with the speed'
        st.error('Step 13 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 14: Verify the host routes are learnt on the first interface after enabling BGP")
    for ip_bgp,intf_bgp in zip(data.v4_static_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='S',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
            success = False

    for ip_bgp,intf_bgp in zip(data.v6_static_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv6',type='S',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 15: Verify the traffic is being sent and received after DPB and enabling BGP on the first interface")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 15 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("## Step 16 - Perform pmon docker restart on the dut {} and verify the DPB configs are saved, traffic is being sent/received as expected. ##".format(data.dut1))
    reboot_api.config_save(data.dut1,shell='vtysh')

    st.log("PMON docker restart")
    basic_api.service_operations_by_systemctl(data.dut1, "pmon", "restart")

    st.log("Wait for PMON docker to restart")
    if not basic_api.poll_for_system_status(data.dut1, "pmon", 120, 3):
        err = 'PMON docker not running after 120 seconds'
        st.error('Step 16 DPB_FAIL: '+err);err_list.append(err)
        success = False

    if not st.poll_wait(basic_api.verify_service_status,60,data.dut1, "pmon"):
        err = 'PMON docker restart failed'
        st.error('Step 16 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 17: Verify ping is working fine for both Ipv4 & Ipv6 after docker restart")
    if not verify_ping():
        err = 'Ipv4/Ipv6 Ping is failing after docker restart'
        st.error('Step 17 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")


    st.log("##################################################")
    st.log("### Step 18: Verify the traffic is being sent and received after reboot")
    st.wait(5)
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 18 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")


    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])



@pytest.fixture(scope="function")
def dpb_007_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_007')
    run_traffic(action='stop',stream_handle=data.l3_streams+data.l3_Ipv6_streams)
    config_static(config='no')
    router_config(config='no')


def test_dpb_004(dpb_004_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3213: To verify LLDP before and after the breakout")
    st.banner("FtOpSoRoDpb32110: To verify port mirroring before and after the breakout")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3213','FtOpSoRoDpb32110']
    err_list = []

    st.log("##################################################")
    st.log("### Step 1: Set LLDP TTL value to 10 ")
    lldp_api.lldp_config(data.dut1,status="rx-and-tx")
    lldp_api.lldp_config(data.dut1,txinterval= 5,txhold=2)
    lldp_api.lldp_config(data.dut2,txinterval= 5,txhold=2)
    st.wait(10)

    st.log("##################################################")
    st.log("### Step 2: Verify the lldp is enabled and the lldp neighbors are learnt over the breakout port")

    if not lldp_api.get_lldp_table(data.dut1,interface=None):
        success = False
        err = "Step 2 Fail: Lldp table doesn't have any entires before breaking the port"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    if not verify_lldp():
        success = False
        err = "Step 2A Fail: Lldp neighbors entries are not as expected before breaking the port"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 3: Verify the lldp TTL is set to 10 on all the breakout port")

    lldp_info = lldp_api.get_lldp_neighbors(data.dut2,interface=data.d1d2_ports[0])
    if lldp_info[0]['chassis_ttl'] != '10':
        err = "Step 3 Fail: TTL value not set to desired value: 10 "
        st.error('DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('TTL set to 10 as expected')

    st.log("##################################################")
    st.log("### Step 4: Create a mirror session with source port as the breakout port and verify the same")

    mirror_api.create_session(data.dut1, session_name=data.dpb_mirror,
                              destination_ifname=data.d1d2_ports[1], mirror_type=data.mirror_type,
                              source_ifname=data.d1d2_ports[0], rx_tx=data.direction_list)

    if not mirror_api.verify_session(data.dut1, mirror_type=data.mirror_type, session_name=data.dpb_mirror,
                                     span_status="active"):
        err = "Step 4 Fail: mirror_session_verification_failed "
        st.error('DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 5: Create a vlan, assign the breakout part of the vlan")

    vlan_api.create_vlan(data.dut1, data.d1tg_vlan_id)
    vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, port_list = [data.d1tg_ports[0],data.d1d2_ports[0]],tagging_mode = 'True')
    vlan_api.verify_vlan_config(data.dut1,vlan_list=data.d1tg_vlan_id, tagged=[data.d1tg_ports[0],data.d1d2_ports[0]])

    st.log("##################################################")
    st.log("### Step 6: Create a stream and start the traffic such that it floods on the breakout port")

    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)
    run_traffic(stream_handle=data.l2_streams[0])

    st.log("##################################################")
    st.log("### Step 7: Verify the traffic is getting mirrored port on the {} port".format(data.d1d2_ports[1]))

    if int(intf_api.show_interfaces_counters(data.dut1, interface=data.d1d2_ports[1])[0]['tx_ok']) < 1000:
        success = False
        err = "Step 7 Fail: Packets are not getting mirrored "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 9: Verify the lldp table is updated and interfaces are no longer part of it")
    st.wait(10)
    if verify_lldp():
        success = False
        err = "Step 9 Fail: Lldp neighbors entries are present even after unbreaking the port "
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 9 Passed : As expected LLDP entries are not present after unbreaking the interface to native mode')

    st.log("##################################################")
    st.log("### Step 10: Verify the source port is deleted from the mirror session since it doesn't exist")
    if mirror_api.verify_session(data.dut1, mirror_type=data.mirror_type, session_name=data.dpb_mirror,
                                 span_status="active"):
        err = "Step 10 Fail: mirror_session is still active even though source port has been deleted  "
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 10 Passed : As expected Mirror session is inactive after breaking the port')

    st.log("##################################################")
    st.log("### Step 11: break the port back and verify the port speed is set to {}".format(data.base_speed))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 11 Fail: Unable break the port back to valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 12: Bring the ports up and verify lldp entries are present")
    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    vlan_api.add_vlan_member(data.dut1, data.d1tg_vlan_id, port_list = [data.d1d2_ports[0]],tagging_mode = 'True')
    vlan_api.verify_vlan_config(data.dut1,vlan_list=data.d1tg_vlan_id, tagged=[data.d1tg_ports[0],data.d1d2_ports[0]])

    st.log("##################################################")
    st.log("### Step 13: Configure the same mirror session again and verify the traffic is getting mirrored")

    mirror_api.create_session(data.dut1, session_name=data.dpb_mirror,
                              destination_ifname=data.d1d2_ports[1], mirror_type=data.mirror_type,
                              source_ifname=data.d1d2_ports[0], rx_tx=data.direction_list)

    if not mirror_api.verify_session(data.dut1, mirror_type=data.mirror_type, session_name=data.dpb_mirror,
                                     span_status="active"):
        success = False
        err = "Step 13 Fail: mirror_session_verification_failed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    intf_api.clear_interface_counters(data.dut1,Interface_Type=all)

    st.wait(8)
    if not verify_lldp():
        success = False
        err = "Step 13 Fail: Lldp neighbors entries are not as expected after unbreaking/breaking the port "
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 13 Passed : As expected LLDP entries are present after breaking the interface')


    st.log("##################################################")
    st.log("### Step 14: Verify the traffic is getting mirrored port after unbreak/break on the {} port".format(data.d1d2_ports[1]))

    if int(intf_api.show_interfaces_counters(data.dut1, interface=data.d1d2_ports[1])[0]['tx_ok']) < 1000:
        success = False
        err = "Step 14 Fail: Packets are not getting mirrored after unbreak/break followed by configuring the same mirror session  "
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 15: Disable the lldp session and verify after breakout the lldp session is down")
    lldp_api.lldp_config(data.dut1,status='disabled')

    for dpb_speed in data.speed:
        if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],dpb_speed],brk_verify=True):
            success = False
            err = "Step 15 Fail: user is not able to break with valid speed"
            st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')

    st.wait(10)
    if verify_lldp():
        success = False
        err = "Step 15 Fail: Lldp neighbors entries are present after breaking the port with lldp globally disabled "
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])



def test_dpb_008(dpb_008_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3220: To verify the VRRP  before and after the breakout")
    st.banner("FtOpSoRoDpb32114: To verify the UDLD is working before and after the breakout")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3220','FtOpSoRoDpb32114']
    err_list = []

    st.log("##################################################")
    st.log("### Step 1: Configure port channel and assign the member ports to it")
    config_lag()
    if not verify_lag():
        success = False
        err = ("Step 1: Portchannel is not up at the beginning of {} test case".format(tc_list[0]))
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 2: Assign the portchannel as part of the vlan and verify it is part of the vlan interface")
    config_po_vlan()

    if not verify_vlan(port_list=2*[data.lag_intf]):
        success = False
        err = ("Step 2: Interface {} is not part of the vlan {} interface".format(data.lag_intf,data.d1tg_vlan_id))
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 3: Configure VRRP on the vlan interface on both the nodes and verify the Master/backup is established ")
    config_vrrp()
    st.wait(5)

    st.log("##################################################")
    st.log("### Step 4: Verify dut1 is master and dut2 is backup ")
    if not verify_master_backup():
        success = False
        err = ("Step 4: Master/backup is not established as expected")
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 5: Verify the breakout port assigned as track interface is present")
    if not verify_vrrp_track():
        success = False
        err = ("Step 5: Track interface is not being tracked as expected")
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 6: Enable UDLD globally and enable on the interface between the nodes")
    udld_enable()

    st.log("##################################################")
    st.log("### Step 7: Verify the Udld is enabled on the interface and neighbor entries are present")
    if not verify_udld():
        success = False
        err = ("Step 7: Udld is not established on the interface {} ".format(data.d1d2_ports[3]))
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 9: Verify after breaking the port, dut2 is master and dut1 is backup ")
    if not verify_master_backup(master_dut=data.dut2,backup_dut=data.dut1):
        success = False
        err = ("Step 9 Fail: Master/backup is not as expected after the breakout")
        st.error('DPB_FAIL: '+err);err_list.append(err)


    st.log("##################################################")
    st.log("### Step 10: Verify the track interface is removed from the vrrp session and priority is reduced after the breakout ")
    result = retry_api(vrrp_api.verify_vrrp,data.dut1, vrid=data.vrrp_id, interface=data.d1tg_vlan_intf,current_prio=95,track_interface_list=[],retry_count=3, delay=2)
    if result is False:
        success = False
        err = ("Step 10 Fail: Vrrp track priority or vrrp track state is not as expected after the breakout")
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 11: Verify the UDLD is removed from the interface after break out")
    if verify_udld():
        success = False
        err = ("Step 11: UDLD is still present even after breaking out the port")
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 11 Pass: As expected there are no UDLD after the breakout')


    st.log("##################################################")
    st.log("### Step 12: Break the port back to {} and assign the interface back to vlan interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 12 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 13: Assign the ports back to Lag interface and track the break out port again")
    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut1,data.lag_intf,data.d1d2_ports[:-1],'add'],
                          [pc.add_del_portchannel_member, data.dut2, data.lag_intf,data.d2d1_ports[:-1],'add']])


    dict1 = {'vrid': data.vrrp_id, 'vip': data.vrrp_vip, 'interface': data.d1tg_vlan_intf, 'priority': data.vrrp_prio,'config':'yes','enable':'', 'track_interface_list':[data.d1d2_ports[2]],'track_priority_list':[10]}
    dict2 = {'vrid': data.vrrp_id, 'vip': data.vrrp_vip, 'interface': data.d1tg_vlan_intf, 'config':'yes','enable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp_api.configure_vrrp, [dict1, dict2])

    st.log("##################################################")
    st.log("### Step 14: Verify dut1 is master and dut2 is backup after breaking the port back to expected speed")
    if not verify_master_backup():
        success = False
        err = ("Step 14: Master/backup is not established as expected after breaking the port back to expected speed")
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")


    st.log("##################################################")
    st.log("### Step 15: Verify the breakout port assigned as track interface is present after breaking the port back to expected speed")
    if not verify_vrrp_track():
        success = False
        err = ("Step 15: Track interface is not being tracked as expected breaking the port back to expected speed")
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 16: Enable UDLD on the ports after breaking the port back to expected speed")
    dict1 = {'intf': data.d1d2_ports[3],'udld_enable': 'yes', 'config': 'yes'}
    parallel.exec_parallel(True,[data.dut1],udld_api.config_intf_udld, [dict1])
    st.wait(3)

    st.log("##################################################")
    st.log("### Step 17: Verify the Udld is enabled on the interface and neighbor entries are present after breaking the port back to expected speed")
    if not verify_udld():
        success = False
        err = ("Step 17: Udld is not established on the interface {} as expected after breaking the port back to expected speed".format(data.d1d2_ports[3]))
        st.error('DPB_FAIL: '+err);err_list.append(err)
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])


@pytest.fixture(scope="function")
def dpb_008_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_008')

    udld_enable(config='no')
    config_vrrp(config='no')
    config_po_vlan(config='no')
    config_lag(config='no')


def test_dpb_009(dpb_009_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3221: To verify the BGP 5549 before and after the breakout")
    st.banner("FtOpSoRoDpb3214: To verify the Static mac functionality before and after the breakout")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3221','FtOpSoRoDpb3214']
    err_list = []
    #import pdb; pdb.set_trace()

    st.log("##################################################")
    st.log("### Step 1: Configure vlan and assign the ports part of the vlan interface, assign IP address")
    router_config_5549()

    st.log("##################################################")
    st.log("### Step 2: Configure a static mac pointing towards the DPB port abd verify it is programmed as expected.")
    for dst_mac in data.dst_mac_list:
        mac_api.config_mac(data.dut1, mac=dst_mac, vlan=data.lag_vlan_id, intf=data.d1d2_ports[2])

    if not mac_api.verify_mac_address(data.dut1,vlan = data.lag_vlan_id , mac_addr = data.dst_mac_list):
        err = 'Static mac is not programmed as expected'
        st.error('Step 2 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 3: Enable BGP 5549 on both the nodes")
    config_bgp_5549()

    st.log("##################################################")
    st.log("### Step 4: Verify BGP 5549 session is up on both the interface")
    st.wait(15)
    if not verify_bgp_5549(dut1_bgp_neigh=[data.d1d2_ports[0],data.d1d2_ports[-1]]):
        err = 'BGP 5549 session didnt come up as expected'
        st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 5: Verify the host route on dut2 is learnt on dut1 through BGP 5549 ")

    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.d1d2_ports[0]]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 6: Start the traffic and verify the packets are getting routed as expected")
    run_traffic(stream_handle=data.l3_streams)

    st.log("##################################################")
    st.log("### Step 7: Verify the traffic is being sent and received on both the nodes before DPB")
    if not verify_traffic():
        err = 'Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 7 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 9: Verify BGP 5549 session comes up on another interface after DPB ")
    if not verify_bgp_5549(dut1_bgp_neigh=[data.d1d2_ports[-1]]):
        err = 'BGP 5549 session didnt come up as expected'
        st.error('Step 9 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 10: Verify the host routes are learnt on second interface between the nodes after DPB")

    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = ip_api.verify_ip_route(data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B')
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 10 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 11: Verify the traffic after breaking to native mode")
    if not verify_traffic():
        err = 'Traffic is getting dropped after breaking to native mode'
        st.error('Step 11 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 11A: Verify the static mac is erased after breaking to native mode")
    if  mac_api.verify_mac_address(data.dut1,vlan = data.lag_vlan_id , mac_addr = data.dst_mac_list):
        err = 'Static mac is still present after breaking to native mode'
        st.error('Step 11A DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 12: Break the port back to {} and enable the Ipv6 link local on the interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 12 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')

    utils.exec_all(True, [[ip_api.config_interface_ip6_link_local, data.dut1, [data.d1d2_ports[0]]]])

    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.vlan_list_id[0], [data.d1d2_ports[2]], True]])

    config_bgp_5549()

    st.log("##################################################")
    st.log("### Step 13: Verify BGP 5549 session comes up")
    if not verify_bgp_5549(dut1_bgp_neigh=[data.d1d2_ports[0],data.d1d2_ports[-1]]):
        err = 'bgp session didnt come up as expected after break and unbreak'
        st.error('Step 13 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 14: Verify the host routes are learnt on the first interface after enabling BGP 5549")
    for ip_bgp,intf_bgp in zip(data.v4_routes,[data.d1d2_ports[0]]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_bgp,interface=intf_bgp, family='ipv4',type='B',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_bgp,intf_bgp)
            st.error('Step 14 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 15: Verify the traffic is being sent and received after DPB and enabling BGP 5549 on the first interface")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 15 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 16: Verify the static mac is programmed back after reverting  back to original speed")
    if not mac_api.verify_mac_address(data.dut1,vlan = data.lag_vlan_id , mac_addr = data.dst_mac_list):
        err = 'Static mac is not present after breaking back to original speed'
        st.error('Step 16 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])

@pytest.fixture(scope="function")
def dpb_009_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_009')

    run_traffic(action='stop',stream_handle=data.l3_streams[0])
    config_bgp_5549(config='no')
    router_config_5549(config='no')




def test_dpb_010(dpb_010_fixture):
    #################################################
    st.banner("FtOpSoRoDpb32111: To verify the PBR functionality before and after the breakout")
    st.banner("FtOpSoRoDpb32117: To verify the behavior of default interface before and after the breakout")
    st.banner("FtOpSoRoDpb3222: To verify the ACL functionality before and after the breakout")
    st.banner("FtOpSoRoDpb32115: To verify the behavior of SNMP get before and after the breakout")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb32111','FtOpSoRoDpb32117','FtOpSoRoDpb3222','FtOpSoRoDpb32115']
    err_list = []
    #import pdb; pdb.set_trace()

    st.log("##################################################")
    st.log("### Step 1: Configure vlan and assign the ports part of the vlan interface, assign IP address")
    router_config()

    st.log("##################################################")
    st.log("### Step 2: Configure an Ip address on the fifth interface to have mutilple next hop")
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[-1], data.d4tg_ip_list[0], data.mask_v4],
                      [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[-1], data.d4tg_ip_list[1], data.mask_v4]])

    st.log("##################################################")
    st.log("### Step 3: Enable OSPF on both the nodes")
    config_ospf()
    ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.access_vlan_intf,cost='800')

    st.log("##################################################")
    st.log("### Step 3A: Configure IP address and assign the port part of vlan to verify the default config feature and verify the same")
    config_default()

    if  verify_default_config():
        err = 'Either IP address is not assigned or interface is not part of vlan to test default config'
        st.error('Step 3A DPB_FAIL: '+err);err_list.append(err)
        success = False
        

    st.log("##################################################")
    st.log("### Step 4: Verify OSPF session comes up")
    if not verify_ospf():
        err = 'OSPF session didnt come up as expected'
        st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 5: Verify the host route on dut2 is learnt on dut1 through OSPF ")

    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 6: Start the traffic and verify the packets are getting routed as expected")
    run_traffic(stream_handle=data.l3_streams)

    st.log("##################################################")
    st.log("### Step 7: Verify the traffic is being sent and received on both the nodes before DPB")
    if not verify_traffic():
        err = 'Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 7 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 8: Verify the traffic is going on 5th port: {} before applying the PBR config".format(data.d1d2_ports[-1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[-1]]):
        err = 'Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 8 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 9: Enable policy map such that the traffic takes the first port")
    pbr_router_config()

    st.log("##################################################")
    st.log("### Step 10: Enable policy map such that the traffic takes the first port")
    if not verify_pbr_config():
        err = 'Policy is not applied as expected before DPB, please verify the logs'
        st.error('Step 10 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 11: Verify the desired next hop: {} is being selected".format([data.d2tg_ip_list[-1]]))
    if not verify_selected_next_hop():
        err = 'Next hop is not selected as expected'
        st.error('Step 11 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 12: Verify the traffic is going on {} port after applying the PBR config".format(data.d1d2_ports[0]))
    if not get_intf_counters(portlist=[data.d1d2_ports[0]]):
        err = 'Traffic is not getting forwarded on the interface after applying PBR config'
        st.error('Step 12 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 12A: Configure default interface and verify the config's are deleted as expected")
    for port in [data.d1d2_ports[2],data.d1d2_ports[3]]:
        if not port_api.default_interface(data.dut1,interface = port):
            err = 'Unable to configure default config'
            st.error('Step 12 A DPB_FAIL: '+err);err_list.append(err)
            success = False

    if vlan_api.verify_vlan_config(dut=data.dut1,vlan_list=data.vlan_list_id[0], tagged=data.d1d2_ports[2]):
        err = 'Either IP address is still present  or interface is still part of vlan to test default config'
        st.error('Step 12B DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('Step 12 A PASS, as expected the interface doesn\'t have any config after applying default config')

    if retry_api(ip_api.verify_ip_route, data.dut1, ip_address=data.def_route[0],interface=data.d1d2_ports[3], family='ipv4',retry_count=1,delay=1):
        err = '{} does not have the ip address {}'.format(data.d1d2_ports[3],data.phy_ip_list[0])
        st.error('Step 12B DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('Step 12 A PASS, as expected {} does have the ip address {}'.format(data.d1d2_ports[3],data.phy_ip_list[0]))

    st.log("##################################################")
    st.log("### Step 12B: Verify the SNMP get of the breakout interface admin is showing up")
    snmp_api.config(data.dut1, {"cli_type": data.cli_type, "community": {"name": data.v1_community, "no_form": False}})
    if not snmp_api.poll_for_snmp(data.dut1, 3 , 1 , ipaddress= data.snmp_ipaddr,oid=data.ifAdminStatus_oid, community_name=data.v1_community,t=5):
        err = 'Unable to get the admin status of the breakout interace '
        st.error('Step 12B DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 13: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 13 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 14: Verify OSPF session comes up on another interface after DPB ")
    if not verify_ospf(dut1_ospf_intf=[data.d1d2_ports[-1]]):
        err = 'OSPF session didnt come up as expected'
        st.error('Step 14 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 15: Verify the host routes are learnt on second interface between the nodes after DPB")

    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = ip_api.verify_ip_route(data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O')
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 15 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 16: Verify the traffic after breaking to native mode")
    if not verify_traffic():
        err = 'Traffic is getting dropped after breaking to native mode'
        st.error('Step 16 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 17: Verify the desired next hop: {} is being selected after DPB".format([data.d4tg_ip_list[-1]]))
    if not verify_selected_next_hop(nh=data.d4tg_ip_list[-1]):
        err = 'Next hop is not selected as expected'
        st.error('Step 17 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 18: Verify the traffic is going on 5th port: {} after DPB".format(data.d1d2_ports[-1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[-1]]):
        err = 'Traffic is not getting routed over the interface after the DPB'
        st.error('Step 18 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 18 A: Try applying default config on the interface which is not present, suitable error should be thrown")
    for port in [data.d1d2_ports[2],data.d1d2_ports[3]]:
        if not port_api.default_interface(data.dut1,interface = port,skip_error='True'):
            err = 'User is able to apply default config on the interface which is not present'
            st.error('Step 18A DPB_FAIL: '+err);err_list.append(err)
            success = False
        else:
            st.log('Step 18A PASS: As expected not able to apply default config on the interface: {} which is not present'.format(port))

    st.log("##################################################")
    st.log("### Step 18 B: Try SNMP get for the admin status of the interface which is not present, suitable error should be thrown")
    if  snmp_api.poll_for_snmp(data.dut1, 3 , 1 , ipaddress= data.snmp_ipaddr,oid=data.ifAdminStatus_oid, community_name=data.v1_community,t=5):
        err = 'Able to get the admin status of the breakout interace even though the interface is not present '
        st.error('Step 18B DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('Step 18B PASS: As expected SNMP get of the interface: {} which is not present is getting an error'.format(port))

    st.log("##################################################")
    st.log("### Step 19: Break the port back to {} and assign the interface back to vlan interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 19 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                          [vlan_api.add_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

    ospf_api.config_interface_ip_ospf_area(data.dut1,interfaces=data.lag_vlan_intf,ospf_area='0.0.0.0')
    ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.access_vlan_intf,cost='800')

    st.log("##################################################")
    st.log("### Step 20: Verify OSPF session comes up")
    if not verify_ospf():
        err = 'OSPF session didnt come up as expected after break and unbreak'
        st.error('Step 20 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 21: Verify the host routes are learnt on the first interface after enabling OSPF")
    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 21 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 22: Verify the traffic is being sent and received after DPB and enabling OSPF on the first interface")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 22 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 22A: Again configure IP address and assign the port part of vlan to verify the default config feature and verify the same")
    config_default()

    if  verify_default_config():
        err = 'Either IP address is not assigned or interface is not part of vlan to test default config'
        st.error('Step 22A DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 23: Enable policy map such that the traffic takes the first port")
    if not verify_pbr_config():
        err = 'Policy is not applied as expected before DPB, please verify the logs'
        st.error('Step 23 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 24: Verify the desired next hop: {} is being selected".format([data.d2tg_ip_list[-1]]))
    if not verify_selected_next_hop():
        err = 'Next hop is not selected as expected'
        st.error('Step 24 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 25: Verify the traffic is going on {} port after applying the PBR config".format(data.d1d2_ports[0]))
    if not get_intf_counters(portlist=[data.d1d2_ports[0]]):
        err = 'Traffic is not getting forwarded on the interface after applying PBR config'
        st.error('Step 25 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 25A: Again configure default interface and verify the config's are deleted as expected")
    for port in [data.d1d2_ports[2],data.d1d2_ports[3]]:
        if not port_api.default_interface(data.dut1,interface = port):
            err = 'Unable to configure default config'
            st.error('Step 25 A DPB_FAIL: '+err);err_list.append(err)
            success = False

    if vlan_api.verify_vlan_config(dut=data.dut1,vlan_list=data.vlan_list_id[0], tagged=data.d1d2_ports[2]):
        err = '{} is  still part of vlan {} after applying default config'.format(data.d1d2_ports[2],data.vlan_list_id[0])
        st.error('Step 25A DPB_FAIL: '+err);err_list.append(err)
        success = False


    if retry_api(ip_api.verify_ip_route, data.dut1, ip_address=data.def_route[0],interface=data.d1d2_ports[3], family='ipv4',retry_count=2,delay=1):
        err = '{} does have the ip address {}'.format(data.d1d2_ports[3],data.phy_ip_list[0])
        st.error('Step 25A DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('Step 25A PASS, as expected routes are not present after applying default config')
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 26B: Verify the SNMP get of the breakout interface admin is showing up after DPB")
    snmp_api.config(data.dut1, {"cli_type": data.cli_type, "community": {"name": data.v1_community, "no_form": False}})
    if not snmp_api.poll_for_snmp(data.dut1, 3 , 1 , ipaddress= data.snmp_ipaddr,oid=data.ifAdminStatus_oid, community_name=data.v1_community,t=5):
        err = 'Unable to get the admin status of the breakout interace after breakout '
        st.error('Step 26B DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.log('Step 26B PASS, as expected routes able to get the snmp get of the breakout interface after DPB')
        st.report_tc_pass("{}".format(tc_list[3]), "tc_passed")


    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])


@pytest.fixture(scope="function")
def dpb_010_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_010')

    run_traffic(action='stop',stream_handle=data.l3_streams[0])
    ospf_api.config_interface_ip_ospf_cost(data.dut1,interfaces=data.access_vlan_intf,cost='800',config='no')
    pbr_router_config(config='no')
    config_ospf(config='no')
    unnum_config(config='no')
    router_config(config='no')
    utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d2_ports[-1], data.d4tg_ip_list[0], data.mask_v4],
                          [ip_api.delete_ip_interface, data.dut2, data.d2d1_ports[-1], data.d4tg_ip_list[1], data.mask_v4]])
    port_api.set_status(data.dut1, data.d1d2_ports[:-1], status='startup')


def test_dpb_011(dpb_011_fixture):
    #################################################
    st.banner("FtOpSoRoDpb32112: To verify the COPP functionality before and after the breakout")
    st.banner("FtOpSoRoDpb317: To configure and verify DPB functionality with different speed")
    st.banner("FtOpSoRoDpb341: To verify DPB with ports being breakout and unbreakout multiple times with different speed")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb32112','FtOpSoRoDpb317','FtOpSoRoDpb341']
    err_list = []
    #import pdb; pdb.set_trace()


    st.log("##################################################")
    st.log("### Step 1: Configure IP address on the edge port")
    ip_api.config_ip_addr_interface(data.dut1,data.d1tg_ports[0], data.d1tg_ip_list[1], data.mask_v4)

    st.log("##################################################")
    st.log("### Step 2: Start sending the ARP control packet from the spirent")
    run_traffic(stream_handle=data.arp_streams[0])
    #st.wait(5)

    st.log("##################################################")
    st.log("### Step 3: Verify the arp traffic to cpu is rate limited to {} pps".format(data.copp_cir_arp))
    if  verify_counter_cpu():
        success = False
        err = 'CPU counter check for rate limiting  arp to {}pps is failed'.format(data.copp_cir_arp)
        st.error('Step 2 DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 3 PASS, as expected cpu traffic is rate limited')
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 4: Break the port into different speed multiple times and verify the DPB is successful")
    speed_iter = [10*[data.def_speed,data.base_speed]]
    flag = True
    for speed in speed_iter[0]:
        if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],speed],brk_verify=True):
            flag = False
            success = False
            err = "Step 3 Fail: user is not able to break with valid speed {}".format(speed)
            st.error('DPB_FAIL: '+err);err_list.append(err)
    port_api.set_status(data.dut1, data.d1d2_ports[:-1], status='startup')

    if not flag:
        st.log('Step 4A PASS, as expected DPB is successful after multiple times')
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 5: Verify the traffic to CPU, it should be rate limited")
    if  verify_counter_cpu():
        success = False
        err = 'CPU counter check for rate limiting  arp to {} pps is failed after DPB'.format(data.copp_cir_arp)
        st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
    else:
        st.log('Step 5 PASS, as expected cpu traffic is rate limited')
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])

@pytest.fixture(scope="function")
def dpb_011_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_011')

    run_traffic(action='stop',stream_handle=data.arp_streams[0])
    ip_api.delete_ip_interface(data.dut1,data.d1tg_ports[0], data.d1tg_ip_list[1], data.mask_v4)


def test_dpb_012():

    #################################################
    st.banner("FtOpSoRoDpb312: Verify the breakout CLIs using OCI Yang/Rest api.")
    st.banner("FtOpSoRoDpb351: To configure and verify DPB functionality while configuring using OC Yang.")
    #################################################
    tc_list = ['FtOpSoRoDpb312','FtOpSoRoDpb351']
    success = True
    err_list = []

    st.log("### Step 1: Unbreak the port using OC yang and verify if it is successful ###")

    if not port_api.dyn_port_breakout(data.dut1,portlist =data.d1d2_ports[0],cli_type ="rest-patch",config='no') :
        st.log(" Step 1 PASSED - As expected not able to break the invalid port ")
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")
    else:
        success = False
        err = 'Not able to unbreak the port {}'.format(data.d1d2_ports[0])
        st.error('Step 1 DPB_FAIL: '+err);err_list.append(err)

    st.log("### Step 2: Verify breaking out is successful with different valid speed options using OC yang###")
    for dpb_speed in data.speed:
        port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed=dpb_speed,cli_type ="rest-patch")
        if not retry_api(port_api.verify_dpb_status,data.dut1,interface=data.d1d2_ports[0],status='Completed',retry_count=12, delay=5):
            success = False
            st.error("{}: failed, user is not able to break with valid speed {}".format(tc_list,dpb_speed))
        else:
            st.log('Step 2 PASS, as expected able to break the port with valid speeds')
    port_api.set_status(data.dut1, data.d1d2_ports[:-1], status='startup')
    st.log("### Step 3: Verify breaking out with a invalid speed should throw an error ###")
    if not port_api.dyn_port_breakout(data.dut1,portlist=data.d1d2_ports[0],speed="5x100",skip_error=True,cli_type ="rest-patch"):
        st.log(" Test Case Step 2 PASSED - As expected not able to break with invalid speed ")
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")
    else:
        success = False
        err = 'User is able to break the port with invalid speed 5x100G'
        st.error('Step 2 DPB_FAIL: '+err);err_list.append(err)

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])

def test_dpb_005(dpb_005_fixture):
    #################################################
    st.banner("FtOpSoRoDpb3217: To verify the OSPF before and after the breakout")
    st.banner("FtOpSoRoDpb3218: To verify the IP Unummbered using OSPF before and after the breakout")
    st.banner("FtOpSoRoDpb332: To verify the DPB functionality with warm reboot")
    st.banner("FtOpSoRoDpb32116: To verify the SFLOW before and after the breakout")
    #################################################
    success = True
    tc_list = ['FtOpSoRoDpb3217','FtOpSoRoDpb3218','FtOpSoRoDpb332','FtOpSoRoDpb32116']
    err_list = []
    st.log("##################################################")
    st.log("### Step 1: Configure vlan and assign the ports part of the vlan interface, assign IP address")
    router_config()

    st.log("##################################################")
    st.log("### Step 2: Configure an Ip unnumbered interface")
    unnum_config()

    st.log("##################################################")
    st.log("### Step 3: Enable OSPF on both the nodes")
    config_ospf()

    st.log("##################################################")
    st.log("### Step 4: Verify OSPF session comes up")
    if not verify_ospf():
        err = 'OSPF session didnt come up as expected'
        st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 5: Verify the host route on dut2 is learnt on dut1 through OSPF ")

    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route, data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 5 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 6: Start the traffic and verify the packets are getting routed as expected")
    run_traffic(stream_handle=data.l3_streams)

    st.log("##################################################")
    st.log("### Step 7: Verify the traffic is being sent and received on both the nodes before DPB")
    if not verify_traffic():
        err = 'Traffic is getting dropped even though routes are being learnt before DPB'
        st.error('Step 7 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 7A: Configure IP address on the {} to collect the sflow samples".format(data.d1d2_ports[1]))
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[1] , data.d4tg_ip_list[0], data.mask_v4],
                          [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[1], data.d4tg_ip_list[1], data.mask_v4]])
    sflow_api.enable_disable_config(data.dut1, action="enable")
    sflow_api.add_del_collector(data.dut1, collector_name=data.collector_name_1, ip_address=data.d4tg_ip_list[1], action="add")
    sflow_api.config_attributes(data.dut1, sample_rate=256, interface_name=data.d1tg_ports[0])

    st.log("##################################################")
    st.log("### Step 7B: clear the interface counter and verify the sflow samples are sent towards the collector")
    sflow_api.show(data.dut1)
    sflow_api.hsflowd_status(data.dut1)

    st.log("##################################################")
    st.log("### Step 7C: Verify the sflow samples are sent towards the collector {}".format(data.d1d2_ports[1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[1]],tx_pkt=6,wait=20):
        err = 'Sflow is not sampling towards the collector'
        st.error('Step 7C DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 8: Un-break the port back to native speed and verify the port speed is set to {}".format(data.def_speed_G))
    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.def_speed_G],brk_verify=True):
        success = False
        err = "Step 8 Fail: Failed: user is not able to break with valid speed "
        st.error('DPB_FAIL: '+err);err_list.append(err)

    st.log("##################################################")
    st.log("### Step 9: Verify OSPF session comes up on another interface after DPB ")
    if not verify_ospf(dut1_ospf_intf=[data.d1d2_ports[-1]]):
        err = 'OSPF session didnt come up as expected'
        st.error('Step 4 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 10: Verify the host routes are learnt on second interface between the nodes after DPB")

    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.d1d2_ports[-1]]*2):
        result = ip_api.verify_ip_route(data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O')
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 10 DPB_FAIL: '+err);err_list.append(err)
            success = False

    st.log("##################################################")
    st.log("### Step 11: Verify the traffic after breaking to native mode")
    if not verify_traffic():
        err = 'Traffic is getting dropped after breaking to native mode'
        st.error('Step 11 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[1]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 12: Break the port back to {} and assign the interface back to vlan interface".format(data.base_speed))

    if not port_api.breakout(data.dut1,data=[data.d1d2_ports[0],data.base_speed],brk_verify=True):
        success = False
        err = "Step 12 Fail: user is not able to break with valid speed"
        st.error('DPB_FAIL: '+err);err_list.append(err)

    port_api.set_status(data.dut1,data.d1d2_ports[:-1],status='startup')
    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1, data.access_vlan_id, data.d1d2_ports[0], True],
                          [vlan_api.add_vlan_member, data.dut2, data.access_vlan_id, data.d2d1_ports[0], True]])

    ospf_api.config_interface_ip_ospf_area(data.dut1,interfaces=data.lag_vlan_intf,ospf_area='0.0.0.0')

    st.log("##################################################")
    st.log("### Step 13: Verify OSPF session comes up")
    if not verify_ospf():
        err = 'OSPF session didnt come up as expected after break and unbreak'
        st.error('Step 13 DPB_FAIL: '+err);err_list.append(err)
        success = False

    st.log("##################################################")
    st.log("### Step 14: Verify the host routes are learnt on the first interface after enabling OSPF")
    for ip_ospf,intf_ospf in zip(data.v4_routes,[data.access_vlan_intf]*2):
        result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address=ip_ospf,interface=intf_ospf, family='ipv4',type='O',retry_count=6,delay=10)
        if not result:
            err = 'Route {} is not learnt on the interface {}'.format(ip_ospf,intf_ospf)
            st.error('Step 14 DPB_FAIL: '+err);err_list.append(err)
            success = False


    st.log("##################################################")
    st.log("### Step 15: Verify the traffic is being sent and received after DPB and enabling OSPF on the first interface")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 15 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[0]), "tc_passed")

    st.log("##################################################")
    st.log("## Step 16 - Trigger warm reboot on the dut {} and verify the DPB configs are saved, traffic is being sent/received as expected. ##".format(data.dut1))
    reboot_api.config_save(data.dut1,shell='vtysh')
    st.reboot(data.dut1, "warm")


    st.log("##################################################")
    st.log("## Step 17 - Verify the OSPF neighborship is Up after warm reboot")
    if not verify_ospf():
        err = 'OSPF session didnt come up after warm reboot'
        st.error('Step 17 DPB_FAIL: '+err);err_list.append(err)
        success = False


    st.log("##################################################")
    st.log("### Step 18: Verify the traffic is being sent and received after reboot")
    if not verify_traffic():
        err = 'Traffic loss observed, please check the statistics'
        st.error('Step 18 DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[2]), "tc_passed")

    st.log("##################################################")
    st.log("### Step 19: Configure IP address on the {} to collect the sflow samples".format(data.d1d2_ports[1]))
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d2_ports[1] , data.d4tg_ip_list[0], data.mask_v4],
                          [ip_api.config_ip_addr_interface, data.dut2, data.d2d1_ports[1], data.d4tg_ip_list[1], data.mask_v4]])
    sflow_api.enable_disable_config(data.dut1, action="enable")
    sflow_api.add_del_collector(data.dut1, collector_name=data.collector_name_1, ip_address=data.d4tg_ip_list[1], action="add")
    sflow_api.config_attributes(data.dut1, sample_rate=256, interface_name=data.d1tg_ports[0])
    sflow_api.show(data.dut1)
    sflow_api.hsflowd_status(data.dut1)

    st.log("##################################################")
    st.log("### Step 19A: Verify the sflow samples are sent towards the collector {}".format(data.d1d2_ports[1]))
    if not get_intf_counters(portlist=[data.d1d2_ports[1]],tx_pkt=6,wait=20):
        err = 'Sflow is not sampling towards the collector'
        st.error('Step 19A DPB_FAIL: '+err);err_list.append(err)
        success = False
    else:
        st.report_tc_pass("{}".format(tc_list[3]), "tc_passed")

    if success:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message',err_list[0])


@pytest.fixture(scope="function")
def dpb_005_fixture():

    yield
    st.log("##################################################")
    st.log('Cleaning up the configurations for the test case - test_dpb_005')

    run_traffic(action='stop',stream_handle=data.l3_streams[0])
    config_ospf(config='no')
    unnum_config(config='no')
    router_config(config='no')
    utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut2, data.d2d1_ports[1], data.d4tg_ip_list[1], data.mask_v4]])
    sflow_api.add_del_collector(data.dut1, collector_name=data.collector_name_1, ip_address=data.d4tg_ip_list[1], action="del")
    sflow_api.config_attributes(data.dut1, sample_rate=256, interface_name=data.d1tg_ports[0],no_form=True)

