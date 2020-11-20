##############################################################################
#Script Title : VRRPv3
#Author       : Raghukumar Rampur
#Mail-id      : raghukumar.thimmareddy@broadcom.com
###############################################################################

import pytest
from spytest import st,utils, tgapi
from spytest.tgen.tg import tgen_obj_dict

from vrrpv3_vars import *
from vrrpv3_vars import data
from vrrpv3_utils import *
import apis.system.basic as basic_api
import apis.system.reboot as reboot_api
import apis.routing.vrf as vrf_api



def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D3:4", "D2D3:4", "D1D4:4","D2D4:4","D3T1:1","D4T1:1","D1D2:1")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    for dut in vars.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d2_ports = [vars.D1D2P1]
    data.d2d1_ports = [vars.D2D1P1]
    data.d1d3_ports = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3,vars.D1D3P4]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]
    data.d2d3_ports = [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3,vars.D2D3P4]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3, vars.D2D4P4]
    data.d3d1_ports = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3,vars.D3D1P4]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3, vars.D3D2P4]
    data.d4d1_ports = [vars.D4D1P1,vars.D4D1P2,vars.D4D1P3,vars.D4D1P4]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3, vars.D4D2P4]
    data.d4tg_ports = vars.D4T1P1
    data.d3tg_ports = vars.D3T1P1
    data.tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tgd3_ports = vars.T1D3P1
    data.tgd4_ports = vars.T1D4P1
    data.tg_dut3_p1 = data.tg1.get_port_handle(vars.T1D3P1)
    data.tg_dut4_p1 = data.tg2.get_port_handle(vars.T1D4P1)
    data.tg_handles = [data.tg_dut3_p1,data.tg_dut4_p1]
    data.D4_tg_mac = basic_api.get_ifconfig(data.dut4, data.d4tg_ports)[0]['mac']
    if 'ixia' in vars['tgen_list'][0]:
        data.delay_factor = 2
    else:
        data.delay_factor = 1


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    print_topology()
    result = vrrpv3_base_config()
    if result is False:
        st.error("Either Port-channel/BGP sessions did not come up in module config")
        pytest.skip()
    yield
    vrrpv3_base_deconfig()

def test_vrrpv3_func_001(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpv3Cli001","FtOpSoRoVrrpv3Cli002","FtOpSoRoVrrpv3Fn008","FtOpSoRoVrrpv3Fn012","FtOpSoRoVrrpv3Fn013","FtOpSoRoVrrpv3Fn027","FtOpSoRoVrrpv3Fn032","FtOpSoRoVrrpv3Fn036"]
    tc_result = True ;err_list=[]
    ################################################################################################################
    hdrMsg("Step01 : Verify VRRP Master/Backup election for all VR-ID {} configured sessions".format(vrrp_sessions))
    ################################################################################################################
    result = verify_vrrp()
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv4 sessions"
        st.report_fail('test_case_failure_message', err)

    result = verify_vrrpv6()
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        st.report_fail('test_case_failure_message', err)

    ################################################################################
    hdrMsg("Step02 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP by "
           "checking vmac {} in backup mac table".format(vrid_list[0:int(vrrp_sessions/2)],data.dut1,vmac_list[0:int(vrrp_sessions/2)]))
    #################################################################################
    result,err = check_mac(data.dut2,vrrp_vlans[0:int(vrrp_sessions/2)],vmac_list[0:int(vrrp_sessions/2)],[lag_intf_list[1]]*len(vrrp_vlans[0:int(vrrp_sessions/2)]))
    if result is False:
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step03 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP by "
           "checking vmac {} in backup mac table".format(vrid_list[int(vrrp_sessions/2):],data.dut1,vmac_list[int(vrrp_sessions/2):]))
    ############################################################
    result,err = check_mac(data.dut1,vrrp_vlans[int(vrrp_sessions/2):],vmac_list[int(vrrp_sessions/2):],[lag_intf_list[0]]*len(vrrp_vlans[int(vrrp_sessions/2):]))
    if result is False:
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    ############################################################################################################
    hdrMsg("Step04 : Disable/Enable VRRP ipv4 sessions {} on dut1(Master)".format(vrid_list[0:int(vrrp_sessions/2)]))
    ############################################################################################################
    for vrid,vlan,vip,prio,vmac in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],
                                       vip_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],
                                       vmac_list_1[0:int(vrrp_sessions/2)]):
        st.log(">>>> Disable VRRP session for vr-id {} <<<<<".format(vrid))
        vrrp.configure_vrrp(data.dut1, vrid=vrid, interface=vlan, config="no",disable='')
        st.log(">>>> Again Enable VRRP session for vr-id {} <<<<<".format(vrid))
        vrrp.configure_vrrp(data.dut1, vrid=vrid, vip=vip, interface=vlan, priority=prio, config="yes",enable='')
        vrrp.configure_vrrp(data.dut1,vrid=vrid,interface=vlan,version=3)
        st.log("\nVerify dut1 again elected as VRRP Master for VRID {} \n".format(vrid))
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2)
        if result is False:
            err = "dut1 not elected as VRRP Master for VRID {}".format(vrid)
            failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step05 : Disable/Enable VRRP ipv6 sessions {} on dut1(Master)".format(vrid_ipv6_list[0:int(vrrp_sessions/2)]))
    ############################################################
    for vrid,vlan,vip,prio,vmac in zip(vrid_ipv6_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],vip_ipv6_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],vmac_ipv6_list_2[0:int(vrrp_sessions/2)]):
        st.log(">>>> Disable VRRP ipv6 session for vr-id {} <<<<<".format(vrid))
        vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid, interface=vlan, config="no",disable='')
        st.log(">>>> Again enable VRRP ipv6 session for vr-id {} <<<<<".format(vrid))
        vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid, vip=vip, interface=vlan, priority=prio, config="yes",enable='')
        st.log("\nVerify dut1 again elected as VRRP Master for VRID {} \n".format(vrid))
        result =verify_master_backup_v6(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2)
        if result is False:
            st.log('dut1 not elected as VRRP ipv6 Master for VRID {}')
            err = "dut1 not elected as VRRP Master for VRID {}".format(vrid)
            failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step06 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP after enabling vrrp by "
           "checking vmac {} in backup mac table".format(vrid_list[0:int(vrrp_sessions/2)],data.dut1,vmac_list[0:int(vrrp_sessions/2)]))
    ############################################################
    result,err = check_mac(data.dut2,vrrp_vlans[0:int(vrrp_sessions/2)],vmac_list[0:int(vrrp_sessions/2)],[lag_intf_list[1]]*len(vrrp_vlans[0:int(vrrp_sessions/2)]))
    if result is False:
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step07 : Trigger ARP request for VIP {}  and {} from TG".format(vip_list[0],vip_list[int(vrrp_sessions/2)]))
    ############################################################

    result1 = data.tg1.tg_arp_control(handle=data.host_handles['vrrp_host_{}'.format(vrid_list[0])], arp_target='all')
    result2 = data.tg1.tg_arp_control(handle=data.host_handles['vrrp_host_{}'.format(vrid_list[int(vrrp_sessions/2)])], arp_target='all')

    if result1['status'] == '0' or result2['status'] == '0':
        err = "Testcase: {} ARP resolve failed in TGEN".format(tc_list[1])
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    ##############################################################################################################
    hdrMsg("Step08 : Verify only Master replied for ARP request by checking VMAC on dut3 pointing to Master dut")
    ##############################################################################################################

    st.log("Verify Vmac {} learnt on Vlan {} pointing to Master(dut1) interface {}".format(vmac_list[0],vlan_list[0],lag_intf_list[0]))

    result = check_mac(data.dut3,vlan_list[0],vmac_list[0],lag_intf_list[0])
    if result is False:
        err = "Testcase: {} On DUT3 Vmac {} not learnt on Vlan {} Interface {}".format(tc_list[1],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    st.log("Verify Vmac {} not learnt on Vlan {} pointing to Backup(dut2) interface {}".format(vmac_list[0],vlan_list[0],lag_intf_list[1]))

    result = check_mac(data.dut3,vlan_list[0],vmac_list[0],lag_intf_list[1])
    if result is True:
        err = "Testcase: {} On DUT3 Vmac {} learnt on Vlan {} Interface {} pointing to backup".format(tc_list[3],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False

    st.log("Verify Vmac {} learnt on Vlan {} pointing to Master(dut2) interface {}".format(vmac_list[int(vrrp_sessions/2)], vlan_list[int(vrrp_sessions/2)],
                                                                                           lag_intf_list[1]))
    result = check_mac(data.dut3, vlan_list[int(vrrp_sessions/2)], vmac_list[int(vrrp_sessions/2)], lag_intf_list[1])
    if result is False:
        err = "Testcase: {} On DUT3 Vmac {} not learnt on Vlan {} Interface {} ".format(tc_list[1],vmac_list[int(vrrp_sessions/2)],vlan_list[int(vrrp_sessions/2)],lag_intf_list[1])
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False


    st.log("Verify Vmac {} not learnt on Vlan {} pointing to Backup(dut1) interface {}".format(vmac_list[int(vrrp_sessions/2)], vlan_list[int(vrrp_sessions/2)],
                                                                                           lag_intf_list[0]))
    result = check_mac(data.dut3, vlan_list[int(vrrp_sessions/2)], vmac_list[int(vrrp_sessions/2)], lag_intf_list[0])
    if result is True:
        err = "Testcase: {} On DUT3 Vmac {} learnt on Vlan {} Interface {} pointing to backup ".format(tc_list[3],vmac_list[int(vrrp_sessions/2)],vlan_list[int(vrrp_sessions/2)],lag_intf_list[1])
        failMsg(err);debug_vrrpv3(); err_list.append(err); tc_result = False


    ################################################################################################
    hdrMsg("Step09: Ping to all Virtual IPs {} from backup dut2 and verify VIP is installed in "
           "routing table with /32 subnet mask only on master".format(vip_list[0:int(vrrp_sessions/2)]))
    ################################################################################################

    for vip,vrid in zip(vip_list[0:int(vrrp_sessions/2)],vrid_list[0:int(vrrp_sessions/2)]):
        result = ip_api.verify_ip_route(data.dut1, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4')
        if result is False:
            err = "VIP {}/32 not installed in dut1(Master)routing table".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut2, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4')
        if result is True:
            err = "VIP {}/32  should not be installed in dut2(Backup)routing table".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

        result = ip_api.ping(data.dut2,vip)
        if result is False:
            err = "Ping to VIP {} failed from backup dut dut2".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

    #####################################################################################################
    hdrMsg("Step10: Ping to all Virtual IPv6s {} from backup dut2 and verify VIP is installed in "
           "routing table with /128 subnet mask only on master".format(vip_ipv6_list[0:int(vrrp_sessions/2)]))
    #####################################################################################################
    for vip,vrid in zip(vip_ipv6_list[0:int(vrrp_sessions/2)],vrid_ipv6_list[0:int(vrrp_sessions/2)]):
        result = ip_api.verify_ip_route(data.dut1, ip_address="{}/128".format(vip),interface='vrrp.{}'.format(vrid), family='ipv6')
        if result is False:
            err = "VIP {}/128 not installed in dut1(Master)routing table".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut2, ip_address="{}/128".format(vip),interface='vrrp.{}'.format(vrid), family='ipv6')
        if result is True:
            err = "VIP {}/128 should not be installed in dut2(Backup)routing table".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

        result = ip_api.ping(data.dut2,vip,family='ipv6',count=2)
        if result is False:
            err = "Ping to VIP {} failed from backup dut dut2".format(vip)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False

    ################################################################################
    hdrMsg("Step11:Verify Traffic gets forwarded for all VRRP sessions configured")
    ################################################################################
    run_traffic()
    result = verify_tg_traffic_rate()
    if result is False:
        err = "data traffic not forwarded for all VRIDs {} {}" .format(vrid_list,vrid_ipv6_list)
        failMsg(err);err_list.append(err);tc_result = False
    run_traffic(action='stop')

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrpv3_func_003(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn003","FtOpSoRoVrrpv3Fn009","FtOpSoRoVrrpv3Fn010","FtOpSoRoVrrpv3Fn015","FtOpSoRoVrrpv3Fn018","FtOpSoRoVrrpv3Fn019","FtOpSoRoVrrpv3Fn033","FtOpSoRoVrrpv3Fn034","FtOpSoRoVrrpv3Fn038","FtOpSoRoVrrpv3Fn040","FtOpSoRoVrrpv3Fn041"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step01 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        st.report_fail('test_case_failure_message', err)

    ###########################################################
    hdrMsg("Step02 : Change the advertisement interval on dut2 (Backup) - {} for VRRP session {})".format(data.dut2,vrid_list[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ######################################################################################################
    hdrMsg("Step02.1 : Change the advertisement interval on dut2 (Backup) - {} for VRRP ipv6 session {})".format(data.dut2,vrid_ipv6_list[0]))
    ######################################################################################################
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step03 : Verify the advertisement interval is set to 2 seconds on dut2 (Backup) - {} for VRRP session {})".format(data.dut2,vrid_list[0]))
    ############################################################
    vrrp.verify_vrrp(data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step03.1 : Verify the advertisement interval is set to 2 seconds on dut2 (Backup) - {} for VRRP ipv6 session {})".format(data.dut2,vrid_ipv6_list[0]))
    ############################################################
    vrrpv3.verify_vrrpv3(data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step04 : Change the advertisement interval on dut1 (Master) - {} for VRRP session {} to 2 as well)".format(data.dut1,vrid_list[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step04.1 : Change the advertisement interval on dut1 (Master) - {} for VRRP ipv6 session {} to 2 as well)".format(data.dut1,vrid_ipv6_list[0]))
    ############################################################
    vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step05 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err);err_list.append(err);  tc_result = False

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        failMsg(err);err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step06 : Revert back the advertisement interval on both the nodes to 1 seconds")
    ############################################################
    dict1 = {'vrid': vrid_list[0],  'interface': dut1_vlan_intf[0],'adv_interval':1}
    parallel.exec_parallel(True,[data.dut1,data.dut2],vrrp.configure_vrrp,[dict1,dict1])

    dict1 = {'vrid': vrid_ipv6_list[0],  'interface': dut1_vlan_intf[0],'adv_interval':1}
    parallel.exec_parallel(True,[data.dut1,data.dut2],vrrpv3.configure_vrrpv3,[dict1,dict1])

    ###########################################################
    hdrMsg("Step07 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err);err_list.append(err);tc_result = False

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        failMsg(err);err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step08 : Set the priority on the backup to higher with preemption mode set to false on vrrp vr-id {} session".format(vrid_list[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], preempt="disable",config ="no")
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], priority = 230)

    ###########################################################
    hdrMsg("Step08.1 : Set the priority on the backup to higher with preemption mode set to false on vrrp ipv6 vr-id {} session".format(vrid_ipv6_list[0]))
    ############################################################
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], preempt="disable",config ="no")
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], priority = 230)

    ###########################################################
    hdrMsg("Step9 : Verify VRRP Backup remains in backup state even though it has high priority for the vr-id {} session".format(vrid_list[0]))
    ############################################################
    result = vrrp.verify_vrrp(data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio = 230,preempt="disabled")
    if result is False:
        err = "After disabling preempt on {} the VRRP Master/Backup election is incorrect for the vrrp ipv4 session {}".format(data.dut2,vrid_list[0])
        failMsg(err);err_list.append(err);  tc_result = False

    ###########################################################
    hdrMsg("Step10 : Verify VRRP ipv6 Backup remains in backup state even though it has high priority for the vr-id {} session".format(vrid_ipv6_list[0]))
    ############################################################
    result = vrrpv3.verify_vrrpv3(data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], current_prio = 230,preempt="disabled")
    if result is False:
        err = "After disabling preempt on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format(data.dut2,vrid_ipv6_list[0])
        failMsg(err);err_list.append(err);  tc_result = False


    ###########################################################
    hdrMsg("Step11 : Enable the preempt and verify the backup takes over the master on vr-id {} session".format(vrid_list[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], preempt="enable")

    ###########################################################
    hdrMsg("Step11.1 : Enable the preempt and verify the backup takes over the master on vrrp ipv6 vr-id {} session".format(vrid_ipv6_list[0]))
    ############################################################
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], preempt="enable")
    st.wait(10)

    ###########################################################
    hdrMsg("Step12:Verify for VRRP sessions {} ,Master DUT {} forwards data traffic".format(vrid_list[int(vrrp_sessions/2):],data.dut2))
    ###########################################################
    run_traffic()
    result = verify_tg_traffic_rate(src_tg_obj=data.tg1,dest_tg_obj=data.tg2,src_port=data.tgd3_ports,dest_port=data.tgd4_ports)
    if result is False:
        err = "Master DUT {} not forwarding data traffic for VRIDs {}".format(data.dut2,vrid_list[int(vrrp_sessions/2):])
        st.generate_tech_support(dut=None,name='test_vrrpv3_func_003')
        failMsg(err);err_list.append(err); tc_result = False

    run_traffic(action='stop')
    revert_vrrp()
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

def test_vrrpv3_func_005(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn004","FtOpSoRoVrrpv3Fn024","FtOpSoRoVrrpv3Fn025","FtOpSoRoVrrpv3Fn028","FtOpSoRoVrrpv3Fn046","FtOpSoRoVrrpv3Fn047"]
    tc_result = True ;err_list=[]

    ###########################################################
    hdrMsg("Step01 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        st.report_fail('test_case_failure_message', err)


    ###########################################################
    hdrMsg("Step02 : Change the priority to 120 on {} and 100 on {} before tracking the port and verify the same".format(data.dut1,data.dut2))
    ############################################################

    dict1 = {'vrid': vrid_list[0], 'interface': dut1_vlan_intf[0], 'priority': 120}
    dict2 = {'vrid': vrid_list[0], 'interface': dut1_vlan_intf[0], 'priority': 100}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'interface': dut1_vlan_intf[0], 'priority': 120}
    dict2 = {'vrid': vrid_ipv6_list[0], 'interface': dut1_vlan_intf[0], 'priority': 100}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "VRRP Master/Backup election is incorrect for the vrrp session {}".format(vrid_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format( vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    ###########################################################
    hdrMsg("Step03 : Track 4 ports: {} with priority 10 each, verify the backup take over the Master and current priority is set to 140".format(data.d2d4_ports))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10])
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'],track_state_list =['Up','Up','Up','Up'])
    if result is False:
        err = "After tracking the ports on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format( data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'],track_state_list =['Up','Up','Up','Up'])
    if result is False:
        err = "After tracking the ports on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format( data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    run_traffic()
    st.wait(3)
    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(data.dut2,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step04 : Shutdown the 3 Track ports: {}, verify the backup take over the Master".format(data.d2d4_ports[:3]))
    ############################################################
    port_api.shutdown(data.dut2, data.d2d4_ports[:3])

    result = retry_api(vrrp.verify_vrrp,data.dut1, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "after shutting down the track the ports,  {} is not the master for the vrrp session {}".format(data.dut1, vrid_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=110,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Down','Down','Down','Up'] )
    if result is False:
        err = "after shutting down the track the ports, {} is not the VRRP Backup for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "after shutting down the track the ports,  {} is not the master for the vrrp ipv6 session {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], current_prio=110,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Down','Down','Down','Up'] )
    if result is False:
        err = "after shutting down the track the ports, {} is not the VRRP Backup for the vrrp ipv6 session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);
        tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(data.dut1,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step05 : Bring the 3 Track ports up: {}, and make sure the Master is now {}".format(data.d2d4_ports[:3],data.dut2))
    ############################################################
    port_api.noshutdown(data.dut2, data.d2d4_ports[:3])

    result = retry_api(vrrp.verify_vrrp,data.dut1, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "{} is not the backup for the vrrp session {}".format( data.dut1, vrid_list[0])
        failMsg(err); err_list.append(err);  tc_result = False

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Up','Up','Up','Up'] )
    if result is False:
        err = "after bring up the tracked ports, {} is not the VRRP Master for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);  tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut1, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "{} is not the backup for the vrrp ipv6 session {}".format( data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);  tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Up','Up','Up','Up'] )
    if result is False:
        err = "after bring up the tracked ports, {} is not the VRRP Master for the vrrp ipv6 session {}".format(data.dut2, vrid_list[0])
        failMsg(err);  err_list.append(err);  tc_result = False


    result = verify_tg_traffic_rate()
    if result is False:
        err = "After bring back the tracked port, traffic drop is seen on Master DUT {} for VRIDs {}".format(data.dut2,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step06 : Delete the tracked 4 ports: {}, verify the backup take over the Master and current priority is set to 100".format(data.d2d4_ports))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10],config = "no")
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10],config = "no")
    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "after deleting tracking ports config on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err); tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "after deleting tracking ports config on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err); tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the track port config is deleted".format(data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg( "Step07: Similarly now track a port-channel & Vlan: {} & {} with priority 50 , verify the backup take over the Master and current priority is set to 150".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[20,20])
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[20,20])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=140, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Up','Up'])
    if result is False:
        err = "After tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err); tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=140, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Up','Up'])
    if result is False:
        err = "After tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err); tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the tracking the lag interface".format(data.dut2, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg( "Step08 : Now shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################
    port_api.shutdown(data.dut2,[lag_intf_list[3]])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Down','Down'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=100, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Down','Down'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after shutting down the tracked the lag interface".format(data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step09 : Now do a no shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3], dut2_uplink_vlan_intf[0]))
    ############################################################

    port_api.noshutdown(data.dut2, [lag_intf_list[3]])
    #vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=[20, 20])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=140, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['20', '20'], track_state_list=['Up', 'Up'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err);err_list.append(err);  tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], current_prio=140, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['20', '20'], track_state_list=['Up', 'Up'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6  session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err);  tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the no shut on the tracked lag and vlan interface".format(data.dut1, vrid_list[0:int(vrrp_sessions/2)]) #,lag_intf_list[3], dut2_uplink_vlan_intf[0])
        failMsg(err);err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step10 : Delete the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=[10, 10], config="no")
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=[10, 10], config="no")

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "after deleting tracking ports confif on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err);err_list.append(err);tc_result = False

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "after deleting tracking ports confif on {} the VRRP Master/Backup election is incorrect for the vrrp ipv6 session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err);tc_result = False

    result = verify_tg_traffic_rate()
    if result is False:
        err = "Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step11 : Try adding the track priority greater than the configured priority, suitable error should be seen")
    ############################################################

    result = vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3]], track_priority_list=[200], config="yes",skip_error=True)
    expected_err = "Error"
    if expected_err not in str(result):
        err = "Track interface with configured priority exceeded 254"
        failMsg(err);err_list.append(err); tc_result = False;

    result = vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3]], track_priority_list=[200], config="yes",skip_error=True)
    expected_err = "Error"
    if expected_err not in str(result):
        err = "Track interface with configured priority exceeded 254"
        failMsg(err);err_list.append(err); tc_result = False;

    ####################################################################################
    hdrMsg("Step12 : Try adding the track interface as invalid interface, error should be seen")
    ####################################################################################
    result = vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=['Vlan4096'], track_priority_list=[50], config="yes", skip_error=True)
    expected_err = "Error"
    if expected_err not in str(result):
        err = "Invalid Track interface is accepted"
        failMsg(err);err_list.append(err);tc_result = False;

    result = vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], track_interface_list=['Vlan4096'], track_priority_list=[50], config="yes", skip_error=True)
    expected_err = "Error"
    if expected_err not in str(result):
        err = "Invalid Track interface is accepted"
        failMsg(err);err_list.append(err);tc_result = False;

    run_traffic(action='stop')
    revert_vrrp()
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list)
    else:
        st.report_pass('test_case_passed')


def test_vrrpv3_func_006(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn014","FtOpSoRoVrrpv3Fn016","FtOpSoRoVrrpv3Fn017","FtOpSoRoVrrpv3Fn037","FtOpSoRoVrrpv3Fn039"]
    tc_result = True ;err_list=[]

    ###########################################################
    hdrMsg("Step01 : Remove the VRRP sessions from the Vlan interface and configure on the physical interface on Dut1 : {} and Dut2 : {} ".format(data.d1d2_ports,data.d2d1_ports))
    ############################################################

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','disable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    dict1 = {'vrid': vrid_ipv6_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','disable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,vrrp_vlan_intf[0],dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.delete_ip_interface,data.dut2,vrrp_vlan_intf[0], dut2_1_ipv6_list[0],mask_v6,'ipv6']])

    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1d2_ports[0],vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,data.d2d1_ports[0],vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1d2_ports[0],dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.config_ip_addr_interface,data.dut2,data.d2d1_ports[0],dut2_1_ipv6_list[0],mask_v6,'ipv6']])


    utils.exec_all(True,[[port_api.noshutdown,data.dut1, data.d1d2_ports],[port_api.noshutdown,data.dut2, data.d2d1_ports]])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d1d2_ports[0],'enable':'yes','priority':'200'}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d2d1_ports[0],'enable':'yes','priority':'150'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': data.d1d2_ports[0], 'version':3}
    dict2 = {'vrid': vrid_list[0], 'interface': data.d2d1_ports[0], 'version':3}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': data.d1d2_ports[0],'enable':'yes','priority':'200'}
    dict2 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': data.d2d1_ports[0],'enable':'yes','priority':'150'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    ###########################################################
    hdrMsg("Step02 : Verify the Master/Backup is established as expected based on the priority")
    ############################################################
    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0], current_prio=150)
    if result is False:
        err = "On {}, expected Backup state for vrrp vr-id {}, the session is either Backup or down".format(data.dut2, vrid_list[0])
        failMsg(err);err_list.append(err);tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "On {}, expected Master state for vrrp vr-id {}".format(data.dut1, vrid_list[0])
        failMsg(err);err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0], current_prio=150)
    if result is False:
        err = "On {}, expected Backup state for vrrp vr-id {}, the session is either Backup or down".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err);tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "On {}, expected Master state for vrrp vr-id {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err); tc_result = False;

    ###########################################################
    hdrMsg( "Step03 : Track a port-channel & Vlan: {} & {} with priority 50 , verify the backup take over the Master and current priority is set to 250".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=data.d2d1_ports[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[50,50])
    vrrpv3.configure_vrrpv3(data.dut2, vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[50,50])

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Master', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=250, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Up','Up'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Backup', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Master', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=250, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Up','Up'])
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    ###########################################################
    hdrMsg( "Step04 : Now shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 150".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    port_api.shutdown(data.dut2,[lag_intf_list[3]])

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    ###########################################################
    hdrMsg( "Step05 : Flap the physical interface and verify the Master back up is established as expected ")
    ############################################################

    port_api.shutdown(data.dut1, data.d1d2_ports)

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Down', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['50', '50'], track_state_list=['Down', 'Down'])
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut2 )
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Down', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut1 )
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Down', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['50', '50'], track_state_list=['Down', 'Down'])
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut2 )
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Down', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut1 )
        failMsg(err); err_list.append(err); tc_result = False;


    port_api.noshutdown(data.dut1, data.d1d2_ports)

    ###########################################################
    hdrMsg( "Step06 : Verify the vrrp state after flapping the physical interface")
    ############################################################

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_list[0])
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_vrrp_state'],[st.generate_tech_support,data.dut2,'dut2_vrrp_state'],[st.generate_tech_support,data.dut3,'dut3_vrrp_state'],[st.generate_tech_support,data.dut4,'dut4_vrrp_state']])


    ###########################################################
    hdrMsg( "Step07 : Remove vrrp sessions from physical interface")
    ############################################################
    dict1 = {'vrid': vrid_list[0], 'interface': data.d1d2_ports[0],'disable':'yes','config':'no'}
    dict2 = {'vrid': vrid_list[0], 'interface': data.d2d1_ports[0],'disable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'interface': data.d1d2_ports[0],'disable':'yes','config':'no'}
    dict2 = {'vrid': vrid_ipv6_list[0], 'interface': data.d2d1_ports[0],'disable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    st.log("\n >>> Revert all phy interface to Vlan interface for VRRP <<<<\n")
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1d2_ports[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,data.d2d1_ports[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1d2_ports[0],dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.delete_ip_interface,data.dut2,data.d2d1_ports[0],dut2_1_ipv6_list[0],mask_v6,'ipv6']])


    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,vrrp_vlan_intf[0], dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.config_ip_addr_interface,data.dut2,vrrp_vlan_intf[0], dut2_1_ipv6_list[0],mask_v6,'ipv6']])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut2[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'version':3}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'version':3}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut2[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])
    
    hdrMsg( "Step08 : Bring up the tracked port-channel interface: {}".format(lag_intf_list[3]))
    port_api.noshutdown(data.dut2,[lag_intf_list[3]])
    
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrpv3_func_007(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn049","FtOpSoRoVrrpv3Fn050"]
    tc_result = True ;err_list=[]

    ###########################################################
    hdrMsg("Step01 : Remove the VRRP sessions from the Vlan interface and configure on the physical interface on Dut1 : {} and Dut2 : {} ".format(data.d1d2_ports,data.d2d1_ports))
    ############################################################

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','disable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    dict1 = {'vrid': vrid_ipv6_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','disable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,vrrp_vlan_intf[0],dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.delete_ip_interface,data.dut2,vrrp_vlan_intf[0], dut2_1_ipv6_list[0],mask_v6,'ipv6']])

    ##################################################################
    hdrMsg("Step01.1: VRF-Config- Configure VRF on dut1 and dut2 ")
    ##################################################################
    dict1 = {'vrf_name':vrrp_vrf, 'config': 'yes'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.config_vrf, [dict1, dict1,dict1])

    #################################################################
    hdrMsg("Step01.2: bind-VRF-to-interface- Interface between dut1 and dut2")
    #################################################################
    vrf_api.bind_vrf_interface(data.dut1,vrf_name =vrrp_vrf, intf_name =data.d1d2_ports[0],skip_error='True')
    vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrrp_vrf, intf_name =data.d2d1_ports[0],skip_error='True')

    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1d2_ports[0],vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,data.d2d1_ports[0],vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1d2_ports[0],ipv6_linklocal_ip_list[0],mask_v6,'ipv6'],
                         [ip_api.config_ip_addr_interface,data.dut2,data.d2d1_ports[0],ipv6_linklocal_ip_list[1],mask_v6,'ipv6']])

    utils.exec_all(True,[[port_api.noshutdown,data.dut1, data.d1d2_ports],[port_api.noshutdown,data.dut2, data.d2d1_ports]])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d1d2_ports[0],'enable':'yes','priority':'200'}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d2d1_ports[0],'enable':'yes','priority':'150'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': data.d1d2_ports[0], 'version':3}
    dict2 = {'vrid': vrid_list[0], 'interface': data.d2d1_ports[0], 'version':3}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': ipv6_linklocal_ip_list[2], 'interface': data.d1d2_ports[0],'enable':'yes','priority':'200'}
    dict2 = {'vrid': vrid_ipv6_list[0], 'vip': ipv6_linklocal_ip_list[2], 'interface': data.d2d1_ports[0],'enable':'yes','priority':'150'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    ###########################################################
    hdrMsg("Step02 : Verify the Master/Backup is established as expected based on the priority")
    ############################################################
    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0], current_prio=150)
    if result is False:
        err = "On {}, expected Backup state for vrrp vr-id {}, the session is either Backup or down".format(data.dut2, vrid_list[0])
        failMsg(err);err_list.append(err);tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "On {}, expected Master state for vrrp vr-id {}".format(data.dut1, vrid_list[0])
        failMsg(err);err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0], current_prio=150)
    if result is False:
        err = "On {}, expected Backup state for vrrp vr-id {}, the session is either Backup or down".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err);tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "On {}, expected Master state for vrrp vr-id {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err);err_list.append(err); tc_result = False;

    ###########################################################
    hdrMsg( "Step03 : Flap the physical interface and verify that vrrp ipv6 sessions are in Down state")
    ############################################################

    port_api.shutdown(data.dut1, data.d1d2_ports)

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Down', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=150)
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut2 )
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Down', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bring the VRRP interface down, the session is still not down on the dut: {}".format(data.dut1 )
        failMsg(err); err_list.append(err); tc_result = False;

    port_api.noshutdown(data.dut1, data.d1d2_ports)

    ###########################################################
    hdrMsg( "Step04 : Verify the vrrp ipv6 state after flapping the physical interface")
    ############################################################
    result = retry_api(vrrpv3.verify_vrrpv3, data.dut2, state='Backup', vrid=vrid_ipv6_list[0], interface=data.d2d1_ports[0],current_prio=150)
    if result is False:
        err = "after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut2, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err); tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3, data.dut1, state='Master', vrid=vrid_ipv6_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(data.dut1, vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);  tc_result = False;

    ###########################################################
    hdrMsg( "Step05 : Remove vrrp sessions from physical interface")
    ############################################################
    dict1 = {'vrid': vrid_list[0], 'interface': data.d1d2_ports[0],'disable':'yes','config':'no'}
    dict2 = {'vrid': vrid_list[0], 'interface': data.d2d1_ports[0],'disable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'interface': data.d1d2_ports[0],'disable':'yes','config':'no'}
    dict2 = {'vrid': vrid_ipv6_list[0], 'interface': data.d2d1_ports[0],'disable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    st.log("\n >>> Revert all phy interface to Vlan interface for VRRP <<<<\n")
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1d2_ports[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,data.d2d1_ports[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1d2_ports[0],ipv6_linklocal_ip_list[0],mask_v6,'ipv6'],
                         [ip_api.delete_ip_interface,data.dut2,data.d2d1_ports[0],ipv6_linklocal_ip_list[1],mask_v6,'ipv6']])


    ##########################################################################
    hdrMsg("unbind-VRF-to-interface:  Interface between dut1 and dut2")
    ##########################################################################
    vrf_api.bind_vrf_interface(data.dut1,vrf_name = vrrp_vrf, intf_name =data.d1d2_ports[0],config = 'no',skip_error='True')
    vrf_api.bind_vrf_interface(data.dut2,vrf_name = vrrp_vrf, intf_name =data.d2d1_ports[0],config = 'no',skip_error='True')

    ##########################################################################
    hdrMsg("Remove VRF-Config: Remove VRF config on dut1 and dut2")
    ##########################################################################
    dict1 = {'vrf_name':vrrp_vrf, 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.config_vrf, [dict1, dict1,dict1])


    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,vrrp_vlan_intf[0], dut1_2_ipv6_list[0],mask_v6,'ipv6'],
                         [ip_api.config_ip_addr_interface,data.dut2,vrrp_vlan_intf[0], dut2_1_ipv6_list[0],mask_v6,'ipv6']])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut2[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'version':3}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'version':3}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut2[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict2])

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrpv3_func_008(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn026","FtOpSoRoVrrpv3Fn048"]
    tc_result = True ;err_list=[]
    run_traffic()
    ##############################################################
    hdrMsg("Step01: Configure track port,advertisement -interval on vrrp session {}".format(vrid_list[0]))
    ##############################################################
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],track_priority_list=[1])
    vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],track_priority_list=[1])

    ##############################################################
    hdrMsg("Step02: Verify all configured parameters under show command for vrid {}".format(vrid_list[0]))
    ##############################################################
    result = retry_api(vrrp.verify_vrrp,data.dut1,state='Master',config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],track_priority_list=['1'],vrid=vrid_list[0],interface=vrrp_vlan_intf[0])
    if result is False:
        err ='VRRP prameters are incorrect for VRID {}'.format(vrid_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    result = retry_api(vrrpv3.verify_vrrpv3,data.dut1,state='Master',config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],track_priority_list=['1'],vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0])
    if result is False:
        err ='VRRPv3 prameters are incorrect for VRID {}'.format(vrid_ipv6_list[0])
        failMsg(err); err_list.append(err);tc_result = False;

    ##############################################################
    hdrMsg("Step03: Verify VRRP elections for all configured sessions")
    ##############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err); err_list.append(err);tc_result = False;

    result = verify_vrrpv6()
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        failMsg(err); err_list.append(err);tc_result = False;

    ###########################################################
    hdrMsg("Step04 : Config save")
    ############################################################
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1,shell='vtysh')

    for trigger in trigger_list:
        ##########################################
        hdrMsg("Perform {} on dut1".format(trigger))
        ##########################################
        if trigger == 'fast_boot':
            st.reboot(data.dut1, 'fast')
        elif trigger == 'config_reload':
            reboot_api.config_reload(data.dut1)
        elif trigger == 'docker_restart':
            basic_api.service_operations_by_systemctl(data.dut1, 'vrrp', 'restart')

        ##############################################################
        hdrMsg("Step: Verify all configured parameters under show command for vrid {} after {}".format(vrid_list[0],trigger))
        ##############################################################
        result = retry_api(vrrp.verify_vrrp,data.dut1,config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],track_priority_list=['1'],vrid=vrid_list[0],interface=vrrp_vlan_intf[0])
        if result is False:
            err ='VRRP prameters are incorrect for VRID {} after {}'.format(vrid_list[0],trigger)
            failMsg(err);err_list.append(err);

        result = retry_api(vrrpv3.verify_vrrpv3,data.dut1,config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],track_priority_list=['1'],vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0])
        if result is False:
            err ='VRRPv3 prameters are incorrect for VRID {} after the trigger {}'.format(vrid_ipv6_list[0],trigger)
            failMsg(err); err_list.append(err);

        ##############################################################
        hdrMsg("Step: Verify VRRP elections for all configured sessions after {}".format(trigger))
        ##############################################################
        result = verify_vrrp(summary='yes',retry_count=15,delay=3)
        if result is False:
            err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions after {}".format(trigger)
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False;

        result = verify_vrrpv6(summary='yes',retry_count=15,delay=3)
        if result is False:
            err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
            failMsg(err);debug_vrrpv3();err_list.append(err);tc_result = False;

        ###########################################################
        hdrMsg("Step: Verify the traffic forwarding for all VRRP sessions after {}".format(trigger))
        ############################################################

        result = verify_tg_traffic_rate()
        if result is False:
            err = "Traffic not forwarded for all configured sessions after {}".format(trigger)
            failMsg(err); err_list.append(err);tc_result = False

    st.log("\n Revert VRRP config on dut1\n")
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],track_priority_list=[1],config='no')
    vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],track_priority_list=[1],config='no')
    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list)
    else:
        st.report_pass('test_case_passed')


def test_vrrpv3_func_004(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn007","FtOpSoRoVrrpv3Fn023","FtOpSoRoVrrpv3Fn031","FtOpSoRoVrrpv3Fn045"]
    tc_result = True ;err_list=[]
    #import pdb;pdb.set_trace()
    ###########################################################
    hdrMsg("Step01 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions"
        st.report_fail('test_case_failure_message', err)

    ###########################################################
    hdrMsg("Step02 : Start Traffic for all configured VRRP sessions")
    ############################################################
    run_traffic()

    ###########################################################
    hdrMsg("Step03 : Shutdown all member ports of LAG {} on dut1 connected to dut3(switch) and "
           "verify dut2 becomes Master for all sessions".format(lag_id_list[0]))
    ############################################################
    port_api.shutdown(data.dut1,data.d1d3_ports)

    for vrid,vlan,vmac,vip in zip(vrid_list,vrrp_vlan_intf,vmac_list_1,vip_list):
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
        if result is False:
            err = "After port shutdown on dut1, dut2 did not become Master for all VRRP ipv4 sessions"
            failMsg(err);err_list.append(err);tc_result = False

    for vrid,vlan,vmac,vip in zip(vrid_ipv6_list,vrrp_vlan_intf,vmac_ipv6_list_2,vip_ipv6_list):
        result =verify_master_backup_v6(vrid,vlan,vmac,vip,master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
        if result is False:
            err = "After port shutdown on dut1, dut2 did not become Master for all VRRP ipv6 sessions"
            failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step04 : Verify Traffic gets load balanced via new Master(DUT2) for all vrrp sessions")
    ############################################################
    result =verify_tg_traffic_rate()
    if result is False:
        err = "Traffic not forwarded by all VRRP Masters"
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step05 : No-Shutdown all member ports of LAG {} on dut1 connected to dut3(switch) and verify dut1"
           " becomes Master again for vrrp sessions {} and ipv6 vrrp sessions {}".format(lag_id_list[0],vrid_list[0:int(vrrp_sessions/2)],vrid_ipv6_list[0:int(vrrp_sessions/2)]))
    ############################################################
    port_api.noshutdown(data.dut1,data.d1d3_ports)

    for vrid,vlan,vmac,vip in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],vmac_list_1[0:int(vrrp_sessions/2)],vip_list[0:int(vrrp_sessions/2)]):
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2,skip_backup_check='yes')
        if result is False:
            err = "After port no-shutdown on dut1, dut1 did not become Master again for VRRP sessions {}".format(vrid_list[0:int(vrrp_sessions/2)])
            failMsg(err);err_list.append(err);tc_result = False

    for vrid,vlan,vmac,vip in zip(vrid_ipv6_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],vmac_ipv6_list_2[0:int(vrrp_sessions/2)],vip_ipv6_list[0:int(vrrp_sessions/2)]):
        result =verify_master_backup_v6(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2,skip_backup_check='yes')
        if result is False:
            err = "After port no-shutdown on dut1, dut1 did not become Master again for VRRP sessions {}".format(vrid_ipv6_list[0:int(vrrp_sessions/2)])
            failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step07 :Change all ports between dut1 <--> dut3, dut2 <---> dut3 to untagged on vlan {}".format(vrrp_vlans[0]))
    ############################################################
    utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[0],'del'],
        [vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[1],'del'],
        [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), [lag_intf_list[0],lag_intf_list[1],data.d3tg_ports],'del']])

    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1,vrrp_vlans[0],lag_intf_list[0]],
                          [vlan_api.add_vlan_member, data.dut2,vrrp_vlans[0],lag_intf_list[1]],
                          [vlan_api.add_vlan_member, data.dut3,vrrp_vlans[0],[lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])


    ###########################################################
    hdrMsg("Step08 :Verify VRRP election happens correctly for untagged Vlan {}".format(vrrp_vlans[0]))
    ############################################################
    result = verify_master_backup(vrid_list[0],vrrp_vlan_intf[0],vmac_list_1[0],vip_list[0],master_dut=data.dut1,backup_dut=data.dut2)
    if result is False:
        err = "VRRP election did not happen after changing port mode from trunk to access"
        failMsg(err);err_list.append(err);tc_result = False

    result = verify_master_backup_v6(vrid_ipv6_list[0],vrrp_vlan_intf[0],vmac_ipv6_list_2[0],vip_ipv6_list[0],master_dut=data.dut1,backup_dut=data.dut2)
    if result is False:
        err = "VRRP ipv6 election did not happen after changing port mode from trunk to access"
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step09 : Increase the priority on backup node to {} and verify dut2 becomes Master".format(vrrp_priority_list_dut1[0]+1))
    ############################################################
    vrrp.configure_vrrp(data.dut2,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority=vrrp_priority_list_dut1[0]+1)
    result = verify_master_backup(vrid_list[0],vrrp_vlan_intf[0],vmac_list_1[0],vip_list[0],master_dut=data.dut2,backup_dut=data.dut1)
    if result is False:
        err = "VRRP failover did not happen for vrrp session over access port"
        failMsg(err);err_list.append(err);tc_result = False

    vrrpv3.configure_vrrpv3(data.dut2,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],priority=vrrp_priority_list_dut1[0]+1)
    result = verify_master_backup_v6(vrid_ipv6_list[0],vrrp_vlan_intf[0],vmac_ipv6_list_2[0],vip_ipv6_list[0],master_dut=data.dut2,backup_dut=data.dut1)
    if result is False:
        err = "VRRP failover did not happen for vrrp ipv6 session over access port"
        failMsg(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step10 : Verify Traffic gets forwarded only for one VRRP session on vlan {}".format(vrrp_vlans[0]))
    ############################################################
    result = verify_tg_traffic_rate(exp_ratio=float(1/float(vrrp_sessions)))
    if result is False:
        err = "untagged traffic failed for vrrp session {} on vlan {}".format(vrid_list[0],vrrp_vlan_intf[0])
        failMsg(err);err_list.append(err);tc_result = False

    st.log("\n #### Revert back vrrp priority on dut2 ### \n")
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut2[0])
    vrrpv3.configure_vrrpv3(data.dut2,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],priority=vrrp_priority_list_dut2[0])

    ###########################################################
    hdrMsg("Step11 :Revert all ports between dut1,dut2 and dut3 back to tagged with all vrrp vlans ")
    ############################################################
    utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1,vrrp_vlans[0],lag_intf_list[0]],
                          [vlan_api.delete_vlan_member, data.dut2,vrrp_vlans[0],lag_intf_list[1]],
                          [vlan_api.delete_vlan_member, data.dut3,vrrp_vlans[0],[lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])

    utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[0]],
        [vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[1]],
        [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), [lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions after triger tagged-untagged-tagged interface type"
        st.report_fail('test_case_failure_message', err)

    result = verify_vrrpv6(summary='yes')
    if result is False:
        err = "VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions after triger tagged-untagged-tagged interface type"
        st.report_fail('test_case_failure_message', err)

    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

###########################################################################################################################################
@pytest.fixture(scope="function")
def vrrpv3_cleanup_fixture(request,prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP Start###")
    st.log("\n#### Remove secondary ip as Virtual-IP config first ###\n")
    dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    st.log("\n#### Configure Virtual IP {} for {} ###\n".format(vip_list[0],vrrp_vlan_intf[0]))
    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0] ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0] ,'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    #ip_api.delete_ip_interface(data.dut1, vrrp_vlan_intf[0], vrrp_sec_ip_list[0], mask)
    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0] ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut1[0],skip_error=True)

    ##### Added by Raghu ####
    st.log("\n#### Remove secondary ip as Virtual-IP config first ###\n")
    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vrrp_sec_ipv6_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    st.log("\n#### Configure Virtual IP {} for {} ###\n".format(vip_ipv6_list[0],vrrp_vlan_intf[0]))
    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0] ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0] ,'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    #ip_api.delete_ip_interface(data.dut1, vrrp_vlan_intf[0], vrrp_sec_ipv6_list[0], mask_v6,family='ipv6')
    dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0] ,'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])

    vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid_ipv6_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut1[0],skip_error=True)
    run_traffic(action='stop')
    ### ------------------------ ###
    hdrMsg("### CLEANUP End####")

def test_vrrpv3_func_002(vrrpv3_cleanup_fixture):
    tc_list = ["FtOpSoRoVrrpv3Fn005","FtOpSoRoVrrpv3Fn006","FtOpSoRoVrrpv3Fn011","FtOpSoRoVrrpv3Fn020","FtOpSoRoVrrpv3Fn021","FtOpSoRoVrrpv3Fn029","FtOpSoRoVrrpv3Fn030","FtOpSoRoVrrpv3Fn035","FtOpSoRoVrrpv3Fn042","FtOpSoRoVrrpv3Fn043"]
    tc_result = True ;err_list=[]
    
    ######################################################################################################################################################
    hdrMsg("Step01 : Configure Virtual IP {} for vrid {} same as that of {} and verify Cli gets ""rejected".format(vip_list[0],vrid_list[1],vrid_list[0]))
    ######################################################################################################################################################
    result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[1],interface=vrrp_vlan_intf[1],vip=vip_list[0],skip_error=True)
    expected_err ="Error"
    if expected_err not in str(result):
        err = "Same VIP {} accepted for two different VRRP ipv4 sessions ".format(vip_list[0])
        failMsg(err);tc_result=False;err_list.append(err)

    #####################################################################################################################################################################
    hdrMsg("Step02 : Configure Virtual IPv6 {} for vrid {} same as that of {} and verify Cli gets ""rejected".format(vip_ipv6_list[0],vrid_ipv6_list[1],vrid_ipv6_list[0]))
    #####################################################################################################################################################################
    result =vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[1],interface=vrrp_vlan_intf[1],vip=vip_ipv6_list[0],skip_error=True)
    expected_err ="Error"
    if expected_err not in str(result):
        err = "Same VIP {} accepted for two different VRRP ipv6 sessions ".format(vip_ipv6_list[0])
        vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[1],interface=vrrp_vlan_intf[1],vip=vip_ipv6_list[0],config='no',skip_error=True)
        #vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[1],interface=vrrp_vlan_intf[1],vip=vip_ipv6_list[1])
        failMsg(err);tc_result=False;err_list.append(err)

    st.log("Start Traffic for VRRP instances ")
    run_traffic()
    
    if st.get_ui_type(data.dut1) == 'click':
        ##############################################################################################################
        hdrMsg("Step03 : Configure secondary ip {} to VRRP  {} on dut1".format(vrrp_sec_ip_list[0],vrrp_vlan_intf[0]))
        ##############################################################################################################
        ip_api.config_ip_addr_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ip_list[0],30)
    
        ######################################################################################################################################################
        hdrMsg("Step04 : Configure secondary ip {} as Virtual ip for vrrp ""session {} on vlan {}".format(vrrp_sec_ip_list[0],vrid_list[0],vrrp_vlan_intf[0]))
        ######################################################################################################################################################
        st.log("------- >>>>> Remove old vritual-ip {} first before configuring secondar ip as virtual-ip <<<<<<< ------ ".format(vip_list[0]))
        dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' }
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
    
        ### --------------------------------------------------------------- ####
        ###########################################################
        hdrMsg("Step05 :Configure primary interface IP as VIP on dut1")
        ###########################################################
        vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority='100',skip_error=True)
        dict1 = {'vrid': vrid_list[0], 'vip': vrrp_ip_list[0][0], 'interface': vrrp_vlan_intf[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
    
        ##############################################################################
        hdrMsg("Step06 : Verify primary ip elected as VIP and priority is set to 255")
        ##############################################################################
        st.wait(5)
        vrrp.verify_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],vip=vrrp_ip_list[0][0],state='Master',config_prio=255)
        
        ####################################################################################
        hdrMsg("Step07 : Try to configure track interface with track priority and verify CLI gets rejected")
        ####################################################################################
        result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],track_interface_list=[data.d1d4_ports[3]], track_priority_list=[50],skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "Track interface allowed for Owner VRRP ipv4 instance {} ".format(vrid_list[0])
            failMsg(err);tc_result=False;err_list.append(err)
        
        ##############################################################
        hdrMsg("Step08 : Remove primary IP as VIP" )
        ##############################################################
        dict1 = {'vrid': vrid_list[0], 'vip': vrrp_ip_list[0][0], 'interface': vrrp_vlan_intf[0], 'config': 'no','skip_error':True }
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
        
        ### --------------------------------------------------------------- ####
        st.log(" ----- >>> Configure secondary ip address {} as virtual-ip on both DUTs <<< ------".format(vrrp_sec_ip_list[0]))
        vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority='100',skip_error=True)
        dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
        
        #######################################################################################
        hdrMsg("Step09 : Verify secondary ip elected as VIP and vrrp roles on dut1 and dut2")
        #######################################################################################
        result = verify_master_backup(vrid=vrid_list[0],interface=vrrp_vlan_intf[0],vmac=vmac_list_1[0],vip=vrrp_sec_ip_list[0],master_dut=data.dut1,backup_dut=data.dut2)
        if result is False:
            err = "Testcase {} VRRP elections incorrect with secondary ip {} configured as Virtualip ".format(tc_list[0],vrrp_sec_ip_list[0])
            failMsg(err);debug_vrrpv3();tc_result=False;err_list.append(err)
        
        ##########################################################################################################################
        hdrMsg("Step10 : Configure secondary ipv6 address {} to VRRP ipv6 {} on dut1".format(vrrp_sec_ipv6_list[0],vrrp_vlan_intf[0]))
        ##########################################################################################################################
        ip_api.config_ip_addr_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ipv6_list[0],70,family='ipv6')
        
        ###########################################################
        hdrMsg("Step11 : Configure secondary ipv6 address {} as Virtual ip for vrrp ipv6  ""session {} on vlan {}".format(vrrp_sec_ipv6_list[0],vrid_ipv6_list[0],vrrp_vlan_intf[0]))
        ############################################################
        st.log("Remove old vritual-ipv6 address {} first before configuring secondar ipv6 address as virtual-ip".format(vip_ipv6_list[0]))
        dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' ,'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])
        
        st.log("Configure secondary ipv6 address {} as virtual-ip on both DUTs".format(vrrp_sec_ipv6_list[0]))
        vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],priority='100',skip_error=True)
        dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vrrp_sec_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])
        
        #################################################################################################
        hdrMsg("Step12 : Verify secondary ipv6 address is elected as VIP and vrrp ipv6 roles on dut1 and dut2")
        #################################################################################################
        result = verify_master_backup_v6(vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],vmac=vmac_ipv6_list_2[0],vip=vrrp_sec_ipv6_list[0],master_dut=data.dut1,backup_dut=data.dut2)
        if result is False:
            err = "Testcase {} VRRP ipv6 elections incorrect with secondary ipv6 address {} configured as Virtualip ".format(tc_list[0],vrrp_sec_ip_list[0])
            failMsg(err);debug_vrrpv3();tc_result=False;err_list.append(err)
        
        hdrMsg(" Try to configure track interface with track priority and verify CLI gets rejected")
        result =vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],track_interface_list=[data.d1d4_ports[3]], track_priority_list=[50],skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "Track interface allowed for Owner VRRP ipv6 instance {} ".format(vrid_ipv6_list[0])
            failMsg(err);tc_result=False;err_list.append(err)
        
        ########################################################################################################################################
        hdrMsg("Step13 : Verify primary ip {} used as  source ip for vrrp ipv4 advertisements sent out from dut1 master".format(vrrp_ip_list[0][0]))
        ########################################################################################################################################
        
        data.tg1.tg_packet_control(port_handle=data.tg_handles[0], action='start')
        st.wait(3)
        data.tg1.tg_packet_control(port_handle=data.tg_handles[0], action='stop')
        pkts_captured = data.tg1.tg_packet_stats(port_handle=data.tg_handles[0], format='var',output_type='hex')
        capture_result = tgapi.validate_packet_capture(tg_type=data.tg1.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[0, 30, 14],
                                             value_list=['01:00:5E:00:00:12',vrrp_ip_list[0][0],str(format(vrrp_vlans[0],'04X'))])
        
        if not capture_result:
            err = "Testcase {} VRRP advertisement not using primary IP {} as source".format(tc_list[0],vrrp_ip_list[0][0])
            failMsg(err);debug_vrrpv3();tc_result=False;err_list.append(err)
        
        ##############################################################################################
        hdrMsg("Step14 : Delete secondary ip as VRRP VIP ")
        ##############################################################################################
        st.log("#### Remove Virtual-IP config first ###")
        dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','skip_error':True }
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
        
        st.log("\n##### Delete secondary IP {} from {}  #####\n".format(vrrp_sec_ip_list[0],vrrp_vlan_intf[0]))
        ip_api.delete_ip_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ip_list[0],30)
        
        st.log("\n#### Configure Virtual IP {} for {} ###\n".format(vip_list[0],vrrp_vlan_intf[0]))
        dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0] ,'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
        
        result = verify_master_backup(vrid=vrid_list[0], interface=vrrp_vlan_intf[0], vmac=vmac_list_1[0],vip=vip_list[0], master_dut=data.dut1, backup_dut=data.dut2)
        if result is False:
            err = "Testcase {} VRRP elections incorrect after deleting secondary ip {} which is also configured as Virtualip ".format(tc_list[0], vrrp_sec_ip_list[0])
            failMsg(err);debug_vrrpv3();tc_result = False;err_list.append(err)
        
        vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut1[0],skip_error=True)

        ##############################################################################################
        hdrMsg("Step15 : Remove secondary ipv6 address as vip and verify VRRP ipv6 elections happens on dut1 and dut2 ")
        ##############################################################################################
        st.log("\n#### Remove secondary ipv6 as Virtual-IP config first ###\n")
        dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vrrp_sec_ipv6_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','skip_error':True }
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])
        
        ##################################################################################
        hdrMsg("Step16 : Remove secondary ipv6 address from the interface of DUT1")
        ##################################################################################
        ip_api.delete_ip_interface(data.dut1, vrrp_vlan_intf[0], vrrp_sec_ipv6_list[0], 70,family='ipv6')

        st.log("\n#### Configure Virtual IPv6 address {} as vip for interface {} ###\n".format(vip_ipv6_list[0],vrrp_vlan_intf[0]))
        dict1 = {'vrid': vrid_ipv6_list[0], 'vip': vip_ipv6_list[0], 'interface': vrrp_vlan_intf[0],'skip_error':True }
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrrpv3.configure_vrrpv3, [dict1, dict1])
        
        result = verify_master_backup_v6(vrid=vrid_ipv6_list[0], interface=vrrp_vlan_intf[0], vmac=vmac_ipv6_list_2[0],vip=vip_ipv6_list[0], master_dut=data.dut1, backup_dut=data.dut2)
        if result is False:
            err = "VRRP ipv6 elections incorrect after deleting secondary ipv6 address {} which is also configured as Virtualip ".format(vrrp_sec_ipv6_list[0])
            failMsg(err);tc_result = False;err_list.append(err)
        
        vrrpv3.configure_vrrpv3(data.dut1, vrid=vrid_ipv6_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut1[0],skip_error=True)
    
    ################################################################################################
    hdrMsg("Step17 : Verify Traffic after delete/add primary IP for VRID {} and ipv6 VRID {} ".format(vrid_list,vrid_ipv6_list))
    ################################################################################################
    result = verify_tg_traffic_rate()
    if result is False:
        err = "data traffic not forwarded for VRIDs"
        failMsg(err); err_list.append(err);tc_result = False
    run_traffic(action='stop')

    ###########################################################
    hdrMsg("Step18 : Verify out of range values gets rejected for advertisement interval -for ipv4 vrrp sessions ")
    ############################################################
    for interval in [0,256]:
        result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],adv_interval=interval,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "{} sec should not be accepted for advertisement interval".format(interval)
            failMsg(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Step19 : Verify out of range values gets rejected for vrrp priority -for ipv4 vrrp sessions ")
    ############################################################
    for prio in [0,255]:
        result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority=prio,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "{} should not be accepted for vrrp priority".format(prio)
            failMsg(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Step20 : Verify out of range values gets rejected for advertisement interval -for ipv6 vrrp sessions ")
    ############################################################
    for interval in [0,256]:
        result =vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],adv_interval=interval,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "{} sec should not be accepted for advertisement interval".format(interval)
            failMsg(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Step21 : Verify out of range values gets rejected for vrrp priority -for ipv6 vrrp sessions ")
    ############################################################
    for prio in [0,255]:
        result =vrrpv3.configure_vrrpv3(data.dut1,vrid=vrid_ipv6_list[0],interface=vrrp_vlan_intf[0],priority=prio,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "{} should not be accepted for vrrp priority".format(prio)
            failMsg(err);tc_result=False;err_list.append(err)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

def test_vrrpv3_func_009(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpv3REST001","FtOpSoRoVrrpv3REST002","FtOpSoRoVrrpv3REST003","FtOpSoRoVrrpv3REST004","FtOpSoRoVrrpv3REST005","FtOpSoRoVrrpv3REST006","FtOpSoRoVrrpv3REST007","FtOpSoRoVrrpv3REST008","FtOpSoRoVrrpv3REST009","FtOpSoRoVrrpv3REST010","FtOpSoRoVrrpv3REST011","FtOpSoRoVrrpv3REST012"]
    tc_result = True ;err_list=[]
    final_result = 0    
    #################################################################################
    #   REST API Testing begins
    #################################################################################   
    ################################################################################
    rest_urls = st.get_datastore(data.dut1,'rest_urls')
    st.banner("Step01: Doing REST Delete operation to delete the VRRPv3 config ")
    ################################################################################
    for vrid,vlan,vip,dut1_prio,dut2_prio,ip in zip(vrid_list,dut1_vlan_intf[0:vrrp_sessions],vip_list,vrrp_priority_list_dut1,vrrp_priority_list_dut2,vrrp_ip_list):
        rest_url_del_dut1 = rest_urls['vrrp_delete'].format(vlan,ip[0],vrid)
        rest_url_del_dut2 = rest_urls['vrrp_delete'].format(vlan,ip[1],vrid)
        st.log(rest_url_del_dut1)
        st.log(rest_url_del_dut2)
        response2 = st.rest_delete(data.dut1, rest_url_del_dut1)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to delete vrrpv3-v4 config through REST API on DUT1")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step1'],[st.generate_tech_support,data.dut2,'dut2_step1']])
            st.report_tc_fail(tc_list[0],'test_case_failure_message')
        
        response2 = st.rest_delete(data.dut2, rest_url_del_dut2)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to delete vrrpv3-v4 config through REST API on DUT2")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step1'],[st.generate_tech_support,data.dut2,'dut2_step1']])
            st.report_tc_fail(tc_list[0],'test_case_failure_message')           
        
    if tc_result is True:
        st.report_tc_pass(tc_list[0],'tc_passed')
    
    tc_result = True    
    for vrid,vlan,vip,dut1_prio,dut2_prio,dut1_ipv6,dut2_ipv6 in zip(vrid_ipv6_list,dut1_vlan_intf[0:vrrp_sessions],vip_ipv6_list,vrrp_priority_list_dut1,vrrp_priority_list_dut2,dut1_2_ipv6_list,dut2_1_ipv6_list):
        rest_url_del_dut1 = rest_urls['vrrpv3_delete'].format(vlan,dut1_ipv6,vrid)
        rest_url_del_dut2 = rest_urls['vrrpv3_delete'].format(vlan,dut2_ipv6,vrid)
        st.log(rest_url_del_dut1)
        st.log(rest_url_del_dut2)
        response2 = st.rest_delete(data.dut1, rest_url_del_dut1)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to delete vrrpv3-v6 config through REST API on DUT1")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step1'],[st.generate_tech_support,data.dut2,'dut2_step1']])
            st.report_tc_fail(tc_list[1],'test_case_failure_message')

        response2 = st.rest_delete(data.dut2, rest_url_del_dut2)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to delete vrrpv3-v6 config through REST API on DUT2")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step1'],[st.generate_tech_support,data.dut2,'dut2_step1']])
            st.report_tc_fail(tc_list[1],'test_case_failure_message')           
        
    if tc_result is True:
        st.report_tc_pass(tc_list[1],'tc_passed')
    
    tc_result = True
    ################################################################################
    st.banner("Step02: Doing REST POST operation to config the VRRPv3 feature ")
    ################################################################################
    for vrid,vlan,vip,dut1_prio,dut2_prio,ip in zip(vrid_list,dut1_vlan_intf[0:vrrp_sessions],vip_list,vrrp_priority_list_dut1,vrrp_priority_list_dut2,vrrp_ip_list):   
        ocdata_dut1 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid,"config":{"virtual-router-id":vrid,"virtual-address":[vip],"priority":dut1_prio,"preempt":bool(1),"advertisement-interval":1,"openconfig-interfaces-ext:version":3}}]}
        ocdata_dut2 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid,"config":{"virtual-router-id":vrid,"virtual-address":[vip],"priority":dut2_prio,"preempt":bool(1),"advertisement-interval":1,"openconfig-interfaces-ext:version":3}}]}
        rest_url_dut1 = rest_urls['vrrp_config_all'].format(vlan,ip[0])
        rest_url_dut2 = rest_urls['vrrp_config_all'].format(vlan,ip[1])
        st.log(rest_url_dut1)
        st.log(rest_url_dut2)
        response2 = st.rest_create(data.dut1, path=rest_url_dut1, data=ocdata_dut1)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to configure vrrpv3-v4 through REST API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step2'],[st.generate_tech_support,data.dut2,'dut2_step2']])
            st.report_tc_fail(tc_list[2],'test_case_failure_message')
        
        response2 = st.rest_create(data.dut2, path=rest_url_dut2, data=ocdata_dut2)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to configure vrrpv3-v4 through REST API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step2'],[st.generate_tech_support,data.dut2,'dut2_step2']])
            st.report_tc_fail(tc_list[2],'test_case_failure_message')       
    
    if tc_result is True:
        st.report_tc_pass(tc_list[2],'tc_passed')
    
    tc_result = True    
    for vrid,vlan,vip,dut1_prio,dut2_prio,dut1_ipv6,dut2_ipv6 in zip(vrid_ipv6_list,dut1_vlan_intf[0:vrrp_sessions],vip_ipv6_list,vrrp_priority_list_dut1,vrrp_priority_list_dut2,dut1_2_ipv6_list,dut2_1_ipv6_list):      
        #####################################
        ocdata_dut1 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid,"config":{"virtual-router-id":vrid,"virtual-address":[vip],"priority":dut1_prio,"preempt":bool(1),"advertisement-interval":1}}]}
        ocdata_dut2 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid,"config":{"virtual-router-id":vrid,"virtual-address":[vip],"priority":dut2_prio,"preempt":bool(1),"advertisement-interval":1}}]}
        rest_url_dut1 = rest_urls['vrrpv3_config_all'].format(vlan,dut1_ipv6)
        rest_url_dut2 = rest_urls['vrrpv3_config_all'].format(vlan,dut2_ipv6)
        st.log(rest_url_dut1)
        st.log(rest_url_dut2)
        response2 = st.rest_create(data.dut1, path=rest_url_dut1, data=ocdata_dut1)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to configure vrrpv3-v6 through REST API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step2'],[st.generate_tech_support,data.dut2,'dut2_step2']])
            st.report_tc_fail(tc_list[3],'test_case_failure_message')
        
        response2 = st.rest_create(data.dut2, path=rest_url_dut2, data=ocdata_dut2)
        result =verify_rest_response(response2)
        if result is False:
            st.error("Failed to configure vrrpv3-v6 through REST API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step2'],[st.generate_tech_support,data.dut2,'dut2_step2']])
            st.report_tc_fail(tc_list[3],'test_case_failure_message')
    
    if tc_result is True:
        st.report_tc_pass(tc_list[3],'tc_passed')
    
    tc_result = True    
    ################################################################################################################
    st.banner("Step03 : Verify VRRP Master/Backup election for all VR-ID {} configured sessions".format(vrrp_sessions))
    ################################################################################################################
    result = verify_vrrp()
    if result is False:
        st.error("VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv4 sessions")
        st.report_tc_fail(tc_list[3],'test_case_failure_message')
    
    result = verify_vrrpv6()
    if result is False:
        st.error("VRRPv3 Master/Backup election is incorrect for one or more VRRP ipv6 sessions")
        st.report_tc_fail(tc_list[3],'test_case_failure_message')
                
    ################################################################################
    st.banner("Step03: Doing REST GET operation to verify VRRP election ")
    ################################################################################
    vrid_end_idx = int(vrrp_sessions/2)
    for vrid,vlan,vip,dut1_prio,dut2_prio,ip in zip(vrid_list[0:vrid_end_idx],dut1_vlan_intf[0:vrid_end_idx],vip_list[0:vrid_end_idx],vrrp_priority_list_dut1[0:vrid_end_idx],vrrp_priority_list_dut2[0:vrid_end_idx],vrrp_ip_list[0:vrid_end_idx]):
        result =vrrp_rest_get_status(data.dut1,vlan,vrid,vip,ip,dut1_prio,dut2_prio,vrrp_state=2,version=3,preempt_value=True,advt_int=1)
        if result is False:
            st.error("Failed to validate show vrrp output through REST GET API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step3'],[st.generate_tech_support,data.dut2,'dut2_step3']])
            st.report_tc_fail(tc_list[4],'test_case_failure_message')
                    
    for vrid,vlan,vip,dut1_prio,dut2_prio,ip in zip(vrid_list[2:vrrp_sessions],dut1_vlan_intf[2:vrrp_sessions],vip_list[2:vrrp_sessions],vrrp_priority_list_dut1[2:vrrp_sessions],vrrp_priority_list_dut2[2:vrrp_sessions],vrrp_ip_list[2:vrrp_sessions]):
        result =vrrp_rest_get_status(data.dut1,vlan,vrid,vip,ip,dut1_prio,dut2_prio,vrrp_state=1,version=3,preempt_value=True,advt_int=1)    
        if result is False:
            st.error("Failed to validate show vrrp output through REST GET API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step3'],[st.generate_tech_support,data.dut2,'dut2_step3']])
            st.report_tc_fail(tc_list[4],'test_case_failure_message')    

    if tc_result is True:
        st.report_tc_pass(tc_list[4],'tc_passed')
    
    tc_result = True
    for vrid,vlan,vip,dut1_prio,dut2_prio,ipv6 in zip(vrid_ipv6_list[0:vrid_end_idx],dut1_vlan_intf[0:vrid_end_idx],vip_ipv6_list[0:vrid_end_idx],vrrp_priority_list_dut1[0:vrid_end_idx],vrrp_priority_list_dut2[0:vrid_end_idx],dut1_2_ipv6_list[0:vrid_end_idx]):
        result =vrrpv3_rest_get_status(data.dut1,vlan,vrid,vip,ipv6,dut1_prio,dut2_prio,vrrp_state=2,version=3,preempt_value=True,advt_int=1)    
        if result is False:
            st.error("Failed to validate show vrrp output through REST GET API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step3'],[st.generate_tech_support,data.dut2,'dut2_step3']])
            st.report_tc_fail(tc_list[5],'test_case_failure_message')
                
    for vrid,vlan,vip,dut1_prio,dut2_prio,ipv6 in zip(vrid_ipv6_list[2:vrrp_sessions],dut1_vlan_intf[2:vrrp_sessions],vip_ipv6_list[2:vrrp_sessions],vrrp_priority_list_dut1[2:vrrp_sessions],vrrp_priority_list_dut2[2:vrrp_sessions],dut1_2_ipv6_list[2:vrrp_sessions]):
        result =vrrpv3_rest_get_status(data.dut1,vlan,vrid,vip,ipv6,dut1_prio,dut2_prio,vrrp_state=1,version=3,preempt_value=True,advt_int=1)
        if result is False:
            st.error("Failed to validate show vrrp output through REST GET API")
            tc_result=False;final_result += 1;
            utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step3'],[st.generate_tech_support,data.dut2,'dut2_step3']])
            st.report_tc_fail(tc_list[5],'test_case_failure_message')
        
    ###########################################################
    st.banner("Step3.1 : Verify Traffic gets forwarded for all VRRP sessions configured")
    ############################################################
    run_traffic()
    result = verify_tg_traffic_rate()
    if result is False:
        st.error("data traffic not forwarded for all VRIDs {} {}" .format(vrid_list,vrid_ipv6_list))
        tc_result = False;final_result += 1;
             
    if tc_result is True:
        st.report_tc_pass(tc_list[5],'tc_passed')
    
    tc_result = True     
    ################################################################################
    st.banner("Step04: Doing REST PATCH operation to disable preempt ")
    ################################################################################    
    ocdata = {"openconfig-if-ip:preempt":bool(0)}
    rest_url = rest_urls['vrrp_preempt'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_preempt'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to disable vrrpv3 preempt through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step4'],[st.generate_tech_support,data.dut2,'dut2_step4']])
        st.report_tc_fail(tc_list[6],'test_case_failure_message')
    
    
    ################################################################################
    st.banner("Step05: Doing REST GET operation to validate preempt mode is disabled ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=False,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=False,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step5'],[st.generate_tech_support,data.dut2,'dut2_step5']])
        st.report_tc_fail(tc_list[6],'test_case_failure_message')
    
    if tc_result is True:
        st.report_tc_pass(tc_list[6],'tc_passed')
    
    tc_result = True     
    ################################################################################
    st.banner("Step06: Doing REST PATCH operation to enable preempt again ")
    ################################################################################    
    ocdata = {"openconfig-if-ip:preempt":bool(1)}
    rest_url = rest_urls['vrrp_preempt'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_preempt'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to enable vrrpv3 preempt through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step6'],[st.generate_tech_support,data.dut2,'dut2_step6']])
        st.report_tc_fail(tc_list[7],'test_case_failure_message')
    
        
    ################################################################################
    st.banner("Step07: Doing REST GET operation to validate preempt mode is enabled ")
    ################################################################################
    st.wait(50)    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step7'],[st.generate_tech_support,data.dut2,'dut2_step7']])
        st.report_tc_fail(tc_list[7],'test_case_failure_message')

    if tc_result is True:
        st.report_tc_pass(tc_list[7],'tc_passed')
    
    tc_result = True 
    ################################################################################
    st.banner("Step08: Doing REST PATCH operation to change the Advertisement-interval on DUT1 to 2")
    ################################################################################
    ocdata = {"openconfig-if-ip:advertisement-interval":2}
    rest_url = rest_urls['vrrp_advt_interval'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_advt_interval'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to config vrrpv3 adv-interval through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step8'],[st.generate_tech_support,data.dut2,'dut2_step8']])
        st.report_tc_fail(tc_list[8],'test_case_failure_message')
    
    
    ################################################################################
    st.banner("Step09: Doing REST GET operation to validate advertisement-interval which is set to 2 ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=2)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=2)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step9'],[st.generate_tech_support,data.dut2,'dut2_step9']])
        st.report_tc_fail(tc_list[8],'test_case_failure_message')
    
    
    ################################################################################
    st.banner("Step10: Doing REST PATCH operation to change the Advertisement-interval to default value")
    ################################################################################
    ocdata = {"openconfig-if-ip:advertisement-interval":1}
    rest_url = rest_urls['vrrp_advt_interval'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_advt_interval'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to config Advt-interval through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step10'],[st.generate_tech_support,data.dut2,'dut2_step10']])
        st.report_tc_fail(tc_list[8],'test_case_failure_message')
    
    
    ################################################################################
    st.banner("Step11: Doing REST GET operation to validate advertisement-interval is set to 1 ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step11'],[st.generate_tech_support,data.dut2,'dut2_step11']])
        st.report_tc_fail(tc_list[8],'test_case_failure_message')

    if tc_result is True:
        st.report_tc_pass(tc_list[8],'tc_passed')
    
    tc_result = True     
    ################################################################################
    st.banner("Step12: Doing REST PATCH operation to change the priority value")
    ################################################################################
    ocdata = {"openconfig-if-ip:priority":20}
    rest_url = rest_urls['vrrp_priority'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_priority'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to config vrrpv3 priority value through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step12'],[st.generate_tech_support,data.dut2,'dut2_step12']])
        st.report_tc_fail(tc_list[9],'test_case_failure_message')

    
    ################################################################################
    st.banner("Step13: Doing REST GET operation to validate priority value is set to 20 and state becomes Backup ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=20,dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=20,dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step13'],[st.generate_tech_support,data.dut2,'dut2_step13']])
        st.report_tc_fail(tc_list[9],'test_case_failure_message')  

        
    ################################################################################
    st.banner("Step14: Doing REST PATCH operation to revert the priority value to original")
    ################################################################################    
    ocdata = {"openconfig-if-ip:priority":vrrp_priority_list_dut1[0]}
    rest_url = rest_urls['vrrp_priority'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_priority'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to config vrrpv3 priority value through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step14'],[st.generate_tech_support,data.dut2,'dut2_step14']])
        st.report_tc_fail(tc_list[9],'test_case_failure_message')

    
    ################################################################################
    st.banner("Step15: Doing REST GET operation to validate priority value is set to original and state becomes Master ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp/vrrp6 output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step15'],[st.generate_tech_support,data.dut2,'dut2_step15']])
        st.report_tc_fail(tc_list[9],'test_case_failure_message')  

    if tc_result is True:
        st.report_tc_pass(tc_list[9],'tc_passed')
    
    tc_result = True     
    ################################################################################
    st.banner("Step16: Doing REST PATCH operation to add track_interface and its priority")
    ################################################################################
    ocdata = {"openconfig-interfaces-ext:vrrp-track":{"vrrp-track-interface":[{"track-intf":data.d1d4_ports[0],"config":{"track-intf":data.d1d4_ports[0],"priority-increment":2}}]}}    
    rest_url = rest_urls['vrrp_track_interface'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_ipv6 = rest_urls['vrrpv3_track_interface'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_modify(data.dut1, path=rest_url, data=ocdata)
    response3 = st.rest_modify(data.dut1, path=rest_url_ipv6, data=ocdata)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to configure vrrpv3 track-interface and its priority value through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step16'],[st.generate_tech_support,data.dut2,'dut2_step16']])
        st.report_tc_fail(tc_list[10],'test_case_failure_message')
    
    ##################################################################################
    st.banner("Validating REST API GET operation to verify VRRP Master/Backup election")
    ##################################################################################
    rest_url_read = "/restconf/data/openconfig-interfaces:interfaces/interface={}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address={}/vrrp/vrrp-group={}".format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_read_ipv6 = "/restconf/data/openconfig-interfaces:interfaces/interface={}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address={}/vrrp/vrrp-group={}".format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    response2 = st.rest_read(data.dut1, rest_url_read)
    response3 = st.rest_read(data.dut1, rest_url_read_ipv6)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    result3 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'][0]['track-intf'])    
    result4 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'][0]['state']['priority-increment']) 
    result5 =str(response3['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'][0]['track-intf'])    
    result6 =str(response3['output']['openconfig-if-ip:vrrp-group'][0]['openconfig-interfaces-ext:vrrp-track']['vrrp-track-interface'][0]['state']['priority-increment'])     
    if  result3 != str(data.d1d4_ports[0]) or result4 != '2' or result5 != str(data.d1d4_ports[0]) or result6 != '2':
        st.error("Verification of VRRP Track interface and its priority value failed through REST API")
        tc_result=False;final_result += 1;
    
    ################################################################################
    st.banner("Step17: Doing REST DELETE operation to delete track_interface and its priority")
    ################################################################################
    rest_url = rest_urls['vrrp_track_interface_delete'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0],data.d1d4_ports[0])
    rest_url_ipv6 = rest_urls['vrrpv3_track_interface_delete'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0],data.d1d4_ports[0])
    st.log(rest_url)
    st.log(rest_url_ipv6)    
    response2 = st.rest_delete(data.dut1, rest_url)
    response3 = st.rest_delete(data.dut1, rest_url_ipv6)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to delete vrrpv3 track-interface and priority value through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step17'],[st.generate_tech_support,data.dut2,'dut2_step17']])
        st.report_tc_fail(tc_list[10],'test_case_failure_message')       
    
    st.wait(50)
    ################################################################################
    st.banner("Step18: Doing REST GET operation to validate show vrrp after deleting the rack-interface and its priority ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp output through REST GET API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step18'],[st.generate_tech_support,data.dut2,'dut2_step18']])
        st.report_tc_fail(tc_list[10],'test_case_failure_message')   
    
    if tc_result is True:
        st.report_tc_pass(tc_list[10],'tc_passed')
    
    tc_result = True
    ################################################################################
    st.banner("Step19: Doing REST DELETE operation to delete all VRRP config")
    ################################################################################
    rest_url_del_dut1 = rest_urls['vrrp_delete'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0],vrid_list[0])
    rest_url_del_ipv6_dut1 = rest_urls['vrrpv3_delete'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0],vrid_ipv6_list[0])
    st.log(rest_url_del_dut1)
    st.log(rest_url_del_ipv6_dut1)    
    response2 = st.rest_delete(data.dut1, rest_url_del_dut1)
    response3 = st.rest_delete(data.dut1, rest_url_del_ipv6_dut1)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to delete vrrpv3 config through REST API on DUT1")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step19'],[st.generate_tech_support,data.dut2,'dut2_step19']])
        st.report_tc_fail(tc_list[11],'test_case_failure_message')    
          
    ################################################################################
    st.banner("Step20: Doing REST POST operation to add all VRRP config via single url")
    ################################################################################
    ocdata_dut1 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid_list[0],"config":{"virtual-router-id":vrid_list[0],"virtual-address":[vip_list[0]],"priority":vrrp_priority_list_dut1[0],"preempt":bool(1),"advertisement-interval":1,"openconfig-interfaces-ext:version":3},"openconfig-interfaces-ext:vrrp-track":{"vrrp-track-interface":[{"track-intf":data.d1d4_ports[0],"config":{"track-intf":data.d1d4_ports[0],"priority-increment":2}}]}}]}
    ocdata_ipv6_dut1 = {"openconfig-if-ip:vrrp-group":[{"virtual-router-id":vrid_ipv6_list[0],"config":{"virtual-router-id":vrid_ipv6_list[0],"virtual-address":[vip_ipv6_list[0]],"priority":vrrp_priority_list_dut1[0],"preempt":bool(1),"advertisement-interval":1},"openconfig-interfaces-ext:vrrp-track":{"vrrp-track-interface":[{"track-intf":data.d1d4_ports[0],"config":{"track-intf":data.d1d4_ports[0],"priority-increment":2}}]}}]}        
    rest_url_dut1 = rest_urls['vrrp_config_all'].format(vrrp_vlan_intf[0],vrrp_ip_list[0][0])
    rest_url_ipv6_dut1 = rest_urls['vrrpv3_config_all'].format(vrrp_vlan_intf[0],dut1_2_ipv6_list[0])
    st.log(rest_url_dut1)
    st.log(rest_url_ipv6_dut1)    
    response2 = st.rest_create(data.dut1, path=rest_url_dut1, data=ocdata_dut1)
    response3 = st.rest_create(data.dut1, path=rest_url_ipv6_dut1, data=ocdata_ipv6_dut1)
    result1 =verify_rest_response(response2)
    result2 =verify_rest_response(response3)
    if False in [result1,result2]:
        st.error("Failed to configure vrrpv3 through REST API")
        tc_result=False;final_result += 1;
        utils.exec_all(True,[[st.generate_tech_support,data.dut1,'dut1_step20'],[st.generate_tech_support,data.dut2,'dut2_step20']])
        st.report_tc_fail(tc_list[11],'test_case_failure_message')    
    
    st.wait(20)    
    ################################################################################
    st.banner("Step21: Doing REST GET operation to validate show vrrp ")
    ################################################################################    
    result1 =vrrp_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_list[0],vip=vip_list[0],ip=vrrp_ip_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    result2 =vrrpv3_rest_get_status(data.dut1,vlan=vrrp_vlan_intf[0],vrid=vrid_ipv6_list[0],vip=vip_ipv6_list[0],ipv6=dut1_2_ipv6_list[0],dut1_prio=vrrp_priority_list_dut1[0],dut2_prio=vrrp_priority_list_dut2[0],vrrp_state=2,version=3,preempt_value=True,advt_int=1)
    if False in [result1,result2]:
        st.error("Failed to validate show vrrp output through REST GET API")
        tc_result=False;final_result += 1;
        st.report_tc_fail(tc_list[11],'test_case_failure_message')
    
    if tc_result is True:
        st.report_tc_pass(tc_list[11],'tc_passed')
    
    #################################################################################
    #   REST API Testing Ends
    #################################################################################
    run_traffic(action='stop')
    if final_result != 0:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')
        
def vrrp_rest_get_status(dut,vlan,vrid,vip,ip,dut1_prio,dut2_prio,vrrp_state,version,preempt_value,advt_int, **kwargs):
    st.log('Validating REST API GET operation to verify VRRP Master/Backup election')
    rest_url_read = "/restconf/data/openconfig-interfaces:interfaces/interface={}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address={}/vrrp/vrrp-group={}".format(vlan,ip[0],vrid)
    st.log(rest_url_read)
    response2 = st.rest_read(dut, rest_url_read)
    st.log(response2)
    result1 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:state'])# VRRP state
    result2 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['priority'])# VRRP priority
    result3 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:version'])# VRRP Version
    result4 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['virtual-address'][0])# VRRP Virtual IP
    result5 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['advertisement-interval'])# VRRP Advertisement interval
    result6 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['preempt'])# VRRP Preemption
    result7 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['virtual-router-id'])# VRRP VRID
    
    st.log("VRRP state is - {}".format(result1))    
    st.log("VRRP priority is - {}".format(result2))
    st.log("VRRP Version is - {}".format(result3))
    st.log("VRRP Virtual IP is - {}".format(result4))
    st.log("VRRP Advertisement interval is - {}".format(result5))
    st.log("VRRP Preemption is - {}".format(result6))
    st.log("VRRP VRID is - {}".format(result7))
    if  result1 != str(vrrp_state) or result2 != str(dut1_prio) or result3 != str(version) or result4 !=str(vip) or result5 !=str(advt_int) or result6 !=str(preempt_value) or result7 !=str(vrid):
        st.error("Verification of VRRP Master/Backup election failed through REST API")
        return False
    else:
        st.log('Verification Passed')
    return True

def vrrpv3_rest_get_status(dut,vlan,vrid,vip,ipv6,dut1_prio,dut2_prio,vrrp_state,version,preempt_value,advt_int, **kwargs):
    st.log('Validating REST API GET operation to verify VRRPv3 Master/Backup election')
    rest_url_read = "/restconf/data/openconfig-interfaces:interfaces/interface={}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address={}/vrrp/vrrp-group={}".format(vlan,ipv6,vrid)
    st.log(rest_url_read)
    response2 = st.rest_read(dut, rest_url_read)
    st.log(response2)
    result1 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:state'])# VRRP state
    result2 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['priority'])# VRRP priority
    result3 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['openconfig-interfaces-ext:version'])# VRRP Version
    result4 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['virtual-address'][0])# VRRP Virtual IP
    result5 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['advertisement-interval'])# VRRP Advertisement interval
    result6 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['state']['preempt'])# VRRP Preemption
    result7 =str(response2['output']['openconfig-if-ip:vrrp-group'][0]['virtual-router-id'])# VRRP VRID
    
    st.log("VRRP state is - {}".format(result1))    
    st.log("VRRP priority is - {}".format(result2))
    st.log("VRRP Version is - {}".format(result3))
    st.log("VRRP Virtual IP is - {}".format(result4))
    st.log("VRRP Advertisement interval is - {}".format(result5))
    st.log("VRRP Preemption is - {}".format(result6))
    st.log("VRRP VRID is - {}".format(result7))
    if  result1 != str(vrrp_state) or result2 != str(dut1_prio) or result3 != str(version) or result4 !=str(vip) or result5 !=str(advt_int) or result6 !=str(preempt_value) or result7 !=str(vrid):
        st.error("Verification of VRRP Master/Backup election failed through REST API")
        return False
    else:
        st.log('Verification Passed')
    return True

def verify_rest_response(response,**kwargs):
    #st.log('Validating REST API status ')
    if not response["status"] in [200, 204, 201]:
        st.log("Failed to config/delete via REST API")
        return False
    else:
        st.log('REST API config/delete passed')
        return True
                 
