##############################################################################
#Script Title : VRRPv2
#Author       : Sooriya/Naveen Nagaraju
#Mail-id      : sooriya.gajendrababu@broadcom.com
###############################################################################

import pytest
from spytest import st,utils
from spytest.tgen.tg import tgen_obj_dict

from vrrp_vars import *
from vrrp_vars import data
from vrrp_utils import *
import apis.system.basic as basic_api
import apis.system.reboot as reboot_api


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
    result = vrrp_base_config()
    if result is False:
        st.report_fail("module_config_verification_failed")
    yield
    vrrp_base_deconfig()

def test_vrrp_func_001(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn003","FtOpSoRoVrrpFn004","FtOpSoRoVrrpFn005","FtOpSoRoVrrpFn007","FtOpSoRoVrrpFn008"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp()
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    ###########################################################
    hdrMsg("Step T2 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP by "
           "checking vmac {} in backup mac table".format(vrid_list[0:int(vrrp_sessions/2)],data.dut1,vmac_list[0:int(vrrp_sessions/2)]))
    ############################################################

    result,err = check_mac(data.dut2,vrrp_vlans[0:int(vrrp_sessions/2)],vmac_list[0:int(vrrp_sessions/2)],[lag_intf_list[1]]*len(vrrp_vlans[0:int(vrrp_sessions/2)]))
    if result is False:
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T3 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP by "
           "checking vmac {} in backup mac table".format(vrid_list[int(vrrp_sessions/2):],data.dut1,vmac_list[int(vrrp_sessions/2):]))
    ############################################################

    result,err = check_mac(data.dut1,vrrp_vlans[int(vrrp_sessions/2):],vmac_list[int(vrrp_sessions/2):],[lag_intf_list[0]]*len(vrrp_vlans[int(vrrp_sessions/2):]))
    if result is False:
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T4 : Disable/Enable VRRP sessions {} on dut1(Master)".format(vrid_list[0:int(vrrp_sessions/2)]))
    ############################################################
    for vrid,vlan,vip,prio,vmac in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],
                                       vip_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],
                                       vmac_list_1[0:int(vrrp_sessions/2)]):
        st.log(">>>> Disable/Enable VRRP session {} <<<<<".format(vrid))
        vrrp.configure_vrrp(data.dut1, vrid=vrid, interface=vlan, config="no",disable='')
        vrrp.configure_vrrp(data.dut1, vrid=vrid, vip=vip, interface=vlan, priority=prio, config="yes",enable='')
        st.log("\nVerify dut1 elected as VRRP Master for VRID {} \n".format(vrid))
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2)
        if result is False:
            err = "Testcase {} dut1 not elected as VRRP Master for VRID {}".format(tc_list[0],vrid)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T5 : For VRIDs {} Verify Master dut {} sent out Gratuitous ARP after enabling vrrp by "
           "checking vmac {} in backup mac table".format(vrid_list[0:int(vrrp_sessions/2)],data.dut1,vmac_list[0:int(vrrp_sessions/2)]))
    ############################################################

    result,err = check_mac(data.dut2,vrrp_vlans[0:int(vrrp_sessions/2)],vmac_list[0:int(vrrp_sessions/2)],[lag_intf_list[1]]*len(vrrp_vlans[0:int(vrrp_sessions/2)]))
    if result is False:
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T6 : Trigger ARP request for VIP {}  and {} from TG".format(vip_list[0],vip_list[int(vrrp_sessions/2)]))
    ############################################################

    result1 = data.tg1.tg_arp_control(handle=data.host_handles['vrrp_host_{}'.format(vrid_list[0])], arp_target='all')
    result2 = data.tg1.tg_arp_control(handle=data.host_handles['vrrp_host_{}'.format(vrid_list[int(vrrp_sessions/2)])], arp_target='all')

    if result1['status'] == '0' or result2['status'] == '0':
        err = "Testcase: {} ARP resolve failed in TGEN".format(tc_list[1])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T7 : Verify only Master replied for ARP request by checking VMAC on dut3 pointing to Master dut")
    ############################################################

    st.log("Verify Vmac {} learnt on Vlan {} pointing to Master(dut1) interface {}".format(vmac_list[0],vlan_list[0],lag_intf_list[0]))

    result = check_mac(data.dut3,vlan_list[0],vmac_list[0],lag_intf_list[0])
    if result is False:
        err = "Testcase: {} On DUT3 Vmac {} not learnt on Vlan {} Interface {}".format(tc_list[1],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    st.log("Verify Vmac {} not learnt on Vlan {} pointing to Backup(dut2) interface {}".format(vmac_list[0],vlan_list[0],lag_intf_list[1]))

    result = check_mac(data.dut3,vlan_list[0],vmac_list[0],lag_intf_list[1])
    if result is True:
        err = "Testcase: {} On DUT3 Vmac {} learnt on Vlan {} Interface {} pointing to backup".format(tc_list[3],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    st.log("Verify Vmac {} learnt on Vlan {} pointing to Master(dut2) interface {}".format(vmac_list[int(vrrp_sessions/2)], vlan_list[int(vrrp_sessions/2)],
                                                                                           lag_intf_list[1]))
    result = check_mac(data.dut3, vlan_list[int(vrrp_sessions/2)], vmac_list[int(vrrp_sessions/2)], lag_intf_list[1])
    if result is False:
        err = "Testcase: {} On DUT3 Vmac {} not learnt on Vlan {} Interface {} ".format(tc_list[1],vmac_list[int(vrrp_sessions/2)],vlan_list[int(vrrp_sessions/2)],lag_intf_list[1])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False


    st.log("Verify Vmac {} not learnt on Vlan {} pointing to Backup(dut1) interface {}".format(vmac_list[int(vrrp_sessions/2)], vlan_list[int(vrrp_sessions/2)],
                                                                                           lag_intf_list[0]))
    result = check_mac(data.dut3, vlan_list[int(vrrp_sessions/2)], vmac_list[int(vrrp_sessions/2)], lag_intf_list[0])
    if result is True:
        err = "Testcase: {} On DUT3 Vmac {} learnt on Vlan {} Interface {} pointing to backup ".format(tc_list[3],vmac_list[int(vrrp_sessions/2)],vlan_list[int(vrrp_sessions/2)],lag_intf_list[1])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False


    ###########################################################
    hdrMsg("Step T8: Ping to all Virtual IPs {} from backup dut2 and verify VIP is installed in "
           "routing table with /32 subnet mask only on master".format(vip_list[0:int(vrrp_sessions/2)]))
    ############################################################

    for vip,vrid in zip(vip_list[0:int(vrrp_sessions/2)],vrid_list[0:int(vrrp_sessions/2)]):
        result = ip_api.ping(data.dut2,vip)
        if result is False:
            err = "Testcase {} Ping to VIP {} failed from backup dut dut2".format(tc_list[2],vip)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut1, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4')
        if result is False:
            err = "Testcase {} VIP {}/32 not installed in dut1(Master)routing table".format(tc_list[2],vip)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut2, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4')
        if result is True:
            err = "Testcase {} VIP {}/32  should not be installed in dut2(Backup)routing table".format(tc_list[4],vip)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T9:Verify Traffic gets forwarded for all VRRP sessions configured")
    ###########################################################
    run_traffic()
    result = verify_tg_traffic_rate()
    if result is False:
        err = "Testcase {} data traffic not forwarded for VRIDs {}".format(tc_list[0],vrid_list)
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False
    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


###########################################################################################################################################


def test_vrrp_func_003(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn001","FtOpSoRoVrrpFn002","FtOpSoRoVrrpFn006","FtOpSoRoVrrpFn009"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        debug_vrrp()
        st.report_fail('test_case_failure_message', err)


    ###########################################################
    hdrMsg("Step T2 : Change the advertisement interval on dut2 (Backup) - {} for VRRP session {})".format(data.dut2,vrid_list[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step T3 : Verify the advertisement interval is set to 2 seconds on dut2 (Backup) - {} for VRRP session {})".format(data.dut2,vrid_list[0]))
    ############################################################

    vrrp.verify_vrrp(data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)
    run_traffic()
    st.wait(2)

    ###########################################################
    hdrMsg("Step T4:Verify for VRRP sessions {} ,Master DUT {} forwards data traffic".format(vrid_list[0:int(vrrp_sessions/2)], data.dut1))
    ###########################################################
    result = verify_tg_traffic_rate(src_tg_obj=data.tg1,dest_tg_obj=data.tg2,src_port=data.tgd3_ports,dest_port=data.tgd4_ports)

    if result is False:
        err = "Testcase {} Master DUT {} not forwarding data traffic for VRIDs {}".format(tc_list[0], data.dut1,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp();  err_list.append(err); tc_result = False


    ###########################################################
    hdrMsg("Step T5 : Change the advertisement interval on dut1 (Master) - {} for VRRP session {} to 2 as well)".format(data.dut1,vrid_list[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], adv_interval=2)

    ###########################################################
    hdrMsg("Step T6 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err);debug_vrrp(); err_list.append(err);  tc_result = False

    ###########################################################
    hdrMsg("Step T7 : Revert back the advertisement interval on both the nodes to 1 seconds")
    ############################################################
    dict1 = {'vrid': vrid_list[0],  'interface': dut1_vlan_intf[0],'adv_interval':1}
    parallel.exec_parallel(True,[data.dut1,data.dut2],vrrp.configure_vrrp,[dict1,dict1])

    ###########################################################
    hdrMsg("Step T8 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err);debug_vrrp();  err_list.append(err);  tc_result = False


    ###########################################################
    hdrMsg("Step T9 : Set the priority on the backup to higher with preemption mode set to false on {} session".format(vrid_list[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], preempt="disable",config ="no")
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], priority = 230)

    ###########################################################
    hdrMsg("Step T10 : Verify VRRP Backup remains in backup state even though it has high priority for the {} session".format(vrid_list[0]))
    ############################################################

    result = vrrp.verify_vrrp(data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio = 230,preempt="disabled")
    if result is False:
        err = "Testcase {} , after disabling preempt on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[1],data.dut2,vrid_list[0])
        failMsg(err);debug_vrrp();  err_list.append(err);  tc_result = False

    result = verify_tg_traffic_rate(src_tg_obj=data.tg1,dest_tg_obj=data.tg2,src_port=data.tgd3_ports,dest_port=data.tgd4_ports)

    if result is False:
        err = "Testcase {} Master DUT {} not forwarding data traffic for VRIDs {}".format(tc_list[0], data.dut1,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp();
        err_list.append(err);
        tc_result = False
    ###########################################################
    hdrMsg("Step T11 : Enable the preempt and verify the backup takes over the master on {} session".format(vrid_list[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], preempt="enable")
    st.wait(3)
    ###########################################################
    hdrMsg("Step T12:Verify for VRRP sessions {} ,Master DUT {} forwards data traffic".format(vrid_list[int(vrrp_sessions/2):],data.dut2))
    ###########################################################
    result = verify_tg_traffic_rate(src_tg_obj=data.tg1,dest_tg_obj=data.tg2,src_port=data.tgd3_ports,dest_port=data.tgd4_ports)

    if result is False:
        err = "Testcase {} Master DUT {} not forwarding data traffic for VRIDs {}".format(tc_list[0], data.dut2,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp();  err_list.append(err);  tc_result = False

    run_traffic(action='stop')
    revert_vrrp()
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')



def test_vrrp_func_004(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn013","FtOpSoRoVrrpFn015"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    ###########################################################
    hdrMsg("Step T2 : Start Traffic for all configured VRRP sessions and verify Trafficgets forwarded by VRRP Masters")
    ############################################################

    run_traffic()

    result =verify_tg_traffic_rate()
    if result is False:
        err = "Testcase {} Traffic not forwarded for all VRRP Masters".format(tc_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T3 : Shutdown all member ports of LAG {} on dut1 connected to dut3(switch) and "
           "verify dut2 becomes Master for all sessions".format(lag_id_list[0]))
    ############################################################

    port_api.shutdown(data.dut1,data.d1d3_ports)

    for vrid,vlan,vmac,vip in zip(vrid_list,vrrp_vlan_intf,vmac_list_1,vip_list):
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
        if result is False:
            err = "Testcase {} After port shutdown on dut1, dut2 didnot become Master for all VRRP sessions"
            failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T4 : Verify Traffic gets load balanced via new Master for all vrrp sessions")
    ############################################################
    result =verify_tg_traffic_rate()
    if result is False:
        err = "Testcase {} Traffic not forwarded by all VRRP Masters".format(tc_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T5 : No-Shutdown all member ports of LAG {} on dut1 connected to dut3(switch) and verify dut1"
           " becomes Master again for sessions {}".format(lag_id_list[0],vrid_list[0:int(vrrp_sessions/2)]))
    ############################################################

    port_api.noshutdown(data.dut1,data.d1d3_ports)

    for vrid,vlan,vmac,vip in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],vmac_list_1[0:int(vrrp_sessions/2)],vip_list[0:int(vrrp_sessions/2)]):
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2,skip_backup_check='yes')
        if result is False:
            err = "Testcase {} After port no-shutdown on dut1, dut1 didnot become Master again for VRRP sessions".format(vrid_list[0:int(vrrp_sessions/2)])
            failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False


    ###########################################################
    hdrMsg("Step T7 :Change all ports between dut1 <--> dut3, dut2 <---> dut3 to untagged on vlan {}".format(vrrp_vlans[0]))
    ############################################################
    utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[0],'del'],
        [vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[1],'del'],
        [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), [lag_intf_list[0],lag_intf_list[1],data.d3tg_ports],'del']])

    utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut1,vrrp_vlans[0],lag_intf_list[0]],
                          [vlan_api.add_vlan_member, data.dut2,vrrp_vlans[0],lag_intf_list[1]],
                          [vlan_api.add_vlan_member, data.dut3,vrrp_vlans[0],[lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])


    ###########################################################
    hdrMsg("Step T8 :Verify VRRP election happens correctly for untagged Vlan {}".format(vrrp_vlans[0]))
    ############################################################
    result = verify_master_backup(vrid_list[0],vrrp_vlan_intf[0],vmac_list_1[0],vip_list[0],master_dut=data.dut1,backup_dut=data.dut2)
    if result is False:
        err = "Testcase {} VRRP election did not happen after changing port mode from trunk to access".format(tc_list[1])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T9 : Increase the priority on backup node to {} and verify dut2 becomes Master".format(vrrp_priority_list_dut1[0]+1))
    ############################################################

    vrrp.configure_vrrp(data.dut2,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority=vrrp_priority_list_dut1[0]+1)
    result = verify_master_backup(vrid_list[0],vrrp_vlan_intf[0],vmac_list_1[0],vip_list[0],master_dut=data.dut2,backup_dut=data.dut1)
    if result is False:
        err = "Testcase {} VRRP failover did not happen for vrrp session over access port".format(tc_list[1])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T10 : Verify Traffic gets forwarded only for one VRRP session on vlan {}".format(vrrp_vlans[0]))
    ############################################################
    result = verify_tg_traffic_rate(exp_ratio=float(1/float(vrrp_sessions)))
    if result is False:
        err = "Testcase {} untagged traffic failed for vrrp session {} on vlan {}".format(tc_list[1],vrid_list[0],vrrp_vlan_intf[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    st.log("\n #### Revert back vrrp priority on dut2 ### \n")
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut2[0])

    ###########################################################
    hdrMsg("Step T11 :Revert all ports between dut1,dut2 and dut3 back to tagged with all vrrp vlans ")
    ############################################################

    utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut1,vrrp_vlans[0],lag_intf_list[0]],
                          [vlan_api.delete_vlan_member, data.dut2,vrrp_vlans[0],lag_intf_list[1]],
                          [vlan_api.delete_vlan_member, data.dut3,vrrp_vlans[0],[lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])

    utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[0]],
        [vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), lag_intf_list[1]],
        [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(vrrp_vlans[0], vrrp_vlans[-1]), [lag_intf_list[0],lag_intf_list[1],data.d3tg_ports]]])


    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrp_func_005(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn016","FtOpSoRoVrrpFn017"]
    tc_result = True ;err_list=[]

    run_traffic()

    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        debug_vrrp()
        run_traffic(action='stop')
        st.report_fail('test_case_failure_message', err)


    ###########################################################
    hdrMsg("Step T3 : Change the priority to 120 on {} and 100 on {} before tracking the port and verify the same".format(data.dut1,data.dut2))
    ############################################################

    dict1 = {'vrid': vrid_list[0], 'interface': dut1_vlan_intf[0], 'priority': 120}
    dict2 = {'vrid': vrid_list[0], 'interface': dut1_vlan_intf[0], 'priority': 100}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "Testcase {} , after disabling preempt on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[1], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp(); err_list.append(err);
        tc_result = False

    ###########################################################
    hdrMsg("Step T4 : Track 4 ports: {} with priority 10 each, verify the backup take over the Master and current priority is set to 140".format(data.d2d4_ports))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'],track_state_list =['Up','Up','Up','Up'])
    if result is False:
        err = "Testcase {} , after tracking the ports on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format( tc_list[1], data.dut2, vrid_list[0])
        failMsg(err);   debug_vrrp();    err_list.append(err);
        tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(tc_list[0], data.dut1,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T5 : Shutdown the 3 Track ports: {}, verify the backup take over the Master".format(data.d2d4_ports[:3]))
    ############################################################
    port_api.shutdown(data.dut2, data.d2d4_ports[:3])

    result = retry_api(vrrp.verify_vrrp,data.dut1, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "Testcase {} , after shutting down the track the ports,  {} is not the master for the vrrp session {}".format(tc_list[1], data.dut1, vrid_list[0])
        failMsg(err);  debug_vrrp(); err_list.append(err);
        tc_result = False

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=110,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Down','Down','Down','Up'] )
    if result is False:
        err = "Testcase {} , after shutting down the track the ports, {} is not the VRRP Backup for the vrrp session {}".format(tc_list[1], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp(); err_list.append(err);
        tc_result = False


    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(tc_list[0], data.dut1,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T6 : Bring the 3 Track ports up: {}, and make sure the Master is now {}".format(data.d2d4_ports[:3],data.dut2))
    ############################################################
    port_api.noshutdown(data.dut2, data.d2d4_ports[:3])

    result = retry_api(vrrp.verify_vrrp,data.dut1, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=120)
    if result is False:
        err = "Testcase {} ,  {} is not the backup for the vrrp session {}".format(tc_list[1], data.dut1, vrid_list[0])
        failMsg(err); debug_vrrp();  err_list.append(err);  tc_result = False

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=140,track_interface_list=data.d2d4_ports, track_priority_list=['10','10','10','10'], track_state_list =['Up','Up','Up','Up'] )
    if result is False:
        err = "Testcase {} , after bring up the tracked ports, {} is not the VRRP Master for the vrrp session {}".format(tc_list[1], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp();   err_list.append(err);  tc_result = False


    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} After bring back the tracked port, traffic drop is seen on Master DUT {} for VRIDs {}".format(tc_list[0], data.dut2,vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T7 : Delete the tracked 4 ports: {}, verify the backup take over the Master and current priority is set to 100".format(data.d2d4_ports))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=data.d2d4_ports, track_priority_list=[10, 10, 10, 10],config = "no")

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "Testcase {} , after tracking the ports on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[1], data.dut2, vrid_list[0])
        failMsg(err);  debug_vrrp();  err_list.append(err); tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(tc_list[0], data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg( "Step T8 : Similarly now track a port-channel & Vlan: {} & {} with priority 50 , verify the backup take over the Master and current priority is set to 150".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[20,20])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=140, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Up','Up'])
    if result is False:
        err = "Testcase {} , after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(
            tc_list[0], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp();err_list.append(err); tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the tracking the lag interface".format( tc_list[0], data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False


    ###########################################################
    hdrMsg( "Step T9 : Now shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    port_api.shutdown(data.dut2,[lag_intf_list[3]])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['20','20'],track_state_list=['Down','Down'])
    if result is False:
        err = "Testcase {} , after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp(); err_list.append(err);tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after shutting down the tracked the lag interface".format( tc_list[0], data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step T9 : Now do a no shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3], dut2_uplink_vlan_intf[0]))
    ############################################################

    port_api.noshutdown(data.dut2, [lag_intf_list[3]])
    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=[20, 20])

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Master', vrid=vrid_list[0], interface=dut1_vlan_intf[0], current_prio=140, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['20', '20'], track_state_list=['Up', 'Up'])
    if result is False:
        err = "Testcase {} , after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format( tc_list[1], data.dut2, vrid_list[0])
        failMsg(err); debug_vrrp(); err_list.append(err);  tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the no shut on the tracked lag and vlan interface".format(tc_list[0], data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T10 : Delete the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=[10, 10], config="no")

    result = retry_api(vrrp.verify_vrrp,data.dut2, state='Backup', vrid=vrid_list[0], interface=dut1_vlan_intf[0],current_prio=100)
    if result is False:
        err = "Testcase {} , after tracking the ports on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[1], data.dut2, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    result = verify_tg_traffic_rate()

    if result is False:
        err = "Testcase {} Master DUT {} is not forwarding data traffic for VRIDs {} after the track port is configured".format(tc_list[0], data.dut1, vrid_list[0:int(vrrp_sessions/2)])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False


    ###########################################################
    hdrMsg("Step T11 : Try adding the track priority greater than the configured priority or invalid interface , suitable error should be seen")
    ############################################################

    result = vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0],track_interface_list=[lag_intf_list[3]], track_priority_list=[200], config="yes",skip_error=True)
    expected_err = "Error"
    #if expected_err not in str(result):
    #    err = "Testcase {} Track interface with configured priority exceeded 254".format(tc_list[1])
    #    failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;

    result = vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=['Vlan4096'], track_priority_list=[50], config="yes", skip_error=True)
    expected_err = "Error"
    if expected_err not in str(result):
        err = "Testcase {} Track interface with configured priority exceeded 254".format(tc_list[1])
        failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;

    run_traffic(action='stop')
    revert_vrrp()
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrp_func_006(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn014"]
    tc_result = True ;err_list=[]

    ###########################################################
    hdrMsg("Step T1 : Remove the VRRP sessions from the Vlan interface and configure on the physical interface on Dut1 : {} and Dut2 : {} ".format(data.d1d2_ports,data.d2d1_ports))
    ############################################################

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no','disable':''}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1d2_ports[0],vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,data.d2d1_ports[0], vrrp_ip_list[0][1],mask]])


    utils.exec_all(True,[[port_api.noshutdown,data.dut1, data.d1d2_ports],[port_api.noshutdown,data.dut2, data.d2d1_ports]])


    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d1d2_ports[0],'enable':'yes','priority':'200'}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': data.d2d1_ports[0],'enable':'yes','priority':'150'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    ###########################################################
    hdrMsg("Step T2 : Verify the Master/Backup is established as expected based on the priority")
    ############################################################

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0], current_prio=150)
    if result is False:
        err = "Testcase {} , {} expected Backup for session {}, the session is either Master or down".format(tc_list[0], vrid_list[0], data.dut2)
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "Testcase {} , {} expected Master for session {}, the session is either Backup or down".format(tc_list[0], vrid_list[0], data.dut2)
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;

    ###########################################################
    hdrMsg( "Step T3 : Track a port-channel & Vlan: {} & {} with priority 50 , verify the backup take over the Master and current priority is set to 250".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    vrrp.configure_vrrp(data.dut2, vrid=vrid_list[0], interface=data.d2d1_ports[0], track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=[50,50])

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Master', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=250, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Up','Up'])
    if result is False:
        err = "Testcase {} , after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut2, vrid_list[0])
        failMsg(err);debug_vrrp();  err_list.append(err);  tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Backup', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "Testcase {} , after tracking the portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut2, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False;


    ###########################################################
    hdrMsg( "Step T4 : Now shutdown the tracked port-channel and Vlan : {} & {}, verify the backup take over the Master and current priority is set to 100".format(lag_intf_list[3],dut2_uplink_vlan_intf[0]))
    ############################################################

    port_api.shutdown(data.dut2,[lag_intf_list[3]])

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "Testcase {} , after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut2, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "Testcase {} , after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut1, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);  tc_result = False;


    ###########################################################
    hdrMsg( "Step T5 : Flap the physical interface and verify the Master back up is established as expected ")
    ############################################################

    port_api.shutdown(data.dut1, data.d1d2_ports)

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Down', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3], dut2_uplink_vlan_intf[0]], track_priority_list=['50', '50'], track_state_list=['Down', 'Down'])
    if result is False:
        err = "Testcase {} , after bring the VRRP interface down, the session is still not down on the dut: {}".format(
            tc_list[0], data.dut2 )
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Down', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "Testcase {} , after bring the VRRP interface down, the session is still not down on the dut: {}".format(
            tc_list[0], data.dut1 )
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;

    port_api.noshutdown(data.dut1, data.d1d2_ports)

    ###########################################################
    hdrMsg( "Step T6 : Verify the state after flapping the physical interface")
    ############################################################

    result = retry_api(vrrp.verify_vrrp, data.dut2, state='Backup', vrid=vrid_list[0], interface=data.d2d1_ports[0],current_prio=150, track_interface_list=[lag_intf_list[3],dut2_uplink_vlan_intf[0]], track_priority_list=['50','50'],track_state_list=['Down','Down'])
    if result is False:
        err = "Testcase {} , after bring the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut2, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;

    result = retry_api(vrrp.verify_vrrp, data.dut1, state='Master', vrid=vrid_list[0], interface=data.d1d2_ports[0], current_prio=200)
    if result is False:
        err = "Testcase {} , after bringing the tracked portchannel on {} the VRRP Master/Backup election is incorrect for the vrrp session {}".format(tc_list[0], data.dut1, vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);  tc_result = False;


    dict1 = {'vrid': vrid_list[0], 'interface': data.d1d2_ports[0],'disable':'yes','config':'no'}
    dict2 = {'vrid': vrid_list[0], 'interface': data.d2d1_ports[0],'disable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    st.log("\n >>> Revert all phy interface to Vlan interface for VRRP <<<<\n")
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1d2_ports[0], vrrp_ip_list[0][0],mask],
                         [ip_api.delete_ip_interface,data.dut2,data.d2d1_ports[0], vrrp_ip_list[0][1],mask]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,vrrp_vlan_intf[0], vrrp_ip_list[0][0],mask],
                         [ip_api.config_ip_addr_interface,data.dut2,vrrp_vlan_intf[0], vrrp_ip_list[0][1],mask]])

    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0],'enable':'yes','priority':vrrp_priority_list_dut2[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])


    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_vrrp_func_007(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn012"]
    tc_result = True ;err_list=[]

    run_traffic(stream_handle=data.stream_handles['vrrp_{}'.format(vrid_list[0])])

    ######################################################################
    hdrMsg("Step T1 :Configure Interface ip {} of dut1 as VIP for VRID {} on both dut1 and dut2".format(vrrp_ip_list[0][0],vrid_list[0]) )
    #####################################################################
    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'config':'no','vip':vip_list[0]}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'config':'no','vip':vip_list[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'vip':vrrp_ip_list[0][0],'priority':100}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'vip': vrrp_ip_list[0][0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    ######################################################################
    hdrMsg("Step T2 : Verify dut1 will be elected as Master with Priority 255" )
    #####################################################################
    dict1=  {"vrid":vrid_list[0],'interface':vrrp_vlan_intf[0],'state':'Master','config_prio':'255','current_prio':'255','vip':vrrp_ip_list[0][0]}
    dict2 = {"vrid":vrid_list[0],'interface':vrrp_vlan_intf[0],'state':'Backup','vip':vrrp_ip_list[0][0]}
    result = retry_parallel(vrrp.verify_vrrp,[dict1,dict2],[data.dut1,data.dut2])

    if result is False:
        err = "Testcase {} With owner config for VRRP session {} , Master/Backup  election is incorrect".format(tc_list[0],vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);  tc_result = False;

    ######################################################################
    hdrMsg("Step T3 : Disable Pre-emption on dut1 for vrid {} and verify CLI gets rejected".format(vrid_list[0]) )
    #####################################################################

    result = vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],preempt='',config='no',skip_error=True)
    expected_err = "Error"
    if expected_err not in result:
        err = "Testcase {} Enabling pre-emtion on owner VRRP not getting rejected".format(tc_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False;


    ######################################################################
    hdrMsg("Step T4 : Shutdown dut1 lag members and verify dut2 becomes Master for owner vrrp instance" )
    #####################################################################
    port_api.shutdown(data.dut1,data.d1d3_ports)

    result = verify_master_backup(vrid_list[0],vrrp_vlan_intf[0],vmac_list_1[0],vrrp_ip_list[0][0],master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
    if result is False:
        err = "Testcase {} dut2 did not become Master for vrid {} after admin down of dut1 ports".format(tc_list[0],vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False;


    ######################################################################
    hdrMsg("Step T5 : No-Shutdown dut1 lag members and verify dut1 becomes Master and dut2 as Backup for owner vrrp instance" )
    #####################################################################
    port_api.noshutdown(data.dut1,data.d1d3_ports)

    dict1=  {"vrid":vrid_list[0],'interface':vrrp_vlan_intf[0],'state':'Master','config_prio':'255','current_prio':'255','vip':vrrp_ip_list[0][0]}
    dict2 = {"vrid":vrid_list[0],'interface':vrrp_vlan_intf[0],'state':'Backup','vip':vrrp_ip_list[0][0]}
    result = retry_parallel(vrrp.verify_vrrp,[dict1,dict2],[data.dut1,data.dut2])

    if result is False:
        err = "Testcase {} With owner config for VRRP session {} , master/Backup  election is incorrect after admin up ports".format(tc_list[0],vrid_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err);  tc_result = False;

    ######################################################################
    hdrMsg("Step T6 : Verify Traffic gets forwarded for vrrp owner instance" )
    #####################################################################
    result =verify_tg_traffic_rate()
    if result is False:
        err = "Testcase {} Traffic Forwarding failed for vrrp owner instance {}".format(tc_list[0],vrid_list[0])
        failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;


    st.log("\n Revert back vrrp owner configs back  to original \n")
    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'config':'no','vip':vrrp_ip_list[0][0]}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'config':'no','vip':vrrp_ip_list[0][0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    dict1 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'vip':vip_list[0],'priority':vrrp_priority_list_dut1[0]}
    dict2 = {'vrid': vrid_list[0], 'interface': vrrp_vlan_intf[0],'vip': vip_list[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict2])

    run_traffic(stream_handle=data.stream_handles['vrrp_{}'.format(vrid_list[0])],action='stop')

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')



def test_vrrp_func_008(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpFn018","FtOpSoRoVrrpCli002"]
    tc_result = True ;err_list=[]
    run_traffic()
    ##############################################################
    hdrMsg("Step T1: Configure track port,advertisement -interval on vrrp session {}".format(vrid_list[0]))
    ##############################################################
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],
                        track_priority_list=[1])

    ##############################################################
    hdrMsg("Step T2: Verify all configured parameters under show command for vrid {}".format(vrid_list[0]))
    ##############################################################

    result = retry_api(vrrp.verify_vrrp,data.dut1,state='Master',config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],
                         track_priority_list=['1'],vrid=vrid_list[0],interface=vrrp_vlan_intf[0])
    if result is False:
        err ='Testcase: {} VRRP prameters are incorrect for VRID {}'.format(tc_list[1],vrid_list[0])
        failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;

    ##############################################################
    hdrMsg("Step T3: Verify VRRP elections for all configured sessions")
    ##############################################################

    result = verify_vrrp(summary='yes')
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;

    ###########################################################
    hdrMsg("Step T4 : Config save")
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

        result = retry_api(vrrp.verify_vrrp,data.dut1,config_prio=vrrp_priority_list_dut1[0],current_prio=vrrp_priority_list_dut1[0]+1, track_interface_list=[data.d1d4_ports[0]],
                             track_priority_list=['1'],vrid=vrid_list[0],interface=vrrp_vlan_intf[0])
        if result is False:
            err ='Testcase: {} VRRP prameters are incorrect for VRID {} after {}'.format(tc_list[0],vrid_list[0],trigger)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;

        ##############################################################
        hdrMsg("Step: Verify VRRP elections for all configured sessions after {}".format(trigger))
        ##############################################################
        result = verify_vrrp(summary='yes',retry_count=15,delay=3)
        if result is False:
            err = "Testcase {} VRRP Master/Backup election is incorrect for one or more VRRP sessions after {}".format(tc_list[0],trigger)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False;

        ###########################################################
        hdrMsg("Step: Verify the traffic forwarding for all VRRP sessions after {}".format(trigger))
        ############################################################

        result = verify_tg_traffic_rate()
        if result is False:
            err = "Testcase {} Traffic not forwarded for all configured sessions after {}".format(tc_list[0],trigger)
            failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    st.log("Revert VRRP config on dut1")
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=dut1_vlan_intf[0], track_interface_list=[data.d1d4_ports[0]],
                        track_priority_list=[1],config='no')
    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    else:
        st.report_pass('test_case_passed')

###########################################################################################################################################

@pytest.fixture(scope="function")
def vrrp_cleanup_fixture(request,prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP Start###")
    st.log("\n#### Remove Virtual-IP config first ###\n")
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
    st.log("Stop Traffic for VRRP instance {}".format(vrid_list[0]))
    run_traffic(stream_handle=data.stream_handles['vrrp_{}'.format(vrid_list[0])],action='stop')

    hdrMsg("### CLEANUP End####")

def test_vrrp_func_002(vrrp_cleanup_fixture):
    tc_list = ["FtOpSoRoVrrpFn010","FtOpSoRoVrrpFn011","FtOpSoRoVrrpCli001"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Configure Virtual IP {} for vrid {} same as that of {} and verify Cli gets "
           "rejected".format(vip_list[0],vrid_list[1],vrid_list[0]))
    ############################################################
    result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[1],interface=vrrp_vlan_intf[1],vip=vip_list[0],skip_error=True)
    expected_err ="Error"
    if expected_err not in str(result):
        err = "Testcase {} Same VIP {} accepted for two different VRRP sessions ".format(tc_list[1],vip_list[0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
    
    st.log("Start Traffic for VRRP instance {}".format(vrid_list[0]))
    run_traffic(stream_handle=data.stream_handles['vrrp_{}'.format(vrid_list[0])])
    
    ###########################################################
    hdrMsg("Step T2 : Configure secondary ip {} to VRRP  {} on dut1".format(vrrp_sec_ip_list[0],vrrp_vlan_intf[0]))
    ############################################################
    ip_api.config_ip_addr_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ip_list[0],30,is_secondary_ip='yes')
    
    ###########################################################
    hdrMsg("Step T3 : Configure secondary ip {} as Virtual ip for vrrp "
        "session {} on vlan {}".format(vrrp_sec_ip_list[0],vrid_list[0],vrrp_vlan_intf[0]))
    ############################################################
    st.log("Remove old vritual-ip {} first before configuring secondar ip as virtual-ip".format(vip_list[0]))
    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' }
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
    
    st.log("Configure secondary ip address {} as virtual-ip on both DUTs".format(vrrp_sec_ip_list[0]))
    vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority='100')
    dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
    
    ###########################################################
    hdrMsg("Step T4 : Verify secondary ip elected as VIP and vrrp roles on dut1 and dut2")
    ############################################################
        
    result = verify_master_backup(vrid=vrid_list[0],interface=vrrp_vlan_intf[0],vmac=vmac_list_1[0],vip=vrrp_sec_ip_list[0],master_dut=data.dut1,backup_dut=data.dut2)
    if result is False:
        err = "Testcase {} VRRP elections incorrect with secondary ip {} configured as Virtualip ".format(tc_list[0],vrrp_sec_ip_list[0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
    
    result = verify_tg_traffic_rate(data.tg1,data.tg2,data.tgd3_ports,data.tgd4_ports)
    if result is False:
        err = "Testcase {} Traffic check failed with secondary ip {} configured as Virtualip ".format(tc_list[0],vrrp_sec_ip_list[0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
        
    ###########################################################
    hdrMsg("Step T5 : Verify primary ip {} used as  source ip for vrrp advertisements sent out from dut1 master".format(vrrp_ip_list[0][0]))
    ############################################################
    
    data.tg1.tg_packet_control(port_handle=data.tg_handles[0], action='start')
    st.wait(3)
    data.tg1.tg_packet_control(port_handle=data.tg_handles[0], action='stop')
    pkts_captured = data.tg1.tg_packet_stats(port_handle=data.tg_handles[0], format='var')
    capture_result = tgapi.validate_packet_capture(tg_type=data.tg1.tg_type, pkt_dict=pkts_captured,
                                         header_list=['ETH:Destination', 'IP:Source', 'VLAN:ID'],offset_list=[0, 30, 14],
                                         value_list=['01:00:5E:00:00:12',vrrp_ip_list[0][0],str(format(vrrp_vlans[0],'04X'))])
    if not capture_result:
        err = "Testcase {} VRRP advertisement not using primary IP {} as source".format(tc_list[0],vrrp_ip_list[0][0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
        
    ###########################################################
    hdrMsg("Step T7 : Delete secondary ip as VRRP VIP ")
    ############################################################
    st.log("\n#### Remove Virtual-IP config first ###\n")
    dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' }
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
         
    st.log("\n##### Delete secondary IP {} from {}  #####\n".format(vrrp_sec_ip_list[0],vrrp_vlan_intf[0]))
    ip_api.delete_ip_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ip_list[0],30,is_secondary_ip='yes')
        
    st.log("\n#### Configure Virtual IP {} for {} ###\n".format(vip_list[0],vrrp_vlan_intf[0]))
    dict1 = {'vrid': vrid_list[0], 'vip': vip_list[0], 'interface': vrrp_vlan_intf[0] }
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])
    
    result = verify_master_backup(vrid=vrid_list[0], interface=vrrp_vlan_intf[0], vmac=vmac_list_1[0],vip=vip_list[0], master_dut=data.dut1, backup_dut=data.dut2)
    if result is False:
        err = "Testcase {} VRRP elections incorrect after deleting secondary ip {} which is also configured as Virtualip ".format(tc_list[0], vrrp_sec_ip_list[0])
        failMsg(err);debug_vrrp();tc_result = False;err_list.append(err)
             
    ###########################################################
    hdrMsg("Step T8 : Verify Traffic after delete/add primary IP for VRID {} ".format(vrid_list[0]))
    ############################################################
    result = verify_tg_traffic_rate()
    if result is False:
        err = "Testcase {} Traffic check failed with after delete/add primary ip {} ".format(tc_list[0],vrrp_ip_list[0][0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
    
    vrrp.configure_vrrp(data.dut1, vrid=vrid_list[0], interface=vrrp_vlan_intf[0], priority=vrrp_priority_list_dut1[0])
    st.log("Stop Traffic for VRRP instance {}".format(vrid_list[0]))
    run_traffic(stream_handle=data.stream_handles['vrrp_{}'.format(vrid_list[0])],action='stop')
     
    ###########################################################
    hdrMsg("Step T9 : Verify out of range values gets rejected for advertisement interval ")
    ############################################################
    
    for interval in [0,256]:
        result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],adv_interval=interval,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "Testcase {}  {} sec should not be accepted for advertisement interval".format(tc_list[2],interval)
            failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)
     
    ###########################################################
    hdrMsg("Step T10 : Verify out of range values gets rejected for vrrp priority ")
    ############################################################
    
    for prio in [0,255]:
        result =vrrp.configure_vrrp(data.dut1,vrid=vrid_list[0],interface=vrrp_vlan_intf[0],priority=prio,skip_error=True)
        expected_err ="Error"
        if expected_err not in str(result):
            err = "Testcase {}:  {} should not be accepted for vrrp priority".format(tc_list[2],prio)
            failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')
        
    