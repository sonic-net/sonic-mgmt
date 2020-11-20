##############################################################################
#Script Title : VRRPv2 over VRF
#Author       : Raghukumar Rampur
#Mail-id      : raghukumar.thimmareddy@broadcom.com
###############################################################################

import pytest
from spytest import st, tgapi
from spytest.tgen.tg import tgen_obj_dict

from vrrp_vars_vrf import *
from vrrp_vars_vrf import data
from vrrp_utils_vrf import *
import apis.system.basic as basic_api


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
        st.error("Either Port-channel/BGP sessions did not come up in module config")
        vrrp_base_deconfig()
        pytest.skip()
    yield
    vrrp_base_deconfig()

def test_vrrp2vrf_func_001(prologue_epilogue):
    
    tc_list = ["FtOpSoRoVrrpvrfFn001","FtOpSoRoVrrpvrfFn002","FtOpSoRoVrrpvrfFn003","FtOpSoRoVrrpvrfFn004","FtOpSoRoVrrpvrfFn005"]
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
           "checking vmac {} in backup mac table".format(vrid_list[0],data.dut1,vmac_list[0]))
    ############################################################

    result,err = check_mac(data.dut2,vrrp_vlans,vmac_list,[lag_intf_list[1]]*len(vrrp_vlans))
    if result is False:
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T4 : Disable/Enable VRRP sessions {} on dut1(Master)".format(vrid_list[0]))
    ############################################################
    for vrid,vlan,vip,prio,vmac in zip(vrid_list,vrrp_vlan_intf,
                                       vip_list,vrrp_priority_list_dut1,
                                       vmac_list_1):
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
           "checking vmac {} in backup mac table".format(vrid_list[0],data.dut1,vmac_list[0]))
    ############################################################

    result,err = check_mac(data.dut2,vrrp_vlans,vmac_list,[lag_intf_list[1]]*len(vrrp_vlans))
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

    result = check_mac(data.dut3,vlan_list,vmac_list,lag_intf_list)
    if result is False:
        err = "Testcase: {} On DUT3 Vmac {} not learnt on Vlan {} Interface {}".format(tc_list[1],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    st.log("Verify Vmac {} not learnt on Vlan {} pointing to Backup(dut2) interface {}".format(vmac_list[0],vlan_list[0],lag_intf_list[1]))

    result = check_mac(data.dut3,vlan_list,vmac_list,lag_intf_list[1])
    if result is True:
        err = "Testcase: {} On DUT3 Vmac {} learnt on Vlan {} Interface {} pointing to backup".format(tc_list[3],vmac_list[0],vlan_list[0],lag_intf_list[0])
        failMsg(err);debug_vrrp(); err_list.append(err); tc_result = False

    ###########################################################
    hdrMsg("Step T8: Ping to all Virtual IPs {} from backup dut2 and verify VIP is installed in "
           "routing table with /32 subnet mask only on master".format(vip_list[0]))
    ############################################################

    for vip,vrid in zip(vip_list,vrid_list):
        result = ip_api.ping(data.dut2,vip,interface=vrrp_vrf,count = 2)
        if result is False:
            err = "Testcase {} Ping to VIP {} failed from backup dut dut2".format(tc_list[2],vip)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut1, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4',vrf_name=vrrp_vrf)
        if result is False:
            err = "Testcase {} VIP {}/32 not installed in dut1(Master)routing table".format(tc_list[2],vip)
            failMsg(err);debug_vrrp();err_list.append(err);tc_result = False

        result = ip_api.verify_ip_route(data.dut2, ip_address="{}/32".format(vip),interface='vrrp.{}'.format(vrid), family='ipv4',vrf_name=vrrp_vrf)
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


def test_vrrp2vrf_func_003(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpvrfFn009","FtOpSoRoVrrpvrfFn010","FtOpSoRoVrrpvrfFn011","FtOpSoRoVrrpvrfFn012"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary='no')
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

    result = verify_vrrp(summary='no')
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

    result = verify_vrrp(summary='no')
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



def test_vrrp2vrf_func_004(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpvrfFn013","FtOpSoRoVrrpvrfFn014"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Verify VRRP Master/Backup election for {} configured sessions".format(vrrp_sessions))
    ############################################################

    result = verify_vrrp(summary='no')
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
           " becomes Master again for sessions {}".format(lag_id_list[0],vrid_list[0]))
    ############################################################

    port_api.noshutdown(data.dut1,data.d1d3_ports)
    for vrid,vlan,vmac,vip in zip(vrid_list,vrrp_vlan_intf,vmac_list_1,vip_list):
        result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2,skip_backup_check='yes')
        if result is False:
            err = "Testcase {} After port no-shutdown on dut1, dut1 didnot become Master again for VRRP sessions".format(vrid_list[0])
            failMsg(err);debug_vrrp(); err_list.append(err);tc_result = False

    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


###########################################################################################################################################


def test_vrrp2vrf_func_002(prologue_epilogue):
    tc_list = ["FtOpSoRoVrrpvrfFn006","FtOpSoRoVrrpvrfFn007","FtOpSoRoVrrpvrfFn008"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step T1 : Configure Virtual IP {} for vrid {} same as that of vrid {} and verify Cli gets "
           "rejected".format(vip_list[0],'100',vrid_list[0]))
    ############################################################
    result =vrrp.configure_vrrp(data.dut1,vrid='100',interface=dut1_vlan_intf[1],vip=vip_list[0],enable='',skip_error=True)

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
    pkts_captured = data.tg1.tg_packet_stats(port_handle=data.tg_handles[0], format='var',output_type='hex')
    capture_result = tgapi.validate_packet_capture(tg_type=data.tg1.tg_type, pkt_dict=pkts_captured,
                                             offset_list=[0, 26],
                                             value_list=['01:00:5E:00:00:12',vrrp_ip_list[0][0]])

    if not capture_result:
        err = "Testcase {} VRRP advertisement not using primary IP {} as source".format(tc_list[0],vrrp_ip_list[0][0])
        failMsg(err);debug_vrrp();tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Step T7 :  Delete secondary ip and verify VRRP elections happens on dut1 and dut2 ")
    ############################################################
    st.log("\n#### Remove secondary ip as Virtual-IP config first ###\n")
    dict1 = {'vrid': vrid_list[0], 'vip': vrrp_sec_ip_list[0], 'interface': vrrp_vlan_intf[0], 'config': 'no' }
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrrp.configure_vrrp, [dict1, dict1])

    #st.log("\n##### Delete secondary IP {} from {}  #####\n".format(vrrp_sec_ip_list[0],vrrp_vlan_intf[0]))
    #ip_api.delete_ip_interface(data.dut1,vrrp_vlan_intf[0],vrrp_sec_ip_list[0],30,is_secondary_ip='yes')

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


