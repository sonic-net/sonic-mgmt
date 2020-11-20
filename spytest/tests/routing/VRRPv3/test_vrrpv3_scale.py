##############################################################################
#Script Title : VRRPv3 Scale Test
#Author       : Raghukumar Rampur
#Mail-id      :
###############################################################################
import pytest

from spytest import st
from spytest.tgen.tg import tgen_obj_dict

from vrrpv3_scale_vars import *
from vrrpv3_scale_vars import data
from vrrpv3_utils_scale import *
from apis.system import port
import apis.system.basic as basic_api
import apis.system.reboot as reboot_api

def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D3:3", "D2D3:3", "D1D4:3","D2D4:3","D3T1:1","D4T1:1")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    for dut in vars.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d3_ports = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3]
    data.d2d3_ports = [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d3d1_ports = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3]
    data.d4d1_ports = [vars.D4D1P1,vars.D4D1P2,vars.D4D1P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]
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
        data.delay_factor = 3
    else:
        data.delay_factor = 1


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    print_topology()
    result = vrrpv3_scalebase_config()
    if result is False:
        st.error("Either Port-channel/BGP sessions did not come up in module config")
        pytest.skip()
    yield
    vrrpv3_scalebase_deconfig()

def test_vrrpv3_scale_001(prologue_epilogue):
    #tc_list = ["FtOpSoRoVrrpv3Fn054","FtOpSoRoVrrpv3Fn055","FtOpSoRoVrrpv3Fn056"]
    tc_result = True ;err_list=[]
    ###########################################################
    hdrMsg("Step01 : Verify VRRP Master/Backup election for all {} configured sessions".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary="yes")
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    result =vrrp.configure_vrrp(data.dut1, vrid='129',interface='Vlan8', config="yes",enable='',skip_error=True,scale_instance_error=1)
    expected_err ="Error"
    if expected_err not in str(result):
        err = "VRRP instance 129 is accepted but Max number of VRRP instances supported is 128 "
        st.error(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Start Traffic for VRRP instance scale config")
    ###########################################################
    #data.tg1.tg_traffic_control(action='run', stream_handle=data.stream_handles.values())
    run_traffic()

    ###########################################################
    hdrMsg("Step02 : Verify Traffic for scale config for all VRID")
    ############################################################
    result = verify_tg_traffic_rate(data.tg1,data.tg2,data.tgd3_ports,data.tgd4_ports)
    if result is False:
        err = "Traffic check failed for configure VRRP {} and flap Vlan".format(vrrp_ip_list[0][0])
        st.error(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Stop Traffic for VRRP instance scale config")
    ###########################################################
    #data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_handles.values())
    run_traffic(action='stop')
    ###########################################################
    hdrMsg("Step03 : Delete/Configure VRRP sessions {} on dut1(Master) and verify vrrp master backup role".format(vrid_list[0:int(vrrp_sessions/2)]))
    ############################################################
    for vrid,vlan,vip,prio,vmac in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],
                                       vip_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],
                                       vmac_list_1[0:int(vrrp_sessions/2)]):
        if vrid - (int(vrrp_sessions/2)) == -1 or vrid - (int(vrrp_sessions/2)) == 0 or vrid - (int(vrrp_sessions/2)) == 1:
            st.log(">>>> Delete/Configur VRRP session {} <<<<<".format(vrid))
            vrrp.configure_vrrp(data.dut1, vrid=vrid, interface=vlan, config="no",disable='')
            vrrp.configure_vrrp(data.dut1, vrid=vrid, vip=vip, interface=vlan, priority=prio, config="yes",enable='')
            vrrp.configure_vrrp(data.dut1,vrid=vrid,interface=vlan,version=3)

    for vrid,vlan,vip,prio,vmac in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],
                                       vip_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],
                                       vmac_list_1[0:int(vrrp_sessions/2)]):
        if vrid - (int(vrrp_sessions/2)) == -1 or vrid - (int(vrrp_sessions/2)) == 0 or vrid - (int(vrrp_sessions/2)) == 1:
            st.log("Verify dut1 elected as VRRP Master for VRID {} ".format(vrid))
            result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut1,backup_dut=data.dut2)
            if result is False:
                err = "dut1 not elected as VRRP Master for VRID {}".format(vrid)
                st.error(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Step04 : Shutdown/No-shutdown VRRP enabled LAG member port in master node dut1 and check new vrrp role")
    ############################################################
    port.shutdown(data.dut1,data.d1d3_ports)

    for vrid,vlan,vip,prio,vmac in zip(vrid_list[0:int(vrrp_sessions/2)],vrrp_vlan_intf[0:int(vrrp_sessions/2)],
                                       vip_list[0:int(vrrp_sessions/2)],vrrp_priority_list_dut1[0:int(vrrp_sessions/2)],
                                       vmac_list_1[0:int(vrrp_sessions/2)]):
        if vrid - (int(vrrp_sessions/2)) == -2 or vrid - (int(vrrp_sessions/2)) == -1 or vrid - (int(vrrp_sessions/2)) == 0:
            st.log("Verify dut2 elected as VRRP Master for VRID {} ".format(vrid))
            result =verify_master_backup(vrid,vlan,vmac,vip,master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
            if result is False:
                err = "dut2 not elected as VRRP Master for VRID {}".format(vrid)
                st.error(err);err_list.append(err);tc_result = False

    for vrid,intf,vmac,vip in zip(vrid_list[int(vrrp_sessions/2):],dut1_vlan_intf[int(vrrp_sessions/2):vrrp_sessions],vmac_list_1[int(vrrp_sessions/2):],vip_list[int(vrrp_sessions/2):]):
        if vrid - (int(vrrp_sessions/2)) == 1 or vrid - (int(vrrp_sessions/2)) == 2 or vrid - vrrp_sessions == 0:
            st.log("Verify dut2 elected as VRRP Master for VRID {} ".format(vrid))
            result =verify_master_backup(vrid,intf,vmac,vip,master_dut=data.dut2,backup_dut=data.dut1,skip_backup_check='yes')
            if result is False:
                err = "dut1 not elected as VRRP Master for VRID {}".format(vrid)
                st.error(err);err_list.append(err);tc_result = False

    ###########################################################
    hdrMsg("Start Traffic for VRRP instance scale config after old master is down")
    ###########################################################
    #data.tg1.tg_traffic_control(action='run', stream_handle=data.stream_handles.values())
    run_traffic()
    ###########################################################
    hdrMsg("Step05 : Verify Traffic for scale VRRP instances with new VRRP master ")
    ############################################################
    result = verify_tg_traffic_rate(data.tg1,data.tg2,data.tgd3_ports,data.tgd4_ports)
    if result is False:
        err = "Traffic check failed with after delete/configure VRRP {} and flap Vlan".format(vrrp_ip_list[0][0])
        st.error(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Stop Traffic for VRRP instance scale config after after old master is down")
    ###########################################################
    #data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_handles.values())
    run_traffic(action='stop')

    ###########################################################
    hdrMsg("No-shutdown VRRP enabled LAG member port in dut1")
    ############################################################
    port.noshutdown(data.dut1,data.d1d3_ports)
    ###########################################################################################
    hdrMsg("Step06: Config save and fast boot DUT" )
    ###########################################################################################
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1,shell='vtysh')
    st.reboot(data.dut1,'fast')

    ###########################################################
    hdrMsg("Step07 : Verify VRRP Master/Backup election for all {} configured sessions after dut1 fast reload".format(vrrp_sessions))
    ############################################################
    result = verify_vrrp(summary="yes",retry_count=20)
    if result is False:
        err = "VRRP Master/Backup election is incorrect for one or more VRRP sessions"
        st.report_fail('test_case_failure_message', err)

    ###########################################################
    hdrMsg("Start Traffic for VRRP instance scale config after dut1 fast reload")
    ###########################################################
    #data.tg1.tg_traffic_control(action='run', stream_handle=data.stream_handles.values())
    run_traffic()
    ###########################################################
    hdrMsg("Step08 : Verify Traffic for scale VRRP instances after dut1 fast reload ")
    ############################################################
    result = verify_tg_traffic_rate(data.tg1,data.tg2,data.tgd3_ports,data.tgd4_ports)
    if result is False:
        err = "Traffic check failed with after delete/configure VRRP {} and flap Vlan".format(vrrp_ip_list[0][0])
        st.error(err);tc_result=False;err_list.append(err)

    ###########################################################
    hdrMsg("Stop Traffic for VRRP instance scale config after after dut1 fast reload")
    ###########################################################
    #data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_handles.values())
    run_traffic(action='stop')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


