##############################################################################
#Script Title : PIM-SSM/L3-IGMP
#Author       : Sooriya/Nagappa
#Mail-id      : sooriya.gajendrababu@broadcom.com
###############################################################################

import ast
import json
import pytest
import netaddr as net_addr

from spytest import st, tgapi, utils
from pim_vars import *
from pim_utils import *
import apis.system.basic as basic_api
import apis.system.reboot as reboot_api
import apis.system.interface as intf_api
import apis.routing.bfd as bfd_api
from spytest.utils import filter_and_select


def initialize_topology_vars():
    native_ports = True # since this module supports only CLICK
    vars = st.ensure_min_topology("D1D3:3", "D2D3:2", "D1D4:2", "D2D4:2", "D1D2:1", "D3D4:2", native=native_ports)
    data.dut_list = vars.dut_list
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    utils.exec_all(True, [[bgp_api.enable_docker_routing_config_mode, dut] for dut in data.dut_list])
    utils.exec_all(True, [[reboot_api.config_save, dut] for dut in data.dut_list])
    utils.exec_all(True, [[reboot_api.config_reload, dut] for dut in data.dut_list])
    data.d1d2_ports = [vars.D1D2P1, vars.D1D2P2]
    data.d1d3_ports = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2]
    data.d2d1_ports = [vars.D2D1P1, vars.D2D1P2]
    data.d2d3_ports = [vars.D2D3P1,vars.D2D3P2]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2]
    data.d3d1_ports = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2]
    data.d4d1_ports = [vars.D4D1P1,vars.D4D1P2]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2]
    data.d3d4_ports = [vars.D3D4P1]
    data.d4d3_ports = [vars.D4D3P1]
    data.d1tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.d2tg_ports = [vars.D2T1P1,vars.D2T1P2]
    data.d3tg_ports = [vars.D3T1P1,vars.D3T1P2]
    data.d4tg_ports = [vars.D4T1P1,vars.D4T1P2]
    handles = tgapi.get_handles(vars, [vars.T1D1P1,vars.T1D1P2, vars.T1D2P1, vars.T1D2P2,
                                       vars.T1D3P1, vars.T1D3P2, vars.T1D4P1, vars.T1D4P2])
    data.tg1 = data.tg2 = data.tg3 = data.tg4 = handles["tg1"]
    data.tgd1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tgd2_ports = [vars.T1D2P1, vars.T1D2P2]
    data.tgd3_ports = [vars.T1D3P1, vars.T1D3P2]
    data.tgd4_ports = [vars.T1D4P1, vars.T1D4P2]
    data.tg_d1_handles = [handles["tg_ph_1"], handles["tg_ph_2"]]
    data.tg_d2_handles = [handles["tg_ph_3"], handles["tg_ph_4"]]
    data.tg_d3_handles = [handles["tg_ph_5"], handles["tg_ph_6"]]
    data.tg_d4_handles = [handles["tg_ph_7"], handles["tg_ph_8"]]
    data.tg_handles = data.tg_d1_handles + data.tg_d2_handles + data.tg_d3_handles + data.tg_d4_handles
    data.src_mac = {}
    data.src_mac[data.tg_d1_handles[0]] = '00:00:00:11:11:33'
    data.src_mac[data.tg_d1_handles[1]] = '00:00:00:11:22:33'
    data.src_mac[data.tg_d2_handles[0]] = '00:00:00:11:33:33'
    data.src_mac[data.tg_d2_handles[1]] = '00:00:00:11:44:33'
    data.tech_support_on_fail = True
    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 1
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 0.2


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    result = pim_base_config()
    if result is False:
        debug_pim_failure()
        st.report_fail("module_config_verification_failed")
    yield
    pim_base_deconfig()

@pytest.fixture(scope='function')
def pim_func_003_cleanup(request,prologue_epilogue):

    yield
    hdrMsg("### CLEANUP Start###")
    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='leave')
        send_igmpv3_report(host='R3', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include', vrf=vrf, mode='leave')
    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)

    hdrMsg("### CLEANUP End####")

def test_pim_func_003(pim_func_003_cleanup):
    tc_list=['FtOpSoRoPimFunc003','FtOpSoRoPimFunc004','FtOpSoRoPimFunc005','FtOpSoRoPimFunc007','FtOpSoRoPimFunc008','FtOpSoRoPimFunc036','FtOpSoRoPimFunc038']
    err_list =[]
    tc_result = True
    multicast_traffic(groups=data.ssm_group_list, source='S1')
    multicast_traffic(source='S2', groups=data.ssm_group_list)
    multicast_traffic(vrf=vrf_name, groups=data.ssm_group_list)
    multicast_traffic(source='S2', vrf=vrf_name, groups=data.ssm_group_list)

    tx_stream_list_1_default = [data.stream_handles['{}_S1_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_1_vrf   = [data.stream_handles['{}_S1_{}'.format(group,vrf_name)] for group in data.ssm_group_list]
    tx_stream_list_2_default = [data.stream_handles['{}_S2_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_2_vrf = [data.stream_handles['{}_S2_{}'.format(group,vrf_name)] for group in data.ssm_group_list]

    ##################################################################
    hdrMsg("Step T1: Send IGMPv3 Report from R1 connected to LHR1 (D3) to join groups {} from source {} and {}".format(data.ssm_group_list,data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='join')

    ##################################################################
    hdrMsg("Step T2: Verify IGMP groups/sources table in LHR1")
    ##################################################################
    entry_cnt = data.ssm_groups
    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=data.ssm_group_list*entry_cnt,mode=['INCL']*len(data.ssm_group_list)*entry_cnt,
                                     source_count=['2']*len(data.ssm_group_list)*entry_cnt,version=['3']*len(data.ssm_group_list)*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Group entries not programmed on LHR1')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',interface=[data.d3tg_vlan_intf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf='default')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',interface=[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf=vrf_name)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    ##################################################################
    hdrMsg("Step T3:LHR1: Verify mroute entry gets programmed for all multicast groups with IIF as rpf nexthop interface for Source")
    ##################################################################
    src_list = [data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt+[data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt
    iif_list_lhr1 = [data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt

    result = pim_api.verify_ip_mroute(data.dut3,source=src_list,group=data.ssm_group_list*4,proto=['IGMP']*4*entry_cnt
                                      ,iif=iif_list_lhr1,
                                      oif=[data.d3tg_vlan_intf[0]]*2*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Mroute entries not programmed in LHR1 pointing to FHR1 and FHR2')

    ##################################################################
    hdrMsg("Step T4:LHR1: Verify PIM state on LHR1 node and verify all (S,G) entries are installed")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut3,cmd_type='state',vrf='all',installed=['1']*entry_cnt*4,source=src_list,
                                     group=data.ssm_group_list*4,
                                     iif=iif_list_lhr1,
                                     oif=[[data.d3tg_vlan_intf[0]]]*2*entry_cnt+[[data.d3tg_vlan_intf_vrf[0]]]*2*entry_cnt,flag=[['I']]*entry_cnt*4)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM states are incorrect in LHR1')

    ##################################################################
    hdrMsg("Step T4:LHR1: Verify PIM join is sent to FHR1(D1) and FHR2(D2) on all VRFs")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut3,cmd_type='upstream',vrf='all',source=src_list,group=data.ssm_group_list*4,
                                     iif=iif_list_lhr1,state=['J']*4*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'LHR1 did not send PIM join upstream to FHR1')

    ##################################################################
    hdrMsg("Step T5:FHR1& FHR2: Verify PIM state and verify join is received from LHR1")
    ##################################################################

    dict1 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'oif':[[data.d3d1_vlan_intf[0]]]*entry_cnt+[[data.d3d1_vlan_intf_vrf[0]]]*entry_cnt,'flag':[['J']]*entry_cnt*2}
    dict2 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'oif':[[data.d3d2_lag_intf_1]]*entry_cnt+[[data.d3d2_lag_intf_2]]*entry_cnt,'flag':[['J']]*entry_cnt*2}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR1 or FHR2 node')

    dict1 = {'cmd_type':'join','vrf':'all','source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'interface':[data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt,'state':['JOIN']*2*entry_cnt}
    dict2 = {'cmd_type':'join','vrf':'all','source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'interface':[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt,'state':['JOIN']*2*entry_cnt}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN info incorrect in FHR1 or FHR2 node')

    ##################################################################
    hdrMsg("Step T6:FHR1: Verify Mroute programming on FHR1 node with correct OIFs and IIFs")
    ##################################################################

    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt,'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d2tg_ports[0]]*entry_cnt+[data.d2tg_ports[1]]*entry_cnt,
             'oif':[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt,'vrf':'all',
             'installed':['*']*2*entry_cnt}


    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'OIF/IIF entries incorrect on FHR1 /FHR2')

    ##################################################################
    hdrMsg("Step T7:Verify multicast stream forwarding only from both Sources S1,S2 for multicast groups on default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failed for default-vrf ')


    ##################################################################
    hdrMsg("Step T8:Verify multicast stream forwarding for multicast groups on {} fromboth sources S1 and S2".format(vrf_name))
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1],data.tgd2_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failure for {}'.format(vrf_name))

    ##################################################################
    hdrMsg("Step T9:Send IGMPv3 Leave for all multicast groups on default and user-vrf from R1 connected to LHR1")
    ##################################################################
    st.log("\n Getting initial PRUNE_TX count on LHR1 towards FHR1 \n")
    initial_prune_tx = get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d1_vlan_intf[0],vrf='default')
    initial_prune_tx_vrf = get_packet_count(data.dut3, pkt_type='prune_tx',interface=data.d3d1_vlan_intf_vrf[0],vrf=vrf_name)

    st.log("\n Getting initial PRUNE_TX count towards FHR2 \n")
    initial_prune_tx_1 = get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d2_lag_intf_1,vrf='default')
    initial_prune_tx_vrf_1 = get_packet_count(data.dut3, pkt_type='prune_tx', interface=data.d3d2_lag_intf_2,vrf=vrf_name)

    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include',vrf=vrf, mode='leave')

    ##################################################################
    hdrMsg("Step T10: Verify IGMP source table is empty on LHR1 after sending Leave report from R1")
    ##################################################################

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',return_output='',vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast sources not removed from igmp table on LHR1')


    ##################################################################
    hdrMsg("Step T11: Verify LHR1 sent out PIM prune on interface towards FHR1,FHR2")
    ##################################################################
    st.log("\n Getting  PRUNE_TX count on LHR1 towards FHR1\n")
    final_prune_tx =  get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d1_vlan_intf[0],vrf='default')
    final_prune_tx_vrf = get_packet_count(data.dut3, pkt_type='prune_tx',interface=data.d3d1_vlan_intf_vrf[0],vrf=vrf_name)

    st.log("\n Getting PRUNE_TX count towards FHR2 \n")
    final_prune_tx_1 = get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d2_lag_intf_1,vrf='default')
    final_prune_tx_vrf_1 = get_packet_count(data.dut3, pkt_type='prune_tx', interface=data.d3d2_lag_intf_2,vrf=vrf_name)

    if int(final_prune_tx) == int(initial_prune_tx):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR1')

    if int(final_prune_tx_vrf) == int(initial_prune_tx_vrf):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR1 on user-vrf')

    if int(final_prune_tx_1) == int(initial_prune_tx_1):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR2')

    if int(final_prune_tx_vrf_1) == int(initial_prune_tx_vrf_1):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR2 on user-vrf')

    ##################################################################
    hdrMsg("Step T12: Verify mroute entry gets deleted in LHR1 ")
    ##################################################################
    output = pim_api.verify_ip_mroute(data.dut3,return_output='')
    if len(output) != 0:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Mroute entry not deleted on LHR1 for {},{}'.format(data.ssm_group_list,data.tgd1_ip))

    ##################################################################
    hdrMsg("Step T13: Verify PIM entries gets deleted in LHR1 under pim state")
    ##################################################################

    output = pim_api.verify_pim_show(data.dut3,cmd_type='state',vrf='all',return_output='')
    if len(output) != 0:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','PIM state entries not deleted on LHR1 for {},{}'.format(data.ssm_group_list,data.tgd1_ip))

    ##################################################################
    hdrMsg("Step T14: Verify OIF set to None for all groups in FHR1/FHR2 mroute table")
    ##################################################################

    #dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['none']*2*entry_cnt,
    #         'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
    #         'oif':['none']*2*entry_cnt,'vrf':'all'}

    #dict2 = {'source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['none']*2*entry_cnt,
    #         'iif':[data.d2tg_ports[0]]*entry_cnt+[data.d2tg_ports[1]]*entry_cnt,
    #         'oif':['none']*2*entry_cnt,'vrf':'all'}


    result1 = retry_null_output(pim_api.verify_ip_mroute,data.dut1,vrf='all',return_output='')
    result2 = retry_null_output(pim_api.verify_ip_mroute, data.dut2, vrf='all', return_output='')

    if not result1 or not result2:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'one or more OIFs under mroute table not deleted after receiving PIM-Prune')

    ##################################################################
    hdrMsg("Step T15: Verify Multicast traffic stops forwarding on all VRFs")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio=0,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic did not forward for default-vrf ')

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1],data.tgd2_ports[1]], dest_port=data.tgd3_ports[1],exp_ratio=0,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic did not forward for user-vrf ')

    ##################################################################
    hdrMsg("Step T16: Send IGMPv3 Report from R3 connected to LHR2 (D4) to join groups {} from both sources {} and {}".format(data.ssm_group_list,
                                                                                                                             data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        send_igmpv3_report(host='R3',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='join')

    ##################################################################
    hdrMsg("Step T17: Verify IGMP groups/sources table in LHR2")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='groups',interface=[data.d4tg_ports[0]]*entry_cnt+[data.d4tg_ports[1]]*entry_cnt,
                                     group=data.ssm_group_list*entry_cnt,mode=['INCL']*len(data.ssm_group_list)*entry_cnt,
                                     source_count=['2']*len(data.ssm_group_list)*entry_cnt,version=['3']*len(data.ssm_group_list)*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Group entries not programmed on LHR2')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d4tg_ports[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf='default')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR2')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d4tg_ports[1]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf=vrf_name)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR2')

    ##################################################################
    hdrMsg("Step T18:LHR2: Verify mroute entry gets programmed for all multicast groups with IIF pointing to both FHR1 and FHR2")
    ##################################################################
    src_list = [data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt+[data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt
    iif_list_lhr2 = [data.d4d1_ports[0]]*entry_cnt+[data.d4d2_vlan_intf[0]]*entry_cnt+[data.d4d1_ports[1]]*entry_cnt+[data.d4d2_vlan_intf_vrf[0]]*entry_cnt

    result = pim_api.verify_ip_mroute(data.dut4,source=src_list,group=data.ssm_group_list*4,proto=['IGMP']*4*entry_cnt
                                      ,iif=iif_list_lhr2,
                                      oif=[data.d4tg_ports[0]]*2*entry_cnt+[data.d4tg_ports[1]]*2*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Mroute entries not programmed in LHR2 pointing to FHR1 and FHR2')

    ##################################################################
    hdrMsg("Step T19:LHR2: Verify PIM state on LHR2 node and verify all (S,G) entries are installed")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut4,cmd_type='state',vrf='all',installed=['1']*entry_cnt*4,source=src_list,
                                     group=data.ssm_group_list*4,
                                     iif=iif_list_lhr2,
                                     oif=[[data.d4tg_ports[0]]]*2*entry_cnt+[[data.d4tg_ports[1]]]*2*entry_cnt,flag=[['I']]*entry_cnt*4)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM states are incorrect in LHR2')

    ##################################################################
    hdrMsg("Step T20:LHR1: Verify PIM join is sent to FHR1(D1) and FHR2(D2) on all VRFs")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut4,cmd_type='upstream',vrf='all',source=src_list,group=data.ssm_group_list*4,
                                     iif=iif_list_lhr2,state=['J']*4*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'LHR1 did not send PIM join upstream to FHR1')

    ##################################################################
    hdrMsg("Step T21:FHR1: Verify PIM states and verify join is received on FHR1 and FHR2")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut1,cmd_type='state',vrf='all',installed=['1']*entry_cnt*2,source=[data.tgd1_ip]*2*entry_cnt,
                                     group=data.ssm_group_list*2,
                                     oif=[[data.d1d4_ports[0]]]*entry_cnt+[[data.d1d4_ports[1]]]*entry_cnt,flag=[['J']]*entry_cnt*2)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR1 node from LHR2')

    result = pim_api.verify_pim_show(data.dut2,cmd_type='state',vrf='all',installed=['1']*entry_cnt*2,source=[data.tgd2_ip]*2*entry_cnt,
                                     group=data.ssm_group_list*2,
                                     oif=[[data.d2d4_vlan_intf[0]]]*entry_cnt+[[data.d2d4_vlan_intf_vrf[0]]]*entry_cnt,flag=[['J']]*entry_cnt*2)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR2 node from LHR2')

    result = pim_api.verify_pim_show(data.dut1,cmd_type='join',vrf='all',source=[data.tgd1_ip]*2*entry_cnt,group=data.ssm_group_list*2,
                                     interface=[data.d1d4_ports[0]]*entry_cnt+[data.d1d4_ports[1]]*entry_cnt,state=['JOIN']*2*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM join incorrect on FHR1 received from LHR2')

    result = pim_api.verify_pim_show(data.dut2,cmd_type='join',vrf='all',source=[data.tgd2_ip]*2*entry_cnt,group=data.ssm_group_list*2,
                                     interface=[data.d2d4_vlan_intf[0]]*entry_cnt+[data.d2d4_vlan_intf_vrf[0]]*entry_cnt,state=['JOIN']*2*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM join incorrect on FHR2 received from LHR2')



    ##################################################################
    hdrMsg("Step T22:FHR1: Verify Mroute programming on FHR1 and FHR2 node with correct OIFs and IIFs")
    ##################################################################

    result = pim_api.verify_ip_mroute(data.dut1,source=[data.tgd1_ip]*2*entry_cnt,group=data.ssm_group_list*2,proto=['PIM']*2*entry_cnt
                                      ,iif=[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
                                      oif=[data.d1d4_ports[0]]*entry_cnt+[data.d1d4_ports[1]]*entry_cnt,vrf='all')

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'OIF/IIF entries incorrect on FHR1')


    result = pim_api.verify_ip_mroute(data.dut2,source=[data.tgd2_ip]*2*entry_cnt,group=data.ssm_group_list*2,proto=['PIM']*2*entry_cnt
                                      ,iif=[data.d2tg_ports[0]]*entry_cnt+[data.d2tg_ports[1]]*entry_cnt,
                                      oif=[data.d2d4_vlan_intf[0]]*entry_cnt+[data.d2d4_vlan_intf_vrf[0]]*entry_cnt,vrf='all')

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'OIF/IIF entries incorrect on FHR2')

    ##################################################################
    hdrMsg("Step T23:Verify Receiver connected to LHR2 receives multicast traffic from S1 and S2 on default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd4_ports[0],exp_ratio=1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from both sources S1 and S2 did not forward for default-vrf ')

    ##################################################################
    hdrMsg("Step T24:Verify Receiver connected to LHR2 receives multicast traffic from S1 and S2 on user-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1],data.tgd2_ports[1]],dest_port=data.tgd4_ports[0],exp_ratio=1,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from both sources S1 and S2 did not forward for user-vrf ')

    ##################################################################
    hdrMsg("Step T25: Send IGMPv3 Report from R3 connected to LHR2 (D4)Blocking both Sources S1 {} and S2 {} ".format(data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    d4d1_prune_tx = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[0],vrf='default')
    d4d1_prune_tx_vrf = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[1],vrf=vrf_name)
    d4d2_prune_tx = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d2_vlan_intf[0],vrf='default')
    d4d2_prune_tx_vrf = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d2_vlan_intf_vrf[0],vrf=vrf_name)
    for vrf in vrf_list:
        send_igmpv3_report(host='R3', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include', vrf=vrf, mode='leave')


    ##################################################################
    hdrMsg("Step T26: Verify IGMP sources are cleared from igmp table")
    ##################################################################

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',return_output='',vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Not all Sources removed from IGMP table after sending IGMPv3-BLOCK OLD sources')

    ##################################################################
    hdrMsg("Step T27: Verify LHR2 Sends PRune to both FHR1 and FHR2")
    ##################################################################
    d4d1_prune_tx_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[0],vrf='default')
    d4d1_prune_tx_vrf_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[1],vrf=vrf_name)
    d4d2_prune_tx_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d2_vlan_intf[0],vrf='default')
    d4d2_prune_tx_vrf_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d2_vlan_intf_vrf[0],vrf=vrf_name)

    if int(d4d1_prune_tx) == int(d4d1_prune_tx_1):
        st.report_fail('test_case_failure_message', 'PRUNE message not sent out on {} towards FHR1'.format(data.d4d1_ports[0]))

    if int(d4d1_prune_tx_vrf) == int(d4d1_prune_tx_vrf_1):
        st.report_fail('test_case_failure_message', 'PRUNE message not sent out on {} towards FHR1 on user-vrf'.format(data.d4d1_ports[1]))

    if int(d4d2_prune_tx) == int(d4d2_prune_tx_1):
        st.report_fail('test_case_failure_message', 'PRUNE message not sent out on {} towards FHR2 '.format(data.d4d2_vlan_intf[0]))

    if int(d4d2_prune_tx_vrf) == int(d4d2_prune_tx_vrf_1):
        st.report_fail('test_case_failure_message', 'PRUNE message not sent out on {} towards FHR2 on user-vrf '.format(data.d4d2_vlan_intf_vrf[0]))

    ##################################################################
    hdrMsg("Step T28: Verify LHR2 deletes all mroute entries for both Sources S1 and S2")
    ##################################################################

    output = pim_api.verify_ip_mroute(data.dut4,vrf='all',return_output ='')
    if len(output) != 0:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Not all Mroute entries deleted on LHR2')


    ##################################################################
    hdrMsg("Step T29: Verify FHR1 removes OIF connected to LHR2 upon receiving PIM PRune")
    ##################################################################

    result1 = retry_null_output(pim_api.verify_ip_mroute,data.dut1,vrf='all',return_output='')
    result2 = retry_null_output(pim_api.verify_ip_mroute, data.dut2, vrf='all', return_output='')

    if not result1 or not result2:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'OIF/IIF entries incorrect on FHR1/FHR2 upon receiving PIM Prune')

    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)
    st.report_pass('test_case_passed')


def test_pim_func_002(prologue_epilogue):
    tc_list = ["FtOpSoRoPimFunc002"]
    tech_support = data.tech_support_on_fail
    key_append = ''
    index = 0
    lag_23 = data.d3d2_lag_intf_1
    d1d4_phy = data.d1d4_ports[0];d4d1_phy = data.d4d1_ports[0]
    dut1 = data.dut_list[0]
    d1_l3_list = [data['d1d2_vlan_intf' + key_append][0], data.d1d4_ports[index]] + data['d1d3_vlan_intf' + key_append]
    d2_l3_list = [data['d1d2_vlan_intf' + key_append][0], data['d2d4_vlan_intf' + key_append][0],lag_23]
    d3_l3_list = data['d1d3_vlan_intf' + key_append] + [lag_23, data['d3d4_vlan_intf' + key_append][0]]
    d4_l3_list = [data.d4d1_ports[index], data['d2d4_vlan_intf' + key_append][0], data['d3d4_vlan_intf' + key_append][0]]
    pim_intf_lst = []
    for intf_lst in [d1_l3_list,d2_l3_list,d3_l3_list,d4_l3_list]:
        pim_intf_lst.append(intf_lst)

    #####################################################################################
    hdrMsg("Step T1 : Verify PIM neighborship details using show ip pim interface")
    #####################################################################################
    # For each pim neighborship (both default and user vrf) verify DR election
    [result,exceptions] = utils.exec_all(True,[[verify_pim_dr,dut,intfs] for dut,intfs in zip(data.dut_list,pim_intf_lst)])

    if not all(i is None for i in exceptions):
        hdrMsg(exceptions)
    if False in result:
        err = "PIM DR election Failed"
        failMsg(err,tech_support,tc_name='pim_002_onfail');tech_support=False
        st.report_fail('test_case_failure_message', err)

    #######################################################################################################
    hdrMsg("Step T2 : Configure DR priority on DUT1 which has lower IP and verify PIM neighborship details")
    #######################################################################################################
    dr_priority1 = 100

    for intf in d1_l3_list:
        pim_api.config_intf_pim(dut1,intf=intf,drpriority=dr_priority1)
    [result,exceptions] = utils.exec_all(True,[[verify_pim_dr,dut,intfs] for dut,intfs in zip(data.dut_list,pim_intf_lst)])
    if not all(i is None for i in exceptions):
        hdrMsg(exceptions)
    if False in result:
        err = "PIM DR election Failed"
        failMsg(err, tech_support, tc_name='pim_002_onfail'); tech_support = False
        st.report_fail('test_case_failure_message', err)
    #########################################################################################################################
    hdrMsg("Step T3 : Configure DR priority to boundary value on all DUTs except DUT1 and verify PIM neighborship details")
    #########################################################################################################################
    dr_priority2 = 4294967294

    dict1 = []
    for intf_lst in [d2_l3_list,d3_l3_list,d4_l3_list]:
        dict1.append({'drpriority': dr_priority2,'intf':intf_lst,'config':'yes'})
    parallel.exec_parallel(True,data.dut_list[1:],pim_api.config_intf_pim,dict1)
    [result,exceptions] = utils.exec_all(True,[[verify_pim_dr,dut,intfs] for dut,intfs in zip(data.dut_list,pim_intf_lst)])

    if not all(i is None for i in exceptions):
        hdrMsg(exceptions)
    if False in result:
        err = "PIM DR election Failed"
        failMsg(err, tech_support, tc_name='pim_002_onfail');
        tech_support = False
        st.report_fail('test_case_failure_message', err)

    #######################################################################################################
    hdrMsg("Step T4 : Configure DR priority on DUT1 which has lower IP and verify PIM neighborship details")
    #######################################################################################################
    dr_priority1 = 4294967295

    for intf in d1_l3_list:
        pim_api.config_intf_pim(dut1,intf=intf,drpriority=dr_priority1)
    [result,exceptions] = utils.exec_all(True,[[verify_pim_dr,dut,intfs] for dut,intfs in zip(data.dut_list,pim_intf_lst)])
    if not all(i is None for i in exceptions):
        hdrMsg(exceptions)
    if False in result:
        err = "PIM DR election Failed"
        failMsg(err, tech_support, tc_name='pim_002_onfail');
        tech_support = False
        st.report_fail('test_case_failure_message', err)
    ###################################################################
    hdrMsg("Step T5 : PIM-UnConfig: DR Priority on all DUTs")
    ###################################################################
    dict1 = []
    for intf_lst in [d1_l3_list,d2_l3_list,d3_l3_list,d4_l3_list]:
        dict1.append({'drpriority':'','intf':intf_lst,'config':'no'})
    parallel.exec_parallel(True,data.dut_list,pim_api.config_intf_pim,dict1)

    st.report_pass('test_case_passed')


def test_pim_func_001(prologue_epilogue):
    tc_list = ["FtOpSoRoPimFunc001"]
    tc_result = True
    err_list =[]
    tech_support = data.tech_support_on_fail
    ###########################################################################################################
    hdrMsg("Step T1 : Enable IGMP on directly connected interfaces between DUT for both default and non default VRF")
    ###########################################################################################################

    for key_append in ['', '_vrf']:
        dict1 = []
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'igmp_enable': ''})
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'igmp_enable': ''})
        parallel.exec_parallel(True, [data.dut1, data.dut2], igmp_api.config_igmp, dict1)

    #################################################################################################
    hdrMsg("Step T2 : Verify Lower IP is elected as IGMP Querier on both default and non default VRF.")
    #################################################################################################
    for key_append in ['','_vrf']:
        if key_append != '':
            vrf = vrf_name
        else:
            vrf = 'default'
        result1 = igmp_api.verify_igmp_interface(data.dut1,interface=data['d1d2_vlan_intf'+key_append][0],querier='local', vrf = vrf)
        result2 = igmp_api.verify_igmp_interface(data.dut2,interface=data['d1d2_vlan_intf'+key_append][0],querier='other', vrf = vrf)

        if result1 is False or result2 is False:
            err = "IGMP Querier election is incorrect :Expected Querier : " + data.dut1 + " Interface : " + data['d1d2_vlan_intf'+key_append][0]
            failMsg(err,tech_support,tc_name='pim_001_onfail');tech_support=False;
            err_list.append(err);tc_result=False
    #############################################################
    hdrMsg("Step T3 : Revert back the configs- Unconfig IGMP.")
    #############################################################
    for key_append in ['','_vrf']:
        dict1 = []
        dict1.append({'intf': data['d1d2_vlan_intf'+key_append][0], 'igmp_enable': '', 'config': 'no'})
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'igmp_enable': '', 'config': 'no'})
        parallel.exec_parallel(True, [data.dut1,data.dut2], igmp_api.config_igmp, dict1)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_pim_func_004(prologue_epilogue):

    tc_list = ['FtOpSoRoPimFunc012','FtOpSoRoPimFunc015','FtOpSoRoPimFunc016','FtOpSoRoPimFunc039',
               'FtOpSoRoPimFunc040','FtOpSoRoPimFunc041','FtOpSoRoPimFunc042','FtOpSoRoPimFunc043','FtOpSoRoPimFunc052']
    err_list =[]
    tc_result = True
    tech_support = data.tech_support_on_fail
    multicast_traffic(groups =data.ssm_group_list[0],source='S1')
    multicast_traffic(groups=data.ssm_group_list[0], source='S1',vrf=vrf_name)
    tx_stream_list_1_default = data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])]
    tx_stream_list_1_vrf   = data.stream_handles['{}_S1_{}'.format(data.ssm_group_list[0],vrf_name)]

    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='10')
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],query_interval='2')
    config_pim_hello(hello=2)
    config_pim_hello(vrf=vrf_name,hello=2)
    #############################################################
    hdrMsg("Step T1 : Configure different values for ip pim packets under each vrf between D1 and D3")
    #############################################################

    dict1 = {'packets':'1'}
    dict2 = {'packets' :'100','vrf':vrf_name}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_pim_global, [dict1]*2)
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_pim_global, [dict2]*2)

    #############################################################
    hdrMsg("Step T2 : Verify PIM neighbors are UP between D1 and D3 for all VRFs")
    #############################################################
    dict1 = {'cmd_type': 'neighbor', 'interface':data.d1d3_vlan_intf+data.d1d3_vlan_intf_vrf,'neighbor': data.d3d1_ip*2 , 'vrf':'all'}
    dict2 = {'cmd_type': 'neighbor', 'interface':data.d3d1_vlan_intf+data.d3d1_vlan_intf_vrf,'neighbor': data.d1d3_ip*2 , 'vrf':'all'}
    dict_list = [dict1,dict2]
    result = retry_parallel(pim_api.verify_pim_show,dict_list,[data.dut1,data.dut3], retry_count=10,delay=1)
    if result is False:
        err = 'One or more PIM neighbors did not coime up with non default ip pim packets'
        failMsg(err,tech_support,tc_name='pim_004_onfail');tech_support=False;tc_result=False;err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc015", "tc_passed")


    #############################################################
    hdrMsg("Step T3 :Disable ip pim packets")
    #############################################################

    dict1 = {'packets':'1','config':'no'}
    dict2 = {'packets' :'100','config':'no','vrf':vrf_name}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_pim_global, [dict1]*2)
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_pim_global, [dict2]*2)

    #############################################################
    hdrMsg("Step : Configure Vlan interfaces between D1 and D3 to use loopback as source for control packets")
    #############################################################

    dict1 = {'intf':data.d1d3_vlan_intf[0],'use_source':data.d1_loopback_ip}
    dict2 = {'intf': data.d1d3_vlan_intf[0], 'use_source': data.d3_loopback_ip}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, [dict1,dict2])

    dict1 = {'intf':data.d1d3_vlan_intf_vrf[0],'use_source':data.d1_loopback_ip,'vrf':vrf_name}
    dict2 = {'intf': data.d1d3_vlan_intf_vrf[0], 'use_source': data.d3_loopback_ip,'vrf':vrf_name}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, [dict1,dict2])

    pim_api.clear_pim_interfaces(data.dut3,vrf='default')
    pim_api.clear_pim_interfaces(data.dut3, vrf=vrf_name)
    pim_api.clear_pim_interfaces(data.dut1,vrf='default')
    pim_api.clear_pim_interfaces(data.dut1, vrf=vrf_name)
    #############################################################
    hdrMsg("Step T5 : Verify PIM neighborship comes up with loopback interfaces as PIM neighbor on D1 and D3")
    #############################################################

    dict1 = {'cmd_type': 'neighbor', 'interface':[data.d1d3_vlan_intf[0],data.d1d3_vlan_intf_vrf[0]],'neighbor': [data.d3_loopback_ip]*2 , 'vrf':'all'}
    dict2 = {'cmd_type': 'neighbor', 'interface':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'neighbor': [data.d1_loopback_ip]*2 , 'vrf':'all'}
    dict_list = [dict1,dict2]
    result = retry_parallel(pim_api.verify_pim_show,dict_list,[data.dut1,data.dut3], retry_count=20,delay=2)
    if result is False:
        err = 'PIM neighbors with source as loopback did not come up'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc016", "tc_passed")
    #############################################################
    hdrMsg("Step T6 : Send IGMP join from R1 connected to LHR1(D1) from Tgen towards Source S1 connected to D1(FHR1)")
    #############################################################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=data.tgd1_ip, filter='include', vrf=vrf, mode='join')

    if 'ixia' in data.tgen_type:
        igmp_api.clear_igmp_interfaces(data.dut3, vrf='default')
        igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf_name)
        for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=data.tgd1_ip,filter='include', vrf=vrf, mode='join',remove_others='no')
    #############################################################
    hdrMsg("Step T7 : Send IGMP join from R3 connected to LHR2(D4)using \'ip igmp join\' command towards Source S1 connected to D1(FHR1)")
    #############################################################
    igmp_api.config_igmp(data.dut4,intf=data.d4tg_ports[0],group=data.ssm_group_list[0],source=data.tgd1_ip,join='')
    igmp_api.config_igmp(data.dut4, intf=data.d4tg_ports[1], group=data.ssm_group_list[0], source=data.tgd1_ip,join='')

    #############################################################
    hdrMsg("Step T8 : Verify IGMP table on both LHRs")
    #############################################################
    dict1= {'cmd_type':'groups','group':[data.ssm_group_list[0]]*2,'vrf':'all','source_count':[1,1],'interface':data.d3tg_vlan_intf+data.d3tg_vlan_intf_vrf}
    dict2= {'cmd_type':'groups','group':[data.ssm_group_list[0]]*2,'vrf':'all','source_count':[1,1]}
    result = retry_parallel(igmp_api.verify_ip_igmp,dut_list=[data.dut3,data.dut4],dict_list=[dict1,dict2])
    if result is False:
        err = 'IGMP groups not learnt on one or both LHRs'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    #############################################################
    hdrMsg("Step T9 : Verify Mroute entries are programmed on all LHRs and FHRs with correct OIFs and IIFs")
    #############################################################

    fhr_dict = {'source':[data.tgd1_ip]*4,'group':[data.ssm_group_list[0]]*4,'iif':[data.d1tg_ports[0]]*2+[data.d1tg_ports[1]]*2,
             'oif':[data.d1d3_vlan_intf[0],data.d1d4_ports[0],data.d1d3_vlan_intf_vrf[0],data.d1d4_ports[1]],'vrf':'all'}
    lhr1_dict = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'iif':[data.d1d3_vlan_intf[0],data.d1d3_vlan_intf_vrf[0]],
                 'oif':[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],'vrf':'all'}
    lhr2_dict = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'iif':[data.d4d1_ports[0],data.d4d1_ports[1]],
                 'oif':[data.d4tg_ports[0],data.d4tg_ports[1]],'vrf':'all'}

    result = retry_parallel(pim_api.verify_ip_mroute, dut_list=[data.dut1,data.dut3, data.dut4], dict_list=[fhr_dict,lhr1_dict,lhr2_dict],retry_count=10)

    if result is False:
        err = 'PIM Mroute entries on FHR with OIFs towards multiple LHRs failed'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    #############################################################
    hdrMsg("Step T10 : Verify Multicast traffic on all VRFs from S1 to hosts connected to LHR1 and LHR2")
    #############################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=[data.tgd3_ports[0],data.tgd4_ports[0]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_default]],mode='aggregate')
    if result is False:
        err = 'Multicast traffic from S1 to R1,R3 failed for default vrf'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=[data.tgd3_ports[1],data.tgd4_ports[1]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]],mode='aggregate')
    if result is False:
        err = 'Multicast traffic from S1 to R1,R3 failed for user vrf'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    igmp_triggers = ['clear_igmp_interfaces','igmp_disable_enable']
    for trigger in igmp_triggers:
        #############################################################
        hdrMsg("Step T11 : Perform {} on LHR1 and verify IGMP table".format(trigger))
        #############################################################
        if trigger == 'clear_igmp_interfaces':
            igmp_api.clear_igmp_interfaces(data.dut3,vrf='default')
            igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf_name)
        else:
            igmp_api.config_igmp(data.dut3,igmp_enable='',config='no',intf=data.d3tg_vlan_intf[0])
            igmp_api.config_igmp(data.dut3, igmp_enable='', config='no',intf=data.d3tg_vlan_intf_vrf[0])

            #############################################################
            hdrMsg("Step T12 : Verify IGMP table is emtpy")
            #############################################################

            output = igmp_api.verify_ip_igmp(data.dut3,cmd_type='groups',return_output='',vrf='all')
            if len(output) != 0:
                err = 'IGMP groups not removed from igmp table after {}'.format(trigger)
                failMsg(err, tech_support, tc_name='pim_004_onfail');
                tech_support = False;
                tc_result = False;err_list.append(err)

            igmp_api.config_igmp(data.dut3,igmp_enable='',config='yes',intf=data.d3tg_vlan_intf[0])
            igmp_api.config_igmp(data.dut3, igmp_enable='', config='yes',intf=data.d3tg_vlan_intf_vrf[0])


        #############################################################
        hdrMsg("Step: Verify IGMP table on both LHRs after {}".format(trigger))
        #############################################################

        dict1 = {'cmd_type': 'groups', 'group': [data.ssm_group_list[0]] * 2, 'vrf': 'all', 'source_count': [1, 1],'interface':data.d3tg_vlan_intf+data.d3tg_vlan_intf_vrf}
        dict2 = {'cmd_type': 'groups', 'group': [data.ssm_group_list[0]] * 2, 'vrf': 'all', 'source_count': [1, 1]}
        result = retry_parallel(igmp_api.verify_ip_igmp, dut_list=[data.dut3, data.dut4], dict_list=[dict1, dict2],retry_count=20,delay=2)
        if result is False:
            err = 'IGMP groups not learnt on one or both LHRs'
            failMsg(err, tech_support, tc_name='pim_004_onfail');
            tech_support = False;
            tc_result = False; err_list.append(err)

        #############################################################
        hdrMsg("Step: Verify Mroute entries are programmed on all LHRs and FHRs with correct OIFs and IIFs after {}".format(trigger))
        #############################################################

        result = retry_parallel(pim_api.verify_ip_mroute, dut_list=[data.dut1, data.dut3, data.dut4],
                                dict_list=[fhr_dict, lhr1_dict, lhr2_dict])
        if result is False:
            err = 'PIM Mroute entries on FHR with OIFs towards multiple LHRs failed'
            failMsg(err, tech_support, tc_name='pim_004_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)


    #############################################################
    hdrMsg("Step: Verify Multicast traffic on all VRFs from S1 to hosts connected to LHR1 and LHR2 after triggers")
    #############################################################

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[0]],
                                  dest_port=[data.tgd3_ports[0], data.tgd4_ports[0]], exp_ratio=1,tx_stream_list=[[tx_stream_list_1_default]],
                                  mode='aggregate')
    if result is False:
        err='Multicast traffic from S1 to R1 failed for default vrf'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]],
                                  dest_port=[data.tgd3_ports[1], data.tgd4_ports[1]], exp_ratio=1,tx_stream_list=[[tx_stream_list_1_vrf]],
                                  mode='aggregate')
    if result is False:
        err ='Multicast traffic from S1 to R1 failed for user vrf'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc040", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimFunc052", "tc_passed")

    #############################################################
    hdrMsg("Step: Do \'Clear ip pim oil' on FHR ndoe and verify OIFs are re-scanned and programmed on Mroute table")
    #############################################################

    pim_api.clear_pim_oil(data.dut1,vrf='default')
    pim_api.clear_pim_oil(data.dut1, vrf=vrf_name)

    #############################################################
    hdrMsg("Step: Verify Mroute entries are programmed on all LHRs and FHRs with correct OIFs and IIFs after  \'Clear ip pim oil\'")
    #############################################################

    result = retry_parallel(pim_api.verify_ip_mroute, dut_list=[data.dut1, data.dut3, data.dut4],
                            dict_list=[fhr_dict, lhr1_dict, lhr2_dict])
    if result is False:
        err = 'PIM Mroute entries on FHR with OIFs towards multiple LHRs failed'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc041", "tc_passed")

    #############################################################
    hdrMsg("Step: Do \'Clear ip pim mroute\' on FHR ndoe and mroute entries are uninstalled")
    #############################################################

    for vrf in vrf_list:
        for i in range(2):
            pim_api.clear_mroute(data.dut1,vrf=vrf)
            result = pim_api.verify_ip_mroute(data.dut1,return_output='',vrf=vrf)
            if len(result) == 0:
                break
        if len(result) != 0:
            err ='Mroute entries not removed after \'clear ip mroute\''
            failMsg(err, tech_support, tc_name='pim_004_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)


    #############################################################
    hdrMsg("Step: Verify Mroute entries are programmed on all LHRs and FHRs with correct OIFs and IIFs after  \'Clear ip mroute\'")
    #############################################################
    result = retry_parallel(pim_api.verify_ip_mroute, dut_list=[data.dut1, data.dut3, data.dut4],dict_list=[fhr_dict, lhr1_dict, lhr2_dict],retry_count=10,delay=7)
    if result is False:
        err = 'PIM Mroute entries on FHR with OIFs towards multiple LHRs failed'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc043", "tc_passed")
    #############################################################
    hdrMsg("Step: Do \'Clear ip pim interfaces\' on FHR ndoe ")
    #############################################################

    pim_api.clear_pim_interfaces(data.dut1,vrf='default')
    pim_api.clear_pim_interfaces(data.dut1, vrf=vrf_name)


    #############################################################
    hdrMsg("Step: Verify PIM neighbors to come up on all interfaces")
    #############################################################
    dict1 = {'cmd_type': 'neighbor', 'interface':[data.d1d3_vlan_intf[0],data.d1d3_vlan_intf_vrf[0]],'neighbor': [data.d3_loopback_ip]*2  , 'vrf':'all'}
    dict2 = {'cmd_type': 'neighbor', 'interface':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'neighbor': [data.d1_loopback_ip]*2  , 'vrf':'all'}
    dict_list = [dict1,dict2]
    result = retry_parallel(pim_api.verify_pim_show,dict_list,[data.dut1,data.dut3], retry_count=20,delay=2)
    if result is False:
        err = 'PIM neighbors did not come up after \'clear ip pim interfaces\''
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    #############################################################
    hdrMsg("Step: Verify Mroute entries are programmed on all LHRs and FHRs with correct OIFs and IIFs after receiving PIM-JOIN from LHR nodes")
    #############################################################

    result = retry_parallel(pim_api.verify_ip_mroute, dut_list=[data.dut1, data.dut3, data.dut4],dict_list=[fhr_dict, lhr1_dict, lhr2_dict],retry_count=15,delay=5)
    if result is False:
        err = 'PIM Mroute entries on FHR with OIFs towards multiple LHRs failed'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    #############################################################
    hdrMsg("Step: Verify Multicast traffic on all VRFs from S1 to hosts connected to LHR1 and LHR2 after trigger")
    #############################################################

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[0]],
                                  dest_port=[data.tgd3_ports[0], data.tgd4_ports[0]], exp_ratio=1,tx_stream_list=[[tx_stream_list_1_default]]
                                  ,mode='aggregate')
    if result is False:
        err ='Multicast traffic from S1 to R1 and R3 failed for default vrf '
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]],
                                  dest_port=[data.tgd3_ports[1], data.tgd4_ports[1]], exp_ratio=1,tx_stream_list=[[tx_stream_list_1_vrf]]
                                  ,mode='aggregate')
    if result is False:
        err ='Multicast traffic from S1 to R1 and R3 failed for user vrf '
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc039", "tc_passed")
    #############################################################
    hdrMsg("Step: Send Leave using \'no ip igmp join\' from LHR2 and from Tgen host on LHR1")
    #############################################################

    igmp_api.config_igmp(data.dut4,intf=data.d4tg_ports[0],group=data.ssm_group_list[0],source=data.tgd1_ip,config='no',join='')
    igmp_api.config_igmp(data.dut4, intf=data.d4tg_ports[1], group=data.ssm_group_list[0], source=data.tgd1_ip,config='no',join='')

    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=data.tgd1_ip,filter='include', vrf=vrf, mode='leave')

    #############################################################
    hdrMsg("Step: Verify Mroute entries and IGMP group entries are removed from LHRs")
    #############################################################

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut4, cmd_type='sources', return_output='', vrf='all')
    if result is False:
        err = 'IGMP groups are not removed from IGMP table'
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    #############################################################
    hdrMsg("Step : Revert Vlan interfaces between D1 and D3 to use own ip as source for control packets")
    #############################################################

    dict1 = {'intf':data.d1d3_vlan_intf[0],'use_source':data.d1_loopback_ip,'config':'no'}
    dict2 = {'intf': data.d1d3_vlan_intf[0], 'use_source': data.d3_loopback_ip,'config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, [dict1,dict2])

    dict1 = {'intf':data.d1d3_vlan_intf_vrf[0],'use_source':data.d1_loopback_ip,'vrf':vrf_name,'config':'no'}
    dict2 = {'intf': data.d1d3_vlan_intf_vrf[0], 'use_source': data.d3_loopback_ip,'vrf':vrf_name,'config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, [dict1,dict2])

    pim_api.clear_pim_interfaces(data.dut3,vrf='default')
    pim_api.clear_pim_interfaces(data.dut3, vrf=vrf_name)


    #############################################################
    hdrMsg("Step: Verify PIM neighbors to come up on all interfaces with interface ip")
    #############################################################
    dict1 = {'cmd_type': 'neighbor', 'interface':[data.d1d3_vlan_intf[0],data.d1d3_vlan_intf_vrf[0]],'neighbor': [data.d3d1_ip[0]]*2 , 'vrf':'all'}
    dict2 = {'cmd_type': 'neighbor', 'interface':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'neighbor': [data.d1d3_ip[0]]*2 , 'vrf':'all'}
    dict_list = [dict1,dict2]
    result = retry_parallel(pim_api.verify_pim_show,dict_list,[data.dut1,data.dut3], retry_count=20,delay=2)
    if result is False:
        err = 'PIM neighbors did not come up after \'clear ip pim interfaces\''
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    #############################################################
    hdrMsg("Step : Verify \'clear ip pim interface traffic resets counter values\'")
    #############################################################

    initial_pkt = get_packet_count(data.dut3,pkt_type='hello_tx',interface=data.d3d1_vlan_intf[0],vrf='default')
    initial_pkt_vrf = get_packet_count(data.dut3, pkt_type='hello_tx', interface=data.d3d1_vlan_intf_vrf[0], vrf=vrf_name)

    pim_api.clear_pim_traffic(data.dut3)
    pim_api.clear_pim_traffic(data.dut3,vrf=vrf_name)

    final_pkt = get_packet_count(data.dut3,pkt_type='hello_tx',interface=data.d3d1_vlan_intf[0],vrf='default')
    final_pkt_vrf = get_packet_count(data.dut3, pkt_type='hello_tx', interface=data.d3d1_vlan_intf_vrf[0], vrf=vrf_name)

    if int(final_pkt) >= int(initial_pkt) or int(final_pkt_vrf) >= int(initial_pkt_vrf):
        err = "PIM counters did not reset"
        failMsg(err, tech_support, tc_name='pim_004_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc042", "tc_passed")
    config_pim_hello(config='no')
    config_pim_hello(config='no',vrf=vrf_name)
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='',
                         query_interval='', config='no')
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)
    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])


def test_pim_func_005(prologue_epilogue):

    tc_list = ['FtOpSoRoPimFunc022','FtOpSoRoPimFunc023','FtOpSoRoPimFunc032','FtOpSoRoPimFunc033','FtOpSoRoPimFunc034','FtOpSoRoPimFunc035',
                'FtOpSoRoPimFunc044','FtOpSoRoPimFunc045','FtOpSoRoPimFunc048','FtOpSoRoPimFunc051']
    err_list =[]
    tc_result = True
    tech_support = data.tech_support_on_fail
    multicast_traffic(groups =data.ssm_group_list[0],source='S1')
    multicast_traffic(groups=data.ssm_group_list[0], source='S1',vrf=vrf_name)
    tx_stream_list_1_default = data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])]
    tx_stream_list_1_vrf   = data.stream_handles['{}_S1_{}'.format(data.ssm_group_list[0],vrf_name)]
    #############################################################
    hdrMsg("Step T1 : Withdraw route to Multicast source {} on all VRFs ".format(data.tgd1_ip))
    #############################################################

    bgp_api.config_bgp(data.dut1,local_as=data.d1_as,config_type_list=['network'], network='{}/{}'.format(data.mcast_source_nw[0], data.mask),config='no')
    bgp_api.config_bgp(data.dut1,local_as=data.d1_as,config_type_list=['network'],network =  '{}/{}'.format(data.mcast_source_nw[0], data.mask),vrf_name= vrf_name,config='no')


    #############################################################
    hdrMsg("Step T2: Send IGMP join for group {} towards Source {} on all VRFs from D3(LHR1) tgen".format(data.ssm_group_list[0],data.tgd1_ip))
    #############################################################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=data.tgd1_ip, filter='include', vrf=vrf, mode='join')

    #############################################################
    hdrMsg("Step T3: Verify RPF check fails since no route available towards source and Mroute entries not programmed")
    #############################################################

    for vrf in vrf_list:
        result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='rpf', source=data.tgd1_ip , group=data.ssm_group_list[0],
                                         rpfiface='none' , rpfaddress='0.0.0.0', vrf=vrf)
        if result is False:
            err=' RPF entry incorrect for vrf {} on LHR'.format(vrf);
            failMsg(err, tech_support, tc_name='pim_005_onfail');
            tech_support = False;
            tc_result=False;err_list.append(err)
        result = pim_api.verify_ip_mroute(data.dut3, source=[data.tgd1_ip], group=[data.ssm_group_list[0]], installed=[''], iif=['none'],vrf=vrf)
        if result is False:
            err=' RPF entry incorrect for vrf {} on LHR'.format(vrf);
            failMsg(err, tech_support, tc_name='pim_005_onfail');
            tech_support = False;
            tc_result=False;err_list.append(err)
    #############################################################
    hdrMsg("Step T4: Advertise route towards source from FHR1 aain via bgp")
    #############################################################
    bgp_api.config_bgp(data.dut1, local_as=data.d1_as, config_type_list=['network'],network='{}/{}'.format(data.mcast_source_nw[0], data.mask))
    bgp_api.config_bgp(data.dut1, local_as=data.d1_as, config_type_list=['network'],network='{}/{}'.format(data.mcast_source_nw[0], data.mask), vrf_name=vrf_name)

    #############################################################
    hdrMsg("Step T5: Verify RPF check succeeds and mroute entries gets programmed on both LHR and FHR")
    #############################################################

    result =retry_api(pim_api.verify_pim_show,data.dut3,cmd_type='rpf',source=[data.tgd1_ip]*2,group=[data.ssm_group_list[0]]*2,
                      rpfiface=[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],rpfaddress=[data.d1d3_ip[0]]*2,vrf='all')
    if result is False:
        err = ' RPF entry incorrect on LHR';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_ip_mroute(data.dut3, source=[data.tgd1_ip]*2, group=[data.ssm_group_list[0]]*2, installed=['*']*2,
                                      iif=[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]], vrf='all')
    if result is False:
        err = ' Mroute entries are not programmed after RPF check succeeds';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc022", "tc_passed")
    #############################################################
    hdrMsg("Step T6: Enable BFD on PIM interfaces between FHR1-LHR1 and FHR2-LHR1 interfaces")
    #############################################################
    #shut vlan102,1102 btw D1 and D3 to avoid ECMP
    port_api.shutdown(data.dut3,[data.d3d1_ports[2]])

    dict1 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes'}
    dict2 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'bfd_enable':'yes'}
    dict3 = {'intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes'}

    parallel.exec_parallel(True, [data.dut1, data.dut2,data.dut3], pim_api.config_intf_pim, [dict2, dict3,dict1])
    #############################################################
    hdrMsg("Step T6: Verify BFD session is UP under PIM neighbor output on all VRFs")
    #############################################################
    result = retry_api(bfd_api.verify_bfd_peer,data.dut3, peer=[data.d1d3_ip[0],data.d2d3_ip], interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1], status=['up']*2)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on default-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = bfd_api.verify_bfd_peer(data.dut3, peer=[data.d1d3_ip[0], data.d2d3_ip], interface=[data.d3d1_vlan_intf_vrf[0], data.d3d2_lag_intf_2],status=['up'] * 2,vrf_name=vrf_name)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on user vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc032", "tc_passed")

    #############################################################
    hdrMsg("Step T6: Configure non-default timers for BFD peers and verify BFD sessions ae UP")
    #############################################################

    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1],neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip],
                          multiplier=["2"]*2,rx_intv=["200"]*2,tx_intv=["200"]*2 )

    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_2], neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip],
                          multiplier=["2"]*2,rx_intv=["200"]*2,tx_intv=["200"]*2,vrf_name=vrf_name)


    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc033", "tc_passed")
    #############################################################
    hdrMsg("Step T7: Remove ip address on Vlan interface towards FHR1 and verify BFD/PIM session timeout immediatley")
    #############################################################
    vlan_api.delete_vlan_member(data.dut3, data.d3d1_vlan_id[0], [data.lag_intf_list[0]],True)
    vlan_api.delete_vlan_member(data.dut3, data.d3d1_vlan_id_vrf[0], [data.lag_intf_list[0]],True)

    ip_api.delete_ip_interface(data.dut3,interface_name=data.d3d1_vlan_intf[0],ip_address=data.d3d1_ip[0],subnet='24')
    ip_api.delete_ip_interface(data.dut3, interface_name=data.d3d1_vlan_intf_vrf[0], ip_address=data.d3d1_ip[0], subnet='24')


    st.log("\n####### Verify PIM neighbor goes down immediatley on FHR1  #######\n")
    result1 = retry_null_output(pim_api.verify_pim_show,data.dut1, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]),return_output='', bfd_status='Up')
    result2 = retry_null_output(pim_api.verify_pim_show,data.dut1, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Up',return_output='',vrf=vrf_name)

    if result1 is False or result2 is False:
        err = 'PIM neighbor did not go down with BFD timeout upon deleting ip address';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    #############################################################
    hdrMsg("Step T8: Verify mroute entry on FHR1 and verify it received PIM join via FHR2 from LHR1")
    #############################################################
    dict1 ={'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'iif':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'oif':['Vlan100','Vlan1100'],'vrf':'all'}
    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1],retry_count =5)
    if result is False:
        err = ' PIM join from LHR1 not received to FHR1 via FHR2';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    #############################################################
    hdrMsg("Step T9: Verify multicast traffic gets forwarded towards receiver via FHR2")
    #############################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=[data.tgd3_ports[0]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Multicast traffic from S1 to R1 failed for default vrf'
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;tc_result=False;err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=[data.tgd3_ports[1]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]])
    if result is False:
        err = 'Multicast traffic from S1 to R1 failed for user vrf'
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    #############################################################
    hdrMsg("Step T10: Re-add ip address and verify BFD and PIM neighbors comes up")
    #############################################################
    vlan_api.add_vlan_member(data.dut3, data.d3d1_vlan_id[0], [data.lag_intf_list[0]], True)
    vlan_api.add_vlan_member(data.dut3, data.d3d1_vlan_id_vrf[0], [data.lag_intf_list[0]], True)
    ip_api.config_ip_addr_interface(data.dut3,interface_name=data.d3d1_vlan_intf[0],ip_address=data.d3d1_ip[0],subnet='24')
    ip_api.config_ip_addr_interface(data.dut3, interface_name=data.d3d1_vlan_intf_vrf[0], ip_address=data.d3d1_ip[0], subnet='24')

    st.log("Verify PIM neighbors comes up between LHR1 and FHR1 with BFD")


    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]), bfd_status='Up',retry_count=15,delay=2)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    #############################################################
    hdrMsg("Step T11: Verify LHR1 now sends out PIM join directly on interface towards FHR1 and send Prune on other interface towards FHR2")
    #############################################################

    dict1 ={'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    result = retry_parallel(pim_api.verify_ip_mroute, dict_list=[dict1, dict2], dut_list=[data.dut3, data.dut1],retry_count=20,delay=3)

    if result is False:
        err = ' Mroute entries incorrect on LHR and FHR1';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc023", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimFunc045", "tc_passed")

    #############################################################
    hdrMsg("Step T12: Disable and Enable BFD on PIM interfaces between FHR1-LHR1 and FHR2-LHR1 interfaces")
    #############################################################
    #shut vlan102,1102 btw D1 and D3 to avoid ECMP
    dict1 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'','config':'no'}
    dict2 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'bfd_enable':'','config':'no'}
    dict3 = {'intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], pim_api.config_intf_pim, [dict2, dict3, dict1])

    dict1 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes'}
    dict2 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'bfd_enable':'yes'}
    dict3 = {'intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes'}

    parallel.exec_parallel(True, [data.dut1, data.dut2,data.dut3], pim_api.config_intf_pim, [dict2, dict3,dict1])
    #############################################################
    hdrMsg("Step T13: Verify BFD session is UP under PIM neighbor output on all VRFs after disable/enable bfd")
    #############################################################

    result = retry_api(bfd_api.verify_bfd_peer,data.dut3, peer=[data.d1d3_ip[0],data.d2d3_ip], interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1], status=['up']*2,retry_count=20,delay=1)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on default-vrf after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = bfd_api.verify_bfd_peer(data.dut3, peer=[data.d1d3_ip[0], data.d2d3_ip], interface=[data.d3d1_vlan_intf_vrf[0], data.d3d2_lag_intf_2],status=['up'] * 2,vrf_name=vrf_name)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on user vrf after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Up',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf after bfd disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc034", "tc_passed")
    #############################################################
    hdrMsg("Step T14: Admin down/up  BFD on PIM interfaces between FHR1-LHR1 and FHR2-LHR1 interfaces")
    #############################################################
    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1],neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip], shutdown='')

    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_2], neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip],vrf_name=vrf_name,shutdown='')

    result = retry_api(pim_api.verify_pim_show,data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]), bfd_status='Unknown')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default after admin-down BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]), bfd_status='Unknown',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf after admin-down BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Unknown')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default after admin-down BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Unknown',vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf after admin-down BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)



    #############################################################
    hdrMsg("Step T15: Verify BFD session is UP under PIM neighbor output on all VRFs after admin down/up bfd")
    #############################################################
    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf[0], data.d3d2_lag_intf_1],
                          neighbor_ip=[data.d1d3_ip[0], data.d2d3_ip], noshut='')
    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf_vrf[0], data.d3d2_lag_intf_2],
                          neighbor_ip=[data.d1d3_ip[0], data.d2d3_ip], vrf_name=vrf_name, noshut='')

    result = retry_api(bfd_api.verify_bfd_peer,data.dut3, peer=[data.d1d3_ip[0],data.d2d3_ip], interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1], status=['up']*2)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on default-vrf after admin-up BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = bfd_api.verify_bfd_peer(data.dut3, peer=[data.d1d3_ip[0], data.d2d3_ip], interface=[data.d3d1_vlan_intf_vrf[0], data.d3d2_lag_intf_2],status=['up'] * 2,vrf_name=vrf_name)
    if result is False:
        err = ' BFD over PIM neighbors did not come up on user vrf after admin-up';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(pim_api.verify_pim_show, data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf[0]),
                       bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default  after admin up BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d1_vlan_intf_vrf[0]),
                                     bfd_status='Up', vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf  after admin up BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_1), bfd_status='Up')
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under default  after admin up BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    result = pim_api.verify_pim_show(data.dut3, cmd_type='neighbor {}'.format(data.d3d2_lag_intf_2), bfd_status='Up',
                                     vrf=vrf_name)
    if result is False:
        err = ' BFD state under PIM neighbor is incorrect under user-vrf  after admin up BFD';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc035", "tc_passed")
    #############################################################
    hdrMsg("Step T16: Flap one of the member ports of LAG interface between LHR1 and FHR1")
    #############################################################
    port_api.shutdown(data.dut3,[data.d3d1_ports[0]])

    st.log("\n####### Verify mroute programming intact on both FHR and LHR nodes ###########\n")
    dict1 ={'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    result = retry_parallel(pim_api.verify_ip_mroute, dict_list=[dict1, dict2], dut_list=[data.dut3, data.dut1],retry_count=10)
    if result is False:
        err = ' Mroute entries incorrect on LHR and FHR1 after shutdown Port-channel member ports';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    port_api.noshutdown(data.dut3, [data.d3d1_ports[0]])

    dict1 ={'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    result = retry_parallel(pim_api.verify_ip_mroute, dict_list=[dict1, dict2], dut_list=[data.dut3, data.dut1],retry_count=10)
    if result is False:
        err = ' Mroute entries incorrect on LHR and FHR1 after no-shut Port-channel member ports';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    #############################################################
    hdrMsg("Step T17: Flap Port-channel interface between LHR1 and FHR1 and verify mroute entries reprogrammed")
    #############################################################
    port_api.shutdown(data.dut3, [data.d1d3_lag_intf])
    port_api.noshutdown(data.dut3, [data.d1d3_lag_intf])
    result = retry_parallel(pim_api.verify_ip_mroute, dict_list=[dict1, dict2], dut_list=[data.dut3, data.dut1],retry_count=15,delay=4)
    if result is False:
        err = ' Mroute entries incorrect on LHR and FHR1 after flapping Port-channel';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc051", "tc_passed")
    #############################################################
    hdrMsg("Step T18: PIM enable/disable on all interfaces")
    #############################################################
    config_igmp_pim(config='no')
    config_igmp_pim(config='yes')
    dict1 ={'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'installed':['*']*2,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}
    result = retry_parallel(pim_api.verify_ip_mroute, dict_list=[dict1, dict2], dut_list=[data.dut3, data.dut1],retry_count=10)

    if result is False:
        err = ' Mroute entries incorrect on LHR and FHR1 after PIM disable/enable';
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    #############################################################
    hdrMsg("Step T20: Verify multicast traffic forwarding after pim/igmp disable and enable")
    #############################################################
    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=[data.tgd3_ports[0]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Multicast traffic from S1 to R1 failed for default vrf after pim/igmp disable and enable'
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=[data.tgd3_ports[1]],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]])
    if result is False:
        err = 'Multicast traffic from S1 to R1 failed for user vrf after pim/igmp disable and enable'
        failMsg(err, tech_support, tc_name='pim_005_onfail');
        tech_support = False;
        tc_result=False;err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc048", "tc_passed")

    ##############################
    hdrMsg("Cleanup for TC_005")
    ##############################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=data.tgd1_ip,filter='include', vrf=vrf, mode='leave')
    #Bring back the ecmp path between d3 and d1
    port_api.noshutdown(data.dut3, [data.d3d1_ports[2]])
    dict1 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'','config':'no'}
    dict2 = {'intf':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'bfd_enable':'','config':'no'}
    dict3 = {'intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'bfd_enable':'yes','config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], pim_api.config_intf_pim, [dict2, dict3, dict1])
    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf[0],data.d3d2_lag_intf_1],neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip],config='no')
    bfd_api.configure_bfd(data.dut3, interface=[data.d3d1_vlan_intf_vrf[0],data.d3d2_lag_intf_2], neighbor_ip=[data.d1d3_ip[0],data.d2d3_ip]
                          ,vrf_name=vrf_name,config='no')
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)
    ##############################
    hdrMsg("Cleanup End for TC_005")
    ##############################
    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])


def test_pim_func_007(prologue_epilogue):
    tc_list = ["FtOpSoRoPimFunc026", "FtOpSoRoPimFunc027"]
    ###########################################################################################################
    hdrMsg("Step T1 : Configure Hello interval for both default and non default VRF")
    ###########################################################################################################
    dut_pair = [data.dut1, data.dut2]
    tech_support = data.tech_support_on_fail
    err_list =[]
    tc_result = True
    # To reduce script run time. Default Hello time of 30s is not verified.
    hello_interval = 4
    hello_interval_vrf = 3
    hold_time = int(3.5 * hello_interval)
    hold_time_vrf = int(3.5 * hello_interval_vrf + 0.5)

    for key_append,interval,ht in zip(['', '_vrf'],[hello_interval,hello_interval_vrf],[hold_time,hold_time_vrf]):
        dict1 = []
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'hello_intv': interval,'hold_time':ht})
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'hello_intv': interval,'hold_time':ht})
        parallel.exec_parallel(True, dut_pair, pim_api.config_intf_pim, dict1)

    # Toggle interface to reset hello interval
    dict_port = []

    dict_port.append({'interfaces': data.d1d2_ports[0]})
    dict_port.append({'interfaces': data.d2d1_ports[0]})

    hdrMsg(" Flap interface to reset hello timer.")
    parallel.exec_parallel(True, dut_pair, intf_api.interface_shutdown, dict_port)
    parallel.exec_parallel(True, dut_pair, intf_api.interface_noshutdown, dict_port)

    result = retry_api(pim_api.verify_pim_show,data.dut1,vrf='all',cmd_type='neighbor',neighbor=[data.d2d1_ip]*2,
                       interface=[data.d1d2_vlan_intf[0],data.d1d2_vlan_intf_vrf[0]])
    if result is False:
        err = "PIM Neighborship not UP after link flap"
        failMsg(err, tech_support, tc_name='pim_007_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    #################################################################################################################
    hdrMsg("Step T2 : Verify configured PIM hello interval using show command on both default and non default VRF.")
    #################################################################################################################
    pre_hello_cnt = []
    post_hello_cnt = []
    for key_append,interval in zip(['', '_vrf'],[hello_interval,hello_interval_vrf]):
        if key_append != '':
            vrf = vrf_name
        else:
            vrf = 'default'
        parsed_output1 = pim_api.verify_pim_interface_detail(data.dut1, interface=data['d1d2_vlan_intf' + key_append][0], vrf=vrf, return_output=1,skip_error=True)
        parsed_output2 = pim_api.verify_pim_interface_detail(data.dut2, interface=data['d1d2_vlan_intf' + key_append][0], vrf=vrf, return_output=1,skip_error=True)

        if len(parsed_output1) == 0 or len(parsed_output2) == 0:
            err = "show command output is Empty"
            failMsg(err, tech_support, tc_name='pim_007_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

        # Workaround for unicode data
        parsed_output1 = ast.literal_eval(json.dumps(parsed_output1))[0]
        parsed_output2 = ast.literal_eval(json.dumps(parsed_output2))[0]
        if parsed_output1['state'] != 'up' or parsed_output2['state'] != 'up':
            err = "PIM Neighborship not UP"
            failMsg(err, tech_support, tc_name='pim_007_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

        if parsed_output1['period'] != str(interval) or parsed_output2['period'] != str(interval):
            err = "Actual PIM Hello interval does not match with Configured value"
            failMsg(err, tech_support, tc_name='pim_007_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

        pre_hello_cnt.append(int(parsed_output1['receive']))
        pre_hello_cnt.append(int(parsed_output1['send']))
        pre_hello_cnt.append(int(parsed_output2['receive']))
        pre_hello_cnt.append(int(parsed_output2['send']))

    #############################################################################
    hdrMsg("Step T4 : Verify PIM hello messages are sent at configured interval.")
    #############################################################################
    # Get current Sent and Received Hello count
    # Wait for hello timer
    st.wait(hello_interval+1)

    # Get current Sent and Received Hello count
    for key_append in ['', '_vrf']:
        if key_append != '':
            vrf = vrf_name
        else:
            vrf = 'default'

        parsed_output1 = pim_api.verify_pim_interface_detail(data.dut1,
                                                             interface=data['d1d2_vlan_intf' + key_append][0], vrf=vrf,
                                                             return_output=1,skip_error=True)
        parsed_output2 = pim_api.verify_pim_interface_detail(data.dut2,
                                                             interface=data['d1d2_vlan_intf' + key_append][0], vrf=vrf,
                                                             return_output=1,skip_error=True)

        if len(parsed_output1) == 0 or len(parsed_output2) == 0:
            err = "show command output is Empty"
            failMsg(err, tech_support, tc_name='pim_007_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

        # Workaround for unicode data
        parsed_output1 = ast.literal_eval(json.dumps(parsed_output1))[0]
        parsed_output2 = ast.literal_eval(json.dumps(parsed_output2))[0]
        post_hello_cnt.append(int(parsed_output1['receive']))
        post_hello_cnt.append(int(parsed_output1['send']))
        post_hello_cnt.append(int(parsed_output2['receive']))
        post_hello_cnt.append(int(parsed_output2['send']))

    # Verify difference in Sent and Received is > 0

    for pre_cnt, post_cnt in zip(pre_hello_cnt, post_hello_cnt):
        if post_cnt <= pre_cnt:
            err = "Before and After Hello Timer expiry Receive and Send counts for " \
                  "default and non-default vrf."+"\n"+str(pre_hello_cnt)+"\n"+str(post_hello_cnt)
            failMsg(err, tech_support, tc_name='pim_007_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    #####################################################################
    hdrMsg("Step T5 : Verify Hold Timer. Stop a DUT from sending PIM Hello.")
    ######################################################################
    # Unconfig PIM enabled Vlan interface from port on DUT1.
    # Verify after 3.5 times the PIM hello interval, hold timer expires
    ###################################################################
    hdrMsg("Vlan-DeConfig: Remove  Vlan membership from Dut1 to simulate PIM Hello drop.")
    ###################################################################
    #data['d1d2_vlan_intf' + key_append][0]
    vlan_list = [data.d1d2_vlan_id, data.d1d2_vlan_id_vrf]
    for vlan in vlan_list:
        vlan_api.delete_vlan_member(data.dut1, vlan[0], data.d1d2_ports[0],True)

    result = verify_hold_timer(hold_time)
    if result is False:
        err = "PIM Hold Timer validation failed."
        failMsg(err, tech_support, tc_name='pim_007_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    ###################################################################
    hdrMsg("Step T6 :Vlan-ReConfig: Add  Vlan member back to Dut1 .")
    ###################################################################
    for vlan in vlan_list:
        vlan_api.add_vlan_member(data.dut1, vlan[0], data.d1d2_ports[0], True)

    ####################################################################################
    hdrMsg("Step T7 : Revert back the configs- Unconfig PIM Hello interval and hold time.")
    ####################################################################################

    for key_append in ['', '_vrf']:
        dict1 = []
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'hello_intv': '', 'config': 'no'})
        dict1.append({'intf': data['d1d2_vlan_intf' + key_append][0], 'hello_intv': '', 'config': 'no'})
        parallel.exec_parallel(True, dut_pair, pim_api.config_intf_pim, dict1)

    hdrMsg(" Flap interface to reset hello timer.")
    parallel.exec_parallel(True, dut_pair, intf_api.interface_shutdown, dict_port)
    parallel.exec_parallel(True, dut_pair, intf_api.interface_noshutdown, dict_port)
    #############################################################
    hdrMsg("Step T8 : Verify PIM neighborship after reverting back the configs.")
    #############################################################
    #############################################################
    hdrMsg("Verify PIM neighbors are UP between D1 and D2 for all VRFs")
    #############################################################
    dict1 = {'cmd_type': 'neighbor', 'interface': data.d1d2_vlan_intf + data.d1d2_vlan_intf_vrf,
             'neighbor': [data.d2d1_ip] * 2, 'vrf': 'all'}
    dict2 = {'cmd_type': 'neighbor', 'interface': data.d2d1_vlan_intf + data.d2d1_vlan_intf_vrf,
             'neighbor': [data.d1d2_ip] * 2, 'vrf': 'all'}
    dict_list = [dict1, dict2]
    result = retry_parallel(pim_api.verify_pim_show, dict_list, [data.dut1, data.dut2], retry_count=20, delay=2)
    if result is False:
        err = 'One or more PIM neighbors did not come up'
        failMsg(err, tech_support, tc_name='pim_007_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])

@pytest.fixture(scope="function")
def pim_func_006_cleanup(request,prologue_epilogue):

    yield
    debug_pim_failure()
    hdrMsg("### CLEANUP Start###")
    for vrf in vrf_list:
        if vrf != 'default':
            intf = data.d3tg_vlan_intf_vrf
        else:
            intf = data.d3tg_vlan_intf
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[0], source=[data.tgd1_ip,data.tgd2_ip],vrf=vrf,config='no')
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[1], source=[data.tgd1_ip, data.tgd2_ip], vrf=vrf,config='no')

    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)

    hdrMsg("### CLEANUP End####")

def test_pim_func_006(pim_func_006_cleanup):
    tc_list=['FtOpSoRoPimFunc010','FtOpSoRoPimFunc011']
    hdrMsg("FtOpSoRoPimFunc010 - Verify (S,G) tree for static multicast group")
    hdrMsg("FtOpSoRoPimFunc011 - Static and dynamic Groups for the same source.Delete readd static ,delete readd dynamic.")

    multicast_traffic(groups=data.ssm_group_list, source='S1')
    multicast_traffic(source='S2', groups=data.ssm_group_list)
    multicast_traffic(vrf=vrf_name, groups=data.ssm_group_list)
    multicast_traffic(source='S2', vrf=vrf_name, groups=data.ssm_group_list)

    tx_stream_list_1_default = [data.stream_handles['{}_S1_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_1_vrf   = [data.stream_handles['{}_S1_{}'.format(group,vrf_name)] for group in data.ssm_group_list]
    tx_stream_list_2_default = [data.stream_handles['{}_S2_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_2_vrf = [data.stream_handles['{}_S2_{}'.format(group,vrf_name)] for group in data.ssm_group_list]

    ##################################################################
    hdrMsg("Step T1: Configure static group {} on LHR1 (D3) from source {} and {}".format(data.ssm_group_list,data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        if vrf != 'default':
            intf = data.d3tg_vlan_intf_vrf
        else:
            intf = data.d3tg_vlan_intf
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[0], source=[data.tgd1_ip,data.tgd2_ip],vrf=vrf)
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[1], source=[data.tgd1_ip, data.tgd2_ip], vrf=vrf)
    ##################################################################
    hdrMsg("Step T2: Verify IGMP groups/sources table in LHR1")
    ##################################################################
    entry_cnt = data.ssm_groups

    result = igmp_api.verify_ip_igmp(data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=data.ssm_group_list*entry_cnt,mode=['INCL']*len(data.ssm_group_list)*entry_cnt,
                                     source_count=['2']*len(data.ssm_group_list)*entry_cnt,version=['3']*len(data.ssm_group_list)*entry_cnt,vrf='all')
    if result is False:
        st.report_fail('test_case_failure_message','IGMP Group entries not programmed on LHR2')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',interface=[data.d3tg_vlan_intf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf='default')
    if result is False:
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR2')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',interface=[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf=vrf_name)
    if result is False:
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR2')


    ##################################################################
    hdrMsg("Step T3:LHR1: Verify mroute entry gets programmed for all multicast groups with IIF as rpf nexthop interface for Source")
    ##################################################################
    src_list = [data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt+[data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt
    iif_list_lhr1 = [data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt

    result = pim_api.verify_ip_mroute(data.dut3,source=src_list,group=data.ssm_group_list*4,proto=['IGMP']*4*entry_cnt
                                      ,iif=iif_list_lhr1,
                                      oif=[data.d3tg_vlan_intf[0]]*2*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,vrf='all')
    if result is False:
        st.report_fail('test_case_failure_message','Mroute entries not programmed in LHR1 pointing to FHR1 and FHR2')


    ##################################################################
    hdrMsg("Step T4:LHR1: Verify PIM state on LHR1 node and verify all (S,G) entries are installed")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut3,cmd_type='state',vrf='all',installed=['1']*entry_cnt*4,source=src_list,
                                     group=data.ssm_group_list*4,
                                     iif=iif_list_lhr1,
                                     oif=[[data.d3tg_vlan_intf[0]]]*2*entry_cnt+[[data.d3tg_vlan_intf_vrf[0]]]*2*entry_cnt,flag=[['I']]*entry_cnt*4)
    if result is False:
        st.report_fail('test_case_failure_message', 'PIM states are incorrect in LHR1')

    ##################################################################
    hdrMsg("Step T4:LHR1: Verify PIM join is sent to FHR1(D1) and FHR2(D2) on all VRFs")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut3,cmd_type='upstream',vrf='all',source=src_list,group=data.ssm_group_list*4,
                                     iif=iif_list_lhr1,state=['J']*4*entry_cnt)

    if result is False:
        st.report_fail('test_case_failure_message', 'LHR1 did not send PIM join upstream to FHR1')

    ##################################################################
    hdrMsg("Step T5:FHR1& FHR2: Verify PIM state and verify join is received from LHR1")
    ##################################################################

    dict1 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'oif':[[data.d3d1_vlan_intf[0]]]*entry_cnt+[[data.d3d1_vlan_intf_vrf[0]]]*entry_cnt,'flag':[['J']]*entry_cnt*2}
    dict2 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'oif':[[data.d3d2_lag_intf_1]]*entry_cnt+[[data.d3d2_lag_intf_2]]*entry_cnt,'flag':[['J']]*entry_cnt*2}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR1 or FHR2 node')

    dict1 = {'cmd_type':'join','vrf':'all','source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'interface':[data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt,'state':['JOIN']*2*entry_cnt}
    dict2 = {'cmd_type':'join','vrf':'all','source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'interface':[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt,'state':['JOIN']*2*entry_cnt}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        st.report_fail('test_case_failure_message', 'PIM  JOIN info incorrect in FHR1 or FHR2 node')


    ##################################################################
    hdrMsg("Step T6:FHR1: Verify Mroute programming on FHR1 node with correct OIFs and IIFs")
    ##################################################################

    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt,'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d2tg_ports[0]]*entry_cnt+[data.d2tg_ports[1]]*entry_cnt,
             'oif':[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt,'vrf':'all',
             'installed':['*']*2*entry_cnt}


    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        st.report_fail('test_case_failure_message', 'OIF/IIF entries incorrect on FHR1 /FHR2')
    ##################################################################
    hdrMsg("Step T7:Verify multicast stream forwarding only from both Sources S1,S2 for multicast groups on default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failed for default-vrf ')


    ##################################################################
    hdrMsg("Step T8:Verify multicast stream forwarding for multicast groups on {} from both sources S1 and S2".format(vrf_name))
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1],data.tgd2_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failure for {}'.format(vrf_name))

    ##################################################################
    hdrMsg("Step T9: Send IGMPv3 Report for same static groups from R1 connected to LHR1 "
           "(D3) to join groups {} from source {} and {}".format(data.ssm_group_list,data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='join')

    ##################################################################
    hdrMsg("Step T10:Verify multicast stream forwarding from both Sources S1,S2 for multicast groups on default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failed for default-vrf ')

    ##################################################################
    hdrMsg("Step T11:Verify multicast stream forwarding for multicast groups on {} from both sources S1 and S2".format(vrf_name))
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1],data.tgd2_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        st.report_fail('test_case_failure_message', 'Multicast traffic from S2 to R1 failed for user-vrf ')
    ##################################################################
    hdrMsg("Step T12: Send IGMPv3 Leave from R3 connected to LHR2 (D4)Blocking both Sources S1 {} and S2 {} ".format(data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include',vrf=vrf, mode='leave')

    ##################################################################
    hdrMsg("Step T13:Verify multicast stream forwarding works because of static entries for multicast groups on default-vrf")
    ##################################################################


    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failed for default-vrf ')

    ##################################################################
    hdrMsg("Step T14:Remove all static multicast groups on default and user-vrf from R1 connected to LHR1")
    ##################################################################
    st.log("\n Getting initial PRUNE_TX count on LHR1 towards FHR1 \n")
    initial_prune_tx = get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d1_vlan_intf[0],vrf='default')
    initial_prune_tx_vrf = get_packet_count(data.dut3, pkt_type='prune_tx',interface=data.d3d1_vlan_intf_vrf[0],vrf=vrf_name)

    st.log("\n Getting initial PRUNE_TX count towards FHR2 \n")
    initial_prune_tx_1 = get_packet_count(data.dut3,pkt_type='prune_tx',interface=data.d3d2_lag_intf_1,vrf='default')
    initial_prune_tx_vrf_1 = get_packet_count(data.dut3, pkt_type='prune_tx', interface=data.d3d2_lag_intf_2,vrf=vrf_name)

    for vrf in vrf_list:
        if vrf != 'default':
            intf = data.d3tg_vlan_intf_vrf
        else:
            intf = data.d3tg_vlan_intf
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[0], source=[data.tgd1_ip,data.tgd2_ip],vrf=vrf,config='no')
        igmp_api.config_igmp(dut=data.dut3, intf=intf, join='yes', group=data.ssm_group_list[1], source=[data.tgd1_ip, data.tgd2_ip], vrf=vrf,config='no')
    ##################################################################
    hdrMsg("Step T15: Verify IGMP source table is empty on LHR1 after sending Leave report from R1")
    ##################################################################

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',return_output='',vrf='all')
    if result is False :
        st.report_fail('test_case_failure_message', 'Multicast sources not removed from igmp table on LHR1')


    ##################################################################
    hdrMsg("Step T12: Verify mroute entry gets deleted in LHR1 ")
    ##################################################################
    output = pim_api.verify_ip_mroute(data.dut3,return_output='')
    if len(output) != 0:
        st.report_fail('test_case_failure_message','Mroute entry not deleted on LHR1 for {},{}'.format(data.ssm_group_list,data.tgd1_ip))

    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def pim_008_fixture(request,prologue_epilogue):

    yield
    ##################################################################
    hdrMsg("Cleanup for func_008")
    ##################################################################
    group_list = [data.asm_group_list[0],data.ssm_group_list[0]]
    asm_nw = data.asm_group_list[0].split('.')[0]
    ssm_nw = data.ssm_group_list[0].split('.')[0]
    incr_val = int(ssm_nw) - int(asm_nw)
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],filter='include', vrf=vrf,
                           mode='leave',group_incr_ip='{}.0.0.0'.format(incr_val),group_incr=incr_val,group_prefix_len='8')
    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.execute_command(data.dut3, config='no')
    pim_api.config_ip_multicast_boundary(data.dut3,intf=data.d3tg_vlan_intf[0],oil_prefix_list="igmp_oil_prefix",config='no')
    pim_api.config_ip_multicast_boundary(data.dut3, intf=data.d3tg_vlan_intf_vrf[0], oil_prefix_list="igmp_oil_prefix",config='no')
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='',query_interval='',config='no')
    intf_api.interface_properties_set(data.dut3, interfaces_list=data.d3tg_ports[0], property='mtu', value='9100')
    data.tg1.tg_traffic_config(mode='modify',length_mode='fixed',frame_size='128',
                           stream_id=data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])])

    ##################################################################
    hdrMsg("Cleanup for func_008 End")
    ##################################################################

def test_pim_func_008(pim_008_fixture):
    tc_list = [ 'FtOpSoRoPimFunc018','FtOpSoRoPimFunc019','FtOpSoRoPimFunc020','FtOpSoRoPimFunc021','FtOpSoRoPimFunc050' ,'FtOpSoRoPimNe002']
    err_list =[]
    tc_result = True
    tech_support = data.tech_support_on_fail
    multicast_traffic(groups=data.ssm_group_list[0])
    multicast_traffic(groups=data.ssm_group_list[0],vrf=vrf_name)

    tx_stream_list_1_default = data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])]
    tx_stream_list_1_vrf   = data.stream_handles['{}_S1_{}'.format(data.ssm_group_list[0],vrf_name)]

    ##################################################################
    hdrMsg("Step T1: Configure Genreal query interval to minimum vlaue of 2 sec on IGMP enabled ports")
    ##################################################################
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='10')
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],query_interval='2')

    ##################################################################
    hdrMsg("Step T2: Send IGMP join for multicast group {} from 2 Receivers R1 and R2 towards LHR1(D3)".format(data.ssm_group_list[0]))
    ##################################################################

    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[data.tgd1_ip],filter='include',vrf=vrf,mode='join')
        send_igmpv3_report(host='R2', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include', vrf=vrf, mode='join')
    if 'ixia' in data.tgen_type:
        igmp_api.clear_igmp_interfaces(data.dut3, vrf='default')
        igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf_name)
        for vrf in vrf_list:
            send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[data.tgd1_ip],filter='include',vrf=vrf,mode='join',remove_others='no')
            send_igmpv3_report(host='R2', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include', vrf=vrf, mode='join',remove_others='no')
    ##################################################################
    hdrMsg("Step T3: Verify multicast groups are learnt on IGMP table on all VRFs")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='groups',
                       interface=[data.d3tg_vlan_intf[0]] + [data.d3tg_vlan_intf_vrf[0]],
                       group=[data.ssm_group_list[0]]*2, mode=['INCL'] * 2,
                       source_count=['1','1'],version=['3','3'], vrf='all')
    if result is False:
        err = 'IGMP groups are not learnt on LHR1'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='sources',
                       interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]] ,
                       group=[data.ssm_group_list[0]]*2, source=[data.tgd1_ip]*2,vrf='all')

    if result is False:
        err = 'IGMP sources are not learnt on LHR1'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T4: Send Leave for multicast group from one of the receivers R2")
    ##################################################################

    for vrf in vrf_list: send_igmpv3_report(host='R2', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include', vrf=vrf, mode='leave')


    ##################################################################
    hdrMsg("Step T5: Verify IGMP groups still present since DUT sends GSSQ query and R1 responds")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='groups',
                       interface=[data.d3tg_vlan_intf[0]] + [data.d3tg_vlan_intf_vrf[0]],
                       group=[data.ssm_group_list[0]]*2, mode=['INCL'] * 2,
                       source_count=['1','1'],version=['3','3'], vrf='all')
    if result is False:
        err = 'GSSQ not sent out by LHR node upon receving leave from one of the receivers'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='sources',
                       interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]] ,
                       group=[data.ssm_group_list[0]]*2, source=[data.tgd1_ip]*2,vrf='all')

    if result is False:
        err = 'GSSQ not sent out by LHR node upon receving leave from one of the receivers'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc018", "tc_passed")


    ##################################################################
    hdrMsg("Step T6: Verify Multicast traffic not impacted for other active receiver R1")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio=1,
                                  tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Mutlicast traffic not forwarded to receiver R1 after sending leave from R2 on default vrf'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]], dest_port=data.tgd3_ports[1],exp_ratio=1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]])
    if result is False:
        err = 'Mutlicast traffic not forwarded to receiver R1 after sending leave from R2 on user vrf'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc050", "tc_passed")
    ##################################################################
    hdrMsg("Step T7: Send Leave for multicast group from R1 also and verify IGMP table removed the group entries ")
    ##################################################################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='leave')

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',return_output='',vrf='all')
    if result is False:
        err = 'IGMP sources not removed from LHR after receing Leave from last receiver '
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    group_list = [data.asm_group_list[0],data.ssm_group_list[0]]
    asm_nw = data.asm_group_list[0].split('.')[0]
    ssm_nw = data.ssm_group_list[0].split('.')[0]
    incr_val = int(ssm_nw) - int(asm_nw)

    multicast_traffic(groups=group_list)
    multicast_traffic(groups=group_list,vrf=vrf_name)

    ##################################################################
    hdrMsg("Step T8: Configure prefix list to permit multicast groups {} and configure it to LHR tgen interfaces facing igmp host".format(group_list))
    ##################################################################
    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_permit_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_permit_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')

    pim_api.config_ip_multicast_boundary(data.dut3,intf=data.d3tg_vlan_intf[0],oil_prefix_list="igmp_oil_prefix")
    pim_api.config_ip_multicast_boundary(data.dut3, intf=data.d3tg_vlan_intf_vrf[0], oil_prefix_list="igmp_oil_prefix")

    ##################################################################
    hdrMsg("Step T9: Send IGMP join for both groups {} and verify IGMP report gets processed".format(group_list))
    ##################################################################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='join',group_incr_ip='{}.0.0.0'.format(incr_val),group_incr=incr_val,group_prefix_len='8')

    entry_cnt = len(group_list)

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all')
    if result is False:
        err='IGMP Group entries not programmed on LHR1'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T10: Modify Prefix-list to allow IGMP joins only for SSM prefix and verify IGMPv3 report rejected for ASM ")
    ##################################################################
    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_permit_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')

    st.log("\n############## Verify ASM groups gets timeout after GMI expiry  #################\n")

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all',entry=[False,True]*2)
    if result is False:
        err='IGMP group {} not denied as per mulitcast oil prefix-list'.format(group_list[0])
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T11: Modify Prefix-list to allow IGMP joins only for ASM prefix and verify IGMPv3 report rejected for SSM ")
    ##################################################################

    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_permit_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')

    st.log("\n############## Verify ASM groups gets timeout after GMI expiry  #################\n")

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all',entry=[True,False]*2)
    if result is False:
        err='IGMP group {} not denied as per mulitcast oil prefix-list'.format(group_list[1])
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T12: Modify Prefix-list to deny both SSM and ASM groups range and verify all groups are removed from IGMP table")
    ##################################################################

    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')

    st.log("\n############## Verify ASM groups gets timeout after GMI expiry  #################\n")

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',return_output='',vrf='all')
    if result is False:
        err='IGMP groups {} not denied as per mulitcast oil prefix-list'.format(group_list)
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc020", "tc_passed")
    ##################################################################
    hdrMsg("Step T13: Delete Prefix-list and verify all IGMP reports are processed")
    ##################################################################
    prefix_list.execute_command(data.dut3, config='no')

    st.log("\n############## Verify ASM groups gets timeout after GMI expiry  #################\n")

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all')
    if result is False:
        err='IGMP groups {} not learnt after deleting prefix-list'.format(group_list)
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T14: Reconfigure Prefix-list with deny all and verify igmp reports are discarded")
    ##################################################################

    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')

    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',return_output='',vrf='all')
    if result is False:
        err='IGMP groups {} not denied as per mulitcast oil prefix-list'.format(group_list)
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T15: Remove prefix-list config from interface and verify igmp reports are processed")
    ##################################################################
    pim_api.config_ip_multicast_boundary(data.dut3,intf=data.d3tg_vlan_intf[0],oil_prefix_list="igmp_oil_prefix",config='no')
    pim_api.config_ip_multicast_boundary(data.dut3, intf=data.d3tg_vlan_intf_vrf[0], oil_prefix_list="igmp_oil_prefix",config='no')
    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all')
    if result is False:
        err='IGMP groups {} not learnt after removing prefix-list from igmp interfaces'.format(group_list)
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    ##################################################################
    hdrMsg("Step T16: Modify Prefix-list to allow only SSM range and re-apply it on igmp interfaces")
    ##################################################################
    prefix_list = ip_api.PrefixList("igmp_oil_prefix")
    prefix_list.add_match_deny_sequence('{}.0.0.0/8'.format(asm_nw), seq_num='10', ge='32')
    prefix_list.add_match_permit_sequence('{}.0.0.0/8'.format(ssm_nw), seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')
    pim_api.config_ip_multicast_boundary(data.dut3,intf=data.d3tg_vlan_intf[0],oil_prefix_list="igmp_oil_prefix")
    pim_api.config_ip_multicast_boundary(data.dut3, intf=data.d3tg_vlan_intf_vrf[0], oil_prefix_list="igmp_oil_prefix")

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=group_list*entry_cnt,mode=['INCL']*len(group_list)*entry_cnt,
                                     source_count=['1']*len(group_list)*entry_cnt,version=['3']*len(group_list)*entry_cnt,vrf='all',entry=[False,True]*2)
    if result is False:
        err='IGMP group {} not denied as per mulitcast oil prefix-list'.format(group_list[0])
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T17: Verify multicast traffic forwarded only for SSM group for default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio=1,
                                  tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Mutlicast traffic failure on default-vrf'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    ##################################################################
    hdrMsg("Step T18: Verify multicast traffic forwarded only for SSM group for user-vrf")
    ##################################################################
    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]], dest_port=data.tgd3_ports[1],exp_ratio=1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]])
    if result is False:
        err = 'Mutlicast traffic failure on user-vrf'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc019", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimFunc021", "tc_passed")

    ##################################################################
    hdrMsg("Step T19: Modify  Multiast stream size to 2000 bytes for {}".format(data.ssm_group_list[0]))
    ##################################################################

    data.tg1.tg_traffic_config(mode='modify',length_mode='fixed',frame_size='2000',
                               stream_id=data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])])



    ##################################################################
    hdrMsg("Step T20: COnfigure MTU size to 1550 bytes on LHR1 egress interfaces ")
    ##################################################################

    intf_api.interface_properties_set(data.dut3,interfaces_list=data.d3tg_ports[0],property='mtu',value='1550')

    ##################################################################
    hdrMsg("Step T21: Verify L3 multcast data traffic not gets fragemented and packets dropped ")
    ##################################################################
    multicast_traffic(groups=data.ssm_group_list[0])
    st.wait(5)
    multicast_traffic(groups=data.ssm_group_list[0],action='stop')
    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio=0,mode='aggregate',
                                  comp_type='oversize_count',delay=0.5,tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Mutlicast traffic getting fragmented'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    ##################################################################
    hdrMsg("Step T22: Revert MTU size to 9100 bytes on LHR1 egress interfaces and verify multicast packets of 2000 bytes gets forwarded ")
    ##################################################################

    intf_api.interface_properties_set(data.dut3, interfaces_list=data.d3tg_ports[0], property='mtu', value='9100')
    multicast_traffic(groups=data.ssm_group_list[0])
    st.wait(5)
    multicast_traffic(groups=data.ssm_group_list[0],action='stop')
    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio=1,mode='aggregate',
                                  comp_type='oversize_count',delay=0.5,tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Mutlicast traffic with jumbo 2000 bytes size dropped'
        failMsg(err, tech_support, tc_name='pim_008_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimNe002", "tc_passed")

    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failure_message', err_list[0])



def pim_func_009_cleanup():
    hdrMsg("### CLEANUP Start###")
    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='leave')
        send_igmpv3_report(host='R3', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include', vrf=vrf, mode='leave')
    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)

    hdrMsg("### CLEANUP End####")

def config_test_009(config='yes'):
    for vrf in ['default','_vrf']:
        if vrf == 'default':
            key_append = ''
            dut3_vlan_list = data['d3_vlan_id'][3]
            tg_port = data.d3tg_ports[0]
        else:
            key_append = '_vrf'
            dut3_vlan_list = data['d3_vlan_id_vrf'][3]
            tg_port = data.d3tg_ports[1]

        vlan_int = data['d3tg_vlan_intf' + key_append][0]

        data.query_int = 12
        data.query_max_resp = 20
        dict1 = {'intf': data['d3tg_vlan_intf' + key_append][0], 'igmp_enable': '','query_interval': data.query_int , 'query_max_response': data.query_max_resp,'config': config}
        if config == 'yes':
            vlan_api.create_vlan(data.dut4, dut3_vlan_list)
            ###################################################################
            hdrMsg("Vlan-Config: Configure a tagged Vlan member between D3 and D4 on vlan {}".format(dut3_vlan_list))
            ###################################################################
            utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut3, dut3_vlan_list, [data.d3d4_ports[0]], True],
                                  [vlan_api.add_vlan_member, data.dut4, dut3_vlan_list, [data.d4d3_ports[0]], True]])
            # Configure IP and enable PIM
            if vrf != 'default':
                vrf_api.bind_vrf_interface(data.dut4,vrf_name = vrf_name,intf_name = vlan_int, skip_error = True,config= config)

            ip_api.config_ip_addr_interface(data.dut4,vlan_int,data.d3tg_ip_2,data.mask)
            dict2 = {'intf': vlan_int, 'igmp_enable': '', 'config': 'no'}
            parallel.exec_parallel(True, [data.dut4, data.dut3], igmp_api.config_igmp, [dict1, dict2])
            pim_api.config_intf_pim(data.dut4, pim_enable = '', intf = vlan_int, config = config)
        else:
            pim_api.config_intf_pim(data.dut4, pim_enable = '', intf = vlan_int, config = config)
            dict2 = {'intf': vlan_int, 'igmp_enable': '', 'config': 'yes'}
            parallel.exec_parallel(True, [data.dut4, data.dut3], igmp_api.config_igmp, [dict1, dict2])
            ip_api.delete_ip_interface(data.dut4, vlan_int, data.d3tg_ip_2, data.mask)
            if vrf != 'default':
                vrf_api.bind_vrf_interface(data.dut4,vrf_name = vrf_name,intf_name = vlan_int, skip_error = True,config= config)
            pim_func_009_cleanup()
            ###################################################################
            hdrMsg("Vlan-Config: Configure a tagged Vlan member between D3 and D4 on vlan {}".format(dut3_vlan_list))
            ###################################################################
            utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut3, dut3_vlan_list, [data.d3d4_ports[0]], True,'',True],
                                  [vlan_api.delete_vlan_member, data.dut4, dut3_vlan_list, [data.d4d3_ports[0]], True,'',True]])
            vlan_api.delete_vlan(data.dut4, dut3_vlan_list)

        # Disable IGMP on D3 - IGMP joins sent from tgen are redirected to D4.

        if config == 'yes':
            dict2 = {'intf': vlan_int, 'igmp_enable': '', 'config': 'no'}
            parallel.exec_parallel(True, [data.dut4, data.dut3], igmp_api.config_igmp, [dict1, dict2])
        else:
            igmp_api.config_igmp(data.dut3,intf= vlan_int, igmp_enable= '', config= 'yes')
            #intf_api.interface_noshutdown(data.dut3, data.d3tg_ports)
            pim_func_009_cleanup()

    hdrMsg("### Config test 009 End####")

@pytest.fixture(scope="function")
def pim_func_009_fixture(request,prologue_epilogue):
    config_test_009(config='yes')
    yield
    config_test_009(config='no')


def test_pim_func_009(pim_func_009_fixture):
    tc_list=['FtOpSoRoPimFunc028','FtOpSoRoPimFunc029','FtOpSoRoPimFunc031','FtOpSoRoPimFunc032']
    err_list =[]
    tc_result = True
    tech_support = data.tech_support_on_fail

    # Learn IGMP groups from port connected to D4 instead of tgen.
    # To simulate max response time expiry - after receiving reports shut port tgen port on D4
    # Configure Tgen port on D4 with same set of groups as on D3.

    multicast_traffic(groups=data.ssm_group_list, source='S1')
    multicast_traffic(source='S2', groups=data.ssm_group_list)
    multicast_traffic(vrf=vrf_name, groups=data.ssm_group_list)
    multicast_traffic(source='S2', vrf=vrf_name, groups=data.ssm_group_list)

    tx_stream_list_1_default = [data.stream_handles['{}_S1_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_1_vrf   = [data.stream_handles['{}_S1_{}'.format(group,vrf_name)] for group in data.ssm_group_list]
    tx_stream_list_2_default = [data.stream_handles['{}_S2_default'.format(group)] for group in data.ssm_group_list]
    tx_stream_list_2_vrf = [data.stream_handles['{}_S2_{}'.format(group,vrf_name)] for group in data.ssm_group_list]

    ##################################################################
    hdrMsg("Step T1: Send IGMPv3 Report from R1 connected to LHR1 (D3) to join groups {} from source {} and {}".format(data.ssm_group_list,data.tgd1_ip,data.tgd2_ip))
    ##################################################################
    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='join')
    ##################################################################
    hdrMsg("Step T2: Verify IGMP groups/sources table in LHR1")
    ##################################################################
    entry_cnt = data.ssm_groups

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='groups',interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                                     group=data.ssm_group_list*entry_cnt,mode=['INCL']*len(data.ssm_group_list)*entry_cnt,
                                     source_count=['2']*len(data.ssm_group_list)*entry_cnt,version=['3']*len(data.ssm_group_list)*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Group entries not programmed on LHR1')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d3tg_vlan_intf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf='default')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf=vrf_name)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    ##################################################################
    hdrMsg("Step T3:LHR1: Verify mroute entry gets programmed for all multicast groups with IIF as rpf nexthop interface for Source")
    ##################################################################
    src_list = [data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt+[data.tgd1_ip]*entry_cnt+[data.tgd2_ip]*entry_cnt
    iif_list_lhr1 = [data.d3d1_vlan_intf[0]]*entry_cnt+[data.d3d2_lag_intf_1]*entry_cnt+[data.d3d1_vlan_intf_vrf[0]]*entry_cnt+[data.d3d2_lag_intf_2]*entry_cnt

    result = pim_api.verify_ip_mroute(data.dut4,source=src_list,group=data.ssm_group_list*4,proto=['IGMP']*4*entry_cnt,
                                      oif=[data.d3tg_vlan_intf[0]]*2*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,vrf='all')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','Mroute entries not programmed in LHR1 pointing to FHR1 and FHR2')

    ##################################################################
    hdrMsg("Step T4:LHR1: Verify PIM state on LHR1 node and verify all (S,G) entries are installed")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut4,cmd_type='state',vrf='all',installed=['1']*entry_cnt*4,source=src_list,
                                     group=data.ssm_group_list*4,
                                     oif=[[data.d3tg_vlan_intf[0]]]*2*entry_cnt+[[data.d3tg_vlan_intf_vrf[0]]]*2*entry_cnt,flag=[['I']]*entry_cnt*4)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM states are incorrect in LHR1')

    ##################################################################
    hdrMsg("Step :LHR1: Verify PIM join is sent to FHR1(D1) and FHR2(D2) on all VRFs")
    ##################################################################
    result = pim_api.verify_pim_show(data.dut4,cmd_type='upstream',vrf='all',source=src_list,group=data.ssm_group_list*4,
                                     state=['J']*4*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'LHR1 did not send PIM join upstream to FHR1')

    ##################################################################
    hdrMsg("Step T5:FHR1& FHR2: Verify PIM state and verify JOIN is received from LHR1")
    ##################################################################

    dict1 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd1_ip]*2*entry_cnt,
             'group':data.ssm_group_list*2, 'flag':[['J']]*entry_cnt*2}
    dict2 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd2_ip]*2*entry_cnt,
             'group':data.ssm_group_list*2,'flag':[['J']]*entry_cnt*2}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR1 or FHR2 node')

    dict1 = {'cmd_type':'join','vrf':'all','source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'state':['JOIN']*2*entry_cnt}
    dict2 = {'cmd_type':'join','vrf':'all','source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'state':['JOIN']*2*entry_cnt}

    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN info incorrect in FHR1 or FHR2 node')

    ##################################################################
    hdrMsg("Step T7:Verify multicast stream forwarding only from both Sources S1,S2 for multicast groups on default-vrf")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0],data.tgd2_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default,tx_stream_list_2_default])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failed for default-vrf ')


    ##################################################################
    hdrMsg("Step T8:Verify multicast stream forwarding for multicast groups on {} fromboth sources S1 and S2".format(vrf_name))
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1],data.tgd2_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf,tx_stream_list_2_vrf])
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast traffic from S1 to R1 failure for {}'.format(vrf_name))
    # Shutdown D4 Receiver port
    #intf_api.interface_shutdown(data.dut3,data.d3tg_ports)

    vlan_api.delete_vlan_member(data.dut3, data['d3_vlan_id'][3], data.d3d4_ports[0],True)
    vlan_api.delete_vlan_member(data.dut3, data['d3_vlan_id_vrf'][3], data.d3d4_ports[0],True)

    ##################################################################
    hdrMsg("Step T9: Stop Reports from Receiver and wait for query_max_response.")
    ##################################################################
    st.log("\n Getting initial PRUNE_TX count on LHR1 towards FHR1 \n")
    initial_prune_tx = get_packet_count(data.dut4,pkt_type='prune_tx',interface=data.d4d2_vlan_intf[0],vrf='default')
    initial_prune_tx_vrf = get_packet_count(data.dut4, pkt_type='prune_tx',interface=data.d4d2_vlan_intf_vrf[0],vrf=vrf_name)

    st.log("\n Getting initial PRUNE_TX count towards FHR2 \n")
    initial_prune_tx_1 = get_packet_count(data.dut4,pkt_type='prune_tx',interface=data.d4d1_ports[0],vrf='default')
    initial_prune_tx_vrf_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[1],vrf=vrf_name)
    #st.wait(data.query_max_resp)

    ##################################################################
    hdrMsg("Step T10: Verify IGMP source table is empty on LHR1 after sending Leave report from R1")
    ##################################################################
    retry_cnt = data.query_max_resp / 2
    result = retry_null_output(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',return_output='',vrf='all',retry_count=retry_cnt,delay=3)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'Multicast sources not removed from igmp table on LHR1')

    ##################################################################
    hdrMsg("Step T11: Verify LHR1 sent out PIM prune on interface towards FHR1,FHR2")
    ##################################################################
    st.log("\n Getting  PRUNE_TX count on LHR1 towards FHR1\n")
    final_prune_tx =  get_packet_count(data.dut4,pkt_type='prune_tx',interface=data.d4d2_vlan_intf[0],vrf='default')
    final_prune_tx_vrf = get_packet_count(data.dut4, pkt_type='prune_tx',interface=data.d4d2_vlan_intf_vrf[0],vrf=vrf_name)

    st.log("\n Getting PRUNE_TX count towards FHR2 \n")
    final_prune_tx_1 = get_packet_count(data.dut4,pkt_type='prune_tx',interface=data.d4d1_ports[0],vrf='default')
    final_prune_tx_vrf_1 = get_packet_count(data.dut4, pkt_type='prune_tx', interface=data.d4d1_ports[1],vrf=vrf_name)

    if int(final_prune_tx) == int(initial_prune_tx):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR1')

    if int(final_prune_tx_vrf) == int(initial_prune_tx_vrf):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR1 on user-vrf')

    if int(final_prune_tx_1) == int(initial_prune_tx_1):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR2')

    if int(final_prune_tx_vrf_1) == int(initial_prune_tx_vrf_1):
        st.report_fail('test_case_failure_message','Prune TX id not increment on LHR1 node towards FHR2 on user-vrf')

    ##################################################################
    hdrMsg("Step T12: Verify mroute entry gets deleted in LHR1 ")
    ##################################################################
    output = pim_api.verify_ip_mroute(data.dut4,return_output='')
    #intf_api.interface_noshutdown(data.dut3,data.d3tg_ports)
    vlan_api.add_vlan_member(data.dut3, data['d3_vlan_id'][3], data.d3d4_ports[0],True)
    vlan_api.add_vlan_member(data.dut3, data['d3_vlan_id_vrf'][3], data.d3d4_ports[0],True)

    if len(output) != 0:
        st.report_fail('test_case_failure_message','Mroute entry not deleted on LHR1 for {},{}'.format(data.ssm_group_list,data.tgd1_ip))

    # Wait for next GQ towards Receivers.
    #st.wait(data.query_int)
    ##################################################################
    hdrMsg("Step : Verify IGMP groups/sources table in LHR1")
    ##################################################################
    entry_cnt = data.ssm_groups
    retry_cnt = data.query_int
    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='groups',
                       interface=[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
                       group=data.ssm_group_list*entry_cnt,mode=['INCL']*len(data.ssm_group_list)*entry_cnt,
                       source_count=['2']*len(data.ssm_group_list)*entry_cnt,version=['3']*len(data.ssm_group_list)*entry_cnt,vrf='all',
                       retry_count=retry_cnt,delay= 3)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Group entries not programmed on LHR1')

    #################################################################################################################
    hdrMsg("Step : Get IGMP Query count before sending Leave on both default and non default VRF.")
    #################################################################################################################
    pre_gq_cnt = []
    post_gq_cnt = []
    for key_append in ['', '_vrf']:
        if key_append != '':
            vrf = vrf_name
        else:
            vrf = 'default'
        parsed_output1 = igmp_api.verify_igmp_stats(data.dut4, vrf=vrf, return_output=1,skip_error=True)

        if len(parsed_output1) == 0 :
            err = "show command output is Empty"
            failMsg(err);
            tc_result = False;
            err_list.append(err)

        # Workaround for unicode data
        #print(parsed_output1)
        parsed_output1 = ast.literal_eval(json.dumps(parsed_output1))[0]
        #print(parsed_output1)
        pre_gq_cnt.append(int(parsed_output1['query_v3']))


    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d3tg_vlan_intf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf='default')
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    result = retry_api(igmp_api.verify_ip_igmp,data.dut4,cmd_type='sources',interface=[data.d3tg_vlan_intf_vrf[0]]*2*entry_cnt,
                                     group=data.ssm_group_list*2*entry_cnt,source =[data.tgd1_ip,data.tgd2_ip]*2*entry_cnt,vrf=vrf_name)
    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message','IGMP Source entries not programmed on LHR1')

    ##################################################################
    hdrMsg("Step :LHR1: Verify PIM join is sent to FHR1(D1) and FHR2(D2) on all VRFs")
    ##################################################################

    result = pim_api.verify_pim_show(data.dut4,cmd_type='upstream',vrf='all',source=src_list,group=data.ssm_group_list*4,
                                     state=['J']*4*entry_cnt)

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'LHR1 did not send PIM join upstream to FHR1')

    ##################################################################
    hdrMsg("Step :FHR1& FHR2: Verify PIM state and verify join is received from LHR1")
    ##################################################################

    dict1 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd1_ip]*2*entry_cnt,
             'group':data.ssm_group_list*2, 'flag':[['J']]*entry_cnt*2}
    dict2 = {'cmd_type':'state','vrf':'all','installed':['1']*entry_cnt*2,'source':[data.tgd2_ip]*2*entry_cnt,
             'group':data.ssm_group_list*2,'flag':[['J']]*entry_cnt*2}


    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN not received  in FHR1 or FHR2 node')

    dict1 = {'cmd_type':'join','vrf':'all','source':[data.tgd1_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'state':['JOIN']*2*entry_cnt}
    dict2 = {'cmd_type':'join','vrf':'all','source':[data.tgd2_ip]*2*entry_cnt,'group':data.ssm_group_list*2,
             'state':['JOIN']*2*entry_cnt}
    result = retry_parallel(pim_api.verify_pim_show,dict_list=[dict1,dict2],dut_list=[data.dut1,data.dut2])

    if result is False:
        debug_pim_failure()
        st.report_fail('test_case_failure_message', 'PIM  JOIN info incorrect in FHR1 or FHR2 node')

    for vrf in vrf_list:  send_igmpv3_report(host='R1',groups=data.ssm_group_list,sources=[data.tgd1_ip,data.tgd2_ip],filter='include',vrf=vrf,mode='leave')
    for vrf in vrf_list:  send_igmpv3_report(host='R3', groups=data.ssm_group_list, sources=[data.tgd1_ip,data.tgd2_ip], filter='include', vrf=vrf, mode='leave')
    i = 0
    for key_append in ['', '_vrf']:
        if key_append != '':
            vrf = vrf_name
        else:
            vrf = 'default'
        parsed_output1 = igmp_api.verify_igmp_stats(data.dut4, vrf=vrf, return_output=1,skip_error=True)

        if len(parsed_output1) == 0 :
            err = "show command output is Empty"
            failMsg(err);
            tc_result = False;
            err_list.append(err)

        # Workaround for unicode data
        #print(parsed_output1)
        parsed_output1 = ast.literal_eval(json.dumps(parsed_output1))[0]
        #print(parsed_output1)
        post_gq_cnt.append(int(parsed_output1['query_v3']))
        if pre_gq_cnt[i] == post_gq_cnt[i]:
            st.report_fail('test_case_failure_message', 'Last member query count is not 2.')
        i += 1

    st.log("============== IGMP GQ count :")
    st.log(pre_gq_cnt)
    st.log(post_gq_cnt)

    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def pim_011_fixture(request,prologue_epilogue):

    yield
    ####################################
    hdrMsg("Cleanup started")
    ####################################
    group_list = [data.asm_group_list[0], data.ssm_group_list[0]]
    incr_val = int(data.ssm_group_list[0].split('.')[0]) - int(data.asm_group_list[0].split('.')[0])
    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)
    prefix_list = ip_api.PrefixList("ssm_list")
    prefix_list.execute_command(data.dut3, config='no')
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='leave',
                                            group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                                            group_prefix_len='8')
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='',
                         query_interval='', config='no')
    ####################################
    hdrMsg("Cleanup End")
    ####################################

@pytest.mark.run_tc
def test_pim_func_011(pim_011_fixture):
    tc_list = ['FtOpSoRoPimCli001','FtOpSoRoPimFunc006','FtOpSoRoPimFunc013','FtOpSoRoPimFunc014']
    err_list = []
    tc_result = True
    tech_support = data.tech_support_on_fail
    group_list = [data.asm_group_list[0], data.ssm_group_list[0]]
    asm_nw = '{}.0.0.0/8'.format(data.asm_group_list[0].split('.')[0])
    ssm_nw = '{}.0.0.0/8'.format(data.ssm_group_list[0].split('.')[0])
    incr_val = int(data.ssm_group_list[0].split('.')[0]) - int(data.asm_group_list[0].split('.')[0])
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='10')
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],query_interval='2')
    ##################################################################
    hdrMsg("Step T1:Verify default SSM range is 232.0.0.0/8")
    ##################################################################
    for vrf in vrf_list:
        result = pim_api.verify_pim_ssm_range(data.dut3,vrf=vrf)
        if result is False:
            err = 'Default SSM groups range is incorrect for {}'.format(vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T2:Verify {} is in SSM type and {} filtered as ASM by default".format(data.ssm_group_list[0],data.asm_group_list[0]))
    ##################################################################
    for vrf in vrf_list:
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='SSM',vrf=vrf)
        if result is False:
            err = ' {} not filtered as SSM for {}'.format(data.ssm_group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='ASM',vrf=vrf)
        if result is False:
            err = ' {} not filtered as ASM for {}'.format(data.asm_group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T3: Configure prefix list to use {} as SSM and apply it under PIM instance".format(asm_nw))
    ##################################################################
    prefix_list = ip_api.PrefixList("ssm_list")
    prefix_list.add_match_permit_sequence('225.0.0.0/8', seq_num='10', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')
    ##################################################################
    hdrMsg("Step T4:Verify prefix list is applied")
    ##################################################################
    for vrf in vrf_list :
        pim_api.config_pim_global(data.dut3, ssm_prefix_list='ssm_list', vrf=vrf)
        result = pim_api.verify_pim_ssm_range(data.dut3, group_range='ssm_list',vrf=vrf)
        if result is False:
            err = 'Configured ssm prefix-list not applied under pim for {}'.format(vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T5:Verify {} is in SSM type and {} filtered as ASM after applying prefix-list".format(data.asm_group_list[0],data.ssm_group_list[0]))
    ##################################################################
    for vrf in vrf_list:
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='ASM',vrf=vrf)
        if result is False:
            err = '{} not filtered as ASM after applying ssm prefix-list for {}'.format(group_list[1],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='SSM',vrf=vrf)
        if result is False:
            err = '{} not filtered as SSM after applying ssm prefix-list for {}'.format(group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T6:Modify SSM prefix-list to allow both prefixes {} and {} as ssm".format(asm_nw,ssm_nw))
    ##################################################################
    prefix_list = ip_api.PrefixList("ssm_list")
    prefix_list.add_match_permit_sequence('225.0.0.0/8', seq_num='10', ge='32')
    prefix_list.add_match_permit_sequence('232.0.0.0/8', seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')
    ##################################################################
    hdrMsg("Step T7: Verify {} and {} selected as SSM after modifying prefix-list".format( data.asm_group_list[0], data.ssm_group_list[0]))
    ##################################################################
    for vrf in vrf_list:
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='SSM',vrf=vrf)
        if result is False:
            err = ' {} not selected as SSM after modifying ssm preix-list for {}'.format(group_list[1],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='SSM',vrf=vrf)
        if result is False:
            err = ' {} not selected as SSM after modifying ssm preix-list for {}'.format(group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T8: Delete the prefix-list and verify SSM prefix reverts to default SSM group rage")
    ##################################################################
    prefix_list.execute_command(data.dut3, config='no')
    for vrf in vrf_list:
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='SSM',vrf=vrf)
        if result is False:
            err = '{} not selected as SSM after deleting ssm prefix-list for {}'.format(group_list[1],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='ASM',vrf=vrf)
        if result is False:
            err = '{} not selected as ASM after deleting SSM prefix-list for {}'.format(group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    ##################################################################
    hdrMsg("Step T9: Re-configure SSM prefix-list to allow both prefixes {} and {} as ssm".format(asm_nw,ssm_nw))
    ##################################################################
    prefix_list = ip_api.PrefixList("ssm_list")
    prefix_list.add_match_permit_sequence('225.0.0.0/8', seq_num='10', ge='32')
    prefix_list.add_match_permit_sequence('232.0.0.0/8', seq_num='20', ge='32')
    prefix_list.execute_command(data.dut3, config='yes')
    for vrf in vrf_list :
        pim_api.config_pim_global(data.dut3, ssm_prefix_list='ssm_list', vrf=vrf)
    ##################################################################
    hdrMsg("Step T10: Verify {} and {} selected as SSM after modifying prefix-list".format( data.asm_group_list[0], data.ssm_group_list[0]))
    ##################################################################
    for vrf in vrf_list:
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='SSM',vrf=vrf)
        if result is False:
            err = '{} not selected as SSM after delete and reconfiguring ssm prefix-list for {}'.format(group_list[1],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='SSM',vrf=vrf)
        if result is False:
            err = '{} not selected as SSM after delete and reconfiguring ssm prefix-list for {}'.format(group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    ##################################################################
    hdrMsg("Step T11:Remove the prefix-list config from PIM instances and verify default SSM-group ranges selected for SSM")
    ##################################################################
    for vrf in vrf_list : pim_api.config_pim_global(data.dut3, ssm_prefix_list='ssm_list', vrf=vrf,config='no')

    for vrf in vrf_list:
        result = pim_api.verify_pim_ssm_range(data.dut3,vrf=vrf)
        if result is False:
            err = 'Default 232.0.0.0/8 range not selected after removing ssm prefix list from pim for {}'.format(vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[1], group_type='SSM',vrf=vrf)
        if result is False:
            err = '{} not selected as SSM after removing ssm prefix-list from pim for {}'.format(group_list[1],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
        result = pim_api.verify_pim_group_type(data.dut3, group=group_list[0], group_type='ASM',vrf=vrf)
        if result is False:
            err = '{} not selected as ASM after removing ssm prefix-list from pim for {}'.format(group_list[0],vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc006", "tc_passed")

    st.log("########### Start Multicast data traffic for both ASM and SSM group ranges ##############")
    multicast_traffic(groups=group_list)
    multicast_traffic(groups=group_list, vrf=vrf_name)
    tx_stream_list_1_default = [data.stream_handles['{}_S1_default'.format(group)] for group in group_list]
    tx_stream_list_1_vrf   = [data.stream_handles['{}_S1_{}'.format(group,vrf_name)] for group in group_list]

    ##################################################################
    hdrMsg("Step T11:Enable ECMP paths towards multicast source on BGP and PIM on all VRF instances")
    ##################################################################
    for vrf in vrf_list:  bgp_api.config_bgp(data.dut3,config_type_list=["max_path_ebgp"],max_path_ebgp=2,vrf_name=vrf,local_as=data.d3_as)
    for vrf in vrf_list: pim_api.config_pim_global(data.dut3,vrf=vrf,ecmp='',ecmp_rebalance='')
    ##################################################################
    hdrMsg("Step T12: Send IGMP join for both groups {} and verify IGMP report gets processed".format(group_list))
    ##################################################################
    for vrf in vrf_list: send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='join',
                                            group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                                            group_prefix_len='8')

    entry_cnt = len(group_list)

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='groups',
                       interface=[data.d3tg_vlan_intf[0]] * entry_cnt + [data.d3tg_vlan_intf_vrf[0]] * entry_cnt,
                       group=group_list * entry_cnt, mode=['INCL'] * len(group_list) * entry_cnt,
                       source_count=['1'] * len(group_list) * entry_cnt, version=['3'] * len(group_list) * entry_cnt,
                       vrf='all')
    if result is False:
        err = 'IGMP Group entries not programmed on LHR1'
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        for vrf in vrf_list:  bgp_api.config_bgp(data.dut3, config_type_list=["max_path_ebgp"], max_path_ebgp=1,
                                                 vrf_name=vrf, local_as=data.d3_as)
        for vrf in vrf_list: pim_api.config_pim_global(data.dut3, vrf=vrf, ecmp='', ecmp_rebalance='', config='no')
        data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)
        prefix_list.execute_command(data.dut3, config='no')
        for vrf in vrf_list:
            send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                               filter='include', vrf=vrf, mode='leave',
                               group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                               group_prefix_len='8')
        igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]],
                             query_max_response='',
                             query_interval='', config='no')
        st.report_fail('test_case_failure_message', err)

    ##################################################################
    hdrMsg("Step T13: Verify multicast groups are load shared across ecmp paths for rpf lookup")
    ##################################################################
    group_iif = {}
    for vrf in vrf_list:
        output = pim_api.verify_pim_show(data.dut3,cmd_type ='rpf',return_output='',vrf=vrf)
        if len(output) != 0:
            iif =[]
            for i in range(len(output)):
                iif.append(output[i]['rpfiface'])
                group_iif['{}_{}'.format(vrf,output[i]['group'])] = iif[i]
            if len(set(iif)) > 1:
                st.log("Both ECMP paths used for RPF lookup")
            else:
                err = 'ECMP paths are not load-shared for {}'.format(vrf)
                failMsg(err, tech_support, tc_name='pim_011_onfail');
                tech_support = False;
                tc_result = False;
                err_list.append(err)
        else:
            err = 'RPF nexthop not resolved for {}'.format(vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            for vrf in vrf_list:  bgp_api.config_bgp(data.dut3, config_type_list=["max_path_ebgp"], max_path_ebgp=1,
                                                     vrf_name=vrf, local_as=data.d3_as)
            for vrf in vrf_list: pim_api.config_pim_global(data.dut3, vrf=vrf, ecmp='', ecmp_rebalance='', config='no')
            data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)
            prefix_list.execute_command(data.dut3, config='no')
            for vrf in vrf_list:
                send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                   filter='include', vrf=vrf, mode='leave',
                                   group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                                   group_prefix_len='8')
            igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]],
                                 query_max_response='',
                                 query_interval='', config='no')
            st.report_fail('test_case_failure_message', err)
    ##################################################################
    hdrMsg("Step T14: Verify mroute entries on LHR and FHR node programmed correctl on LHR and FHR nodes")
    ##################################################################
    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['IGMP']*2*entry_cnt,
             'oif':[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
             'iif':[group_iif['default_{}'.format(group_list[0])],group_iif['default_{}'.format(group_list[1])],
                    group_iif['{}_{}'.format(vrf_name,group_list[0])],group_iif['{}_{}'.format(vrf_name,group_list[1])]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[group_iif['default_{}'.format(group_list[0])],group_iif['default_{}'.format(group_list[1])],
                    group_iif['{}_{}'.format(vrf_name,group_list[0])],group_iif['{}_{}'.format(vrf_name,group_list[1])]],'vrf':'all',
             'installed':['*']*2*entry_cnt}


    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])
    if result is False:
        err = "PIM Mroute entries are incorrect with ecmp enabled"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    ##################################################################
    hdrMsg("Step T15:Verify multicast traffic across ecmp paths on default and user-vrf")
    ##################################################################
    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 with ecmp enabled on default-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 with ecmp enabled on usr-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T16:shutdown one of the ecmp paths and verify all multicast groups uses {},{}"
           " as rpf nexthop".format(data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]))
    ##################################################################
    port_api.shutdown(data.dut3,[data.d3d1_ports[2]])

    ##################################################################
    hdrMsg("Step T17: Verify mroute entries on LHR and FHR node programmed correctl on LHR and FHR nodes")
    ##################################################################
    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['IGMP']*2*entry_cnt,
             'oif':[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
             'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])
    if result is False:
        err = "PIM Mroute entries are incorrect with ecmp enabled"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)


    ##################################################################
    hdrMsg("Step T18:Verify multicast traffic fowarding after shutting one of the ecmp paths")
    ##################################################################
    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 after shutting one of the ecmp paths on default-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 after shutting one of the ecmp paths on usr-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                           filter='include', vrf=vrf, mode='leave',
                           group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                           group_prefix_len='8')
    ##################################################################
    hdrMsg("Step T19:Bring back the ecmp link and verify multicast RPF lookup uses both ecmp paths for RPF lookup")
    ##################################################################
    port_api.noshutdown(data.dut3, [data.d3d1_ports[2]])
    for vrf in vrf_list:
        st.log("Verify PIM neighbors are up")
        dict1 = {'cmd_type': 'neighbor', 'neighbor': data.d3_nbrs, 'vrf':vrf}
        dict2 = {'cmd_type': 'neighbor', 'neighbor': data.d1_nbrs, 'vrf':vrf}
        dict_list = [dict1,dict2]
        result = retry_parallel(pim_api.verify_pim_show,dict_list,[data.dut3,data.dut1], retry_count=12,delay=3)
        if result is False:
            err = "PIM neighbors not up after ECMP link flap on {}".format(vrf)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    st.log("########### Clear igmp/mroute entries and Re-send IGMP joins ################## ")
    for vrf in vrf_list:
        igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf)
        pim_api.clear_mroute(data.dut3,vrf=vrf)
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                           filter='include', vrf=vrf, mode='join',
                           group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                           group_prefix_len='8',remove_others='no')

    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['IGMP']*2*entry_cnt,
             'oif':[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
             'iif':[group_iif['default_{}'.format(group_list[0])],group_iif['default_{}'.format(group_list[1])],
                    group_iif['{}_{}'.format(vrf_name,group_list[0])],group_iif['{}_{}'.format(vrf_name,group_list[1])]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[group_iif['default_{}'.format(group_list[0])],group_iif['default_{}'.format(group_list[1])],
                    group_iif['{}_{}'.format(vrf_name,group_list[0])],group_iif['{}_{}'.format(vrf_name,group_list[1])]],'vrf':'all',
             'installed':['*']*2*entry_cnt}


    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])
    if result is False:
        err = "PIM Mroute entries are incorrect with ecmp enabled"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T20:Verify multicast traffic after bringing up the ECMP links")
    ##################################################################

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_default])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 after bringing back ecmp paths on default-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[tx_stream_list_1_vrf])
    if result is False:
        err = "Multicast traffic faied from S1 to R1 after bringing back ecmp paths on user-vrf"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    ##################################################################
    hdrMsg("Step T21:Disable PIM ecmp and verify rpf lookup uses only one nexthop for all mutlicast groups")
    ##################################################################

    for vrf in vrf_list: pim_api.config_pim_global(data.dut3, vrf=vrf, ecmp='', ecmp_rebalance='',config='no')
    for vrf in vrf_list: igmp_api.clear_igmp_interfaces(data.dut3,vrf=vrf)
    """
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='leave',
                                            group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                                            group_prefix_len='8')
        send_igmpv3_report(host='R1', groups=group_list, sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='join',
                                            group_incr_ip='{}.0.0.0'.format(incr_val), group_incr=incr_val,
                                            group_prefix_len='8',remove_others='no')
    """
    dict1 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['IGMP']*2*entry_cnt,
             'oif':[data.d3tg_vlan_intf[0]]*entry_cnt+[data.d3tg_vlan_intf_vrf[0]]*entry_cnt,
             'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    dict2 = {'source':[data.tgd1_ip]*2*entry_cnt,'group':group_list*2,'proto':['PIM']*2*entry_cnt,
             'iif':[data.d1tg_ports[0]]*entry_cnt+[data.d1tg_ports[1]]*entry_cnt,
             'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all',
             'installed':['*']*2*entry_cnt}

    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])
    if result is False:
        err = "PIM Mroute entries are incorrect with ecmp disabled"
        failMsg(err, tech_support, tc_name='pim_011_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    for vrf in vrf_list:  bgp_api.config_bgp(data.dut3, config_type_list=["max_path_ebgp"], max_path_ebgp=1,
                                            vrf_name=vrf, local_as=data.d3_as)
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc013", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimFunc014", "tc_passed")

    ##################################################################
    hdrMsg("Step T23:Verify out of range values are rejected for PIM global commands")
    ##################################################################
    err_msg1 = '% Unknown command'
    err_msg = "nown command"
    join_prune = [59,601];keep_alive=[30,60001];pim_pkt=[0,101]
    for val in join_prune:
        output = pim_api.config_pim_global(data.dut3,join_prune_interval=val,skip_error=True)
        if  err_msg not in output:
            err = "join_prune_interval command did not fail with invalid value {}".format(val)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    for val in keep_alive:
        output = pim_api.config_pim_global(data.dut3,keep_alive=val,skip_error=True)
        if  err_msg not in output:
            err = "keep_alive_interval command did not fail with invalid value {}".format(val)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    for val in pim_pkt:
        output = pim_api.config_pim_global(data.dut3,packets=val,skip_error=True)
        if  err_msg not in output:
            err = "pim packets command did not fail with invalid value {}".format(val)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    ##################################################################
    hdrMsg("Step T24:Verify out of range values are rejected for PIM interface commands")
    ##################################################################
    dr_prio =[0,4294967296];hello=[0,256]
    for val in dr_prio:
        output = pim_api.config_intf_pim(data.dut3,intf=data.d3tg_vlan_intf[0],drpriority=val,skip_error=True)
        if  err_msg not in output:
            err = "pim DR-priority command did not fail with invalid value {}".format(val)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)
    for val in hello:
        output = pim_api.config_intf_pim(data.dut3,intf=data.d3tg_vlan_intf[0],hello_intv=val,skip_error=True)
        if  err_msg not in output:
            err = "pim hello interval command did not fail with invalid value {}".format(val)
            failMsg(err, tech_support, tc_name='pim_011_onfail');
            tech_support = False;
            tc_result = False;
            err_list.append(err)

    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimCli001", "tc_passed")

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    st.report_pass('test_case_passed')


def test_pim_func_014(prologue_epilogue):
    tc_list = ['FtOpSoRoPimFunc053']
    err_list = []
    tc_result = True
    tech_support = data.tech_support_on_fail
    ##################################################################
    hdrMsg("Step T1: Send static igmp join from LHR node")
    ##################################################################
    igmp_api.config_igmp(data.dut3, intf=data.d3tg_vlan_intf[0], source=data.tgd1_ip, group=data.ssm_group_list[0], join='')
    st.wait(2)
    ##################################################################
    hdrMsg("Step T2:Verify Multicast traceroute towards {} succeeds from LHR1".format(data.tgd1_ip))
    ##################################################################

    output = pim_api.mtrace(data.dut3, source=data.tgd1_ip, group=data.ssm_group_list[0])

    ip1 = data.d3d1_ip[0];
    ip2 = data.d1d3_ip[0];
    pim_pattern = 'PIM (S,G)'
    if ip1 not in output or ip2 not in output or pim_pattern not in output:
        err = "Mtrace toward source {} failed ".format(data.tgd1_ip)
        failMsg(err, tech_support, tc_name='pim_014_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)
    ##################################################################
    hdrMsg("Step T3:Verify Multicast traceroute towards {} on FHR1 succeeds via multihop(D2-FHR2) from LHR1".format(
        data.tgd1_ip))
    ##################################################################
    bgp_api.config_bgp(data.dut3, local_as=data.d3_as, config='yes', config_type_list=["redist"],
                       redistribute='connected', addr_family="ipv4")
    port_api.shutdown(data.dut3, data.d3d1_ports)
    st.wait(2)
    output = pim_api.mtrace(data.dut3, source=data.tgd1_ip, group=data.ssm_group_list[0])

    ip1 = data.d3d2_ip;
    ip2 = data.d2d3_ip;
    ip4 = data.d1d2_ip
    if ip1 not in output or ip2 not in output or ip4 not in output or pim_pattern not in output:
        err = "Mtrace toward source {} failed via dut2".format(data.tgd1_ip)
        failMsg(err, tech_support, tc_name='pim_014_onfail');
        tech_support = False;
        tc_result = False;
        err_list.append(err)

    bgp_api.config_bgp(data.dut3, local_as=data.d3_as, config='no', config_type_list=["redist"],
                       redistribute='connected', addr_family="ipv4")
    port_api.noshutdown(data.dut3, data.d3d1_ports[0:2])
    st.wait(3)
    port_api.noshutdown(data.dut3, [data.d3d1_ports[2]])

    ##################################################################
    hdrMsg("Step T4: Remove static igmp groups from LHR")
    ##################################################################
    igmp_api.config_igmp(data.dut3, intf=data.d3tg_vlan_intf[0], source=data.tgd1_ip, group=data.ssm_group_list[0], join='',
                         config='no')

    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    st.report_pass('test_case_passed')

def config_test_012(config='yes'):
    hdrMsg("### Config Start###")
    for vrf in vrf_list:
        if vrf == 'default':
            d3d4_int = data.d3d4_vlan_intf[0]
            dummy_int_dut4 = data.d2d4_vlan_intf[0]
            dummy_int_dut3 = data.d3tg_vlan_intf[0]

        else:
            d3d4_int = data.d3d4_vlan_intf_vrf[0]
            dummy_int_dut4 = data.d2d4_vlan_intf_vrf[0]
            dummy_int_dut3 = data.d3tg_vlan_intf_vrf[0]

        dict1 = []
        dict2 = []

        for intf in [dummy_int_dut3, dummy_int_dut4]:
            dict1.append({'intf': intf, 'join': 'yes','igmp_enable':'', 'group' : data.ssm_group_list[0], 'source' : [data.tgd1_ip],'vrf' : vrf, 'config':config})
            dict2.append({'pim_enable': '', 'intf': intf, 'config':config})
        parallel.exec_parallel(True, [data.dut3, data.dut4], igmp_api.config_igmp, dict1)
        dict3 = {'intf': d3d4_int, 'join': 'yes','igmp_enable':'', 'group' : data.ssm_group_list[0], 'source' : [data.tgd1_ip],'vrf' : vrf, 'config':config}
        parallel.exec_parallel(True, [data.dut3, data.dut4], igmp_api.config_igmp, [dict3]*2)
        #parallel.exec_parallel(True, [data.dut3, data.dut4], pim_api.config_intf_pim, dict2)

    if config == 'no':
        igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],igmp_enable='')
        #    pim_api.config_intf_pim(data.dut3,pim_enable='',intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],igmp_enable='')
    data.tg1.tg_traffic_control(action='stop',stream_handle=data.stream_list)

    hdrMsg("### Config End####")

@pytest.fixture(scope="function")
def pim_012_fixture(request,prologue_epilogue):
    ##################################################################
    hdrMsg("PIM neighbors before start of the TC.")
    ##################################################################

    dict = {'vrf' : 'all', 'cmd_type':'neighbor','skip_error':'True','return_output':''}
    parallel.exec_parallel(True, data.dut_list, pim_api.verify_pim_show, [dict]*len(data.dut_list))
    config_test_012()
    yield
    config_test_012(config='no')
    ##################################################################
    hdrMsg("PIM neighbors After of the TC Run.")
    ##################################################################

    dict = {'vrf' : 'all', 'cmd_type':'neighbor','skip_error':True,'return_output':''}
    parallel.exec_parallel(True, data.dut_list, pim_api.verify_pim_show, [dict]*len(data.dut_list))

def test_pim_func_012(pim_012_fixture):
    tc_list = ['FtOpSoRoPimFunc017']
    err_list = []
    tc_result = True
    d3d4_int = data.d3d4_vlan_intf[0]
    d3d4_int_vrf = data.d3d4_vlan_intf_vrf[0]
    hdrMsg("FtOpSoRoPimFunc017 - Verify PIM Assert functionality")

    # Configure Static IGMP group (S1,G1) on DUT3,DUT4 Vlan towards Source
    ##################################################################
    hdrMsg("Step T1: Configure static group {} on LHR1 (D3) from source {} and {}".format(data.ssm_group_list,data.tgd1_ip,data.tgd2_ip))
    ##################################################################

    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',vrf='all',group=[data.ssm_group_list[0]]*2,version=['3','3'],
                       interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],retry_count=6,delay=2)
    if result is False:
        err = 'IGMP group entries not learnt'
        failMsg(err);
        err_list.append(err)
        tc_result=False
        st.report_fail('test_case_failure_message',err)

    stream_handle1 = [data.stream_handles['{}_{}_{}'.format(group, 'S1', vrf_list[0])] for group in [data.ssm_group_list[0]]]
    stream_handle2 = [data.stream_handles['{}_{}_{}'.format(group, 'S1', vrf_list[1])] for group in [data.ssm_group_list[0]]]

    data.tg1.tg_traffic_control(action='run', stream_handle=stream_handle1)
    data.tg1.tg_traffic_control(action='run', stream_handle=stream_handle2)

    # Workaround for unicode data
    result1 = result2 = False
    for i in range(0,10):
        port_api.shutdown(data.dut3, [data.d3d4_ports[0]])
        st.wait(2)
        port_api.noshutdown(data.dut3, [data.d3d4_ports[0]])
        st.wait(3)
        #result = retry_api(pim_api.verify_pim_show,data.dut4,cmd_type='interface traffic', interface=d3d4_int, vrf='default',assert_tx=1,retry_count=2,delay=2)
        parsed_output =  pim_api.verify_pim_show(data.dut4, cmd_type='interface traffic', interface=d3d4_int, vrf = 'all',return_output = "")
        parsed_output = ast.literal_eval(json.dumps(parsed_output))
        for output in parsed_output:
            if output['interface'] == d3d4_int_vrf and int(output['assert_tx']) > 0 :
                result2 = True;
            if output['interface'] == d3d4_int and int(output['assert_tx']) > 0:
                result1 = True;
        if result1 is True and result2 is True: break

    if result1 is False:
        err = "PIM Assert failed on Default VRF"
        failMsg(err);
        err_list.append(err);
        tc_result = False
        st.report_fail('test_case_failure_message', err)

    #result2 = pim_api.verify_pim_show(data.dut4, cmd_type='interface traffic', interface=d3d4_int_vrf,
    #                                  vrf=vrf_list[1], assert_tx=1)
    if result2 is False:
        err = "PIM Assert failed on User VRF"
        failMsg(err);
        err_list.append(err);
        tc_result = False
        st.report_fail('test_case_failure_message', err)

    st.report_pass('test_case_passed')


def test_pim_func_013(prologue_epilogue):
    tc_list = ['FtOpSoRoPimFunc028']
    hdrMsg("FtOpSoRoPimFunc028 - Verify pim join-prune-interval with non default values.")
    join_prune_int = 600
    join_prune_def = 60
    err_list = []
    tc_result = True

    # Config join prune interval
    pim_api.config_pim_global(data.dut4,join_prune_interval=join_prune_int)

    result = pim_api.verify_ip_multicast(data.dut4,upstream_join_timer=join_prune_int,skip_error=True)
    err_list = []
    if result is False :
        err = "Failed to validate configured global PIM Join-Prune value."
        failMsg(err); err_list.append(err); tc_result = False
    pim_api.config_pim_global(data.dut4,join_prune_interval=join_prune_int,config = 'no')
    result = pim_api.verify_ip_multicast(data.dut4,upstream_join_timer=join_prune_def,skip_error=True)
    if result is False :
        err = "Failed to reset to default Join-Prune value."
        failMsg(err); err_list.append(err); tc_result = False

    # Revert back config
    if tc_result is False:
        st.report_fail('test_case_failure_message', err_list[0])
    st.report_pass('test_case_passed')



@pytest.fixture(scope="function")
def pim_010_fixture(request,prologue_epilogue):

    yield
    ##################################################################
    hdrMsg("Cleanup Starts")
    ##################################################################
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], version='3')
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='',config='no')
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],query_interval='',config='no')
    st.log("Revert IGMP hosts on Tgen to V3")
    data.tg1.tg_emulation_multicast_group_config(mode='delete',handle=data.groups[data.ssm_group_list[0]])
    data.tg1.tg_emulation_igmp_config(handle=data.igmp_sessions['R1_default_igmp'], mode='modify',igmp_version='v3')
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream_list)
    dict1 = {'intf': data.d3d1_vlan_intf[0], 'oif': data.d3tg_vlan_intf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no','skip_error':True}

    dict2 = {'intf': data.d1tg_ports[0], 'oif': data.d3d1_vlan_intf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1, dict2])

    dict1 = {'intf': data.d3d1_vlan_intf_vrf[0], 'oif': data.d3tg_vlan_intf_vrf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no','skip_error':True}

    dict2 = {'intf': data.d1tg_ports[1], 'oif': data.d3d1_vlan_intf_vrf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1, dict2])
    ##################################################################
    hdrMsg("Cleanup End")
    ##################################################################


def test_pim_func_010(pim_010_fixture):
    tc_list= ['FtOpSoRoPimFunc047','FtOpSoRoPimFunc049','FtOpSoRoPimNe001']
    err_list= []
    tc_result = True
    tech_support = data.tech_support_on_fail

    port_api.noshutdown(data.dut3, data.d3d1_ports[0:2])
    port_api.noshutdown(data.dut3, [data.d3d1_ports[2]])
    pim_api.clear_mroute(data.dut3)
    pim_api.clear_mroute(data.dut3,vrf=vrf_name)
    pim_api.clear_mroute(data.dut1)
    pim_api.clear_mroute(data.dut1,vrf=vrf_name)

    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], query_max_response='10')
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],query_interval='2')

    ##################################################################
    hdrMsg("Step T1: Configure IGMP version to V2 and send IGMP join from TGEN to LHR1(D3) ")
    ##################################################################
    igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],version='2')

    ##################################################################
    hdrMsg("Step T2: Verify igmp version is set to 2 under the igmp interface and send IGMPv3 report")
    ##################################################################

    result = igmp_api.verify_igmp_interface(data.dut3,interface=data.d3tg_vlan_intf[0],version='2')
    if result is False:
        err = 'IGMP version not set to 2 for {}'.format(data.d3tg_vlan_intf[0])
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    result = igmp_api.verify_igmp_interface(data.dut3, interface=data.d3tg_vlan_intf_vrf[0], version='2',vrf=vrf_name)
    if result is False:
        err = 'IGMP version not set to 2 for {}'.format(data.d3tg_vlan_intf_vrf[0])
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[data.tgd1_ip],filter='include',vrf=vrf,mode='join')
    if 'ixia' in data.tgen_type:
        igmp_api.clear_igmp_interfaces(data.dut3, vrf='default')
        igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf_name)
        pim_api.clear_mroute(data.dut1)
        pim_api.clear_mroute(data.dut1, vrf=vrf_name)
        for vrf in vrf_list:
            send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include',
                               vrf=vrf, mode='join',remove_others='no')

    ##################################################################
    hdrMsg("Step T3: Verify IGMPv3 report processed as V2 and mroute (*,G) entry gets created in igmp source table")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',vrf='all',interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],group=[data.ssm_group_list[0]]*2,version=['2','2'])
    if result is False:
        err = 'IGMP group entries incorrect after setting version to 2'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='sources',vrf='all',source=['*']*2,group=[data.ssm_group_list[0]]*2,interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]])
    if result is False:
        err = '(*,G) entry not created under igmp source table'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False


    ##################################################################
    hdrMsg("Step T5:Configure static mroute on FHR and LHR and verify static mroute gets programmed")
    ##################################################################

    dict1= {'intf':data.d3d1_vlan_intf[0],'oif':data.d3tg_vlan_intf[0],'source':data.tgd1_ip,'group':data.ssm_group_list[0]}

    dict2 = {'intf': data.d1tg_ports[0],'oif': data.d3d1_vlan_intf[0],'source': data.tgd1_ip, 'group': data.ssm_group_list[0]}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])


    dict1= {'intf':data.d3d1_vlan_intf_vrf[0],'oif':data.d3tg_vlan_intf_vrf[0],'source':data.tgd1_ip,'group':data.ssm_group_list[0]}

    dict2 = {'intf': data.d1tg_ports[1],'oif': data.d3d1_vlan_intf_vrf[0],'source': data.tgd1_ip, 'group': data.ssm_group_list[0]}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])



    dict1 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['STATIC']*2,'installed':['*']*2,
             'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]] ,'oif':[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['STATIC']*2,'installed':['*']*2,
             'iif':[data.d1tg_ports[0],data.d1tg_ports[1]] ,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}

    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])

    if result is False:
        err = 'Static mroute entries are not programmed on LHR1 and FHR1'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result = False

    ##################################################################
    hdrMsg("Step T6:Verify Multicast traffic gets forwarded to IGMPv2 host with static mroute configured")
    ##################################################################
    multicast_traffic(groups=data.ssm_group_list[0])
    multicast_traffic(groups=data.ssm_group_list[0],vrf=vrf_name)
    tx_stream_list_1_default = data.stream_handles['{}_S1_default'.format(data.ssm_group_list[0])]
    tx_stream_list_1_vrf   = data.stream_handles['{}_S1_{}'.format(data.ssm_group_list[0],vrf_name)]

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[0]],dest_port=data.tgd3_ports[0],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_default]])
    if result is False:
        err = 'Multicast traffic failed with static mroute configuration on default vrf'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result = False

    result = verify_mcast_traffic(data.tg1,data.tg1,src_port=[data.tgd1_ports[1]],dest_port=data.tgd3_ports[1],exp_ratio= 1,
                                  tx_stream_list=[[tx_stream_list_1_vrf]])
    if result is False:
        err = 'Multicast traffic failed with static mroute configuration on user vrf'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result = False

    ##################################################################
    hdrMsg("Step T6:Delete static mroutes and verify mroute entries are removed")
    ##################################################################

    dict1 = {'intf': data.d3d1_vlan_intf[0], 'oif': data.d3tg_vlan_intf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no'}

    dict2 = {'intf': data.d1tg_ports[0], 'oif': data.d3d1_vlan_intf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no'}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1, dict2])

    dict1 = {'intf': data.d3d1_vlan_intf_vrf[0], 'oif': data.d3tg_vlan_intf_vrf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no'}

    dict2 = {'intf': data.d1tg_ports[1], 'oif': data.d3d1_vlan_intf_vrf[0], 'source': data.tgd1_ip,
             'group': data.ssm_group_list[0],'config':'no'}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1, dict2])


    dict1 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['STATIC']*2,'installed':['*']*2,
             'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]] ,'oif':[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['STATIC']*2,'installed':['*']*2,
             'iif':[data.d1tg_ports[0],data.d1tg_ports[1]] ,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}

    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1],retry_count=1)
    if result is True:
        err = 'Static mroute entries are not removed from mroute table after deleting'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result = False

    ##################################################################
    hdrMsg("Step T7: Revert back the version to 3 on LHR1")
    ##################################################################
    igmp_api.config_igmp(data.dut3, intf=[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]], version='3')
    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include',
                           vrf=vrf, mode='leave')
        send_igmpv3_report(host='R1', groups=data.ssm_group_list[0], sources=[data.tgd1_ip], filter='include',
                           vrf=vrf, mode='join')

    ##################################################################
    hdrMsg("Step T9: Verify igmp version is set to 3 under the igmp interface ")
    ##################################################################

    result = igmp_api.verify_igmp_interface(data.dut3,interface=data.d3tg_vlan_intf[0],version='3')
    if result is False:
        err = 'IGMP version not set to 3 for {}'.format(data.d3tg_vlan_intf[0])
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    result = igmp_api.verify_igmp_interface(data.dut3, interface=data.d3tg_vlan_intf_vrf[0], version='3',vrf=vrf_name)
    if result is False:
        err = 'IGMP version not set to 3 for {}'.format(data.d3tg_vlan_intf_vrf[0])
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False


    ##################################################################
    hdrMsg("Step T10: Verify IGMPv3 report processed as V3 and mroute (S,G) entry gets created in igmp source table")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',vrf='all',group=[data.ssm_group_list[0]]*2,version=['3','3'],
                       interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],retry_count=6,delay=2)
    if result is False:
        err = 'IGMP group entries incorrect after setting version to 3'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='sources',vrf='all',interface=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],
                       source=[data.tgd1_ip]*2,group=[data.ssm_group_list[0]]*2)
    if result is False:
        err = '(S,G) entry not created under igmp source table after changing version from V2 to V3'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    ##################################################################
    hdrMsg("Step T11: Verify (S,G) entries are programmed in mroute upon receiving igmpv3 report")
    ##################################################################

    dict1 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['IGMP']*2,'installed':['*']*2,
             'iif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]] ,'oif':[data.d3tg_vlan_intf[0], data.d3tg_vlan_intf_vrf[0]],'vrf':'all'}
    dict2 = {'source':[data.tgd1_ip]*2,'group':[data.ssm_group_list[0]]*2,'proto':['PIM']*2,'installed':['*']*2,
             'iif':[data.d1tg_ports[0],data.d1tg_ports[1]] ,'oif':[data.d3d1_vlan_intf[0],data.d3d1_vlan_intf_vrf[0]],'vrf':'all'}

    result = retry_parallel(pim_api.verify_ip_mroute,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut1])
    if result is False:
        err = 'mroute entries are not programmed on LHR1 and FHR1 after changing version from V2 to V3'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result = False


    ##################################################################
    hdrMsg("Step T12: Send IGMPv3 Leave for the multicast groups")
    ##################################################################

    for vrf in vrf_list:
        send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[data.tgd1_ip],filter='include',vrf=vrf,mode='leave')


    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc049", "tc_passed")

    ##################################################################
    hdrMsg("Step T13: Send IGMPv2 Join towards LHR that has IGMPv3 version configured and verify join is processed as (*,G)")
    ##################################################################

    st.log("Modify TGEN host to version 2 and send ASM join")
    data.tg1.tg_emulation_igmp_config(handle=data.igmp_sessions['R1_default_igmp'], mode='modify',igmp_version='v2')

    send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[],filter='include',vrf='default',mode='join')

    ##################################################################
    hdrMsg("Step T14: Verify IGMPv2 report are processed on interface configured with version 3")
    ##################################################################
    result = retry_api(igmp_api.verify_ip_igmp,data.dut3,cmd_type='groups',group=[data.ssm_group_list[0]],version=['2'])
    if result is False:
        err = 'IGMPv2 report are not processed on interface configured with version 3'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False

    result = retry_api(igmp_api.verify_ip_igmp, data.dut3, cmd_type='sources',source=['*'],group=[data.ssm_group_list[0]])
    if result is False:
        err = 'IGMPv2 report are not processed on interface configured with version 3'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False


    send_igmpv3_report(host='R1',groups=data.ssm_group_list[0],sources=[],filter='include',vrf='default',mode='leave')
    if tc_result is True:
        st.report_tc_pass("FtOpSoRoPimFunc047", "tc_passed")

    ##################################################################
    hdrMsg("Step T16: Try to configure static mroute with OIF and IIF as same interface and verify command throjiws error")
    ##################################################################

    result = pim_api.config_ip_mroute(data.dut3,intf= data.d3d1_vlan_intf[0],oif= data.d3d1_vlan_intf[0],source= data.tgd1_ip,group=data.ssm_group_list[0],skip_error=True)
    if 'Failed to add route' not in result:
        err = 'Mroute command with same OIF and IIF accepted without error'
        failMsg(err, tech_support, tc_name='pim_010_onfail');
        tech_support = False;
        err_list.append(err)
        tc_result=False
    else:
        st.report_tc_pass("FtOpSoRoPimNe001", "tc_passed")

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')


def test_pim_scale_001(prologue_epilogue):
    tc_list=['FtOpSoRoPimFun059','FtOpSoRoPimFunc060','FtOpSoRoPimFunc061','FtOpSoRoPimFunc062','FtOpSoRoPimSc001',
             'FtOpSoRoPimSc002','FtOpSoRoPimSc003','FtOpSoRoPimSt001','FtOpSoRoPimSt002','FtOpSoRoPimSt003']


    for dut in [data.dut1,data.dut3]:
        pim_api.clear_mroute(dut)
        pim_api.clear_mroute(dut,vrf=vrf_name)

    #for vrf in vrf_list: igmp_api.clear_igmp_interfaces(data.dut3,vrf=vrf)
    data.platform_list = []
    for dut in [data.dut1, data.dut3]:
        data.platform_list.append(basic_api.get_hwsku(dut))

    th1_type = 'Accton-AS7712-32X'
    th3_type = 'Accton-AS9716-32D'
    if th3_type in data.platform_list:
        data.dynamic_scale_count = 508
        data.max_mroutes = data.dynamic_scale_count + data.static_igmp + data.static_mroute
        data.max_igmp = data.dynamic_scale_count + data.static_mroute
        data.mroute_count_per_vrf = data.max_mroutes / 2

    data.maxtime = 2000

    data.group_list_scale =range_ipv4(data.ssm_group_list[0],count=data.mroute_count_per_vrf,mask=32)
    data.dynamic_group_list_scale = data.group_list_scale[0:data.dynamic_scale_count/2]
    data.igmp_static_groups = data.group_list_scale[data.dynamic_scale_count/2]
    data.static_mroute_groups = data.group_list_scale[-1]
    data.dest_mac_list_scale = [ip2mac(group) for group in data.group_list_scale]
    data.dest_mac_list_scale_spirent_1 = get_scale_mac_list_to_str(data.dest_mac_list_scale[:data.mroute_count_per_vrf/2])
    data.dest_mac_list_scale_spirent_2 = get_scale_mac_list_to_str(data.dest_mac_list_scale[data.mroute_count_per_vrf/2:])

    scale_pre_config()

    #############################################################
    hdrMsg("Step: Send IGMPv3 Reprot for 8k multicast groups (4k on default and 4k on user-vrf")
    #############################################################

    for vrf in vrf_list:
        send_igmpv3_report(host='R1', groups=data.dynamic_group_list_scale,sources=[data.tgd1_ip],
                                            filter='include', vrf=vrf, mode='join',group_incr_ip='0.0.0.1',
                                            group_incr='1',group_prefix_len='32')

    if data.tgen_type == 'ixia':
        for vrf in vrf_list:
            data.tg1.tg_topology_test_control(handle=data.host_handles['R1_{}'.format(vrf)], action='stop_protocol',
                                          stack='deviceGroup')
        for vrf in vrf_list:
            data.tg1.tg_topology_test_control(handle=data.host_handles['R1_{}'.format(vrf)], action='start_protocol',
                                          stack='deviceGroup')
    st.log("Wait for 10 sec for all 8k multicast routes to install")
    st.wait(10)
    #############################################################
    hdrMsg("Step: Send igmp join for groups {} using \"ip igmp join command on all VRFs\"".format(data.igmp_static_groups))
    #############################################################

    for intf in [data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]]:
        igmp_api.config_igmp(data.dut3,intf=intf,source=data.tgd1_ip,group=data.igmp_static_groups,join='')

    #############################################################
    hdrMsg("Step: Configure static mroutes for {} on both VRFs on both LHR and FHR nodes".format(data.static_mroute_groups))
    #############################################################

    dict1= {'intf':data.d3d1_vlan_intf[0],'oif':data.d3tg_vlan_intf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups}
    dict2 = {'intf': data.d1tg_ports[0],'oif': data.d3d1_vlan_intf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])


    dict1= {'intf':data.d3d1_vlan_intf_vrf[0],'oif':data.d3tg_vlan_intf_vrf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups}
    dict2 = {'intf': data.d1tg_ports[1],'oif': data.d3d1_vlan_intf_vrf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])

    #############################################################
    hdrMsg("Step: Verify PIM states with scaled config")
    #############################################################
    result,err = verify_pim_scale()
    if result is False:
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimSc001", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimSc002", "tc_passed")
        st.report_tc_pass("FtOpSoRoPimSc003", "tc_passed")

    #############################################################
    hdrMsg("Trigger: Disable/Enable PIM on interfaces...")
    #############################################################
    dict1 = []
    for intf_lst in [data.d1d3_vlan_intf_scale]*2:
        dict1.append({'pim_enable':'','intf':intf_lst,'config':'no','maxtime':data.maxtime})
    parallel.exec_parallel(True,[data.dut1,data.dut3],pim_api.config_intf_pim,dict1)
    dict1 = []
    for intf_lst in [data.d1d3_vlan_intf_scale]*2:
        dict1.append({'pim_enable':'','intf':intf_lst,'config':'yes','maxtime':data.maxtime})
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, dict1)
    dict1 = []
    for intf_lst in [data.d1d3_vlan_intf_scale[0:2] + data.d1d3_vlan_intf_vrf] * 2:
        dict1.append({'intf': intf_lst, 'config': 'yes', 'bfd_enable': 'yes','maxtime':data.maxtime})
    parallel.exec_parallel(True, [data.dut1, data.dut3], pim_api.config_intf_pim, dict1)

    for vrf in vrf_list: igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf)
    config_pim_params()

    result, err = verify_pim_scale()
    if result is False:
        err += ' after PIM disable/enable'
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimSt002", "tc_passed")

    #############################################################
    hdrMsg("Trigger: Link Flaps")
    #############################################################
    port_api.shutdown(data.dut3,data.d3d1_ports+data.d3d2_ports+data.d3d4_ports+data.d3tg_ports)
    port_api.noshutdown(data.dut3, data.d3d1_ports + data.d3d2_ports + data.d3d4_ports + data.d3tg_ports)
    for vrf in vrf_list: igmp_api.clear_igmp_interfaces(data.dut3, vrf=vrf)
    result, err = verify_pim_scale()
    if result is False:
        err += ' after link flap'
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimSt003", "tc_passed")


    #############################################################
    hdrMsg("Trigger: Config Save")
    #############################################################
    data.my_dut_list = [data.dut3, data.dut1]
    #utils.exec_all(True, [[bgp_api.enable_docker_routing_config_mode, dut] for dut in data.my_dut_list])
    utils.exec_all(True, [[reboot_api.config_save, dut] for dut in data.my_dut_list])
    utils.exec_all(True, [[reboot_api.config_save, dut, 'vtysh'] for dut in data.my_dut_list])

    #############################################################
    hdrMsg("Trigger: Fast Reboot ...")
    #############################################################
    utils.exec_all(True, [[st.reboot, dut, "fast"] for dut in data.my_dut_list])
    result,err = verify_pim_scale()
    if result is False:
        err += ' after Fastboot'
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimFun059", "tc_passed")

    #############################################################
    hdrMsg("Trigger: bgpd docker restart ...")
    #############################################################
    utils.exec_all(True, [[basic_api.service_operations_by_systemctl, dut, "bgp", "restart"] for dut in data.my_dut_list])
    dict1 = {'service':'bgp'}
    dict_list = [dict1] * 2
    result = retry_parallel(basic_api.get_system_status, dict_list, [data.dut3, data.dut1], retry_count=20, delay=2)
    if result:
        result, err = verify_pim_scale()
        if result is False:
            err += ' after bgp docker restart'
            scale_post_config()
            st.report_fail('test_case_failure_message',err)
        else:
            st.report_tc_pass("FtOpSoRoPimFunc062", "tc_passed")
    else:
        err = 'System did not come up after BGP docker restart'
        scale_post_config()
        st.report_fail('test_case_failure_message', err)

    #############################################################
    hdrMsg("Trigger: Config Reload ...")
    #############################################################
    utils.exec_all(True, [[reboot_api.config_reload, dut] for dut in data.my_dut_list])
    result, err = verify_pim_scale()
    if result is False:
        err += ' after Config Reload'
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc061", "tc_passed")


    #############################################################
    hdrMsg("Trigger: warm Reboot ...")
    #############################################################
    utils.exec_foreach(True, data.my_dut_list, reboot_api.config_warm_restart, oper="enable", tasks=["system", "bgp"])
    utils.exec_all(True, [[st.reboot, dut, "warm"] for dut in data.my_dut_list])
    result, err = verify_pim_scale()
    if result is False:
        err += ' after Warmboot'
        scale_post_config()
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_tc_pass("FtOpSoRoPimFunc060", "tc_passed")

    #############################################################
    hdrMsg("Modify Line-rate to 100 percent and verify multicast traffic is fine")
    #############################################################
    if data.tgen_type == 'ixia':
        line_rate = 100.0
    else:
        line_rate = 50.0
    data.tg1.tg_traffic_config(mode='disable', stream_id=data.stream_list)
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.scale_streams)
    data.tg1.tg_traffic_config(mode='modify', stream_id=data.scale_streams, rate_percent=line_rate)
    data.tg1.tg_traffic_control(action='run', stream_handle=data.scale_streams)
    #############################################################
    hdrMsg("Step: Verify Line-Rate Multicast traffic for all {} multicast groups on default-vrf".format(data.mroute_count_per_vrf))
    #############################################################

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[0]],
                                  dest_port=data.tgd3_ports[0], exp_ratio=1,delay=3,mode='aggregate')
    if result is False:
        data.tg1.tg_traffic_control(action='stop',stream_handle=data.scale_streams)
        data.tg1.tg_traffic_config(mode='modify', stream_id=data.scale_streams, rate_pps=data.traffic_rate)
        data.tg1.tg_traffic_config(mode='enable', stream_id=data.stream_list)
        err = 'Line-rate Multicast Traffic failed on default-vrf with {} mroute entries installed '.format(data.mroute_count_per_vrf)
        failMsg(err)
        scale_post_config()
        st.report_fail('test_case_failure_message', err)

    #############################################################
    hdrMsg("Step: Verify Multicast traffic for all {} multicast groups on user-vrf".format(data.mroute_count_per_vrf))
    #############################################################
    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]],
                                  dest_port=data.tgd3_ports[1], exp_ratio=1,delay=3,mode='aggregate')
    if result is False:
        data.tg1.tg_traffic_control(action='stop', stream_handle=data.scale_streams)
        data.tg1.tg_traffic_config(mode='modify', stream_id=data.scale_streams, rate_pps=10000)
        data.tg1.tg_traffic_config(mode='enable', stream_id=data.stream_list)
        err = 'Line-rate Multicast Traffic failed on user-vrf with {} mroute entries installed '.format(data.mroute_count_per_vrf)
        failMsg(err)
        scale_post_config()
        st.report_fail('test_case_failure_message', err)
    else:
        st.report_tc_pass("FtOpSoRoPimSt001", "tc_passed")
    #############################################################
    hdrMsg("Send Leave for all multicast groups and verify mroute entries are deleted on LHR and FHR nodes")
    #############################################################
    for vrf in vrf_list:   send_igmpv3_report(host='R1', groups=data.dynamic_group_list_scale, sources=[data.tgd1_ip],
                                              filter='include', vrf=vrf, mode='leave', group_incr_ip='0.0.0.1',
                                              group_incr='1', group_prefix_len='32')

    #############################################################
    hdrMsg("Step: Send igmp leave for groups {} using \"no ip igmp join command on all VRFs\"".format(data.igmp_static_groups))
    #############################################################

    for intf in [data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]]:
        igmp_api.config_igmp(data.dut3,intf=intf,source=data.tgd1_ip,group=data.igmp_static_groups,join='',config='no')
    st.wait(10)
    #############################################################
    hdrMsg("Step: Delete static mroutes for {} on both VRFs on both LHR and FHR nodes".format(data.static_mroute_groups))
    #############################################################

    dict1= {'intf':data.d3d1_vlan_intf[0],'oif':data.d3tg_vlan_intf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups,'config':'no'}
    dict2 = {'intf': data.d1tg_ports[0],'oif': data.d3d1_vlan_intf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups,'config':'no'}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])


    dict1= {'intf':data.d3d1_vlan_intf_vrf[0],'oif':data.d3tg_vlan_intf_vrf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups,'config':'no'}
    dict2 = {'intf': data.d1tg_ports[1],'oif': data.d3d1_vlan_intf_vrf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups,'config':'no'}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])

    """
    #############################################################
    hdrMsg("Verify all mroutes uninstalled from LHR and FHR nodes ")
    #############################################################

    result = retry_api(pim_api.verify_ip_multicast, data.dut3,tot_mcast_routes_ac=0, retry_count=20, delay=3)
    if result is False:
        err ="Not all 8k Mroutes unistalled across all VRFs"
        failMsg(err)
        scale_post_config()
        st.report_fail('test_case_failure_message', err)
    """
    #############################################################
    hdrMsg("Verify IGMP source table is emtpy")
    #############################################################
    result =retry_null_output(igmp_api.verify_ip_igmp,data.dut3,cmd_type='sources',vrf='all',return_output='',retry_count=10,delay=25)
    if result is False:
        err ="Not all IGMP sources removed from igmp table after sending Leave for 8k multicast groups"
        failMsg(err)
        scale_post_config()
        st.report_fail('test_case_failure_message', err)

    scale_post_config()
    data.tg1.tg_traffic_config(mode='modify', stream_id=data.scale_streams, rate_pps=data.traffic_rate)
    data.tg1.tg_traffic_config(mode='enable', stream_id=data.stream_list)
    st.report_pass('test_case_passed')



def verify_hold_timer(hold_time):

    result = pim_api.verify_pim_show(data.dut2,cmd_type='neighbor',interface= [data.d1d2_vlan_intf[0], data.d1d2_vlan_intf_vrf[0]],
             neighbor= [data.d1d2_ip] * 2, vrf ='all')
    if result is False:
        failMsg('PIM Neighbor deleted before hold timer expiry.')
        return False

    output = pim_api.verify_pim_show(data.dut2, cmd_type='neighbor',interface=[data.d1d2_vlan_intf[0], data.d1d2_vlan_intf_vrf[0]],
             neighbor=[data.d1d2_ip] * 2, vrf='all',return_output='')

    match_dict = {'interface':data.d1d2_vlan_intf[0]}
    match_dict1 = {'interface':data.d1d2_vlan_intf_vrf[0]}

    entry1 = filter_and_select(output,match=match_dict)
    entry2 = filter_and_select(output,match=match_dict1)

    if not entry1 or not entry2:
        failMsg("PIM neighbor deleted before hold timer expiry")
        return False
    hold_time1 = int(entry1[0]['holdtime'].split(":")[-1])
    hold_time2 = int(entry2[0]['holdtime'].split(":")[-1])

    if hold_time1 >= hold_time or hold_time2 >= hold_time:
        failMsg("Holdtimer not getting expired after stoppng pim hellos")
        return False

    st.log("\n >>>> Default vrf : Hold timer expires in {} seconds <<<<\n".format(hold_time1))
    st.log("\n >>>> User vrf : Hold timer expires in {} seconds <<<<\n".format(hold_time2))
    remaining_time = max(hold_time1,hold_time2)
    st.wait(remaining_time+1)

    result = pim_api.verify_pim_show(data.dut2,cmd_type='neighbor',interface= [data.d1d2_vlan_intf[0], data.d1d2_vlan_intf_vrf[0]],
             neighbor= [data.d1d2_ip] * 2, vrf ='all')
    if result is not False:
        failMsg('PIM Neighbor not deleted after hold timer expiry.')
        return False

    return True

def verify_pim_dr(dut,pim_intf_lst=[]):

    ###################################################################
    hdrMsg("Get show ip pim inerface detail and neighbor outputs.")
    ###################################################################
    parsed_output1 = pim_api.verify_pim_interface_detail(dut, return_output=1, vrf = 'all', interface="detail",skip_error=True)
    parsed_output2 = pim_api.verify_pim_show(dut, return_output=1, interface="detail",vrf = 'all', cmd_type='neighbor',skip_error=True)

    if len(parsed_output1) == 0 or len(parsed_output2) == 0:
        st.error("show command output is Empty")
        return False

    # Workaround for unicode data
    parsed_output1 = ast.literal_eval(json.dumps(parsed_output1))
    parsed_output2 = ast.literal_eval(json.dumps(parsed_output2))

    # Get all the PIM neighborship details
    for output in parsed_output1:
        intf = output['interface']
        # Skip the interfaces which are not of interest. ex : pimreg, interfaces towards host.
        if pim_intf_lst != [] and intf not in pim_intf_lst: continue
        # Verify PIM neighborship state.
        if output['state'] != 'up' :
            failMsg("PIM neighborship is down. Interface: {} , IP : {} , nbr IP: {}".format(output['interface'],
                                                                                            output['primary_addr'],output['pim_nbr']))
            st.error("PIM neighborship is down.")
            return False

        dr_priority_local = output['dr_priority_local']
        for nbr_output in parsed_output2:
            if nbr_output['interface'] == intf :
                dr_priority_remote =  nbr_output['dr_priority']
        nbr_ip = output['pim_nbr']
        if int(dr_priority_remote) > int(dr_priority_local) and output['dr_addr'] == output['primary_addr']:
            failMsg("Remote DR priority: {} , Local DR priority: {}".format(dr_priority_remote, dr_priority_local))
            st.error("Incorrect PIM DR elected.")
            return False
        ip1 = net_addr.IPAddress(output['primary_addr'])
        ip2 = net_addr.IPAddress(nbr_ip)
        dr_ip = net_addr.IPAddress(output['dr_addr'])
        if ip1 > ip2:
            expected_dr_ip = ip1
        else:
            expected_dr_ip = ip2
        # If DR priority is same verify higher IP is PIM DR
        if int(dr_priority_remote) == int(dr_priority_local) and expected_dr_ip != dr_ip :
            failMsg("Local IP address:{} Remote IP address:{} DR ip address:{} ".format(output['primary_addr'],nbr_ip,output['dr_addr'] ))
            st.error("Higher IP address is not elected as PIM DR")
            return False

    return True
