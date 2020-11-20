##############################################################################
#Script Title : BGP Evpn - Vlan interface as underlay
#Author       : Nagappa and Sooriya
#Mail-id      : nagappa.chincholi@broadcom.com, sooriya.gajendrababu@broadcom.com
###############################################################################

import pytest

from spytest import st, tgapi

from ipsla_vars import *
from ipsla_vars import data
from ipsla_utils import *

import apis.routing.route_map as rmap_api
import apis.system.reboot as reboot_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
import apis.system.port as port_api
import random


def initialize_topology_vars():

    vars = st.ensure_min_topology("D1D3:3","D1D4:3","D2D3:3","D2D4:3","D1D2:3")
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped","Skipping cli mode CLICK")

    data.dut_list = st.get_dut_names()

    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]

    #for dut in data.dut_list:
    #    bgp_api.enable_docker_routing_config_mode(dut)

    data.d1d3_ports = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3]
    data.d3d1_ports = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3]
    data.d4d1_ports = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3]

    data.d2d3_ports = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]
    data.d1d2_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3]
    data.d2d1_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3]

    handles = tgapi.get_handles(vars, [vars.T1D3P1,vars.T1D4P1])
    data.tg = handles["tg1"]

    data.d3t1_ports = [vars.D3T1P1]
    data.d4t1_ports = [vars.D4T1P1]

    data.t1d3_ports = [vars.T1D3P1]
    data.t1d4_ports = [vars.T1D4P1]

    data.d3_tg_ph1 = handles["tg_ph_1"]
    data.d4_tg_ph1 = handles["tg_ph_2"]
    data.tg_handles = [data.d3_tg_ph1,data.d4_tg_ph1]
    data.traffic_rate = 1000
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
    result = ipsla_base_config()
    if result is False:
        st.report_fail("Error in module config")
    yield
    ipsla_base_unconfig()

def test_ipsla_001(prologue_epilogue):
    tc_list = ['FtOpSoRoIpSlaFt001','FtOpSoRoIpSlaFt002','FtOpSoRoIpSlaFt003','FtOpSoRoIpSlaFt005','FtOpSoRoIpSlaFt006']

    result1,err1 = verify_sla_basic(vrf='default',sla='ICMP-echo')
    if result1:
        st.report_tc_pass(tc_list[0],'tc_passed')

    result2,err2 = verify_sla_basic(vrf='default',sla='TCP-connect')
    if result2:
        st.report_tc_pass(tc_list[1],'tc_passed')

    if result1 and result2:
        st.report_tc_pass(tc_list[2], 'tc_passed')

    result3,err3 = verify_sla_basic(vrf=vrf1,sla='ICMP-echo')
    if result3:
        st.report_tc_pass(tc_list[3],'tc_passed')

    result4, err4 = verify_sla_basic(vrf=vrf1, sla='TCP-connect')
    if result4:
        st.report_tc_pass(tc_list[4], 'tc_passed')

    if result1 is False:
        st.report_fail('test_case_failure_message',err1)
    if result2 is False:
        st.report_fail('test_case_failure_message',err2)
    if result3 is False:
        st.report_fail('test_case_failure_message',err3)
    if result4 is False:
        st.report_fail('test_case_failure_message',err4)

    st.report_pass('test_case_passed')


def test_ipsla_002(prologue_epilogue):
    tc_list=['FtOpSoRoIpSlaFt007','FtOpSoRoIpSlaFt008','FtOpSoRoIpSlaFt009','FtOpSoRoIpSlaFt010','FtOpSoRoIpSlaFt011',
             'FtOpSoRoIpSlaCli001','FtOpSoRoIpSlaCli002','FtOpSoRoIpSlaCli003']
    for tc in tc_list: data[tc] =True
    tc_result=True;err_list=[];tech_support=data.tech_support_on_fail

    ##############################################################
    st.banner("Configure non-default params frequency,threshold,ttl,tos for each SLA")
    ##############################################################
    data_size = ['28','256','512','1472']
    frequency = ['1','2','3','2']*2;threshold=['1','2','1','2']*2
    ttl = ['2','3','5','10']*2
    tos =  [random.randint(1,255) for _ in range(4) ]*2
    timeout = ['4','4','5','3']*2
    sla_id_list = [str(i) for i in range(1,9)]
    index_list = range(len(frequency))
    type_list = ['icmp-echo']*2 +['tcp-connect']*2+['icmp-echo']*2+['tcp-connect']*2
    dst_ip_list = [target_ips[0],target_ipv6[0],target_ips[1],target_ipv6[1],target_ips[2],target_ipv6[2],target_ips[3],target_ipv6[3]]
    #src_port = random.randint(1,65535)
    src_port_dict = {}

    for sla_id,type,dst_ip,index,data_size_index in zip(sla_id_list,type_list,dst_ip_list,index_list,range(4)*2):
        if type == 'tcp-connect':
            port ='22' if sla_id == '3' else '179'
            src_port_dict[sla_id] = random.randint(10000,11000)
            src_port = src_port_dict[sla_id]
            ip_api.config_ip_sla(data.dut3,sla_num=sla_id,sla_type=type,dst_ip=dst_ip,frequency=frequency[index],timeout=timeout[index],
                         threshold=threshold[index],tos=tos[index],ttl=ttl[index],tcp_port=port,src_port=src_port,skip_error=True)
        if type == 'icmp-echo':
            ip_api.config_ip_sla(data.dut3, sla_num=sla_id, sla_type=type, dst_ip=dst_ip, frequency=frequency[index],timeout=timeout[index],
                                 threshold=threshold[index], tos=tos[index], ttl=ttl[index],data_size=data_size[data_size_index],skip_error=True)

    ##############################################################
    st.banner("Verify all SLAs re Up with non-default params configured")
    ##############################################################
    result = retry_api(verify_ipsla,retry_count=10,delay=1)
    if result is False:
        err='One or more SLAs are not Up with non-defaule params configured';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;
        data['FtOpSoRoIpSlaFt007'] = data['FtOpSoRoIpSlaFt010'] = data['FtOpSoRoIpSlaFt011'] = False

    ###########################################################
    st.banner("Verify all ipv4 and ipv6 static routes")
    ###########################################################
    result = verify_ipsla_static_route()
    if result is False:
        err='one or more static routs not installed with SLA configured with non-default params';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;
        data['FtOpSoRoIpSlaFt007'] = data['FtOpSoRoIpSlaFt010'] = data['FtOpSoRoIpSlaFt011'] = False

    ##########################################################
    st.banner("Configure invalid source-address for each sla and verify it goes down after SLA timeout")
    ##########################################################
    sla_id_v4 = [1,3,5,7]
    sla_type = ['icmp-echo','tcp-connect']*2
    sla_id_v6 = [2,4,6,8]
    invalid_src = ['27.27.27.1']*4
    invalid_src_v6 = ['2727::1']*4
    for id,sla,dst,src in zip(sla_id_v4,sla_type,target_ips,invalid_src):
        if sla =='tcp-connect':
            port = '22' if id == 3 else '179'
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src,tcp_port=port)
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src)
    for id,sla,dst,src in zip(sla_id_v6,sla_type,target_ipv6,invalid_src_v6):
        if sla == 'tcp-connect':
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src,tcp_port='179')
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src)


    ###############################################################
    st.banner("Verify SLAs are down  since target becomes unreachable with invalid source-address")
    ################################################################
    result = retry_api(verify_ipsla,exp_state='Down',retry_count=10,delay=1)
    if result is False:
        err='One or more SLAs did not go down with invalid src-addr configured';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt009']=False

    ############################################################
    st.banner("Verify Static routs mapped to SLA are uninstalled")
    #############################################################
    result = verify_ipsla_static_route(entry=False,vrf='all')
    if result is False:
        err='Not all static routes uninstalled after SLAs are down with invalid src-addr';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt009']=False


    ############################################################
    st.banner("Re-add correct src-addr for all SLA")
    ############################################################
    valid_src = [dut3_1_ip_list[0]]*2 +[dut3_2_ip_list[0]]*2
    valid_src_v6 = [dut3_1_ipv6_list[0]]*2 +[dut3_2_ipv6_list[0]]*2
    for id,sla,dst,src in zip(sla_id_v4,sla_type,target_ips,valid_src):
        if sla =='tcp-connect':
            port = '22' if id == 3 else '179'
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src,tcp_port=port)
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src)
    for id,sla,dst,src in zip(sla_id_v6,sla_type,target_ipv6,valid_src_v6):
        if sla == 'tcp-connect':
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src,tcp_port='179')
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src)

    ##########################################################
    st.banner("Verify all SLAs comes up after configuring correct source-addr")
    ##########################################################
    result = retry_api(verify_ipsla,retry_count=10,delay=1)
    if result is False:
        err='One or more SLa did not come up after configuring back correct src-addr';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt009']=False
    ##########################################################
    st.banner("Verify all static routes gets re-installed after adding back valid source-addr")
    ##########################################################
    result = verify_ipsla_static_route(vrf='all')
    if result is False:
        err='Not all Static routes installed back after SLAs are up with correct src-addr';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt009']=False

    if data['FtOpSoRoIpSlaFt009']:
       st.report_tc_pass('FtOpSoRoIpSlaFt009','tc_passed')

    ##########################################################
    st.banner("COnfigure invalid source-intf for each SLA and verify SLA timeout happens")
    ##########################################################
    src_intf = [vlanInt_s2_l1[0]]*2 +[vlanInt_s1_l1[0]]*2
    for id,sla,dst,intf in zip(sla_id_v4,sla_type,target_ips,src_intf):
        if sla =='tcp-connect':
            port = '22' if id == 3 else '179'
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf,tcp_port=port)
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf)
    for id,sla,dst,intf in zip(sla_id_v6,sla_type,target_ipv6,src_intf):
        if sla == 'tcp-connect':
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf,tcp_port='179')
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf)

    ###############################################################
    st.banner("Verify all SLAs goes down with invalid src-intf configured")
    ##############################################################
    result = retry_api(verify_ipsla,exp_state='Down',retry_count=10,delay=1)
    if result is False:
        err='One or more SLAs did not go down with invalid src-intf configured';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt008']=False
    ################################################################
    st.banner("Verify all static routes gets uninstalled with invalid src-intf configured")
    ################################################################
    result = verify_ipsla_static_route(entry=False,vrf='all')
    if result is False:
        err='Not all static routes uninstalled after SLAs are down';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt008']=False
    ##################################################################
    st.banner("Re-configure valid src-intf for all SLAs")
    ##################################################################
    src_intf = [vlanInt_s1_l1[0]]*2+[vlanInt_s2_l1[0]]*2
    for id,sla,dst,intf in zip(sla_id_v4,sla_type,target_ips,src_intf):
        if sla =='tcp-connect':
            port = '22' if id == 3 else '179'
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf,tcp_port=port)
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf)
    for id,sla,dst,intf in zip(sla_id_v6,sla_type,target_ipv6,src_intf):
        if sla == 'tcp-connect':
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf,tcp_port='179')
        else:
            ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_intf=intf)
    ################################################################
    st.banner("Verify targets are reachable after configuring correct src-intf and SLAs are up")
    ################################################################
    result =retry_api(verify_ipsla,retry_count=10,delay=1)
    if result is False:
        err='One or more SLAs did not come up after configuring correct src-intf';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt008']=False

    ###############################################################
    st.banner("Verify static routs gets re-installed")
    ###############################################################
    result = verify_ipsla_static_route()
    if result is False:
        err='Not all static routes installed after configuring correct src-intf';
        failMsg(err,tech_support,tc_name='ipsla_002_on_fail');tc_result=False
        err_list.append(err);tech_support=False;data['FtOpSoRoIpSlaFt008']=False

    if data['FtOpSoRoIpSlaFt008']:
        st.report_tc_pass('FtOpSoRoIpSlaFt008','tc_passed')

    ##############################################################
    st.banner("Verify all non-default params configured under each SLA")
    ##############################################################

    vrf_list = ['default']*4 + [vrf1]*4
    src_list = [dut3_1_ip_list[0],dut3_1_ipv6_list[0]]*2 + [dut3_2_ip_list[0],dut3_2_ipv6_list[0]]*2
    src_intf = [vlanInt_s1_l1[0]]*4+[vlanInt_s2_l1[0]]*4
    type_list = ['ICMP-echo'] * 2 + ['TCP-connect'] * 2 + ['ICMP-echo'] * 2 + ['TCP-connect'] * 2
    for sla_id,type,dst_ip,vrf,index,data_size_index,src,intf in zip(sla_id_list,type_list,dst_ip_list,vrf_list,index_list,range(4)*2,src_list,src_intf):
        if type == 'TCP-connect':
            port ='22' if sla_id == '3' else '179'
            src_port = src_port_dict[sla_id]
            result = ip_api.verify_ip_sla_inst(data.dut3,inst=sla_id,type=type,freq=frequency[index],vrf_name=vrf,
                              src_port=src_port,dst_port=port,dst_addr=dst_ip,src_addr=src,ttl=ttl[index],tos=tos[index],
                              threshold=threshold[index],src_intf=intf,timeout=timeout[index])
            if result is False:
                err = "Verification of TCP SLA params failed for {}".format(sla_id)
                failMsg(err,tech_support,tc_name='ipsla_002_on_fail');err_list.append(err);tc_result=False
                tech_support=False
                data['FtOpSoRoIpSlaFt007'] =False
        else:
            result = ip_api.verify_ip_sla_inst(data.dut3,inst=sla_id,type=type,freq=frequency[index],vrf_name=vrf,
                              dst_addr=dst_ip,src_addr=src,ttl=ttl[index],tos=tos[index],icmp_size=data_size[data_size_index],
                              threshold=threshold[index],src_intf=intf,timeout=timeout[index])
            if result is False:
                err = "Verification of ICMP SLA params failed for {}".format(sla_id)
                failMsg(err,tech_support,tc_name='ipsla_002_on_fail');err_list.append(err);tc_result=False
                tech_support=False
                data['FtOpSoRoIpSlaFt007'] = False

    if data['FtOpSoRoIpSlaFt007']:
        st.report_tc_pass('FtOpSoRoIpSlaFt007','tc_passed')
        st.report_tc_pass('FtOpSoRoIpSlaFt010', 'tc_passed')
        st.report_tc_pass('FtOpSoRoIpSlaFt011', 'tc_passed')
        st.report_tc_pass('FtOpSoRoIpSlaCli001','tc_passed')
        st.report_tc_pass('FtOpSoRoIpSlaCli002', 'tc_passed')
        st.report_tc_pass('FtOpSoRoIpSlaCli003', 'tc_passed')
    ###############################################################
    st.banner("Remove all non-default params configured under each SLAs and verify it resets to default values")
    ###############################################################
    type_list = ['icmp-echo'] * 2 + ['tcp-connect'] * 2 + ['icmp-echo'] * 2 + ['tcp-connect'] * 2
    for sla_id,type,dst_ip,index,data_size_index in zip(sla_id_list,type_list,dst_ip_list,index_list,range(4)*2):
        if type == 'tcp-connect':
            port ='22' if sla_id == '3' else '179'
            ip_api.config_ip_sla(data.dut3,sla_num=sla_id,sla_type=type,dst_ip=dst_ip,tcp_port=port,config='no',
                                 del_cmd_list=['src_addr','src_intf','src_port','frequency','threshold','timeout','ttl','tos'])
            ip_api.config_ip_sla(data.dut3,sla_num=sla_id,sla_type=type,dst_ip=dst_ip,tcp_port=port,frequency=sla_freq)
        if type == 'icmp-echo':
            ip_api.config_ip_sla(data.dut3, sla_num=sla_id, sla_type=type, dst_ip=dst_ip,config='no',
                                 del_cmd_list=['src_intf','frequency','threshold','ttl','timeout','tos','data_size'])
            ip_api.config_ip_sla(data.dut3, sla_num=sla_id, sla_type=type, dst_ip=dst_ip,frequency=sla_freq)

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])

    st.report_pass('test_case_passed')


def test_ipsla_003(prologue_epilogue):
    tc_list =['FtOpSoRoIpSlaFt021']

    ##################################################
    st.banner("Verify SLA counters are incrementing for each SLA ")
    ##################################################

    sla_counters_initial = {}
    sla_id = [str(i) for i in range(1,9)]
    for id in sla_id:
        output = ip_api.verify_ip_sla_inst(data.dut3,id,return_output='')
        type = 'ICMP-echo' if id in ['1','2','5','6'] else 'TCP-connect'
        if 'ICMP' in type:
            sla_counters_initial['{}_tx'.format(id)] = int(output[0]['icmp_req_cnt'])
            sla_counters_initial['{}_rx'.format(id)] = int(output[0]['icmp_succ_cnt'])
        else:
            sla_counters_initial['{}_tx'.format(id)] = int(output[0]['tcp_req_cnt'])
            sla_counters_initial['{}_rx'.format(id)] = int(output[0]['tcp_succ_cnt'])

    st.wait(5,'Wait for 5 sec for the counters to increment')
    sla_counters_final = {}
    sla_id = [str(i) for i in range(1,9)]
    for id in sla_id:
        output = ip_api.verify_ip_sla_inst(data.dut3,id,return_output='')
        type = 'ICMP-echo' if id in ['1','2','5','6'] else 'TCP-connect'
        if 'ICMP' in type:
            sla_counters_final['{}_tx'.format(id)] = int(output[0]['icmp_req_cnt'])
            sla_counters_final['{}_rx'.format(id)] = int(output[0]['icmp_succ_cnt'])
        else:
            sla_counters_final['{}_tx'.format(id)] = int(output[0]['tcp_req_cnt'])
            sla_counters_final['{}_rx'.format(id)] = int(output[0]['tcp_succ_cnt'])

    st.log("Initial Counters : {}".format(sla_counters_initial))
    st.log("Final Counters : {}".format(sla_counters_final))

    for id in sla_id:
        if sla_counters_final['{}_tx'.format(id)] == sla_counters_initial['{}_tx'.format(id)]:
            err = "Request counters not incrementing for SLA ID {}".format(id)
            st.report_fail('test_case_failure_message',err)
        if sla_counters_final['{}_rx'.format(id)] == sla_counters_initial['{}_rx'.format(id)]:
            err = "Reply counters not incrementing for SLA ID {}".format(id)
            st.report_fail('test_case_failure_message',err)

    import random
    type = ['all','id']
    select_type = type[random.randint(0,1)]
    st.log("clear statistics type : {}".format(select_type))

    sla_counters_reset = {}
    sla_id = [str(i) for i in range(1, 9)]
    if select_type == 'all':
        ##################################################
        st.banner("Reset all SLA counters using all")
        ##################################################
        ip_api.clear_ip_sla(data.dut3,inst='all')

    for id in sla_id:
        if select_type == 'id':
            ##############################################
            st.banner("Reset SLA counters using SLA-id for {}".format(id))
            ##############################################
            ip_api.clear_ip_sla(data.dut3, inst=id)

        output = ip_api.verify_ip_sla_inst(data.dut3, id, return_output='')
        type = 'ICMP-echo' if id in ['1','2','5','6'] else 'TCP-connect'
        if 'ICMP' in type:
            sla_counters_reset['{}_tx'.format(id)] = int(output[0]['icmp_req_cnt'])
            sla_counters_reset['{}_rx'.format(id)] = int(output[0]['icmp_succ_cnt'])
        else:
            sla_counters_reset['{}_tx'.format(id)] = int(output[0]['tcp_req_cnt'])
            sla_counters_reset['{}_rx'.format(id)] = int(output[0]['tcp_succ_cnt'])

        st.log(">>>> Before reset Counters for {} : Tx- {},Rx- {} <<<<<<".format(id,sla_counters_final['{}_tx'.format(id)],
                                                                     sla_counters_final['{}_rx'.format(id)]))
        st.log(">>>> After Reset Counters for {}: Tx- {}, Rx- {} <<<<<<".format(id,sla_counters_reset['{}_tx'.format(id)],
                                                        sla_counters_reset['{}_rx'.format(id)]))

        if sla_counters_reset['{}_tx'.format(id)] >= sla_counters_final['{}_tx'.format(id)]:
            err = "Request counters did not reset for SLA ID {}".format(id)
            st.report_fail('test_case_failure_message', err)
        if sla_counters_reset['{}_rx'.format(id)] == sla_counters_final['{}_rx'.format(id)]:
            err = "Reply counters did not reset for SLA ID {}".format(id)
            st.report_fail('test_case_failure_message', err)

    st.report_pass('test_case_passed')


def test_ipsla_004(prologue_epilogue):
    tc_list =['FtOpSoRoIpSlaFt004','FtOpSoRoIpSlaFt016']
    tc_result=True;err_list=[];
    data['FtOpSoRoIpSlaFt016'] = True
    tech_support = data.tech_support_on_fail

    run_traffic(action='start',version='ipv4',vrf=vrf1,sla='ICMP-echo')
    #################################################
    st.banner("Verify ICMP SLA 5 is up and static route is installed for the target")
    #################################################
    result = ip_api.verify_ip_sla_inst(data.dut3,'5',type='ICMP-echo',oper_state='Up')
    if result is False:
        err ='SLA instance 5 not up'
        st.report_fail('test_case_failure_message',err)
    result = verify_ipsla_static_route(entry=True,vrf=vrf1,addr_family='ipv4',sla_type='ICMP-echo')
    if result is False:
        err ='Static routes mapped with SLA 5 not installed in routing table'
        st.report_fail('test_case_failure_message', err)

    ##################################################
    st.banner("Delete Sla type and verify type set to None")
    ##################################################
    ip_api.config_ip_sla(data.dut3,sla_num='5',sla_type='icmp-echo',dst_ip=target_ips[2],del_cmd_list=['src_addr','vrf_name'],config='no')
    ip_api.config_ip_sla(data.dut3,sla_num='5',sla_type='icmp-echo',dst_ip='',del_cmd_list=['sla_type'],config='no')
    result = ip_api.verify_ip_sla_inst(data.dut3, '5', type='None')
    if result is False:
        err ='SLA type/state not set to None after deleting sla type'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False
    result = verify_ipsla_static_route(entry=False, vrf=vrf1, addr_family='ipv4', sla_type='ICMP-echo')
    if result is False:
        err ='Static routes not getting uninstalled after deleting Sla_type'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False
    ##################################################
    st.banner("Re-configure SLA 5 to TCP-connect with same target ip")
    ##################################################

    ip_api.config_ip_sla(data.dut3,sla_num='5',sla_type='tcp-connect',dst_ip=target_ips[2],tcp_port='179',frequency=1,vrf_name=vrf1)
    result = retry_api(ip_api.verify_ip_sla_inst,data.dut3, '5', type='TCP-connect', oper_state='Up',retry_count=10,delay=1)
    if result is False:
        err ='SLA instance 5 not coming up after switching from ICMP-echo to TCP-connect'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False
    result = verify_ipsla_static_route(entry=True, vrf=vrf1, addr_family='ipv4', sla_type='ICMP-echo')
    if result is False:
        err ='Static routes not installed after SLA type switched from ICMP to TCP'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False

    if not verify_traffic():
        err ='Traffic not forwarded after SLA type switched from ICMP to TCP'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False

    ##########################################################
    st.banner("Verify SLA history updated with all Up events")
    ##########################################################
    event_list = ['Started', 'State changed to: Up']
    event_list1 = ['Started','Nexthop/VRF not present', 'State changed to: Up']
    result1 = ip_api.verify_ip_sla_history(data.dut3,'5', verify_sequence=True,
                                 event=event_list)
    if result1 is False:
        result1 = ip_api.verify_ip_sla_history(data.dut3, '5', verify_sequence=True,
                                               event=event_list1)
        if result1 is False:
            err = 'SLA history not updated with the events'
            failMsg(err, tech_support, tc_name='ipsla_004_on_fail');data['FtOpSoRoIpSlaFt016'] = False
            tech_support = False;err_list.append(err);tc_result = False

    #########################################################
    st.banner("Make target not reachable by deleting ip address")
    #########################################################
    ip_api.delete_ip_interface(data.dut4,target_vlan_intfs[2], target_ips[2], mask24)
    #port_api.shutdown(data.dut4,[data.d4t1_ports[0]])
    result = retry_api(ip_api.verify_ip_sla_inst, data.dut3, '5', type='TCP-connect', oper_state='Down', retry_count=10, delay=1)
    if result is False:
        err ='SLA did not timeout after changing type from icmp to tcp'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False
    result = verify_ipsla_static_route(entry=False, vrf=vrf1, addr_family='ipv4', sla_type='ICMP-echo')
    if result is False:
        err ='STatic routes not uninstalled after SLA timeout with type switched from icmp to tcp'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False

    ##########################################################
    st.banner("Verify SLA history updated with all Down events")
    ##########################################################
    event_list = ['Started', 'State changed to: Up','Timeout waiting for response(s)' ,'State changed to: Down',
                                        'Nexthop/VRF not present']
    event_list1 = ['Started','Nexthop/VRF not present','State changed to: Up','Timeout waiting for response(s)' ,'State changed to: Down',
                                        'Nexthop/VRF not present']
    result1 = ip_api.verify_ip_sla_history(data.dut3,'5', verify_sequence=True,
                                 event=event_list)
    if result1 is False:
        result1 = ip_api.verify_ip_sla_history(data.dut3, '5', verify_sequence=True,
                                               event=event_list1)
        if result1 is False:
            err = 'SLA history not updated with Down events'
            failMsg(err, tech_support, tc_name='ipsla_004_on_fail');data['FtOpSoRoIpSlaFt016'] = False
            tech_support = False;err_list.append(err);tc_result = False

    if data['FtOpSoRoIpSlaFt016']:
        st.report_tc_pass('FtOpSoRoIpSlaFt016','tc_passed')
    #########################################################
    st.banner("Revert back SLA from TCP to ICMP and verify SLA comes up")
    #########################################################
    ip_api.config_ip_addr_interface(data.dut4, target_vlan_intfs[2], target_ips[2], mask24)
    add_static_arp('ipv4')
    #port_api.noshutdown(data.dut4, [data.d4t1_ports[0]])
    ip_api.config_ip_sla(data.dut3, sla_num='5', sla_type='tcp-connect',dst_ip=target_ips[2],tcp_port='179', del_cmd_list=['src_addr','vrf_name'], config='no')
    ip_api.config_ip_sla(data.dut3, sla_num='5', sla_type='tcp-connect',dst_ip='', del_cmd_list=['sla_type','dst_port'], config='no')
    ip_api.config_ip_sla(data.dut3, sla_num='5', sla_type='icmp-echo',dst_ip=target_ips[2],frequency=1,vrf_name=vrf1,src_addr=dut3_2_ip_list[0])
    result = retry_api(ip_api.verify_ip_sla_inst,data.dut3, '5', type='ICMP-echo', oper_state='Up',retry_count=10,delay=1)
    if result is False:
        err ='SLA did not come up after reverting from TCP to ICMP type'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');tech_support=False;
        err_list.append(err);tc_result=False
    result = verify_ipsla_static_route(entry=True, vrf=vrf1, addr_family='ipv4', sla_type='ICMP-echo')
    if result is False:
        err ='Static routes not installed after reverting sla type from TCP to ICMP'
        failMsg(err,tech_support,tc_name='ipsla_004_on_fail');
        err_list.append(err);tc_result=False

    if not verify_traffic():
        err = 'Traffic not forwarded after SLA type switched from TCP to ICMP'
        failMsg(err, tech_support, tc_name='ipsla_004_on_fail');
        err_list.append(err);
        tc_result = False

    run_traffic(action='stop', version='ipv4', vrf=vrf1, sla='ICMP-echo')
    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])

    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def ipsla_5_fixture(request,prologue_epilogue):

    yield
    st.log("#### CLEANUP for ipsla_005 #######")
    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config_type_list=["routeMap"],config='no',
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv4', routeMap='deny_bgp_routes', diRection='in',vrf_name=vrf1)
    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config_type_list=["routeMap"],config='no',
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv6', routeMap='deny_bgp_routes', diRection='in',vrf_name=vrf1)
    rmap = rmap_api.RouteMap("deny_bgp_routes")
    rmap.execute_command(data.dut3, config='no')

    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config='yes', config_type_list=["routeMap"],
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv6', routeMap='rmap_v6', diRection='in',vrf_name=vrf1)
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0], static_ip='0.0.0.0/0', family='ipv4',vrf=vrf1)
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ipv6_list[0], static_ip='::/0', family='ipv6',vrf=vrf1)
    st.log("#### CLEANUP END #######")

def test_ipsla_005(ipsla_5_fixture):
    tc_list = ['FtOpSoRoIpSlaFt012']
    ###############################################
    st.banner("Delete existing route-map config under ipv6 bgp neighbor")
    ###############################################
    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config='no', config_type_list=["routeMap"],
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv6', routeMap='rmap_v6', diRection='in',vrf_name=vrf1)

    ###############################################
    st.banner("Configure route-map to deny routes with source-protocol bgp and apply it on VRF bgp neighbors ")
    ###############################################
    rmap = rmap_api.RouteMap("deny_bgp_routes")
    rmap.add_deny_sequence('10')
    rmap.add_sequence_match_source_protocol('10', 'bgp')
    rmap.execute_command(data.dut3)

    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config_type_list=["routeMap"],
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv4', routeMap='deny_bgp_routes', diRection='in',vrf_name=vrf1)
    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, config_type_list=["routeMap"],
                       neighbor=dut2_3_ipv6_list[0], addr_family='ipv6', routeMap='deny_bgp_routes', diRection='in',vrf_name=vrf1)

    ###############################################
    st.banner("Bring down the trarget by flapping target interface ")
    ###############################################
    port_api.shutdown(data.dut4,[data.d4t1_ports[0]])
    st.wait(5,'Wait for SLAs on user-vrf to timeout')
    port_api.noshutdown(data.dut4, [data.d4t1_ports[0]])

    ###############################################
    st.banner("Verify SLAs on user-vrf did not come up since no bgp routes is present ")
    ###############################################
    result = retry_api(ip_api.verify_ip_sla,data.dut3,['5','6','7','8'], type=['ICMP-echo']*2+['TCP-connect']*2,
                       target=[target_ips[2],target_ipv6[2],target_ips[3],target_ipv6[3]],
                       vrf_name=[vrf1]*4, state=['Up']*4,retry_count=5,delay=1)
    if result:
        err = 'SLAs 5 to 8 should not come up since no route to target '
        failMsg(err)
        st.report_fail('test_case_failure_message',err)

    ###############################################
    st.banner(" COnfigure target reachability via default route for ipv4 and ipv6 in user-vrf")
    ###############################################
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0], static_ip='0.0.0.0/0', family='ipv4',vrf=vrf1)
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ipv6_list[0], static_ip='::/0', family='ipv6',vrf=vrf1)

    ###############################################
    st.banner("Verify all SLAs under user-vrf comes up with default-route reachability")
    ###############################################
    result = retry_api(ip_api.verify_ip_sla,data.dut3,['5','6','7','8'], type=['ICMP-echo']*2+['TCP-connect']*2,
                       target=[target_ips[2],target_ipv6[2],target_ips[3]+'(179)',target_ipv6[3]+'(179)'],
                       vrf_name=[vrf1]*4, state=['Up']*4,retry_count=20,delay=1)
    if not result:
        err = 'SLAs 5 to 8 did not come up with target reachable via default routes'
        failMsg(err)
        st.report_fail('test_case_failure_message',err)
    st.report_pass('test_case_passed')


def test_ipsla_006(prologue_epilogue):
    tc_list = ['FtOpSoRoIpSlaFt013','FtOpSoRoIpSlaFt015','FtOpSoRoIpSlaFt020']
    tc_result = True;tech_support=data.tech_support_on_fail;err_list=[]

    ##################################################
    st.banner("Delete source-vrf confgi from SLAs 5,6")
    ##################################################
    sla_list = ['5','6']
    target_list = [target_ips[2],target_ipv6[2]]
    for sla_id,dst_ip in zip(sla_list,target_list):
        ip_api.config_ip_sla(data.dut3,sla_id,sla_type='icmp-echo',dst_ip=dst_ip,config='no',del_cmd_list=['vrf_name','src_addr'])

    ##################################################
    st.banner("Verify SLAs 5 ,6 goes down since target ip/ipv6 not reacgable on default-vrf")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,sla_list, type=['ICMP-echo']*2,
                       target=[target_ips[2],target_ipv6[2]],vrf_name=['default']*2, state=['Down']*2,retry_count=10,delay=1)
    if result is False:
        err ='SLAs 5 & 6 did not go down after changing src-vrf config'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)
    ##################################################
    st.banner("Create static route-leak on default-vrf for the target")
    ##################################################

    ip_api.create_static_route_nexthop_vrf(data.dut3, next_hop=dut2_3_ip_list[0],
                                           static_ip='{}/{}'.format(target_ips_subnet[2],mask24),
                                           nhopvrf=vrf1)
    ip_api.create_static_route_nexthop_vrf(data.dut3, next_hop=dut2_3_ipv6_list[0],
                                           static_ip='{}/{}'.format(target_ipv6_subnet[2],mask_v6),
                                           nhopvrf=vrf1,family='ipv6')

    ##################################################
    st.banner("Verify SLAs 5,6 comes up since targets are reachable via leaked routes")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,sla_list, type=['ICMP-echo']*2,
                       target=[target_ips[2],target_ipv6[2]],vrf_name=['default']*2, state=['Up']*2,retry_count=20,delay=1)

    if result is False:
        err ='SLAs 5 & 6 did not come up after configuring route leaks'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)
    ##################################################
    st.banner("Verify SLA mapped Static routes are installed")
    ##################################################

    result = verify_ipsla_static_route(vrf=vrf1,sla_type='ICMP-echo')
    if result is False:
        err ='Static routes not installed for SLAs 5 and 6 with route leaks'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    ##################################################
    st.banner("Delete the static route-leaks")
    ##################################################
    ip_api.create_static_route_nexthop_vrf(data.dut3, next_hop=dut2_3_ip_list[0],
                                           static_ip='{}/{}'.format(target_ips_subnet[2],mask24),
                                           nhopvrf=vrf1,config='no')
    ip_api.create_static_route_nexthop_vrf(data.dut3, next_hop=dut2_3_ipv6_list[0],
                                           static_ip='{}/{}'.format(target_ipv6_subnet[2],mask_v6),
                                           nhopvrf=vrf1,family='ipv6',config='no')

    ##################################################
    st.banner("Verify SLAs 5,6 goes down after deleting static route-leaks")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,sla_list, type=['ICMP-echo']*2,
                       target=[target_ips[2],target_ipv6[2]],vrf_name=['default']*2, state=['Down']*2,retry_count=20,delay=1)
    if result is False:
        err ='SLAs did not down after deleting route leaks for the target'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    ##################################################
    st.banner("Revert the source-vrf to {} for SLAs".format(vrf1))
    ##################################################
    src_list = [dut3_2_ip_list[0],dut3_2_ipv6_list[0]]
    for sla_id,dst_ip,src in zip(sla_list,target_list,src_list):
        ip_api.config_ip_sla(data.dut3,sla_id,sla_type='icmp-echo',dst_ip=dst_ip,vrf_name=vrf1,src_addr=src)


    ##################################################
    st.banner("Verify SLAs comes up and static routes are re-installed")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla, data.dut3, sla_list, type=['ICMP-echo'] * 2,
                       target=[target_ips[2], target_ipv6[2]], vrf_name=[vrf1] * 2, state=['Up'] * 2,
                       retry_count=20, delay=1)
    if result is False:
        err ='SLAs did not come up after reverting from default to user-vrf'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    result = verify_ipsla_static_route(vrf=vrf1, sla_type='ICMP-echo')
    if result is False:
        err ='Static routes are not installed after changing source-vrf from default to user-vrf'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    if tc_result:
        st.report_tc_pass('FtOpSoRoIpSlaFt015','tc_passed')

    ##################################################
    st.banner("COnfigure SLAs 9 and 10 with target ip as conencted ip addresses {} and {}".format(dut2_3_ip_list[0],dut2_3_ipv6_list[0]))
    ##################################################

    ip_api.config_ip_sla(data.dut3,'9',dst_ip=dut2_3_ip_list[0],sla_type='icmp-echo',vrf_name=vrf1,frequency=1)
    ip_api.config_ip_sla(data.dut3, '10', dst_ip=dut2_3_ipv6_list[0], sla_type='icmp-echo', vrf_name=vrf1, frequency=1)

    ##################################################
    st.banner("Create default static routes on ipv4/v6 with SLAs 9 and 10")
    ##################################################

    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0], static_ip='0.0.0.0/0', family='ipv4', track='9',vrf=vrf1)
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ipv6_list[0], static_ip='::/0', family='ipv6', track='10',vrf=vrf1)

    ##################################################
    st.banner("Verify SLAs are UP")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,['9','10'], type=['ICMP-echo']*2,
                        target=[dut2_3_ip_list[0],dut2_3_ipv6_list[0]],vrf_name=[vrf1]*2, state=['Up']*2,retry_count=20,delay=1)
    if result is False:
        err ='SLAs not UP -target via connected routes'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    ##################################################
    st.banner("Verify default static routes are installed")
    ##################################################

    result1 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ip_list[0], ip_address='0.0.0.0/0',family='ipv4', vrf_name=vrf1)
    result2 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ipv6_list[0], ip_address='::/0',family='ipv6', vrf_name=vrf1)
    if not result1 or not result2:
        err ='Either ip or ipv6 default static route not installed'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    ##################################################
    st.banner("Trigger target failure by deleting ip address on dut2")
    ##################################################

    ip_api.delete_ip_interface(data.dut2,vlanInt_s2_l1[0],dut2_3_ip_list[0],'31')
    ip_api.delete_ip_interface(data.dut2,vlanInt_s2_l1[0],dut2_3_ipv6_list[0],'64',family='ipv6')

    ##################################################
    st.banner("Verify SLA goes down and default static routes are uninstalled")
    ##################################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,['9','10'], type=['ICMP-echo']*2,
                       target=[dut2_3_ip_list[0],dut2_3_ipv6_list[0]],vrf_name=[vrf1]*2, state=['Down']*2,retry_count=20,delay=1)

    if result is False:
        err ='SLAs for connected targets did not go down after deleting  target ip'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    result1 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ip_list[0], ip_address='0.0.0.0/0',family='ipv4', vrf_name=vrf1)
    result2 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ipv6_list[0], ip_address='::/0',family='ipv6', vrf_name=vrf1)
    if result1 or result2:
        err ='Either IP or Ipv6 default static route not uninstalled after SLA is down'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)
    ##################################################
    st.banner("Re-add Ip addresses and verify SLA comes up")
    ##################################################

    ip_api.config_ip_addr_interface(data.dut2,vlanInt_s2_l1[0],ip_address=dut2_3_ip_list[0],subnet='31')
    ip_api.config_ip_addr_interface(data.dut2,vlanInt_s2_l1[0],ip_address=dut2_3_ipv6_list[0], subnet='64',family='ipv6')


    result = retry_api(ip_api.verify_ip_sla,data.dut3,['9','10'], type=['ICMP-echo']*2,
                       target=[dut2_3_ip_list[0],dut2_3_ipv6_list[0]],vrf_name=[vrf1]*2, state=['Up']*2,retry_count=20,delay=1)
    if result is False:
        err ='SLAs configured with connected target not comng up after re-adding ip address'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    ##################################################
    st.banner("Verify default static routes are re-installed")
    ##################################################

    result1 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ip_list[0], ip_address='0.0.0.0/0',family='ipv4', vrf_name=vrf1)
    result2 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ipv6_list[0], ip_address='::/0',family='ipv6', vrf_name=vrf1)
    if not result1 or not result2:
        err ='Either IPv4 or IPv6 default static route not re-installed'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)
    ##################################################
    st.banner("Delete SLAs 9 and 10 and verify static default routes gets uninstalled")
    ##################################################

    ip_api.config_ip_sla(data.dut3,'9',sla_type='icmp-echo',dst_ip=dut2_3_ip_list[0],config='no',del_cmd_list=['sla_num'])
    ip_api.config_ip_sla(data.dut3, '10',sla_type='icmp-echo', dst_ip=dut2_3_ipv6_list[0],config='no',del_cmd_list=['sla_num'])

    result1 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ip_list[0], ip_address='0.0.0.0/0',family='ipv4', vrf_name=vrf1)
    result2 = ip_api.verify_ip_route(data.dut3, type='S', nexthop=dut2_3_ipv6_list[0], ip_address='::/0',family='ipv6', vrf_name=vrf1)
    if result1 or result2:
        err ='Static routes not uninstalled after deleting SLAs'
        failMsg(err,tech_support,tc_name='ipsla_006_onfail');tech_support=False;
        tc_result=False;err_list.append(err)

    st.log("####### Cleanup ######")
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0], static_ip='0.0.0.0/0', family='ipv4', track='9',vrf=vrf1,
                               config='no')
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ipv6_list[0], static_ip='::/0', family='ipv6', track='10',vrf=vrf1,
                               config='no')
    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def pbr_fixture(request,prologue_epilogue):

    yield
    st.log("######## Cleanup Started for ipsla_007 ######")
    port_api.noshutdown(data.dut4, [data.d4t1_ports[0]])
    add_static_arp('ipv4');add_static_arp('ipv6')
    run_traffic(action='stop')
    acl_dscp_api.config_service_policy_table(data.dut3, interface_name=vlanInt_tgen[0], service_policy_name='policy_pbr',
                                             policy_kind='unbind', policy_type='forwarding')

    acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name='policy_pbr',
                                          class_name='class_v4', policy_type='forwarding')
    acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name='policy_pbr',
                                          class_name='class_v6', policy_type='forwarding')
    acl_dscp_api.config_policy_table(data.dut3, enable='del', policy_name='policy_pbr')
    acl_dscp_api.config_classifier_table(data.dut3, enable='del', class_name='class_v4',
                                         match_type='fields')
    acl_dscp_api.config_classifier_table(data.dut3, enable='del', class_name='class_v6',
                                         match_type='fields')
    st.log("##### CLeanup End #####")

def test_ipsla_007(pbr_fixture):
    tc_list = ['FtOpSoRoIpSlaFt019']

    ##########################################
    st.banner("Configure Classifiers to match icmp targets on default vrf")
    ##########################################
    acl_dscp_api.config_classifier_table(data.dut3, enable='create', class_name='class_v4',
                                         match_type='fields',
                                         class_criteria=['--dst-ip'],
                                         criteria_value=[target_ips_subnet[0]+str('/{}'.format(mask24))])
    acl_dscp_api.config_classifier_table(data.dut3, enable='create', class_name='class_v6',
                                         match_type='fields',
                                         class_criteria=['--dst-ipv6'],
                                         criteria_value=[target_ipv6_subnet[0]+str('/{}'.format(mask_v6))])

    ##########################################
    st.banner("Configure policy-map with both ipv4 and ipv6 flows")
    ##########################################
    acl_dscp_api.config_flow_update_table(data.dut3, flow='add', policy_name='policy_pbr',
                                          policy_type='forwarding',
                                          class_name='class_v4', flow_priority=10, priority_option='next-hop',
                                          next_hop=[dut1_3_ip_list[0]])

    acl_dscp_api.config_flow_update_table(data.dut3, flow='add', policy_name='policy_pbr',
                                          policy_type='forwarding',
                                          class_name='class_v6', flow_priority=10, priority_option='next-hop',
                                          next_hop=[dut1_3_ipv6_list[0]],version='ipv6')

    ##########################################
    st.banner("Bind service-policy to D3 ingress Vlan intf and start Traffic streams")
    ##########################################

    acl_dscp_api.config_service_policy_table(data.dut3, interface_name=vlanInt_tgen[0], service_policy_name='policy_pbr',
                                             policy_kind='bind', policy_type='forwarding')
    run_traffic()

    ##########################################
    st.banner("Verify service-polivy counters gets incremented")
    ##########################################
    result = verify_policy_counters_incrementing(data.dut3,policy='policy_pbr',flow_list=['class_v4','class_v6'],interface=vlanInt_tgen[0])
    if not result:
        err ='Flow couters not incrementing'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)
    ##########################################
    st.banner("Verify SLAs 1,2 are up")
    ##########################################

    result = retry_api(ip_api.verify_ip_sla,data.dut3,['1','2'], type=['ICMP-echo']*2,
                       target=[target_ips[0],target_ipv6[0]], state=['Up']*2,retry_count=5,delay=1)
    if not result:
        err ='SLAs are not UP'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Shutdown target interface and verify SLAs 1,2 goes down")
    ##########################################
    port_api.shutdown(data.dut4,[data.d4t1_ports[0]])
    result = retry_api(ip_api.verify_ip_sla,data.dut3,['1','2'], type=['ICMP-echo']*2,
                       target=[target_ips[0],target_ipv6[0]], state=['Down']*2,retry_count=10,delay=1)
    if not result:
        err ='SLAs did not go down after target intf shut'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Verify Static routes gets uninstalled")
    ##########################################
    result =verify_ipsla_static_route(entry=False,vrf='default',addr_family='both',sla_type='ICMP-echo')
    if not result:
        err ='Static routes did not get uninstalled after SLAs are down'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Verify policy counters increments after SLA down ")
    ##########################################
    result = verify_policy_counters_incrementing(data.dut3,policy='policy_pbr',flow_list=['class_v4','class_v6'],interface=vlanInt_tgen[0])
    if not result:
        err ='Policy counters did not increment after SLAs are down'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Verify D3 still forwards traffic towards D1 as per service-polivy though SLAs are down")
    ##########################################
    result = verify_traffic_counters(data.dut3,[data.d3d1_ports[0]])
    if not result:
        err ='D3 not forwarding traffic as per policy after SLAs are down'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def ipsla_008_fixture(prologue_epilogue):
    config_loopback()
    config_unnumbered_5549()
    #ipsla_008_static_routes()

    port_api.shutdown(data.dut1, [data.d1d3_ports[0],data.d1d4_ports[0]])
    sla_lst_icmp = ["icmp-echo"] * 2
    dst_ip_lst = [target_ips[0], target_ipv6[0]]
    src_ip_lst = [dut3_1_ip_list[0], dut3_1_ipv6_list[0]]

    for id, dst in zip(range(1, 3), dst_ip_lst):
        ip_api.config_ip_sla(data.dut3, id, sla_type="icmp-echo", dst_ip=dst, config='no', del_cmd_list=['src_addr'])
    ip_api.config_ip_sla(data.dut3, 3, sla_type="tcp-connect", dst_ip=target_ips[1],tcp_port='22',src_addr=dut3_loopback_ip[0])
    ip_api.config_ip_sla(data.dut3, 4, sla_type="tcp-connect", dst_ip=target_ipv6[1],tcp_port='179', config='no', del_cmd_list=['src_addr'])
    yield
    port_api.noshutdown(data.dut1, [data.d1d3_ports[0],data.d1d3_ports[1],data.d1d4_ports[0],data.d1d4_ports[1]])

    ip_api.config_ip_sla(data.dut3, 3, sla_type="tcp-connect", dst_ip=target_ips[1], tcp_port='22',config='no', del_cmd_list=['src_addr'])

    for id, sla, dst, src in zip(range(1, 3), sla_lst_icmp, dst_ip_lst, src_ip_lst):
        ip_api.config_ip_sla(data.dut3, id, sla_type=sla, dst_ip=dst, src_addr=src, config='yes')
    ip_api.config_ip_sla(data.dut3, 4, sla_type="tcp-connect", tcp_port='179',dst_ip=target_ipv6[1],src_addr=dut3_1_ipv6_list[0],config='yes')

    config_unnumbered_5549(config = 'no')
    #ipsla_008_static_routes(config = 'no')
    config_loopback(config = 'remove')



def ipsla_008_static_routes(config = 'yes'):
    if config == 'yes':
        static_route_api = ip_api.create_static_route
    else:
        static_route_api = ip_api.delete_static_route

    ##################################################
    st.banner("Configure next hop as IPv4 unnumbered interface {}".format(data.d3d1_ports[1]))
    ##################################################
    dut = data.dut3
    # Jira 26027 - Instead of interface using loopback ip as next hop for now.
    static_route_api(dut, next_hop=dut1_loopback_ip[0], static_ip=target_ips_subnet[0] + '/' + mask24, track=1)
    static_route_api(dut, next_hop=dut1_loopback_ip[0], static_ip=target_ips_subnet[1] + '/' + mask24, track=3)

    ##################################################
    st.banner("Configure next hop as BGP 5549 interface {}".format(data.d3d1_ports[2]))
    ##################################################
    addr_family_lst = ['ipv4', 'ipv6'] * 2
    mask = [mask24, mask_v6] * 2
    dst_ip_lst = [target_ips_subnet[0], target_ipv6_subnet[0], target_ips_subnet[1], target_ipv6_subnet[1]]

    for i, targ_ip, addr_family, m in zip(range(1, 5), dst_ip_lst, addr_family_lst, mask):
        static_route_api(dut, next_hop=data.d3d1_ports[2], static_ip=targ_ip + '/' + m, family=addr_family, track=i,
                         cli_type='vtysh')

def test_ipsla_008(ipsla_008_fixture):
    tc_list = ['FtOpSoRoIpSlaFt014']
    tech_support = data.tech_support_on_fail
    err_list=[];tc_result=True
    ##########################################
    st.banner("Test case : BGP ip unnumbered and BGP 5549 ")
    ##########################################
    # Configure BGP Unnumbered
    # Verify BGP neibhorship
    # Verify IP SLA
    # Verify static route
    nbrs = [dut3_loopback_ip[0],dut4_loopback_ip[0],data.d1d3_ports[2],data.d1d4_ports[2]]
    result = utils_obj.retry_api(ip_bgp.check_bgp_session, data.dut1, nbr_list=nbrs, state_list=['Established'] * len(nbrs),
                                 delay=1, retry_count=25)
    if not result:
        err ='IPv4 unnumbered BGP session or BGP 5549 is down.'
        failMsg(err);
        st.report_fail('test_case_failure_message',err)

    ##########################################
    st.banner("Except IPv4 unnumbered ports , shutdown other BGP sessions -ipv4 and bgp 5549.")
    ##########################################
    port_api.shutdown(data.dut1, [data.d1d3_ports[2],data.d1d4_ports[2]])

    # Verify IP SLAs.
    ##########################################################
    st.banner("Verify all SLAs comes up with IPv4 unnumbered BGP sessions")
    ##########################################################
    result1 = retry_api(ip_api.verify_ip_sla,data.dut3,['1'], type=['ICMP-echo'],
                       target=[target_ips[0]], state=['Up'],retry_count=20,delay=1)
    result2 = retry_api(ip_api.verify_ip_sla,data.dut3,['3'], type=['TCP-connect'],
                       target=[target_ips[1]+'(22)'], state=['Up'],retry_count=20,delay=1)
    if False in [result1,result2]:
        err='One or more SLA did not come up with IPv4 unnumbered BGP sessions';
        failMsg(err,tech_support,tc_name='ipsla_008_on_fail');tc_result=False
        err_list.append(err);tech_support=False;
    ##########################################
    st.banner("Bring up 5549 BGP session and shutdown other sessions.")
    ##########################################
    port_api.noshutdown(data.dut1, [data.d1d3_ports[2],data.d1d4_ports[2]])
    port_api.shutdown(data.dut1, [data.d1d3_ports[1],data.d1d4_ports[1]])

    result = utils_obj.retry_api(ip_bgp.check_bgp_session,data.dut1, nbr_list=[data.d1d3_ports[2],data.d1d4_ports[2]],
                                  state_list=['Established'] * 2, delay=1, retry_count=30)

    if result is False:
        err='BGP sessions over 5549 did not come up';
        failMsg(err,tech_support,tc_name='ipsla_008_on_fail');tc_result=False
        err_list.append(err);tech_support=False;
    ##########################################################
    st.banner("Verify all SLAs comes up with BGP 5549 BGP sessions")
    ##########################################################
    result = retry_api(verify_ipsla,retry_count=20,delay=1)

    if result is False:
        err = 'One or more SLA did not come up with BGP 5549 BGP sessions';
        failMsg(err, tech_support, tc_name='ipsla_008_on_fail');
        tc_result = False
        err_list.append(err)

    if not tc_result:
        st.report_fail('test_case_failure_message',err_list[0])

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def trigger_fixture(prologue_epilogue):
    # Unconfigure existing IPSLA configurations from functional cases.
    # Configure IP SLAs 25 ICMP-Echo on DUT3 in default VRF and 25 in User VRF
    # Configure frequency and threshold
    # Configure source interface
    # Configure Static routes mapping to 50 SLAs.
    # Configure Targets- On DUT4, 25 Vlans in default VRF and 25 Vlans in User VRF.
    # Configure VRF and IPs .
    config_ip_sla_scale(sla_id=9, sla_count=17)
    config_ip_sla_scale(sla_id=26, sla_count=25, vrf=vrf1, vlan=1026)
    config_ipsla_params()
    yield
    config_ip_sla_scale(sla_id=9, sla_count=17,config='no')
    config_ip_sla_scale(sla_id=26, sla_count=25, vrf=vrf1, vlan=1026,config='no')
    config_ipsla_params(config='no')

def scale_verifications():
    if not verify_bgp():
        err = 'BGP neighborship not coming up'
        failMsg(err);
        return False,err
    if not verify_ipsla_instance_params():
        err = 'One or more IP SLAs configured SLA parameters incorrect.'
        failMsg(err);
        return False, err

    if not verify_ipsla_scale():
        err = 'One or more IP SLAs are down in default VRF.'
        failMsg(err);
        return False, err

    if not verify_ipsla_scale(sla_id=26):
        err = 'One or more IP SLAs are down in user VRF.'
        failMsg(err);
        return False, err
    st.wait(3)
    # Verify flaps if any - Transitions
    if not verify_static_route_scale():
        err = 'One or more static routes are not installed for default VRF.'
        return False, err
    if not verify_static_route_scale(sla_count=25,vrf=vrf1):
        err = 'One or more static routes are not installed for user VRF.'
        return False, err

    return True,None

def test_ipsla_trigger_001(trigger_fixture):
    tc_list = ['FtOpSoRoIpSlaTrig001','FtOpSoRoIpSlaTrig002','FtOpSoRoIpSlaTrig003','FtOpSoRoIpSlaTrig004','FtOpSoRoIpSlaTrig005']
    tech_support = data.tech_support_on_fail
    tc_result = True
    # Verify SLAs are up
    # Verify static routes are configured.
    result,err = scale_verifications()
    if result is False:
        failMsg(err,tech_support,tc_name='ipsla_trigger_001_on_fail');tech_support=False
        st.report_fail('test_case_failure_message',err)

    result = verify_ipsla_static_route(addr_family='both', sla_type='both')
    if result is False:
        err = 'static routes not installed'
        failMsg(err,tech_support,tc_name='ipsla_trigger_001_on_fail');tech_support=False
        st.report_fail('test_case_failure_message',err)
    trigger_list = ['fast_reboot','config_reload','bgp_docker','clear_bgp','warm_boot']

    ##########################################
    st.banner("## Step - Save config ##")
    ##########################################

    bgp_api.enable_docker_routing_config_mode(data.dut3)
    reboot_api.config_save(data.dut3)
    reboot_api.config_save(data.dut3, 'vtysh')
    
    for trigger in trigger_list:
        if trigger == 'clear_bgp':
            tc='FtOpSoRoIpSlaTrig005'
            ##########################################
            st.banner("## Step - Trigger clear bgp ##")
            ##########################################
            bgp_api.clear_ip_bgp_vtysh(data.dut3)

        elif trigger == "bgp_docker":
            tc = 'FtOpSoRoIpSlaTrig004'
            ##########################################
            st.banner("## Step - Trigger bgp docker restart ##")
            ##########################################
            basic_api.service_operations_by_systemctl(data.dut3, "bgp", "restart")
            st.wait(2)
            result = utils_obj.retry_api(basic_api.get_system_status, data.dut3, service = 'bgp', retry_count=20, delay=2)
            if result is False:
                failMsg(err, tech_support, tc_name='ipsla_trigger_001_on_fail');
                tech_support = False
                st.report_fail('test_case_failure_message', err)
        elif trigger == "fast_reboot":
            tc = 'FtOpSoRoIpSlaTrig002'
            ##########################################
            st.banner("## Step - Trigger fast reboot ##")
            ##########################################
            st.reboot(data.dut3, "fast")
        elif trigger == "config_reload":
            tc = 'FtOpSoRoIpSlaTrig003'
            ##########################################
            st.banner("## Step - Trigger config reload ##")
            ##########################################
            reboot_api.config_reload(data.dut3)
        else:
            tc = 'FtOpSoRoIpSlaTrig001'
            ##########################################
            st.banner("## Step - Trigger warm reboot ##")
            ##########################################
            reboot_api.config_warm_restart(data.dut3,oper = "enable", tasks = ["system", "bgp"])
            st.reboot(data.dut3, 'warm')

        st.banner("## Step - Verify SLA status and static routes after trigger {} ##".format(trigger))
        result,err =  scale_verifications()
        if result is False:
            err ='{} after {}'.format(err,trigger)
            failMsg(err, tech_support, tc_name=tc)
            tech_support = False;
            st.report_fail('test_case_failure_message',err)
        else:
            st.report_tc_pass(tc,'tc_passed')
    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def ipsla_scale_fixture(prologue_epilogue):
    # Unconfigure existing IPSLA configurations from functional cases.
    config_ipsla('no')
    yield
    config_ipsla()

def test_ipsla_scale_001(ipsla_scale_fixture):
    tc_list = ['FtOpSoRoIpSlaScale001','FtOpSoRoIpSlaScale002','FtOpSoRoIpSlaScale003','FtOpSoRoIpSlaScale004']
    tc = 'FtOpSoRoIpSlaScale001'
    tc_result1=True;err_list=[];tech_support=data.tech_support_on_fail

    st.banner("Verify max ICMP-Echo IP SLA in default vrf")

    st.banner("## Step - Configure max 50 ICMP-Echo IPv4 SLA ##")
    config_ip_sla_scale(sla_id=1, sla_count=50)
    st.wait(4)

    st.banner("## Step - Verify SLA status of 50 ICMP-Echo IPv4 SLA ##")
    if not verify_ipsla_scale(sla_id=1,sla_count=50):
        err = 'One or more IP SLAs are down in default VRF max ICMP-Echo IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result1 = False

    st.banner("## Step - Verify static route mapped to 50 ICMP-Echo IPv4 SLA ##")
    if not verify_static_route_scale(sla_count=50):
        err = 'One or more static routes are not installed for default VRF with max ICMP-Echo IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result1 = False

    st.banner("## Step - Verify SLA flaps ##")
    if not verify_sla_transition_count():
        err = 'One or more SLAs are flapping.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tc_result1 = False

    st.banner("## Step -Unconfig IP SLAs ##")

    config_ip_sla_scale(sla_id=1, sla_count=50,config='no',targ_config=False,route_config=False)
    if not tc_result1:
        st.report_tc_pass(tc, 'tc_passed')

    tc = 'FtOpSoRoIpSlaScale003'
    tc_result2 = True
    st.banner("Verify max TCP-Connect IP SLA in default vrf")

    st.banner("## Step - Configure max 50 TCP-Connect IPv4 SLA ##")
    config_ip_sla_scale(sla_id=1, sla_count=50,sla_type='tcp-connect',targ_config=False,route_config=False)
    st.wait(4)

    st.banner("## Step - Verify SLA status of 50 TCP-Connect IPv4 SLA ##")
    if not verify_ipsla_scale(sla_id=1,sla_count=50,sla_type='TCP-connect'):
        err = 'One or more IP SLAs are down in default VRF max TCP-Connect IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result2 = False

    st.banner("## Step - Verify static route mapped to 50 TCP-Connect IPv4 SLA ##")
    if not verify_static_route_scale(sla_count=50):
        err = 'One or more static routes are not installed for default VRF with max TCP-Connect IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result2 = False

    st.banner("## Step - Verify SLA flaps ##")
    if not verify_sla_transition_count():
        err = 'One or more SLAs are flapping.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err); tc_result2 = False

    st.banner("## Step -Unconfig TCP-connect default vrf IP SLAs ##")
    config_ip_sla_scale(sla_id=1, sla_count=50,config='no')

    if not tc_result2:
        st.report_tc_pass(tc, 'tc_passed')

    tc = 'FtOpSoRoIpSlaScale002'
    tc_result3=True
    st.banner("Verify max ICMP-Echo IP SLA in User vrf")
    st.banner("## Step - Configure max 50 ICMP-Echo IPv4 SLA in User vrf##")
    config_ip_sla_scale(sla_id=1, sla_count=50,vrf=vrf1)
    st.wait(4)

    st.banner("## Step - Verify SLA status of 50 ICMP-Echo IPv4 SLAin User vrf ##")
    if not verify_ipsla_scale(sla_id=1,sla_count=50):
        err = 'One or more IP SLAs are down in user VRF max ICMP-Echo IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result3 = False

    st.banner("## Step - Verify static route mapped to 50 ICMP-Echo IPv4 SLA ##")
    if not verify_static_route_scale(sla_count=50,vrf=vrf1):
        err = 'One or more static routes are not installed for user VRF with max ICMP-Echo IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result3 = False

    st.banner("## Step - Verify SLA flaps ##")
    if not verify_sla_transition_count():
        err = 'One or more SLAs are flapping.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tc_result3 = False

    config_ip_sla_scale(sla_id=1, sla_count=50,config='no',targ_config=False,route_config=False,vrf=vrf1)

    if not tc_result3:
        st.report_tc_pass(tc, 'tc_passed')

    tc = 'FtOpSoRoIpSlaScale004'
    tc_result4 = True
    st.banner("Verify max TCP-Connect IP SLA in user vrf")

    st.banner("## Step - Configure max 50 TCP-Connect IPv4 SLA ##")
    config_ip_sla_scale(sla_id=1, sla_count=50,sla_type='tcp-connect',targ_config=False,route_config=False,tcp_port='179',vrf=vrf1)
    st.wait(4)

    st.banner("## Step - Verify SLA status of 50 TCP-Connect IPv4 SLA in User vrf##")
    if not verify_ipsla_scale(sla_id=1,sla_count=50,tcp_port='(179)',sla_type='TCP-connect'):
        err = 'One or more IP SLAs are down in user VRF max TCP-Connect IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result4 = False

    st.banner("## Step - Verify static route mapped to 50 TCP-Connect IPv4 SLAin User vrf ##")
    if not verify_static_route_scale(sla_count=50,vrf=vrf1):
        err = 'One or more static routes are not installed for user VRF with max TCP-Connect IP SLA.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err);tech_support=False;tc_result4 = False

    st.banner("## Step - Verify SLA flaps ##")
    if not verify_sla_transition_count():
        err = 'One or more SLAs are flapping in User vrf.'
        failMsg(err, tech_support, tc_name=tc); err_list.append(err); tc_result4 = False
    config_ip_sla_scale(sla_id=1, sla_count=50,vrf=vrf1, config = 'no')

    if False in [tc_result1,tc_result2,tc_result3,tc_result4]:
        st.report_fail('test_case_failure_message',err_list[0])

    st.report_pass('test_case_passed')


