###############################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest
from spytest import st, putils
from spytest.tgen.tg import tgen_obj_dict
import utilities.common as utils

from dyndis_vars import * #all the variables used for the testcases
from dyndis_vars import data
import dyndis_lib as loc_lib
from utilities import parallel

import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.system.reboot as reboot_obj


#Topology:
#------#TG#----(2links)----#DUT1#----(4links)----#DUT2#----(2links)-----#TG#--------#

def initialize_topology():
    st.log("Script Starts Here!. Initialize..........................................................................................")
    vars = st.ensure_min_topology("D1D2:4","D2D3:4","D1T1:2", "D3T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    utils.exec_all(True,[[bgp_obj.enable_docker_routing_config_mode,data.dut1], [bgp_obj.enable_docker_routing_config_mode,data.dut2], [bgp_obj.enable_docker_routing_config_mode,data.dut3]])
    data.d1_d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2_d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]
    data.d2_d3_ports = [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3,vars.D2D3P4]
    data.d3_d2_ports = [vars.D3D2P1,vars.D3D2P2,vars.D3D2P3,vars.D3D2P4]
    data.dut1_tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.dut3_tg_ports = [vars.D3T1P1,vars.D3T1P2]
    data.tg_dut1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tg_dut3_ports = [vars.T1D3P1,vars.T1D3P2]
    data.tg = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg.get_port_handle(vars.T1D1P1)
    data.tg_dut3_p1 = data.tg.get_port_handle(vars.T1D3P1)
    data.tg_dut1_p2 = data.tg.get_port_handle(vars.T1D1P2)
    data.tg_dut3_p2 = data.tg.get_port_handle(vars.T1D3P2)
    data.d1_stream_list = {}
    data.d1_stream_list_vrf = {}
    data.d3_stream_list = {}
    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 2
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 1

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    global bgp_cli_type
    bgp_cli_type = st.get_ui_type()
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    loc_lib.module_config_scale()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    loc_lib.module_unconfig_scale()
    loc_lib.reset_streams()

#Buzznik,buzznik,Dynamic BGP Neighbor Hardening,FtOpSoRoAutoSc001,test_dynamic_unnumbered_scale

@pytest.mark.sanity
def test_dynamic_unnumbered_scale():

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoAutoSc001 - Verify maximum BGP unnumbered sessions')
    st.banner('FtOpSoRoAutoSc002 - Verify maximum sessions with listen range')
    vlan_list_d1_d2 = ['%s'%x for x in range (1,101)]
    ip_list_dut2 = loc_lib.ip_range('2.0.0.1',2,100)
    ip_list_dut3 = loc_lib.ip_range('2.0.0.2',2,100)
    loc_lib.bgp_router_id()
    loc_lib.redistribute_routes()
    st.log('Configure BGP unnumbered sessions or 100 vlans between DUT1 and DUT2')
    for vlan in vlan_list_d1_d2:
        dict1 = {'addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list':['remote-as','activate'],'interface':'Vlan'+vlan,'neighbor':'Vlan'+vlan}
        dict2 = {'addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list':['remote-as','activate'],'interface':'Vlan'+vlan,'neighbor':'Vlan'+vlan}
        putils.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    st.log('Configure IPv4 peer groups on DUT2 and DUT3')
    utils.exec_all(True,[[bgp_obj.create_bgp_peergroup,data.dut2, dut2_as,'d2d3_v4_peer',dut3_as], [bgp_obj.create_bgp_peergroup,data.dut3, dut3_as,'d2d3_v4_peer',dut2_as]])
    st.log('Configure listen range on DUT2')
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2.0.0.0', subnet = 16, peer_grp_name = 'd2d3_v4_peer', limit = 100, config = 'yes')
    st.log('Configure IPv4 and IPv6 BGP sessions on DUT2 and DUT3')
    st.log('Configure neighbors on DUT3')
    for ip in ip_list_dut2:
        bgp_obj.create_bgp_neighbor_use_peergroup(dut = data.dut3, local_asn = dut3_as, peer_grp_name = 'd2d3_v4_peer', neighbor_ip = ip, family="ipv4")
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as,ip,'ipv4',remote_asn = dut2_as)
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as,ip,'ipv6',remote_asn = dut2_as)

    st.log('Configure 100 BGP sessions with listen range')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = ['Vlan2','*'+ip_list_dut3[0]], state='Established', retry_count= 10, delay= 15):
        st.error("Failed to form BGP unnumbered session using IPv6 link local address over vlan")
        result += 1
    ip_obj.show_ip_route(data.dut1, family = "ipv4")
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 10, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over vlan with BGP unnumbered and Dynamic Discovery failed')
        result += 1
    st.log("Reduce the limit and verify the neighbor is removed")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 1)
    bgp_obj.clear_ip_bgp_vtysh(data.dut2, value="*")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 100)
    bgp_obj.clear_ip_bgp_vtysh(data.dut2, value="*")
    st.wait(2)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = ['Vlan2','*'+ip_list_dut3[0]], state='Established', retry_count= 10, delay= 15):
        st.error("Failed to form BGP unnumbered session using IPv6 link local address over vlan")
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoAutoSc001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoAutoSc001','test_case_failed')

    if result == 0 :
        st.report_tc_pass('FtOpSoRoAutoSc002','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoAutoSc002','test_case_failed')

    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_warm_reboot(request,prologue_epilogue):
    yield
    reboot_obj.config_warm_restart(data.dut2, oper = "disable")
    reboot_obj.config_warm_restart(data.dut2, oper = "disable", tasks = ["bgp", "swss", "teamd", "system"])
    dict1 = {'local_asn':dut1_as,'config':'del','preserve_state':'1'}
    dict2 = {'local_asn':dut2_as,'config':'del','preserve_state':'1'}
    dict3 = {'local_asn':dut3_as,'config':'del','preserve_state':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp_graceful_restart, [dict1, dict2, dict3])

def test_warm_reboot_dynmaic_neigh(fixture_test_warm_reboot):

    #####################################################################################################################################

    errs = []
    st.banner('FtOpSoRoDynReb002 - Verify BGP unnumbererd and listen range on default after a warm reboot')
    st.log(" Add graceful restart and preserve_state state configuration")
    dict1 = {'local_asn':dut1_as,'config':'add','preserve_state':'1'}
    dict2 = {'local_asn':dut2_as,'config':'add','preserve_state':'1'}
    dict3 = {'local_asn':dut3_as,'config':'add','preserve_state':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp_graceful_restart, [dict1, dict2, dict3])
    st.log('FtOpSoRoDynReb002 - Enable warm restart for dockers')
    reboot_obj.config_warm_restart(data.dut2, oper = "enable")
    reboot_obj.config_warm_restart(data.dut2, oper = "enable", tasks = ["bgp", "swss", "teamd", "system"])
    st.log("Verify ping and BGP session before warm reboot")
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = 'Vlan2', state='Established', retry_count= 10, delay= 15):
        errs.append(st.error("Failed to form BGP unnumbered session using IPv6 link local address over vlan"))
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 10, delay= 10):
        errs.append(st.error('IPv4 Ping from DUT1 to DUT3 failed'))
    st.log("Save the running config in sonic and vtysh modes")
    reboot_obj.config_save(data.dut2)
    st.vtysh(data.dut2,"copy running startup")
    st.reboot(data.dut2, 'warm')
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 10, delay= 10):
        errs.append(st.error('IPv4 Ping from DUT1 to DUT3 failed'))
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        errs.append(st.error('IPv4 traffic over default VRF with BGP unnumbered and Dynamic Discovery failed'))

    if not errs:
        st.report_tc_pass('FtOpSoRoDynReb002','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynReb002','test_case_failed')

    if not errs:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed_msg', ", ".join(errs))

