###############################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com
###############################################################################

import pytest

from spytest import st
import utilities.common as utils

from ipunnum_vars import * #all the variables used for the testcase
from ipunnum_vars import data
import ipunnum_lib as loc_lib
from utilities import parallel

import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj

from spytest.tgen.tg import tgen_obj_dict

# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunScl001,test_scale_ip_unnumbered
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunRel002,test_warm_reboot_ip_unnumbered

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
    loc_lib.tg_streams()
    loc_lib.module_config_scale()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    loc_lib.module_unconfig_scale()
    loc_lib.reset_streams()

@pytest.mark.sanity
def test_scale_ip_unnumbered():

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunScl001 - Verify maximum IPv4 unnumbered interfaces')
    st.log('Configure IP unnumbered on Physical interfaces between DUT1 and DUT3')
    for d1port, d2port in zip(data.d1_d2_ports,data.d2_d1_ports):
        dict1 = {'family':'ipv4', 'action':'add','interface':d1port, 'loop_back':dut1_loopback[0]}
        dict2 = {'family':'ipv4', 'action':'add','interface':d2port, 'loop_back':dut2_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    st.log('Configure IP unnumbered on Physical interfaces between DUT2 and DUT3')
    for d2port, d3port in zip(data.d2_d3_ports,data.d3_d2_ports):
        dict2 = {'family':'ipv4', 'action':'add','interface':d2port, 'loop_back':dut2_loopback[0]}
        dict3 = {'family':'ipv4', 'action':'add','interface':d3port, 'loop_back':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.config_unnumbered_interface, [dict2, dict3])
    if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d3_ports[0], dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not arp_obj.verify_arp(dut = data.dut2, ipaddress = dut3_loopback_ip[0]):
        st.error("Failed to resolve ARP for link local address over physical interface")
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    port_obj.shutdown(data.dut2, [data.d2_d1_ports[0],data.d2_d1_ports[1],data.d2_d1_ports[2],data.d2_d1_ports[3],data.d2_d3_ports[0],data.d2_d3_ports[1],data.d2_d3_ports[2],data.d2_d3_ports[3]])
    st.log('Wait for OSFP to go down')
    st.wait(10)
    port_obj.noshutdown(data.dut2, [data.d2_d1_ports[0],data.d2_d1_ports[1],data.d2_d1_ports[2],data.d2_d1_ports[3],data.d2_d3_ports[0],data.d2_d3_ports[1],data.d2_d3_ports[2],data.d2_d3_ports[3]])
    st.log('Wait for OSFP to come up')
    st.wait(10)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT2 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunScl001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunScl001','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_warm_reboot_ip_unnumbered():

    #####################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunRel002 - Verify unnumbered interface accross a warm reboot')
    st.log('Enable warm restart for dockers')
    reboot_obj.config_warm_restart(data.dut2, oper = "enable")
    reboot_obj.config_warm_restart(data.dut2, oper = "enable", tasks = ["swss", "teamd", "system"])
    st.log("Save the running config in sonic and vtysh modes")
    reboot_obj.config_save(data.dut2)
    st.vtysh(data.dut2,"copy running startup")
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed before warm_restart')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed before warm_restart')
        result += 1
    st.reboot(data.dut2, 'warm')
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 4, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT2 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    reboot_obj.config_warm_restart(data.dut2, oper = "disable")
    reboot_obj.config_warm_restart(data.dut2, oper = "disable", tasks = ["swss", "teamd", "system"])
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunRel002','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunRel002','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
