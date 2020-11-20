################################################################################
#
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com
#
################################################################################

import pytest

from spytest import st
import utilities.common as utils

from ipunnum_vars import * #all the variables used for the testcase
from ipunnum_vars import data
import ipunnum_lib as loc_lib
from utilities import parallel

import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_obj
import apis.routing.bfd as bfd_obj
import apis.routing.ospf as ospf_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj
import apis.system.interface as intf_obj

from spytest.tgen.tg import tgen_obj_dict

# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun001,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun002,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun003,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun004,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun005,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun017,test_01_to_05_17
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunRel001,test_reboot_ip_unnumbered
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunRel003,test_config_reload_ip_unnumbered
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun018,test_18_19_20_21
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun019,test_18_19_20_21
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun020,test_18_19_20_21
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun021,test_18_19_20_21
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun006,test_06
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun022,test_22_23_24_25_27
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun023,test_22_23_24_25_27
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun024,test_22_23_24_25_27
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun025,test_22_23_24_25_27
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun027,test_22_23_24_25_27
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun007,test_07_08_09_10_26
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun008,test_07_08_09_10_26
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun009,test_07_08_09_10_26
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun010,test_07_08_09_10_26
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun026,test_07_08_09_10_26
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun012,test_12_13_14_15
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun013,test_12_13_14_15
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun014,test_12_13_14_15
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun015,test_12_13_14_15
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun011,test_11
# Buzznik,buzznik,IPv4 Unnumbered interfaces,FtOpSoRoIPunFun016,test_16


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
    loc_lib.module_config()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    # loc_lib.module_unconfig()
    #loc_lib.reset_streams()

@pytest.mark.sanity
def test_01_to_05_17():

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun001 - Verify IP unnumbered related CLI and show config')
    st.banner('FtOpSoRoIPunFun002 - Verify IP unnumbered interface config on physical interface along with ping, arp and traceroute')
    st.log('Configure IP unnumbered on Physical interfaces between DUT2 and DUT3')
    dict2 = {'family':'ipv4', 'action':'add','interface':data.d2_d3_ports[0], 'loop_back':dut2_loopback[0]}
    dict3 = {'family':'ipv4', 'action':'add','interface':data.d3_d2_ports[0], 'loop_back':dut3_loopback[0]}
    parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.config_unnumbered_interface, [dict2, dict3])
    if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d3_ports[0], dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    if not ip_obj.verify_interface_ip_address(data.dut3, data.d3_d2_ports[0], dut3_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT3-Physical Interface failed')
        result += 1
    ip_obj.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut2, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT2 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.traceroute, data.dut2, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Traceroute from DUT2 to DUT3 failed')
        result += 1
    if not arp_obj.verify_arp(dut = data.dut2, ipaddress = dut3_loopback_ip[0]):
        st.error("Failed to resolve ARP for link local address over physical interface")
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun001','test_case_failed')
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun002','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun002','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun003 - Verify IP unnumbered interface config on portchannel along with ping, arp and traceroute')
    st.banner('FtOpSoRoIPunFun004 - Verify IP unnumbered on a breakout interface')
    st.log('Configure IP unnumbered on PortChannel1 between DUT1 and DUT2')
    dict1 = {'family':'ipv4', 'action':'add','interface':'PortChannel1', 'loop_back':dut1_loopback[0]}
    dict2 = {'family':'ipv4', 'action':'add','interface':'PortChannel1', 'loop_back':dut2_loopback[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    if not ip_obj.verify_interface_ip_address(data.dut1, 'PortChannel1', dut1_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT1-PortChannel1 failed')
        result += 1
    if not ip_obj.verify_interface_ip_address(data.dut2, 'PortChannel1', dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    #st.wait(18)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut2_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT2 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.traceroute, data.dut1, addresses = dut2_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Traceroute from DUT1 to DUT2 failed')
        result += 1
    if not arp_obj.verify_arp(dut = data.dut1, ipaddress = dut2_loopback_ip[0]):
        st.error("Failed to resolve ARP for link local address over portchannel")
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun003','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun003','test_case_failed')
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun004','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun004','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun017 - Verify OSPF BFD over unnumbered interface')
    st.log('Configure BFD on PortChannel and Physical interafce')
    dict1 ={"interface":'PortChannel1','neighbor_ip':dut2_loopback_ip[0],'config':'yes','noshut':'yes'}
    dict2 ={"interface":'PortChannel1','neighbor_ip':dut1_loopback_ip[0],'config':'yes','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    dict1 ={"interface":data.d2_d3_ports[0],'neighbor_ip':dut3_loopback_ip[0],'config':'yes','noshut':'yes'}
    dict2 ={"interface":data.d3_d2_ports[0],'neighbor_ip':dut2_loopback_ip[0],'config':'yes','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut2,data.dut3],bfd_obj.configure_bfd,[dict1,dict2])
    if not loc_lib.retry_api(bfd_obj.verify_bfd_peer, data.dut2, peer = dut1_loopback_ip[0], interface = 'PortChannel1', status= 'up', retry_count= 3, delay= 2):
        st.error('Failed to form BFD session over IP unnumbered session')
        result += 1
    if not loc_lib.retry_api(bfd_obj.verify_bfd_peer, data.dut3, peer = dut2_loopback_ip[0], interface = data.d3_d2_ports[0], status= 'up', retry_count= 3, delay= 2):
        st.error('Failed to form BFD session over IP unnumbered session')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun017','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun017','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun005 - Verify unnumbered interface after adding and removing donar IP')
    st.log('Remove the donar interface on DUT2')
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'del', interface = 'PortChannel1',loop_back = dut2_loopback[0])
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'del', interface = data.d2_d3_ports[0],loop_back = dut2_loopback[0])
    #ip_obj.delete_ip_interface(data.dut2,dut2_loopback[0], dut2_loopback_ipv6[0],ipv6_loopback_prefix, "ipv6")
    ip_obj.delete_ip_interface(data.dut2,dut2_loopback[0], dut2_loopback_ip[0],ip_loopback_prefix, "ipv4")
    ip_obj.configure_loopback(data.dut2,loopback_name = dut2_loopback[0], config="no")
    ip_obj.configure_loopback(data.dut2,loopback_name = dut2_loopback[0], config="yes")
    st.log('On DUT2 Assign IPv4 and IPv6 addressees to the donar interface')
    ip_obj.config_ip_addr_interface(data.dut2, dut2_loopback[0], dut2_loopback_ipv6[0], ipv6_loopback_prefix,'ipv6', 'add', True)
    ip_obj.config_ip_addr_interface(data.dut2, dut2_loopback[0], dut2_loopback_ip[0], ip_loopback_prefix,'ipv4', 'add', True)
    st.log('Re-configure PortChannel1 and physical interface on DUT2 as unnumbered interface')
    if loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[0], interface = 'PortChannel1',ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.log('As expected, IPv4 route from DUT1 to DUT3 not present')
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'add', interface = 'PortChannel1',loop_back = dut2_loopback[0])
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'add', interface = data.d2_d3_ports[0],loop_back = dut2_loopback[0])
    #st.wait(18)
    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[0], interface = 'PortChannel1',ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
       st.error('IPv4 traffic with IPv4 unnumbered failed')
       result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun005','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun005','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_12_13_14(request,prologue_epilogue):
    yield
    ip_obj.config_unnumbered_interface(dut = data.dut1, family='ipv4', action='add',interface='PortChannel1', loop_back=dut1_loopback[0])

#@pytest.mark.depends('test_01_to_05_17')
def test_12_13_14(fixture_test_12_13_14):

    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun012 - Verify ECMP with OSPF over unnumbered interface')
    st.log('Configure IP unnumbered on Physical interfaces between DUT1 and DUT2')
    dict1 = {'family':'ipv4', 'action':'add','interface':data.d1_d2_ports[3], 'loop_back':dut1_loopback[0]}
    dict2 = {'family':'ipv4', 'action':'add','interface':data.d2_d1_ports[3], 'loop_back':dut2_loopback[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, data.d1_d2_ports[3],'point-to-point','default','yes'],
                         [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, data.d2_d1_ports[3],'point-to-point','default','yes']])
    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[0], interface = data.d1_d2_ports[3],ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    dict1 = {'family':'ipv4', 'action':'del','interface':data.d1_d2_ports[3], 'loop_back':dut1_loopback[0]}
    dict2 = {'family':'ipv4', 'action':'del','interface':data.d2_d1_ports[3], 'loop_back':dut2_loopback[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, data.d1_d2_ports[3],'point-to-point','default','no'],
                         [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, data.d2_d1_ports[3],'point-to-point','default','no']])
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun012','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun012','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun014 - Verify OSPF after clearing ospf neighbors and removing and adding ospf')
    ospf_obj.clear_interface_ip_ospf(dut = data.dut2, interfaces = 'PortChannel1')
    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[0], interface = 'PortChannel1',ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    loc_lib.unnumbered_ospf(config = 'no')
    loc_lib.unnumbered_ospf()
    st.log('Wait for OSPF to come up')
    st.wait(20)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[0], interface = 'PortChannel1',ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun014','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun014','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun013 - Verify OSPF with unnumbered interfaces on one side and normal interface on the other side')
    ip_obj.config_unnumbered_interface(dut = data.dut1, family='ipv4', action='del',interface='PortChannel1', loop_back=dut1_loopback[0])
    ip_obj.config_ip_addr_interface(data.dut1, 'PortChannel1', dut1_dut2_ip[0], 24,'ipv4', 'add', True)
    if not ip_obj.verify_interface_ip_address(data.dut1, 'PortChannel1', dut1_dut2_ip[0]+'/'+'24', 'ipv4',''):
        st.error('IP Unnumbered verification for PortChannel1 with new IP address failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut2, type='O', nexthop = dut1_dut2_ip[0], interface = 'PortChannel1',ip_address = dut1_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 2, delay= 10):
        st.log('As expected, IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
    else:
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered as the subnets are different')
        result += 1
    ip_obj.delete_ip_interface(data.dut1, 'PortChannel1', dut1_dut2_ip[0], 24,'ipv4')
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun013','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun013','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
    
@pytest.fixture(scope="function")
def fixture_test_07_08_09_10_26(request,prologue_epilogue):
    yield
    ospf_obj.config_ospf_network(data.dut2, dut2_loopback_ip[1]+'/'+ip_loopback_prefix, 0, 'default', '','yes')
    ospf_obj.config_ospf_network(data.dut2, dut2_loopback_ip[2]+'/'+ip_loopback_prefix, 0, 'default', '','yes')

#@pytest.mark.depends('test_01_to_05_17')
def test_07_08_09_10_26(fixture_test_07_08_09_10_26):

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun009 - Verify unnumbered interface when we alter the donar interface')
    st.banner('FtOpSoRoIPunFun026 - Verify unnumbered interface cannot have multiple donars')
    st.log('Remove the unnumbered configuration from PortChannel1 and reconfigure a different loopback as a donar')
    ospf_obj.config_ospf_network(data.dut2, dut2_loopback_ip[1]+'/'+ip_loopback_prefix, 0, 'default', '','yes')
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'del', interface = 'PortChannel1', loop_back = dut2_loopback[0])
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'add', interface = 'PortChannel1',loop_back = dut2_loopback[1])
    if not ip_obj.verify_interface_ip_address(data.dut2, 'PortChannel1', dut2_loopback_ip[1]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-PortChannel failed')
        result += 1
    st.log('Wait for OSPF to come up')
    st.wait(20)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun009','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun009','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun008 - Verify multiple unnumbered interfaces with the same donar IP')
    st.log('Remove the unnumbered configuration from PortChannel1 and reconfigure the same loopback for two interfaces')
    ospf_obj.config_ospf_network(data.dut2, dut2_loopback_ip[1]+'/'+ip_loopback_prefix, 0, 'default', '','yes')
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'del', interface = 'PortChannel1',loop_back = dut2_loopback[1])
    ip_obj.config_unnumbered_interface(data.dut2, family = 'ipv4', action = 'add', interface = 'PortChannel1',loop_back = dut2_loopback[0])
    if not ip_obj.verify_interface_ip_address(data.dut2, 'PortChannel1', dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Portchannel failed')
        result += 1
    #st.wait(18)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun008','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun008','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun007 - Verify secondary IP not supported for IP unnumbered donor interface')
    st.banner('FtOpSoRoIPunFun007 - Verify change in donor interface IP is reflected in borrower interface')
    st.log('Add a new IP address to the loopback and delete the existing one')
    if ip_obj.config_ip_addr_interface(data.dut2, dut2_loopback[0], dut2_loopback_ip[2], ip_loopback_prefix,'ipv4', 'add',False, is_secondary_ip="yes"):
        st.error('Secondary IP on a donor interface is supported DUT2 which is not expcted failed')
        result += 1
    else:
        st.log('Secondary IP on a donor interface is not supported as expected passed')

    ip_obj.delete_ip_interface(data.dut2,dut2_loopback[0], dut2_loopback_ip[0],ip_loopback_prefix, "ipv4")
    if not ip_obj.config_ip_addr_interface(data.dut2, dut2_loopback[0], dut2_loopback_ip[2], ip_loopback_prefix,'ipv4', 'add',False):
        st.error('Cannot add multiple addressed on the donar interfaces')
        result += 1
    ip_obj.configure_loopback(data.dut2,loopback_name=dut2_loopback[4],config="yes")
    if not ip_obj.config_ip_addr_interface(data.dut2, dut2_loopback[4], dut2_loopback_ip[4], '32','ipv4', 'add',False):
        st.error('Cannot add IP address with a different subnet')
        result += 1

    if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d3_ports[0], dut2_loopback_ip[2]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('Change Donor interface primary IP do not change barrower IP on DUT2 failed')
        result += 1
    else:
        st.log('Change Donor interface primary IP do change barrower IP on DUT2 passed')

    ip_obj.configure_loopback(data.dut2,loopback_name=dut2_loopback[4],config="no")
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun007','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun007','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_01_to_05_17')
def test_reboot_ip_unnumbered():
    ######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunRel001 - Verify unnumbered interface accross a fast reboot')
    st.log("Verify ping before reboot")
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    st.log("Save the running config in sonic and vtysh modes")
    reboot_obj.config_save(data.dut2)
    reboot_obj.config_save(data.dut2, shell='vtysh')
    st.reboot(data.dut2, 'fast')
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunRel001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunRel001','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_18_19_20_21(request,prologue_epilogue):
    yield
    loc_lib.bgp_unconfig()

#@pytest.mark.depends('test_01_to_05_17')
def test_18_19_20_21(fixture_test_18_19_20_21):
    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun021 - Verify multi hop BGP session over unnumbered interface')
    st.banner('FtOpSoRoIPunFun018 - Verify BGP session over unnumbered interface')
    st.log('####s##------Configure BGP--######')
    loc_lib.bgp_router_id()
    dict1 = {'local_as':dut1_as,'neighbor':dut3_loopback_ip[0],'remote_as':dut3_as,'config_type_list':['neighbor']}
    dict2 = {'local_as':dut3_as,'neighbor':dut1_loopback_ip[0],'remote_as':dut1_as,'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'local_as':dut1_as,'neighbor':dut3_loopback_ip[0],'remote_as':dut3_as,'config_type_list':['activate','update_src_intf','ebgp_mhop'],'update_src_intf':'PortChannel1','ebgp_mhop':'2'}
    dict2 = {'local_as':dut3_as,'neighbor':dut1_loopback_ip[0],'remote_as':dut1_as,'config_type_list':['activate','update_src_intf','ebgp_mhop'],'update_src_intf':data.d3_d2_ports[0],'ebgp_mhop':'2'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_obj.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Established', retry_count= 5, delay= 10):
        st.error("Failed to form multihop BGP session having IP unnumbered configuration")
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun021','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun021','test_case_failed')
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun018','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun018','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun020 - Verify BGP over unnumbered session after a clear and adding and removing BGP')
    st.log("Clear the BGP session")
    bgp_obj.clear_ip_bgp_vtysh(data.dut1, value="*")
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Established', retry_count= 5, delay= 10):
        st.error("Failed to form multihop BGP session having IP unnumbered configuration")
        result += 1

    if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='O', nexthop = dut2_loopback_ip[2], interface = 'PortChannel1',ip_address = dut3_loopback_ip[0]+'/'+ip_loopback_prefix,family = "ipv4", retry_count= 5, delay= 10):
        st.error('IPv4 route from DUT1 to DUT3 not learnt using IP unnumbered')
        loc_lib.debug_failure()
        result += 1
    st.log("Unconfigure/reconfigure BGP and verify")
    loc_lib.bgp_unconfig()
    loc_lib.bgp_router_id()
    dict1 = {'local_as':dut1_as,'neighbor':dut3_loopback_ip[0],'remote_as':dut3_as,'config_type_list':['neighbor']}
    dict2 = {'local_as':dut3_as,'neighbor':dut1_loopback_ip[0],'remote_as':dut1_as,'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'local_as':dut1_as,'neighbor':dut3_loopback_ip[0],'remote_as':dut3_as,'config_type_list':['activate','update_src_intf','ebgp_mhop'],'update_src_intf':'PortChannel1','ebgp_mhop':'2'}
    dict2 = {'local_as':dut3_as,'neighbor':dut1_loopback_ip[0],'remote_as':dut1_as,'config_type_list':['activate','update_src_intf','ebgp_mhop'],'update_src_intf':data.d3_d2_ports[0],'ebgp_mhop':'2'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_obj.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Established', retry_count= 13, delay= 10):
        st.error("Failed to form multihop BGP session having IP unnumbered configuration")
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun020','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun020','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun019 - Verify BGP BFD session over unnumbered interface')
    st.log('Configure BFD on BGP unnumbered session')
    dict1 = {'config':'yes', 'local_as':dut1_as,'config_type_list': ['bfd'],'neighbor': dut3_loopback_ip[0],'remote_as':dut3_as}
    dict2 = {'config':'yes', 'local_as':dut3_as,'config_type_list': ['bfd'],'neighbor': dut1_loopback_ip[0],'remote_as':dut1_as}
    parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_obj.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Established', retry_count= 5, delay= 10):
        st.error("Failed to form multihop BGP session having IP unnumbered configuration")
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 2):
        st.error('IPv4 Ping from DUT1 to DUT2 failed')
        result += 1
    if not loc_lib.retry_api(bfd_obj.verify_bfd_peer, data.dut1, peer = dut3_loopback_ip[0], multihop = 'yes', local_addr = dut1_loopback_ip[0], status= 'up', retry_count= 3, delay= 2):
        st.error('Failed to form mutlihop BFD session over BGP unnumbered session')
        result += 1
    st.log("Flap the interface and reverify the BFD session")
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1]])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Active', retry_count= 2, delay= 3):
        st.error("Multihop BGP session having IP unnumbered configuration has not gone down")
        result += 1
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1]])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', neighbor = dut3_loopback_ip[0], state='Established', retry_count= 5, delay= 10):
        st.error("Failed to form multihop BGP session having IP unnumbered configuration")
        result += 1
    if not loc_lib.retry_api(bfd_obj.verify_bfd_peer, data.dut1, peer = dut3_loopback_ip[0], multihop = 'yes', local_addr = dut1_loopback_ip[0], status= 'up', retry_count= 2, delay= 3):
        st.error('Failed to form mutlihop BFD session over BGP unnumbered session')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun019','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun019','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_06(request,prologue_epilogue):
    yield
    loc_lib.ipv6_bgp_unconfig()

#@pytest.mark.depends('test_01_to_05_17')
def test_06(fixture_test_06):

    ########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun006 - Verify unnumbered interface with IPv6 address configured on that interface')
    st.log('Enable autogenerated link local on PortChannel1 and configure BGP unnumbered for PortChannel1')
    loc_lib.bgp_router_id()
    loc_lib.ipv6_bgp(type = 'unnumbered')
    loc_lib.ipv6_bgp(type = 'normal')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv6', neighbor = ['PortChannel1'], state='Established', retry_count= 13, delay= 10):
        st.error("Failed to form BGP unnumbered session over portchannel having IP unnumbered configuration")
        result += 1
    bgp_obj.activate_bgp_neighbor(data.dut1,dut1_as,dut2_dut1_ipv6[0],'ipv6',remote_asn = dut2_as)
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,dut1_dut2_ipv6[0],'ipv6',remote_asn = dut1_as)
    st.log('Assign global IPv6 address on PortChannel and  configure BGPv6 neighbor for PortChannel1')
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, 'PortChannel1', dut1_dut2_ipv6[0], 64,'ipv6', 'add', True],
                         [ip_obj.config_ip_addr_interface, data.dut2, 'PortChannel1', dut2_dut1_ipv6[0], 64,'ipv6', 'add', True]])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv6', neighbor = [dut2_dut1_ipv6[0]], state='Established', retry_count= 13, delay= 10):
        st.error("Failed to form BGPv6 session over portchannel having IP unnumbered configuration")
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun006','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun006','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_01_to_05_17')
def test_22_23_24_25_27():

    #########################################################################################################################################
    result = 0 
    st.banner('FtOpSoRoIPunFun022 - Verify static route configuration with unnumbered interface')
    st.banner('FtOpSoRoIPunFun025 - Verify IP address cannot be configured on an unnumbered interface')
    dict1 = {'family':'ipv4', 'action':'add','interface':data.d1_d2_ports[2], 'loop_back':dut1_loopback[0]}
    dict2 = {'family':'ipv4', 'action':'add','interface':data.d2_d1_ports[2], 'loop_back':dut2_loopback[1]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d1_ports[2], dut2_loopback_ip[1]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    st.log('Configure static routes for unnumbered interfaces')
    utils.exec_all(True,[[ip_obj.create_static_route, data.dut1, None, dut2_loopback_ip[1]+'/32','sonic','ipv4',data.d1_d2_ports[2]],
                         [ip_obj.create_static_route, data.dut2, None, dut1_loopback_ip[0]+'/32','sonic','ipv4',data.d2_d1_ports[2]]])
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_loopback_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT2 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    utils.exec_all(True,[[ip_obj.delete_static_route, data.dut1, None, dut2_loopback_ip[1]+'/32','ipv4','vtysh',data.d1_d2_ports[2], None],
                         [ip_obj.delete_static_route, data.dut2, None, dut1_loopback_ip[0]+'/32','ipv4','vtysh',data.d2_d1_ports[2], None]])
    dict1 = {'family':'ipv4', 'action':'del','interface':data.d1_d2_ports[2], 'loop_back':dut1_loopback[0]}
    dict2 = {'family':'ipv4', 'action':'del','interface':data.d2_d1_ports[2], 'loop_back':dut2_loopback[1]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun022','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun022','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun023 - Verify unnumbered interface cannot be bound to a VRF')
    st.banner('FtOpSoRoIPunFun027 - Verify error messages for IP unnumbered')
    vrf_obj.config_vrf(dut = data.dut1, vrf_name = 'Vrf-1', skip_error = True)
    vrf_obj.bind_vrf_interface(dut = data.dut1, vrf_name = 'Vrf-1', intf_name = data.d1_d2_ports[2], skip_error = True)
    if not ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'add', interface = data.d1_d2_ports[2], loop_back = dut1_loopback[0], skip_error = True):
        st.error('IP Unnumbered configuration on a port bound to VRF should fail')
        result += 1
    else:
        st.log('As expected, IP Unnumbered configuration on a port bound to VRF is not supported')
    if ip_obj.verify_interface_ip_address(data.dut1, data.d1_d2_ports[2], dut1_loopback[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    vrf_obj.config_vrf(dut = data.dut1, vrf_name = 'Vrf-1', config = 'no')
    if ip_obj.verify_interface_ip_address(data.dut1, data.d1_d2_ports[2], dut1_loopback[0]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun023','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun023','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun024 - Verify static routes, BGP and OSPF with the same donar')
    dict1 = {'config':'yes','loopback_name':dut1_loopback[3]}
    dict2 = {'config':'yes','loopback_name':dut2_loopback[3]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.configure_loopback, [dict1, dict2])
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, dut1_loopback[3], dut1_loopback_ip[3], ip_loopback_prefix,'ipv4', 'add', True],
                         [ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[3], dut2_loopback_ip[3], ip_loopback_prefix,'ipv4', 'add', True]])
    dict1 = {'family':'ipv4', 'action':'add','interface':data.d1_d2_ports[3], 'loop_back':dut1_loopback[3]}
    dict2 = {'family':'ipv4', 'action':'add','interface':data.d2_d1_ports[3], 'loop_back':dut2_loopback[3]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    if not ip_obj.verify_interface_ip_address(data.dut1, data.d1_d2_ports[3], dut1_loopback_ip[3]+'/'+ip_loopback_prefix, 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip[3]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                         [ospf_obj.config_ospf_network, data.dut2, dut2_loopback_ip[3]+'/'+ip_loopback_prefix, 0, 'default', '','yes']])
    utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, data.d1_d2_ports[3],'point-to-point','default','yes'],
                         [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, data.d2_d1_ports[3],'point-to-point','default','yes']])
    dict1 = {'router_id':dut1_router_id,'local_as':dut1_as,'neighbor':dut2_loopback_ip[3],'remote_as':dut2_as,'config_type_list':['neighbor']}
    dict2 = {'router_id':dut2_router_id,'local_as':dut2_as,'neighbor':dut1_loopback_ip[3],'remote_as':dut1_as,'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'local_as':dut1_as,'neighbor':dut2_loopback_ip[3],'remote_as':dut2_as,'config_type_list':['activate']}
    dict2 = {'local_as':dut2_as,'neighbor':dut1_loopback_ip[3],'remote_as':dut1_as,'config_type_list':['activate']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    st.wait(20)
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip[3]+'/'+ip_loopback_prefix, 0, 'default', '','no'],
                         [ospf_obj.config_ospf_network, data.dut2, dut2_loopback_ip[3]+'/'+ip_loopback_prefix, 0, 'default', '','no']])
    utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, data.d1_d2_ports[3],'point-to-point','default','no'],
                         [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, data.d2_d1_ports[3],'point-to-point','default','no']])
    dict1 = {'family':'ipv4', 'action':'del','interface':data.d1_d2_ports[3], 'loop_back':dut1_loopback[3]}
    dict2 = {'family':'ipv4', 'action':'del','interface':data.d2_d1_ports[3], 'loop_back':dut2_loopback[3]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, dut1_loopback[3], dut1_loopback_ip[3], ip_loopback_prefix,'ipv4'],
                         [ip_obj.delete_ip_interface, data.dut2, dut2_loopback[3], dut2_loopback_ip[3], ip_loopback_prefix,'ipv4']])
    dict1 = {'config':'no','loopback_name':dut1_loopback[3]}
    dict2 = {'config':'no','loopback_name':dut2_loopback[3]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.configure_loopback, [dict1, dict2])
    loc_lib.bgp_unconfig()
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun024','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun024','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_01_to_05_17')
def test_config_reload_ip_unnumbered():
    ######################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunRel003 - Verify unnumbered interface accross a config reload')
    reboot_obj.config_save(data.dut2)
    reboot_obj.config_save(data.dut2, shell='vtysh')
    reboot_obj.config_reload(data.dut2)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunRel003','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunRel003','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_01_to_05_17')
def test_16():
    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun016 - Verify L3 MTU with unnumbered interface')
    utils.exec_all(True,[[intf_obj.interface_properties_set, data.dut2, [data.d2_d3_ports[0]],'mtu','1548','False'],
                         [intf_obj.interface_properties_set, data.dut3, [data.d3_d2_ports[0]],'mtu','1548','False']])
    if not intf_obj.verify_interface_status(dut = data.dut2, interface = data.d2_d3_ports[0], property = 'mtu', value = '1548'):
        st.error('MTU for IPv4 unnumbered interface not modified')
        result += 1
    #st.wait(18)
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 6, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    utils.exec_all(True,[[intf_obj.interface_properties_set, data.dut2, [data.d2_d3_ports[0]],'mtu','9100','False','click'],
                         [intf_obj.interface_properties_set, data.dut3, [data.d3_d2_ports[0]],'mtu','9100','False','click']])
    if not intf_obj.verify_interface_status(dut = data.dut2, interface = data.d2_d3_ports[0], property = 'mtu', value = '9100'):
        st.error('MTU for IPv4 unnumbered interface not modified')
        result += 1
    #st.wait(18)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 6, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun016','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun016','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_01_to_05_17')
def test_11_15():
    #####################################################################################################################################

    result = 0
    st.banner('FtOpSoRoIPunFun015 - Verify OSPF when the donar IP interface is same as router ID')
    st.banner('FtOpSoRoIPunFun011 - Verify unnumbered interfaces where all the donars in the topology have the same IP')
    st.log('Configure loopbacks with same IPs')
    dict1 = {'config':'yes','loopback_name':dut2_loopback[4]}
    dict2 = {'config':'yes','loopback_name':dut3_loopback[4]}
    parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2])
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[4], '11.11.11.11', 32,'ipv4', 'add', True],
                         [ip_obj.config_ip_addr_interface, data.dut3, dut3_loopback[4], '11.11.11.11', 32,'ipv4', 'add', True]])
    st.log('Configure IP unnumbered on Physical interfaces between DUT2 and DUT3')
    dict2 = {'family':'ipv4', 'action':'add','interface':data.d2_d3_ports[3], 'loop_back':dut2_loopback[4]}
    dict3 = {'family':'ipv4', 'action':'add','interface':data.d3_d2_ports[3], 'loop_back':dut3_loopback[4]}
    parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.config_unnumbered_interface, [dict2, dict3])
    if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d3_ports[3], '11.11.11.11/32', 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT2-Physical Interface failed')
        result += 1
    if not ip_obj.verify_interface_ip_address(data.dut3, data.d3_d2_ports[3], '11.11.11.11/32', 'ipv4','','U'):
        st.error('IP Unnumbered configuration on DUT3-Physical Interface failed')
        result += 1
    ip_obj.show_ip_route(data.dut1, family="ipv4", shell="sonic", vrf_name=None)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], retry_count= 5, delay= 10):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic(type = 'ipv4')
    if not aggrResult:
        st.error('IPv4 traffic with IPv4 unnumbered failed')
        result += 1
    st.log('Unconfigure')
    dict2 = {'family':'ipv4', 'action':'del','interface':data.d2_d3_ports[3], 'loop_back':dut2_loopback[4]}
    dict3 = {'family':'ipv4', 'action':'del','interface':data.d3_d2_ports[3], 'loop_back':dut3_loopback[4]}
    parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.config_unnumbered_interface, [dict2, dict3])
    dict1 = {'config':'no','loopback_name':dut2_loopback[4]}
    dict2 = {'config':'no','loopback_name':dut3_loopback[4]}
    parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2])
    if result == 0 :
        st.report_tc_pass('FtOpSoRoIPunFun011','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoIPunFun011','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
