###############################################################################
#Script Title : IP unnumbered over non-default vrf vrf and vlan
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest
from spytest import st
from unnumbered_vrf_vars import data
import unnumbered_vrf_lib as loc_lib
from utilities import parallel
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.routing.bfd as bfd_obj
import apis.routing.ospf as ospf_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj
import apis.switching.mac as mac_obj
import utilities.common as utils
from spytest.tgen.tg import tgen_obj_dict
from utilities.utils import retry_api

#Topology:
#------#TG#----(2links)----#DUT1#----(4links)----#DUT2#----(2links)-----#TG#--------#



def initialize_topology():
    st.log("Script Starts Here!. Initialize..........................................................................................")

    #DUT topology variables
    vars = st.ensure_min_topology("D1D2:4","D1T1:2", "D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.d1_d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2_d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]

    #DUT-TG topology variables
    data.dut1_tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.dut2_tg_ports = [vars.D2T1P1,vars.D2T1P2]
    data.tg_dut1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tg_dut2_ports = [vars.T1D2P1,vars.T1D2P2]
    data.tg = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg.get_port_handle(vars.T1D1P1)
    data.tg_dut2_p1 = data.tg.get_port_handle(vars.T1D2P1)
    data.tg_dut1_p2 = data.tg.get_port_handle(vars.T1D1P2)
    data.tg_dut2_p2 = data.tg.get_port_handle(vars.T1D2P2)
    data.d1_stream_list = {}
    data.d2_stream_list = {}
    data.d1_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut1,data.dut1_tg_ports[0])
    #TGEN delay
    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 2
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 1

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.module_config()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    loc_lib.tg_streams()
    yield

@pytest.fixture(scope="function")
def fixture_test_unnumvrf_basic(request,prologue_epilogue):
    yield
    port_obj.noshutdown(data.dut1, data.d1_d2_ports)

def test_unnumvrf_basic(fixture_test_unnumvrf_basic):
    tc_list = ['FtOpSoRoIPnumvrfFun001','FtOpSoRoIPnumvrfFun002','FtOpSoRoIPnumvrfFun003']
    final_result = 0
    error_list = []
    st.banner('FtOpSoRoIPnumvrfFun001 -- to -- FtOpSoRoIPnumvrfFun003')

    st.banner('Configure and verify IP unnumbered over non-default vrf and default-vrf on a physical interface ')
    tc_result = True
    result = utils.exec_all(True, [[loc_lib.dut1_config_unnumbered,'phy',''],[loc_lib.dut2_config_unnumbered,'phy','']]) 
    if result is False:
        error = "IP unnumbered configuration on a physical interface failed"
        tc_result = False ; error_list.append(error)
    result = utils.exec_all(True, [[loc_lib.dut1_verify_unnumbered, 'phy'],[loc_lib.dut2_verify_unnumbered,'phy']]) 
    if result is False:
        error = "IP unnumbered verification on a physical interface failed"
        tc_result = False ; error_list.append(error)
    st.log('On DUT1 verify routes on non default vrf use physical interface')
    result = retry_api(ip_obj.verify_ip_route, data.dut1, vrf_name = data.dut1_vrf[0], type='O', nexthop = data.dut2_loopback_ip[0], interface = data.d1_d2_ports[0],ip_address = data.dut2_loopback_ip[0]+'/'+data.ip_loopback_prefix, family = "ipv4", retry_count= 7, delay= 5)
    if result is False:
        error = "IP routes on non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.send_verify_traffic(type = 'ipv4')
    if result is False:
        error = 'IPv4 traffic with IPv4 unnumbered over physical interface on a non-default vrf failed'
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)


    st.banner('Configure and verify IP unnumbered over non-default vrf and default-vrf on a portchannel interface ')
    st.log('On DUT1 disable physical interface for the routes to be learnt from portchannel')
    port_obj.shutdown(data.dut1, data.d1_d2_ports[0])
    tc_result = True
    result = utils.exec_all(True, [[loc_lib.dut1_config_unnumbered,'pc',''],[loc_lib.dut2_config_unnumbered,'pc','']]) 
    if result is False:
        error = "IP unnumbered configuration on a portchannel interface failed"
        tc_result = False ; error_list.append(error)
    result = utils.exec_all(True, [[loc_lib.dut1_verify_unnumbered, 'pc'],[loc_lib.dut2_verify_unnumbered,'pc']]) 
    if result is False:
        error = "IP unnumbered verification on a portchannel interface failed"
        tc_result = False ; error_list.append(error)
    st.log('On DUT1 verify routes on non default vrf use portchannel')
    result = retry_api(ip_obj.verify_ip_route, data.dut1, vrf_name = data.dut1_vrf[0], type='O', nexthop = data.dut2_loopback_ip[2], interface = data.portchannel,ip_address = data.dut2_loopback_ip[2]+'/'+data.ip_loopback_prefix, family = "ipv4", retry_count= 7, delay= 5)
    if result is False:
        error = "IP routes on non-default vrf using portchannel failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.send_verify_traffic(type = 'ipv4')
    if result is False:
        error = 'IPv4 traffic with IPv4 unnumbered over portchannel on a non-default vrf failed'
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)


    st.log('Configure and verify IP unnumbered over non-default vrf and default-vrf on a vlan interface ')
    st.log('On DUT1 disable physical interface for the routes to be learnt from portchannel')
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[2],data.d1_d2_ports[3]])
    tc_result = True
    result = utils.exec_all(True, [[loc_lib.dut1_config_unnumbered,'vlan',''],[loc_lib.dut2_config_unnumbered,'vlan','']]) 
    if result is False:
        error = "IP unnumbered configuration on a vlan interface failed"
        tc_result = False ; error_list.append(error)
    result = utils.exec_all(True, [[loc_lib.dut1_verify_unnumbered, 'vlan'],[loc_lib.dut2_verify_unnumbered,'vlan']]) 
    if result is False:
        error = "IP unnumbered verification on a vlan interface failed"
        tc_result = False ; error_list.append(error)
    st.log('On DUT1 verify routes on non default vrf use vlan')
    result = retry_api(ip_obj.verify_ip_route, data.dut1, vrf_name = data.dut1_vrf[0], type='O', nexthop = data.dut2_loopback_ip[1], interface = 'Vlan'+data.dut1_dut2_vlan[0],ip_address = data.dut2_loopback_ip[1]+'/'+data.ip_loopback_prefix, family = "ipv4", retry_count= 7, delay= 5)
    if result is False:
        error = "IP routes on non-default vrf using vlan failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.send_verify_traffic(type = 'ipv4')
    if result is False:
        error = 'IPv4 traffic with IPv4 unnumbered over vlan interface on a non-default vrf failed'
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)


    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')

def test_unnumvrf_reboot_reload():
    ######################################################################################################################################
    tc_list = ['FtOpSoRoIPnumvrfFun010','FtOpSoRoIPnumvrfFun011']
    final_result = 0
    error_list = []
    st.banner('FtOpSoRoIPnumvrfFun010 -- to -- FtOpSoRoIPnumvrfFun011')

    st.banner('FtOpSoRoIPnumvrfFun010 - Verify unnumbered interface accross a fast reboot')
    tc_result = True
    st.log("Save the running config in sonic and vtysh modes")
    reboot_obj.config_save(data.dut1)
    reboot_obj.config_save(data.dut1, shell='vtysh')
    st.reboot(data.dut1, 'fast')
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[0], interface= data.dut1_vrf[0], retry_count= 3, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[1], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[2], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)

    st.log('Verify OSPF is up for all interfaces')
    result = loc_lib.verify_ospf()
    if result is False:
        error = "After reload OSPF neighbors are not up for all/some of the unnumbered interfaces"
        tc_result = False ; error_list.append(error)

    result = loc_lib.send_verify_traffic()
    if result is False:
        error = "After fast reboot IPv4 traffic on unnumbered interface failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)

    st.banner('FtOpSoRoIPnumvrfFun011 - Verify unnumbered interface across a config reload')
    tc_result = True
    reboot_obj.config_reload(data.dut1)
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[0], interface= data.dut1_vrf[0], retry_count= 3, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[1], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[2], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "After reload Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)

    st.log('Verify OSPF is up for all interfaces')
    result = loc_lib.verify_ospf()
    if result is False:
        error = "After reload OSPF neighbors are not up for all/some of the unnumbered interfaces"
        tc_result = False ; error_list.append(error)
    result = loc_lib.send_verify_traffic()
    if result is False:
        error = "After config reload IPv4 traffic on unnumbered interface failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)
    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def fixture_unnumvrf_test_donar(request,prologue_epilogue):
    yield
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[1],data.d1_d2_ports[2],data.d1_d2_ports[3]])
    ip_obj.config_unnumbered_interface(data.dut1, family = 'ipv4', action = 'del', interface = data.d1_d2_ports[0],loop_back = data.dut1_loopback[0])
    ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[3]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','no')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ip[0],data.ip_loopback_prefix, "ipv4")
    ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[0]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','yes')
    loc_lib.dut1_config_unnumbered('phy','')
    loc_lib.verify_ospf()

def test_unnumvrf_donar(fixture_unnumvrf_test_donar):

    tc_list = ['FtOpSoRoIPnumvrfFun007','FtOpSoRoIPnumvrfFun008','FtOpSoRoIPnumvrfFun009']
    final_result = 0
    result = True
    error_list = []
    st.banner('FtOpSoRoIPnumvrfFun007 -- to -- FtOpSoRoIPnumvrfFun009')

    st.banner('Verify unnumbered interface for non default vrf after unbind and rebind vrf')
    tc_result = True
    st.log('Remove the unnumbered configuration on DUT1')
    loc_lib.dut1_config_unnumbered('phy','no')
    loc_lib.dut1_config_unnumbered('vlan','no')
    loc_lib.dut1_config_unnumbered('pc','no')

    st.log('Remove the OSPF configuration for the unnumbered interfaces on DUT1')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.d1_d2_ports[0],'point-to-point',data.dut1_vrf[0],'no')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point',data.dut1_vrf[0],'no')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.portchannel,'point-to-point',data.dut1_vrf[0],'no')

    st.log('Remove the IP addresses for the unnumbered interfaces on DUT1')
    ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ip[2],data.ip_loopback_prefix, "ipv4")
    ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ip[1],data.ip_loopback_prefix, "ipv4")
    ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ip[0],data.ip_loopback_prefix, "ipv4")

    st.log('Remove the VRF binding for the unnumbered interfaces on DUT1')
    vrf_obj.bind_vrf_interface(dut = data.dut1, vrf_name = [data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0]], intf_name = [data.d1_d2_ports[0], 'Vlan'+data.dut1_dut2_vlan[0], data.portchannel], config = 'no')

    st.log('Bind the back to the unnumbered interfaces on DUT1')
    vrf_obj.bind_vrf_interface(dut = data.dut1, vrf_name = [data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0]], intf_name = [data.d1_d2_ports[0], 'Vlan'+data.dut1_dut2_vlan[0], data.portchannel], config = 'yes')

    st.banner('On DUT1 verify vrf bindings for all the interfaces')
    output = vrf_obj.get_vrf_verbose(dut = data.dut1,vrfname = data.dut1_vrf[0])
    if data.dut1_vrf[0] in output['vrfname']:
        st.log('VRF configured on DUT1 is as expected',data.dut1_vrf[0])
    else:
        st.error('VRF name configured on DUT1 is as not expected',data.dut1_vrf[0])
        result = False
    for value in output['interfaces']:
        if data.dut1_tg_ports[0] or data.dut1_loopback[0] or data.dut1_loopback[1] or data.dut1_loopback[2] or data.d1_d2_ports[0] or 'Vlan'+data.dut1_dut2_vlan[0] or data.portchannel == value:
            st.log('Bind to VRF is as expected',value)
        else:
            st.error('Bind to VRF is not as expected',value)
            result = False
    if result is False:
        error = "Unbind/Rebind of unnumbered interfaces failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)

    st.banner('Verify unnumbered interface for non default vrf after adding and removing donar IP')
    tc_result = True
    st.log('On DUT1 configure back the ip addresses on the loopbacks')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ip[1], data.ip_loopback_prefix,'ipv4')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ip[2], data.ip_loopback_prefix,'ipv4')

    st.log('On DUT1 add the interfaces back in the ospf network')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point',data.dut1_vrf[0],'yes')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.portchannel,'point-to-point',data.dut1_vrf[0],'yes')

    st.log('On DUT1 configure and verify portchannel and vlan as unnumbered interfaces')
    loc_lib.dut1_config_unnumbered('vlan','')
    result = loc_lib.dut1_verify_unnumbered('vlan')
    if result is False:
        error = "Verification of unnumbered interfaces over vrf on a vlan failed after adding/removing the donar interface"
        tc_result = False ; error_list.append(error)
    loc_lib.dut1_config_unnumbered('pc','')
    result = loc_lib.dut1_verify_unnumbered('pc')
    if result is False:
        error = "Verification of unnumbered interfaces over vrf on a portchannel failed after adding/removing the donar interface"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)

    st.banner('Verify unnumbered interface for non default vrf after modifying the donar IP')
    tc_result = True
    st.log('On DUT1 modify the donar interface address, add them to the ospf network and configure the physical interface as unnumbered for the new donar IP')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ip[3], data.ip_loopback_prefix,'ipv4')
    ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.d1_d2_ports[0],'point-to-point',data.dut1_vrf[0],'yes')
    ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[3]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','yes')
    ip_obj.config_unnumbered_interface(data.dut1, family = 'ipv4', action = 'add', interface = data.d1_d2_ports[0],loop_back = data.dut1_loopback[0])

    st.log('Verify OSPF is up for all interfaces')
    result = loc_lib.verify_ospf()
    if result is False:
        error = "OSPF neighbors are not up for all/some of the unnumbered interfaces"
        tc_result = False ; error_list.append(error)

    result = ip_obj.verify_interface_ip_address(data.dut1, data.d1_d2_ports[0], data.dut1_loopback_ip[3]+'/'+data.ip_loopback_prefix, 'ipv4',data.dut1_vrf[0],'U')
    if result is False:
        error = "Verification of unnumbered interfaces over vrf on a physical interface failed after modifying the donar IP"
        tc_result = False ; error_list.append(error)
    st.log('Shutting the other ports for traffic to take new configured donar address')
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[1],data.d1_d2_ports[2],data.d1_d2_ports[3]])

    result = retry_api(ip_obj.verify_ip_route, data.dut2, type='O', nexthop = data.dut1_loopback_ip[3], interface = data.d2_d1_ports[0],ip_address = data.dut1_loopback_ip[3]+'/'+data.ip_loopback_prefix, family = "ipv4", retry_count= 7, delay= 5)
    if result is False:
        error = "IP routes on non-default vrf with new IP failed"
        tc_result = False ; error_list.append(error)

    result = loc_lib.send_verify_traffic()
    if result is False:
        error = "Traffic over vrf on a physical interface failed after modifying the donar IP"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)


    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def fixture_unnumvrf_test_bfd(request,prologue_epilogue):
    yield
    dict1 ={"interface":data.d1_d2_ports[0],'neighbor_ip':data.dut2_loopback_ip[0],'config':'no','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":data.d1_d2_ports[0],'neighbor_ip':data.dut1_loopback_ip[0],'config':'no','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    dict1 ={"interface":data.portchannel,'neighbor_ip':data.dut2_loopback_ip[2],'config':'no','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":data.portchannel,'neighbor_ip':data.dut1_loopback_ip[2],'config':'no','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    dict1 ={"interface":'Vlan'+data.dut1_dut2_vlan[0],'neighbor_ip':data.dut2_loopback_ip[1],'config':'no','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":'Vlan'+data.dut1_dut2_vlan[0],'neighbor_ip':data.dut1_loopback_ip[1],'config':'no','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])

def test_unnumvrf_bfd(fixture_unnumvrf_test_bfd):

    tc_list = ['FtOpSoRoIPnumvrfFun004','FtOpSoRoIPnumvrfFun005','FtOpSoRoIPnumvrfFun006']
    final_result = 0
    error_list = []
    st.banner('FtOpSoRoIPnumvrfFun004 -- to -- FtOpSoRoIPnumvrfFun006')


    st.banner('Verify OSPF BFD over all the unnumbered interfaces over non-default vrf')
    tc_result = True
    st.log('Verify OSPF is up for all interfaces')
    loc_lib.verify_ospf()
    st.log('Configure BFD on PortChannel, Physical interface and vlan')
    dict1 ={"interface":data.d1_d2_ports[0],'neighbor_ip':data.dut2_loopback_ip[0],'config':'yes','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":data.d2_d1_ports[0],'neighbor_ip':data.dut1_loopback_ip[0],'config':'yes','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[0], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "Ping on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(bfd_obj.verify_bfd_peer, data.dut1, peer = data.dut2_loopback_ip[0], interface = data.d1_d2_ports[0], vrf_name = data.dut1_vrf[0], status= 'up', retry_count= 3, delay= 2)
    if result is False:
        error = "BFD on IP unnumbered physical interface over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)

    tc_result = True
    dict1 ={"interface":data.portchannel,'neighbor_ip':data.dut2_loopback_ip[2],'config':'yes','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":data.portchannel,'neighbor_ip':data.dut1_loopback_ip[2],'config':'yes','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[2], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "Ping on IP unnumbered portchannel over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(bfd_obj.verify_bfd_peer, data.dut1, peer = data.dut2_loopback_ip[2], interface = data.portchannel, status= 'up', vrf_name = data.dut1_vrf[0], retry_count= 3, delay= 2)
    if result is False:
        error = "BFD on IP unnumbered portchannel over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)

    tc_result = True
    dict1 ={"interface":'Vlan'+data.dut1_dut2_vlan[0],'neighbor_ip':data.dut2_loopback_ip[1],'config':'yes','noshut':'yes','vrf_name':data.dut1_vrf[0]}
    dict2 ={"interface":'Vlan'+data.dut1_dut2_vlan[0],'neighbor_ip':data.dut1_loopback_ip[1],'config':'yes','noshut':'yes'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    result = retry_api(ip_obj.ping, data.dut1, addresses = data.dut2_loopback_ip[1], interface= data.dut1_vrf[0], retry_count= 2, delay= 10)
    if result is False:
        error = "Ping on IP unnumbered vlan over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    result = retry_api(bfd_obj.verify_bfd_peer, data.dut1, peer = data.dut2_loopback_ip[1], interface = 'Vlan'+data.dut1_dut2_vlan[0], status= 'up', vrf_name = data.dut1_vrf[0], retry_count= 3, delay= 2)
    if result is False:
        error = "BFD on IP unnumbered vlan over non-default vrf failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)

    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')
