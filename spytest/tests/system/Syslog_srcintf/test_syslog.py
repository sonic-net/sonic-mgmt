###############################################################################
#Script Title : Syslog source interface over default and non default vrf
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################
import pytest
import os
from spytest import st
from syslog_vars import data
import syslog_lib as loc_lib
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.system.port as port_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.rsyslog as log_obj
import apis.system.basic as basic_obj

#Topology:
#------#TG#----(2links)----#DUT1#----(4links)----#DUT2#----(2links)-----#TG#--------#

def initialize_topology():
    st.log("Script Starts Here!. Initialize..........................................................................................")
    vars = st.ensure_min_topology("D1D2:4","D2D3:4")
    data.dut_list = st.get_dut_names()
    data.dut1_client = data.dut_list[0]
    data.dut2_server = data.dut_list[1]
    data.dut3_client = data.dut_list[2]
    data.d1_d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2_d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]
    data.d2_d3_ports = [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3,vars.D2D3P4]
    data.d3_d2_ports = [vars.D3D2P1,vars.D3D2P2,vars.D3D2P3,vars.D3D2P4]
    data.d1_mgmt_ip = st.get_mgmt_ip(data.dut1_client)
    data.d2_mgmt_ip = st.get_mgmt_ip(data.dut2_server)
    data.d3_mgmt_ip = st.get_mgmt_ip(data.dut3_client)
    data.mgmt_intf = 'Management0'
    data.portchannel = 'PortChannel1'
    data.portchannel_2 = 'PortChannel2'
    data.server_src_path = "/tmp/rsyslog.conf"
    data.server_dst_path = "/etc/rsyslog.conf"
    data.remote_syslog_file = 'test_syslog.log'
    data.remote_syslog_path = '/var/log/sonic/test_syslog.log'
    data.syslog_file_path =  [os.path.join(os.path.dirname(__file__),'rsyslog.conf')]

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.module_config()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    #loc_lib.module_unconfig()

    '''
    Test case list:
    1 Verify remote syslog over management interface
    2 Verify remote syslog with physical interface as source interface
    3 Verify remote syslog with vlan as source interface
    4 Verify remote syslog with portchannel as source interface
    5 Verify remote syslog with loopback as source
    6 Verify remote syslog with physical interface as source interface over non-default vrf
    7 Verify remote syslog with vlan as source interface over non-default vrf
    8 Verify remote syslog with portchannel as source interface over non-default vrf
    9 Verify remote syslog with loopback as source interface over non-default vrf
    10 Configure and modify syslog after modifying source-interface
    11 Configure and verify syslog with non default remote port configuration
    12 Configure and verify syslog over a management VRF
    13 Configure and verify syslog over a management interface with DHCP enabled
    14 Verify remote syslog server with IPv6 host address and IPv4 source interface address
    15 Verify remote syslog server with mismatched source interface and vlan values
    16 Verify remote syslog server without IP in source interface
    17 Delete a vrf when remote syslog server is configured with it
    18 Delete a source-interface when remote syslog server is configured with it
    19 Verify multiple remote syslog server accross a cold reboot
    '''

@pytest.fixture(scope="function")
def fixture_test_rsyslog_default_vrf(request,prologue_epilogue):
    yield
    port_obj.noshutdown(data.dut2_server, data.mgmt_intf)
    port_obj.noshutdown(data.dut2_server, data.d2_d1_ports)

def test_rsyslog_default_vrf(fixture_test_rsyslog_default_vrf):
    tc_list = ['FtOpSoRoSyslogFun001','FtOpSoRoSyslogFun002','FtOpSoRoSyslogFun003','FtOpSoRoSyslogFun004','FtOpSoRoSyslogFun005']
    final_result = 0
    error_list = []
    st.banner('FtOpSoRoSyslogFun001 -- to -- FtOpSoRoSyslogFun005')


    st.log('Shutting all other interfaces')
    st.log('Configure and verify remote syslog over IPv4 address on a management interface ')
    tc_result = True
    port_obj.shutdown(data.dut2_server, data.d2_d1_ports)
    result = loc_lib.config_server(mgmt_intf = '')
    if result is False:
        error = "Syslog server configuration over management interface with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(mgmt_intf = '')
    if result is False:
        error = "Syslog server verification over management interface failed with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Remove and the Management interface and verify the logs')
    ip_obj.show_ip_route(data.dut1_client, family="ipv4")
    st.wait(5, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, ' show ip route vrf default', lines=100, file_length=110, match=None)
    if result is False:
        error = "Syslogs verification failed after shut-noshut of the client Management interface"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(mgmt_intf = '', config = 'no')
    if result is False:
        error = "Syslog server unconfig over management interface with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)


    st.log('Configure and verify remote syslog over IPv6 address on a physical interface ')
    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.mgmt_intf)
    port_obj.noshutdown(data.dut2_server, data.d2_d1_ports[0])
    result = loc_lib.config_server(phy = '',family = 'ipv6')
    if result is False:
        error = "Syslog server configuration over physical interface with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(phy = '',family = 'ipv6')
    if result is False:
        error = "Syslog server verification over physical interface failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    loc_lib.config_server(phy = '',family = 'ipv6', config = 'no')
    loc_lib.config_server(phy = '',family = 'ipv6')
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, 'hostcfgd', lines=100, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification failed after shut-noshut of the client physical interface"
        tc_result = False ; error_list.append(error)
    st.log('Configure and verify remote syslog over IPv4 address on a physical interface ')
    result = loc_lib.config_server(phy = '',family = 'ipv6',config = 'no')
    if result is False:
        error = "Syslog server unconfig over physical interface with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(phy = '')
    if result is False:
        error = "Syslog server configuration over physical interface with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(phy = '')
    if result is False:
        error = "Syslog server verification over physical interface failed with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(phy = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over physical interface with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)


    st.log('Configure and verify remote syslog over IPv6 address on a loopback ')
    tc_result = True
    st.log('Configure static routes for the loopback to be reachable')
    result = loc_lib.config_server(loop_bk = '',family = 'ipv6')
    if result is False:
        error = "Syslog server configuration over loopback with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(loop_bk = '',family = 'ipv6')
    if result is False:
        error = "Syslog server verification over loopback failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Verify the logs on the server after removing and adding removing')
    loc_lib.config_server(loop_bk = '',family = 'ipv6', config = 'no')
    loc_lib.config_server(loop_bk = '',family = 'ipv6')
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, 'hostcfgd' , lines=100, file_length=110, match=None)
    if result is False:
        error = "Syslogs verification failed after show loopback on the client"
        tc_result = False ; error_list.append(error)
    st.log('Configure and verify remote syslog over IPv4 address on a loopback ')
    result = loc_lib.config_server(loop_bk = '',family = 'ipv6', config = 'no')
    if result is False:
        error = "Syslog server unconfig over loopback with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Delete the IPv6 address on portchannel and configure IPv4 address back ')
    result = loc_lib.config_server(loop_bk = '')
    if result is False:
        error = "Syslog server configuration over loopback with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(loop_bk = '')
    if result is False:
        error = "Syslog server verification over loopback with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(loop_bk = '', config = 'no')
    if result is False:
        error = "Syslog server unconfig over loopback with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[4], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[4],'test_case_failure_message',error)


    st.log('Configure and verify remote syslog over IPv6 address on a vlan ')
    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d1_ports[0])
    port_obj.noshutdown(data.dut2_server, data.d2_d1_ports[1])
    result = loc_lib.config_server(vlan = '',family = 'ipv6')
    if result is False:
        error = "Syslog server configuration over vlan with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(vlan = '',family = 'ipv6')
    if result is False:
        error = "Syslog server verification over vlan failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Verify the logs on the server for show vlan')
    vlan_obj.show_vlan_config(data.dut1_client, vlan_id=2)
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, ' Vlan'+data.dut1_dut2_vlan[0], lines=60, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification failed after show vlan on the client"
        tc_result = False ; error_list.append(error)
    st.log('Configure and verify remote syslog over IPv4 address on a vlan ')
    result = loc_lib.config_server(vlan = '',family = 'ipv6', config = 'no')
    if result is False:
        error = "Syslog server unconfig over vlan with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Configure and verify remote syslog over IPv4 address on a vlan ')
    result = loc_lib.config_server(vlan = '')
    if result is False:
        error = "Syslog server configuration over vlan with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(vlan = '')
    if result is False:
        error = "Syslog server verification over vlan with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(vlan = '', config = 'no')
    if result is False:
        error = "Syslog server unconfig over vlan with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)

    st.log('Configure and verify remote syslog over IPv6 address on a portchannel ')
    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d1_ports[1])
    port_obj.noshutdown(data.dut2_server, [data.d2_d1_ports[2],data.d2_d1_ports[3]])
    result = loc_lib.config_server(pc = '',family = 'ipv6')
    if result is False:
        error = "Syslog server configuration over portchannel with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(pc = '',family = 'ipv6')
    if result is False:
        error = "Syslog server verification over portchannel failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Verify the logs on the server for show portchannel')
    ip_obj.delete_ip_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ipv6[2], data.dut1_dut2_ipv6_subnet,'ipv6') 
    pc_obj.add_del_portchannel_member(data.dut1_client, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]],'del')
    ip_obj.config_ip_addr_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ipv6[2], data.dut1_dut2_ipv6_subnet,'ipv6') 
    pc_obj.add_del_portchannel_member(data.dut1_client, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]],'add')
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, 'addLagMemberToHardware', lines=60, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification failed after show portchannel on the client"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(pc = '',family = 'ipv6', config = 'no')
    if result is False:
        error = "Syslog server unconfig over portchannel with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Configure and verify remote syslog over IPv4 address on a portchannel ')
    result = loc_lib.config_server(pc = '')
    if result is False:
        error = "Syslog server configuration over portchannel with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(pc = '')
    if result is False:
        error = "Syslog server verification over vlan with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(pc = '', config = 'no')
    if result is False:
        error = "Syslog server unconfig over portchannel with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[3], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[3],'test_case_failure_message',error)


    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')

def test_rsyslog_negative():
    tc_list = ['FtOpSoRoSyslogFun014','FtOpSoRoSyslogFun015','FtOpSoRoSyslogFun016','FtOpSoRoSyslogFun017','FtOpSoRoSyslogFun018']
    final_result = 0
    tc_result = True
    error_list = []
    st.banner('FtOpSoRoSyslogFun014 -- to -- FtOpSoRoSyslogFun018')


    st.banner('FtOpSoRoSyslogFun014 - Verify remote syslog server with IPv6 host address and IPv4 source interface address')
    st.banner('FtOpSoRoSyslogFun016 - Verify remote syslog server without IP in source interface')
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d1_ports)
    port_obj.noshutdown(data.dut2_server, data.d2_d1_ports[0])
    st.log('Remove IPv6 address from physical interface and configure IPv6 address as the host') 
    ip_obj.delete_ip_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ipv6[0], data.dut1_dut2_ipv6_subnet,'ipv6')
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = data.dut2_dut1_ipv6[0], source_intf = data.d1_d2_ports[0])
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, 'D1', lines=5, file_length=5, match=None)
    if result is True:
        error = "Syslogs verification with IPv6 host address and IPv4 source interface address should have failed"
        tc_result = False ; error_list.append(error)
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = data.dut2_dut1_ipv6[0], source_intf = data.d1_d2_ports[0], config = 'no')
    ip_obj.config_ip_addr_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ipv6[0], data.dut1_dut2_ipv6_subnet,'ipv6')
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)


    st.banner('FtOpSoRoSyslogFun015 - Verify remote syslog server with mismatched source interface and vlan values')
    result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = data.dut2_dut1_ipv6[0], source_intf = 'Vlan10', skip_error = True)
    if result is True:
        error = "Syslog server verification with mismatched source interface and vlan values should have failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        st.exec_all([[st.generate_tech_support,data.dut1_client,'negative_DUT1_TC15'],[st.generate_tech_support,data.dut2_server,'negative_DUT2_TC15']])
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)


    st.banner('FtOpSoRoSyslogFun017 and FtOpSoRoSyslogFun018')
    vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, config = 'yes')
    log_obj.config_remote_syslog_server(dut = data.dut3_client, host = data.dut2_dut1_ipv6[0], source_intf = data.d1_d2_ports[0], vrf = data.dut3_vrf_phy, skip_error = True)
    result = vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, config = 'no', skip_error = True)
    if result is False:
        error = "VRF removal after syslog configuration should have failed"
        tc_result = False ; error_list.append(error)
    log_obj.config_remote_syslog_server(dut = data.dut3_client, host = data.dut2_dut1_ipv6[0], source_intf = data.d1_d2_ports[0], vrf = data.dut3_vrf_phy, skip_error = True, config = 'no')
    if tc_result:
        st.report_tc_pass(tc_list[3], 'tc_passed')
        st.report_tc_pass(tc_list[4], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[3],'test_case_failure_message',error)
        st.report_tc_fail(tc_list[4],'test_case_failure_message',error)

    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')

def test_rsyslog_nondefault_vrf():
    tc_list = ['FtOpSoRoSyslogFun006','FtOpSoRoSyslogFun007','FtOpSoRoSyslogFun008','FtOpSoRoSyslogFun009']
    final_result = 0
    tc_result = True
    error_list = []
    st.banner('FtOpSoRoSyslogFun006 -- to -- FtOpSoRoSyslogFun009')


    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d1_ports)
    port_obj.shutdown(data.dut2_server, data.d2_d3_ports)
    port_obj.noshutdown(data.dut2_server, data.d2_d3_ports[0])
    result = loc_lib.config_server(phy = '', vrf = '')
    if result is False:
        error = "Syslog server configuration over physical interface on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(phy = '', vrf = '')
    if result is False:
        error = "Syslog server verification over physical interface on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Shut-noshut the Physical interface on a non-default VRF and verify the logs')
    port_obj.shutdown(data.dut3_client, data.d3_d2_ports[0])
    port_obj.noshutdown(data.dut3_client, data.d3_d2_ports[0])
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path,  'updatePortOperStatus', lines=50, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification failed after shut-noshut of the client physical interface  on a non-default VRF"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(phy = '',vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over physical interface  on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(phy = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server configuration over physical interface  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(phy = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server verification over physical interface  on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(phy = '',family = 'ipv6', vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over physical interface  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[0],'test_case_failure_message',error)

    #ip_obj.ping(data.dut3_client, '22.22.22.22', interface= data.dut3_vrf_phy, cli_type = 'click')
    st.log('Configure and verify remote syslog over IPv address on a Loopback ')
    tc_result = True
    st.log('Shutting all other interfaces')
    result = loc_lib.config_server(loop_bk = '', vrf = '')
    if result is False:
        error = "Syslog server configuration over loopback on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(loop_bk = '', vrf = '')
    if result is False:
        error = "Syslog server verification over loopback on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    loc_lib.config_server(loop_bk = '',vrf = '',config = 'no')
    loc_lib.config_server(loop_bk = '', vrf = '')
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path,  'hostcfgd', lines=50, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification on a non-default VRF failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(loop_bk = '',vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over loopback  on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(loop_bk = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server configuration over loopback  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(loop_bk = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server verification over loopback on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(loop_bk = '',family = 'ipv6', vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over loopback  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[2],'test_case_failure_message',error)


    st.log('Configure and verify remote syslog over IPv address on a vlan ')
    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d3_ports[0])
    port_obj.noshutdown(data.dut2_server, data.d2_d3_ports[1])
    result = loc_lib.config_server(vlan = '', vrf = '')
    if result is False:
        error = "Syslog server configuration over vlan on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(vlan = '', vrf = '')
    if result is False:
        error = "Syslog server verification over vlan on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Shut-noshut the Physical interface on a non-default VRF and verify the logs')
    vlan_obj.show_vlan_config(data.dut3_client, vlan_id=2)
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, ' Vlan'+data.dut2_dut3_vlan[0], lines=60, file_length=100, match=None)
    if result is False:
        error = "Syslogs verification on a non-default VRF failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(vlan = '',vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over vlan  on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(vlan = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server configuration over vlan  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(vlan = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server verification over vlan on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(vlan = '',family = 'ipv6', vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over vlan  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[1], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[1],'test_case_failure_message',error)


    st.log('Configure and verify remote syslog over IPv address on a portchannel ')
    tc_result = True
    st.log('Shutting all other interfaces')
    port_obj.shutdown(data.dut2_server, data.d2_d3_ports[1])
    port_obj.noshutdown(data.dut2_server, [data.d2_d3_ports[2],data.d2_d3_ports[3]])
    result = loc_lib.config_server(pc = '', vrf = '')
    if result is False:
        error = "Syslog server configuration over portchannel on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(pc = '', vrf = '')
    if result is False:
        error = "Syslog server verification over portchannel on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    st.log('Shut-noshut the Physical interface on a non-default VRF and verify the logs')
    ip_obj.delete_ip_interface(data.dut3_client, data.portchannel_2, data.dut3_dut2_ipv6[2], data.dut3_dut2_ipv6_subnet,'ipv6') 
    ip_obj.config_ip_addr_interface(data.dut3_client, data.portchannel_2, data.dut3_dut2_ipv6[2], data.dut3_dut2_ipv6_subnet,'ipv6') 
    st.wait(10, 'Waiting for all the syslogs')
    result = basic_obj.check_error_log(data.dut2_server, data.remote_syslog_path, 'addRoute', lines=60, file_length=100, match=None)    
    if result is False:
        error = "Syslogs verification on a non-default VRF failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(pc = '',vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over portchannel  on a non-default VRF with IPv4 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(pc = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server configuration over portchannel  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.verify_server(pc = '',family = 'ipv6', vrf = '')
    if result is False:
        error = "Syslog server verification over portchannel on a non-default VRF failed with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    result = loc_lib.config_server(pc = '',family = 'ipv6', vrf = '',config = 'no')
    if result is False:
        error = "Syslog server unconfig over portchannel  on a non-default VRF with IPv6 address failed"
        tc_result = False ; error_list.append(error)
    if tc_result:
        st.report_tc_pass(tc_list[3], 'tc_passed')
    else:
        final_result += 1
        st.report_tc_fail(tc_list[3],'test_case_failure_message',error)

    if final_result != 0:
        st.report_fail('test_case_failure_message',error_list)
    else:
        st.report_pass('test_case_passed')
