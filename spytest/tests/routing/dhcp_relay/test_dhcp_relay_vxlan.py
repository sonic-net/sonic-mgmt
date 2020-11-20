##############################################################################
#Script Title : DHCP-Relay over Vxlan
#Author       : Sooriya/Raghu
#Mail-id      : Sooriya.Gajendrababu@broadcom.com;raghukumar.thimmareddy@broadcom.com
###############################################################################

import os
import pytest
from spytest import st, tgapi
from dhcp_relay_vars import *
from dhcp_relay_vars import data
from dhcp_relay_utils import *
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.reboot as reboot_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
import apis.routing.ospf as ospf_obj
import apis.system.port as port_api
from utilities import utils


def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D2:1", "D1D3:2","D2D4:3", "D2T1:1", "D3T1:1", "D2CHIP=TD3", "D3CHIP=TD3")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]

    for dut in data.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)

    data.d1d2_ports = [vars.D1D2P1]
    data.d2d1_ports = [vars.D2D1P1]
    #data.d1d3_ports = [vars.D1D3P1]
    #data.d3d1_ports = [vars.D3D1P1]
    data.d1d3_ports = [vars.D1D3P1, vars.D1D3P2]
    data.d3d1_ports = [vars.D3D1P1, vars.D3D1P2]
    #data.d3server_ports = [vars.D3Server1]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]


    # DUT as dhcp server
    data.dhcp_server_port = data.d3d1_ports[1]
    data.server_d3_port = data.d1d3_ports[1]

    data.dhcp_server_ip = '172.16.40.210'
    data.dhcp_server_ipv6 = '2072::210'
    data.username = 'admin'
    data.password = st.get_credentials(data.dut1)[3]

    temp_list = data.dhcp_server_ip.split('.')
    temp_list[3] = '1'
    data.dut3_server_ip_list =  ['.'.join(temp_list)]
    data.dut3_server_ipv6_list = [data.dhcp_server_ipv6.split('::')[0] + "::1"]

    data.relay_port = ['Vlan100',data.d2d4_ports[1],'PortChannel12']
    data.lb_src_intf_list = [src_intf_same_vni, src_intf_same_vni, src_intf_same_vni]
    if data.inter_vni:
        data.lb_src_intf_list = [src_intf_same_vni, src_intf_diff_vni, src_intf_same_vni]
    data.client_port = ['Vlan100', data.d4d2_ports[1], 'PortChannel12']
    data.client_port_ip = ['192.168.0.1','20.20.20.1','30.30.30.1']
    data.server_pool = ['192.168.0.','20.20.20.','30.30.30.']
    data.client_port_ipv6 = ['2092::1','2020::1','2030::1']
    data.server_pool_ipv6 = ['2092::','2020::','2030::']
    data.dhcp_files =  ['isc-dhcp-server','dhcpd.conf','dhcpd6.conf']
    data.dhcp_files_path =  [os.path.join(os.path.dirname(__file__),data.dhcp_files[0]),os.path.join(os.path.dirname(__file__),data.dhcp_files[1]),os.path.join(os.path.dirname(__file__),data.dhcp_files[2])]
    data.dhcp_files_path =  []
    for file in data.dhcp_files: data.dhcp_files_path.append(os.path.join(os.path.dirname(__file__),file))

@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    print_topology()
    result = dhcp_relay_base_config()
    if result is False:
        st.report_fail("Error in module config")
    for intf in data.client_port: ip_api.config_interface_ip6_link_local(data.dut4, intf, 'enable')
    yield
    for intf in data.client_port: ip_api.config_interface_ip6_link_local(data.dut4, intf, 'disable')
    dhcp_relay_base_deconfig()


def test_dhcp_relay_vxlan_002(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRFt012','FtOpSoRoDHCPRFt013 ','FtOpSoRoDHCPRFt014','FtOpSoRoDHCPRFt015']
    tc_result = True ;err_list=[]
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    #################################################
    hdrMsg("Validate : dhcp relay functionality with server unreachable")
    #################################################

    #################################################
    hdrMsg("Step01 : Configure invalid dhcp server IP details on leaf1")
    #################################################
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2], IP=data.dhcp_server_ip,action='remove',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2], IP=['172.16.0.199'],action='add',vrf_name =vrf_name)
    #dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")
    #################################################
    hdrMsg("Step02 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4,data.client_port[2])

    ##############################################################################################
    hdrMsg("Step03 : Verify that the desired address is not assigned as the server IP is invalid")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is True:
        err ="DHCP client ip address assignment passed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step04 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    #dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################################
    hdrMsg("Step05 : Unconfigure invalid dhcp server IP details on leaf1 and add 3 invalid server ip and one valid IP")
    #################################################################
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2], IP=['172.16.0.199'],action='remove',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2], IP=['172.16.0.199','172.16.0.200','172.16.0.201',data.dhcp_server_ip],action='add',vrf_name =vrf_name)

    #################################################
    hdrMsg("Step06 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    ##############################################################################################
    hdrMsg("Step07 : Verify that the desired address is assigned ")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[1],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step08 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
    #################################################
    result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
    if result is False:
        err ="DHCP relay statistics check failed for {} with link-select".format(data.relay_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[1],'test_case_failure_message',err)

    #st.log('Verify reachabality to dhcp server from dhcp cleint')
    #result =ip_api.ping(data.dut4, data.dhcp_server_ip)

    #################################################
    hdrMsg("Step09 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################
    hdrMsg("Step10 : Configure src-intf suboption with loopback interface on dhcp-relay enabled interfaces ")
    #################################################
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2], IP=['172.16.0.199','172.16.0.200','172.16.0.201',data.dhcp_server_ip],action='remove')
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.relay_port[2],IP=data.dhcp_server_ip,action='add',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface=src_intf_same_vni,interface=data.relay_port[2],option='src-intf')

    #################################################
    hdrMsg("Step11 : Remove the ip address assigned to the src-intf Loopback3")
    #################################################
    ip_api.delete_ip_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')

    #################################################
    hdrMsg("Step12 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    ##############################################################################################
    hdrMsg("Step13 : Verify that the desired address is assigned ")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[2],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step14 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
    #################################################
    result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
    if result is False:
        err ="DHCP relay statistics check failed for {} with src-intf option".format(data.relay_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[2],'test_case_failure_message',err)

    #st.log('Verify reachabality to dhcp server from dhcp cleint')
    #result =ip_api.ping(data.dut4, data.dhcp_server_ip)

    #################################################
    hdrMsg("Step15 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################
    hdrMsg("Step16 : Configure link-select suboption on dhcp-relay enabled interfaces and restart the dhcp cleint ")
    #################################################
    dhcp_relay.dhcp_relay_option_config(data.dut2,interface=data.relay_port[2],option='link-select')
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    #################################################
    hdrMsg("Step17 : Verify link-select option enabled under detailed output for {}".format(data.relay_port[2]))
    #################################################
    result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=data.relay_port[2],src_interface=src_intf_same_vni,link_select='enable')
    if result is False:
        err = "link state config failed on {}".format(data.relay_port[2])
        tc_result = False; err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

    #################################################
    hdrMsg("Step18 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
    #################################################
    result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
    if result is False:
        err ="DHCP relay statistics check failed for {} with link-select".format(data.relay_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

    ##############################################################################################
    hdrMsg("Step19 : Verify that the desired address is assigned to dhcl client")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

    #st.log('Verify reachabality to dhcp server from dhcp cleint')
    #result =ip_api.ping(data.dut4, data.dhcp_server_ip)

    #################################################
    hdrMsg("Step20 : Stop DHCP client on portchannel interface {} and add ip address to source interface".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")
    ip_api.config_ip_addr_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')

    #################################################
    hdrMsg("Step21 : restart the dhcp cleint ")
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    ##############################################################################################
    hdrMsg("Step22 : Verify that the desired address is assigned to dhcl client")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

    #################################################
    hdrMsg("ClEANUP....the config to base config")
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    dhcp_relay.dhcp_relay_option_config(data.dut2, interface=data.relay_port[2],option='link-select',action='remove')
    dhcp_relay.dhcp_relay_option_config(data.dut2, interface=data.relay_port[2], option='src-intf', action='remove')

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')


def test_dhcp_relay_vxlan_003(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRFt023']
    tc_result = True ;err_list=[]

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    #################################################
    hdrMsg("Validate : Overlay dhcp relay function with source interface selection, where source interface has multiple IP address configured")
    #################################################

    #################################################
    hdrMsg("Step01 : Configure dhcp server IP details and clear the dhcp relay stats on leaf1")
    #################################################
    #dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################
    hdrMsg("Step02 : Configure src-intf suboption with loopback interface on dhcp-relay enabled interfaces ")
    #################################################
    dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface=src_intf_same_vni,interface=data.relay_port[2],option='src-intf')

    #################################################
    hdrMsg("Step03 : Configure multiple(secondary) ip address to src-intf Loopback3")
    #################################################
    ip_api.config_ip_addr_interface(data.dut2,src_intf_same_vni,'200.200.200.100','32',is_secondary_ip='yes')

    #################################################
    hdrMsg("Step04 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    ##############################################################################################
    hdrMsg("Step05 : Verify that the desired ip address is assigned and used primary ip of src-int ")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step06 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
    #################################################
    result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
    if result is False:
        err ="DHCP relay statistics check failed for {} with src-intf option".format(data.relay_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step07 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################
    hdrMsg("Step08 : Remove the primary ip address assigned to the src-intf Loopback3")
    #################################################
    #ip_api.delete_ip_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')

    #################################################
    hdrMsg("Step09 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

    ##############################################################################################
    hdrMsg("Step10 : Verify that the desired ip address is assigned and used secondary ip address of src-int")
    ##############################################################################################
    result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    #################################################
    hdrMsg("Step11 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
    #################################################
    result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
    if result is False:
        err ="DHCP relay statistics check failed for {} with src-intf option".format(data.relay_port[2])
        tc_result=False;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[0],'test_case_failure_message',err)


    #################################################
    hdrMsg("Step12 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
    #################################################
    dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
    dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

    #################################################
    hdrMsg("ClEANUP....the config to base config")
    #################################################
    dhcp_relay.dhcp_relay_option_config(data.dut2, interface=data.relay_port[2], option='src-intf', action='remove')

    #################################################
    hdrMsg("Step: Unconfigure secondary ip address to src-intf Loopback3 and add primary ip address")
    #################################################
    ip_api.delete_ip_interface(data.dut2,src_intf_same_vni,'200.200.200.100','32',is_secondary_ip='yes')
    #ip_api.config_ip_addr_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

def test_dhcp_relay_vxlan_004(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRFt024']
    tc_result = True ;err_list=[]

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    #################################################
    hdrMsg("Validate : Overlay dhcp relay function with source interface selection, where source interface to be used are physical/Ve/Portchannel")
    #################################################

    for interface1 in data.relay_port:
        #################################################
        hdrMsg("Step01 : Configure dhcp server IP details and clear the dhcp relay stats on leaf1")
        #################################################
        dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

        #################################################
        hdrMsg("Step02 : Configure src-intf suboption with {} interface on dhcp-relay enabled interfaces".format(interface1))
        #################################################
        dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface=interface1,interface=data.relay_port[2],option='src-intf')

        #################################################
        hdrMsg("Step03 : Start DHCP client on portchannel interface {}".format(data.client_port[2]))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, data.client_port[2])

        ##############################################################################################
        hdrMsg("Step04 : Verify that the desired ip address is assigned when src-int used as {}".format(interface1))
        ##############################################################################################
        result = check_dhcp_client(interface=data.client_port[2],network_pool=data.server_pool[2])
        if result is False:
            err ="DHCP client ip address assignment failed for {}".format(data.client_port[2])
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step05 : Verify dhcp relay statistics on {}".format(data.relay_port[2]))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=data.relay_port[2])
        if result is False:
            err ="DHCP relay statistics check failed for {} with src-intf option as {}".format(data.relay_port[2],interface1)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step06 : Stop DHCP client on portchannel interface {}".format(data.client_port[2]))
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, data.client_port[2])
        dhcp_relay.clear_statistics(data.dut2, interface=data.client_port[2], family="ipv4")

        #################################################
        hdrMsg("ClEANUP....the config to base config")
        #################################################
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=data.relay_port[2], option='src-intf', action='remove')

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

def test_dhcp_relay_vxlan_001(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRFt002','FtOpSoRoDHCPRFt001','FtOpSoRoDHCPRFt003','FtOpSoRoDHCPRFt004','FtOpSoRoDHCPRFt006','FtOpSoRoDHCPRFt005',
              'FtOpSoRoDHCPRFt008','FtOpSoRoDHCPRFt009','FtOpSoRoDHCPRFt011','FtOpSoRoDHCPRFt010']
    tc_result = True ;err_list=[]

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    for tc,intf,client_intf,_,pool,pool_v6 in zip(tc_list[0:3],data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4,client_intf, family='ipv6')

        #################################################
        hdrMsg("Step : Verify dhcp relay configuration under interface {}".format(intf))
        #################################################
        result = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
        if result is False:
            err ="DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}" .format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_relay_statistics(data.dut2,interface=intf,family='ipv6')
        if result is False:
            err ="IPv6 DHCP relay statistics check failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        if tc_result is True:
            st.report_tc_pass(tc,'tc_passed')

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################


        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv6")

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics reset to 0")
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf,expected=0)
        if result is False:
            err ="DHCP relay statistics did not reset after clearing for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[6],'test_case_failure_message',err)

        result = check_dhcp_relay_statistics(data.dut2,interface=intf,family='ipv6',expected=0)
        if result is False:
            err ="IPv6 DHCP relay statistics cdid not reset after clearing for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[6],'test_case_failure_message',err)

    if tc_result:
        st.report_tc_pass(tc_list[6], 'tc_passed')
    killall_dhclient(data.dut4)
    tc_result = True
    #################################################
    hdrMsg("Step : Configure src-intf suboption with loopback interface on all dhcp-relay enabled interfaces and start dhcp clients")
    #################################################

    for interface,src_intf in zip(data.relay_port, data.lb_src_intf_list):
        dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface=src_intf,interface=interface,option='src-intf')
        dhcp_relay.dhcp_relay_option_config(data.dut2, src_interface=src_intf, interface=interface, option='src-intf',family='ipv6')


    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

        ###################################################
        hdrMsg("Start packet capture at DHCP server and start the client")
        ##################################################
        start_packet_capture(intf=data.d1d3_ports[1],src_ip='100.100.100.100')

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')
        if  client_intf == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
                del data['ip_add_phy']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)
            if 'ip_add_phy_v6' in data.keys():
                ip_api.delete_ip_interface(data.dut4,client_intf, data.ip_add_phy_v6, '64', family="ipv6",skip_error=True)
                del data['ip_add_phy_v6']
                dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')

        #################################################
        hdrMsg("Step : Verify src-intf option in detailed dhcp-relay for {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,link_select='disable',max_hop_count=10)
        if result is False:
            err = "Source-interface config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,family='ipv6',max_hop_count=10)
        if result is False:
            err = "IPv6 Source-interface config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify dhcp client gets ip address assigned on expected subnet for {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        #################################################
        hdrMsg("Stop capture Validate packet received at DHCP server has loopback ip as source address")
        #################################################
        result = validate_packet()
        if result is False:
            err ="DHCP relay agent did not use loopback ip for sending DHCP packets towards server on {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}".format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        result = check_dhcp_relay_statistics(data.dut2,interface=intf,family='ipv6')
        if result is False:
            err ="IPv6 DHCP relay statistics check failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)


        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################

        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv6")
        killall_dhclient(data.dut4)

    if tc_result is True:
        st.report_tc_pass(tc_list[3],'tc_passed')
    tc_result = True
    #################################################
    hdrMsg("Step : Enable link-select suboption and restart dhcp clients on all client interfaces ")
    #################################################
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2,interface=interface,option='link-select')


    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        # dhcp_relay.dhcp_client_start(data.dut4, interface,family='ipv6')
        if  client_intf == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
                del data['ip_add_phy']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        #################################################
        hdrMsg("Step : Verify link-select option enabled under detailed output for {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,link_select='enable')
        if result is False:
            err = "link state config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[4],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify client on interface {} obtain ip address on expected subnet ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with link-select".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[4],'test_case_failure_message',err)
        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}".format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {} with link-select".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[4],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################

        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
    if tc_result is True:
        st.report_tc_pass(tc_list[4],'tc_passed')
    killall_dhclient(data.dut4)
    tc_result = True
    #################################################
    hdrMsg("Step-Raghu: Configure max-hop-count suboption to 1 and restart dhcp clients on all client interfaces ")
    #################################################
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2,interface=interface,option='max-hop-count',max_hop_count=1)
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='max-hop-count',family='ipv6',max_hop_count=1)


    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        #dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')
        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,ink_select='enable',max_hop_count=1)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf, family='ipv6',max_hop_count=1)
        if result is False:
            err = "IPv6 max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify the client interface obtain ip address since packets will be Relay interface {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "DHCH packets dropped for {} with max-hop-count set to 1".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)


    killall_dhclient(data.dut4)

    for intf, client_intf, _, pool, pool_v6, src_intf in zip(data.relay_port, data.client_port, data.client_port_ip,
                                                        data.server_pool, data.server_pool_ipv6,data.lb_src_intf_list):

        #################################################
        hdrMsg("Step : Change the max-hop-count to 15 on {} and restart dhcp clients".format(intf))
        #################################################

        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=intf, option='max-hop-count', max_hop_count=15)
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=intf, option='max-hop-count', family='ipv6',max_hop_count=15)

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')

        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,link_select='enable',max_hop_count=15)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,amily='ipv6',max_hop_count=15)
        if result is False:
            err = "IPv6 max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify all clients gets ip/ipv6 address from server after changing max-hop-count {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "IP address assignment failed  for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf, network_pool=pool_v6, family='ipv6')
        if result is False:
            err = "IPv6 address assignment failed for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

    if tc_result is True:
        st.report_tc_pass(tc_list[5],'tc_passed')

    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface,family='ipv6',skip_error_check=True)
        if client_interface == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface)
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy, '24', skip_error=True)
                del data['ip_add_phy']
            if 'ip_add_phy_v6' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface, family='ipv6')
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy_v6, '64', family="ipv6", skip_error=True)
                del data['ip_add_phy_v6']
        if 'PortChannel' in client_interface:
            dhcp_relay.dhcp_client_start(data.dut4, client_interface,family='ipv6')
            st.wait(5)
            dhcp_relay.dhcp_client_stop(data.dut4, client_interface,skip_error_check=True,family='ipv6')
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")
    killall_dhclient(data.dut4)

    #############################################################
    hdrMsg("Config Save")
    #############################################################
    bgp_api.enable_docker_routing_config_mode(data.dut2)
    reboot_api.config_save(data.dut2)
    reboot_api.config_save(data.dut2, 'vtysh')

    for trigger,tc in zip(['config_reload','reboot','warmboot'],tc_list[7:]):

        #############################################################
        hdrMsg("Trigger : {}".format(trigger))
        #############################################################

        if trigger == 'reboot' :  st.reboot(data.dut2, "fast")
        if trigger == 'config_reload':  reboot_api.config_reload(data.dut2)
        if trigger == 'warmboot':
            reboot_api.config_warm_restart(data.dut2,oper = "enable", tasks = ["system"])
            st.reboot(data.dut2, "warm")

        for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

            ########################################################################
            hdrMsg("Stopping and restart dhclient to renew ip address")
            ########################################################################

            dhcp_relay.dhcp_client_start(data.dut4, client_intf)
            dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')
            #################################################
            hdrMsg("Step : Verify max-hop-count configuration on {} after trigger {}".format(intf,trigger))
            #################################################
            result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,link_select='enable',max_hop_count=15)
            if result is False:
                err = "max-hop-count config failed on {} after {} ".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);
                st.report_tc_fail(tc,'test_case_failure_message', err)

            result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,family='ipv6',max_hop_count=15)
            if result is False:
                err = "IPv6 max-hop-count config failed on {} after {}".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);
                st.report_tc_fail(tc,'test_case_failure_message', err)

            #################################################
            hdrMsg("Step : Verify all clients gets ip/ipv6 address from server after changing max-hop-count {} after {} ".format(intf,trigger))
            #################################################
            result = check_dhcp_client(interface=client_intf, network_pool=pool)
            if result is False:
                err = "IP address assignment failed  for {} after {}".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);
                st.report_tc_fail(tc, 'test_case_failure_message',err)

            result = check_dhcp_client(interface=client_intf, network_pool=pool_v6, family='ipv6')
            if result is False:
                err = "IPv6 address assignment failed for {} after {}".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);
                st.report_tc_fail(tc, 'test_case_failure_message',err)

            ##################################################
            hdrMsg("Step: Stop dhclient")
            ##################################################
            dhcp_relay.dhcp_client_stop(data.dut4, client_intf, skip_error_check=True)
            dhcp_relay.dhcp_client_stop(data.dut4, client_intf, family='ipv6', skip_error_check=True)
            if client_intf == data.d4d2_ports[1]:
                if 'ip_add_phy' in data.keys():
                    dhcp_relay.dhcp_client_start(data.dut4, client_intf)
                    ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24', skip_error=True)
                    del data['ip_add_phy']
                if 'ip_add_phy_v6' in data.keys():
                    dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')
                    ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy_v6, '64', family="ipv6",
                                               skip_error=True)
                    del data['ip_add_phy_v6']
            if 'PortChannel' in client_intf:
                dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')
                st.wait(5)
                dhcp_relay.dhcp_client_stop(data.dut4, client_intf, skip_error_check=True, family='ipv6')
            killall_dhclient(data.dut4)
        if tc_result is True:
            st.report_tc_pass(tc,'tc_passed')

    #################################################
    hdrMsg("ClEANUP.... ")
    #################################################
    killall_dhclient(data.dut4)
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")
    killall_dhclient(data.dut4)
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='link-select', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='src-intf', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='max-hop-count', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='src-intf', action='remove',family='ipv6')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='max-hop-count', action='remove',family='ipv6')
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def test_dhcp_relay_vxlan_006(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRRE002','FtOpSoRoDHCPRRE001','FtOpSoRoDHCPRRE003','FtOpSoRoDHCPRRE004','FtOpSoRoDHCPRRE006','FtOpSoRoDHCPRRE005',
              'FtOpSoRoDHCPRRE008','FtOpSoRoDHCPRRE009','FtOpSoRoDHCPRRE011','FtOpSoRoDHCPRRE010']
    tc_result = True ;err_list=[]

    rest_urls = st.get_datastore(data.dut2,'rest_urls')
    if st.get_ui_type() in ['click', 'klish']:
        st.report_unsupported("test_execution_skipped", "Skipping OC-Yang test case for ui_type={}".format(st.get_ui_type()))
            
    ################################################################################
    hdrMsg("Step01: Doing REST Delete operation to delete the dhcp relay config ")
    ################################################################################
    for client_intf in data.relay_port:
        rest_url_del = rest_urls['dhcp_relay_helperaddress_config'].format(client_intf)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcp-relay config through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    for client_intf in data.relay_port:
        rest_url_del = rest_urls['dhcpv6_relay_helperaddress_config'].format(client_intf)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcpv6-relay config through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    ################################################################################
    hdrMsg("Step02: Doing REST PUT operation to config the dhcp relay helper address ")
    ################################################################################
    for client_intf in data.relay_port:
        ocdata = { "openconfig-relay-agent:helper-address": [ data.dhcp_server_ip ]}
        ocdata_vrf = {"openconfig-relay-agent-ext:vrf":vrf_name}
        rest_url = rest_urls['dhcp_relay_helperaddress_config'].format(client_intf)
        rest_url_vrf = rest_urls['dhcp_relay_server_vrf'].format(client_intf)
        response3 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        response4 = st.rest_update(data.dut2, path=rest_url_vrf, data=ocdata_vrf)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response3)
        st.log(response4)
        st.log('-----------------------------------------------------------------------------------------')
        if not response3["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay helper address through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    for client_intf in data.relay_port:
        ocdata = { "openconfig-relay-agent:helper-address": [ data.dhcp_server_ipv6 ]}
        ocdata_vrf = {"openconfig-relay-agent-ext:vrf":vrf_name}
        rest_url = rest_urls['dhcpv6_relay_helperaddress_config'].format(client_intf)
        rest_url_vrf = rest_urls['dhcpv6_relay_server_vrf'].format(client_intf)
        response3 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        response4 = st.rest_update(data.dut2, path=rest_url_vrf, data=ocdata_vrf)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response3)
        st.log(response4)
        st.log('-----------------------------------------------------------------------------------------')
        if not response3["status"] in [200, 204]:
            err ="Failed to configure dhcpv6-relay helper address through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    state_id = [2,0,1]
    for tc,intf,client_intf,_,pool,pool_v6,state in zip(tc_list[0:3],data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,state_id):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4,client_intf, family='ipv6')

        #################################################
        hdrMsg("Step : Verify dhcp relay configuration under interface {}".format(intf))
        #################################################
        result = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
        if result is False:
            err ="DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        ################################################################################
        hdrMsg("Step : Verify dhcp relay address configuration under interface {} via REST API".format(intf))
        ################################################################################
        rest_url_read = rest_urls['dhcp_relay_address']
        response2 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        x =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][0]['state']['helper-address'][0])
        if x != data.dhcp_server_ip:
            err ="Failed to read dhcp-relay address through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        x =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][0]['state']['helper-address'][0])
        if x != data.dhcp_server_ipv6:
            err ="Failed to read dhcpv6-relay address through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc,'test_case_failure_message',err)


        ##########################################################################
        hdrMsg("Step: Doing REST GET operation to verify the relay statistics ")
        ##########################################################################
        rest_url_read = rest_urls['dhcp_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        y = str(response1['output']['openconfig-relay-agent:interface'][0]['state']['counters']['bootrequest-received'])
        #st.log(y)
        if y == 0:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_read = rest_urls['dhcpv6_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        y = str(response1['output']['openconfig-relay-agent:interface'][0]['state']['counters']['dhcpv6-request-received'])
        #st.log(y)
        if y == 0:
            err ="Failed to read dhcpv6-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        if tc_result is True:
            st.report_tc_pass(tc,'tc_passed')

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv6")

    killall_dhclient(data.dut4)
    tc_result = True
    #################################################
    hdrMsg("Step : Configure src-intf suboption with loopback interface on all dhcp-relay enabled interfaces and start dhcp clients")
    #################################################

    for interface,src_intf in zip(data.relay_port, data.lb_src_intf_list):
        ocdata = { "openconfig-relay-agent-ext:src-intf": src_intf}
        rest_url = rest_urls['dhcp_relay_src_int_config'].format(interface)
        response2 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay src-intf suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        ocdata = { "openconfig-relay-agent-ext:src-intf": src_intf}
        rest_url = rest_urls['dhcpv6_relay_src_int_config'].format(interface)
        response2 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcpv6-relay src-intf suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):
        ### Start dhcp client ##########################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')
        if  client_intf == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
                del data['ip_add_phy']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)
            if 'ip_add_phy_v6' in data.keys():
                ip_api.delete_ip_interface(data.dut4,client_intf, data.ip_add_phy_v6, '64', family="ipv6",skip_error=True)
                del data['ip_add_phy_v6']
                dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')

        #################################################
        hdrMsg("Step : Verify src-intf option in detailed dhcp-relay for {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,link_select='disable',max_hop_count=10)
        if result is False:
            err = "Source-interface config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,family='ipv6',max_hop_count=10)
        if result is False:
            err = "IPv6 Source-interface config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify dhcp client gets ip address assigned on expected subnet for {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)


        ##########################################################################
        hdrMsg("Step: Doing REST GET operation to verify the relay statistics ")
        ##########################################################################
        rest_url_read = rest_urls['dhcp_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_read = rest_urls['dhcpv6_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################

        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv6")
        killall_dhclient(data.dut4)

    if tc_result is True:
        st.report_tc_pass(tc_list[3],'tc_passed')
    tc_result = True
    #################################################
    hdrMsg("Step : Enable link-select suboption and restart dhcp clients on all client interfaces ")
    #################################################
    for interface in data.relay_port:
        ocdata = { "openconfig-relay-agent-ext:link-select": "ENABLE"}
        rest_url = rest_urls['dhcp_relay_link_select'].format(interface)
        response2 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay link-select suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        if  client_intf == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
                del data['ip_add_phy']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        #################################################
        hdrMsg("Step : Verify link-select option enabled under detailed output for {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,link_select='enable')
        if result is False:
            err = "link state config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[4],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify client on interface {} obtain ip address on expected subnet ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with link-select".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[4],'test_case_failure_message',err)


        ##########################################################################
        hdrMsg("Step: Doing REST GET operation to verify the relay statistics ")
        ##########################################################################
        rest_url_read = rest_urls['dhcp_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################

        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
    if tc_result is True:
        st.report_tc_pass(tc_list[4],'tc_passed')
    killall_dhclient(data.dut4)
    tc_result = True

    #################################################
    hdrMsg("Step: Configure max-hop-count suboption to 1 and restart dhcp clients on all client interfaces ")
    #################################################
    for interface in data.relay_port:
        ocdata = { "openconfig-relay-agent-ext:max-hop-count": 1}
        rest_url = rest_urls['dhcp_relay_max_hop_count'].format(interface)
        response2 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        ocdata = { "openconfig-relay-agent-ext:max-hop-count": 1}
        rest_url = rest_urls['dhcpv6_relay_max_hop_count'].format(interface)
        response2 = st.rest_update(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcpv6-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)


    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,ink_select='enable',max_hop_count=1)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf, family='ipv6',max_hop_count=1)
        if result is False:
            err = "IPv6 max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify the client interface obtain ip address since packets will be Relay interface {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "DHCH packets dropped for {} with max-hop-count set to 1".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        ##########################################################################
        hdrMsg("Step: Doing REST GET operation to verify the relay statistics ")
        ##########################################################################
        rest_url_read = rest_urls['dhcp_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)


    killall_dhclient(data.dut4)

    for intf, client_intf, _, pool, pool_v6, src_intf in zip(data.relay_port, data.client_port, data.client_port_ip,
                                                        data.server_pool, data.server_pool_ipv6,data.lb_src_intf_list):

        #################################################
        hdrMsg("Step : Change the max-hop-count to 15 on {} and restart dhcp clients".format(intf))
        #################################################

        ocdata = { "openconfig-relay-agent-ext:max-hop-count": 15}
        rest_url = rest_urls['dhcp_relay_max_hop_count'].format(intf)
        response2 = st.rest_modify(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        ocdata = { "openconfig-relay-agent-ext:max-hop-count": 15}
        rest_url = rest_urls['dhcpv6_relay_max_hop_count'].format(intf)
        response2 = st.rest_modify(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcpv6-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')

        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,link_select='enable',max_hop_count=15)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,family='ipv6',max_hop_count=15)
        if result is False:
            err = "IPv6 max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify all clients gets ip/ipv6 address from server after changing max-hop-count {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "IP address assignment failed  for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf, network_pool=pool_v6, family='ipv6')
        if result is False:
            err = "IPv6 address assignment failed for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv6")
        killall_dhclient(data.dut4)

    if tc_result is True:
        st.report_tc_pass(tc_list[5],'tc_passed')

    #################################################################################
    hdrMsg("Step : Remove all dhcp relay config")
    #################################################################################
    config_dhcpRelay(action='remove')
    system_id =[0,0,1]
    for intf, client_intf, _, pool, pool_v6, src_intf, id in zip(data.relay_port, data.client_port, data.client_port_ip,
                                                        data.server_pool, data.server_pool_ipv6,data.lb_src_intf_list,system_id):

        #################################################
        hdrMsg("Step : Config dhcp-relay-helper address along with scr-intf {}, link enable and max-hop-count through REST and restart dhcp clients".format(src_intf))
        #################################################
        ocdata = {"openconfig-relay-agent:dhcp":{"agent-information-option":{},"interfaces":{"interface":[{"id":intf,"config":{"id":intf,"helper-address":[data.dhcp_server_ip],"openconfig-relay-agent-ext:src-intf":src_intf,"openconfig-relay-agent-ext:vrf":vrf_name,"openconfig-relay-agent-ext:max-hop-count":15,"openconfig-relay-agent-ext:vrf-select":"DISABLE","openconfig-relay-agent-ext:link-select":"ENABLE","openconfig-relay-agent-ext:policy-action":"DISCARD"},"interface-ref":{},"agent-information-option":{}}]}}}
        rest_url = rest_urls['dhcp_relay_config_all_options']
        response2 = st.rest_modify(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcp-relay with all suboptions through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)
        
        ocdata = {"openconfig-relay-agent:dhcpv6":{"options":{},"interfaces":{"interface":[{"id":intf,"config":{"id":intf,"helper-address":[data.dhcp_server_ipv6],"openconfig-relay-agent-ext:src-intf":src_intf,"openconfig-relay-agent-ext:vrf":vrf_name,"openconfig-relay-agent-ext:max-hop-count":15,"openconfig-relay-agent-ext:vrf-select":"DISABLE"},"interface-ref":{},"options":{}}]}}}
        rest_url = rest_urls['dhcpv6_relay_config_all_options']
        response2 = st.rest_modify(data.dut2, path=rest_url, data=ocdata)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to configure dhcpv6-relay with all suboptions through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')

        ########################################################################
        hdrMsg("Step : Verify max-hop-count, src-intf and link select configuration on {} via REST API".format(intf))
        ########################################################################

        rest_url_read = rest_urls['dhcp_relay_address']
        response2 = st.rest_read(data.dut2, rest_url_read)
        st.log(response2)
        result1 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][id]['config']['openconfig-relay-agent-ext:max-hop-count'])
        result2 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][id]['config']['openconfig-relay-agent-ext:src-intf'])
        result3 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][id]['config']['openconfig-relay-agent-ext:link-select'])
        result4 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][id]['id'])
        if  result1 != '15' or result2 != src_intf or result3 != 'ENABLE' or result4 !=intf:
            err ="Failed to read dhcp-relay config through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        result1 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][id]['config']['openconfig-relay-agent-ext:max-hop-count'])
        result2 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][id]['config']['openconfig-relay-agent-ext:src-intf'])
        result3 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][id]['id'])
        if  result1 != '15' or result2 != src_intf or result3 !=intf:
            err ="Failed to read dhcpv6-relay config through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify all clients gets ip/ipv6 address from server after changing max-hop-count {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "IP address assignment failed  for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf, network_pool=pool_v6, family='ipv6')
        if result is False:
            err = "IPv6 address assignment failed for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        ##########################################################################
        hdrMsg("Step: Doing REST GET operation to verify the relay statistics ")
        ##########################################################################
        rest_url_read = rest_urls['dhcp_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_read = rest_urls['dhcpv6_relay_stats'].format(intf)
        response1 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response1)
        st.log('-----------------------------------------------------------------------------------------')
        if not response1["status"] in [200, 204]:
            err ="Failed to read dhcp-relay stats through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    if tc_result is True:
        st.report_tc_pass(tc_list[5],'tc_passed')
    #############  End of new code ##################

    #################################################################################
    #################################################
    hdrMsg("ClEANUP.... ")
    #################################################

    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface,family='ipv6',skip_error_check=True)
        if client_interface == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface)
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy, '24', skip_error=True)
                del data['ip_add_phy']
            if 'ip_add_phy_v6' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface, family='ipv6')
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy_v6, '64', family="ipv6", skip_error=True)
                del data['ip_add_phy_v6']
        if 'PortChannel' in client_interface:
            dhcp_relay.dhcp_client_start(data.dut4, client_interface,family='ipv6')
            st.wait(5)
            dhcp_relay.dhcp_client_stop(data.dut4, client_interface,skip_error_check=True,family='ipv6')
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")
    killall_dhclient(data.dut4)

    for interface, state in zip(data.relay_port, state_id):
        #########################################################
        rest_url_del = rest_urls['dhcp_relay_link_select'].format(interface)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcp-relay link-select suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_del = rest_urls['dhcp_relay_src_int_config'].format(interface)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcp-relay src-intf suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_del = rest_urls['dhcp_relay_max_hop_count'].format(interface)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcp-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_del = rest_urls['dhcpv6_relay_src_int_config'].format(interface)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcpv6-relay src-intf suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        rest_url_del = rest_urls['dhcpv6_relay_max_hop_count'].format(interface)
        response2 = st.rest_delete(data.dut2, rest_url_del)
        st.log('-----------------------------------------------------------------------------------------')
        st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        if not response2["status"] in [200, 204]:
            err ="Failed to delete dhcpv6-relay max-hop-count suboption through REST API"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        ################################################################################
        hdrMsg("Step : Verify dhcp relay address configuration under interface {} via REST API".format(interface))
        ################################################################################
        rest_url_read = rest_urls['dhcp_relay_address']
        response2 = st.rest_read(data.dut2, rest_url_read)
        st.log('-----------------------------------------------------------------------------------------')
        #st.log(response2)
        st.log('-----------------------------------------------------------------------------------------')
        result1 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][state]['state']['helper-address'][0])
        result2 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcp']['interfaces']['interface'][state]['id'])
        if result1 != data.dhcp_server_ip or result2 !=interface:
            err ="Failed to read dhcp-relay address through REST API after deleting the all the suboptions"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        result1 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][state]['state']['helper-address'][0])
        result2 =str(response2['output']['openconfig-relay-agent:relay-agent']['dhcpv6']['interfaces']['interface'][state]['id'])

        if result1 != data.dhcp_server_ipv6 or result2 !=interface:
            err ="Failed to read dhcpv6-relay address through REST API after deleting the all the suboptions"
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def test_dhcp_relay_vxlan_007(prologue_epilogue):
    tc_list = ['FtOpSoRoDHCPRFt052','FtOpSoRoDHCPRFt053','FtOpSoRoDHCPRFt054','FtOpSoRoDHCPRFt055','FtOpSoRoDHCPRFt056','FtOpSoRoDHCPRFt057']
    tc_result = True ;err_list=[]

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    ########################################################################################
    hdrMsg("Step01 : Bring-up Ipunnumbered interface between SPINE(dhcp-server) and LEAF2")
    ########################################################################################
    for ip in route_list:
        ip_api.delete_static_route(data.dut1, next_hop= data.dut3_server_ip_list[0],static_ip=ip)

    ip_api.delete_ip_interface(data.dut1,'Vlan50', data.dhcp_server_ip,mask_24)
    ip_api.delete_ip_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ip_list[0],mask_24)

    ##################################################################################################
    hdrMsg("Step02 : Create loopback interface on both  SPINE and LEAF2 device and assign ip address")
    ##################################################################################################
    parallel.exec_parallel(True, [data.dut1,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback3'}] * 2)
    vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Loopback3',skip_error='True')
    st.exec_all([[ip_api.config_ip_addr_interface, data.dut1, "Loopback3", data.dhcp_server_ip, '32'],[ip_api.config_ip_addr_interface, data.dut3, "Loopback3", dut3_loopback_ip_list[2], '32']])

    for ip in route_list:
        ip_api.create_static_route(data.dut1, next_hop= dut3_loopback_ip_list[2],static_ip=ip)

    hdrMsg('Configure ospf between DUT1 and DUT3')
    st.exec_all([[ospf_obj.config_ospf_router_id, data.dut1, dut1_ospf_router_id, 'default', '','yes'],[ospf_obj.config_ospf_router_id, data.dut3, dut3_ospf_router_id, vrf_name, '','yes']])
    st.exec_all([[ospf_obj.config_ospf_network, data.dut1, data.dhcp_server_ip+'/'+ip_loopback_prefix, 0, 'default', '','yes'],[ospf_obj.config_ospf_network, data.dut3, '55.55.55.55'+'/'+ip_loopback_prefix, 0, vrf_name, '','yes']])
    st.exec_all([[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'Vlan50','point-to-point','default','yes'],[ospf_obj.config_interface_ip_ospf_network_type, data.dut3, data.dhcp_server_port,'point-to-point',vrf_name,'yes']])

    #########################################################################################
    hdrMsg('Configure IP unnumbered on Vlan50 interface DUT1 and physical interface on DUT3')
    #########################################################################################
    dict1 = {'family':'ipv4', 'action':'add','interface':'Vlan50', 'loop_back':'Loopback3'}
    dict2 = {'family':'ipv4', 'action':'add','interface':data.dhcp_server_port, 'loop_back':'Loopback3'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.config_unnumbered_interface, [dict1, dict2])

    ###################################################################
    hdrMsg('Redistribute ospf into bgp on DUT3')
    ###################################################################
    bgp_api.config_bgp(data.dut3, local_as=dut3_AS, vrf_name=vrf_name, config_type_list =["redist"], redistribute ='ospf')

    ###################################################
    hdrMsg("Verifying ospf neighbors on dut3")
    ###################################################
    result1 = retry_api(ospf_obj.verify_ospf_neighbor_state,data.dut3,ospf_links=[data.dhcp_server_port], states=['Full'],vrf=vrf_name)
    if not result1:
        st.error('ospf neighborship failed to Establish')
        tc_result=False;
        st.report_tc_fail(tc_list[0], 'test_case_failure_message')

    if tc_result is True:
       st.report_tc_pass(tc_list[0],'tc_passed')


    for tc,intf,client_intf,_,pool,pool_v6 in zip(tc_list[1:],data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):
        tc_result = True
        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for interface {} ".format(intf)
            tc_result=False;
            st.report_tc_fail(tc, 'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")

        if tc_result is True:
            st.report_tc_pass(tc,'tc_passed')

    #################################################
    hdrMsg("ClEANUP.... ")
    #################################################
    killall_dhclient(data.dut4)
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")


    ##########################################################################################
    hdrMsg('UnConfig IP unnumbered on Vlan50 and physical interfaces between DUT1 and DUT3')
    ##########################################################################################
    dict1 = {'family':'ipv4', 'action':'del','interface':'Vlan50', 'loop_back':'Loopback3'}
    dict2 = {'family':'ipv4', 'action':'del','interface':data.dhcp_server_port, 'loop_back':'Loopback3'}
    parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.config_unnumbered_interface, [dict1, dict2])

    ##############################################
    hdrMsg('UnConfig ospf between DUT1 and DUT3')
    ##############################################
    st.exec_all([[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'Vlan50','point-to-point','default','no'],[ospf_obj.config_interface_ip_ospf_network_type, data.dut3, data.dhcp_server_port ,'point-to-point',vrf_name,'no']])
    st.exec_all([[ospf_obj.config_ospf_router, data.dut1, 'default', '','no'],[ospf_obj.config_ospf_router, data.dut3, vrf_name, '','no']])

    for ip in route_list:
        ip_api.delete_static_route(data.dut1, next_hop= dut3_loopback_ip_list[2],static_ip=ip)

    st.exec_all([[ip_api.delete_ip_interface, data.dut1, "Loopback3", data.dhcp_server_ip, '32'],[ip_api.delete_ip_interface, data.dut3, "Loopback3", dut3_loopback_ip_list[2], '32']])
    vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Loopback3',skip_error='True',config='no')
    ip_api.configure_loopback(data.dut1,loopback_name="Loopback3",config='no')

    ip_api.config_ip_addr_interface(data.dut1,'Vlan50', data.dhcp_server_ip,mask_24)
    ip_api.config_ip_addr_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ip_list[0],mask_24)

    for ip in route_list:
        ip_api.create_static_route(data.dut1, next_hop= data.dut3_server_ip_list[0],static_ip=ip)

    if tc_result is False:
        err = "One of the dhcp cleint failed to get an IP address from the server"
        st.report_fail('test_case_failure_message',err)
    else:
        st.report_pass('test_case_passed')



@pytest.fixture(scope="function")
def dhcprelay_cleanup_fixture_005(request,prologue_epilogue):
    yield
    #################################################
    hdrMsg("ClEANUP....Starts ")
    #################################################
    killall_dhclient(data.dut4)
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")

    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='link-select', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='src-intf', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='vrf-select', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='src-intf', action='remove',family='ipv6')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='vrf-select', action='remove',family='ipv6')

    action = 'remove'
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,action=action,family='ipv6')
    ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ip_list[1],mask_24)
    ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[1],mask_v6,family="ipv6")
    ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
    ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[0],mask_v6,family="ipv6")
    action = 'add'
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,action=action,family='ipv6',vrf_name =vrf_name)

    #################################################
    hdrMsg("ClEANUP.... Ends")
    #################################################

def test_dhcp_relay_vxlan_005(dhcprelay_cleanup_fixture_005):
    tc_list = ['FtOpSoRoDHCPRFt026','FtOpSoRoDHCPRFt038','FtOpSoRoDHCPRFt039','FtOpSoRoDHCPRFt040','FtOpSoRoDHCPRFt041','FtOpSoRoDHCPRFt042','FtOpSoRoDHCPRFt043','FtOpSoRoDHCPRFt044','FtOpSoRoDHCPRFt045','FtOpSoRoDHCPRFt046','FtOpSoRoDHCPRFt047']
    tc_result = True ;err_list=[]
    final_result = 0
    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        st.report_unsupported("test_execution_skipped", "Skipping Non-OC-Yang test case for ui_type={}".format(st.get_ui_type()))

    data.inter_vni = True
    action = 'remove'
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ip,action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ipv6,action=action,family='ipv6')
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,action=action,family='ipv6')

    ip_api.delete_ip_interface(data.dut2,data.d2d4_ports[1],dut2_4_ip_list[1],mask_24)
    ip_api.delete_ip_interface(data.dut2, data.d2d4_ports[1], dut2_4_ipv6_list[1], mask_v6,family='ipv6')
    vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name =data.d2d4_ports[1],config = 'no',skip_error='True')

    vrf_api.config_vrf(data.dut2, vrf_name=vrf_blue, config='yes')
    vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name ='Vlan600',skip_error='True')
    vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name =data.d2d4_ports[1],skip_error='True')

    ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
    ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ipv6_list[1],mask_v6,family="ipv6")

    ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
    ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[0],mask_v6,family="ipv6")
    ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ip_list[1],mask_24)
    ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[1],mask_v6,family="ipv6")

    evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "600", "600")
    evpn.map_vrf_vni(data.dut2, vrf_blue,vtep_name='vtepLeaf1', vni="600")

    #bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_name, addr_family ='ipv4', config_type_list=["import_vrf"], import_vrf_name=vrf_blue)
    #bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_name, addr_family ='ipv6', config_type_list=["import_vrf"], import_vrf_name=vrf_blue)
    bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config_type_list =["redist"], redistribute ='connected')
    bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')

    evpn.config_bgp_evpn(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config ='yes', config_type_list=["advertise_ipv4_vrf"], advertise_ipv4='unicast')
    evpn.config_bgp_evpn(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config ='yes', config_type_list=["advertise_ipv6_vrf"], advertise_ipv6='unicast')
    #bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, addr_family ='ipv4', config_type_list=["import_vrf"], import_vrf_name=vrf_name)
    #bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, addr_family ='ipv6', config_type_list=["import_vrf"], import_vrf_name=vrf_name)

    #################################################
    hdrMsg("Step : Configure src-intf suboption with loopback interface on all dhcp-relay enabled interfaces and start dhcp clients")
    #################################################
    action = 'add'
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ip,action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ipv6,action=action,family='ipv6',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,action=action,family='ipv6',vrf_name =vrf_name)

    for interface in data.relay_port:
        src_intf = src_intf_same_vni
        dhcp_relay.dhcp_relay_option_config(data.dut2, src_interface=src_intf, interface=interface, option='src-intf')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='link-select')
        dhcp_relay.dhcp_relay_option_config(data.dut2, src_interface=src_intf, interface=interface, option='src-intf',family='ipv6')

    server_pool = ['20.20.20.','20.20.20.','30.30.30.']
    server_pool_ipv6 = ['2020::','2020::','2030::']
    data.client_port_ip = ['20.20.20.1','20.20.20.1','30.30.30.1']
    killall_dhclient(data.dut4)
    for intf,client_intf,pool,pool_v6 in zip(data.relay_port,data.client_port,server_pool,server_pool_ipv6):
        #################################################
        hdrMsg("Step : Start DHCP client on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4,client_intf, family='ipv6')


        if 'ip_add_phy' in data.keys():
           ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
           del data['ip_add_phy']
           dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        if 'ip_add_phy_v6' in data.keys():
            ip_api.delete_ip_interface(data.dut4,client_intf, data.ip_add_phy_v6, '64', family="ipv6",skip_error=True)
            del data['ip_add_phy_v6']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')

        #################################################
        hdrMsg("Step : Verify client on interface {} obtain ip address on expected subnet ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} without VSS option".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {} without VSS option".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
    if tc_result is True:
        st.log("Testcase passed - {}".format(tc_list[0]))
        st.report_tc_pass(tc_list[0],'tc_passed')

    killall_dhclient(data.dut4)
    tc_result = True
    ####################################################
    hdrMsg("Step : Configure VSS option(151) on the dhcp relay ")
    ####################################################
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2,interface=interface, option='vrf-select')
        dhcp_relay.dhcp_relay_option_config(data.dut2,interface=interface, option='vrf-select',family='ipv6')


    for tc,intf,client_intf,pool,pool_v6 in zip(tc_list[1:5],data.relay_port,data.client_port,server_pool,server_pool_ipv6):
        #################################################
        hdrMsg("Step : Start DHCP client on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4,client_intf, family='ipv6')


        if 'ip_add_phy' in data.keys():
           ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
           del data['ip_add_phy']
           dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        if 'ip_add_phy_v6' in data.keys():
            ip_api.delete_ip_interface(data.dut4,client_intf, data.ip_add_phy_v6, '64', family="ipv6",skip_error=True)
            del data['ip_add_phy_v6']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf,family='ipv6')

        #################################################
        hdrMsg("Step : Verify client on interface {} obtain ip address on expected subnet ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with VSS option".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc,'test_case_failure_message',err)

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')
        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {} with VSS option".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc,'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
        if tc_result is True:
            st.log("Testcase passed - {}".format(tc))
            st.report_tc_pass(tc,'tc_passed')

    killall_dhclient(data.dut4)
    tc_result = True
    #############################################################
    hdrMsg("Config Save")
    #############################################################
    bgp_api.enable_docker_routing_config_mode(data.dut2)
    reboot_api.config_save(data.dut2)
    reboot_api.config_save(data.dut2, 'vtysh')
    tc_1 = tc_list[5:8]
    for trigger in (['config_reload','reboot']):

        #############################################################
        hdrMsg("Trigger : {}".format(trigger))
        #############################################################

        if trigger == 'reboot' :  st.reboot(data.dut2, "fast")
        if trigger == 'config_reload':  reboot_api.config_reload(data.dut2)
        if trigger == 'warmboot':
            reboot_api.config_warm_restart(data.dut2,oper = "enable", tasks = ["system"])
            st.reboot(data.dut2, "warm")

        for tc,intf,client_intf,_,pool,pool_v6 in zip(tc_1,data.relay_port,data.client_port,data.client_port_ip,server_pool,server_pool_ipv6):

            ########################################################################
            hdrMsg("Stopping and restart dhclient to renew ip address")
            ########################################################################
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)

            #################################################
            hdrMsg("Step : Verify all clients gets ip address from server on interface {} after {} ".format(intf,trigger))
            #################################################
            result = check_dhcp_client(interface=client_intf, network_pool=pool)
            if result is False:
                err = "IP address assignment failed  for {} after {}".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);final_result += 1;
                st.report_tc_fail(tc, 'test_case_failure_message',err)


            ##################################################
            hdrMsg("Step: Stop dhclient")
            ##################################################
            dhcp_relay.dhcp_client_stop(data.dut4, client_intf, skip_error_check=True)
            if client_intf == data.d4d2_ports[1]:
                if 'ip_add_phy' in data.keys():
                    dhcp_relay.dhcp_client_start(data.dut4, client_intf)
                    ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24', skip_error=True)
                    del data['ip_add_phy']
                st.wait(5)
            killall_dhclient(data.dut4)
            if tc_result is True:
                st.log("Testcase passed - {}".format(tc))
                st.report_tc_pass(tc,'tc_passed')
        tc_1 =tc_list[8:]

    if final_result != 0:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')


def test_dhcp_relay_vxlan_scale(prologue_epilogue):

    vars = st.get_testbed_vars()
    data.d3_tg_1 = vars.D3T1P1
    data.d2_tg_1 = vars.D2T1P1
    data.tg_d3_1, data.tg_d3_1_ph = tgapi.get_handle_byname("T1D3P1")
    data.tg_d2_1, data.tg_d2_1_ph = tgapi.get_handle_byname("T1D2P1")
    if data.tg_d3_1.tg_type != 'stc':
        st.report_unsupported('test_execution_skipped', 'Not supported on TGEN type: {}'. format(data.tg_d3_1.tg_type))

    data.d3_tg_1_mac = basic_api.get_ifconfig_ether(data.dut3, data.d3_tg_1)


    tc_list = ['FtOpSoRoDHCPRScal001','FtOpSoRoDHCPRScal002', 'FtOpSoRoDHCPRScal003','FtOpSoRoDHCPRScal004']

    vrf_api.config_vrf(data.dut2, vrf_name=vrf_blue, config='yes')
    st.exec_all([[config_dhcp_client], [config_client_intf]], first_on_main=True)
    config_dhcp_server()

    final_result = 0
    for test_case in ['bind', 'renew', 'release_and_bind', 'client_intf_flap_renew']:
        tc_index = 0
        st.log('Executing Test Case: {}'.format(test_case))
        if test_case in ['bind', 'renew']:
            start_dhcp_client(action=test_case)
            st.wait(20, 'Waiting for clients to get address')
            tc_result = utils.retry_api(verify_dhcp_client_stats, stats_type=test_case, total_bound = data.clients_supported, total_renew = data.clients_supported, delay=10, retry_count=10)
        if test_case in ['release_and_bind']:
            start_dhcp_client(action='release')
            st.wait(5, 'Waiting for addresses to be released')
            start_dhcp_client(action='bind')
            st.wait(20, 'Waiting for clients to get address, after release')
            tc_result = utils.retry_api(verify_dhcp_client_stats, stats_type='bind', total_bound = data.clients_supported, total_renew = data.clients_supported, delay=10, retry_count=10)

        if test_case in ['client_intf_flap_renew']:
            port_api.set_status(data.dut2, [data.d2_tg_1],'shutdown')
            st.wait(2, 'Keep intf in down state')
            port_api.set_status(data.dut2, [data.d2_tg_1],'startup')
            st.wait(5, 'Waiting for intf to come up')
            start_dhcp_client(action='renew')
            st.wait(20, 'Waiting for clients to get address, after release')
            tc_result = utils.retry_api(verify_dhcp_client_stats, stats_type='renew', total_bound = data.clients_supported, total_renew = data.clients_supported, delay=10, retry_count=10)

        if tc_result:
            st.log('Test Case: {}, {}'.format(test_case, 'Passed'))
            st.report_tc_pass(tc_list[tc_index], 'test_case_passed')
        else:
            final_result += 1
            st.log('Test Case: {}, {}'.format(test_case, 'Failed'))
            dump_dhcp_client_stats()
            st.report_tc_fail(tc_list[tc_index], 'test_case_failed')

        tc_index += 1

    st.log('final_result: {}'.format(final_result))
    if final_result == 0:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')



