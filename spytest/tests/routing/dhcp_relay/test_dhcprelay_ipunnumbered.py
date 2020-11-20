##############################################################################
#Script Title : DHCP-Relay over IPunnumbered
#Author       : Raghu
#Mail-id      : raghukumar.thimmareddy@broadcom.com
###############################################################################

import os
import pytest
from spytest import st
from dhcprelay_ipunnumbered_vars import *
from dhcprelay_ipunnumbered_vars import data
from dhcprelay_ipunnumbered_utils import *
from dhcp_relay_utils import check_dhcp_relay_statistics,killall_dhclient,check_dhcp_relay_interface_config
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.reboot as reboot_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api


def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D3:1", "D2D3:1","D2D4:3")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]

    for dut in data.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d3_ports = [vars.D1D3P1]
    data.d3d1_ports = [vars.D3D1P1]
    data.d2d3_ports = [vars.D2D3P1]
    data.d3d2_ports = [vars.D3D2P1]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]

    # DUT as dhcp server
    data.dhcp_server_port = data.d3d1_ports[0]
    data.server_d3_port = data.d1d3_ports[0]
    #dhcp_server_vxlan_param_list = ['server_mgmt_ip', 'dhcp_server_ip', 'dhcp_server_ipv6', 'username', 'password']
    #for server_param in dhcp_server_vxlan_param_list:
    #    data[server_param] = util_obj.ensure_service_params(data.dut1, 'dhcp_server_vxlan', server_param)

    data.dhcp_server_ip = '172.16.40.210'
    data.dhcp_server_ipv6 = '2072::210'
    data.username = 'admin'
    data.password = st.get_credentials(data.dut1)[3]

    temp_list = data.dhcp_server_ip.split('.')
    temp_list[3] = '1'
    data.dut3_server_ip_list =  ['.'.join(temp_list)]
    data.dut3_server_ipv6_list = [data.dhcp_server_ipv6.split('::')[0] + "::1"]

    data.relay_port = ['Vlan100',data.d2d4_ports[1],'PortChannel12']
    data.client_port = ['Vlan100', 'Vlan200', 'Vlan300']
    data.client_port_ip = ['192.168.0.1','20.20.20.1','30.30.30.1']
    data.server_pool = ['192.168.0.','20.20.20.','30.30.30.']
    data.client_port_ipv6 = ['2092::1','2020::1','2030::1']
    data.server_pool_ipv6 = ['2092::','2020::','2030::']
    data.lb_src_intf_list = ['Loopback1','Loopback1','Loopback1']
    data.dhcp_files =  ['dhcp-server-interface','dhcpd.conf','dhcpd6.conf']
    data.dhcp_files_path =  [os.path.join(os.path.dirname(__file__),data.dhcp_files[0]),os.path.join(os.path.dirname(__file__),data.dhcp_files[1]),os.path.join(os.path.dirname(__file__),data.dhcp_files[2])]
    data.dhcp_files_path =  []
    for file in data.dhcp_files: data.dhcp_files_path.append(os.path.join(os.path.dirname(__file__),file))

@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    print_topology()
    #import pdb;pdb.set_trace()
    result = dhcp_relay_base_config()
    if result is False:
        st.report_fail("Error in module config")
    yield
    dhcp_relay_base_deconfig()


@pytest.fixture(scope="function")
def dhcprelay_cleanup_fixture_001(request,prologue_epilogue):
    yield
    #################################################
    hdrMsg("ClEANUP....Starts ")
    #################################################
    
    killall_dhclient(data.dut4)
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
    killall_dhclient(data.dut4)
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='link-select', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='src-intf', action='remove')
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=interface, option='max-hop-count', action='remove')
    
    #################################################
    hdrMsg("ClEANUP.... Ends")
    #################################################
        
def test_dhcprelay_over_ipunn_001(dhcprelay_cleanup_fixture_001):
    tc_list = ['FtOpSoRoDHCPRFt027','FtOpSoRoDHCPRFt028','FtOpSoRoDHCPRFt029','FtOpSoRoDHCPRFt030','FtOpSoRoDHCPRFt031','FtOpSoRoDHCPRFt032','FtOpSoRoDHCPRFt033','FtOpSoRoDHCPRFt034','FtOpSoRoDHCPRFt035','FtOpSoRoDHCPRFt036']
    tc_result = True ;err_list=[]
    final_result = 0
    for tc,intf,client_intf,_,pool,pool_v6 in zip(tc_list[0:3],data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify dhcp relay configuration under interface {}".format(intf))
        #################################################
        result = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
        if result is False:
            err ="DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc,'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(client_intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {}".format(client_intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc,'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}" .format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc,'test_case_failure_message',err)

        if tc_result is True:
            st.report_tc_pass(tc,'tc_passed')

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics reset to 0")
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf,expected=0)
        if result is False:
            err ="DHCP relay statistics did not reset after clearing for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
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

    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        if  client_intf == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                ip_api.delete_ip_interface(data.dut4, client_intf, data.ip_add_phy, '24',skip_error=True)
                del data['ip_add_phy']
            dhcp_relay.dhcp_client_start(data.dut4, client_intf)


        #################################################
        hdrMsg("Step : Verify src-intf option in detailed dhcp-relay for {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2,interface=intf,src_interface=src_intf,link_select='disable',max_hop_count=10)
        if result is False:
            err = "Source-interface config failed on {}".format(intf)
            tc_result = False; err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[3],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify dhcp client gets ip address assigned on expected subnet for {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)


        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}".format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {} with source-interface".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop all dhcp clients and  clear dhcp-relay statistics on all interfaces ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")
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
            tc_result = False; err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[4],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify client on interface {} obtain ip address on expected subnet ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {} with link-select".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[4],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}".format(intf))
        #################################################
        result = check_dhcp_relay_statistics(data.dut2,interface=intf)
        if result is False:
            err ="DHCP relay statistics check failed for {} with link-select".format(intf)
            tc_result=False;err_list.append(err);failMsg(err);final_result += 1;
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
    hdrMsg("Step: Configure max-hop-count suboption to 1 and restart dhcp clients on all client interfaces ")
    #################################################
    for interface in data.relay_port:
        dhcp_relay.dhcp_relay_option_config(data.dut2,interface=interface,option='max-hop-count',max_hop_count=1)


    for intf,client_intf,_,pool,pool_v6,src_intf in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6,data.lb_src_intf_list):

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,ink_select='enable',max_hop_count=1)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify the client interface obtain ip address since packets will be Relay interface {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "DHCH packets dropped for {} with max-hop-count set to 1".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)


    killall_dhclient(data.dut4)

    for intf, client_intf, _, pool, pool_v6, src_intf in zip(data.relay_port, data.client_port, data.client_port_ip,
                                                        data.server_pool, data.server_pool_ipv6,data.lb_src_intf_list):

        #################################################
        hdrMsg("Step : Change the max-hop-count to 15 on {} and restart dhcp clients".format(intf))
        #################################################

        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=intf, option='max-hop-count', max_hop_count=15)

        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify max-hop-count configuration on {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,link_select='enable',max_hop_count=15)
        if result is False:
            err = "max-hop-count config failed on {}".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[5],'test_case_failure_message', err)

        #################################################
        hdrMsg("Step : Verify all clients gets ip address from server after changing max-hop-count {} ".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf, network_pool=pool)
        if result is False:
            err = "IP address assignment failed  for {} with max-hop-count set to 15".format(intf)
            tc_result = False;
            err_list.append(err);failMsg(err);final_result += 1;
            st.report_tc_fail(tc_list[5], 'test_case_failure_message',err)

    if tc_result is True:
        st.report_tc_pass(tc_list[5],'tc_passed')

    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface,skip_error_check=True)
        if client_interface == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface)
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy, '24', skip_error=True)
                del data['ip_add_phy']

        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
    killall_dhclient(data.dut4)
    
    tc_result = True    
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
            #################################################
            hdrMsg("Step : Verify max-hop-count configuration on {} after trigger {}".format(intf,trigger))
            #################################################
            result = dhcp_relay.verify_dhcp_relay_detailed(data.dut2, interface=intf, src_interface=src_intf,link_select='enable',max_hop_count=15)
            if result is False:
                err = "max-hop-count config failed on {} after {} ".format(intf,trigger)
                tc_result = False;
                err_list.append(err);failMsg(err);final_result += 1;
                st.report_tc_fail(tc,'test_case_failure_message', err)


            #################################################
            hdrMsg("Step : Verify all clients gets ip address from server after changing max-hop-count {} after {} ".format(intf,trigger))
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
            st.report_tc_pass(tc,'tc_passed')

    
    if final_result != 0:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def dhcprelay_cleanup_fixture_002(request,prologue_epilogue):
    yield
    #################################################
    hdrMsg("ClEANUP....Starts ")
    #################################################
    killall_dhclient(data.dut4)
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
    
    action='remove'
    hdrMsg("Un-Configure dhcp relay on DUT2 ")
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=dut3_2_ip_list[0],vlan='Vlan100',action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=dut3_2_ip_list[0],action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='PortChannel12', IP=dut3_2_ip_list[0],action=action)
    
    hdrMsg("Un-Configure dhcp relay on DUT3  ")
    dhcp_relay.dhcp_relay_config(data.dut3, interface=data.d3d2_ports[0], IP=data.dhcp_server_ip,action=action)
    
    config_dhcpRelay(action='add')
    hdrMsg("ClEANUP....Ends ")    
                
def test_dhcprelay_over_ipunn_002(dhcprelay_cleanup_fixture_002):
    tc_list = ['FtOpSoRoDHCPRFt048','FtOpSoRoDHCPRFt049','FtOpSoRoDHCPRFt050','FtOpSoRoDHCPRFt051']
    tc_result = True ;err_list=[]
    final_result = 0
    
    config_dhcpRelay(action='remove')
    action='add'
    hdrMsg("Configure dhcp relay on DUT2 and the relay address should of DUT3 interface ip address")
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=dut3_2_ip_list[0],vlan='Vlan100',action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=dut3_2_ip_list[0],action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='PortChannel12', IP=dut3_2_ip_list[0],action=action)

    ################################################################################################################
    hdrMsg("Configure dhcp relay on DUT3 and the relay address should of actual server ip address {} ".format(data.dhcp_server_ip))
    dhcp_relay.dhcp_relay_config(data.dut3, interface=data.d3d2_ports[0], IP=data.dhcp_server_ip,action=action)

    data.relay_port_dut3 =[data.d3d2_ports[0],data.d3d2_ports[0],data.d3d2_ports[0]]
    for intf,client_intf,_,pool,pool_v6 in zip(data.relay_port_dut3,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify policy action option(in discard mode) in detailed dhcp-relay output for interface {}".format(intf))
        #################################################
        result = dhcp_relay.verify_dhcp_relay_detailed(data.dut3,interface=intf,policy_action='discard')
        if result is False:
            err ="Policy action by default should be in discard mode on interface {}".format(intf)
            tc_result=False;
            final_result += 1;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(client_intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is True:
            err ="DHCP client ip address assignment passed for interface {} even though policy action is in discard mode".format(client_intf)
            tc_result=False;
            final_result += 1;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[0],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")

    if tc_result:
        st.report_tc_pass(tc_list[0], 'tc_passed')
    killall_dhclient(data.dut4)
    tc_result = True

    ################################################################
    hdrMsg("Step : Configure policy action set to append on DUT3 ")
    ################################################################
    dhcp_relay.dhcp_relay_option_config(data.dut3,interface=data.d3d2_ports[0],option='policy-action',policy_action='append')

    #################################################
    hdrMsg("Step : Verify policy action option in detailed dhcp-relay output for interface {}".format(data.d3d2_ports[0]))
    #################################################
    result = dhcp_relay.verify_dhcp_relay_detailed(data.dut3,interface=data.d3d2_ports[0],policy_action='append')
    if result is False:
        err ="Policy action not in append mode on interface {}".format(data.d3d2_ports[0])
        tc_result=False;
        final_result += 1;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[1],'test_case_failure_message',err)

    for intf,client_intf,_,pool,pool_v6 in zip(data.relay_port_dut3,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(client_intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for interface {} even though policy action is set to append mode".format(client_intf)
            tc_result=False;
            final_result += 1;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[2],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")

    if tc_result:
        st.report_tc_pass(tc_list[2], 'tc_passed')
    killall_dhclient(data.dut4)

    tc_result = True
    ################################################################
    hdrMsg("Step : Configure policy action set to replace on DUT3 ")
    ################################################################
    dhcp_relay.dhcp_relay_option_config(data.dut3,interface=data.d3d2_ports[0],option='policy-action',policy_action='replace')

    #################################################
    hdrMsg("Step : Verify policy action option in detailed dhcp-relay output for interface {}".format(intf))
    #################################################
    result = dhcp_relay.verify_dhcp_relay_detailed(data.dut3,interface=data.d3d2_ports[0],policy_action='replace')
    if result is False:
        err ="Policy action not in replace mode on interface {}".format(intf)
        tc_result=False;
        final_result += 1;err_list.append(err);failMsg(err);
        st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

    for intf,client_intf,_,pool,pool_v6 in zip(data.relay_port_dut3,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Start DHCP on client side on interface {}".format(client_intf))
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)

        #################################################
        hdrMsg("Step : Verify dhcp clinet assigned ip address on expected subnet on {}".format(client_intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is True:
            err ="DHCP client got an ip address for interface {} even though policy action is set to replace mode".format(client_intf)
            tc_result=False;
            final_result += 1;err_list.append(err);failMsg(err);
            st.report_tc_fail(tc_list[3],'test_case_failure_message',err)

        #################################################
        hdrMsg("Step : Stop dhcp client and clear dhcp-relay statistics ")
        #################################################
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.clear_statistics(data.dut2, intf, family="ipv4")

    if tc_result:
        st.report_tc_pass(tc_list[3], 'tc_passed')
        
    if final_result != 0:
        st.report_fail('test_case_failure_message',err_list)
    else:
        st.report_pass('test_case_passed')
    
    
