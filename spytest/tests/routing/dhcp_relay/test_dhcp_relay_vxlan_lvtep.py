##############################################################################
#Script Title : DHCP-Relay over Vxlan
#Author       : Sooriya/Raghu
#Mail-id      : Sooriya.Gajendrababu@broadcom.com;raghukumar.thimmareddy@broadcom.com
###############################################################################

import pytest
from spytest import st,utils
from dhcp_relay_vars_lvtep import *
from dhcp_relay_vars_lvtep import data
from dhcp_relay_utils_lvtep import *
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.reboot as reboot_api
import apis.system.interface as int_api

import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *
import apis.routing.sag as sag
import apis.routing.dhcp_relay as dhcp_relay

def initialize_topology_vars():
    vars = st.ensure_min_topology("D1D2:1", "D1D5:1", "D2D5:2" , "D1D3:2","D2D4:2", "D5D4:2", "D2CHIP=TD3", "D3CHIP=TD3", "D5CHIP=TD3")

    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    data.dut5 = data.dut_list[4]

    vars = st.get_testbed_vars()
    # Platform check
    #for dut in [data.dut2,data.dut3,data.dut5]:
    #   dut_type=basic_api.get_hwsku(dut)
    #    if "7326" in dut_type or "AS7726" in dut_type or "S5232f" in dut_type or "IX8" in dut_type:
    #       st.log("platform {} can be used as leaf node for evpn dhcp relay testing".format(dut_type))
    #    else:
    #        hdrMsg("Supported platforms for vxlan evpn - \"7326\" or \"AS7726\" or \"S5232f\" or \"Quanta IX8\"")
    #        st.report_env_fail("platform_check_fail",dut)

    for dut in data.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    data.d1d2_ports = [vars.D1D2P1]
    data.d2d1_ports = [vars.D2D1P1]
    data.d1d3_ports = [vars.D1D3P1, vars.D1D3P2]
    data.d3d1_ports = [vars.D3D1P1, vars.D3D1P2]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]

    #server_details = st.get_device_param(data.dut3, 'dhcp_server_vxlan', None)
    #if server_details:
    #    data.dhcp_server_port = server_details[0]
    #    data.server_d3_port = server_details[1]

    # DUT as dhcp server
    data.dhcp_server_port = data.d3d1_ports[1]
    data.server_d3_port = data.d1d3_ports[1]

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

    data.client_lag = 'PortChannel12'
    data.client_lag_l3 = 'PortChannel13'
    data.iccp_lag = 'PortChannel10'

    data.client_port_ip = ['192.168.0.1','20.20.20.1','192.168.200.1','30.30.30.1']
    data.server_pool = ['192.168.0.','20.20.20.','192.168.200.','30.30.30.']
    data.client_port_ipv6 = ['2092::1','2020::1','2200::1','2030::1']
    data.server_pool_ipv6 = ['2092::','2020::','2200::','2030::']
    data.relay_port = ['Vlan100',data.d2d4_ports[1],'Vlan200',data.client_lag_l3]
    data.client_port = ['Vlan100',data.d4d2_ports[1],'Vlan200',data.client_lag_l3]

    data.d3d1_ports = [vars.D3D1P1,vars.D3D1P2]

    data.d1d5_ports = [vars.D1D5P1]
    data.d5d1_ports = [vars.D5D1P1]
    data.d5d2_ports = [vars.D5D2P1, vars.D5D2P2, vars.D5D2P3]
    data.d2d5_ports = [vars.D2D5P1, vars.D2D5P2, vars.D2D5P3]
    data.d5d4_ports = [vars.D5D4P1, vars.D5D4P2, vars.D5D4P3, vars.D5D4P4]
    data.d4d5_ports = [vars.D4D5P1, vars.D4D5P2, vars.D4D5P3]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3,vars.D2D4P4]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3,vars.D4D2P4]
    #data.dhcp_server_port = dhcp_server_port

    data.client_port_ip_2 = ['192.168.0.1','30.30.30.1']
    data.server_pool_2 = ['192.168.0.','30.30.30.']
    data.client_port_ipv6_2 = ['2092::1','2030::1']
    data.server_pool_ipv6_2 = ['2092::','2030::']
    data.relay_port_2 = ['Vlan100',data.client_lag_l3]
    data.client_port_2 = ['Vlan100',data.client_lag_l3]
    #config_file_path = os.path.join(os.path.dirname(__file__), dhcp_file)
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

def verify_dhcp_statistics(interface,expected=1):

    def f1():
        if expected == 0:
            result1 = check_dhcp_relay_statistics(data.dut2, interface=interface, expected=0)
            result2 = check_dhcp_relay_statistics(data.dut2, interface=interface, family='ipv6', expected=0)
        else:
            result1 = check_dhcp_relay_statistics(data.dut2, interface=interface)
            result2 = check_dhcp_relay_statistics(data.dut2, interface=interface, family='ipv6')
        return result1,result2

    def f2():
        if expected == 0:
            result1 = check_dhcp_relay_statistics(data.dut5, interface=interface, expected=0)
            result2 = check_dhcp_relay_statistics(data.dut5, interface=interface, family='ipv6', expected=0)
        else:
            result1 = check_dhcp_relay_statistics(data.dut5, interface=interface)
            result2 = check_dhcp_relay_statistics(data.dut5, interface=interface, family='ipv6')
        return [result1,result2]
    if 'Vlan' in interface:
        [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    else:
        [result1,result2] = f1()

@pytest.fixture(scope="function")
def dhcp_relay_cleanup_fixture():

    yield
    #################################################
    hdrMsg("ClEANUP.... dhcp_relay_cleanup_fixture")
    #################################################
    client_ip_cleanup()
    killall_dhclient(data.dut4)

def client_ip_cleanup():
    for interface, client_interface in zip(data.relay_port, data.client_port):
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface, skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_interface, family='ipv6', skip_error_check=True)
        if client_interface == data.d4d2_ports[1]:
            if 'ip_add_phy' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface)
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy, '24', skip_error=True)
                del data['ip_add_phy']
            if 'ip_add_phy_v6' in data.keys():
                dhcp_relay.dhcp_client_start(data.dut4, client_interface, family='ipv6')
                ip_api.delete_ip_interface(data.dut4, client_interface, data.ip_add_phy_v6, '64', family="ipv6",
                                           skip_error=True)
                del data['ip_add_phy_v6']
        if 'PortChannel' in client_interface:
            dhcp_relay.dhcp_client_start(data.dut4, client_interface, family='ipv6')
            st.wait(5)
            dhcp_relay.dhcp_client_stop(data.dut4, client_interface, skip_error_check=True, family='ipv6')


def test_dhcp_relay_vxlan_lvtep_001(dhcp_relay_cleanup_fixture):
    tc_list = ['FtOpSoRoDHCPRFt0018','FtOpSoRoDHCPRFt0019','FtOpSoRoDHCPRFt0020']
    tc_result = True ;err_list=[]
    #################################################
    hdrMsg("FtOpSoRoDHCPRFt0018: Overlay dhcp relay functionality with LVTEP ")
    hdrMsg("FtOpSoRoDHCPRFt0019:Overlay dhcp relay functionality with LVTEP & Orphan Clients")
    hdrMsg("FtOpSoRoDHCPRFt0020:Overlay dhcp relay functionality with LVTEP with non default VRF")
    #################################################
    tc_result = True

    for intf,client_intf,ip,pool,pool_v6 in zip(data.relay_port,data.client_port,data.client_port_ip,data.server_pool,data.server_pool_ipv6):

        #################################################
        hdrMsg("Step : Verify dhcp relay configuration under interface {}".format(intf))
        #################################################
        result2 = True
        result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
        if 'Vlan' in intf:
            result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ip)

        if result1 is False or result2 is False:
            err ="DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err)
            st.report_fail('test_case_failure_message', err_list[0])

        result2 = True
        result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')
        if 'Vlan' in intf:
            result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')

        if result1 is False or result2 is False:
            err ="IPv6 DHCP relay interface config incorrect for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err)
            st.report_fail('test_case_failure_message', err_list[0])

        #################################################
        hdrMsg("Step : Start DHCP on client side on all interfaces")
        #################################################
        dhcp_relay.dhcp_client_start(data.dut4, client_intf)
        dhcp_relay.dhcp_client_start(data.dut4, client_intf, family='ipv6')
        st.wait(5)

        #################################################
        hdrMsg("Step : Verify dhcp client assigned ip address on expected subnet on {}".format(intf))
        #################################################
        result = check_dhcp_client(interface=client_intf,network_pool=pool)
        if result is False:
            err ="DHCP client ip address assignment failed for {}".format(intf)
            tc_result=False;err_list.append(err);failMsg(err)
            st.report_fail('test_case_failure_message', err_list[0])

        result = check_dhcp_client(interface=client_intf,network_pool=pool_v6,family='ipv6')

        if result is False:
            err ="IPv6 DHCP client ip address assignment failed for {}".format(client_intf)
            tc_result=False;err_list.append(err);failMsg(err);
            st.report_fail('test_case_failure_message', err)

        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,skip_error_check=True)
        dhcp_relay.dhcp_client_stop(data.dut4, client_intf,family='ipv6',skip_error_check=True)
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

        #################################################
        hdrMsg("Step : Verify dhcp relay statistics on {}" .format(intf))
        #################################################
        verify_dhcp_statistics(interface=intf)

    #################################################
    hdrMsg("Step : Stop all dhcp clients and clear dhcp-relay statistics on all interfaces")
    #################################################
    for interface,client_interface in zip(data.relay_port,data.client_port):
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
        dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")
        if 'Vlan' in interface:
            dhcp_relay.clear_statistics(data.dut5, interface, family="ipv4")
            dhcp_relay.clear_statistics(data.dut5, interface, family="ipv6")
        #################################################
        hdrMsg("Step : Verify dhcp relay statistics reset to 0")
        #################################################
        verify_dhcp_statistics(interface=interface,expected=0)
    killall_dhclient(data.dut4)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')

def sag_unconfig():
    data.sag_mac = "00:00:00:04:01:03"
    # Configure SAG for Vlan100
    def f1():
        intf = 'Vlan100'
        sag_ip = dut2_4_ip_list[0]
        sag_ip6 = dut2_4_ipv6_list[0]

        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf , IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove', family='ipv6')
        sag.config_sag_ip(data.dut2, interface=intf, gateway=sag_ip, mask=mask_24,config='remove')
        sag.config_sag_ip(data.dut2, interface=intf, gateway=sag_ip6, mask=mask_v6,config='remove')
        sag.config_sag_mac(data.dut2, mac=data.sag_mac,config='remove')
        sag.config_sag_mac(data.dut2, config="disable")
        sag.config_sag_mac(data.dut2, ip_type='ipv6', config="disable")
        ip_api.config_ip_addr_interface(data.dut2, intf, dut2_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut2, intf, dut2_4_ipv6_list[0], mask_v6, family="ipv6")
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add', family='ipv6', vrf_name=vrf_name)
        return True


    def f2():
        intf = 'Vlan100'
        sag_ip = dut2_4_ip_list[0]
        sag_ip6 = dut2_4_ipv6_list[0]

        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf , IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove', family='ipv6')
        sag.config_sag_ip(data.dut5, interface=intf, gateway=sag_ip, mask=mask_24,config='remove')
        sag.config_sag_ip(data.dut5, interface=intf, gateway=sag_ip6, mask=mask_v6,config='remove')
        sag.config_sag_mac(data.dut5, mac=data.sag_mac,config='remove')
        sag.config_sag_mac(data.dut5, config="disable")
        sag.config_sag_mac(data.dut5, ip_type='ipv6', config="disable")
        ip_api.config_ip_addr_interface(data.dut5, intf, dut5_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut5, intf, dut5_4_ipv6_list[0], mask_v6, family="ipv6")
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add', family='ipv6', vrf_name=vrf_name)
        return True

    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    killall_dhclient(data.dut4)

    if False in set(res):
        fail_msg = "ERROR:  SAG output error after config."
        hdrMsg(fail_msg)


@pytest.fixture(scope="function")
def dhcp_relay_cleanup_lvtep_002():

    yield
    #################################################
    hdrMsg("ClEANUP....test_dhcp_relay_vxlan_lvtep_002 ")
    #################################################
    client_ip_cleanup()
    killall_dhclient(data.dut4)
    sag_unconfig()

def test_dhcp_relay_vxlan_lvtep_002(dhcp_relay_cleanup_lvtep_002):
    data.sag_mac = "00:00:00:04:01:03"
    tc = "FtOpSoRoDHCPRFt0021"
    tc_result = True ;err_list=[]
    hdrMsg("FtOpSoRoDHCPRFt0021: Overlay dhcp relay functionality with LVTEP with SAG")
    err = ""
    #################################################
    hdrMsg("DHCP Relay with SAG  configured")
    #################################################
    # Configure SAG for Vlan100
    def f1():
        intf = 'Vlan100'
        action = 'add'
        sag_ip = dut2_4_ip_list[0]
        sag_ip6 = dut2_4_ipv6_list[0]

        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf , IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove', family='ipv6')
        ip_api.delete_ip_interface(data.dut2,intf, dut2_4_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut2,intf, dut2_4_ipv6_list[0],mask_v6,family="ipv6")

        sag.config_sag_ip(data.dut2, interface=intf, gateway=sag_ip, mask=mask_24)
        sag.config_sag_ip(data.dut2, interface=intf, gateway=sag_ip6, mask=mask_v6)
        sag.config_sag_mac(data.dut2, mac=data.sag_mac)
        sag.config_sag_mac(data.dut2, config="enable")
        sag.config_sag_mac(data.dut2, ip_type='ipv6', config="enable")
        st.wait(1)
        #ip_api.config_ip_addr_interface(data.dut2, 'Vlan100', dut5_4_ip_list[0], mask_24)
        #ip_api.config_ip_addr_interface(data.dut2, 'Vlan100', dut5_4_ipv6_list[0], mask_v6, family="ipv6")
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ip, vlan=intf, action=action, vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut2, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action=action, family='ipv6', vrf_name=vrf_name)
        res1 = sag.verify_sag(data.dut2)
        res2 = sag.verify_sag(data.dut2, ip_type='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: SAG output error."
            hdrMsg(fail_msg)
            return False
        return True

    def f2():
        intf = 'Vlan100'
        action = 'add'
        sag_ip = dut2_4_ip_list[0]
        sag_ip6 = dut2_4_ipv6_list[0]
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove', family='ipv6')

        ip_api.delete_ip_interface(data.dut5,intf, dut5_4_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut5,intf, dut5_4_ipv6_list[0],mask_v6,family="ipv6")

        sag.config_sag_ip(data.dut5, interface=intf, gateway=sag_ip, mask=mask_24)
        sag.config_sag_ip(data.dut5, interface=intf, gateway=sag_ip6, mask=mask_v6)
        sag.config_sag_mac(data.dut5, mac=data.sag_mac)
        sag.config_sag_mac(data.dut5, config="enable")
        sag.config_sag_mac(data.dut5, ip_type='ipv6', config="enable")

        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ip, vlan=intf, action=action, vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut5, interface= intf, IP=data.dhcp_server_ipv6, vlan=intf, action=action, family='ipv6', vrf_name=vrf_name)
        st.wait(1)
        res1 = sag.verify_sag(data.dut5)
        res2 = sag.verify_sag(data.dut5, ip_type='ipv6')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: SAG output error."
            hdrMsg(fail_msg)
            return False
        return True

    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    if False in set(res):
        err = "ERROR:  SAG output error after config."
        tc_result = False ; failMsg(err);

    st.wait(30, 'Waiting for SAG interface to come up')
    intf = 'Vlan100'
    result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')
    result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')

    if result1 is False or result2 is False:
        err ="DHCP relay interface config incorrect for {}".format(intf)
        tc_result=False;failMsg(err);err_list.append(err)
        st.report_fail('test_case_failure_message',err_list[0])

    result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
    result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ip)

    if result1 is False or result2 is False:
        err ="IPv6 DHCP relay interface config incorrect for {}".format(intf)
        tc_result=False;failMsg(err);err_list.append(err)
        st.report_fail('test_case_failure_message',err_list[0])

    dhcp_relay.dhcp_client_start(data.dut4, intf)
    dhcp_relay.dhcp_client_start(data.dut4, intf, family='ipv6')
    st.wait(5)

    result = check_dhcp_client(interface=intf,network_pool=data.server_pool[0])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(intf)
        tc_result=False;failMsg(err);err_list.append(err)
        st.report_fail('test_case_failure_message',err_list[0])

    result = check_dhcp_client(interface=intf, network_pool=data.server_pool_ipv6[0], family='ipv6')
    if result is False:
        err ="DHCP client ipv6 address assignment failed for {}".format(intf)
        tc_result=False;failMsg(err);err_list.append(err)
        st.report_fail('test_case_failure_message',err)

    dhcp_relay.dhcp_client_stop(data.dut4, intf,skip_error_check=True)
    dhcp_relay.dhcp_client_stop(data.dut4, intf,family='ipv6',skip_error_check=True)

    #############################################################
    hdrMsg("Config Save")
    #############################################################
    bgp_api.enable_docker_routing_config_mode(data.dut2)
    reboot_api.config_save(data.dut2)
    reboot_api.config_save(data.dut2, 'vtysh')
    for trigger in ['mclag_interface_flap1','mclag_interface_flap2','tunnel_flap','reboot']:

        #############################################################
        hdrMsg("Trigger : {}".format(trigger))
        #############################################################
        if trigger == 'reboot' :
            st.reboot(data.dut2, "fast")
            result1 = retry_api(pc.verify_portchannel_state, data.dut2, portchannel=data.iccp_lag)
            result2 = retry_api(pc.verify_portchannel_state, data.dut4, portchannel=data.client_lag)
            result3 = retry_api(pc.verify_portchannel_state, data.dut4, portchannel=data.client_lag_l3)

            if False in [result1, result2, result3]:
                err = "PortChannel not up after reboot"
                tc_result = False;
                err_list.append(err);
                failMsg(err);
                st.report_fail('test_case_failure_message', err_list[0])

        if trigger == 'mclag_interface_flap1':
            int_api.interface_shutdown(data.dut4,data.d4d5_ports[1])
        if trigger == 'mclag_interface_flap2':
            int_api.interface_shutdown(data.dut4, data.d4d2_ports[2])
        if trigger == 'tunnel_flap':
            int_api.interface_shutdown(data.dut3, data.d3d1_ports[0])
            int_api.interface_noshutdown(data.dut3, data.d3d1_ports[0])
            evpn.clear_bgp_evpn(data.dut3, "*")
            st.wait(3)
            result = verify_vxlan()
            if result is False:
                err = "Vxlan tunnel down after link flap between dut3 and dut1"
                tc_result = False;err_list.append(err)
                failMsg(err);
                st.report_fail('test_case_failure_message', err_list[0])

        ###################################################################
        hdrMsg("Step : Start DHCP clients after trigger {} ".format(trigger))
        ###################################################################

        for interface in data.client_port_2:
            dhcp_relay.dhcp_client_start(data.dut4, interface)
            dhcp_relay.dhcp_client_start(data.dut4, interface, family='ipv6')
        st.wait(3)

        for intf,client_intf,ip,pool,pool_v6 in zip(data.relay_port_2,data.client_port_2,data.client_port_ip_2,data.server_pool_2,data.server_pool_ipv6_2):

            if trigger == 'reboot':

                #################################################
                hdrMsg("Step : Verify dhcp relay configuration under interface after reboot {}".format(intf))
                #################################################
                result1 = check_dhcp_relay_interface_config(data.dut2, interface=intf, server_ip=data.dhcp_server_ip)
                result2 = check_dhcp_relay_interface_config(data.dut5, interface=intf, server_ip=data.dhcp_server_ip)

                if result1 is False or result2 is False:
                    err = "DHCP relay interface config incorrect for {} after trigger - {}".format(intf,trigger)
                    tc_result = False;err_list.append(err);  failMsg(err);
                    st.report_fail('test_case_failure_message', err_list[0])

                result1 = check_dhcp_relay_interface_config(data.dut2, interface=intf, server_ip=data.dhcp_server_ipv6,family='ipv6')
                result2 = check_dhcp_relay_interface_config(data.dut5, interface=intf, server_ip=data.dhcp_server_ipv6,family='ipv6')

                if result1 is False or result2 is False:
                    err = "IPv6 DHCP relay interface config incorrect for {} after trigger - {}".format(intf,trigger)
                    tc_result = False;err_list.append(err)
                    failMsg(err);
                    st.report_fail('test_case_failure_message', err_list[0])
                st.wait(5)

            #################################################
            hdrMsg("Step : Verify dhcp client assigned ip address on expected subnet on {} after trigger - {}".format(intf,trigger))
            #################################################
            result = check_dhcp_client(interface=client_intf, network_pool=pool)

            if result is False:
                err = "DHCP client ip address assignment failed for {} after trigger - {}".format(intf,trigger)
                tc_result = False;err_list.append(err); failMsg(err);
                st.report_fail('test_case_failure_message', err_list[0])

            result = check_dhcp_client(interface=client_intf, network_pool=pool_v6, family='ipv6')

            if result is False:
                err = "IPv6 DHCP client ip address assignment failed for {} after trigger - {}".format(client_intf,trigger)
                failMsg(err);err_list.append(err)
                st.report_fail('test_case_failure_message', err)

            #################################################
            hdrMsg("Step : Verify dhcp relay statistics on {}".format(intf))
            #################################################
            verify_dhcp_statistics(interface=intf)

            if trigger == 'mclag_interface_flap1':
                int_api.interface_noshutdown(data.dut4,data.d4d5_ports[1])
            if trigger == 'mclag_interface_flap2':
                int_api.interface_noshutdown(data.dut4, data.d4d2_ports[2])
        for interface in data.client_port_2:
            dhcp_relay.dhcp_client_stop(data.dut4, interface, skip_error_check=True)
            dhcp_relay.dhcp_client_stop(data.dut4, interface, family='ipv6', skip_error_check=True)
        #client_ip_cleanup()

        for interface,client_interface in zip(data.relay_port,data.client_port):
            dhcp_relay.clear_statistics(data.dut2, interface, family="ipv4")
            dhcp_relay.clear_statistics(data.dut2, interface, family="ipv6")
            if 'Vlan' in interface:
                dhcp_relay.clear_statistics(data.dut5, interface, family="ipv4")
                dhcp_relay.clear_statistics(data.dut5, interface, family="ipv6")
        killall_dhclient(data.dut4)

    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')


def uniqueIP_unconfig():
    data.sag_mac = "00:00:00:04:01:03"

    def f1():
        intf = 'Vlan100'
        ip4 = dut2_4_ip_list[0]
        ip6 = dut2_4_ipv6_list[0]

        # Unconfig DHCP for mclag vlan
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove',
                                     family='ipv6')

        ip_api.delete_ip_interface(data.dut2, intf, ip4, mask_24)
        ip_api.delete_ip_interface(data.dut2, intf, ip6, mask_v6, family="ipv6")
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, skip_error='True',config = 'no')

        # Unconfig IP - Vlan100
        mclag.config_uniqueip(data.dut2, op_type='del', vlan=intf)
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, skip_error='True')

        # Configure different ip on both lvtep nodes on vlan100
        ip_api.config_ip_addr_interface(data.dut2, intf, ip4, mask_24)
        ip_api.config_ip_addr_interface(data.dut2, intf, ip6, mask_v6, family="ipv6")

        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add',
                                     family='ipv6', vrf_name=vrf_name)

    def f2():
        intf = 'Vlan100'
        ip4 = dut5_4_ip_list[0]
        ip6 = dut5_4_ipv6_list[0]
        # Unconfig DHCP for mclag vlan
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove',
                                     family='ipv6')

        ip_api.delete_ip_interface(data.dut5, intf, ip4, mask_24)
        ip_api.delete_ip_interface(data.dut5, intf, ip6, mask_v6, family="ipv6")
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, skip_error='True',config = 'no')

        # Unconfig IP - Vlan100
        mclag.config_uniqueip(data.dut5, op_type='del', vlan=intf)

        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, skip_error='True')
        # Configure different ip on both lvtep nodes on vlan100
        ip_api.config_ip_addr_interface(data.dut5, intf, ip4, mask_24)
        ip_api.config_ip_addr_interface(data.dut5, intf, ip6, mask_v6, family="ipv6")

        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add',
                                     family='ipv6', vrf_name=vrf_name)

    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    killall_dhclient(data.dut4)

    if False in set(res):
        fail_msg = "ERROR:  SAG output error after config."
        hdrMsg(fail_msg)

def test_dhcp_relay_vxlan_lvtep_003():
    data.sag_mac = "00:00:00:04:01:03"
    tc = "FtOpSoRoDHCPRFt0022"
    tc_result = True ;err_list=[]
    hdrMsg("FtOpSoRoDHCPRFt0022: Overlay dhcp relay functionality with LVTEP with Unique IP")

    #################################################
    hdrMsg("Testcase : DHCP Relay with Unique IP configured")
    #################################################

    # Configure Unique IP for Vlan100

    def f1():
        intf = 'Vlan100'
        ip4 = data.server_pool[0] + '2'
        ip6 = data.server_pool_ipv6[0] + '2'

        # Unconfig DHCP for mclag vlan
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove', family='ipv6')

        # Configure different ip on both lvtep nodes on vlan100
        ip_api.delete_ip_interface(data.dut2, intf, dut2_4_ip_list[0], mask_24)
        ip_api.delete_ip_interface(data.dut2, intf, dut2_4_ipv6_list[0], mask_v6, family="ipv6")
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, skip_error='True',config = 'no')

        # Unconfig IP - Vlan100
        mclag.config_uniqueip(data.dut2, op_type='add', vlan=intf)
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, skip_error='True')

        # Configure different ip on both lvtep nodes on vlan100
        #ip_api.config_ip_addr_interface(data.dut2, intf, ip4, mask_24)
        #ip_api.config_ip_addr_interface(data.dut2, intf, ip6, mask_v6, family="ipv6")
        ip_api.config_ip_addr_interface(data.dut2, intf, dut2_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut2, intf, dut2_4_ipv6_list[0], mask_v6, family="ipv6")
        # Configure Unique IP
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut2, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add', family='ipv6', vrf_name=vrf_name)

        return True

    def f2():

        intf = 'Vlan100'
        ip4 = data.server_pool[0] + '3'
        ip6 = data.server_pool_ipv6[0] + '3'

        # Unconfig DHCP for mclag vlan
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='remove')
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='remove',
                                     family='ipv6')

        # Configure different ip on both lvtep nodes on vlan100
        ip_api.delete_ip_interface(data.dut5, intf, dut5_4_ip_list[0], mask_24)
        ip_api.delete_ip_interface(data.dut5, intf, dut5_4_ipv6_list[0], mask_v6, family="ipv6")
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, skip_error='True',config = 'no')

        # Unconfig IP - Vlan100
        mclag.config_uniqueip(data.dut5, op_type='add', vlan=intf)
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, skip_error='True')

        # Configure different ip on both lvtep nodes on vlan100
        #ip_api.config_ip_addr_interface(data.dut5, intf, ip4, mask_24)
        #ip_api.config_ip_addr_interface(data.dut5, intf, ip6, mask_v6, family="ipv6")
        ip_api.config_ip_addr_interface(data.dut5, intf, dut5_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut5, intf, dut5_4_ipv6_list[0], mask_v6, family="ipv6")
        # Configure Unique IP
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ip, vlan=intf, action='add', vrf_name=vrf_name)
        dhcp_relay.dhcp_relay_config(data.dut5, interface=intf, IP=data.dhcp_server_ipv6, vlan=intf, action='add', family='ipv6', vrf_name=vrf_name)
        return True
    #################################################
    hdrMsg("Configure unique IP on both the lvteps.")
    #################################################

    [res, exceptions] = utils.exec_all(True, [[f1], [f2]])
    if False in set(res):
        err = "ERROR:  SAG output error after config."
        tc_result = False;err_list.append(err);uniqueIP_unconfig()
        st.report_fail('test_case_failure_message',err)
    st.wait(30, 'Waiting for SAG interface to come up')

    intf = 'Vlan100'
    result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')
    result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ipv6,family='ipv6')

    if result1 is False or result2 is False:
        err ="DHCP relay interface config incorrect for {}".format(intf)
        tc_result=False;err_list.append(err);failMsg(err);uniqueIP_unconfig()
        st.report_fail('test_case_failure_message',err)
    result1 = check_dhcp_relay_interface_config(data.dut2,interface=intf,server_ip=data.dhcp_server_ip)
    result2 = check_dhcp_relay_interface_config(data.dut5,interface=intf,server_ip=data.dhcp_server_ip)

    if result1 is False or result2 is False:
        err ="IPv6 DHCP relay interface config incorrect for {}".format(intf)
        tc_result=False;err_list.append(err);failMsg(err);uniqueIP_unconfig()
        st.report_fail('test_case_failure_message',err)
    dhcp_relay.dhcp_client_start(data.dut4, intf)
    dhcp_relay.dhcp_client_start(data.dut4, intf, family='ipv6')
    st.wait(5)

    result = check_dhcp_client(interface=intf,network_pool=data.server_pool[0])
    if result is False:
        err ="DHCP client ip address assignment failed for {}".format(intf);err_list.append(err)
        tc_result=False;failMsg(err)

    result = check_dhcp_client(interface=intf, network_pool=data.server_pool_ipv6[0], family='ipv6')
    if result is False:
        err ="DHCP client ipv6 address assignment failed for {}".format(intf);err_list.append(err)
        tc_result=False;failMsg(err)

    dhcp_relay.dhcp_client_stop(data.dut4, intf,skip_error_check=True)
    dhcp_relay.dhcp_client_stop(data.dut4, intf,family='ipv6',skip_error_check=True)
    uniqueIP_unconfig()
    if tc_result is False:
        st.report_fail('test_case_failure_message',err_list[0])
    else:
        st.report_pass('test_case_passed')
