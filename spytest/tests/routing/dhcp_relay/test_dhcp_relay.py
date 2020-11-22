import pytest
from spytest import st, tgapi
from spytest.utils import poll_wait, random_vlan_list
import utilities.utils as utils
from utilities.common import exec_foreach
from dhcp_relay_vars import data
import apis.routing.ip as ip
from apis.switching.vlan import config_vlan_range, config_vlan_range_members, create_vlan_and_add_members, delete_vlan, delete_vlan_member, create_vlan, add_vlan_member
from apis.switching.portchannel import get_portchannel_list, get_portchannel, clear_portchannel_configuration, create_portchannel, add_del_portchannel_member
import apis.routing.dhcp_relay as dhcp_relay
from apis.routing.arp import show_arp, show_ndp
import apis.system.interface as interface
from apis.routing.vrf import config_vrf, bind_vrf_interface
from apis.system.basic import dhcp_server_config, get_content_file_number, write_content_to_line_number, delete_content_from_line_number, verify_free_memory, get_ifconfig_inet, get_ifconfig_inet6
import os
from apis.system.switch_configuration import write_config_db
from apis.qos.copp import bind_class_action_copp_policy


functions_vrf = ["test_dhcp_relay_functionality_vlan_vrf",
                 "test_dhcp_relay_functionality_phy_intf_vrf",
                 "test_dhcp_relay_functionality_portchannel_vrf",
                 "test_dhcpv6_relay_functionality_vlan_vrf",
                 "test_dhcpv6_relay_functionality_phy_intf_vrf",
                 "test_dhcpv6_relay_functionality_portchannel_vrf"]

def initialize_variables():
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D2D3:2", "D1T1:2")
    global tg_handler, tg1, tg2, tg_ph_1, tg_ph_2
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D1P2])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.vlan = 10
    data.vlan_int = "Vlan{}".format(data.vlan)
    data.client_vlan = random_vlan_list(count=1, exclude=[data.vlan])[0]
    data.client_vlan_intf = "Vlan{}".format(data.client_vlan)
    data.routing_int = vars.D2D3P1
    data.portchannel = "PortChannel101"
    data.dhcp_service_name = "isc-dhcp-server"
    data.RA_ipaddress_1 = '176.16.40.1'
    data.RA_ipaddress_2 = '192.168.0.2'
    data.RA_ipaddress_21 = '192.168.0.2/24'
    data.subnet = '24'
    data.RA_ipv6address = "2072::1"
    data.RA_ipv6_address_2 = "2092::22"
    data.RA_ipv6_address_2_subnet = 64
    data.ip6_addr_mask = '64'
    data.af_ipv4 = "ipv4"
    data.af_ipv6 = "ipv6"
    data.pool_ip_address = "192.168.2"
    data.vrf_name = "Vrf-RELAY"
    data.intf_list1 = [vars.D2D3P1, data.vlan_int, data.portchannel]
    data.intf_list2 = [vars.D3D2P1, data.vlan_int, data.portchannel]
    data.wait_time_to_no_shut = 10
    data.dhcp_relay_params = vars.D2D1P1
    data.dhcp_server_ip = '176.16.40.210'
    data.dhcp_v6server_ip = '2072::210'
    data.my_dut_list = st.get_dut_names()
    data.dhcp_renew_check_timer = 80
    data.dhcp_files = ['isc-dhcp-server', 'dhcpd.conf', 'dhcpd6.conf']
    data.dhcp_files_path =  [os.path.join(os.path.dirname(__file__),data.dhcp_files[0]),os.path.join(os.path.dirname(__file__),data.dhcp_files[1]),os.path.join(os.path.dirname(__file__),data.dhcp_files[2])]
    data.dhcp_files_path =  []
    for file in data.dhcp_files: data.dhcp_files_path.append(os.path.join(os.path.dirname(__file__),file))
    data.username = 'admin'
    data.route_list = ['192.168.0.0/24', '100.100.100.0/24', '200.200.200.0/24', '11.11.11.0/24', '110.110.110.0/24']
    data.route_list_6 = ['2092::0/64']


@pytest.fixture(scope="module", autouse=True)
def dhcp_relay_module_config(request):
    initialize_variables()
    bind_class_action_copp_policy(vars.D3, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp')
    router_ip_address = data.RA_ipaddress_2.split(".")
    router_ip_address[3] = "1"
    dhcp_conf_line = r"\s*option routers {};$".format(".".join(router_ip_address))
    line_number = get_content_file_number(data.dhcp_files_path[1], dhcp_conf_line)
    if line_number:
        write_content_to_line_number(data.dhcp_files_path[1], r"\    \max-lease-time 60;", line_number+1)
    st.log("DATA --- {}".format(data))
    response = dhcp_server_config(vars.D1, dhcp_files_path=data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=data.dhcp_server_ip, server_ipv6=data.dhcp_v6server_ip,
                       route_list=data.route_list, route_list_v6=data.route_list_6, ipv4_relay_agent_ip=data.RA_ipaddress_1, ipv6_relay_agent_ip=data.RA_ipv6address)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "installation", "failed")
    if line_number:
        delete_content_from_line_number(data.dhcp_files_path[1], line_number+1)
    #config IPv4 address to connected interface of DHCP server and check reachability
    connected_port_ip_address_config("ipv4")
    #config IPv6 address to connected interface of DHCP server and check reachability
    connected_port_ip_address_config("ipv6")
    # if not poll_for_interface_status(vars.D2, data.dhcp_relay_params, "oper", "up", iteration=5, delay=1):
    #     interface_operation(vars.D2, data.dhcp_relay_params, operation="startup", skip_verify=True)
    if not ip.ping(vars.D2, data.dhcp_server_ip):
        st.log("Pinging to DHCP server failed from DUT, issue either with DUT or server")
        st.report_fail("ping_fail", data.dhcp_server_ip)
    #IPV6 interface status and check the ping status
    if not ip.ping(vars.D2, data.dhcp_v6server_ip, family=data.af_ipv6):
        st.log("Pinging to DHCPv6 server failed from DUT, issue either with DUT or server")
        st.report_fail("ping_fail", data.dhcp_v6server_ip)
    basic_dhcp_relay_config_addition()
    yield
    response = dhcp_server_config(vars.D1, action="unconfig", dhcp_files_path=data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=data.dhcp_server_ip, server_ipv6=data.dhcp_v6server_ip,
                       route_list=data.route_list, route_list_v6=data.route_list_6, ipv4_relay_agent_ip=data.RA_ipaddress_1, ipv6_relay_agent_ip=data.RA_ipv6address)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "uninstallation", "failed")
    dhcp_relay_cleanup_config()


@pytest.fixture(scope="function", autouse=True)
def dhcp_relay_func_hooks(request):
    add_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
    if st.get_func_name(request) in ["test_dhcp_relay_functionality_portchannel", "test_dhcpv6_relay_functionality_portchannel",
                                     "test_dhcp_relay_functionality_portchannel_vrf","test_dhcpv6_relay_functionality_portchannel_vrf"]:
        add_vlan_member(vars.D3, data.vlan, vars.D3D2P2)
    yield
    # Function cleanup
    if st.get_func_name(request) in ["test_dhcp_relay_functionality", "test_dhcp_relay_shut_noshut",
                                      "test_dhcp_relay_ip_address_config_remove_add", "test_dhcp_relay_statistics"]:
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
    elif st.get_func_name(request) == "test_dhcp_relay_lease_time_renew":
        dhcp_relay_vlan_config_clean()
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
    elif st.get_func_name(request) == "test_dhcp_relay_functionality_physical_interface":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        unconfig_dhcp_relay(vars.D2, data.routing_int)
        st.log("IPv4 config cleanup")
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4,
                                    config='remove')
    elif st.get_func_name(request) == "test_dhcp_relay_functionality_portchannel":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, [vars.D3D2P1, vars.D3D2P2])
        unconfig_dhcp_relay(vars.D2, data.portchannel)
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4,
                                    config='remove')
        ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipaddress_1, data.subnet,
                                    family=data.af_ipv4, config='remove')
        clear_portchannel_configuration(vars.D2)
    elif st.get_func_name(request) == "test_dhcpv6_relay_functionality":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        dhcp_relay_vlan_config_clean("ipv6")
    elif st.get_func_name(request) == 'test_dhcpv6_relay_functionality_physical_interface':
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        unconfig_dhcp_relay(vars.D2, data.routing_int, ip_addr=data.dhcp_v6server_ip, family="ipv6")
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='remove')
    elif st.get_func_name(request) == 'test_dhcpv6_relay_functionality_portchannel':
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, [vars.D3D2P1, vars.D3D2P2])
        unconfig_dhcp_relay(vars.D2, data.portchannel, ip_addr=data.dhcp_v6server_ip, family="ipv6")
        ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'disable')
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='remove')
        ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipv6address, data.ip6_addr_mask,
                                    family=data.af_ipv6, config='remove')
        clear_portchannel_configuration(vars.D2)
    elif st.get_func_name(request) == "test_dhcp_relay_functionality_vlan_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=data.vlan_int, IP=data.dhcp_server_ip, skip_error_check=True, vrf_name=data.vrf_name)
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4,
                                    config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.vlan1, vrf_name=data.vrf_name, config='no', skip_error=False)
        delete_vlan_member(vars.D2, data.vlan, [vars.D2D3P1], skip_error_check=True)
    elif st.get_func_name(request) == "test_dhcp_relay_functionality_phy_intf_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True, show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        unconfig_dhcp_relay(vars.D2, data.routing_int, vrf_name=data.vrf_name)
        st.log("IPv4 config cleanup")
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipaddress_2, data.subnet,
                                    family=data.af_ipv4, config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.routing_int, vrf_name=data.vrf_name, config='no', skip_error=False)
    elif st.get_func_name(request) == "test_dhcp_relay_functionality_portchannel_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv4", skip_error_check=True,
                                    show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, [vars.D3D2P1, vars.D3D2P2])
        unconfig_dhcp_relay(vars.D2, data.portchannel, vrf_name=data.vrf_name)
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipaddress_2, data.subnet,
                                    family=data.af_ipv4,
                                    config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.portchannel, vrf_name=data.vrf_name, config='no', skip_error=False)
        st.log("Removing configurations")
        clear_portchannel_configuration(vars.D2)
    elif st.get_func_name(request) == "test_dhcpv6_relay_functionality_vlan_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True,
                                    show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        st.log("Removing VRF configuration")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=data.vlan1, IP=data.dhcp_v6server_ip, family="ipv6",
                                            skip_error_check=True, vrf_name=data.vrf_name)
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.vlan1, vrf_name=data.vrf_name, config='no', skip_error=False)
        delete_vlan_member(vars.D2, data.vlan, [vars.D2D3P1], skip_error_check=True)
        delete_vlan(vars.D2, [data.vlan])
    elif st.get_func_name(request) == "test_dhcpv6_relay_functionality_phy_intf_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True,
                                    show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)
        dhcp_relay.dhcp_relay_config_remove(vars.D2, interface=data.routing_int, IP=data.dhcp_v6server_ip,
                                            family="ipv6",
                                            skip_error_check=True, vrf_name=data.vrf_name)
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.routing_int, vrf_name=data.vrf_name, config='no', skip_error=False)
    elif st.get_func_name(request) == "test_dhcpv6_relay_functionality_portchannel_vrf":
        dhcp_relay.dhcp_client_stop(vars.D3, data.vlan_int, family="ipv6", skip_error_check=True,
                                    show_interface=True)
        delete_vlan_member(vars.D3, data.vlan, [vars.D3D2P1, vars.D3D2P2])
        unconfig_dhcp_relay(vars.D2, data.portchannel, ip_addr=data.dhcp_v6server_ip, family="ipv6", vrf_name=data.vrf_name)
        st.log("Removing configurations")
        ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'disable')
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='remove')
        bind_vrf_interface(vars.D2, intf_name=data.portchannel, vrf_name=data.vrf_name, config='no', skip_error=False)
        ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipv6address, data.ip6_addr_mask,
                                    family=data.af_ipv6, config='remove')
        config_vrf(vars.D2, vrf_name=data.vrf_name, config='no', skip_error=True)
        clear_portchannel_configuration([vars.D2])
    elif st.get_func_name(request) == "test_dhcp_relay_single_vlan_multi_server":
        vlan_1 = 100
        vlan_11 = "Vlan{}".format(vlan_1)
        RA_ipaddress_3 = '192.168.3.10'
        RA_ipaddr_mask_3 = '192.168.3.10/24'
        dhcp_server1_ip = '2.2.2.2'
        dhcp_server2_ip = '3.3.3.3'
        st.log("config clean up")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_11, IP=dhcp_server1_ip)
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_11, IP=dhcp_server2_ip)
        ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='remove')
        delete_vlan_member(vars.D2, vlan_1, [vars.D2D3P1], tagging_mode=True)
        delete_vlan(vars.D2, [vlan_1])
    elif st.get_func_name(request) == "test_dhcp_relay_statistics":
        delete_vlan_member(vars.D3, data.vlan, vars.D3D2P1)

def basic_dhcp_relay_config_addition():
    data.vlan1 = "Vlan{}".format(data.vlan)
    st.log("Create VLAN and participate client connected interface in vlan")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": data.vlan, "untagged": [vars.D2D3P1]}])
    create_vlan(vars.D3, data.vlan)


def dhcp_relay_cleanup_config():
    st.log("Cleanup DHCP Relay configurations")
    ip.clear_ip_configuration([vars.D2, vars.D3])
    ip.clear_ip_configuration([vars.D2, vars.D3], 'ipv6', skip_error_check=True)
    ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'disable')
    clear_portchannel_configuration(data.my_dut_list)


def connected_port_ip_address_config(family="ipv4"):
    if family == "ipv4":
        st.log("About to add IP address on port connected to DHCP server")
        ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipaddress_1, data.subnet,
                                        family=data.af_ipv4, config='add')
    else:
        st.log("About to add IPv6 address on port connected to DHCP server")
        ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipv6address, data.ip6_addr_mask,
                                 family=data.af_ipv6, config='add')


def dhcp_relay_vlan_config(family="ipv4", vrf_name=None):
    data.vlan1 = "Vlan{}".format(data.vlan)
    if family == "ipv4":
        st.log("About to add IP address in RA DUT")
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4, config='add')
        st.log("Add DHCP server address to vlan")
        if not vrf_name:
            dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.dhcp_server_ip)
        else:
            dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.dhcp_server_ip, vrf_name=vrf_name)
    else:
        st.log("Enable link-local address on DHCP client")
        ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'enable')
        st.log("About to add IPv6 address in RA DUT")
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet, family=data.af_ipv6, config='add')
        st.log("Add DHCPv6 server address to vlan")
        if not vrf_name:
            dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.dhcp_v6server_ip, family="ipv6")
        else:
            dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.dhcp_v6server_ip, family="ipv6", vrf_name=vrf_name)

def dhcp_relay_vlan_config_clean(family="ipv4"):
    st.log("vlan config clean up")
    if family == "ipv4":
        st.log("About to remove IPv4 address in RA DUT")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=data.vlan_int, IP= data.dhcp_server_ip, skip_error_check=True)
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4, config='remove')
    else:
        st.log("About to remove IPv6 address in RA DUT")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=data.vlan_int, IP= data.dhcp_v6server_ip, family="ipv6", skip_error_check=True)
        ip.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet, family=data.af_ipv6, config='remove')
    try:
        delete_vlan_member(vars.D2, data.vlan, [vars.D2D3P1], skip_error_check=True)
        delete_vlan(vars.D2, [data.vlan])
    except Exception:
        st.log("VLAN already deleted")


def dhcp_relay_interface_config(family="ipv4", vrf_name=None):
    if family == "ipv4":
        st.log("About to add IP address in RA DUT")
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4, config='add')
        st.log("Add DHCP server address to Physical interface")
        if not vrf_name:
            dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.routing_int, IP=data.dhcp_server_ip)
        else:
            dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.routing_int, IP=data.dhcp_server_ip, vrf_name=vrf_name)
    else:
        st.log("Enable link-local address on DHCP client")
        ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'enable')
        st.log("About to add IPv6 address in RA DUT")
        ip.config_ip_addr_interface(vars.D2, data.routing_int, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='add')
        st.log("DHCPv6 relay config for Routing interface");
        if not vrf_name:
            dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.routing_int, IP=data.dhcp_v6server_ip, family="ipv6")
        else:
            dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.routing_int, IP=data.dhcp_v6server_ip,
                                             family="ipv6", vrf_name=vrf_name)


def dhcp_relay_portchannel_config(family="ipv4"):
    st.log("Create port-channel and participate client connected interface in that group")
    if not (get_portchannel(vars.D2, data.portchannel) and get_portchannel(vars.D3, data.portchannel)):
        st.log("Port Channel config")
        try:
            create_portchannel(vars.D2, [data.portchannel], static=True)
            add_del_portchannel_member(vars.D2, data.portchannel, vars.D2D3P2, flag="add", skip_verify=True,
                                       skip_err_check=False)
        except Exception:
            st.log("portchannel already exist")

    if family == "ipv4":
        st.log("About to add IP address in portchannel for RA DUT")
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4)
        st.log("Add DHCP server address to portchannel interface")
        dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.portchannel, IP=data.dhcp_server_ip)
    else:
        st.log("Enable link-local address on DHCP client")
        ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'enable')
        st.log("Enable Global IPv6 address on DHCP Helper")
        ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                    family=data.af_ipv6, config='add')
        st.log("Configure IPv6 DHCP relay address on an portchannel")
        dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.portchannel, IP=data.dhcp_v6server_ip, family="ipv6")


def check_dhcp_relay_config(family="ipv4"):
    if not dhcp_relay.verify_dhcp_relay(vars.D2, "Vlan{}".format(data.vlan), data.dhcp_server_ip, family=family):
    # if not verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                                   dhcp_helper_add=data.dhcp_server_ip):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan))
        st.report_fail("IP_Helper_address_config_failed", vars.D2)


def check_dhcp_relay_interface_config(int_type="physical"):
    if int_type == "physical":
        if not dhcp_relay.verify_dhcp_relay(vars.D2, data.routing_int, data.dhcp_server_ip,
                                            family="ipv4"):
            dhcp_relay_debug(vars.D2, interface=data.routing_int)
            st.report_fail("IP_Helper_address_config_failed", vars.D2)
    else:
        if not dhcp_relay.verify_dhcp_relay(vars.D2, data.portchannel, data.dhcp_server_ip,
                                            family="ipv4"):
            dhcp_relay_debug(vars.D2, interface=data.portchannel)
            st.report_fail("IP_Helper_address_config_failed", vars.D2)


def verify_dhcp_client(dut, interface_name, ip_ad="", network="", family =""):
    ip_ad = data.RA_ipaddress_2 if not ip_ad else ip_ad
    network = data.subnet if not network else network
    family = "ipv4" if not family else family
    client_ip = None
    try:
        if family == "ipv4":
            ip_details = get_ifconfig_inet(dut, interface_name)
            if ip_details:
                client_ip = ip_details[0].strip()
        elif family == "ipv6":
            ip_details = get_ifconfig_inet6(dut, interface_name)
            if ip_details:
                if len(ip_details) > 1:
                    if not ip_details[1].startswith("fe"):
                        client_ip = ip_details[1].strip()
                    else:
                        client_ip = ip_details[0].strip()
                else:
                    client_ip = ip_details[0].strip()
        else:
            st.log("Unsupported family .. {}".format(family))
            return False
    except Exception as e:
        st.log(e)
        st.error("DHCP client failed to get the IP address on {}".format(dut))
        return False
    if not client_ip:
        st.log("No Client IP found")
        return False
    client_ip = client_ip.split("/")
    st.log("OFFERED IP {}".format(client_ip[0]))
    if family == "ipv6":
        client_ip = client_ip[0].split("%")
    if not utils.verify_ip4_ip6_in_subnetwork(client_ip[0], "{}/{}".format(ip_ad, network)):
        st.log("DHCP Client failed to get the ip4/6 address from the configured pool")
        return False
    return True


def unconfig_dhcp_relay(dut, interface, ip_addr="", cli_type="", action="remove", family="ipv4", vrf_name=None):
    ip_addr = data.dhcp_server_ip if not ip_addr else ip_addr
    interface = vars.D2D3P1 if not interface else interface
    ip_address = data.dhcp_server_ip if not ip_addr else ip_addr
    kwargs = {"action": action, "interface": interface,
              "IP": ip_address, "family":family}
    if vrf_name:
        kwargs.update({"vrf_name":vrf_name})
    dhcp_relay.dhcp_relay_config(dut, **kwargs)


def check_dhcp_relay_statistics(int_type = "vlan", family = "ipv4"):
    if int_type == "physical":
        stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2,interface = data.routing_int,
                                 family = family)
    elif int_type == "portchannel":
        stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2,interface = data.portchannel,
                                 family = family)
    else:
        stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2,interface = data.vlan_int, family = family)
    pkts_relayed_server_to_client = stats[0]["dhcp_offer_msgs_sent_by_the_relay_agent"]
    if  int(pkts_relayed_server_to_client) == int(0) :
        st.report_fail("packets_relayed_from_server_to_client_statistics_not_incremented")
    pkts_relayed_client_to_server = stats[0]["bootrequest_msgs_forwarded_by_the_relay_agent"]
    if int(pkts_relayed_client_to_server) == int(0):
        st.report_fail("packets_relayed_from_client_to_server_statistics_not_incremented")

def dhcp_relay_debug(dut, family = "ip", interface=None):
    family = "ipv4" if not family else family
    st.banner("Start of Collecting the needed info for debugging the failure")
    try:
        get_portchannel_list(dut)
        interface.interface_status_show(dut)
        dhcp_relay.dhcp_relay_detailed_show(dut)
        dhcp_relay.get_dhcp_relay_statistics(dut, interface=interface)
        ip.get_interface_ip_address(dut)
        show_arp(dut)
        if family == "ipv6":
            dhcp_relay.dhcp_relay_detailed_show(dut, family = "ipv6")
            dhcp_relay.get_dhcp_relay_statistics(dut, family = "ipv6", interface=interface)
            ip.get_interface_ip_address(dut, family ="ipv6")
            show_ndp(dut)
    except Exception as e:
        st.log(e)
        st.error("Failed to execute the debug commands")
    st.banner("End of Collecting the needed info for debugging the failure")

@pytest.mark.regression
@pytest.mark.dhcp_server_relay
def test_dhcp_relay_functionality():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the client is assigned DHCP IP address from server.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on Vlan routing interface,where server and client connected ports are in default VRF domain.")
    dhcp_relay_vlan_config()
    st.log("About to verify dhcp relay configuration")
    check_dhcp_relay_config()
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan1))
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.log("About to verify DHCP Relay statistics in dhcp client")
    check_dhcp_relay_statistics("vlan", "ipv4")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_shut_noshut():
    #################################################
    #
    # Objective - Configure DHCP relay on a Vlan and verify if the client is assigned DHCP IP after shut/no-shut of client connected port.
    #
    #################################################
    st.log("Shutdown the relay interface link.")
    if not interface.interface_operation(vars.D2, vars.D2D3P1, "shutdown"):
        st.report_fail('interface_admin_shut_down_fail', vars.D2D3P1)
    st.wait(data.wait_time_to_no_shut)
    interface.interface_operation(vars.D2, vars.D2D3P1, 'startup')
    st.wait(data.wait_time_to_no_shut)
    check_dhcp_relay_config()
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan1))
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_multi_vlan_multi_server():
    #################################################
    #
    # Objective - Configure DHCP relay on two Vlans and with different DHCP servers each and verify the configuration.
    #
    #################################################
    vlan_1 = 100
    vlan_11 = "Vlan{}".format(vlan_1)
    vlan_2 = 200
    vlan_22 = "Vlan{}".format(vlan_2)
    RA_ipaddress_3 = '192.168.3.10'
    RA_ipaddress_4 = '192.168.4.10'
    RA_ipaddr_mask_3 = '192.168.3.10/24'
    RA_ipaddr_mask_4 = '192.168.4.10/24'
    dhcp_server1_ip = '2.2.2.2'
    dhcp_server2_ip = '3.3.3.3'

    st.log("About to create non default vlans ")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": vlan_1, "tagged": [vars.D2D3P1]}])
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": vlan_2, "tagged": [vars.D2D3P1]}])

    st.log("About to config different dhcp servers as IP helper addresses ")
    ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='add')
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_11, IP=dhcp_server1_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_22, RA_ipaddress_4, data.subnet, family=data.af_ipv4, config='add')
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_22, IP=dhcp_server2_ip)

    st.log("About to verify dhcp relay config")
    if not dhcp_relay.verify_dhcp_relay(vars.D2, "Vlan{}".format(vlan_1), dhcp_server1_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_1, ip_address=RA_ipaddr_mask_3, dhcp_helper_add=dhcp_server1_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)
    if not dhcp_relay.verify_dhcp_relay(vars.D2, "Vlan{}".format(vlan_2), dhcp_server2_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_2, ip_address=RA_ipaddr_mask_4, dhcp_helper_add=dhcp_server2_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)

    st.log("config clean up")
    dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_11, IP=dhcp_server1_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='remove')
    delete_vlan_member(vars.D2, vlan_1, [vars.D2D3P1], tagging_mode=True)
    dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_22, IP=dhcp_server2_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_22, RA_ipaddress_4, data.subnet, family=data.af_ipv4, config='remove')
    delete_vlan_member(vars.D2, vlan_2, [vars.D2D3P1], tagging_mode=True)
    delete_vlan(vars.D2, [vlan_1,vlan_2])
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_multi_vlan_single_server():
    #################################################
    #
    # Objective - Configure DHCP relay on two Vlans and with same DHCP server and verify the configuration.
    #
    #################################################

    vlan_1 = 100
    vlan_11 = "Vlan{}".format(vlan_1)
    vlan_2 = 200
    vlan_22 = "Vlan{}".format(vlan_2)
    RA_ipaddress_3 = '192.168.3.10'
    RA_ipaddress_4 = '192.168.4.10'
    RA_ipaddr_mask_3 = '192.168.3.10/24'
    RA_ipaddr_mask_4 = '192.168.4.10/24'
    dhcp_server1_ip = '2.2.2.2'

    st.log("About to create non default vlans ")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": vlan_1, "tagged": [vars.D2D3P1]}])
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": vlan_2, "tagged": [vars.D2D3P1]}])

    st.log("About to config  dhcp server as IP helper address on multiple vlans ")
    ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='add')
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_11, IP=dhcp_server1_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_22, RA_ipaddress_4, data.subnet, family=data.af_ipv4, config='add')
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_22, IP=dhcp_server1_ip)

    st.log("About to verify dhcp relay config")
    if not dhcp_relay.verify_dhcp_relay(vars.D2, "Vlan{}".format(vlan_1), dhcp_server1_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_1, ip_address=RA_ipaddr_mask_3, dhcp_helper_add=dhcp_server1_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)
    if not dhcp_relay.verify_dhcp_relay(vars.D2, "Vlan{}".format(vlan_2), dhcp_server1_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_2, ip_address=RA_ipaddr_mask_4, dhcp_helper_add=dhcp_server1_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)

    st.log("config clean up")
    dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_11, IP=dhcp_server1_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='remove')
    delete_vlan_member(vars.D2, vlan_1, [vars.D2D3P1], tagging_mode=True)
    delete_vlan(vars.D2, [vlan_1])
    dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=vlan_22, IP=dhcp_server1_ip)
    ip.config_ip_addr_interface(vars.D2, vlan_22, RA_ipaddress_4, data.subnet, family=data.af_ipv4, config='remove')
    delete_vlan_member(vars.D2, vlan_2, [vars.D2D3P1], tagging_mode=True)
    delete_vlan(vars.D2, [vlan_2])
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_single_vlan_multi_server():
    #################################################
    #
    # Objective - Configure DHCP relay on a Vlan with different DHCP servers and verify the configuration.
    #
    #################################################
    vlan_1 = 100
    vlan_11 = "Vlan{}".format(vlan_1)
    RA_ipaddress_3 = '192.168.3.10'
    RA_ipaddr_mask_3 = '192.168.3.10/24'
    dhcp_server1_ip = '2.2.2.2'
    dhcp_server2_ip = '3.3.3.3'

    st.log("About to create non default vlans ")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": vlan_1, "tagged": [vars.D2D3P1]}])

    st.log("About to config multiple dhcp servers as IP helper address on single vlan ")
    ip.config_ip_addr_interface(vars.D2, vlan_11, RA_ipaddress_3, data.subnet, family=data.af_ipv4, config='add')
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_11, IP=dhcp_server1_ip)
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan = vlan_11, IP=dhcp_server2_ip)
    st.log("About to verify dhcp relay config")
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, vlan_11, server_addr=dhcp_server1_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_1, ip_address=RA_ipaddr_mask_3, dhcp_helper_add=dhcp_server1_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, vlan_11, server_addr=dhcp_server2_ip, family=data.af_ipv4):
    # if not verify_vlan_brief(vars.D2, vlan_1, ip_address=RA_ipaddr_mask_3, dhcp_helper_add=dhcp_server2_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_invalid_server_ip():
    #################################################
    #
    # Objective-Verify that Invalid DHCP Server addr config in IP Helper Address will not get Ip address to DHCP client.
    #
    #################################################
    data.invalid_ip_helper_address_1 = "0.0.0.0"
    data.invalid_ip_helper_address_2 = "255.255.255.255"
    data.invalid_ip_helper_address_3 = "239.1.1.1"
    data.invalid_ip_helper_address_4 = "300.300.300.1"

    st.log("About to remove valid relay IP helper address in Relay agent")
    dhcp_relay.dhcp_relay_config_remove(vars.D2, vlan=data.vlan_int, IP=data.dhcp_server_ip)
    st.log("About to add invalid relay IP helper addresses in Relay agent")
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.invalid_ip_helper_address_1, skip_error_check=True)
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.invalid_ip_helper_address_2, skip_error_check=True)
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.invalid_ip_helper_address_3, skip_error_check=True)
    dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.invalid_ip_helper_address_4, skip_error_check=True)
    if dhcp_relay.verify_dhcp_relay(vars.D2, data.vlan, data.invalid_ip_helper_address_1, family=data.af_ipv4):
    # if verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                               dhcp_helper_add=data.invalid_ip_helper_address_1):
        st.report_fail("able_to_config_invalid_ip_address_as_IP_Helper_address")
    if dhcp_relay.verify_dhcp_relay(vars.D2, data.vlan, data.invalid_ip_helper_address_2, family=data.af_ipv4):
    # if verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                               dhcp_helper_add=data.invalid_ip_helper_address_2):
        st.report_fail("able_to_config_invalid_ip_address_as_IP_Helper_address")
    if dhcp_relay.verify_dhcp_relay(vars.D2, data.vlan, data.invalid_ip_helper_address_3, family=data.af_ipv4):
    # if verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                               dhcp_helper_add=data.invalid_ip_helper_address_3):
        st.report_fail("able_to_config_invalid_ip_address_as_IP_Helper_address")
    if dhcp_relay.verify_dhcp_relay(vars.D2, data.vlan, data.invalid_ip_helper_address_4, family=data.af_ipv4):
    # if verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                               dhcp_helper_add=data.invalid_ip_helper_address_4):
        st.report_fail("able_to_config_invalid_ip_address_as_IP_Helper_address")
    st.log("About to check client IP")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if ip.verify_interface_ip_address(vars.D3, vars.D3D2P1, data.pool_ip_address, family="ipv4", vrfname=''):
        st.report_fail("client_got_ip_with_invalid_ip_helper_address", data.invalid_ip_helper_address_1)
    dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_ip_address_config_remove_add():
    #################################################
    #
    # Objective-Verify dhcp relay working fine after removing ip address on server facing interface
    #
    #################################################
    st.log("About to config valid relay IP helper address in Relay agent")
    try:
        dhcp_relay.dhcp_relay_config_add(vars.D2, vlan=data.vlan_int, IP=data.dhcp_server_ip)
    except Exception:
        st.log("IP helper address already conigured")
    st.log("About to remove IP config on server connected port in relay agent DUT")
    ip.delete_ip_interface(vars.D2, interface_name=data.dhcp_relay_params, ip_address=data.RA_ipaddress_1,
                               subnet="24", family="ipv4")
    if ip.verify_interface_ip_address(vars.D3, data.vlan_int, data.pool_ip_address, family="ipv4", vrfname=''):
        st.report_fail("client_got_ip_without_proper_connectivity_to_server")
    st.log("About to add IP config on server connected port in relay agent DUT")
    ip.config_ip_addr_interface(vars.D2, interface_name=data.dhcp_relay_params, ip_address=data.RA_ipaddress_1,
                                    subnet='24', family="ipv4", config='add')
    st.log("About to check client IP")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        st.error("After remove and re add relay agent ip address, client to failed to aquire ipv4 address")
        dhcp_relay_debug(vars.D2, interface=data.vlan_int)
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_statistics():
    #################################################
    #
    # Objective - Verify dhcp relay statistics are updated properly .
    #
    #################################################
    st.log("About to verify dhcp relay configuration")
    check_dhcp_relay_config()
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2,interface = data.vlan_int)
    pkts_relayed_server_to_client = stats[0]["dhcp_offer_msgs_sent_by_the_relay_agent"]
    if  int(pkts_relayed_server_to_client) == int(0):
        dhcp_relay_debug(vars.D2,interface = data.vlan_int)
        st.report_fail("packets_relayed_from_server_to_client_statistics_not_incremented")
    pkts_relayed_client_to_server = stats[0]["bootrequest_msgs_forwarded_by_the_relay_agent"]
    if int(pkts_relayed_client_to_server) == int(0):
        dhcp_relay_debug(vars.D2,interface = data.vlan_int)
        st.report_fail("packets_relayed_from_client_to_server_statistics_not_incremented")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_lease_time_renew():
    #################################################
    #
    # Objective - Verify dhcp relay statistics are updated properly .
    #
    #################################################
    st.log("About to verify dhcp relay configuration")
    check_dhcp_relay_config()
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2,interface = data.vlan_int)
    pkts_relayed_server_to_client = stats[0]["bootreply_msgs_forwarded_by_the_relay_agent"]
    pkts_relayed_client_to_server = stats[0]["bootrequest_msgs_received_by_the_relay_agent"]
    if  int(pkts_relayed_server_to_client) == int(0) :
        st.report_fail("packets_relayed_from_server_to_client_statistics_not_incremented")
    if int(pkts_relayed_client_to_server) == int(0):
        st.report_fail("packets_relayed_from_client_to_server_statistics_not_incremented")
    st.wait(data.dhcp_renew_check_timer)
    stats = dhcp_relay.get_dhcp_relay_statistics(vars.D2, interface=data.vlan_int)
    pkts_relayed_server_to_client_renew = stats[0]["bootreply_msgs_forwarded_by_the_relay_agent"]
    pkts_relayed_client_to_server_renew = stats[0]["bootrequest_msgs_received_by_the_relay_agent"]
    if not int(pkts_relayed_server_to_client_renew) > int(pkts_relayed_server_to_client):
        dhcp_relay_debug(vars.D2,interface = data.vlan_int)
        st.report_fail("client_failed_to_renew_ip_address")
    if not int(pkts_relayed_client_to_server_renew) > int(pkts_relayed_client_to_server):
        dhcp_relay_debug(vars.D2,interface = data.vlan_int)
        st.report_fail("client_failed_to_renew_ip_address")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_functionality_physical_interface():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the client is assigned DHCP IP address from server.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on routing interface,where server and client connected ports are in default VRF domain.")
    dhcp_relay_interface_config()
    st.log("About to verify dhcp relay configuration on routing interface")
    check_dhcp_relay_interface_config()
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface=data.routing_int)
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "physical interface")
    st.log("About to verify DHCP Relay statistics in dhcp client")
    check_dhcp_relay_statistics("physical", "ipv4")
    st.report_pass("dhcp_relay_functionality_tc_status", "IPv4", "passed", "physical interface")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_functionality_portchannel():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the client is assigned DHCP IP address from server.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on portchannel interface in default VRF domain.")
    dhcp_relay_portchannel_config("ipv4")
    st.log("About to verify dhcp relay configuration on port channel")
    check_dhcp_relay_interface_config("portchannel")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface=data.portchannel)
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "portchannel interface")
    st.report_pass("dhcp_relay_functionality_tc_status", "IPv4", "passed", "portchannel")


def check_dhcpv6_relay_config():
    data.vlan1 = "Vlan{}".format(data.vlan)
    if not dhcp_relay.verify_dhcp_relay(vars.D2, data.vlan1, data.dhcp_v6server_ip,
                                                   family="ipv6"):
        st.report_fail("IPv6_Helper_address_config_failed", vars.D2)


def check_dhcpv6_client(interface_name=None):
    dhcp_relay.dhcp_client_start(vars.D3, interface_name, family="ipv6")
    st.wait(5)
    try:
        pool_ip = ip.get_interface_ip_address(vars.D3, interface_name, family="ipv6")
        pool_ip = pool_ip[0]['ipaddr']
    except Exception:
        dhcp_relay.dhcp_client_stop(vars.D3, interface_name, family="ipv6")
        st.report_fail('IP_address_assignment_failed', vars.D2)
    pool_ip = pool_ip.split("/")
    pool_ip = pool_ip[0][-1]
    st.log("offered_ip {}".format(pool_ip))
    if not (int(pool_ip) in range(255)):
        st.report_fail("IP_address_assignment_failed", vars.D2)


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality():
    #################################################
    #
    # Objective - Configure DHCPv6 relay and verify if the client is assigned DHCPv6 IP address from server.
    #
    #################################################
    st.log("Create VLAN and participate client connected interface in vlan")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": data.vlan, "untagged": [vars.D2D3P1]}])
    st.log("Verify IPv6 DHCP relay functionality on Vlan routing interface")
    dhcp_relay_vlan_config("ipv6")
    st.log("About to verify dhcpv6 relay configuration")
    check_dhcpv6_relay_config()
    st.log("About to verify IPv6 address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int, family = "ipv6")
    if not poll_wait(verify_dhcp_client, 90, vars.D3, data.vlan_int, ip_ad = data.RA_ipv6_address_2, network = data.ip6_addr_mask, family = "ipv6"):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan), family="ipv6")
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan1), family="ipv6")
        st.report_fail("IP_address_assignment_failed", vars.D2)
    st.report_pass("dhcp_relay_functionality_tc_status", "IPv6", "passed", "vlan")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality_physical_interface():
    #################################################
    #
    # Objective - Configure DHCPv6 relay and verify if the client is assigned DHCPv6 IP address from server.
    #
    #################################################
    st.log("Verify IPv6 DHCP relay functionality on routing interface")
    dhcp_relay_interface_config("ipv6")
    st.log("About to verify dhcpv6 relay configuration")
    if not dhcp_relay.verify_dhcp_relay(vars.D2, data.routing_int, data.dhcp_v6server_ip,
                                                   family="ipv6"):
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv6", "failed", "physical interface")
    st.report_pass("dhcp_relay_functionality_tc_status", "IPv6", "passed", "physical")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality_portchannel():
    #################################################
    #
    # Objective - Configure DHCPv6 relay and verify if the client is assigned DHCP IP address from server for PC.
    #
    #################################################
    st.log("Verify IPv6 DHCP relay functionality on portchannel interface,where server and client connected ports are in default VRF domain.")
    dhcp_relay_portchannel_config("ipv6")
    st.log("About to verify dhcp relay configuration on port channel")
    if not dhcp_relay.verify_dhcp_relay(vars.D2, data.portchannel, data.dhcp_v6server_ip,
                                                   family="ipv6"):
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv6", "failed", "portchannel")
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int, family = "ipv6")
    if not poll_wait(verify_dhcp_client, 90, vars.D3, data.vlan_int, ip_ad=data.RA_ipv6_address_2,
                     network=data.ip6_addr_mask, family="ipv6"):
        dhcp_relay_debug(vars.D2, family="ipv6", interface=data.portchannel)
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv6", "failed", "portchannel")
    st.report_pass("dhcp_relay_functionality_tc_status", "IPv6", "passed", "portchannel")

### VRF UTILS #######################################################################################################
def util_clean_up_vrf(interface_name, vrf_name):
    st.log("Unbind DUT interface {} to non-default VRF {}".format(interface_name, vrf_name))
    exec_foreach(True, data.my_dut_list, bind_vrf_interface, intf_name=interface_name,
                                                             vrf_name=vrf_name, config='no', skip_error=False)
    st.log("Delete vrf from DUT")
    exec_foreach(True, data.my_dut_list, config_vrf,config='no',vrf_name=data.vrf_name,skip_error=False)

def util_create_vrf(vrf_name, intf_name):
    st.log("Create vrf from DUT")
    try:
        config_vrf(vars.D2, vrf_name=data.vrf_name, config='yes', skip_error=False)
    except Exception:
        st.log("Already VRF exists")
    st.log("bind DUT interface {} to non-default VRF {}".format(intf_name, vrf_name))
    bind_vrf_interface(vars.D2, intf_name=intf_name, vrf_name=vrf_name, config='yes', skip_error=False)


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_functionality_vlan_vrf():
    #################################################
    #
    # Objective - Verify IPv4 DHCP relay functionality on VLAN routing interface,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on Vlan,where server and client connected ports are in user defined VRF domain.")
    st.log("Create VLAN and participate client connected interface in vlan")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": data.vlan, "untagged": [vars.D2D3P1]}])
    st.log("Create and bind VRF to interfaces")
    config_vrf(vars.D2, vrf_name=data.vrf_name, config='yes', skip_error=True)
    bind_vrf_interface(vars.D2, intf_name=data.vlan1, vrf_name=data.vrf_name, config='yes', skip_error=True)
    bind_vrf_interface(vars.D2, intf_name=data.dhcp_relay_params, vrf_name=data.vrf_name, config='yes', skip_error=True)
    ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipaddress_1, data.subnet,
                                family=data.af_ipv4, config='add')
    dhcp_relay_vlan_config(vrf_name=data.vrf_name)
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan))
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan1))
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv4", "failed", data.vrf_name, "vlan")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv4", "passed", data.vrf_name, "vlan")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_functionality_phy_intf_vrf():
    #################################################
    #
    # Objective - Verify IPv4 DHCP relay functionality on routing interface,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on physical interface,where server and client connected ports are in user VRF domain.")
    st.log("Create and bind VRF to interfaces")
    bind_vrf_interface(vars.D2, intf_name=data.routing_int, vrf_name=data.vrf_name, config='yes', skip_error=True)
    dhcp_relay_interface_config(vrf_name=data.vrf_name)
    st.log("About to verify dhcp relay configuration on routing interface")
    check_dhcp_relay_interface_config()
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv4", "failed", data.vrf_name, "physical")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv4", "passed", data.vrf_name, "physical")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcp_relay_functionality_portchannel_vrf():
    #################################################
    #
    # Objective - Verify IPv4 DHCP relay functionality on portchannel,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IPv4 DHCP relay functionality on PC,where server and client connected ports are in user VRF domain.")
    create_portchannel(vars.D2, [data.portchannel], static=True)
    add_del_portchannel_member(vars.D2, data.portchannel, vars.D2D3P2, flag="add", skip_verify=True, skip_err_check=True)
    st.log("bind VRF to port channel interface")
    bind_vrf_interface(vars.D2, intf_name=data.portchannel, vrf_name=data.vrf_name, config='yes', skip_error=True)
    st.log("About to add IP address in portchannel for RA DUT")
    ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipaddress_2, data.subnet, family=data.af_ipv4)
    st.log("Add DHCP server address to portchannel interface")
    dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.portchannel, IP=data.dhcp_server_ip, vrf_name=data.vrf_name)
    st.log("About to verify dhcp relay configuration on port channel")
    check_dhcp_relay_interface_config("portchannel")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, data.vlan_int):
        dhcp_relay_debug(vars.D2, interface=data.portchannel)
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv4", "failed", data.vrf_name, "portchannel")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv4", "passed", data.vrf_name, "portchannel")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality_vlan_vrf():
    #################################################
    #
    # Objective - Verify IPv6 DHCP relay functionality on VLAN routing interface,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IP6 DHCP relay functionality on Vlan,where server and client connected ports are in user defined VRF domain.")
    st.log("Create VLAN and participate client connected interface in vlan")
    create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": data.vlan, "untagged": [vars.D2D3P1]}])
    ip.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipv6address, data.ip6_addr_mask,
                                family=data.af_ipv6, config='add')
    bind_vrf_interface(vars.D2, intf_name=data.vlan1, vrf_name=data.vrf_name, config='yes', skip_error=False)
    dhcp_relay_vlan_config(family="ipv6", vrf_name=data.vrf_name)
    st.log("About to verify dhcpv6 relay configuration")
    check_dhcpv6_relay_config()
    st.log("About to verify IPv6 address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int, family="ipv6")
    if not poll_wait(verify_dhcp_client, 90, vars.D3, data.vlan_int, ip_ad=data.RA_ipv6_address_2,
                     network=data.ip6_addr_mask, family="ipv6"):
        dhcp_relay_debug(vars.D2, family="ipv6", interface="Vlan{}".format(data.vlan1))
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv6", "failed", data.vrf_name, "vlan")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv6", "passed", data.vrf_name, "vlan")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality_phy_intf_vrf():
    #################################################
    #
    # Objective - Verify IPv6 DHCP relay functionality on routing interface,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IPv6 DHCP relay functionality on physical interface,where server and client connected ports are in user VRF domain.")
    bind_vrf_interface(vars.D2, intf_name=data.routing_int, vrf_name=data.vrf_name, config='yes', skip_error=True)
    dhcp_relay_interface_config(family="ipv6", vrf_name=data.vrf_name)
    st.log("About to verify dhcpv6 relay configuration")
    if not dhcp_relay.verify_dhcp_relay(vars.D2, data.routing_int, data.dhcp_v6server_ip,
                                                   family="ipv6"):
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv6", "failed", data.vrf_name, "physical")
    st.log("About to verify IP address in dhcp client")
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int, family="ipv6")
    if not poll_wait(verify_dhcp_client, 90, vars.D3, data.vlan_int, ip_ad=data.RA_ipv6_address_2,
                     network=data.ip6_addr_mask, family="ipv6"):
        dhcp_relay_debug(vars.D2, family="ipv6", interface=data.routing_int)
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv6", "failed", data.vrf_name, "physical")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv6", "passed", data.vrf_name, "physical")


@pytest.mark.regression
@pytest.mark.test_dhcp_relay_functionality
def test_dhcpv6_relay_functionality_portchannel_vrf():
    #################################################
    #
    # Objective - Verify IPv6 DHCP relay functionality on portchannel,where server and client
    #             connected ports are in user/non-default VRF domain.
    #
    #################################################
    st.log("Verify IPv6 DHCP relay functionality on PC,where server and client connected ports are in user VRF domain.")
    ip.config_interface_ip6_link_local(vars.D3, data.vlan_int, 'enable')
    create_portchannel(vars.D2, [data.portchannel], static=True)
    add_del_portchannel_member(vars.D2, data.portchannel, vars.D2D3P2, flag="add", skip_verify=True,
                               skip_err_check=False)
    st.log("bind VRF to port channel interface")
    bind_vrf_interface(vars.D2, intf_name=data.portchannel, vrf_name=data.vrf_name, config='yes', skip_error=False)
    ip.config_ip_addr_interface(vars.D2, data.portchannel, data.RA_ipv6_address_2, data.RA_ipv6_address_2_subnet,
                                family=data.af_ipv6, config='add')
    st.log("Configure IPv6 DHCP relay address on an portchannel")
    dhcp_relay.dhcp_relay_config_add(vars.D2, interface=data.portchannel, IP=data.dhcp_v6server_ip, family="ipv6", vrf_name=data.vrf_name)
    dhcp_relay.dhcp_client_start(vars.D3, data.vlan_int, family="ipv6")
    if not poll_wait(verify_dhcp_client, 90, vars.D3, data.vlan_int, ip_ad=data.RA_ipv6_address_2,
                     network=data.ip6_addr_mask, family="ipv6"):
        dhcp_relay_debug(vars.D2, family="ipv6", interface=data.portchannel)
        st.report_fail("dhcp_relay_vrf_functionality_tc_status", "IPv6", "failed", data.vrf_name, "portchannel")
    st.report_pass("dhcp_relay_vrf_functionality_tc_status", "IPv6", "passed", data.vrf_name, "portchannel")


@pytest.mark.dhcp_relay_mem
def test_dhcp_relay_mem():
    #################################################
    #
    # Objective - With multiple (10 instances) DHCP relays are configured, and a large number of L3 interfaces are
    # present, verify there is no memory leak in dhcp relay process when dhcp discover packets are sent on to the routing
    # interfces on which ip address is removed.
    # Issue reproduced in 5 minutes of run earlier, so minimum amount of time to run the test is 5 min.
    #################################################
    ip.config_ip_addr_interface(vars.D1, vars.D1T1P2, "8.1.0.1", "24", family="ipv4", config='add')
    config_vlan_range(vars.D1, "9 {}".format(110), config="add")
    config_vlan_range_members(vars.D1, "9 {}".format(110), [vars.D1T1P1], config="add")
    vlan_intf_config = {"VLAN_INTERFACE": {}}
    for each in range(9, 111):
        vlan_intf_config['VLAN_INTERFACE']["Vlan{}".format(each)] = {}
        vlan_intf_config['VLAN_INTERFACE']["Vlan{}|{}.1.0.1/24".format(each, each)] = {}
    write_config_db(vars.D1, vlan_intf_config)
    for each in range(100, 110):
        dhcp_relay.dhcp_relay_config(vars.D1, vlan="Vlan{}".format(each), IP="8.1.0.2", action="add")
    if_data_list = []
    for each in range(87, 93):
        if_data_list.append({'name': "Vlan{}".format(each), 'ip': "{}.1.0.1".format(each), 'subnet': "24", 'family': "ipv4"})
    ip.config_unconfig_interface_ip_addresses(vars.D1, if_data_list, config='remove')
    tg_stream_handle = \
    tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
                          rate_pps=500, mac_src='00:00:00:00:00:01', mac_dst='FF:FF:FF:FF:FF:FF',
                          data_pattern_mode='fixed', frame_size=354, ethernet_value='8100', l2_encap='ethernet_ii',
                          data_pattern='00 58 08 00 45 00 01 48 00 00 00 00 40 11 79 A6 00 00 00 00 FF FF FF FF 00 44 00'
                                       ' 43 01 34 05 DA 01 01 06 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                       ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                       ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                       ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                       ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 63 82 53 63 35 01 01 39 02 04 80 FF 00 00 00 00 00 00 00 00 00 00 00 00'
                                       ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 75 A1 98')['stream_id']
    tg1.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    if not verify_free_memory(vars.D1, 20000):
        tg1.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
        st.report_fail("dhcp_relay_mem_leak_verification_status", "failed")
    tg1.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    st.report_pass("dhcp_relay_mem_leak_verification_status", "successful")


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    return tg_handler

