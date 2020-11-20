import pytest
from spytest import st
from spytest.dicts import SpyTestDict
from spytest.utils import random_vlan_list, poll_wait
import apis.routing.ip as ip
from apis.switching.vlan import add_vlan_member, create_vlan, delete_vlan, delete_vlan_member
from apis.switching.portchannel import get_portchannel_list, clear_portchannel_configuration, \
    create_portchannel, add_del_portchannel_member
import utilities.utils as utils
from utilities.common import poll_wait
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.interface as interface
from apis.routing.arp import show_arp, show_ndp
from apis.system.reboot import config_save
from apis.routing.bgp import config_bgp, advertise_bgp_network, verify_bgp_summary
from apis.system.basic import dhcp_server_config, get_ifconfig_inet, get_ifconfig_inet6
from apis.system.rest import rest_operation, config_rest, get_rest, delete_rest
from apis.qos.copp import bind_class_action_copp_policy
import os

relay_data = SpyTestDict()

def initialize_variables():
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D2D3:2", "D1D4:1", "D2D4:1")
    relay_data.server_relay_connected_port = vars.D2D1P1
    relay_data.dhcp_server_ip = "176.16.40.210"
    relay_data.dhcp_v6server_ip = "2072::210"
    relay_data.ipv6_link_local_intf = vars.D2D4P1
    relay_data.ipv6_link_local_network = "176.16.40.0/24"
    relay_data.loopback_intf = "Loopback0"
    relay_data.loopback_intf_1 = "Loopback1"
    relay_data.loopback_intf_2 = "Loopback2"
    relay_data.portchannel_intf = "PortChannel100"
    relay_data.src_portchannel_intf = "PortChannel102"
    relay_data.vlan_id = random_vlan_list(2)
    relay_data.vlan_intf = "Vlan{}".format(relay_data.vlan_id[0])
    relay_data.src_vlan_intf = "Vlan{}".format(relay_data.vlan_id[1])
    relay_data.src_intf_ip = "110.110.110.1"
    relay_data.src_intf_ip_subnet = 24
    relay_data.relay_client_ip = "192.168.0.2"
    relay_data.relay_client_ip_subnet = 24
    relay_data.relay_client_ip_0 = "20.20.20.5"
    relay_data.relay_client_ip_subnet_0 = 24
    relay_data.relay_client_ip6 = "2092::22"
    relay_data.relay_client_ip6_subnet = 64
    relay_data.relay_server_ip = "176.16.40.1"
    relay_data.relay_server_ip_subnet = 24
    relay_data.relay_server_ip6 = "2072::1"
    relay_data.relay_server_ip6_subnet = 64
    relay_data.loopback_ip = "100.100.100.1"
    relay_data.loopback_ip_1 = "137.15.1.1"
    relay_data.loopback_ip_2 = "200.200.200.1"
    relay_data.loopback_ip_subnet = 32
    relay_data.max_hop_count = 16
    relay_data.relay_stats_data = {"bootrequest_msgs_received_by_the_relay_agent":"non-zero",
                                   "bootrequest_msgs_forwarded_by_the_relay_agent":"non-zero",
                                   "dhcp_offer_msgs_sent_by_the_relay_agent": "non-zero"}
    relay_data.dhcp_files = ['isc-dhcp-server', 'dhcpd.conf', 'dhcpd6.conf']
    relay_data.dhcp_files_path = [os.path.join(os.path.dirname(__file__), relay_data.dhcp_files[0]),
                            os.path.join(os.path.dirname(__file__), relay_data.dhcp_files[1]),
                            os.path.join(os.path.dirname(__file__), relay_data.dhcp_files[2])]
    relay_data.dhcp_files_path = []
    for file in relay_data.dhcp_files: relay_data.dhcp_files_path.append(os.path.join(os.path.dirname(__file__), file))
    relay_data.username = 'admin'
    relay_data.route_list = ['100.100.100.0/24', '200.200.200.0/24', '11.11.11.0/24', '110.110.110.0/24', "20.20.20.0/24"]
    relay_data.route_list_6 = ['1092::0/64']
    relay_data.dhcp_service_name = "isc-dhcp-server"
    relay_data.cli_type = st.get_ui_type(vars.D1)


@pytest.fixture(scope="module", autouse=True)
def dhcp_relay_link_select_module_config(request):
    initialize_variables()
    bind_class_action_copp_policy(vars.D3, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp')
    response = dhcp_server_config(vars.D1, dhcp_files_path=relay_data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=relay_data.dhcp_server_ip, server_ipv6=relay_data.dhcp_v6server_ip,
                       route_list=relay_data.route_list, route_list_v6=relay_data.route_list_6,
                       ipv4_relay_agent_ip=relay_data.relay_server_ip, ipv6_relay_agent_ip=relay_data.relay_server_ip6)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "installation", "failed")
    interface.interface_noshutdown(vars.D2, [relay_data.server_relay_connected_port, relay_data.ipv6_link_local_intf])
    create_vlan(vars.D2, relay_data.vlan_id)
    create_portchannel(vars.D2, [relay_data.portchannel_intf, relay_data.src_portchannel_intf], static=True)
    ip.config_loopback_interfaces(vars.D2, loopback_name=[relay_data.loopback_intf,
                                                          relay_data.loopback_intf_1, relay_data.loopback_intf_2], config="yes")
    ip_list = list()
    ip_list.append({'name': relay_data.server_relay_connected_port, 'ip': relay_data.relay_server_ip,
                    'subnet': relay_data.relay_server_ip_subnet,
                    'family': "ipv4"})
    ip_list.append(
        {'name': relay_data.loopback_intf, 'ip': relay_data.loopback_ip, 'subnet': relay_data.loopback_ip_subnet,
         'family': "ipv4"})
    ip_list.append(
        {'name': relay_data.loopback_intf_1, 'ip': relay_data.loopback_ip_1, 'subnet': relay_data.loopback_ip_subnet,
         'family': "ipv4"})
    ip_list.append(
        {'name': relay_data.loopback_intf_2, 'ip': relay_data.loopback_ip_2, 'subnet': relay_data.loopback_ip_subnet,
         'family': "ipv4"})
    ip.config_unconfig_interface_ip_addresses(vars.D2, ip_list, config='add')
    ip.config_interface_ip6_link_local(vars.D2, vars.D2D4P1, action="enable")
    configure_bgp(action="yes")
    yield
    response = dhcp_server_config(vars.D1, action="unconfig",dhcp_files_path=relay_data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=relay_data.dhcp_server_ip, server_ipv6=relay_data.dhcp_v6server_ip,
                       route_list=relay_data.route_list, route_list_v6=relay_data.route_list_6,
                       ipv4_relay_agent_ip=relay_data.relay_server_ip, ipv6_relay_agent_ip=relay_data.relay_server_ip6)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "uninstallation", "failed")
    ip.clear_ip_configuration(vars.D2)
    ip.config_interface_ip6_link_local(vars.D2, vars.D2D4P1, action="disable")
    ip.config_loopback_interfaces(vars.D2, loopback_name=[relay_data.loopback_intf,
                                  relay_data.loopback_intf_1, relay_data.loopback_intf_2], config="no")
    clear_portchannel_configuration(vars.D2)
    delete_vlan(vars.D2, relay_data.vlan_id)
    configure_bgp(action="no")

def configure_bgp(action="yes"):
    removeBGP = "no" if action  == "yes" else "no"
    config_params_1 = {'addr_family': 'ipv6', 'local_as': "2001", 'remote_as': "3001", 'config_type_list': ['remote-as', 'activate'],
    'interface': relay_data.ipv6_link_local_intf, 'neighbor': relay_data.ipv6_link_local_intf, "config":action, "removeBGP":removeBGP}
    config_params_2 = {'addr_family': 'ipv6', 'local_as': "3001", 'remote_as': "2001",
                     'config_type_list': ['remote-as', 'activate'],
                     'interface': vars.D4D2P1, 'neighbor': vars.D4D2P1,
                     "config": action, "removeBGP": removeBGP}
    config_bgp(vars.D2, **config_params_1)
    config_bgp(vars.D4, **config_params_2)
    advertise_bgp_network(vars.D2, "2001", "{}/{}".format(relay_data.loopback_ip_2, relay_data.loopback_ip_subnet), config=action,
                      family='ipv4')
    advertise_bgp_network(vars.D4, "3001",
                          "{}/{}".format(relay_data.relay_server_ip, relay_data.relay_server_ip_subnet), config=action,
                          family='ipv4')

def config_dhcp_relay(dut, src_interface="", interface="", ip_addr="", action="add", max_hop_count=""):
    src_interface = relay_data.loopback_intf if not src_interface else src_interface
    interface = vars.D2D3P1 if not interface else interface
    ip_address = relay_data.dhcp_server_ip if not ip_addr else ip_addr
    max_hop_count = 10 if not max_hop_count else max_hop_count
    kwargs = {"action": action, "interface": interface,
              "IP": ip_address,
              "link_select": "enable", "src_interface": src_interface, "max_hop_count":max_hop_count}
    if action == "remove":
        del kwargs["link_select"]
        del kwargs["src_interface"]
        del kwargs["max_hop_count"]
    dhcp_relay.dhcp_relay_config(dut, **kwargs)

def dhcp_relay_link_select_debug(dut, family = "ipv4", interface=None):
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

def verify_dhcp_client(dut, interface_name, ip_ad="", network="", family =""):
    ip_ad = relay_data.relay_client_ip if not ip_ad else ip_ad
    network = relay_data.relay_client_ip_subnet if not network else network
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

@pytest.fixture(scope="function", autouse=True)
def dhcp_relay_link_select_func_hooks(request):
    # Function configuration
    yield
    if st.get_func_name(request) == "test_ft_dhcp_relay_link_select_001":
        config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf, interface=vars.D2D3P1, action="remove")
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1, ip_address=relay_data.relay_client_ip,
                                    subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='remove')
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_002":
        config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf, interface=relay_data.portchannel_intf,
                          action="remove")
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.portchannel_intf, ip_address=relay_data.relay_client_ip,
                                    subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='remove')
        add_del_portchannel_member(vars.D2, relay_data.portchannel_intf, vars.D2D3P1, flag="del", skip_verify=True,
                                   skip_err_check=False)
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_003":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        config_dhcp_relay(vars.D2, src_interface=relay_data.src_vlan_intf, interface=relay_data.vlan_intf,
                          action="remove")
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.src_vlan_intf, ip_address=relay_data.src_intf_ip,
                                    subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='remove')
        delete_vlan_member(vars.D2, relay_data.vlan_id[1], [vars.D2D3P2])
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_004":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        config_dhcp_relay(vars.D2, src_interface=relay_data.src_portchannel_intf, interface=relay_data.vlan_intf,
                          action="remove")
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.src_portchannel_intf, ip_address=relay_data.src_intf_ip,
                                    subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='remove')
        add_del_portchannel_member(vars.D2, relay_data.src_portchannel_intf, vars.D2D3P2, flag="del", skip_verify=True,
                                   skip_err_check=False)
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_005":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        config_dhcp_relay(vars.D2, src_interface=vars.D2D3P2, interface=relay_data.vlan_intf,
                          action="remove")
        ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P2,
                                    ip_address=relay_data.src_intf_ip,
                                    subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='remove')
    elif st.get_func_name(request) in ["test_ft_dhcp_relay_link_select_006",
                                        "test_ft_dhcp_relay_link_select_007",
                                        "test_ft_dhcp_relay_link_select_008",
                                        "test_ft_dhcp_relay_link_select_009",
                                        "test_ft_dhcp_relay_link_select_010"]:
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        if st.get_func_name(request) == "test_ft_dhcp_relay_link_select_010":
            config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf, interface=relay_data.vlan_intf,
                              action="remove")
            ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf,
                                        ip_address=relay_data.relay_client_ip,
                                        subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='remove')
            delete_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1])
    elif st.get_func_name(request) in ["test_ft_dhcp_relay_link_select_011","test_ft_dhcp_relay_link_select_012"]:
        if st.get_func_name(request) == "test_ft_dhcp_relay_link_select_011":
            delete_vlan_member(vars.D1, 50, vars.D1D4P1)
            add_vlan_member(vars.D1, 50, vars.D1D2P1)
            ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D1P1,
                                        ip_address=relay_data.relay_server_ip,
                                        subnet=24, family="ipv4")
            ip.config_ip_addr_interface(vars.D4, interface_name=vars.D4D1P1,
                                        ip_address=relay_data.relay_server_ip,
                                        subnet=24, family="ipv4", config="remove")
            ip.config_interface_ip6_link_local(vars.D4, vars.D4D2P1, action="disable")
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf_2, interface=vars.D2D3P1,
                          ip_addr=relay_data.dhcp_server_ip, action="remove")
        if st.get_func_name(request) == "test_ft_dhcp_relay_link_select_012":
            ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                        ip_address=relay_data.relay_client_ip,
                                        subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='remove')

    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_013":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                    ip_address=relay_data.relay_client_ip_0,
                                    subnet=relay_data.relay_client_ip_subnet_0, family="ipv4", config='remove')
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_014":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv6", skip_error_check=True, show_interface=True)
        ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                    ip_address=relay_data.relay_client_ip6,
                                    subnet=relay_data.relay_client_ip6_subnet, family="ipv6", config='remove')
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.server_relay_connected_port,
                                    ip_address=relay_data.relay_server_ip6,
                                    subnet=relay_data.relay_server_ip6_subnet, family="ipv6", config='remove')
        ip.config_interface_ip6_link_local(vars.D3, vars.D3D2P1, action="disable")
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_015":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        dhcp_relay.dhcp_relay_config(vars.D2, action="remove", cli_type="klish", interface=relay_data.vlan_intf,
                                     IP=relay_data.dhcp_server_ip)
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf,
                                    ip_address=relay_data.relay_client_ip_0,
                                    subnet=relay_data.relay_client_ip_subnet_0, family="ipv4", config='remove', cli_type="klish")
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_016":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv6", skip_error_check=True, show_interface=True)
        dhcp_relay.dhcp_relay_config(vars.D2, action="remove", cli_type="klish", interface=relay_data.vlan_intf,
                                     IP=relay_data.dhcp_v6server_ip, family = "ipv6")
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf,
                                    ip_address=relay_data.relay_client_ip6,
                                    subnet=relay_data.relay_client_ip6_subnet, family="ipv6", config='remove', cli_type="klish")
        ip.config_interface_ip6_link_local(vars.D3, vars.D3D2P1, action="disable")
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.server_relay_connected_port,
                                    ip_address=relay_data.relay_server_ip6,
                                    subnet=relay_data.relay_server_ip6_subnet, family="ipv6", config='remove', cli_type="klish")
    elif st.get_func_name(request) == "test_ft_dhcp_relay_link_select_017":
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
        ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf,
                                    ip_address=relay_data.relay_client_ip,
                                    subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='remove')
        # delete_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1])


@pytest.mark.dhcp_relay_link_select
@pytest.mark.dhcp_server_case
def test_ft_dhcp_relay_link_select_001():
    """
    Validate the DHCP relay agent link-select functionality on the Port
    based routing interface with source interface as Loopback interface in default VRF.
    """
    result = False
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                ip_address=relay_data.relay_client_ip,
                                subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=vars.D2D3P1)
        st.wait(2)
        result = True
        st.report_tc_fail("RtDhL3ReLsFn001", "dhcp_relay_link_select_src_intf_status_default_vrf", "Port", "Loopback", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn001", "dhcp_relay_link_select_src_intf_status_default_vrf", "Port", "Loopback", "SUCCESS")
    relay_data.relay_stats_data.update({"interface":vars.D2D3P1})
    if not dhcp_relay.verify_dhcp_relay_statistics(vars.D2, **relay_data.relay_stats_data):
        result = True
        st.report_tc_fail("RtDhL3ReLsSe001", "dhcp_relay_stats_verification_status", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsSe001", "dhcp_relay_stats_verification_status", "SUCCESS")
    if result:
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Port", "Loopback", "FAILED")
    else:
        st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Port", "Loopback", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_002():
    """
    Validate the DHCP relay agent link-select functionality on the Port Channel
    based routing interface with source interface as Loopback interface in default VRF.
    """
    add_del_portchannel_member(vars.D2, relay_data.portchannel_intf, vars.D2D3P1, flag="add", skip_verify=True,
                               skip_err_check=True)
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.portchannel_intf, ip_address=relay_data.relay_client_ip,
                                subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf, interface=relay_data.portchannel_intf, action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60,vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.portchannel_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Port Channel", "Loopback", "FAILED")
    st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Port Channel", "Loopback", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_003():
    """
    Validate the DHCP relay agent link-select functionality on the Vlan
    based routing interface with source interface as Vlan interface in default VRF.
    """
    add_vlan_member(vars.D2, relay_data.vlan_id[1], [vars.D2D3P2], tagging_mode=False)
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.src_vlan_intf, ip_address=relay_data.src_intf_ip,
                                subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='add')
    add_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1], tagging_mode=False)
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf, ip_address=relay_data.relay_client_ip,
                                subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, src_interface=relay_data.src_vlan_intf, interface=relay_data.vlan_intf, action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Vlan", "FAILED")
    st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Vlan", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_004():
    """
    Validate the DHCP relay agent link-select functionality on the Vlan
    based routing interface with source interface as Port Channel interface in default VRF.
    """
    add_del_portchannel_member(vars.D2, relay_data.src_portchannel_intf, vars.D2D3P2, flag="add", skip_verify=True,
                               skip_err_check=False)
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.src_portchannel_intf, ip_address=relay_data.src_intf_ip,
                                subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, src_interface=relay_data.src_portchannel_intf, interface=relay_data.vlan_intf, action="add")
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, relay_data.vlan_intf,
                                                 src_interface=relay_data.src_portchannel_intf, link_select="enable"):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_update_status", "FAILED")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Port Channel", "FAILED")
    st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Port Channel", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_005():
    """
    Validate the DHCP relay agent link-select functionality on the Vlan
    based routing interface with source interface as Physical interface in default VRF.
    """
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P2, ip_address=relay_data.src_intf_ip,
                                subnet=relay_data.src_intf_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, src_interface=vars.D2D3P2, interface=relay_data.vlan_intf,
                      action="add")
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, relay_data.vlan_intf,
                                                 src_interface=vars.D2D3P2, link_select="enable"):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_update_status", "FAILED")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Port", "FAILED")
    st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Port", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_006():
    """
    1) Validate the DHCP relay agent link-select functionality on the Vlan
        based routing interface with source interface as Loopback interface in default VRF.
    2) Validate the DHCP relay agent link-select functionality after shut no shut on the
        Vlan based routing interface with source interface as Loopback interface in default VRF.
    3) Validate the DHCP relay agent link-select functionality on the Vlan based
        routing interface in default VRF after vlan member is removed and re added.
    4) Validate the DHCP relay agent link-select functionality in default VRF after
        shut no shut on the source interface.
    """
    st.banner("Validate the DHCP relay agent link-select functionality on the Vlan \
        based routing interface with source interface as Loopback interface in default VRF.")
    result = False
    config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf, interface=relay_data.vlan_intf,
                      action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        st.error("DHCP CLIENT status verification failed.")
        result = True
    if result:
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_tc_fail("RtDhL3ReLsFn006", "dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Loopback", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn006", "dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Loopback", "SUCCESS")
    result = False
    st.banner("Validate the DHCP relay agent link-select functionality after shut no shut on the \
        Vlan based routing interface with source interface as Loopback interface in default VRF.")
    dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    interface.interface_shutdown(vars.D2, vars.D2D3P1)
    if not interface.poll_for_interface_status(vars.D2, vars.D2D3P1, "oper", "down", iteration=5, delay=1):
        st.error("Failed to shutdown interface {} on the DUT {}".format(vars.D2D3P1, vars.D2))
        result = True
    else:
        interface.interface_noshutdown(vars.D2, vars.D2D3P1)
        if not interface.poll_for_interface_status(vars.D2, vars.D2D3P1, "oper", "up", iteration=5, delay=1):
            st.error("Failed to startup interface {} on the DUT {}".format(vars.D2D3P1, vars.D2))
            result = True
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, relay_data.vlan_intf,
                                                 src_interface=relay_data.loopback_intf, link_select="enable"):
        st.error("After shut no-shut, DHCP RELAY Agent config is not retained on the interface.")
        result = True
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        st.error("DHCP CLIENT status verification failed.")
        result = True
    if result:
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_tc_fail("RtDhL3ReLsFn007", "dhcp_relay_link_select_shut_no_shut_src_intf_status_default_vrf", "Vlan", "Loopback", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn007", "dhcp_relay_link_select_shut_no_shut_src_intf_status_default_vrf", "Vlan", "Loopback", "SUCCESS")
    result = False
    st.banner("Validate the DHCP relay agent link-select functionality on the Vlan based \
            routing interface in default VRF after vlan member is removed and re added.")
    dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    delete_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1], skip_error_check=True)
    st.wait(5)
    add_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1], tagging_mode=False)
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        st.error("DHCP CLIENT status verification failed.")
        result = True
    if result:
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_tc_fail("RtDhL3ReLsFn012", "dhcp_relay_link_select_src_intf_status_default_vrf_vlan_member_add_remove", "Vlan", "Loopback", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn012", "dhcp_relay_link_select_src_intf_status_default_vrf_vlan_member_add_remove", "Vlan", "Loopback", "SUCCESS")
    result = False
    st.banner("Validate the DHCP relay agent link-select functionality in default VRF after "
              "shut no shut on the source interface.")
    dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    interface.interface_shutdown(vars.D2, vars.D2D3P2)
    if not interface.poll_for_interface_status(vars.D2, vars.D2D3P2, "oper", "down", iteration=5, delay=1):
        st.error("Failed to shutdown interface {} on the DUT {}".format(vars.D2D3P2, vars.D2))
        result = True
    else:
        interface.interface_noshutdown(vars.D2, vars.D2D3P2)
        if not interface.poll_for_interface_status(vars.D2, vars.D2D3P2, "oper", "up", iteration=5, delay=1):
            st.error("Failed to startup interface {} on the DUT {}".format(vars.D2D3P2, vars.D2))
            result = True
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        result = True
        st.report_tc_fail("RtDhL3ReLsFn009", "dhcp_relay_link_select_src_intf_ip_shut_no_shut_status", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn009", "dhcp_relay_link_select_src_intf_ip_shut_no_shut_status", "SUCCESS")
    if result:
        st.report_fail("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Loopback", "FAILED")
    else:
        st.report_pass("dhcp_relay_link_select_src_intf_status_default_vrf", "Vlan", "Loopback", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_007():
    """
    1) Validate the DHCP relay agent link-select functionality in default VRF
    after removing and re-adding the ip address on the Source interface.
    """
    result = False
    st.banner("Validate the DHCP relay agent link-select functionality in default VRF \
    after removing and re-adding  the ip address on the Source interface.")
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.loopback_intf,
                                ip_address=relay_data.loopback_ip,
                                subnet=relay_data.loopback_ip_subnet, family="ipv4", config='remove')
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if verify_dhcp_client(vars.D3, vars.D3D2P1):
        result = True
        st.error("Client recevied IP address even though there is not ip address to source")
    else:
        dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.loopback_intf,
                                ip_address=relay_data.loopback_ip,
                                subnet=relay_data.loopback_ip_subnet, family="ipv4", config='add')
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        result = True
        st.report_tc_fail("RtDhL3ReLsFn008", "dhcp_relay_link_select_src_intf_ip_addr_change_status", "FAILED")
    else:
        st.report_tc_pass("RtDhL3ReLsFn008", "dhcp_relay_link_select_src_intf_ip_addr_change_status", "SUCCESS")
    if result:
        st.report_fail("dhcp_relay_link_select_src_intf_ip_addr_change_status", "FAILED")
    else:
        st.report_pass("dhcp_relay_link_select_src_intf_ip_addr_change_status", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_008():
    """
    Validate the DHCP relay agent link-select functionality in default VRF after changing the source interface.
    :return:
    """
    result = False
    st.log("Changing the source interface of the relay agent to a "
           "different source interface for which there is no reachability "
           "from the server, in this case client should not get the IP address")
    dhcp_relay.dhcp_relay_option_config(vars.D2, option="src-intf", interface=relay_data.vlan_intf,
                                        src_interface=relay_data.loopback_intf_1, action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if verify_dhcp_client(vars.D3, vars.D3D2P1):
        st.error("Client received the IP address when there is no route to the updated source interface ip in DHCP server.")
        result = True
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
    dhcp_relay.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    st.log("Reverting source interface and verifying whether client is getting ip address or not")
    dhcp_relay.dhcp_relay_option_config(vars.D2, option="src-intf", interface=relay_data.vlan_intf,
                                        src_interface=relay_data.loopback_intf, action="add")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        st.error("Client did not receive IP address even though there is not ip address to source")
        result = True
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)

    if result:
        st.report_fail("dhcp_relay_link_select_src_intf_update_status", "FAILED")
    else:
        st.report_pass("dhcp_relay_link_select_src_intf_update_status", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_009():
    """
    Validate the DHCP relay agent link-select functionality in default VRF after warm boot.
    :return:
    """
    config_save(vars.D2)
    st.log("Performing warm-reboot ...")
    st.reboot(vars.D2, 'warm')
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 240, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_default_vrf_with_diff_boot_status", "warm boot", "FAILED")
    st.report_pass("dhcp_relay_link_select_default_vrf_with_diff_boot_status", "warm boot", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_010():
    """
    Validate the DHCP relay agent link-select functionality in default VRF after Reboot (fastboot).
    :return:
    """
    config_save(vars.D2)
    st.log("Performing fast-reboot ...")
    st.reboot(vars.D2, 'fast')
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.report_fail("dhcp_relay_link_select_default_vrf_with_diff_boot_status", "fast boot","FAILED")
    st.report_pass("dhcp_relay_link_select_default_vrf_with_diff_boot_status", "fast boot","SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_011():
    """
    Validate the DHCP relay agent link-select functionality in default VRF
    with DHCP server rechability via IPv6 link local address (BGP unnumbered)
    :return:
    """
    ip.config_interface_ip6_link_local(vars.D4, vars.D4D2P1, action="enable")
    delete_vlan_member(vars.D1,50,vars.D1D2P1)
    add_vlan_member(vars.D1, 50, vars.D1D4P1)
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D1P1,
                                ip_address=relay_data.relay_server_ip,
                                subnet=24, family="ipv4", config="remove")
    ip.config_ip_addr_interface(vars.D4, interface_name=vars.D4D1P1,
                                ip_address=relay_data.relay_server_ip,
                                subnet=24, family="ipv4")
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                ip_address=relay_data.relay_client_ip,
                                subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='add')
    config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf_2, interface=vars.D2D3P1, ip_addr=relay_data.dhcp_server_ip,action="add")
    if not poll_wait(verify_bgp_summary, 90, vars.D2, family='ipv6', neighbor = [relay_data.ipv6_link_local_intf], state='Established'):
        st.report_fail("BGP_unnumbered_neighbor_establish_status", "FAILED")
    if not poll_wait(ip.verify_ip_route, 10, vars.D2, family="ipv4", ip_address=relay_data.ipv6_link_local_network,type="B"):
        st.report_fail("BGP_unnumbered_neighbor_route_learn_status", "FAILED")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_link_select_debug(vars.D2, interface=vars.D2D3P1)
        st.report_fail("dhcp_relay_link_select_ipv6_link_local_status", "FAILED")
    st.report_pass("dhcp_relay_link_select_ipv6_link_local_status", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_012():
    """
    Validate the DHCP relay agent link-select max-hop-count configuration
    :return:
    """
    config_dhcp_relay(vars.D2, src_interface=relay_data.loopback_intf_2, interface=vars.D2D3P1,
                      ip_addr=relay_data.dhcp_server_ip, action="add", max_hop_count=relay_data.max_hop_count)
    dhcp_relay.dhcp_relay_detailed_show(vars.D2, vars.D2D3P1, family="ipv4")
    if not dhcp_relay.verify_dhcp_relay_detailed(vars.D2, vars.D2D3P1, max_hop_count=relay_data.max_hop_count):
        st.report_fail("DHCP_relay_link_select_max_hop_count_status", "FAILED")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    dhcp_relay.dhcp_relay_option_config(vars.D2, interface=vars.D2D3P1, action="remove", option="max-hop-count")
    if dhcp_relay.verify_dhcp_relay_detailed(vars.D2, vars.D2D3P1, max_hop_count=relay_data.max_hop_count):
        st.report_fail("DHCP_relay_link_select_max_hop_count_status", "FAILED")
    st.report_pass("DHCP_relay_link_select_max_hop_count_status", "SUCCESS")


@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_013():
    """
    Validate the DHCP relay agent functionality in default VRF using REST
    :return:
    """
    st.warn("This test function need to be removed after REST API supported added to this feature.")
    credentials = st.get_credentials(vars.D2)
    st.rest_init(vars.D2, credentials[0], credentials[1], credentials[2])
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                ip_address=relay_data.relay_client_ip_0,
                                subnet=relay_data.relay_client_ip_subnet_0, family="ipv4", config='add')
    report_flag = 0
    data = {
            "openconfig-relay-agent:interface": [
            {
                "id": vars.D2D3P1,
                "config": {
                    "id": vars.D2D3P1,
                    "helper-address": [
                    relay_data.dhcp_server_ip
                    ]
                }
            }
        ]
    }
    rest_url_datastore = st.get_datastore(vars.D2, "rest_urls")
    dhcp_relay_rest_update_url = rest_url_datastore["config_dhcp_relay_on_interface"].format(vars.D2D3P1)
    st.log("Enable DHCP Relay agent on interface {} using REST".format(vars.D2D3P1))
    res_update = config_rest(vars.D2, http_method="patch", rest_url=dhcp_relay_rest_update_url, json_data=data)
    if not res_update:
        st.error("Failed to update/enable DHCP Relay agent for {} through REST".format(vars.D2D3P1))
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "FAILED")
    dhcp_relay_rest_delete_url = rest_url_datastore["config_helper_address_on_interface"].format(vars.D2D3P1)
    dhcp_relay_rest_get_stat_url = rest_url_datastore["dhcp_discover_rcvd_on_intferface"].format(vars.D2D3P1)
    st.log("Check whether client gets ipv4 address")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    st.wait(2)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1, ip_ad = relay_data.relay_client_ip_0, network = relay_data.relay_client_ip_subnet_0 ):
        report_flag = 1
        dhcp_relay_link_select_debug(vars.D2, interface=vars.D2D3P1)
    st.log("GET DHCP Relay agent statistics through REST")
    try:
        dhcp_relay_res_get_stat = get_rest(vars.D2, http_method="get", rest_url=dhcp_relay_rest_get_stat_url)
        dhcp_relay_res_get_stat_ret_val = dhcp_relay_res_get_stat['output']['openconfig-relay-agent:dhcp-discover-received']
        if not int(dhcp_relay_res_get_stat_ret_val.encode('UTF-8')) >= 1:
            report_flag = 1
            st.error("DHCP relay agent dhcp-discover-received stats are not updated correctly when retrieved through REST")
    except Exception as e:
        st.log(e)
        report_flag = 1
        st.error("DHCP relay agent dhcp-discover-received stats are not updated correctly when retrieved through REST")
    st.log("Deleting the DHCP relay agent through REST")
    res_del = delete_rest(vars.D2, http_method="delete", rest_url=dhcp_relay_rest_delete_url)
    if res_del:
        if not res_del:
            report_flag = 1
            st.error("Failed to remove DHCP Relay agent config for {} through REST".format(vars.D2D3P1))
    else:
        report_flag=1
    if report_flag:
        dhcp_relay_link_select_debug(vars.D2, interface=vars.D2D3P1)
        st.log("As REST delete call failed, removing the DHCP relay agent config using CLI ")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, interface=vars.D2D3P1, IP=relay_data.dhcp_server_ip)
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "FAILED")
    st.report_pass("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "SUCCESS")



@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_014():
    """
    Validate the DHCPv6 relay agent functionality in default VRF using REST
    :return:
    """
    st.warn("This test function need to be removed after REST API supported added to this feature.")
    credentials = st.get_credentials(vars.D2)
    st.rest_init(vars.D2, credentials[0], credentials[1], credentials[2])
    ip.config_ip_addr_interface(vars.D2, interface_name=vars.D2D3P1,
                                ip_address=relay_data.relay_client_ip6,
                                subnet=relay_data.relay_client_ip6_subnet, family="ipv6", config='add')
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.server_relay_connected_port,
                                ip_address=relay_data.relay_server_ip6,
                                subnet=relay_data.relay_server_ip6_subnet, family="ipv6", config='add')
    ip.config_interface_ip6_link_local(vars.D3, vars.D3D2P1, action="enable")

    report_flag = 0
    data = {
            "openconfig-relay-agent:config": {
                "id": vars.D2D3P1,
                "helper-address": [
                relay_data.dhcp_v6server_ip
                ]
            }
    }
    rest_url_datastore = st.get_datastore(vars.D2, "rest_urls")
    dhcp6_relay_rest_update_url = rest_url_datastore["config_dhcp_relay_on_interface_v6"].format(vars.D2D3P1)
    dhcp6_relay_rest_get_url = rest_url_datastore["config_helper_address_on_interface_v6"].format(vars.D2D3P1)
    dhcp6_relay_res_get_stat_url = rest_url_datastore["dhcp_advt_sent_on_intferface_v6"].format(vars.D2D3P1)
    st.log("Enable DHCPv6 Relay agent on interface {} using REST".format(vars.D2D3P1))
    res_update = config_rest(vars.D2, http_method="patch", rest_url=dhcp6_relay_rest_update_url, json_data=data)
    if not res_update:
        st.error("Failed to update/enable DHCPv6 Relay agent for {} through REST".format(vars.D2D3P1))
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v6", "REST", "FAILED")
        dhcp_relay_link_select_debug(vars.D2, family="ipv6", interface=vars.D2D3P1)
    st.log("Validating DHCP relay agent config using GET call through REST")
    try:
        dhcp6_relay_res_get = get_rest(vars.D2, http_method="get", rest_url=dhcp6_relay_rest_get_url)
        res_val = dhcp6_relay_res_get['output']['openconfig-relay-agent:helper-address'][0]
        if not res_val.encode('UTF-8') == relay_data.dhcp_v6server_ip:
            report_flag = 1
            st.error("Failed to update/enable DHCPv6 Relay agent for {} through REST".format(vars.D2D3P1))
            dhcp_relay_link_select_debug(vars.D2, family="ipv6", interface=vars.D2D3P1)
    except Exception as e:
        st.log(e)
        report_flag = 1
        st.error("Failed to update/enable DHCPv6 Relay agent for {} through REST".format(vars.D2D3P1))
    st.log("Check ipv6 client gets the IPv6 address")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1, family = "ipv6")
    st.wait(2)
    if not poll_wait(verify_dhcp_client, 90, vars.D3, vars.D3D2P1, ip_ad = relay_data.relay_client_ip6, network = relay_data.relay_client_ip6_subnet, family = "ipv6"):
        report_flag = 1
        dhcp_relay_link_select_debug(vars.D2, family = "ipv6", interface=vars.D2D3P1)
    st.log("Check the statistics of DHCP relay agent through REST")
    try:
        dhcp6_relay_res_get_stat = get_rest(vars.D2, http_method="get", rest_url=dhcp6_relay_res_get_stat_url)
        dhcp6_relay_res_get_stat_ret_val = dhcp6_relay_res_get_stat['output']['openconfig-relay-agent:dhcpv6-adverstise-sent']
        if not int(dhcp6_relay_res_get_stat_ret_val.encode('UTF-8')) >= 1:
            report_flag = 1
            st.error("DHCP relay agent dhcpv6-adverstise-sent stats are not updated correctly when retrieved through REST")
    except Exception as e:
        st.log(e)
        report_flag = 1
        st.error("DHCP relay agent dhcpv6-adverstise-sent stats are not updated correctly when retrieved through REST")
    st.log("Deleting DHCP relay agent config using DELETE call through REST")
    rest_delete_url = rest_url_datastore["config_helper_addr_on_interface_v6"].format(vars.D2D3P1, relay_data.dhcp_v6server_ip)
    res_del = delete_rest(vars.D2, http_method="delete", rest_url=rest_delete_url)
    if res_del:
        if not res_del:
            report_flag = 1
            st.error("Failed to remove DHCPv6 Relay agent config for {} through REST".format(vars.D2D3P1))
    else:
        report_flag = 1
    if report_flag:
        dhcp_relay_link_select_debug(vars.D2, family="ipv6", interface=vars.D2D3P1)
        if not res_del:
            dhcp_relay.dhcp_relay_config_remove(vars.D2, interface=vars.D2D3P1, family="ipv6", IP=relay_data.dhcp_v6server_ip)
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v6", "REST", "FAILED")
    st.report_pass("dhcp_relay_verification_rest_klish_status_default_vrf", "v6", "REST", "SUCCESS")



@pytest.mark.dhcp_relay_link_select
def test_ft_dhcp_relay_link_select_017():
    """
    Validate the DHCP relay agent link-select and src-intf functionality in default VRF using REST
    :return:
    """
    add_vlan_member(vars.D2, relay_data.vlan_id[0], [vars.D2D3P1])
    st.warn("This test function need to be removed after REST API supported added to this feature.")
    credentials = st.get_credentials(vars.D2)
    st.rest_init(vars.D2, credentials[0], credentials[1], credentials[2])
    ip.config_ip_addr_interface(vars.D2, interface_name=relay_data.vlan_intf,
                                ip_address=relay_data.relay_client_ip,
                                subnet=relay_data.relay_client_ip_subnet, family="ipv4", config='add')
    report_flag = 0
    data = {
            "openconfig-relay-agent:config": {
                "id": relay_data.vlan_intf,
                "helper-address": [
                    relay_data.dhcp_server_ip
                ],
            "openconfig-relay-agent-ext:link-select": "ENABLE",
            "openconfig-relay-agent-ext:src-intf": relay_data.loopback_intf,
            "openconfig-relay-agent-ext:max-hop-count": relay_data.max_hop_count
            }
    }
    rest_url_datastore = st.get_datastore(vars.D2, "rest_urls")
    dhcp_relay_rest_update_url = rest_url_datastore["config_dhcp_relay_on_interface_v4"].format(relay_data.vlan_intf)
    st.log("Enable DHCP Relay agent with (link select, src-intf and max-hop-count) on interface {} using REST".format(relay_data.vlan_intf))
    res_update = config_rest(vars.D2, http_method="patch", rest_url=dhcp_relay_rest_update_url, json_data=data)
    if not res_update:
        st.error("Failed to update/enable DHCP Relay agent with (link select, src-intf and max-hop-count) on interface {} through REST".format(relay_data.vlan_intf))
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "FAILED")
    dhcp_relay_rest_get_url = rest_url_datastore["config_dhcp_relay_on_interface"].format(relay_data.vlan_intf)
    try:
        dhcp_relay_res_get_val = get_rest(vars.D2, http_method="get", rest_url=dhcp_relay_rest_get_url)
        ret_link_select_val = dhcp_relay_res_get_val['output'][u'openconfig-relay-agent:interface'][0][u'config'][u'openconfig-relay-agent-ext:link-select']
        ret_src_val= dhcp_relay_res_get_val['output'][u'openconfig-relay-agent:interface'][0][u'config'][u'openconfig-relay-agent-ext:src-intf']
        ret_max_hop_val = dhcp_relay_res_get_val['output'][u'openconfig-relay-agent:interface'][0][u'config'][u'openconfig-relay-agent-ext:max-hop-count']

        if not ret_link_select_val:
            report_flag = 1
            st.error("Link-select value is either incorrectly set or not updated/retrieved properly through REST GET call")
        if not ret_src_val.encode('UTF-8') == relay_data.loopback_intf:
            report_flag = 1
            st.error("src-intf value is either incorrectly set or not updated/retrieved properly through REST GET call")
        if not int(ret_max_hop_val) == relay_data.max_hop_count:
            report_flag = 1
            st.error("max-hop-count value is either incorrectly set or not updated/retrieved properly through REST GET call")
    except Exception as e:
        st.log(e)
        report_flag = 1
    st.log("Check whether client gets ipv4 address")
    dhcp_relay.dhcp_client_start(vars.D3, vars.D3D2P1)
    st.wait(2)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1, ip_ad = relay_data.relay_client_ip, network = relay_data.relay_client_ip_subnet):
        report_flag = 1
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
    st.log("Check the values are correctly set or not through REST GET call")
    st.log("Deleting the DHCP relay agent through REST")
    dhcp_relay_rest_delete_url = rest_url_datastore["config_helper_address_on_interface"].format(
        relay_data.vlan_intf)
    res_del = delete_rest(vars.D2, http_method="delete", rest_url=dhcp_relay_rest_delete_url)
    if res_del:
        if not res_del:
            report_flag = 1
            st.error("Failed to remove DHCP Relay agent config for {} through REST".format(vars.D2D3P1))
    else:
        report_flag = 1
    if report_flag:
        dhcp_relay_link_select_debug(vars.D2, interface=relay_data.vlan_intf)
        st.log("As REST delete call failed, removing the DHCP relay agent config using CLI ")
        dhcp_relay.dhcp_relay_config_remove(vars.D2, interface=relay_data.vlan_intf, IP=relay_data.dhcp_server_ip)
        st.report_fail("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "FAILED")
    st.report_pass("dhcp_relay_verification_rest_klish_status_default_vrf", "v4", "REST", "SUCCESS")

