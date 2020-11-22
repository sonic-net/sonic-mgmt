import pytest
from spytest import SpyTestDict, st
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.system.basic as basic_obj
import apis.routing.dhcp_relay as dhcp_relay_obj
from apis.switching.portchannel import get_portchannel_list
from apis.routing.arp import show_arp, show_ndp
import apis.system.reboot as rb_obj
from apis.qos.copp import bind_class_action_copp_policy
import utilities.utils as utils
from spytest.utils import poll_wait
import os


def initialize_variables():
    global data, vars
    data = SpyTestDict()
    vars = st.get_testbed_vars()
    data.vlan = 10
    data.vlan_int = "Vlan{}".format(data.vlan)
    data.dhcp_service_name = "isc-dhcp-server"
    data.RA_ipaddress_1 = '176.16.40.1'
    data.RA_ipaddress_2 = '192.168.0.2'
    data.RA_ipaddress_21 = '192.168.0.2/24'
    data.subnet = '24'
    data.family = 'ipv4'
    data.pool_ip_address = "192.168.2"
    data.wait_time_to_no_shut = 10
    data.dhcp_relay_params = vars.D2D1P1
    data.dhcp_server_ip = '176.16.40.210'
    data.dhcp_files = ['isc-dhcp-server', 'dhcpd.conf', 'dhcpd6.conf']
    data.dhcp_files_path = [os.path.join(os.path.dirname(__file__), data.dhcp_files[0]),
                            os.path.join(os.path.dirname(__file__), data.dhcp_files[1]),
                            os.path.join(os.path.dirname(__file__), data.dhcp_files[2])]
    data.dhcp_files_path = []
    for file in data.dhcp_files: data.dhcp_files_path.append(os.path.join(os.path.dirname(__file__), file))
    data.username = 'admin'
    data.route_list = ['192.168.0.0/24', '100.100.100.0/24', '200.200.200.0/24', '11.11.11.0/24', '110.110.110.0/24']


@pytest.fixture(scope="module", autouse=True)
def dhcp_relay_module_config(request):
    initialize_variables()
    vars = st.ensure_min_topology("D1D2:1", "D2D3:2")
    bind_class_action_copp_policy(vars.D3, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp')
    response = basic_obj.dhcp_server_config(vars.D1, dhcp_files_path=data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=data.dhcp_server_ip, route_list=data.route_list, ipv4_relay_agent_ip=data.RA_ipaddress_1)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "installation", "failed")
    connected_port_ip_address_config()
    if not basic_obj.check_interface_status(vars.D2, data.dhcp_relay_params, "up"):
        basic_obj.ifconfig_operation(vars.D2, data.dhcp_relay_params, "up")
    if not ip_obj.ping(vars.D2, data.dhcp_server_ip):
        st.log("Pinging to DHCP server failed from DUT, issue either with DUT or server")
        st.report_fail("ping_fail", data.dhcp_server_ip)
    basic_dhcp_relay_config_addition()
    yield
    response = basic_obj.dhcp_server_config(vars.D1, action="unconfig", dhcp_files_path=data.dhcp_files_path, server_port=vars.D1D2P1,
                       server_ipv4=data.dhcp_server_ip, route_list=data.route_list, ipv4_relay_agent_ip=data.RA_ipaddress_1)
    if not response:
        st.report_fail("service_operation_status", "isc-dhcp-server", "uninstallation", "failed")
    dhcp_relay_obj.dhcp_relay_config_remove(vars.D2, vlan=data.vlan_int, IP= data.dhcp_server_ip)
    ip_obj.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipaddress_1, data.subnet, family=data.family, config='remove')
    ip_obj.clear_ip_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    vlan_obj.clear_vlan_configuration(st.get_dut_names())




@pytest.fixture(scope="function", autouse=True)
def dhcp_relay_func_hooks(request):
    # Function configuration
    yield
    dhcp_relay_obj.dhcp_client_stop(vars.D3, vars.D3D2P1, family="ipv4", skip_error_check=True, show_interface=True)
    basic_obj.get_ps_aux(vars.D3, "dhclient")
    # Function cleanup


def basic_dhcp_relay_config_addition():
    data.vlan1 = "Vlan{}".format(data.vlan)
    st.log("Create VLAN and participate client connected interface in vlan")
    vlan_obj.create_vlan_and_add_members([{"dut": [vars.D2], "vlan_id": data.vlan, "untagged": [vars.D2D3P1]}])
    st.log("About to add IP address in RA DUT")
    ip_obj.config_ip_addr_interface(vars.D2, data.vlan1, data.RA_ipaddress_2, data.subnet, family=data.family, config='add')
    st.log("Add DHCP server address to vlan")
    dhcp_relay_obj.dhcp_relay_config_add(vars.D2, vlan=data.vlan1, IP=data.dhcp_server_ip)

def connected_port_ip_address_config():
    st.log("About to add IP address on port connected to DHCP server")
    ip_obj.config_ip_addr_interface(vars.D2, data.dhcp_relay_params, data.RA_ipaddress_1, data.subnet,
                                    family=data.family,
                                    config='add')

def check_dhcp_relay_config():
    if not dhcp_relay_obj.verify_dhcp_relay(vars.D2, "Vlan{}".format(data.vlan), data.dhcp_server_ip, family=data.family):
    # if not vlan_obj.verify_vlan_brief(vars.D2, data.vlan, ip_address=data.RA_ipaddress_21,
    #                                   dhcp_helper_add=data.dhcp_server_ip):
        st.report_fail("IP_Helper_address_config_failed", vars.D2)

# def check_dhcp_client():
#     dhcp_relay_obj.dhcp_client_start(vars.D3, vars.D3D2P1)
#     st.wait(5)
#     try:
#         pool_ip = ip_obj.get_interface_ip_address(vars.D3, interface_name=vars.D3D2P1, family="ipv4")
#         pool_ip = pool_ip[0]['ipaddr']
#     except Exception:
#         st.report_fail('IP_address_assignment_failed', vars.D3)
#     pool_ip = pool_ip.split("/")
#     pool_ip = pool_ip[0][-1]
#     st.log("offered_ip {}".format(pool_ip))
#     if not (int(pool_ip) in range(255)):
#         st.report_fail("IP_address_assignment_failed", vars.D3)

def dhcp_relay_debug(dut, family = "", interface=None):
    family = "ipv4" if not family else family
    st.banner("Start of Collecting the needed info for debugging the failure")
    try:
        get_portchannel_list(dut)
        interface.interface_status_show(dut)
        dhcp_relay_obj.dhcp_relay_detailed_show(dut)
        dhcp_relay_obj.get_dhcp_relay_statistics(dut, interface=interface)
        ip_obj.get_interface_ip_address(dut)
        show_arp(dut)
        if family == "ipv6":
            dhcp_relay_obj.dhcp_relay_detailed_show(dut, family = "ipv6")
            dhcp_relay_obj.get_dhcp_relay_statistics(dut, family = "ipv6", interface=interface)
            ip_obj.get_interface_ip_address(dut, family ="ipv6")
            show_ndp(dut)
    except Exception as e:
        st.log(e)
        st.error("Failed to execute the debug commands")
    st.banner("End of Collecting the needed info for debugging the failure")

def verify_dhcp_client(dut, interface_name, ip_ad="", network="", family =""):
    ip_ad = data.RA_ipaddress_2 if not ip_ad else ip_ad
    network = data.subnet if not network else network
    family = "ipv4" if not family else family
    client_ip = None
    try:
        if family == "ipv4":
            ip_details = basic_obj.get_ifconfig_inet(dut, interface_name)
            if ip_details:
                client_ip = ip_details[0].strip()
        elif family == "ipv6":
            ip_details = basic_obj.get_ifconfig_inet6(dut, interface_name)
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

def check_dhcp_relay_statistics():
    stats = dhcp_relay_obj.get_dhcp_relay_statistics(vars.D2,interface = "Vlan{}".format(data.vlan))
    pkts_relayed_server_to_client = stats[0]["bootreply_msgs_forwarded_by_the_relay_agent"]
    if  int(pkts_relayed_server_to_client) == int(0) :
        st.report_fail("packets_relayed_from_server_to_client_statistics_not_incremented")
    pkts_relayed_client_to_server = stats[0]["bootrequest_msgs_forwarded_by_the_relay_agent"]
    if int(pkts_relayed_client_to_server) == int(0):
        st.report_fail("packets_relayed_from_client_to_server_statistics_not_incremented")

@pytest.mark.regression
@pytest.mark.test_dhcp_relay_save_reboot
def test_dhcp_relay_save_reboot():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the configuration is reatined post reboot.
    #
    #################################################
    st.log("Performing Config save")
    rb_obj.config_save(vars.D2)
    st.log("Performing Reboot")
    st.reboot(vars.D2)
    st.log("Verifying DHCP Helper configuration post reboot")
    check_dhcp_relay_config()
    dhcp_relay_obj.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan))
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.log("Verifying DHCP Relay statistics in dhcp client post cold reboot")
    check_dhcp_relay_statistics()
    st.log("Successfully verified DHCP Helper configuration is retained post reboot")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.test_dhcp_relay_config
def test_dhcp_relay_config():
    #################################################
    #
    # Objective - Verify that ip dhcp relay config is applied fine when configured from config_db.json file.
    #
    #################################################
    test_dhcp_relay_save_reboot()
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.test_dhcp_relay_fast_reboot
def test_dhcp_relay_fast_reboot():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the configuration is retained after fast reboot.
    #
    #################################################
    st.log("Performing Config save")
    rb_obj.config_save(vars.D2)
    st.log("Performing fast Reboot")
    st.reboot(vars.D2, "fast")
    st.wait(5)
    st.log("Verifying DHCP Helper configuration post reboot")
    check_dhcp_relay_config()
    dhcp_relay_obj.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan))
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.log("Verifying DHCP Relay statistics in dhcp client post fast reboot")
    check_dhcp_relay_statistics()
    st.log("Successfully verified DHCP Helper configuration is retained post reboot")
    st.report_pass("test_case_passed")


def docker_restart_test():

    st.log("Performing Config save")
    rb_obj.config_save(vars.D2)

    #check the docker part
    st.log("DHCP relay docker restart")
    basic_obj.service_operations_by_systemctl(vars.D2, "dhcp_relay.service", "restart")
    st.log("Wait for DHCP relay docker restart")
    if not basic_obj.poll_for_system_status(vars.D2, 'dhcp_relay.service', 120, 3):
        st.report_fail("service_not_running", "dhcp-relay")
    if not st.poll_wait(basic_obj.verify_service_status,60,vars.D2, "dhcp_relay"):
        st.report_fail("docker_restart_failed")
    st.log("Verifying DHCP Helper configuration post Docker Restart")
    check_dhcp_relay_config()
    dhcp_relay_obj.dhcp_client_start(vars.D3, vars.D3D2P1)
    if not poll_wait(verify_dhcp_client, 60, vars.D3, vars.D3D2P1):
        dhcp_relay_debug(vars.D2, interface="Vlan{}".format(data.vlan))
        st.report_fail("dhcp_relay_functionality_tc_status", "IPv4", "failed", "vlan")
    st.report_pass("test_case_passed")

#RtDhReL3Fn031
def test_dhcp_helper_docker_restart():
    docker_restart_test()

@pytest.mark.regression
@pytest.mark.test_dhcp_relay_warm_reboot
def test_dhcp_relay_warm_reboot():
    #################################################
    #
    # Objective - Configure DHCP relay and verify if the configuration is retained after warm reboot.
    #
    #################################################
    data.platform = basic_obj.get_hwsku(vars.D2)
    data.constants = st.get_datastore(vars.D2, "constants", 'default')
    st.log("OUTPUT:{}".format(data.constants))
    if not data.platform.lower() in data.constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        st.report_fail('test_case_unsupported')
    st.log("Performing Config save")
    rb_obj.config_save(vars.D2)
    st.log("Performing warm Reboot")
    st.reboot(vars.D2, "warm")
    if not basic_obj.poll_for_system_status(vars.D2, 'dhcp_relay.service', 120, 1):
        st.report_fail("service_not_running", "dhcp-relay")
    if not st.poll_wait(basic_obj.verify_service_status,60,vars.D2, "dhcp_relay"):
        st.log("DHCP relay service not running")
    st.log("Verifying DHCP Helper configuration post reboot")
    check_dhcp_relay_config()
    dhcp_relay_obj.dhcp_client_start(vars.D3, vars.D3D2P1)
    if ip_obj.verify_interface_ip_address(vars.D3, vars.D3D2P1, data.pool_ip_address, family="ipv4", vrfname=''):
        st.report_fail("IP_address_assignment_failed", vars.D3)
    st.log("Successfully verified DHCP Helper configuration is retained after warm reboot")
    st.report_pass("test_case_passed")
