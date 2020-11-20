import pytest
import os
from spytest import st
from spytest.utils import random_vlan_list
from spytest.dicts import SpyTestDict
import apis.security.radius as radius
import apis.security.tacacs as security
import apis.system.connection as ssh
import apis.system.basic as basic
import apis.security.user as user
import apis.routing.ip as ip
import apis.switching.vlan as vlan_obj
from utilities.utils import ensure_service_params
from utilities.parallel import ensure_no_exception
from apis.system.connection import connect_to_device
import utilities.common as common_utils
import apis.system.management_vrf as mvrf
from apis.system.basic import get_ifconfig_inet
from utilities.common import poll_wait
import apis.system.interface as interface
from utilities.parallel import exec_parallel, exec_all, exec_foreach
from apis.security.rbac import ssh_call
from apis.switching.vlan import clear_vlan_configuration
import apis.routing.vrf as vrf
from apis.system.ssh import enable_ssh_in_user_vrf
from apis.system.gnmi import gnmi_set, gnmi_get
from apis.system.ssh import get_ssh_server_vrf
import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj
from apis.system.rest import config_rest, get_rest
import apis.switching.portchannel as pc_obj

radius_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def radius_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:4")
    radius_variables()

    radius_module_prolog()
    yield
    radius_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def radius_func_hooks(request):
    if st.get_func_name(request) == 'test_ft_radius_ssh_mgmt_vrf':
        radius_with_mgmt(action='add')
        enable_ssh_in_user_vrf(vars.D1, config='add', vrf_name="mgmt")
    elif st.get_func_name(request) == 'test_ft_radius_ssh_login_ipv6_unnumbered':
        getting_link_local_ipv6()
        creating_ipv6_radius_link_local()
    elif st.get_func_name(request) == "test_ft_radius_ssh_login_ipv4_unnumbered":
        configure_unnumbered_interface(action="add")
        configure_static_route()
        ipv4_radius_unnumbered(action="add")
    elif st.get_func_name(request) == 'test_ft_radius_ssh_login_ipv6_server':
        radius.config_global_server_params(vars.D2, skip_error_check=False,
                                           params={"key": {"value": radius_data.global_passkey, "no_form": True},
                                                   "timeout": {"value": radius_data.global_timeout, "no_form": True},
                                                   "auth_type": {"value": radius_data.global_auth_type,
                                                                 "no_form": True},
                                                   "retransmit": {"value": radius_data.global_retransmit,
                                                                  "no_form": True},
                                                   "source_ip": {"value": radius_data.ipv6_source_ip, "no_form": True}})
        dict1 = {'loop_back': radius_data.loopback_name, 'action': 'del', 'interface': vars.D1D2P2}
        dict2 = {'loop_back': radius_data.loopback_name, 'action': 'del', 'interface': vars.D2D1P2}
        exceptions = exec_parallel(True, [vars.D1, vars.D2], ip.config_unnumbered_interface, [dict1, dict2])[1]
        ensure_no_exception(exceptions)

        dict1 = {'interface_name': vars.D1D2P1, 'ip_address': radius_data.dut1_ipv6_address,
                 'subnet': radius_data.ipv6_subnet, 'family': "ipv6"}
        dict2 = {'interface_name': vars.D2D1P1, 'ip_address': radius_data.dut2_ipv6_address,
                 'subnet': radius_data.ipv6_subnet, 'family': "ipv6"}
        exceptions = exec_parallel(True, [vars.D1, vars.D2], ip.delete_ip_interface, [dict1, dict2])[1]
        ensure_no_exception(exceptions)
        data = {vars.D1: {"interface": vars.D1D2P3, "action": "disable", "family": "ipv4"},
                vars.D2: {"interface": vars.D2D1P3, "action": "disable", "family": "ipv4"}}
        [_, exceptions] = common_utils.exec_foreach(True, [vars.D1, vars.D2], clear_v4_v6_link_local_addresses, data)
        if not ensure_no_exception(exceptions):
            st.report_fail("exception_observed", exceptions)
        vrf_config(config='yes')
        enable_ssh_in_user_vrf(vars.D1, config='add', vrf_name=radius_data.ipv6_user_vrf)
        get_ssh_server_vrf(vars.D1, vrf_name=radius_data.ipv6_user_vrf)
    elif st.get_func_name(request) == 'test_ft_ssh_radius_gnmi':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
    elif st.get_func_name(request) == 'test_ft_nas_ip_statistics_ipv6':
        if not radius.config_server(vars.D1, ip_address=radius_data.host_ip, key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, action="add"):
            st.log("server is not configured with proper ip")
        if not security.set_aaa_authentication_properties(vars.D1, 'login', radius_data.aaa_login_local_radius):
            st.report_fail("authentication_login_config_fail")
        if not security.set_aaa_authentication_properties(vars.D1, 'failthrough', radius_data.aaa_failthrough_enable):
            st.report_fail("authentication_failthrough_config_fail")
        if not radius.config_global_server_params(vars.D1, skip_error_check=False,
                                                  params={"nasip": {"value": radius_data.dut1_ipv6_address},
                                                          "statistics": {"value": "enable"}}):
            st.log("configuration of global server parameters nasip, statistics and server failed ")
            st.report_fail("radius_global_params_config_failed")
    elif st.get_func_name(request) == 'test_ft_nas_ip_statistics_ipv4':
        if not radius.config_server(vars.D1, ip_address=radius_data.host_ip, key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, action="add"):
            st.log("server is not configured with proper ip")
        if not security.set_aaa_authentication_properties(vars.D1, 'login', radius_data.aaa_login_local_radius):
            st.report_fail("authentication_login_config_fail")
        if not radius.config_global_server_params(vars.D1, skip_error_check=False,
                                                  params={"nasip": {"value": radius_data.loopback_dut1},
                                                          "statistics": {"value": "enable"}}):
            st.log("configuration of global server parameters like nasip, statistics and server failed ")
            st.report_fail("radius_global_params_config_failed")
    elif st.get_func_name(request) == 'test_ft_source_intf_mgmt':
        radius.config_server(vars.D2, no_form=True, ip_address=[host.ip for host in radius_data.hosts], action="delete")
        if not security.set_aaa_authentication_properties(vars.D2, 'login', radius_data.aaa_login_local_radius):
            st.report_fail("authentication_login_config_fail")
        if not radius.config_server(vars.D2, ip_address=radius_data.host_ip, key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, source_intf=radius_data.source_interface[0],
                                    action="add"):
            st.log("server is not configured with proper ip")
    elif st.get_func_name(request) == 'test_ft_source_intf_Ethernet':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        basic_obj.config_radius_server(vars.D1, config_files_path=radius_data.radius_files_path, action="config")
        if not security.set_aaa_authentication_properties(vars.D2, 'login', radius_data.aaa_login_local_radius):
            st.report_fail("authentication_login_config_fail")
        ip.config_ip_addr_interface(vars.D2, vars.D2D1P4, radius_data.ip4_addr[0], 24, family=radius_data.ipv4)
        ip.config_ip_addr_interface(vars.D1, vars.D1D2P4, radius_data.ip4_addr[1], 24, family=radius_data.ipv4)
        if not radius.config_server(vars.D2, ip_address=radius_data.ip4_addr[1], key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, source_intf=radius_data.source_interface[1],
                                    action="add"):
            st.log("server is not configured with proper ip")
    elif st.get_func_name(request) == 'test_ft_source_intf_portchannel':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        pc_obj.create_portchannel(vars.D2, radius_data.port_channel)
        pc_obj.create_portchannel(vars.D1, radius_data.port_channel)
        pc_obj.add_portchannel_member(vars.D1, radius_data.port_channel, vars.D1D2P4)
        pc_obj.add_portchannel_member(vars.D2, radius_data.port_channel, vars.D2D1P4)
        ip.config_ip_addr_interface(vars.D2, radius_data.port_channel, radius_data.ip4_addr[0], 24,
                                    family=radius_data.ipv4)
        ip.config_ip_addr_interface(vars.D1, radius_data.port_channel, radius_data.ip4_addr[1], 24,
                                    family=radius_data.ipv4)
        basic_obj.config_radius_server(vars.D1, config_files_path=radius_data.radius_files_path, action="config")
        if not radius.config_server(vars.D2, ip_address=radius_data.ip4_addr[1], key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, source_intf=radius_data.source_interface[2],
                                    action="add"):
            st.log("server is not configured with proper ip")
    elif st.get_func_name(request) == 'test_ft_source_intf_loopback':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        basic_obj.config_radius_server(vars.D1, config_files_path=radius_data.radius_files_path, action="config")
        ip.configure_loopback(vars.D2, loopback_name='Loopback1', config="yes")
        ip.config_ip_addr_interface(vars.D2, 'Loopback1', radius_data.ip4_addr[2], 32, family=radius_data.ipv4)
        ip.config_ip_addr_interface(vars.D2, vars.D2D1P4, radius_data.ip4_addr[0], 24, family=radius_data.ipv4)
        ip.config_ip_addr_interface(vars.D1, vars.D1D2P4, radius_data.ip4_addr[1], 24, family=radius_data.ipv4)
        ip.create_static_route(vars.D1, next_hop=radius_data.ip4_addr[0], static_ip=radius_data.static_ip,
                               shell="vtysh", family='ipv4', interface=None, vrf=None)
        if not radius.config_server(vars.D2, ip_address=radius_data.ip4_addr[1], key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, source_intf=radius_data.source_interface[3],
                                    action="add"):
            st.log("server is not configured with proper ip")
    elif st.get_func_name(request) == 'test_ft_source_intf_vlan':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        basic_obj.config_radius_server(vars.D1, config_files_path=radius_data.radius_files_path, action="config")
        vlan_obj.create_vlan(vars.D1, radius_data.vlan_1)
        vlan_obj.create_vlan(vars.D2, radius_data.vlan_1)
        vlan_obj.add_vlan_member(vars.D1, radius_data.vlan_1, [vars.D1D2P4], tagging_mode=True)
        vlan_obj.add_vlan_member(vars.D2, radius_data.vlan_1, [vars.D2D1P4], tagging_mode=True)
        ip.config_ip_addr_interface(vars.D2, radius_data.vlan_int_1, radius_data.ip4_addr[0], 24,
                                    family=radius_data.ipv4)
        ip.config_ip_addr_interface(vars.D1, radius_data.vlan_int_1, radius_data.ip4_addr[1], 24,
                                    family=radius_data.ipv4)
        if not radius.config_server(vars.D2, ip_address=radius_data.ip4_addr[1], key=radius_data.host_passkey,
                                    priority=radius_data.host_priority, source_intf=radius_data.source_interface[4],
                                    action="add"):
            st.log("server is not configured with proper ip")
    yield
    if st.get_func_name(request) == 'test_ft_radius_ssh_mgmt_vrf':
        mvrf.config(vars.D1, no_form=True)
        enable_ssh_in_user_vrf(vars.D1, config='del', vrf_name="mgmt")
        if not poll_wait(get_ifconfig_inet, 50, vars.D1, 'eth0'):
            st.log("IP Address not found on eth0 after prologue")
            st.report_fail("mgmt_vrf_eth0_bind_fail")
        radius_with_mgmt(action='delete')
    elif st.get_func_name(request) == 'test_ft_radius_ssh_login_ipv6_unnumbered':
        deleting_ipv6_radius_link_local()
    elif st.get_func_name(request) == 'test_ft_radius_ssh_login_ipv4_unnumbered':
        ipv4_radius_unnumbered(action="delete")
    elif st.get_func_name(request) == 'test_ft_ssh_local_radius':
        user.config_user(vars.D2, radius_data.host_username, mode='del')
    elif st.get_func_name(request) == 'test_ft_radius_ssh_login_ipv6_server':
        enable_ssh_in_user_vrf(vars.D1, config='del', vrf_name=radius_data.ipv6_user_vrf)
        vrf.bind_vrf_interface(vars.D1, config='no', vrf_name=radius_data.ipv6_user_vrf, intf_name=vars.D1D2P1)
        vrf_config(config='no')
        data = {vars.D1: {"v6_interface": vars.D1D2P1, "v6_address": radius_data.dut1_ipv6_address,
                          "v4_interface": radius_data.loopback_name, "v4_address": radius_data.loopback_dut1,
                          "link_local_interface": vars.D1D2P3},
                vars.D2: {"v6_interface": vars.D2D1P1, "v6_address": radius_data.dut2_ipv6_address,
                          "v4_interface": radius_data.loopback_name, "v4_address": radius_data.loopback_dut2,
                          "link_local_interface": vars.D2D1P3}
                }
        [_, exceptions] = common_utils.exec_foreach(True, [vars.D1, vars.D2], configure_v6_v4_link_local_address, data)
        if not ensure_no_exception(exceptions):
            debug_info("ping_check")
            st.report_fail("exception_observed", exceptions)
    elif st.get_func_name(request) == 'test_ft_ssh_radius_rest':
            radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
    elif st.get_func_name(request) == "test_ft_nas_ip_statistics_ipv6":
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        radius.config_global_server_params(vars.D2, skip_error_check=False,
                                           params={"nasip": {"value": "nasip", "no_form": True}})
        radius.clear_radius_statistics(vars.D1)
        radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="debug", action="disable")
        radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="trace", action="disable")
    elif st.get_func_name(request) == "test_ft_nas_ip_statistics_ipv4":
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
        radius.config_global_server_params(vars.D2, skip_error_check=False,
                                           params={"nasip": {"value": "nasip", "no_form": True}})
        radius.clear_radius_statistics(vars.D1)
        radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="debug", action="disable")
        radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="trace", action="disable")
    elif st.get_func_name(request) == 'test_ft_source_intf_mgmt':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.host_ip, action="delete")
    elif st.get_func_name(request) == 'test_ft_source_intf_Ethernet':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.ip4_addr[1], action="delete")
        ip.config_ip_addr_interface(vars.D2, vars.D2D1P4, radius_data.ip4_addr[0], 24, family=radius_data.ipv4,
                                    config='remove')
        ip.config_ip_addr_interface(vars.D1, vars.D1D2P4, radius_data.ip4_addr[1], 24, family=radius_data.ipv4,
                                    config='remove')
    elif st.get_func_name(request) == 'test_ft_source_intf_portchannel':
        radius.config_server(vars.D2, ip_address=radius_data.ip4_addr[1], action="delete")
        ip.config_ip_addr_interface(vars.D2, radius_data.port_channel, radius_data.ip4_addr[0], 24,
                                    family=radius_data.ipv4, config='remove')
        ip.config_ip_addr_interface(vars.D1, radius_data.port_channel, radius_data.ip4_addr[1], 24,
                                    family=radius_data.ipv4, config='remove')
        pc_obj.clear_portchannel_configuration(st.get_dut_names())
    elif st.get_func_name(request) == 'test_ft_source_intf_loopback':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.ip4_addr[1], action="delete")
        ip.delete_static_route(vars.D1, next_hop=radius_data.ip4_addr[0], static_ip=radius_data.static_ip,
                               family='ipv4', shell="vtysh", interface=None, vrf=None)
        ip.config_ip_addr_interface(vars.D2, 'Loopback1', radius_data.ip4_addr[2], 32, family=radius_data.ipv4,
                                    config='remove')
        ip.configure_loopback(vars.D2, loopback_name='Loopback1', config="no")
        ip.config_ip_addr_interface(vars.D2, vars.D2D1P4, radius_data.ip4_addr[0], 24, family=radius_data.ipv4,
                                    config='remove')
        ip.config_ip_addr_interface(vars.D1, vars.D1D2P4, radius_data.ip4_addr[1], 24, family=radius_data.ipv4,
                                    config='remove')
    elif st.get_func_name(request) == 'test_ft_source_intf_vlan':
        radius.config_server(vars.D2, no_form=True, ip_address=radius_data.ip4_addr[1], action="delete")
        ip.config_ip_addr_interface(vars.D2, radius_data.vlan_int_1, radius_data.ip4_addr[0], 24,
                                    family=radius_data.ipv4, config='remove')
        ip.config_ip_addr_interface(vars.D1, radius_data.vlan_int_1, radius_data.ip4_addr[1], 24,
                                    family=radius_data.ipv4, config='remove')


def radius_variables():
    radius_data.clear()
    radius_data.hosts = ensure_service_params(vars.D2, "radius", "hosts")
    radius_data.host_ip = ensure_service_params(vars.D2, "radius", "hosts", 0, "ip")
    radius_data.host_username = ensure_service_params(vars.D2, "radius", "hosts", 0, "username")
    radius_data.host_password = ensure_service_params(vars.D2, "radius", "hosts", 0, "password")
    radius_data.host_timeout = ensure_service_params(vars.D2, "radius", "hosts", 0, "timeout")
    radius_data.host_auth_type = ensure_service_params(vars.D2, "radius", "hosts", 0, "auth_type")
    radius_data.host_udp_port = ensure_service_params(vars.D2, "radius", "hosts", 0, "udp_port")
    radius_data.host_passkey = ensure_service_params(vars.D2, "radius", "hosts", 0, "passkey")
    radius_data.host_priority = ensure_service_params(vars.D2, "radius", "hosts", 0, "priority")
    radius_data.local_username = ensure_service_params(vars.D2, "radius", "local", "username")
    radius_data.local_password = ensure_service_params(vars.D2, "radius", "local", "password")
    radius_data.global_passkey = ensure_service_params(vars.D2, "radius", "globals", 0, "passkey")
    radius_data.global_diff_passkey = ensure_service_params(vars.D2, "radius", "globals", 1, "passkey")
    radius_data.global_source_ip = ensure_service_params(vars.D2, "radius", "globals", 0, "source_ip")
    radius_data.global_auth_type = ensure_service_params(vars.D2, "radius", "globals", 0, "auth_type")
    radius_data.global_auth_type_mschapv2 = ensure_service_params(vars.D2, "radius", "globals", 0, "auth_type_mschapv2")
    radius_data.global_auth_type_chap = ensure_service_params(vars.D2, "radius", "globals", 1, "auth_type_chap")
    radius_data.global_timeout = ensure_service_params(vars.D2, "radius", "globals", 0, "timeout")
    radius_data.global_retransmit = ensure_service_params(vars.D2, "radius", "globals", 0, "retransmit")
    radius_data.aaa_login_radius = ensure_service_params(vars.D2, "radius", "aaa", 0, "login_radius")
    radius_data.aaa_login_local = ensure_service_params(vars.D2, "radius", "aaa", 0, "login_local")
    radius_data.aaa_login_default = ensure_service_params(vars.D2, "radius", "aaa", 0, "login_default")
    radius_data.aaa_failthrough_enable = ensure_service_params(vars.D2, "radius", "aaa", 0, "failthrough_enable")
    radius_data.aaa_failthrough_disable = ensure_service_params(vars.D2, "radius", "aaa", 0, "failthrough_disable")
    radius_data.aaa_failthrough_default = ensure_service_params(vars.D2, "radius", "aaa", 0, "failthrough_default")
    radius_data.aaa_fallback_enable = ensure_service_params(vars.D2, "radius", "aaa", 0, "fallback_enable")
    radius_data.aaa_fallback_disable = ensure_service_params(vars.D2, "radius", "aaa", 0, "fallback_disable")
    radius_data.aaa_fallback_default = ensure_service_params(vars.D2, "radius", "aaa", 0, "fallback_default")
    radius_data.invalid_username = ensure_service_params(vars.D2, "radius", "invalid", "username")
    radius_data.invalid_password = ensure_service_params(vars.D2, "radius", "invalid", "password")
    radius_data.aaa_login_local_radius = ensure_service_params(vars.D2, "radius", "aaa", 1, 'login_local_radius')
    radius_data.aaa_login_radius_local = ensure_service_params(vars.D2, "radius", "aaa", 1, 'login_radius_local')
    radius_data.dut1_ipv6_address = "1001::1"
    radius_data.dut2_ipv6_address = "1001::2"
    radius_data.dut1_ipv4_address = "192.168.1.1/32"
    radius_data.dut2_ipv4_address = "192.168.1.2/32"
    radius_data.ipv6_subnet = "64"
    radius_data.ipv4_subnet = "32"
    radius_data.loopback_dut1 = "192.168.1.1"
    radius_data.loopback_dut2 = "192.168.1.2"
    radius_data.radius_nss = ensure_service_params(vars.D2, "radius", "radius_conf_files", "path")
    radius_data.radius_nss_bkp = ensure_service_params(vars.D2, "radius", "radius_conf_files", "backup_path")
    radius_data.root_username = ensure_service_params(vars.D2, "radius", "root_credentials", "username")
    radius_data.root_password = ensure_service_params(vars.D2, "radius", "root_credentials", "password")
    radius_data.invalid_passkey = ensure_service_params(vars.D2, "radius", "invalid_passkey", "invalid_passkey")
    radius_data.ipv4_source_ip = ensure_service_params(vars.D2, "radius", "source_ip", "ipv4")
    radius_data.ipv6_source_ip = ensure_service_params(vars.D2, "radius", "source_ip", "ipv6")
    radius_data.radius_logs_path = ensure_service_params(vars.D2, "radius", "logs_path", "path")
    radius_data.cisco_acs_ip = ensure_service_params(vars.D2, "radius", "cisco_acs_server", "ip")
    radius_data.cisco_acs_username = ensure_service_params(vars.D2, "radius", "cisco_acs_server", "username")
    radius_data.cisco_acs_password = ensure_service_params(vars.D2, "radius", "cisco_acs_server", "password")
    radius_data.cisco_acs_passkey = ensure_service_params(vars.D2, "radius", "cisco_acs_server", "passkey")
    radius_data.host_mgmt = "mgmt"
    radius_data.max_sessions = 50
    radius_data.free_memory = 200000
    radius_data.group = "nogroup"
    radius_data.loopback_name = "Loopback0"
    radius_data.ipv6 = "ipv6"
    radius_data.ipv4 = "ipv4"
    radius_data.fail = "fail"
    radius_data.success = "success"
    radius_data.rw_user = {'username': radius_data.host_username,
                           'password': radius_data.host_password,
                           'mode': 'rw'}
    radius_data.ro_username = ensure_service_params(vars.D2, "radius", "ro_user", "username")
    radius_data.ro_password = ensure_service_params(vars.D2, "radius", "ro_user", "password")
    radius_data.YANG_MODEL = "sonic-system-radius:sonic-system-radius"
    radius_data.host_ipv6 = ensure_service_params(vars.D2, "radius", "hosts", 6, "ip")
    radius_data.ipv6_user_vrf = 'Vrf_1'
    radius_data.nas_sever_username = "test"
    radius_data.nas_server_pass = "test"
    radius_data.ip4_addr = ['10.10.10.1', '10.10.10.2', '10.12.12.12']
    radius_data.port_channel = 'PortChannel1'
    radius_data.static_ip = '10.12.12.12/32'
    radius_data.config_files = ["users", "clients.conf"]
    radius_data.radius_files_path = [os.path.join(os.path.dirname(__file__), radius_data.config_files[0]),
                                     os.path.join(os.path.dirname(__file__), radius_data.config_files[1])]
    radius_data.radius_files_path = []
    for file in radius_data.config_files: radius_data.radius_files_path.append(
        os.path.join(os.path.dirname(__file__), file))
    radius_data.vlan_1 = str(random_vlan_list()[0])
    radius_data.vlan_int_1 = "Vlan{}".format(radius_data.vlan_1)
    radius_data.source_interface = ['Management0', vars.D2D1P4, 'PortChannel1', 'Loopback1', radius_data.vlan_int_1]


def radius_module_prolog():
    if user.verify(vars.D2, 'user_list', verify_list=[radius_data.host_username]):
        user.config_user(vars.D2, radius_data.host_username, mode='del')
    st.log("Getting IP address of the DUT")
    ensure_device_ipaddress()
    st.log("Creating backup file {} for {} file".format(radius_data.radius_nss_bkp, radius_data.radius_nss))
    basic.copy_file_to_local_path(vars.D2, radius_data.radius_nss, radius_data.radius_nss_bkp)
    st.log("Enabling failthrough mode for AAA")
    if not security.set_aaa_authentication_properties(vars.D2, 'failthrough', radius_data.aaa_failthrough_enable):
        st.report_fail("authentication_failthrough_config_fail")
    st.log("Configuring global radius parameters")
    config_global_radius()
    configure_max_servers()
    modify_radius_nss_conf()
    root_password_change()
    config_loop_back_interface(action="yes")
    data = {vars.D1: {"v6_interface": vars.D1D2P1, "v6_address": radius_data.dut1_ipv6_address,
                      "v4_interface": radius_data.loopback_name, "v4_address": radius_data.loopback_dut1,
                      "link_local_interface": vars.D1D2P3},
            vars.D2: {"v6_interface": vars.D2D1P1, "v6_address": radius_data.dut2_ipv6_address,
                      "v4_interface": radius_data.loopback_name, "v4_address": radius_data.loopback_dut2,
                      "link_local_interface": vars.D2D1P3}
            }
    [_, exceptions] = common_utils.exec_foreach(True, [vars.D1, vars.D2], configure_v6_v4_link_local_address, data)
    if not ensure_no_exception(exceptions):
        debug_info("ping_check")
        st.report_fail("exception_observed", exceptions)


def radius_module_epilog():
    debug_info("module_epilog")
    st.log("Making aaa authentication parameters to default")
    making_aaa_params_to_default()
    st.log("Making radius global params to default")
    radius.config_global_server_params(vars.D2, skip_error_check=False,
                                       params={"key": {"value": radius_data.global_passkey, "no_form": True},
                                               "timeout": {"value": radius_data.global_timeout, "no_form": True},
                                               "auth_type": {"value": radius_data.global_auth_type, "no_form": True},
                                               "retransmit": {"value": radius_data.global_retransmit, "no_form": True},
                                               "source_ip": {"value": radius_data.ipv6_source_ip, "no_form": True}})
    data = {vars.D1: {"interface": vars.D1D2P3, "action": "disable", "family": "all"},
            vars.D2: {"interface": vars.D2D1P3, "action": "disable", "family": "all"}}
    [_, exceptions] = common_utils.exec_foreach(True, [vars.D1, vars.D2], clear_v4_v6_link_local_addresses, data)
    if not ensure_no_exception(exceptions):
        st.report_fail("exception_observed", exceptions)
    config_loop_back_interface(action="no")
    st.log("Copying {} file to {} file".format(radius_data.radius_nss_bkp, radius_data.radius_nss))
    basic.copy_file_to_local_path(vars.D2, radius_data.radius_nss_bkp, radius_data.radius_nss)
    user.config_user(vars.D2, radius_data.host_username, mode='del')
    clear_vlan_configuration([vars.D2, vars.D1])
    basic_obj.config_radius_server(vars.D1, action="unconfig")
    radius.config_server(vars.D2, no_form=True, ip_address=[host.ip for host in radius_data.hosts], action="delete")


def vrf_config(config='yes'):
    ip_obj.config_ipv6(vars.D1)
    if config == 'yes':
        vrf.config_vrf(vars.D1, vrf_name=radius_data.ipv6_user_vrf, config=config)
        vrf.bind_vrf_interface(vars.D1, vrf_name=radius_data.ipv6_user_vrf, intf_name=vars.D1D2P1, config=config)
    elif config == 'no':
        vrf.config_vrf(vars.D1, vrf_name=radius_data.ipv6_user_vrf, config=config)
    else:
        st.report_fail("invalid_config")


def configure_max_servers():
    st.log("Configuring maximum supported servers on the device")
    for i in range(0, 8):
        ip_addr = ensure_service_params(vars.D2, "radius", "hosts", i, "ip")
        pass_key = ensure_service_params(vars.D2, "radius", "hosts", i, "passkey")
        priority = ensure_service_params(vars.D2, "radius", "hosts", i, "priority")
        radius.config_server(vars.D2, ip_address=ip_addr, key=pass_key, priority=priority, action="add")


def deleting_reachable_servers():
    for i in range(0, 8):
        ip_addr = ensure_service_params(vars.D2, "radius", "hosts", i, "ip")
        st.log("Reachability check start for the server {}".format(ip_addr))
        if ip.ping(vars.D2, ip_addr):
            radius.config_server(vars.D2, no_form=True, ip_address=ip_addr, action="delete")
        st.log("Reachability check end")


def configuring_login_method(type):
    if type == radius_data.aaa_login_radius_local:
        st.log("Configuring authentication login parameter to Radius local")
        if not security.set_aaa_authentication_properties(vars.D2, 'login', radius_data.aaa_login_radius_local):
            st.report_fail("authentication_login_config_fail")
    elif type == radius_data.aaa_login_local_radius:
        st.log("Configuring authentication login parameter to local Radius")
        if not security.set_aaa_authentication_properties(vars.D2, 'login', radius_data.aaa_login_local_radius):
            st.report_fail("authentication_login_config_fail")
    else:
        st.report_fail("invalid_login_type")


def verfiying_max_servers_config():
    for i in range(0, 8):
        ip_addr = ensure_service_params(vars.D2, "radius", "hosts", i, "ip")
        if not radius.show_config(vars.D2, search_string=ip_addr):
            st.report_fail("radius_server_config_failed", ip_addr)


def creating_local_user():
    st.log("Creating local user which is present in the radius server")
    if not user.config_user(vars.D2, radius_data.host_username, mode='add'):
        st.report_fail("local_user_creation_failed", radius_data.host_username)
    if not st.change_passwd(vars.D2, radius_data.host_username, radius_data.host_password):
        st.report_fail("password_config_failed")


def clear_v4_v6_link_local_addresses(dut, data):
    st.log("Clearing IPV4 and IPV6 addresses on back to back links on both the devices")
    ip.clear_ip_configuration(dut, family=data[dut]["family"], thread=False)
    st.log("Disabling IPV6 link local on both the devices to clear the automatically generated addressess")
    if not ip.config_interface_ip6_link_local(dut, data[dut]["interface"], data[dut]["action"]):
        st.report_fail("ip6_disable_link_local_failed", data[dut]["interface"])


def debug_info(test_case):
    if test_case == "test_ft_radius_login":
        st.log("Checking radius server is reachable or not from the device")
        radius_server_reachablity_check(vars.D2, radius_data.host_ip)
        checking_radius_config(radius_data.host_ip)
    if test_case == "test_ft_ssh_cisco_acs":
        st.log("Checking CISCO ACS server is reachable or not from the device")
        radius_server_reachablity_check(vars.D2, radius_data.cisco_acs_ip)
    if test_case == "test_ft_radius_ssh_login_ipv6_unnumbered":
        st.log("Checking link local address reachability")
        link_local_rechablility()


def verify_radius_default_config(dut):
    st.log("Verify that authentication login parameters should be default configs")
    if not security.verify_aaa(dut, 'local (default)', 'False (default)'):
        st.report_fail("authentication_default_configs_fail")


def ensure_device_ipaddress():
    radius_data.ip_address_list = basic.get_ifconfig_inet(vars.D2, 'eth0')
    if not radius_data.ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")
    radius_data.ip_address = radius_data.ip_address_list[0]
    radius_data.ipv4_source_ip = radius_data.ip_address


def radius_server_reachablity_check(dut, radius_server_ip):
    st.log("Reachability check start")
    if not ip.ping(dut, radius_server_ip):
        st.report_fail("ping_to_radius_server_is_not_successful", radius_server_ip)
    st.log("Reachability check end")


def auth_type_config(auth_type):
    if auth_type == radius_data.global_auth_type_chap:
        if not radius.config_global_server_params(vars.D2, skip_error_check=False,
                                                  params={"auth_type": {"value": radius_data.global_auth_type_chap}}):
            st.report_fail("auth_type_config_failed", radius_data.global_auth_type_chap)
    elif auth_type == radius_data.global_auth_type_mschapv2:
        if not radius.config_global_server_params(vars.D2, skip_error_check=False, params={
            "auth_type": {"value": radius_data.global_auth_type_mschapv2}}):
            st.report_fail("auth_type_config_failed", radius_data.global_auth_type_mschapv2)
    else:
        st.report_fail("invalid_auth_type_configured")


def config_global_radius():
    if not radius.config_global_server_params(vars.D2, skip_error_check=False,
                                              params={"key": {"value": radius_data.global_passkey},
                                                      "auth_type": {"value": radius_data.global_auth_type},
                                                      "timeout": {"value": radius_data.global_timeout},
                                                      "retransmit": {"value": radius_data.global_retransmit},
                                                      "source_ip": {"value": radius_data.ipv4_source_ip}}):
        st.report_fail("radius_global_params_config_failed")


def checking_radius_config(ip):
    if not radius.verify_config(vars.D2, params={"servers": [{'address': ip}]}):
        st.report_fail("radius_server_config_failed", ip)


def configure_v6_v4_link_local_address(dut, data):
    """
    :param dut:
    :param data: {vars.D1: {"v6_interface": vars.D1D2P1, "v6_address": radius_data.dut1_ipv6_address,
             "v4_interface": vars.D1D2P2, "v4_address":radius_data.dut1_ipv4_address, "link_local_interface":vars.D1D2P3},
            vars.D2: {"v6_interface": vars.D2D1P1, "v6_address": radius_data.dut2_ipv6_address,
             "v4_interface": vars.D2D1P2, "v4_address": radius_data.dut2_ipv4_address,
             "link_local_interface": vars.D2D1P3}
            }
    :return:
    """
    if not ip.config_ip_addr_interface(dut, data[dut]["v6_interface"], data[dut]["v6_address"],
                                       radius_data.ipv6_subnet, "ipv6", 'add'):
        st.report_fail("ip6_routing_int_create_fail", data[dut]["v6_interface"])
    if not ip.config_ip_addr_interface(dut, data[dut]["v4_interface"], data[dut]["v4_address"],
                                       radius_data.ipv4_subnet, "ipv4", 'add'):
        st.report_fail("ip_routing_int_create_fail", data[dut]["v4_interface"])
    if not ip.config_interface_ip6_link_local(dut, data[dut]["link_local_interface"]):
        st.report_fail("ip6_link_local_addr_auto_generation_failed")


def root_password_change():
    if not st.change_passwd(vars.D2, radius_data.root_username, radius_data.root_password):
        st.report_fail("password_config_failed")


def making_aaa_params_to_default():
    security.set_aaa_authentication_properties(vars.D2, 'login', radius_data.aaa_login_default)
    security.set_aaa_authentication_properties(vars.D2, 'failthrough', radius_data.aaa_failthrough_default)


def modify_radius_nss_conf():
    st.log("Updating # many_to_one=y string in {} file with many_to_one=a".format(radius_data.radius_nss))
    line_no = int(basic.get_match_string_line_number(vars.D2, '# many_to_one=y', radius_data.radius_nss))
    if not basic.replace_line_in_file_with_line_number(vars.D2, line_number=line_no, text='many_to_one=a',
                                                       file_path=radius_data.radius_nss, device='dut'):
        st.report_fail("file_modification_failed")


def checking_failed_logs():
    string = "Invalid user {}".format(radius_data.invalid_username)
    if not basic.find_line_in_file(vars.D2, string, radius_data.radius_logs_path, device="dut"):
        st.report_fail("radius_log_not_found")


def radius_with_mgmt(action='add'):
    if action == 'add':
        radius.config_server(vars.D1, ip_address=radius_data.host_ip, key=radius_data.host_passkey,
                             priority=radius_data.host_priority, use_mgmt_vrf=radius_data.host_mgmt, action="add")
    elif action == 'delete':
        radius.config_server(vars.D1, no_form=True, ip_address=radius_data.host_ip, action="delete")
    else:
        st.report_fail("invalid_action")


def mgmt_vrf_enable():
    mvrf.config(vars.D1)
    if not poll_wait(get_ifconfig_inet, 90, vars.D1, 'eth0'):
        st.log("IP Address not found on eth0 after prologue")
        st.report_fail("mgmt_vrf_eth0_bind_fail")


def getting_link_local_ipv6():
    dut1_link_local_address = ip.get_link_local_addresses(vars.D1, vars.D1D2P3)
    if dut1_link_local_address:
        radius_data.dut1_link_local = dut1_link_local_address[0]
    dut2_link_local_address = ip.get_link_local_addresses(vars.D2, vars.D2D1P3)
    if dut2_link_local_address:
        radius_data.dut2_link_local = dut2_link_local_address[0]
    radius_data.d1_ip = ip.get_interface_ip_address(vars.D1, interface_name=vars.D1D2P3, family="ipv6")
    radius_data.d2_ip = ip.get_interface_ip_address(vars.D2, interface_name=vars.D2D1P3, family="ipv6")
    try:
        radius_data.dut1_ipv6_link_local = radius_data.d1_ip[0]['ipaddr']
        radius_data.dut2_ipv6_link_local = radius_data.d2_ip[0]['ipaddr']
    except Exception as e:
        st.log("{} exception occurred".format(e))
        st.report_fail('ip6_link_local_addr_auto_generation_failed')


def link_local_rechablility():
    st.log("Ping from {} to {} for ipv6 link-local address".format(vars.D2, vars.D1))
    if not ip.ping(vars.D2, radius_data.dut1_link_local, family='ipv6', interface=vars.D2D1P3):
        st.report_fail("ping_fail_from_DUT_to_DUt", vars.D2, vars.D1)
    st.log("Ping from {} to {} for ipv6 link-local address".format(vars.D2, vars.D1))
    if not ip.ping(vars.D2, radius_data.dut2_link_local, family='ipv6', interface=vars.D2D1P3):
        st.report_fail("ping_fail_from_DUT_to_DUt", vars.D2, vars.D1)


def creating_ipv6_radius_link_local():
    radius.config_server(vars.D1, ip_address=radius_data.dut2_link_local, key=radius_data.host_passkey,
                         priority=radius_data.host_priority, action="add")


def deleting_ipv6_radius_link_local():
    radius.config_server(vars.D1, no_form=True, ip_address=radius_data.dut2_link_local, action="delete")


def config_loop_back_interface(action):
    out = exec_foreach(True, [vars.D1, vars.D2], ip.configure_loopback, loopback_name=radius_data.loopback_name,
                       config=action)
    ensure_no_exception(out[1])


def configure_unnumbered_interface(action):
    dut1_data1 = {'loop_back': radius_data.loopback_name, 'interface': vars.D1D2P2, 'config': action}
    dut2_data1 = {'loop_back': radius_data.loopback_name, 'interface': vars.D2D1P2, 'config': action}
    out = exec_parallel(True, [vars.D1, vars.D2], ip.config_unnumbered_interface, [dut1_data1, dut2_data1])
    ensure_no_exception(out[1])


def configure_static_route():
    params = list()
    params.append(common_utils.ExecAllFunc(ip.create_static_route, vars.D1, None, radius_data.dut2_ipv4_address, shell="vtysh",
                                 family=radius_data.ipv4, interface=vars.D1D2P2))
    params.append(common_utils.ExecAllFunc(ip.create_static_route, vars.D2, None, radius_data.dut1_ipv4_address, shell="vtysh",
                                 family=radius_data.ipv4, interface=vars.D2D1P2))
    out = exec_all(True, params)
    ensure_no_exception(out[1])


def ipv4_radius_unnumbered(action):
    if action == "add":
        radius.config_server(vars.D1, ip_address=radius_data.loopback_dut2, key=radius_data.host_passkey)
    elif action == "delete":
        radius.config_server(vars.D1, no_form=True, ip_address=radius_data.loopback_dut2, action="delete")
    else:
        st.report_fail("invalid_action")


@pytest.mark.auth_with_local_radius
def test_ft_ssh_local_radius():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn014:	Verify that authentication takes place with the local user only when the user is configured in both local and radius server and authentication order configured with local and radius
    '''
    creating_local_user()
    configuring_login_method(radius_data.aaa_login_local_radius)
    st.log("SSH login when login methods configured to local and radius")
    radius_data.ssh_con_local = ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password)
    if not radius_data.ssh_con_local:
        debug_info("test_ft_radius_login")
        st.report_fail("ssh_local_login_status", radius_data.fail)
    ssh.ssh_disconnect(radius_data.ssh_con_local)
    st.report_pass("ssh_local_login_status", radius_data.success)


@pytest.mark.radius_ssh_login
def test_ft_radius_login():
    '''
       Author: Sai Durga <pchvsai.durga@broadcom.com>
       FtOpSoScRaFn001:  Verify that aaa authentication can be configured to radius and login authentication is successful
       FtOpSoScRaFn002:	Verify that login authentication successful when configured auth-port in the device and auth-port at radius server is same
       FtOpSoScRaFn005:	Verify that user able to configure the radius source interface and also verify that radius packets are going through it
       FtOpSoScRaFn008:	Verify that login attempts from the second highest priority server when first high priority server is not  available
       FtOpSoScRaFn010:	Verify that login is successful with the key which is configured in the server level even though different radius key configured in the global level
       FtOpSoScRaFn015:	Verify that login authentication successful when authentication method set to radius and local
       FtOpSoScRaSc001:	Verify that max of 8 mix of IPV4 and IPV6 servers created in the device
    '''
    verfiying_max_servers_config()
    configuring_login_method(radius_data.aaa_login_radius_local)
    st.log("SSH to device using radius credentials with auth_type pap")
    if not ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        debug_info("test_ft_radius_login")
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)


@pytest.mark.radius_ssh_login_chap
def test_ft_radius_login_chap():
    '''
       Author: Sai Durga <pchvsai.durga@broadcom.com>
       FtOpSoScRaFn027:	Verify that SSH authentication when auth-type set to chap
       FtOpSoScRaFn009:	Verify that login authentication fails upon providing wrong credentials and authentication failure logs are generated in syslog file and successful upon providing valid credentials
    '''
    st.log("SSH to device using invalid username {} and password {}".format(radius_data.invalid_username,
                                                                            radius_data.invalid_password))
    if ssh.connect_to_device(radius_data.ip_address, radius_data.invalid_username, radius_data.invalid_password):
        st.report_fail("ssh_login_success_invalid")
    checking_failed_logs()
    st.log("SSH to device using radius credentials with auth_type chap")
    auth_type_config('chap')
    if not ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        debug_info("test_ft_radius_login")
        st.report_fail("ssh_login_failed", radius_data.global_auth_type_chap)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type_chap)


@pytest.mark.rbac
def test_ft_rbac_rw_radius_cred_ssh():
    '''
    FtOpSoScRBACFn011: 	Verify that admin Radius user will have all permissions when SSH to the system with username/password
    '''
    ssh_call(vars.D2, login_type='cred', **radius_data.rw_user)


@pytest.mark.radius_non_root_users
@pytest.mark.rbac
def test_ft_rbac_ro_radius_cred_ssh():
    '''
           Author: Sai Durga <pchvsai.durga@broadcom.com>
           FtOpSoScRaFn029:	Verify that non-admin user doesnot get admin privileges
           FtOpSoScRBACFn010: Verify that non-admin Radius user doesn?t have all permissions except show (get) commands when SSH to the system with username/password.
    '''
    radius_data.ssh_con = ssh.connect_to_device(radius_data.ip_address, radius_data.ro_username,
                                                radius_data.ro_password)
    if not st.exec_ssh(vars.D2, radius_data.ro_username, radius_data.ro_password, ['show vlan config']):
        st.report_fail("cmd_not_executed")
    if not st.exec_ssh(vars.D2, radius_data.ro_username, radius_data.ro_password, ['sudo config vlan add 1000']):
        st.report_fail("admin_user_root_privilege", "non", "got")
    st.report_pass("admin_user_root_privilege", "non", "doesnot got")


@pytest.mark.radius_scaling_memory_leak
def test_ft_radius_scaling_memory_leak():
    '''
       Author: Sai Durga <pchvsai.durga@broadcom.com>
       FtOpSoScRaStTe001:	Verify that device is stable upon login to the devices with 50 sessions using radius server credentials and also verify that there should not be any memory leak
    '''
    configuring_login_method(radius_data.aaa_login_radius_local)
    st.log("SSH to device using radius credentials with auth_type pap")
    radius_data.m1 = basic.get_memory_info(vars.D2)
    radius_data.ssh_con_obj = []
    for session_id in range(radius_data.max_sessions):
        radius_data.ssh_con_obj.append(ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password))
        if not radius_data.ssh_con_obj[session_id]:
            debug_info("test_ft_radius_login")
            st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    for session_id in range(radius_data.max_sessions):
        ssh.ssh_disconnect(radius_data.ssh_con_obj[session_id])
    radius_data.m2 = basic.get_memory_info(vars.D2)
    radius_data.free_memory1 = radius_data.m1['free']
    radius_data.free_memory2 = radius_data.m2['free']
    st.log("Free memory before opening SSH sessions: {}".format(radius_data.free_memory1))
    st.log("Free memory after opening SSH sessions: {}".format(radius_data.free_memory2))
    free_memory = (radius_data.free_memory1-radius_data.free_memory2)
    st.log("Free memory difference: {}".format(free_memory))
    if free_memory >= radius_data.free_memory:
        st.report_fail("free_memory_limit_exceeded_after_radius_ssh", radius_data.max_sessions)
    st.report_pass("radius_scaling_memory_leak_success", radius_data.max_sessions)



@pytest.mark.radius_root_login
def test_ft_root_login_with_radius():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn028:	Verify that root login with radius server failed
    '''
    st.log("Trying to SSH to device using root credentials")
    if ssh.connect_to_device(radius_data.ip_address, radius_data.root_username, radius_data.root_password):
        st.report_fail("ssh_root_with_radius_status", radius_data.success)
    st.report_pass("ssh_root_with_radius_status", radius_data.fail)


@pytest.mark.radius_ssh_mgmt_vrf
def test_ft_radius_ssh_mgmt_vrf():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn016:	Verify that login authentication successful when radius server is configured to use Management vrf
    '''
    auth_type_config('chap')
    mgmt_vrf_enable()
    if not ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        st.report_fail("ssh_radius_login_mgmt_vrf_status", radius_data.fail)
    st.report_pass("ssh_radius_login_mgmt_vrf_status", radius_data.success)


@pytest.mark.radius_ipv6_source_ip
def test_ft_radius_ipv6_source_ip():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn004	Verify that source-ip config modified to ipv6 address when ipv4 address configured first and then ipv6 address.
    '''
    if not radius.config_global_server_params(vars.D2, skip_error_check=False, params={"source_ip": {"value": radius_data.ipv6_source_ip}}):
        st.report_fail("ipv6_source_ip_failed")
    if not radius.show_config(vars.D2, search_string=radius_data.ipv6_source_ip):
        st.report_fail("source_ip_override_failed")
    st.report_pass("sourceip_override_success")


@pytest.mark.ssh_login_unreachable_servers
def test_ft_radius_login_unreachable_servers():
    '''
        Author: Sai Durga <pchvsai.durga@broadcom.com>
        FtOpSoScRaFn030:	Verify that login authentication fails when 2 unreachable radius servers and fail through is enabled
        FtOpSoScRaFn020:   Verify that login authentication failed with radius credentials after deletion of radius server from the device
    '''
    deleting_reachable_servers()
    st.log("Trying to SSH to the device with unreachable servers")
    if ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        st.report_fail("ssh_login_success_unreachable_server")
    st.report_pass("ssh_login_failed_unreachable_server")


@pytest.mark.ssh_login_ipv6_unnumbered
def test_ft_radius_ssh_login_ipv6_unnumbered():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn022:   	Verify that login authentication successful when radius server configured to use IPV6 unnumbered interface
    '''
    interface.clear_interface_counters(vars.D1)
    st.log("executing hwsku command to make sure that the device comes to normal mode to execute linux ssh commands")
    basic_obj.get_hwsku(vars.D2)
    st.exec_ssh_remote_dut(vars.D2, radius_data.dut1_ipv6_link_local, radius_data.host_username,
                           radius_data.host_password, command="")
    counters = interface.get_interface_counters(vars.D1, vars.D1D2P1, "rx_ok")
    if counters == 0:
        st.report_fail("ssh_unnumbered_status", radius_data.ipv6, radius_data.fail)
    st.report_pass("ssh_unnumbered_status", radius_data.ipv6, radius_data.success)


@pytest.mark.ssh_login_ipv4_unnumbered
def test_ft_radius_ssh_login_ipv4_unnumbered():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn021:	Verify that login authentication successful when radius server is configured to use IPV4 unnumbered interface(default VRF)
    '''
    interface.clear_interface_counters(vars.D2)
    st.log("executing hwsku command to make sure that the device comes to normal mode to execute linux ssh commands")
    basic_obj.get_hwsku(vars.D2)
    st.exec_ssh_remote_dut(vars.D2, radius_data.loopback_dut1, radius_data.host_username,
                           radius_data.host_password, command="")
    counters = interface.get_interface_counters(vars.D1, vars.D1D2P1, "rx_ok")
    if counters == 0:
        st.report_fail("ssh_unnumbered_status", radius_data.ipv4, radius_data.fail)
    st.report_pass("ssh_unnumbered_status", radius_data.ipv4, radius_data.success)


@pytest.mark.ssh_login_ipv6_server
def test_ft_radius_ssh_login_ipv6_server():
    '''
    FtOpSoScRaFn018:	Verify that login authentication successful with IPv6 radius server when authentication failed with the IPv4 server and failthrough mechanism is enabled (User VRF)
    '''
    interface.clear_interface_counters(vars.D1)
    st.log("executing hwsku command to make sure that the device comes to normal mode to execute linux ssh commands")
    basic_obj.get_hwsku(vars.D2)
    st.exec_ssh_remote_dut(vars.D2, radius_data.dut1_ipv6_address, radius_data.host_username, radius_data.host_password, command="")
    counters = interface.get_interface_counters(vars.D1, vars.D2D1P1, "rx_ok")
    if counters == 0:
        st.report_fail("ssh_ipv6_status", radius_data.fail)
    st.report_pass("ssh_ipv6_status", radius_data.success)


@pytest.mark.radius_invalid_passkey
def test_ft_radius_invalid_passkey():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaCfg003	Verify that invalid characters are not configured for the server key
    '''
    result = radius.config_global_server_params(vars.D2, skip_error_check=True,
                                                params={"key": {"value": radius_data.invalid_passkey}})
    if result:
        st.report_fail("invalid_passkey_configured", radius_data.invalid_passkey)
    st.report_pass("invalid_passkey_config_unsuccessful")


@pytest.mark.test_ft_ssh_radius_rest
def test_ft_ssh_radius_rest():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn032: Verify that login authentication successful when radius config done through REST
    '''
    st.log("Configuring aaa authentication method to local and radius")
    configuring_login_method(radius_data.aaa_login_local_radius)
    rest_url = "/restconf/data/{}".format(radius_data.YANG_MODEL)
    RADIUS_SERVER = {"RADIUS_SERVER_LIST": [{"ipaddress": radius_data.host_ip,
                                             "auth_port": radius_data.host_udp_port,
                                             "passkey": radius_data.host_passkey,
                                             "auth_type": radius_data.host_auth_type,
                                             "priority": radius_data.host_priority}]
                     }

    radius_dict = {'sonic-system-radius:sonic-system-radius': {'RADIUS_SERVER': RADIUS_SERVER}}
    st.log(radius_dict)
    if not radius_dict:
        st.report_fail("radius_data_not_created", radius_data.host_ip, "REST")
    st.log("Configuring radius server using REST")
    set_radius_response = config_rest(vars.D2, rest_url=rest_url, http_method='rest-patch', json_data=radius_dict)
    st.log(set_radius_response)
    get_radius_response = get_rest(vars.D2, rest_url=rest_url)
    st.log("Rest response after REST call for creating radius server ==> {}".format(get_radius_response["status"]))
    if get_radius_response and get_radius_response["status"] == 200:
        radius_rest_data = get_radius_response["output"][radius_data.YANG_MODEL]["RADIUS_SERVER"]["RADIUS_SERVER_LIST"]
        if not radius_rest_data:
            st.report_fail("radius_data_empty", "REST")
        else:
            radius_rest_data = get_radius_response["output"][radius_data.YANG_MODEL]["RADIUS_SERVER"][
                "RADIUS_SERVER_LIST"]
            if not radius_rest_data:
                st.report_fail("radius_data_empty", "REST")

    else:
        st.log("RESPONSE -- {}".format(get_radius_response))
    st.log("Configuring aaa authentication method to radius and local")
    configuring_login_method(radius_data.aaa_login_radius_local)
    st.log("Login to the device using radius credentials. Username: {} and Password: {}".format(radius_data.host_username,
                                                                                             radius_data.host_password))
    if not ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        st.report_fail("ssh_login", "REST", radius_data.fail)
    st.report_pass("ssh_login", "REST", radius_data.success)


@pytest.mark.test_ft_ssh_radius_gnmi
def test_ft_ssh_radius_gnmi():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoScRaFn031	Verify that login authentication successful when radius config done through GNMI
    '''
    configuring_login_method(radius_data.aaa_login_local_radius)
    radius_data.get_set_xpath = "/sonic-system-radius:sonic-system-radius/"
    radius_data.json_data = {
        "sonic-system-radius:sonic-system-radius": {
            "RADIUS_SERVER": {
                "RADIUS_SERVER_LIST": [{
                    "auth_port": int(radius_data.host_udp_port),
                    "auth_type": str(radius_data.host_auth_type),
                    "ipaddress": str(radius_data.host_ip),
                    "passkey": str(radius_data.host_passkey),
                    "priority": int(radius_data.host_priority)
                }]
            }
        }
    }
    st.log("Configuring radius server using gNMI")
    gnmi_set_output = gnmi_set(vars.D2, xpath=radius_data.get_set_xpath, json_content=radius_data.json_data)
    st.log(gnmi_set_output)
    if not gnmi_set_output:
        st.report_fail("radius_data_empty", "gnmi")
    if not "op: UPDATE" in gnmi_set_output:
        st.report_fail("radius_data_empty", "gnmi")
    st.log("Checking whether radius server configured with gNMI or not")
    gnmi_get_output = gnmi_get(vars.D2, xpath=radius_data.get_set_xpath)
    st.log(gnmi_get_output)
    if not gnmi_get_output:
        st.report_fail('radius_data_not_found')
    if "sonic-system-radius:sonic-system-radius" not in gnmi_get_output:
        st.report_fail("radius_data_not_created", radius_data.host_ip, "REST")
    st.log("Configuring aaa authentication method to radius and local")
    configuring_login_method(radius_data.aaa_login_radius_local)
    st.log("Login to the device using radius credentials. Username: {} and Password: {}".format(radius_data.host_username,
                                                                                             radius_data.host_password))
    if not ssh.connect_to_device(radius_data.ip_address, radius_data.host_username, radius_data.host_password):
        st.report_fail("ssh_login", "gnmi", radius_data.fail)
    st.report_pass("ssh_login", "gnmi", radius_data.success)


def test_ft_nas_ip_statistics_ipv6():
    output = radius.show_config(vars.D1)
    nas_ip_res = output["globals"][0]["global_nas_ip"]
    st.log("Configured nas_ip is {}".format(nas_ip_res))
    statistics_res = output["globals"][0]["global_statistics"]
    st.log("Configured statistics state is {}".format(statistics_res))
    if nas_ip_res == radius_data.dut1_ipv6_address and statistics_res == "True":
        st.log("nas_ip and statistics of radius server are configured properly")
    else:
        st.log("nas_ip and statistics of radius server are not configured as expected")
        return False
    if not radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="debug", action="enable"):
        return False
    if not radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="trace", action="enable"):
        return False
    device_ip_address = basic.get_ifconfig_inet(vars.D1, 'eth0')
    device_ip_address = device_ip_address[0]
    st.log("device ip address is {}".format(device_ip_address))
    st.exec_ssh_remote_dut(vars.D1, device_ip_address, radius_data.nas_sever_username,
                           radius_data.nas_server_pass, command="")
    basic_obj.get_hwsku(vars.D1)
    output = radius.show_config(vars.D1)
    st.log("output is {}".format(output))
    access_requests = output["servers"][2]["access_requests"]
    st.log("access_requests are {}".format(access_requests))
    access_accepts = output["servers"][2]["access_accepts"]
    st.log("access_accepts are {}".format(access_accepts))
    if not access_requests and access_accepts == "1":
        access_rejects = output["servers"][2]["access_rejects"]
        st.log("access_rejects are {}".format(access_rejects))
        st.log("No user logged in")
        return False
    string = "Accepted password for admin from {}".format(device_ip_address)
    if not basic.find_line_in_file(vars.D1, string, "/var/log/auth.log", device= "dut"):
        st.report_fail("radius_log_not_found")
    else:
        st.report_pass("radius_nas_ip_statistics_config_success")


def test_ft_nas_ip_statistics_ipv4():
    output = radius.show_config(vars.D1)
    nas_ip_res = output["globals"][0]["global_nas_ip"]
    st.log("Configured nas_ip is {}".format(nas_ip_res))
    statistics_res = output["globals"][0]["global_statistics"]
    st.log("Configured statistics state is {}".format(statistics_res))
    if nas_ip_res == radius_data.loopback_dut1 and statistics_res == "True":
        st.log("nas_ip and statistics of radius server are configured properly")
    else:
        st.log("nas_ip and statistics of radius server are not configured as expected")
        return False
    if not radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="debug", action="enable"):
        return False
    if not radius.aaa_authentication_debug_trace(vars.D1, skip_error_check=False, option="trace", action="enable"):
        return False
    device_ip_address = basic.get_ifconfig_inet(vars.D1, 'eth0')
    device_ip_address = device_ip_address[0]
    st.log("device ip address is {}".format(device_ip_address))
    st.exec_ssh_remote_dut(vars.D1, device_ip_address, radius_data.nas_sever_username,
                           radius_data.nas_server_pass, command="")
    basic_obj.get_hwsku(vars.D1)
    output = radius.show_config(vars.D1)
    st.log("output is {}".format(output))
    access_requests = output["servers"][2]["access_requests"]
    st.log("access_requests are {}".format(access_requests))
    access_accepts = output["servers"][2]["access_accepts"]
    st.log("access_accepts are {}".format(access_accepts))
    if not access_requests and access_accepts == "1":
        access_rejects = output["servers"][2]["access_rejects"]
        st.log("access_rejects are {}".format(access_rejects))
        st.log("No user logged in")
        return False
    string = "Accepted password for admin from {}".format(device_ip_address)
    if not basic.find_line_in_file(vars.D1, string, "/var/log/auth.log", device= "dut"):
        st.report_fail("radius_log_not_found")
    else:
        st.report_pass("radius_nas_ip_statistics_config_success")


def test_ft_source_intf_mgmt():
    st.log("SSH to device using radius credentials with auth_type pap")
    if not poll_wait(connect_to_device, 10, radius_data.ip_address, radius_data.host_username,
                     radius_data.host_password):
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)


def test_ft_source_intf_Ethernet():
    st.log("SSH to device using radius credentials with auth_type pap")
    if not poll_wait(connect_to_device, 10, radius_data.ip_address, radius_data.host_username,
                     radius_data.host_password):
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)


def test_ft_source_intf_portchannel():
    st.log("SSH to device using radius credentials with auth_type pap")
    if not poll_wait(connect_to_device, 10, radius_data.ip_address, radius_data.host_username,
                     radius_data.host_password):
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)


def test_ft_source_intf_loopback():
    st.log("SSH to device using radius credentials with auth_type pap")
    if not poll_wait(connect_to_device, 10, radius_data.ip_address, radius_data.host_username,
                     radius_data.host_password):
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)


def test_ft_source_intf_vlan():
    st.log("SSH to device using radius credentials with auth_type pap")
    if not poll_wait(connect_to_device, 10, radius_data.ip_address, radius_data.host_username,
                     radius_data.host_password):
        st.report_fail("ssh_login_failed", radius_data.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", radius_data.global_auth_type)
