import pytest
from spytest import st
from spytest.dicts import SpyTestDict
import apis.security.tacacs as tacacs_obj
import apis.system.connection as ssh_obj
import apis.system.basic as basic_obj
import apis.system.logging as slog
from apis.security.rbac import ssh_call
from utilities.utils import ensure_service_params
from utilities.common import poll_wait
from apis.security.tacacs import show_tacacs, filter_and_select

vars = dict()
data = SpyTestDict()


def ensure_device_ipaddress():
    data.ip_address_list = basic_obj.get_ifconfig_inet(vars.D1, 'eth0')
    if not data.ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")
    data.ip_address = data.ip_address_list[0]


def config_default_tacacs_properties(dut):
    st.log("Making TACACS+ parameters to default")
    tacacs_obj.set_tacacs_properties(dut, 'default', 'authtype')
    tacacs_obj.set_tacacs_properties(dut, 'default', 'passkey')
    tacacs_obj.set_tacacs_properties(dut, 'default', 'timeout')


def verify_tacacs_details(dut, tacacs_params, cli_type=""):
    """
    API to verify the tacacs details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param tacacs_params:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if tacacs_params:
        output = show_tacacs(dut, cli_type=cli_type)
        if output and "servers" in output:
            output = output['servers']
            for params in tacacs_params:
                if params["ip"] and not filter_and_select(output, ['address'], {"address": params["ip"]}):
                    st.error("Provided and configured address values are not matching.")
                    return False
                if params["tcp_port"] and not filter_and_select(output, ['tcp_port'], {"tcp_port": params["tcp_port"]}):
                    st.error("Provided and configured tcp_port values are not matching.")
                    return False
                if params["priority"] and not filter_and_select(output, ['priority'], {"priority": params["priority"]}):
                    st.error("Provided and configured priority values are not matching.")
                    return False
                if params["timeout"] and not filter_and_select(output, ['timeout'], {"timeout": params["timeout"]}):
                    st.error("Provided and configured timeout values are not matching.")
                    return False
                if params["auth_type"] and not filter_and_select(output, ['auth_type'], {"auth_type": params["auth_type"]}):
                    st.error("Provided and configured auth_type values are not matching.")
                    return False
            return True
        else:
            st.log("servers index not found in output ...")
            return False
    else:
        st.log("tacacs params not provided ...")
        return False


@pytest.fixture(scope="module", autouse=True)
def tacacs_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1")
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    st.log("Getting IP address of the device")
    data.clear()
    data.hosts = ensure_service_params(vars.D1, "tacacs", "hosts")
    data.tacacs_ser_ip_1 = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "ip")
    data.tcp_port_1 = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "tcp_port")
    data.tcp_port_2 = ensure_service_params(vars.D1, "tacacs", "hosts", 1, "tcp_port")
    data.passkey = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "passkey")
    data.priority1 = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "priority")
    data.priority2 = ensure_service_params(vars.D1, "tacacs", "hosts", 1, "priority")
    data.priority3 = ensure_service_params(vars.D1, "tacacs", "hosts", 2, "priority")
    data.timeout = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "timeout")
    data.auth_type = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "auth_type")
    data.tacacs_ser_ip_2 = ensure_service_params(vars.D1, "tacacs", "hosts", 1, "ip")
    data.tacacs_ser_ip_3 = ensure_service_params(vars.D1, "tacacs", "hosts", 2, "ip")
    data.priority_server2 = ensure_service_params(vars.D1, "tacacs", "hosts", 1, "priority")
    data.time_out = '10'
    data.username = 'test'
    data.password = 'test'
    data.protocol = 'ssh'
    data.ssh_port = '22'
    data.login_type = "tacacs+"
    data.failthrough_mode = 'enable'
    data.local_username = 'cisco'
    data.local_password = 'cisco123'
    data.local_password2 = 'broadcom'
    data.username1 = 'test'
    data.password1 = 'test'
    data.rw_user = {'username': data.username, 'password': data.password, 'mode': 'rw', 'role': 'admin'}
    data.ro_username = ensure_service_params(vars.D1, "radius", "ro_user", "username")
    data.ro_password = ensure_service_params(vars.D1, "radius", "ro_user", "password1")
    ensure_device_ipaddress()
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_1, data.tcp_port_1, data.timeout, data.passkey,
                                 data.auth_type, data.priority1, use_mgmt_vrf=True)
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_2, data.tcp_port_1, data.timeout, data.passkey,
                                 data.auth_type, data.priority2, use_mgmt_vrf=True)
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_3, data.tcp_port_1, data.timeout, data.passkey,
                                 data.auth_type, data.priority3, use_mgmt_vrf=True)
    st.log("Configuring authentication login parameter as tacacs+ and local")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'tacacs+ local')
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'default')
    slog.clear_logging(vars.D1)
    yield
    st.log("Deleting extra TACACS+ servers from the device")
    for i in range(3, 8):
        tacacs_obj.set_tacacs_server(vars.D1, 'delete', tacacs_params.hosts[i].ip)
    st.log("Making AAA parameters to default")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'local tacacs+')
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable')
    st.log("Delete Vlan 100")
    st.config(vars.D1, "config vlan del 100")


@pytest.mark.drop_1
def test_ft_tacacs_ssh_login_with_tacacs_operations():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    This testcase covers the below scenarios
    scenario-1: Verify default login via tacacs is successful.
    scenario-2: Verify that by default, no TACACS servers exist and that a single TACACS server can be added and used for authentication
    scenario-3: Verify that SSH login using Cisco ACS TACACS+ Server is successful.
    Scenario-4: Verify If TACACS+ Authentication is enabled, a new PAM configuration file ?common-auth-sonic? is created.
	Scenario-5: Verify that user is able to execute the ?TACACS-server key command successfully in appropriate mode.
	Scenario-6: Verify that authentication to a TACACS server will only take place if the NAS and the server are configured with the same shared key
    """
    if not basic_obj.verify_file_on_device(vars.D1, "/etc/pam.d", "common-auth"):
        st.report_fail("PAM_file_is_not_created")
    if not basic_obj.verify_file_on_device(vars.D1, "/etc/pam.d", "common-auth-sonic"):
        st.report_fail("PAM_file_is_not_created")
    if not ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol,
                                     data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed_for_tacacs_user")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_rbac_rw_tacacs_cred_ssh():
    '''
    FtOpSoScRBACFn009:	Verify that admin tacacs user will have all permissions when SSH to the system with username/password.
    '''
    ssh_call(vars.D1, login_type='cred', **data.rw_user)
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_rbac_ro_tacacs_cred_ssh():
    '''
    Author: Sai Durga (pchvsai.durga@broadcom,com)
    FtOpSoScRBACFn008	Verify that non-admin tacacs user doesn?t have all permissions except show (get) commands when SSH to the system with username/password.
    '''
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['show vlan config']):
        st.report_fail("cmd_not_executed")
    if not st.exec_ssh(vars.D1, data.ro_username, data.ro_password, ['sudo config vlan add 1000']):
        st.report_fail("admin_user_root_privilege", "non", "got")
    st.log("User does not have access to create vlan")
    st.report_pass("admin_user_root_privilege", "non", "doesnot got")


@pytest.mark.drop_1
def test_ft_tacacs_accounting():
    """
    Author: Ashish Pant (aspant@cisco.com)
    Verify aaa accounting local, and logs are saved in syslog
    """

    st.log("Trying to SSH to the device with TACACS+ server")
    if not poll_wait(ssh_obj.connect_to_device, 10, data.ip_address, data.username,
                     data.password, data.protocol, data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")

    st.log("Reading syslog to check accounting messages")
    log_count = slog.get_logging_count(vars.D1, severity="INFO", filter_list=["Audisp-tacplus"])
    slog.show_logging(vars.D1, log_type='STANDARD', lines=100)
    if log_count == 0:
        st.report_fail("No Tacacs accounting logs found locally")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_tacacs_enable_disable_failthrough():
    """
    Author: Karthik Kumar Goud Battula(karthikkumargoud,battula@broadcom.com)
    This test case covers the below Scenarios
    Scenario-1: Verify the functionality of failthrough mechanism by changing the login authentication order
    Scenario-2: Verify the functionality of failthrough mechanism when DUT have multiple server with default priority.
    """
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_2, data.tcp_port_2, data.timeout, data.passkey,
                                 data.auth_type, data.priority_server2, username=data.username, password=data.password, use_mgmt_vrf=True)
    st.log(
        "Trying to SSH to the device using local credetails when login method set to TACACS+ and local and fail through mode is not enabled")
    if ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password, data.protocol,
                                 data.ssh_port, alt_password=data.local_password2):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to TACACS+ and local and fail through mode is not enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Setting login authentication to local and tacacs+")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'local tacacs+', username=data.username, password=data.password)
    st.log(
        "Trying to SSH to the device using local credetails when login method set to local and TACACS+ and fail through mode is not enabled")
    st.wait(2, "to sync the Setting login authentication to local and tacacs+ changes")
    if not ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password,
                                     alt_password=data.local_password2):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to local and TACACS+ and fail through mode is not enabled")
    if ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Configuring AAA login to tacacs+ and local and enabling failthrough mode")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'tacacs+ local')
    st.wait(2, "sync the tacacs server after config changes")
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable', username=data.username, password=data.password)
    st.wait(2, "sync the tacacs server after config changes")
    st.log(
        "Trying to SSH to the device using local credetails when login method set to TACACS+ and local and fail through mode is enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.local_username, data.local_password,
                                     alt_password=data.local_password2):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log(
        "Trying to SSH to the device using TACACS+ credetails when login method set to TACACS+ and local and fail through mode is enabled")
    if not ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_tacacs_modify_server_parameters():
    """

    Author: Karthik Kumar Goud Battula(karthikkuamrgoud.battula@broadcom.com)
    This Testcase covers the below scenarios
    Scenario-1: Verify device behavior when TACACS+ application parameters (valid and invalid) are modified while traffic is running.
    Scenario-2: Verify that the key and timeout options default to global but may be specified to unique values on a per Server basis.
    Scenario-3: Verify that the NAS will stop communicating with the current server is the server is down  after the duration of the configured server timeout  or the default timeout value
    Scenario-4: Verify that Taccacs server key can be configured with more that 4 special characters
    """
    invalid_l4_port = '59'
    invalid_ip_addr = '10.10.10.1'
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', tacacs_params.hosts[2].ip)
    tacacs_obj.set_tacacs_properties(vars.D1, 'passkey', 'secretstring')
    st.log("Configuring global tacacs server key with special characters")
    tacacs_obj.set_tacacs_properties(vars.D1, 'passkey', data.passkey)
    st.log("Check client authentication by modifing ip address,timeout,passkey")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', data.tacacs_ser_ip_1)
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', data.tacacs_ser_ip_2)
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', data.tacacs_ser_ip_3)
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_1, invalid_l4_port, data.timeout, data.passkey,
                                 data.auth_type, data.priority1, use_mgmt_vrf=True)

    st.log("Trying to SSH to the device when TACACS+ server is configured with invalid parameters")
    if ssh_obj.connect_to_device(data.ip_address, data.username, data.password, data.protocol, data.ssh_port):
        st.log("Deleting the TACACS+ server which is invalid for failed scenario")
        tacacs_obj.set_tacacs_server(vars.D1, 'delete', invalid_ip_addr)
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.log("Deleting the TACACS+ server which is invalid")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', data.tacacs_ser_ip_1)
    st.log("Creating valid TACACS+ server")
    tacacs_obj.set_tacacs_server(vars.D1, 'add', data.tacacs_ser_ip_1, data.tcp_port_1, data.timeout, data.passkey,
                                 data.auth_type, data.priority1, use_mgmt_vrf=True)
    st.wait(2, "sync the tacacs server after config changes")
    st.log("Trying to SSH to the device with TACACS+ server which is configured with the valid parameters")
    if not poll_wait(ssh_obj.connect_to_device, 10, data.ip_address, data.username,
                     data.password, data.protocol, data.ssh_port):
        st.report_fail("Login_to_DUT_via_SSH_is_failed")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_tacacs_maximum_servers():
    """
     Author: Karthik Kumar Goud Battula(karthikkumargoud.battula@broadcom.com)
    This testcase covers the below scenarios
    Scenario-1: Verify that more than one TACACS server can be configured on the NAS, upto the maximum number of servers that are allowed.
    Scenario-2: Verify that TACACS+ servers with IPv4 and IPv6 address can be added at the same time.
    Scenario-3: Verify that Maximum number of TACACS IPv4 servers can be configured on DUT.
    Scenario-4: Verify that Maximum number of TACACS IPv6 servers can be configured on DUT.
    Scenario-5: Verify the Save and Reload Functionality for TACACS IPv6 feature.
    """
    tacacs_obj.set_aaa_authentication_properties(vars.D1, 'login', 'default')
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    for i in range(1, 8):
        ip_addr = ensure_service_params(vars.D1, "tacacs", "hosts", i, "ip")
        priority = ensure_service_params(vars.D1, "tacacs", "hosts", i, "priority")
        tcp_port = ensure_service_params(vars.D1, "tacacs", "hosts", i, "tcp_port")
        tacacs_obj.set_tacacs_server(vars.D1, 'add', ip_addr, tcp_port,
                                     data.timeout, data.passkey,
                                     data.auth_type, priority,
                                     use_mgmt_vrf=True)
    if not verify_tacacs_details(vars.D1, tacacs_params.hosts):
        st.report_fail("Tacacs_server_configs_are_not_successful", tacacs_params.hosts)
    st.report_pass("test_case_passed")
