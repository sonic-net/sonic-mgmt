import pytest
from spytest import st
from spytest.dicts import SpyTestDict
import apis.security.radius as radius
from utilities.utils import ensure_service_params
import apis.system.reboot as reboot
import apis.security.tacacs as tacacs
import apis.system.switch_configuration as switchconf

security_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def security_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    security_variables()
    security_module_prolog()
    yield
    security_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def security_func_hooks(request):
    yield


def security_variables():
    security_data.clear()
    if st.is_feature_supported("radius", vars.D1):
        security_data.radius_hosts = ensure_service_params(vars.D1, "radius", "hosts")
        security_data.radius_host_ip = ensure_service_params(vars.D1, "radius", "hosts", 0, "ip")
        security_data.radius_host_passkey = ensure_service_params(vars.D1, "radius", "hosts", 0, "passkey")
        security_data.radius_host_priority = ensure_service_params(vars.D1, "radius", "hosts", 0, "priority")
    security_data.tacacs_host_ip = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "ip")
    security_data.tacacs_tcp_port = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "tcp_port")
    security_data.tacacs_passkey = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "passkey")
    security_data.tacacs_timeout = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "timeout")
    security_data.tacacs_priority = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "priority")
    security_data.tacacs_auth_type = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "auth_type")
    security_data.delay = 5


def security_module_prolog():
    tacacs_config()
    tacacs_config_verify()
    if st.is_feature_supported("radius", vars.D1):
        radius_config()
        st.log("Verifying radius server details")
        checking_radius_config(security_data.radius_host_ip)


def security_module_epilog():
    if st.is_feature_supported("radius", vars.D1):
        radius.config_server(vars.D1, ip_address=security_data.radius_host_ip, action="delete")
    tacacs.set_tacacs_server(vars.D1, 'delete', security_data.tacacs_host_ip)


def checking_radius_config(ip):
    st.log("Checking Radius server config after save and reboot")
    if not radius.verify_config(vars.D1, params={"servers": [{'priority': security_data.radius_host_priority, 'address': ip,
                                                              'passkey': security_data.radius_host_passkey}]}):
        st.report_fail("security_server_config_not_successful")


def tacacs_config():
    tacacs.set_tacacs_server(vars.D1, 'add', security_data.tacacs_host_ip, security_data.tacacs_tcp_port,
                                 security_data.tacacs_timeout, security_data.tacacs_passkey,
                                 security_data.tacacs_auth_type, security_data.tacacs_priority)


def tacacs_config_verify():
    st.log("Checking TACACS+ server config after save and reboot")
    if not switchconf.verify_running_config(vars.D1, "TACPLUS_SERVER", security_data.tacacs_host_ip, "priority", "1"):
        st.report_fail("running_config_failed", vars.D1, "TACPLUS_SERVER", security_data.tacacs_host_ip, "priority","1")
    else:
        st.log("tacacs server configuration is successful")


def radius_config():
    radius.config_server(vars.D1, ip_address=security_data.radius_host_ip, key=security_data.radius_host_passkey,
                         priority=security_data.radius_host_priority, action="add")


@pytest.mark.savereboot
def test_ft_security_config_mgmt_verifying_config_with_save_fast_reboot():
    '''
     Author: Sai Durga <pchvsai.durga@broadcom.com>
     FtOpSoScRaFn007:   Verify that radius config retained after config save and fast boot
    '''
    reboot.config_save(vars.D1)
    st.reboot(vars.D1, 'fast')
    st.wait(security_data.delay)
    tacacs_config_verify()
    if st.is_feature_supported("radius", vars.D1):
        checking_radius_config(security_data.radius_host_ip)
    st.report_pass("security_config_retained_after_fast_reboot")

