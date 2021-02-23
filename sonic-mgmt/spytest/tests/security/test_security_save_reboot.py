import pytest
from spytest import st
from spytest.dicts import SpyTestDict
import apis.security.radius as radius
import apis.security.tacacs as tacacs
from utilities.utils import ensure_service_params
import apis.system.reboot as reboot
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
    security_data.hosts = ensure_service_params(vars.D1, "radius", "hosts")
    security_data.radius_host_ip = ensure_service_params(vars.D1, "radius", "hosts", 0, "ip")
    security_data.radius_host_passkey = ensure_service_params(vars.D1, "radius", "hosts", 0, "passkey")
    security_data.radius_host_priority = ensure_service_params(vars.D1, "radius", "hosts", 0, "priority")
    security_data.global_diff_passkey = ensure_service_params(vars.D1, "radius", "globals", 1, "passkey")
    security_data.global_auth_type = ensure_service_params(vars.D1, "radius", "globals", 0, "auth_type")
    security_data.global_timeout = ensure_service_params(vars.D1, "radius", "globals", 0, "timeout")
    security_data.global_retransmit = ensure_service_params(vars.D1, "radius", "globals", 0, "retransmit")
    security_data.tacacs_host_ip = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "ip")
    security_data.tacacs_tcp_port = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "tcp_port")
    security_data.tacacs_passkey = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "passkey")
    security_data.tacacs_timeout = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "timeout")
    security_data.tacacs_priority = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "priority")
    security_data.tacacs_auth_type = ensure_service_params(vars.D1, "tacacs", "hosts", 0, "auth_type")


def security_module_prolog():
    tacacs_config()
    tacacs_config_verify()
    if not st.is_feature_supported("radius"):
        return
    config_global_radius()
    radius_config()
    st.log("Verifying radius server details before save-reboot")
    checking_radius_config(security_data.radius_host_ip)


def security_module_epilog():
    tacacs.set_tacacs_server(vars.D1, 'delete', security_data.tacacs_host_ip)
    if not st.is_feature_supported("radius", vars.D1):
        return
    radius.config_server(vars.D1, ip_address=security_data.radius_host_ip, action="delete")
    radius.config_global_server_params(vars.D1, skip_error_check=False,
                                       params={"key": {"value": security_data.global_diff_passkey, "no_form": True},
                                               "timeout": {"value": security_data.global_timeout, "no_form": True},
                                               "auth_type": {"value": security_data.global_auth_type, "no_form": True},
                                               "retransmit": {"value": security_data.global_retransmit,
                                                              "no_form": True}})


def verify_security_default_config(dut):
    if not tacacs.verify_aaa(dut, 'local (default)', 'False (default)'):
        st.report_fail("authentication_default_configs_fail")


def config_global_radius():
    if not radius.config_global_server_params(vars.D1, skip_error_check=False,
                                              params={"key": {"value": security_data.global_diff_passkey},
                                                      "auth_type": {"value": security_data.global_auth_type},
                                                      "timeout": {"value": security_data.global_timeout},
                                                      "retransmit": {"value": security_data.global_retransmit}}):
        st.report_fail("security_global_params_config_failed")


def radius_config():
    radius.config_server(vars.D1, ip_address=security_data.radius_host_ip, key=security_data.radius_host_passkey,
                         priority=security_data.radius_host_priority, action="add")


def checking_radius_config(ip):
    st.log("Checking Radius server config after save and reboot")
    if not radius.verify_config(vars.D1, params={"globals": {"global_retransmit": security_data.global_retransmit,
                                                             "global_timeout": security_data.global_timeout,
                                                             "global_passkey": security_data.global_diff_passkey},
                                                 "servers": [{'priority': security_data.radius_host_priority, 'address': ip,
                                                              'passkey': security_data.radius_host_passkey}]}):
        st.report_fail("radius_server_config_not_successful")
    else:
        st.log("Radius configuration successful")


def tacacs_config():
    tacacs.set_tacacs_server(vars.D1, 'add', security_data.tacacs_host_ip, security_data.tacacs_tcp_port,
                             security_data.tacacs_timeout, security_data.tacacs_passkey,
                             security_data.tacacs_auth_type, security_data.tacacs_priority)


def tacacs_config_verify():
    st.log("Checking whether config is loaded to running config from config_db after save-reboot")
    if not switchconf.verify_running_config(vars.D1, "TACPLUS_SERVER", security_data.tacacs_host_ip, "priority", "1"):
        st.report_fail("running_config_failed", vars.D1, "TACPLUS_SERVER", security_data.tacacs_host_ip, "priority",
                       "1")
    else:
        st.log("tacacs server configuration is successful")


@pytest.mark.savereboot
def test_ft_security_config_mgmt_verifying_config_with_save_reboot():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
       FtOpSoScRaFn006:   Verify that radius config retained after config save and reboot
    '''
    st.log("performing Config save and reloading the device")
    reboot.config_save_reload(vars.D1)
    tacacs_config_verify()
    if st.is_feature_supported("radius", vars.D1):
        checking_radius_config(security_data.radius_host_ip)
    st.report_pass("security_config_retained_after_save_reboot")
