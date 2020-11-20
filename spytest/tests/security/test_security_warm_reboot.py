import pytest
from spytest import st
import apis.security.tacacs as tacacs_obj
import apis.system.reboot  as rb_obj
import apis.system.basic as basic_obj
import apis.system.switch_configuration as sconf_obj
from spytest.dicts import SpyTestDict

def init_vars():
    global vars
    vars = st.get_testbed_vars()
    vars = st.ensure_min_topology("D1")

def initialize_variables():
    global data
    data = SpyTestDict()

def get_parms():
    data.platform = basic_obj.get_hwsku(vars.D1)
    data.constants = st.get_datastore(vars.D1, "constants", "default")

@pytest.fixture(scope="module", autouse=True)
def security_warm_reboot_module_hooks(request):
    # add things at the start of this module
    init_vars()
    initialize_variables()
    get_parms()

    st.log("Checking whether the platform supports warm-reboot")
    if not data.platform.lower() in data.constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        st.report_unsupported('test_case_unsupported')

    st.log("configuring tacacs server")
    tacacs_config()
    st.log("Verifying tacacs server details in running-config before warm-reboot")
    tacacs_config_verify()

    yield
    # add things at the end of this module"
    #Below step will clear the TACACS+ server config from the device
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    tacacs_obj.set_tacacs_server(vars.D1, 'delete', tacacs_params.hosts[0].ip)

@pytest.fixture(scope="function", autouse=True)
def security_warm_reboot_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case.

    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case

def tacacs_config():
    st.log("configuring tacacs server")
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    tacacs_obj.set_tacacs_server(vars.D1, 'add', tacacs_params.hosts[0].ip, tacacs_params.hosts[0].tcp_port,
                                 tacacs_params.hosts[0].timeout, tacacs_params.hosts[0].passkey,
                                 tacacs_params.hosts[0].auth_type, tacacs_params.hosts[0].priority)
def tacacs_config_verify():
    st.log("verifying whether configuring tacacs server is successful or not - FtOpSoScTaCm004")
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    if not sconf_obj.verify_running_config(vars.D1, "TACPLUS_SERVER", tacacs_params.hosts[0].ip, "priority", "1"):
        st.report_fail("running_config_failed", vars.D1, "TACPLUS_SERVER", tacacs_params.hosts[0].ip, "priority","1")
    else:
        st.log("tacacs server configuration is successful")

@pytest.mark.savereboot
def test_ft_security_config_mgmt_verifying_config_with_save_warm_reboot():
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    st.log("Checking whether config is loaded to running config from config_db after warm-reboot")
    tacacs_config_verify()
    st.log("configuration  is successfully stored to config_db file after save and warm-reboot")
    st.report_pass("test_case_passed")
