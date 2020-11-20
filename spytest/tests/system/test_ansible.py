import pytest
from spytest.dicts import SpyTestDict
from spytest import st
import apis.system.ansible as ansible_obj

@pytest.fixture(scope="module", autouse=True)
def ansible_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    global_vars()
    yield


@pytest.fixture(scope="function", autouse=True)
def ansible_func_hooks(request):
    yield

def global_vars():
    global data
    data = SpyTestDict()
    data.device_ip = st.get_mgmt_ip(vars.D1)
    data.ansible_params = st.get_service_info(vars.D1, "ansible")
    data.ansible_hosts = data.ansible_params.hosts

@pytest.mark.ansible_new_vdi
def test_ft_ansible_playbooks_chk_use_vdi():
    device_ip = st.get_mgmt_ip(vars.D1)
    result = True
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1,"ping.yml", host= device_ip, ok="1", fail="0"):
        result= False
        st.report_tc_fail("ft_ansible_host_ping_playbook","ansible_fail")
        st.report_tc_fail("ft_ansible_host_ping_using_pwd","ansible_fail")
        st.report_tc_fail("ft_ansible_host_ping_using_ssh","ansible_fail")
        st.report_tc_fail("ft_ansible_host_multiple_grp_ping","ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_host_ping_playbook", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_host_ping_using_pwd", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_host_ping_using_ssh", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_host_multiple_grp_ping", "ansible_playbook_success")
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1, "fact.yml", host=device_ip, ok="2", fail="0"):
        result = False
        st.report_tc_fail("ft_ansible_host_fact_playbook", "ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_host_fact_playbook", "ansible_playbook_success")
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1, "fact_false.yml", host=device_ip, ok="1", fail="0"):
        result = False
        st.report_tc_fail("ft_ansible_fact_cmd_line", "ansible_fail")
        st.report_tc_fail("ft_ansible_host_adhoc_cmd", "ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_fact_cmd_line", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_host_adhoc_cmd", "ansible_playbook_success")
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1, "copy.yml", host=device_ip, ok="2",fail="0"):
        result = False
        st.report_tc_fail("ft_ansible_copy_playbook", "ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_copy_playbook", "ansible_playbook_success")
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1, "role_test.yml", host=device_ip, fail="0"):
        result = False
        st.report_tc_fail("ft_ansible_playbook_role", "ansible_fail")
        st.report_tc_fail("ft_ansible_playbook_tags", "ansible_fail")
        st.report_tc_fail("ft_ansible_package_chk_using_cmd", "ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_playbook_role", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_playbook_tags", "ansible_playbook_success")
        st.report_tc_pass("ft_ansible_package_chk_using_cmd", "ansible_playbook_success")
    if not ansible_obj.verify_ansible_playbook_vdi(vars.D1, "handler.yml", host=device_ip,fail="0"):
        result = False
        st.report_tc_fail("ft_ansible_playbook_handler", "ansible_fail")
    else:
        st.report_tc_pass("ft_ansible_playbook_handler", "ansible_playbook_success")
    if result:
        st.report_pass("ansible_playbook_success")
    else:
        st.report_fail("ansible_fail")

