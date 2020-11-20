import pytest

from spytest import st, SpyTestDict, mutils

import apis.system.boot_up as bootup_obj
import apis.system.logging as logging_obj

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def bootup_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    st.log("Ensure HTTP server details")
    data.http_ip = mutils.ensure_service_params(vars.D1, 'http', 'ip')
    data.build_path = mutils.ensure_service_params(vars.D1, 'http', 'path')
    data.build_name = mutils.ensure_service_params(vars.D1, 'http', 'image1')
    st.log("Fetching Present build(Current active build)")
    data.build_details_list = bootup_obj.sonic_installer_list(vars.D1)
    data.initial_build = data.build_details_list['Current'][0]
    yield

@pytest.fixture(scope="function", autouse=True)
def bootup_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield

@pytest.mark.ft_bootup_build_all
def test_ft_bootup_build_all():
    '''
    Author: Jagadish <jagadish.chatrasi@broadcom.com>
    Topology: DUT--- Service Port
    Test Description: Verify that SONiC installer new image download,
                      set_next_boot, list, update, set_default and
                      remove operations are successful.
    '''
    vars = st.get_testbed_vars()
    st.log("Removing additional builds")
    for build in data.build_details_list['Available']:
        if not build == data.initial_build:
            if not bootup_obj.sonic_installer_remove(vars.D1, build):
                st.report_fail("build_remove_fail", build)
    st.log("Loading build")
    build = "http://" + data.http_ip + data.build_path + "/" + data.build_name
    bootup_obj.sonic_installer_install(vars.D1, build)
    st.log("Verifying whether build is loaded or not")
    build_details_list = bootup_obj.sonic_installer_list(vars.D1)
    if not len(build_details_list['Available']) == 2:
        st.report_fail("build_load_unsuccessful")
    new_image = bootup_obj.sonic_installer_list(vars.D1)['Next'][0]
    if new_image == data.initial_build:
        st.report_fail('verify_next_active_build_as_new_build_fail')
    st.reboot(vars.D1, 'fast')
    err_count = logging_obj.get_logging_count(vars.D1, filter_list=['SIGABRT', 'Runtime error', 'SAI_STATUS_FAILURE'])
    if err_count:
        st.report_fail("error_string_found", 'string', 'show logging')
    if not bootup_obj.sonic_installer_list(vars.D1)['Current'][0] == new_image:
        st.report_fail('verify_active_build_as_new_build_fail')
    st.log("Configuring old build as next build")
    if not bootup_obj.sonic_installer_set_next_boot(vars.D1, data.initial_build):
        st.report_fail("set_next_active_build_as_old_fail")
    st.log("Verifying next active build")
    if not bootup_obj.sonic_installer_list(vars.D1)['Next'][0] == data.initial_build:
        st.report_fail("verify_next_active_build_as_old_build_fail")
    st.log("Configuring new build as default build")
    if not bootup_obj.sonic_installer_set_default(vars.D1, new_image):
        st.report_fail("set_old_build_as_default_fail")
    st.log('Verify whether new build is set to next active or not')
    if not bootup_obj.sonic_installer_list(vars.D1)['Next'][0] == new_image:
        st.report_fail("verify_next_active_build_as_new_build_fail")
    st.log("Removing the old build")
    if not bootup_obj.sonic_installer_remove(vars.D1, data.initial_build):
       st.report_fail("remove_old_build_fail")
    st.log("Verifyig whether old build is deleted or not")
    if data.initial_build in bootup_obj.sonic_installer_list(vars.D1)['Available']:
       st.report_fail("verify_remove_old_build_fail")
    st.report_pass("test_case_passed")
