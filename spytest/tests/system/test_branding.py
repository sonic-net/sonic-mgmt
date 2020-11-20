import pytest
from spytest import st
from spytest.dicts import SpyTestDict
from apis.system.boot_up import sonic_installer_list
from apis.system.basic import check_sonic_branding

brand_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def branding_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    initialize_variables()
    yield


@pytest.fixture(scope="function", autouse=True)
def branding_func_hooks(request):
    yield


def initialize_variables():
    brand_data.clear()
    brand_data.build_version_in_show_version = vars.version[vars.D1]
    brand_data.sonic_installer_output = sonic_installer_list(vars.D1)
    brand_data.build_version_in_sonic_installer = brand_data.sonic_installer_output['Current'][0]


@pytest.mark.test_ft_version_branding
def test_ft_version_branding():
    """
    This test function verifies the branding changes
    Author: Jagadish Chatrasi<jagadish.chatrasi@gmail.com>
    """
    st.banner('Verify that "show version" command displaying version of the build in correct format or not')
    if not check_sonic_branding(brand_data.build_version_in_show_version):
        st.report_fail('invalid_build_version_format', 'show version')
    st.log('Successfully verified that "show version" command displaying version of the build in correct format')

    st.banner('Verifying that "sonic_installer list" command displaying version of the build in correct format or not')
    if not check_sonic_branding(brand_data.build_version_in_sonic_installer, cli_type='click'):  #Passing the cli_type because the sonic_installer output is supported only in click
        st.report_fail('invalid_build_version_format', 'sonic installer list')
    st.log('Successfully verified "sonic_installer list" command displaying version of the build in correct format')

    st.banner('Verifying that version string does not contains the text "dirty"')
    if 'dirty' in brand_data.build_version_in_show_version.lower():
        st.report_fail('found_string_dirty', 'show version')
    if 'dirty' in brand_data.build_version_in_sonic_installer.lower():
        st.report_fail('found_string_dirty', 'sonic installer list')
    st.log('Successfully verified that version string does not contains the text "dirty"')

    st.report_pass('test_case_passed')
