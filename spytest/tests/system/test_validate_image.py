#############################################################################
#Script Title : 
#Author       : 
#Mail-id      : 
#############################################################################


import pytest
from spytest import st

import apis.system.basic as basic_api
import apis.system.interface as intf_api
from spytest.dicts import SpyTestDict

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue():

    vars = st.ensure_min_topology('D1')
    data.dut_list = st.get_dut_names()
    data.dut_platform_info = dict()
    data.dut_version_info = dict()
    for dut in data.dut_list:
        plat_name = st.get_device_param(dut, 'plat_name', '_') 
        data.dut_platform_info[dut] = str(plat_name)
        ver_str = st.get_device_param(dut, 'ver_str', '3.')
        data.dut_version_info[dut] = str(ver_str)

    yield


@pytest.mark.sanity
def validate_image(dut):
    tc_list = ['verify_system_status', 'verify_show_version', 'show_platform_summary', 'show_platform_syseprom', 'show_interface_status']

    result_count = len(tc_list)
    st.log('Executing Image Validation Tests on: {}'.format(data.dut_platform_info[dut]))
    
    version_op = basic_api.show_version(dut)
    if  data.dut_version_info[dut] in version_op['version']:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Passed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[1]))
        result_count -= 1
    else:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Failed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[1]))

    if basic_api.get_system_status(dut):
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Passed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[0]))
        result_count -= 1
    else:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Failed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[0]))
        
    plat_sum_op = basic_api.get_platform_summary(dut)
    if data.dut_platform_info[dut].lower() in plat_sum_op['platform'].lower():
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Passed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[2]))
        result_count -= 1
    else:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Failed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[2]))
        st.log(plat_sum_op)

    plat_eep_op = basic_api.get_platform_syseeprom(dut)
    if plat_eep_op: 
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Passed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[3]))
        result_count -= 1
    else:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Failed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[3]))
        st.log(plat_eep_op)

    intf_status_op = intf_api.interface_status_show(dut)
    if intf_status_op: 
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Passed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[4]))
        result_count -= 1
    else:
        st.log('Build: {}, DUT: {}, Platform: {}, TestCase: {} Failed'.format(version_op['version'], dut, data.dut_platform_info[dut], tc_list[4]))

    if result_count == 0:
        st.log('Image Validation on platform {}: Passed'.format(data.dut_platform_info[dut]))
        st.report_pass('test_case_passed')
    else:
        st.log('Image Validation on platform {}: Failed'.format(data.dut_platform_info[dut]))
        st.report_fail('test_case_failed')
def test_validate_image():
    st.exec_each(data.dut_list, validate_image)
