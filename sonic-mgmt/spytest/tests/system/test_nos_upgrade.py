import pytest
import apis.routing.ip as ping_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
from spytest import st
from spytest.dicts import SpyTestDict
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
import sys
import tests.system.test_platform as test_platform
data = SpyTestDict()

platform_details = {
    "image_name" : "sonic-cisco-8000.bin",
    "voltage_sensors" : ["MB_GB_VDDS_L1_VIN", "MB_GB_VDDA_L2_VOUT", "MB_GB_VDDS_L1_VOUT", "CPU_U17_PVCCIN_VIN", "CPU_U17_PVCCIN_VOUT", "CPU_U17_P1P05V_VOUT", "MB_3_3V_R_L1_VIN", "MB_3_3V_R_L1_VOUT", "MB_GB_VDDCK_L2_VOUT", "MB_3_3V_L_L1_VIN", "MB_3_3V_L_L1_VOUT", "GB_PCIE_VDDH", "GB_PCIE_VDDACK", "GB_P1V8_VDDIO", "GB_P1V8_PLLVDD", "CPU_U117_P1P2V_VIN", "CPU_U117_P1P2V_VOUT", "CPU_U117_P1P05V_VOUT", "MB_A1V8", "MB_A1V", "MB_A3V3", "MB_A1V2", "MB_P3V3", "MB_GB_CORE_VIN_L1", "MB_GB_CORE_VOUT_L1", "MB_GB_CORE_IIN_L1", "MB_GB_CORE_IOUT_L1"],
    "current_sensors" : ["MB_GB_VDDS_L1_IIN","MB_GB_VDDS_L1_IOUT","MB_GB_VDDA_L2_IOUT","CPU_U17_PVCCIN_IIN","CPU_U17_PVCCIN_IOUT","CPU_U17_P1P05V_IOUT", "MB_3_3V_R_L1_IIN", "MB_3_3V_R_L1_IOUT", "MB_GB_VDDCK_L2_IOUT", "MB_3_3V_L_L1_IIN", "MB_3_3V_L_L1_IOUT", "CPU_U117_P1P2V_IIN", "CPU_U117_P1P2V_IOUT", "CPU_U117_P1P05V_IOUT"]
}

@pytest.fixture(scope="module", autouse=True)
def nos_module_hooks(request):
    # add things at the start of this module
    # global vars
    # vars = st.ensure_min_topology("D1")
    yield
    # add things at the end of this module"


@pytest.fixture(scope="function", autouse=True)
def nos_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case
    yield

    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

@pytest.mark.community
@pytest.mark.community_pass

def test_ft_platform_nosupgrade():
    """
    Author: Deekshitha Kankanala <dkankana@cisco.com>
    Validate 'sonic-installer install xxxxx.bin' command
    """

    vars = st.get_testbed_vars()
    dut = vars.D1
    try:
        st.log("####### IN TEST PLATFORM NOSUPGRADE #####")
        st.log("##### Image should be copied to the dut ########")
        result = basic_obj.apply_install(dut, platform_details.get('image_name'))
        st.reboot(vars.D1)
        # st.wait(60)
        version_data = basic_obj.show_version(dut)
        #Get the commit hash from the input yaml
        commit_data = st.get_build_commit_hash(dut)
        #Get the Build time from the input yaml
        build_time = st.get_build_time(dut)
        #Get the sdk version from the input yaml
        sdk_version = st.get_sdk_version(dut)

        if version_data is None:
            raise Exception("Parsed version date retuned null")
         
        #Validate as below 
        if isinstance(version_data, dict):
            #Check the build commit hash if matched with the input yaml 
            if version_data.get('build_commit') is None and version_data.get('build_commit') != commit_data :
                raise Exception("Parsed built commit val {} not matched to the build_commit {}".format(version_data.get('built_commit'), commit_data))
            #Check the build time if match with the input yaml
            if version_data.get('build_date') is None and version_data.get('build_date') != build_time :
                raise Exception("Parsed built date val {} not matched to the  {}".format(version_data.get('build_date'), build_time))
            #Check the sdk-version if match with the input yaml
            if version_data.get('sdk_version') is None and version_data.get('sdk_version') != sdk_version :
                raise Exception("Parsed sdk-version val {} not matched to the sdk_version {}".format(version_data.get('sdk_version'), sdk_version))
        else:
            raise Exception("Version data expected to be dict but resulted {}".format(type(version_data)))
        #Check if the dockers are up 
        docker_data = basic_obj.get_docker_ps(vars.D1)
        if docker_data is None:
            raise Exception("Parsed docker data returned null")
        for data in docker_data:
            if not test_platform.check_uptime_docker(vars.D1, data.get('names')):
                st.log("docker {} container verification failed".format(data.get('names')))
                raise Exception("docker {} container verification failed".format(data.get('names')))
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")





    


