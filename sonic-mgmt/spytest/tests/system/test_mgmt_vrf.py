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
def mgmt_module_hooks(request):
    # add things at the start of this module
    # global vars
    # vars = st.ensure_min_topology("D1")
    yield
    # add things at the end of this module"


@pytest.fixture(scope="function", autouse=True)
def mgmt_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case
    yield

    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

@pytest.mark.community
@pytest.mark.community_pass
def test_ft_mgmt_vrf():
    """
    Author:Deekshitha Kankanala(dkankana@cisco.com)
    Scenario: Verify the mgmt vrf via the telnet session
    """
    
    #enable mgmt-vrf 
    verify_ssh_enable_mgmt_vrf()
    #disable mgmt-vrf
    verify_ssh_disable_mgmt_vrf()
    #verify mgmt ip 
    verify_telnet_mgmt_vrf()
    
    st.report_pass("test_case_passed") 

def verify_ssh_enable_mgmt_vrf():
    """
    Verifying mgmt-vrf enable 
    """
    vars = st.get_testbed_vars()
    #config mgmt-vrf
    user_name = st.get_username(vars.D1)
    password = st.get_password(vars.D1)
    #Connecting to ssh session and enabling mgmt-vrf 
    ssh_d1 = connect_to_device(st.get_mgmt_ip(vars.D1), user_name, password)
    if ssh_d1:
        st.log("Executing command - 'sudo config vrf add mgmt' in to the SSH session.")
        st.log(execute_command(ssh_d1, 'sudo config vrf add mgmt'))
        st.wait(5, 'After executing "config vrf mgmt" cmd on SSH session.')
        st.log("Forcefully disconnecting the SSH session..")
        ssh_disconnect(ssh_d1)
    else:
        st.error('Cannot SSH into Device with default credentials')
        st.report_fail("ssh_failed")

def verify_ssh_disable_mgmt_vrf():
    """
    Verifying mgmt vrf disable 
    """
    vars = st.get_testbed_vars()
    #config mgmt-vrf
    user_name = st.get_username(vars.D1)
    password = st.get_password(vars.D1)
    ssh_d1 = connect_to_device(st.get_mgmt_ip(vars.D1), user_name, password)
    if ssh_d1:
        st.log("Executing command - 'sudo config vrf del mgmt' in to the SSH session.")
        st.log(execute_command(ssh_d1, 'sudo config vrf del mgmt'))
        st.wait(5, 'After executing "config vrf mgmt" cmd on SSH session.')
        st.log("Forcefully disconnecting the SSH session..")
        ssh_disconnect(ssh_d1)
    else:
        st.error('Cannot SSH into Device with default credentials')
        st.report_fail("ssh_failed")

def verify_telnet_mgmt_vrf():
    """
    Verfiying mgmt vrf via telnet 
    """
    vars = st.ensure_min_topology("D1", "CONSOLE_ONLY")
    user_name = st.get_username(vars.D1)
    password = st.get_password(vars.D1)
    basic_obj.shutdown_eth0(vars.D1)
    try:
        ssh_d1 = connect_to_device(st.get_mgmt_ip(vars.D1), user_name, password)
        if ssh_d1:
            ssh_disconnect(ssh_d1)
            st.error('logged in through ssh after shutting down eth0')
            st.report_fail("test_case_failed")
        else:
            raise Exception("Connection Time_out")
    except:
        st.log("Unexpected error:", sys.exc_info()[0])
        basic_obj.startup_eth0(vars.D1)
        ssh_d2 = connect_to_device(st.get_mgmt_ip(vars.D1), user_name, password)
        if ssh_d2:
            st.log("Successfully logged through ssh")
            ssh_disconnect(ssh_d1)
            st.report_pass("test_case_passed")
        else:
            st.error('Cannot SSH into Device with  credentials')
            st.report_fail("test_case_failed")



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
        shutdown_result = basic_obj.shutdown_dut(dut)
        st.wait(60)
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
        test_platform.test_ft_docker_ps()
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")





    


