import pytest
import apis.routing.ip as ping_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
from spytest import st
from spytest.dicts import SpyTestDict
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
import sys

data = SpyTestDict()

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








    


