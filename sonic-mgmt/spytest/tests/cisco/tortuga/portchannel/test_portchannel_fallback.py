import pytest
from spytest import st, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.system.interface as intf_obj
from spytest.utils import poll_wait

# Global variables
data = SpyTestDict()
data.portchannel_name = "PortChannel01"
data.module_unconfig = False


@pytest.fixture(scope="module", autouse=True)
def portchannel_fallback_module_hooks(request):
    # Initialize module level configuration
    global vars
    data.module_unconfig = False
    data.portchannel_name = "PortChannel01"

    # Ensure 2-node topology with 4 links between them and IXIA connections
    vars = st.ensure_min_topology("D5D6:4")

    data.dut1 = vars.D5
    data.dut2 = vars.D6
    data.members_dut1 = [vars.D5D6P1, vars.D5D6P2, vars.D5D6P3 ]
    data.members_dut2 = [vars.D5D6P1, vars.D5D6P2, vars.D5D6P3 ]

    yield
    module_unconfig()

def module_unconfig():
    """Module level cleanup"""
    if not data.module_unconfig:
        data.module_unconfig = True
        st.log('Module config Cleanup')
        portchannel_obj.clear_portchannel_configuration([data.dut1, data.dut2])

@pytest.fixture(scope='function', autouse=True)
def portchannel_fallback_func_hooks(request):
    """Function level setup and teardown"""
    function_config()
    yield
    function_unconfig()

def function_config():
    """Function level setup - Create portchannels and bring up all interfaces before each test"""
    
    # Create portchannel on both DUTs
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True)
    portchannel_obj.create_portchannel(data.dut2, portchannel_list=[data.portchannel_name])

    # No shutdown all member interfaces on both DUTs
    intf_obj.interface_noshutdown(data.dut1, data.members_dut1, skip_verify=False)
    intf_obj.interface_noshutdown(data.dut2, data.members_dut2, skip_verify=False)

def function_unconfig():
    """Function level cleanup"""
    # Delete portchannel if exists on both DUTs
    for dut in [data.dut1, data.dut2]:
        if portchannel_obj.get_portchannel(dut, data.portchannel_name):
            members = portchannel_obj.get_portchannel_members(dut, data.portchannel_name)
            if members:
                for member in members:
                    portchannel_obj.delete_portchannel_member(dut, data.portchannel_name, member)
            portchannel_obj.delete_portchannel(dut, data.portchannel_name)

####################
#                  #
#  2-Node Topology #
#                  #
#  SD5-----SD6     #
####################

######################################################################
#                                                                    #
#         IXIA --- DUT1 <---PortChannel---> DUT2 --- IXIA            #
#              (4 links between DUT1 and DUT2)                       #
#                                                                    #
######################################################################


def test_portchannel_fallback_no_operational_ports():
    """
    Verify the Portchannel status with no operational ports
    """
    intf_obj.interface_shutdown(data.dut1, data.members_dut1[:2], skip_verify=False)

    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])

    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "down", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel with fallback enabled - PortChannel DOWN, all member ports Deselected")
    st.report_pass('test_case_passed')


def test_portchannel_fallback_no_lacp_peers():
    """
    Verify the Portchannel status with no LACP peers on any of portchannel ports that are operationally UP.
    """
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(30, "Waiting for LACP negotiation and fallback")

    # Verify member port states: first port S (Selected), second port D (Deselected)
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel fallback working - First port Selected, second port Deselected, PortChannel UP")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_higher_index_port_add():
    """
    Verify the Portchannel status and active port selected when another higher preference port is added to the portchannel.
    """
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[0])
    st.wait(10, "Waiting for LACP negotiation and fallback")

    member_state_dict = {
        data.members_dut1[0]: 'S'
    }

    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    #Add a higher index port to the portchannel
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[1])
    st.wait(10, "Waiting for LACP negotiation and fallback")
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel Active port Selection - First port Selected, second port Deselected, PortChannel UP")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_lower_index_port_add():
    """
    Verify the Portchannel status and active port selected when another lower index port is added to the portchannel.
    """
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[1])
    st.wait(10, "Waiting for LACP negotiation and fallback")

    member_state_dict = {
        data.members_dut1[1]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.log("FAIL: PortChannel fallback member state verification failed")
        st.report_fail("portchannel_fallback_state_verification_fail")

    #Add a lower index port to the portchannel
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[0])
    st.wait(10, "Waiting for LACP negotiation and fallback")
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel Active port Selection - First port Selected, second port Deselected, PortChannel UP")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_lacp_peer_present_without_additional_op_members():
    """
    Verify the Portchannel status when LACP peer is present on one of the portchannel ports and no other operational ports
    """
    intf_obj.interface_shutdown(data.dut1, data.members_dut1[1], skip_verify=False)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[0])
    st.wait(30, "Waiting for LACP negotiation")

    # Verify member port states: first port S (Selected), second port D (Deselected)
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel fallback working - First port Selected, second port Deselected, PortChannel UP")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_lacp_peer_present_with_additional_op_members():
    '''
    Verify the Portchannel status when LACP peer is present on one of the portchannel ports and
    portchannel has other operational ports without any LACP peer
    '''
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[0])
    st.wait(30, "Waiting for LACP negotiation")

    # Verify member port states: first port S (Selected), second port D (Deselected)
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }

    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel fallback working - First port Selected, second port Deselected, PortChannel UP")
    st.report_pass('test_case_passed')

def portchannel_member_add_via_teamdctl(dut, portchannel_name, member_port, port_data):
    command = "ip link set {} down".format(member_port)
    st.config(dut, command)
    command = "sudo teamdctl {} port config update {} '{}'".format(portchannel_name, member_port, port_data)
    st.config(dut, command)
    command = "teamdctl {} port add {}".format(portchannel_name, member_port)
    st.config(dut, command)
    command = "ip link set {} up".format(member_port)
    st.config(dut, command)

def test_portchannel_fallback_port_priority():
    '''
    Verify the Portchannel status and active port selection when another lower priority port is added to the portchannel
    and no LACP peer exists. Verify the same when another higher priority port is added.
    '''
    port1_lacp_data = '{ "lacp_key": 101, "link_watch": { "name": "ethtool" }, "lacp_prio": 20 }'
    port2_lacp_data =  '{ "lacp_key": 101, "link_watch": { "name": "ethtool" }, "lacp_prio": 10 }'
    port3_lacp_data =  '{ "lacp_key": 101, "link_watch": { "name": "ethtool" }, "lacp_prio": 30 }'

    portchannel_member_add_via_teamdctl(data.dut1, data.portchannel_name, data.members_dut1[0], port1_lacp_data)
    st.wait(10, "Waiting for LACP negotiation")
    member_state_dict = {
        data.members_dut1[0]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    portchannel_member_add_via_teamdctl(data.dut1, data.portchannel_name, data.members_dut1[1], port2_lacp_data)
    st.wait(10, "Waiting for LACP negotiation")
    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'S',
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    portchannel_member_add_via_teamdctl(data.dut1, data.portchannel_name, data.members_dut1[2], port3_lacp_data)
    st.wait(10, "Waiting for LACP negotiation")
    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'S',
        data.members_dut1[2]: 'D',
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    command = "teamdctl {} port remove {}".format( data.portchannel_name, data.members_dut1[0])
    st.config(data.dut1, command)
    command = "teamdctl {} port remove {}".format(data.portchannel_name, data.members_dut1[1])
    st.config(data.dut1, command)
    command = "teamdctl {} port remove {}".format(data.portchannel_name, data.members_dut1[2])
    st.config(data.dut1, command)
    st.log("PASS: PortChannel state and fallabck port selection verified with lower and higher priority port addition")
    st.report_pass('test_case_passed')


def test_portchannel_fallback_port_shutdown_with_no_other_port():
    '''
    Verify the Portchannel status for a portchannel when the port with LACP peer is shutdown on DUT and
    has no other operational ports
    '''
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[0])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[0])
    st.wait(10, "Waiting for LACP negotiation")

    # Verify PortChannel is UP on DUT1
    member_state_dict = {
        data.members_dut1[0]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    # Shutdown port on DUT1
    intf_obj.interface_shutdown(data.dut1, data.members_dut1[0], skip_verify=False)
    st.wait(10, "Waiting for interface shutdown to take effect")

    # Verify PortChannel state is DOWN and member port state is D (Deselected)
    member_state_dict = {
        data.members_dut1[0]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "down", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel DOWN after member shutdown, member port Deselected")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_port_shutdown_with_other_op_port():
    '''
    Verify the Portchannel status for a portchannel when the port with LACP peer is shutdown on DUT and
    has other operational ports
    '''
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[0])
    st.wait(10, "Waiting for LACP negotiation")

    # Verify member port states: first port S (Selected with LACP peer), second port D (Deselected)
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    # Shutdown first port on DUT1 (port with LACP peer)
    intf_obj.interface_shutdown(data.dut1, data.members_dut1[0], skip_verify=False)
    st.wait(10, "Waiting for fallback to second port")

    # Verify member port states: first port D (shutdown), second port S (Selected via fallback)
    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'S'
    }

    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.log("FAIL: PortChannel fallback member state verification failed after shutdown")
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel fallback working - Second port Selected after first port shutdown, PortChannel UP")
    st.report_pass('test_case_passed')


def test_portchannel_fallback_with_port_shutdown():
    '''
    Verify the Portchannel status when both ports have LACP peers
    Verify portchannel status when only port is shutdown on DUT1
    '''
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[:2])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    # Shutdown first port on DUT1
    intf_obj.interface_shutdown(data.dut1, data.members_dut1[0], skip_verify=False)
    st.wait(10, "Waiting for interface shutdown to take effect")

    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel UP after DUT1 port shutdown, one LACP peer still present")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_1_min_link_without_lacp_peer():
    '''
    Verify the Portchannel status for a portchannel with no LACP peers and min-links lesser than the number of portchannel ports.
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True, min_link=1)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel UP without LACP peer with min-link as 1")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_2_min_link_with_only_one_lacp_peer():
    '''
    Verify the Portchannel status for a portchannel with min-links lesser than the number of portchannel ports and has LACP peer only one of the ports
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True, min_link=2)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1)
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut1[0])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D',
        data.members_dut1[2]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "down", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel DOWN with only 1 LACP peer and min-link as 2(Lesser than portchannel member count")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_tc_2_min_link_without_lacp_peer():
    '''
    Verify the Portchannel status for a portchannel with min-links equal to the number of portchannel ports and no LACP peers.
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True, min_link=2)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel UP without LACP peer with min-link as 2(Same as portchannel member count)")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_2_min_link_2_lacp_peer():
    '''
    Verify the Portchannel status for a portchannel with min-links equal to the number of the portchannel ports and
    LACP peer exists on all of the ports
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True, min_link=2)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut1[0])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "down", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    # Add second port to portchannel on DUT2
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut1[1])
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel UP with LACP peer on all ports and min-link as 2(Same as portchannel member count)")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_fast_rate():
    '''
    Verify the Portchannel status for a portchannel converges faster with fast-rate enabled
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name], fallback=True, fast_rate=True)
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(15, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'S'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    portchannel_obj.delete_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(15, "Waiting for lesser interval")

    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel UP once LACP peers goes down on all ports at a faster pace with fast-rate enabled")
    st.report_pass('test_case_passed')

def test_portchannel_fallback_without_fallback_enabled():
    '''
    Verify the LAG behavior when a portchannel with fallback enabled is removed and
    recreated as a normal portchannel without any LACP peers on any ports
    '''
    portchannel_obj.delete_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.create_portchannel(data.dut1, portchannel_list=[data.portchannel_name])
    portchannel_obj.add_portchannel_member(data.dut1, portchannel=data.portchannel_name, members=data.members_dut1[:2])
    st.wait(30, "Waiting for LACP negotiation")

    member_state_dict = {
        data.members_dut1[0]: 'D',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "down", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    # Add Port1 to portchannel on DUT2
    portchannel_obj.add_portchannel_member(data.dut2, portchannel=data.portchannel_name, members=data.members_dut2[0])
    st.wait(30, "Waiting for LACP negotiation")
    member_state_dict = {
        data.members_dut1[0]: 'S',
        data.members_dut1[1]: 'D'
    }
    if not portchannel_obj.verify_portchannel_member_state_fallback(data.dut1, data.portchannel_name, "up", member_state_dict):
        st.report_fail("portchannel_fallback_state_verification_fail")

    st.log("PASS: PortChannel DOWN on a normal portchannel without any LACP peers. State Change to UP once LACP peer comes up")
    st.report_pass('test_case_passed')
