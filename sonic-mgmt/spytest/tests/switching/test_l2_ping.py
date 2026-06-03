import pytest
from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as portchannel_obj
import apis.routing.ip as ip_obj
import apis.system.interface as intf_obj

# Test data
data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def vlan_ping_module_hooks(request):
    """
    Module level setup and teardown for VLAN ping tests.

    Topology:
        SD3 ---- SD1 ---- SD4
              (2 links)  (1 link)

    SD1 <-> SD3: Ethernet1_1, Ethernet1_2 (for 2-member PortChannel)
    SD1 <-> SD4: Ethernet1_5 on SD1, Ethernet1_2 on SD4
    """
    global vars

    vars = st.ensure_min_topology("D1D3:2", "D1D4:1")

    vlan_ping_init_data()



def vlan_ping_init_data():
    """
    Initialize test data variables.
    """
    # VLAN configuration
    data.vlan_id = 10
    data.vlan_id_2 = 20
    data.vlan_int = "Vlan{}".format(data.vlan_id)
    data.vlan_int_2 = "Vlan{}".format(data.vlan_id_2)

    # IP addresses for VLAN 10 (SD1 <-> SD3)
    data.d1_vlan10_ip = "10.1.1.1"
    data.d3_vlan10_ip = "10.1.1.2"

    # IP addresses for VLAN 10 transit (SD3 -> SD1 -> SD4)
    data.d3_vlan10_ip_transit = "10.1.1.1"
    data.d1_vlan10_ip_transit = "10.1.1.2"

    # IP addresses for VLAN 20 (SD1 <-> SD4)
    data.d1_vlan20_ip = "20.1.1.2"
    data.d4_vlan20_ip = "20.1.1.1"

    # Subnet info for static routes
    data.vlan10_subnet = "10.1.1.0/24"
    data.vlan20_subnet = "20.1.1.0/24"

    data.mask = "24"

    # PortChannel configuration
    data.portchannel_name = "PortChannel10"
    data.portchannel_name_2 = "PortChannel20"

    # DUT list
    data.dut1 = vars.D1  
    data.dut3 = vars.D3  
    data.dut4 = vars.D4  

    # Interface mappings
    data.d1d3_port1 = vars.D1D3P1  
    data.d1d3_port2 = vars.D1D3P2  
    data.d3d1_port1 = vars.D3D1P1  
    data.d3d1_port2 = vars.D3D1P2  
    data.d1d4_port1 = vars.D1D4P1  
    data.d4d1_port1 = vars.D4D1P1  
    # Ping settings
    data.ping_count = 5


def clear_portchannel_config(dut_list):
    """
    Clear all PortChannel configurations on the given DUTs.
    This is a simplified version that avoids klish-dependent EVPN operations.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("############## {} : PortChannel Cleanup ################".format(dut))
        portchannel_list = portchannel_obj.get_portchannel_list(dut)
        if portchannel_list:
            for portchannel in portchannel_list:
                portchannel_name = portchannel.get("teamdev") or portchannel.get("name")
                if not portchannel_name:
                    continue
                
                portchannel_members = portchannel_obj.get_portchannel_members(dut, portchannel_name)
                if portchannel_members:
                    if not portchannel_obj.delete_portchannel_member(dut, portchannel_name, portchannel_members):
                        st.log("Error while deleting portchannel members for {}".format(portchannel_name))
                
                if not portchannel_obj.delete_portchannel(dut, portchannel_name):
                    st.log("Portchannel deletion failed {}".format(portchannel_name))
    return True


def vlan_ping_module_cleanup():
    st.log("Cleanup: Clearing all configurations")

    # Clear static routes first (must be done before removing IPs)
    ip_obj.delete_static_route(data.dut3, data.d1_vlan10_ip_transit, data.vlan20_subnet, family='ipv4', skip_error_check=True)
    ip_obj.delete_static_route(data.dut4, data.d1_vlan20_ip, data.vlan10_subnet, family='ipv4', skip_error_check=True)

    # Clear IP, VLAN, and PortChannel configurations
    ip_obj.clear_ip_configuration(st.get_dut_names())
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    clear_portchannel_config(st.get_dut_names())


###############################################################################
# Verification Functions
###############################################################################

def verify_ping(dut, dest_ip, count=5, expected=True, max_attempts=1):
    """Verify ping from DUT to destination IP."""
    for attempt in range(1, max_attempts + 1):
        if attempt == 1:
            st.log("Step: Verifying ping from {} to {}".format(dut, dest_ip))
        result = ip_obj.ping(dut, dest_ip, family='ipv4', count=count)
        if (result and expected) or (not result and not expected):
            if expected:
                st.log("Ping to {} successful as expected".format(dest_ip))
            else:
                st.log("Ping to {} failed as expected".format(dest_ip))
            return True
        if attempt < max_attempts:
            st.wait(2, "Waiting before ping retry")

    if expected:
        st.error("Ping to {} failed, but expected to pass".format(dest_ip))
    else:
        st.error("Ping to {} succeeded, but expected to fail".format(dest_ip))
    return False


def verify_ping_both_sides(dut_a, dest_ip_b, dut_b, dest_ip_a, count=5, expected=True):
    """Verify ping between two DUTs in both directions."""
    max_attempts = 5 if expected else 1
    result = True
    if not verify_ping(dut_a, dest_ip_b, count=count, expected=expected, max_attempts=max_attempts):
        result = False
    if not verify_ping(dut_b, dest_ip_a, count=count, expected=expected, max_attempts=max_attempts):
        result = False
    return result


###############################################################################
# Test Case 1: VLAN with physical port as Untagged member
###############################################################################

def test_vlan_ping_physical_port_untagged():
    """
    Test Case 1: Validate Ping for VLAN with physical port as Untagged member

    Steps:
        1. Create VLAN 10 on SD1 and SD3
        2. Add physical port as untagged member on both devices
        3. Configure IP on Vlan10 interface on both devices
        4. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int

    st.banner("Test Case 1: VLAN with physical port as Untagged member")

    try:
        # Step 1: Create VLAN on SD1 and SD3
        st.log("Step: Creating VLAN {} on SD1 and SD3".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)

        # Step 2: Add physical port as untagged member to VLAN
        st.log("Step: Adding physical port as untagged member")
        vlan_obj.add_vlan_member(data.dut1, vlan_id, data.d1d3_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, data.d3d1_port1, tagging_mode=False)

        # Step 3: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 4: Verify configurations using show commands
        st.log("Step: Verifying VLAN configuration")
        vlan_obj.show_vlan_brief(data.dut1)
        vlan_obj.show_vlan_brief(data.dut3)

        # Step 5: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping between SD3 and SD1 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 2: VLAN with physical port as Tagged member
###############################################################################

def test_vlan_ping_physical_port_tagged():
    """
    Test Case 2: Validate Ping for VLAN with physical port as Tagged member

    Steps:
        1. Create VLAN 10 on SD1 and SD3
        2. Add physical port as tagged member on both devices
        3. Configure IP on Vlan10 interface on both devices
        4. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int

    st.banner("Test Case 2: VLAN with physical port as Tagged member")

    try:
        # Step 1: Create VLAN on SD1 and SD3
        st.log("Step: Creating VLAN {} on SD1 and SD3".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)

        # Step 2: Add physical port as tagged member to VLAN
        st.log("Step: Adding physical port as tagged member")
        vlan_obj.add_vlan_member(data.dut1, vlan_id, data.d1d3_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, data.d3d1_port1, tagging_mode=True)

        # Step 3: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 4: Verify configurations using show commands
        st.log("Step: Verifying VLAN configuration")
        vlan_obj.show_vlan_brief(data.dut1)
        vlan_obj.show_vlan_brief(data.dut3)

        # Step 5: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping between SD3 and SD1 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 3: VLAN with PortChannel, 1 member, Untagged
###############################################################################

def test_vlan_ping_portchannel_1member_untagged():
    """
    Test Case 3: Validate Ping for VLAN with PortChannel (1 member), Untagged

    Topology: SD3 ---- SD1 (VLAN 10 over PortChannel10, 1 member, Untagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3
        2. Add 1 member to PortChannel on both devices
        3. Create VLAN 10 and add PortChannel as untagged member
        4. Configure IP on Vlan10 interface on both devices
        5. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int
    portchannel = data.portchannel_name

    st.banner("Test Case 3: VLAN with PortChannel (1 member), Untagged")

    try:
        # Step 1: Create PortChannel on SD1 and SD3
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel))
        portchannel_obj.create_portchannel(data.dut1, portchannel)
        portchannel_obj.create_portchannel(data.dut3, portchannel)

        # Step 2: Add member to PortChannel
        st.log("Step: Adding member to PortChannel")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)

        # Step 3: Create VLAN and add PortChannel as untagged member
        st.log("Step: Creating VLAN {} and adding PortChannel as untagged member".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)
        vlan_obj.add_vlan_member(data.dut1, vlan_id, portchannel, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, portchannel, tagging_mode=False)

        # Step 4: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 6: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping between SD3 and SD1 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 4: VLAN with PortChannel, 1 member, Tagged
###############################################################################

def test_vlan_ping_portchannel_1member_tagged():
    """
    Test Case 4: Validate Ping for VLAN with PortChannel (1 member), Tagged

    Topology: SD3 ---- SD1 (VLAN 10 over PortChannel10, 1 member, Tagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3
        2. Add 1 member to PortChannel on both devices
        3. Create VLAN 10 and add PortChannel as tagged member
        4. Configure IP on Vlan10 interface on both devices
        5. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int
    portchannel = data.portchannel_name

    st.banner("Test Case 4: VLAN with PortChannel (1 member), Tagged")

    try:
        # Step 1: Create PortChannel on SD1 and SD3
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel))
        portchannel_obj.create_portchannel(data.dut1, portchannel)
        portchannel_obj.create_portchannel(data.dut3, portchannel)

        # Step 2: Add member to PortChannel
        st.log("Step: Adding member to PortChannel")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)

        # Step 3: Create VLAN and add PortChannel as tagged member
        st.log("Step: Creating VLAN {} and adding PortChannel as tagged member".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)
        vlan_obj.add_vlan_member(data.dut1, vlan_id, portchannel, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, portchannel, tagging_mode=True)

        # Step 4: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 6: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping between SD3 and SD1 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 5: VLAN with PortChannel, 2 members, Untagged (with toggle test)
###############################################################################

def test_vlan_ping_portchannel_2member_untagged():
    """
    Test Case 5: Validate Ping for VLAN with PortChannel (2 members), Untagged

    Topology: SD3 ---- SD1 (VLAN 10 over PortChannel10, 2 members, Untagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3
        2. Add 2 members to PortChannel on both devices
        3. Create VLAN 10 and add PortChannel as untagged member
        4. Configure IP on Vlan10 interface on both devices
        5. Verify ping from both sides (SD3->SD1 and SD1->SD3)
        6. Toggle test: Shutdown member1 on SD1 only, verify ping from both sides
        7. Toggle test: Shutdown member2 on SD1 only, verify ping from both sides
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int
    portchannel = data.portchannel_name

    st.banner("Test Case 5: VLAN with PortChannel (2 members), Untagged with Toggle Test")

    try:
        # Step 1: Create PortChannel on SD1 and SD3
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel))
        portchannel_obj.create_portchannel(data.dut1, portchannel)
        portchannel_obj.create_portchannel(data.dut3, portchannel)

        # Step 2: Add 2 members to PortChannel
        st.log("Step: Adding 2 members to PortChannel")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port2)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port2)

        st.wait(15, "Waiting for LACP negotiation")
        if not portchannel_obj.verify_portchannel_state(data.dut1, portchannel, state="up"):
            st.error("PortChannel not UP after member addition - cannot proceed")
            result = False

        # Step 3: Create VLAN and add PortChannel as untagged member
        st.log("Step: Creating VLAN {} and adding PortChannel as untagged member".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)
        vlan_obj.add_vlan_member(data.dut1, vlan_id, portchannel, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, portchannel, tagging_mode=False)

        # Step 4: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 6: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Initial ping between SD3 and SD1 failed")
            result = False

        # Step 7: Toggle test - Shutdown member1 on SD1 only (admin_down on SD1, op_down on SD3)
        st.log("Step: Toggle test - Shutting down member1 ({}) on SD1 only".format(data.d1d3_port1))
        intf_obj.interface_shutdown(data.dut1, data.d1d3_port1)
        st.wait(20, "Waiting for PortChannel to stabilize after member shutdown")

        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping failed after shutting down member1 on SD1 - expected to pass with 1 member active")
            result = False

        st.log("Step: Bringing up member1 ({}) on SD1".format(data.d1d3_port1))
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port1)
        st.wait(20, "Waiting for PortChannel to stabilize after member startup")

        # Step 8: Toggle test - Shutdown member2 on SD1 only (admin_down on SD1, op_down on SD3)
        st.log("Step: Toggle test - Shutting down member2 ({}) on SD1 only".format(data.d1d3_port2))
        intf_obj.interface_shutdown(data.dut1, data.d1d3_port2)
        st.wait(20, "Waiting for PortChannel to stabilize after member shutdown")

        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping failed after shutting down member2 on SD1 - expected to pass with 1 member active")
            result = False

        st.log("Step: Bringing up member2 ({}) on SD1".format(data.d1d3_port2))
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port2)
        st.wait(5, "Waiting for PortChannel to stabilize after member startup")

    finally:
        # Ensure SD1 interfaces are up before cleanup
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port1)
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port2)

        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 6: VLAN with PortChannel, 2 members, Tagged (with toggle test)
###############################################################################

def test_vlan_ping_portchannel_2member_tagged():
    """
    Test Case 6: Validate Ping for VLAN with PortChannel (2 members), Tagged

    Topology: SD3 ---- SD1 (VLAN 10 over PortChannel10, 2 members, Tagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3
        2. Add 2 members to PortChannel on both devices
        3. Create VLAN 10 and add PortChannel as tagged member
        4. Configure IP on Vlan10 interface on both devices
        5. Verify ping from both sides (SD3->SD1 and SD1->SD3)
        6. Toggle test: Shutdown member1 on SD1 only, verify ping from both sides
        7. Toggle test: Shutdown member2 on SD1 only, verify ping from both sides
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int
    portchannel = data.portchannel_name

    st.banner("Test Case 6: VLAN with PortChannel (2 members), Tagged with Toggle Test")

    try:
        # Step 1: Create PortChannel on SD1 and SD3
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel))
        portchannel_obj.create_portchannel(data.dut1, portchannel)
        portchannel_obj.create_portchannel(data.dut3, portchannel)

        # Step 2: Add 2 members to PortChannel
        st.log("Step: Adding 2 members to PortChannel")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port2)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port2)

        st.wait(15, "Waiting for LACP negotiation")
        if not portchannel_obj.verify_portchannel_state(data.dut1, portchannel, state="up"):
            st.error("PortChannel not UP after member addition - cannot proceed")
            result = False

        # Step 3: Create VLAN and add PortChannel as tagged member
        st.log("Step: Creating VLAN {} and adding PortChannel as tagged member".format(vlan_id))
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)
        vlan_obj.add_vlan_member(data.dut1, vlan_id, portchannel, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, portchannel, tagging_mode=True)

        # Step 4: Configure IPv4 address on Vlan10 on both devices
        st.log("Step: Configuring IPv4 addresses on Vlan10")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 6: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Initial ping between SD3 and SD1 failed")
            result = False

        # Step 7: Toggle test - Shutdown member1 on SD1 only (admin_down on SD1, op_down on SD3)
        st.log("Step: Toggle test - Shutting down member1 ({}) on SD1 only".format(data.d1d3_port1))
        intf_obj.interface_shutdown(data.dut1, data.d1d3_port1)
        st.wait(20, "Waiting for PortChannel to stabilize after member shutdown")

        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping failed after shutting down member1 on SD1 - expected to pass with 1 member active")
            result = False

        st.log("Step: Bringing up member1 ({}) on SD1".format(data.d1d3_port1))
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port1)
        st.wait(20, "Waiting for PortChannel to stabilize after member startup")

        # Step 8: Toggle test - Shutdown member2 on SD1 only (admin_down on SD1, op_down on SD3)
        st.log("Step: Toggle test - Shutting down member2 ({}) on SD1 only".format(data.d1d3_port2))
        intf_obj.interface_shutdown(data.dut1, data.d1d3_port2)
        st.wait(20, "Waiting for PortChannel to stabilize after member shutdown")

        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping failed after shutting down member2 on SD1 - expected to pass with 1 member active")
            result = False

        st.log("Step: Bringing up member2 ({}) on SD1".format(data.d1d3_port2))
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port2)
        st.wait(5, "Waiting for PortChannel to stabilize after member startup")

    finally:
        # Ensure SD1 interfaces are up before cleanup
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port1)
        intf_obj.interface_noshutdown(data.dut1, data.d1d3_port2)

        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 7: Transit Ping for VLAN with physical port as Untagged member
###############################################################################

def test_vlan_transit_ping_physical_port_untagged():
    """
    Test Case 7: Validate transit Ping for VLAN with physical port as Untagged member

    Topology:
        SD3 (10.1.1.1/24) ---- SD1 (10.1.1.2/24, 20.1.1.2/24) ---- SD4 (20.1.1.1/24)
              VLAN 10                                                    VLAN 20

    Steps:
        1. Create VLAN 10 on SD1 and SD3, VLAN 20 on SD1 and SD4
        2. Add physical ports as untagged members
        3. Configure IP addresses on Vlan interfaces
        4. Configure static routes on SD3 and SD4 for transit
        5. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 7: Transit Ping for VLAN with physical port as Untagged member")

    try:
        # Step 1: Create VLANs
        st.log("Step: Creating VLAN 10 on SD1 and SD3")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN 20 on SD1 and SD4")
        vlan_obj.create_vlan(data.dut1, vlan_id_20)
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 2: Add physical ports as untagged members
        st.log("Step: Adding physical ports as untagged members")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, data.d1d3_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, data.d3d1_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, data.d1d4_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, data.d4d1_port1, tagging_mode=False)

        # Step 3: Configure IP addresses on Vlan interfaces
        st.log("Step: Configuring IPv4 addresses on Vlan interfaces")
        # SD1: Vlan10 = 10.1.1.2, Vlan20 = 20.1.1.2
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_vlan20_ip, data.mask, family='ipv4')
        # SD3: Vlan10 = 10.1.1.1
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_vlan10_ip_transit, data.mask, family='ipv4')
        # SD4: Vlan20 = 20.1.1.1
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_vlan20_ip, data.mask, family='ipv4')

        # Step 4: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        # SD3: route to 20.1.1.0/24 via 10.1.1.2
        ip_obj.create_static_route(data.dut3, data.d1_vlan10_ip_transit, data.vlan20_subnet, family='ipv4')
        # SD4: route to 10.1.1.0/24 via 20.1.1.2
        ip_obj.create_static_route(data.dut4, data.d1_vlan20_ip, data.vlan10_subnet, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying VLAN configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        vlan_obj.show_vlan_brief(data.dut3)
        vlan_obj.show_vlan_brief(data.dut4)

        # Step 6: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_vlan20_ip, data.dut4, data.d3_vlan10_ip_transit,
                                      count=data.ping_count):
            st.error("Transit ping between SD3 and SD4 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 8: Transit Ping for VLAN with physical port as Tagged member
###############################################################################

def test_vlan_transit_ping_physical_port_tagged():
    """
    Test Case 8: Validate transit Ping for VLAN with physical port as Tagged member

    Topology:
        SD3 (10.1.1.1/24) ---- SD1 (10.1.1.2/24, 20.1.1.2/24) ---- SD4 (20.1.1.1/24)
              VLAN 10 (Tagged)                                       VLAN 20 (Tagged)

    Steps:
        1. Create VLAN 10 on SD1 and SD3, VLAN 20 on SD1 and SD4
        2. Add physical ports as tagged members
        3. Configure IP addresses on Vlan interfaces
        4. Configure static routes on SD3 and SD4 for transit
        5. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 8: Transit Ping for VLAN with physical port as Tagged member")

    try:
        # Step 1: Create VLANs
        st.log("Step: Creating VLAN 10 on SD1 and SD3")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN 20 on SD1 and SD4")
        vlan_obj.create_vlan(data.dut1, vlan_id_20)
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 2: Add physical ports as tagged members
        st.log("Step: Adding physical ports as tagged members")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, data.d1d3_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, data.d3d1_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, data.d1d4_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, data.d4d1_port1, tagging_mode=True)

        # Step 3: Configure IP addresses on Vlan interfaces
        st.log("Step: Configuring IPv4 addresses on Vlan interfaces")
        
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_vlan20_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_vlan20_ip, data.mask, family='ipv4')

        # Step 4: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_vlan10_ip_transit, data.vlan20_subnet, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_vlan20_ip, data.vlan10_subnet, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying VLAN configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        vlan_obj.show_vlan_brief(data.dut3)
        vlan_obj.show_vlan_brief(data.dut4)

        # Step 6: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_vlan20_ip, data.dut4, data.d3_vlan10_ip_transit,
                                      count=data.ping_count):
            st.error("Transit ping between SD3 and SD4 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 9: Transit Ping for VLAN with PortChannel as Untagged member
###############################################################################

def test_vlan_transit_ping_portchannel_untagged():
    """
    Test Case 9: Validate transit Ping for VLAN with PortChannel as Untagged member

    Topology:
        SD3 (10.1.1.1/24) ---- SD1 (10.1.1.2/24, 20.1.1.2/24) ---- SD4 (20.1.1.1/24)
              PortChannel10 (VLAN 10, Untagged)      PortChannel20 (VLAN 20, Untagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3, PortChannel20 on SD1 and SD4
        2. Add members to PortChannels
        3. Create VLANs and add PortChannels as untagged members
        4. Configure IP addresses on Vlan interfaces
        5. Configure static routes on SD3 and SD4 for transit
        6. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2
    portchannel_10 = data.portchannel_name
    portchannel_20 = data.portchannel_name_2

    st.banner("Test Case 9: Transit Ping for VLAN with PortChannel as Untagged member")

    try:
        # Step 1: Create PortChannels
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel_10))
        portchannel_obj.create_portchannel(data.dut1, portchannel_10)
        portchannel_obj.create_portchannel(data.dut3, portchannel_10)

        st.log("Step: Creating {} on SD1 and SD4".format(portchannel_20))
        portchannel_obj.create_portchannel(data.dut1, portchannel_20)
        portchannel_obj.create_portchannel(data.dut4, portchannel_20)

        # Step 2: Add members to PortChannels
        st.log("Step: Adding members to PortChannels")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_10, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel_10, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_20, data.d1d4_port1)
        portchannel_obj.add_portchannel_member(data.dut4, portchannel_20, data.d4d1_port1)

        # Step 3: Create VLANs and add PortChannels as untagged members
        st.log("Step: Creating VLANs and adding PortChannels as untagged members")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)
        vlan_obj.create_vlan(data.dut3, vlan_id_10)
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, portchannel_10, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, portchannel_20, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, portchannel_10, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, portchannel_20, tagging_mode=False)

        # Step 4: Configure IP addresses on Vlan interfaces
        st.log("Step: Configuring IPv4 addresses on Vlan interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_vlan20_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_vlan20_ip, data.mask, family='ipv4')

        # Step 5: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_vlan10_ip_transit, data.vlan20_subnet, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_vlan20_ip, data.vlan10_subnet, family='ipv4')

        # Step 6: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 7: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_vlan20_ip, data.dut4, data.d3_vlan10_ip_transit,
                                      count=data.ping_count):
            st.error("Transit ping between SD3 and SD4 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 10: Transit Ping for VLAN with PortChannel as Tagged member
###############################################################################

def test_vlan_transit_ping_portchannel_tagged():
    """
    Test Case 10: Validate transit Ping for VLAN with PortChannel as Tagged member

    Topology:
        SD3 (10.1.1.1/24) ---- SD1 (10.1.1.2/24, 20.1.1.2/24) ---- SD4 (20.1.1.1/24)
              PortChannel10 (VLAN 10, Tagged)        PortChannel20 (VLAN 20, Tagged)

    Steps:
        1. Create PortChannel10 on SD1 and SD3, PortChannel20 on SD1 and SD4
        2. Add members to PortChannels
        3. Create VLANs and add PortChannels as tagged members
        4. Configure IP addresses on Vlan interfaces
        5. Configure static routes on SD3 and SD4 for transit
        6. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2
    portchannel_10 = data.portchannel_name
    portchannel_20 = data.portchannel_name_2

    st.banner("Test Case 10: Transit Ping for VLAN with PortChannel as Tagged member")

    try:
        # Step 1: Create PortChannels
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel_10))
        portchannel_obj.create_portchannel(data.dut1, portchannel_10)
        portchannel_obj.create_portchannel(data.dut3, portchannel_10)

        st.log("Step: Creating {} on SD1 and SD4".format(portchannel_20))
        portchannel_obj.create_portchannel(data.dut1, portchannel_20)
        portchannel_obj.create_portchannel(data.dut4, portchannel_20)

        # Step 2: Add members to PortChannels
        st.log("Step: Adding members to PortChannels")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_10, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel_10, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_20, data.d1d4_port1)
        portchannel_obj.add_portchannel_member(data.dut4, portchannel_20, data.d4d1_port1)

        # Step 3: Create VLANs and add PortChannels as tagged members
        st.log("Step: Creating VLANs and adding PortChannels as tagged members")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)
        vlan_obj.create_vlan(data.dut3, vlan_id_10)
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, portchannel_10, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, portchannel_20, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, portchannel_10, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, portchannel_20, tagging_mode=True)

        # Step 4: Configure IP addresses on Vlan interfaces
        st.log("Step: Configuring IPv4 addresses on Vlan interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_vlan20_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_vlan10_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_vlan20_ip, data.mask, family='ipv4')

        # Step 5: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_vlan10_ip_transit, data.vlan20_subnet, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_vlan20_ip, data.vlan10_subnet, family='ipv4')

        # Step 6: Verify configurations
        st.log("Step: Verifying configurations")
        vlan_obj.show_vlan_brief(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut1)

        # Step 7: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_vlan20_ip, data.dut4, data.d3_vlan10_ip_transit,
                                      count=data.ping_count):
            st.error("Transit ping between SD3 and SD4 failed")
            result = False

    finally:
        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 11: PortChannel min-links constraint with ping verification
###############################################################################

def test_vlan_ping_portchannel_minlinks():
    """
    Test Case 11: PortChannel min-links constraint with ping verification

    Steps:
        1. Create PortChannel with min-links=2 on SD1 and SD3
        2. Add 2 members and configure VLAN/IP
        3. Verify ping from both sides
        4. Shutdown one member on SD3 only (admin_down on SD3, op_down on SD1 peer)
        5. Verify ping fails in both directions due to min-links constraint
        6. Restore member and verify ping from both sides again
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int
    portchannel = data.portchannel_name
    min_links = 2

    st.banner("Test Case 11: PortChannel min-links constraint with ping verification")

    try:
        # Step 1: Create PortChannel with min-links on SD1, without min-links on SD3
        portchannel_obj.create_portchannel(data.dut1, portchannel, min_link=str(min_links))
        portchannel_obj.create_portchannel(data.dut3, portchannel, min_link=str(min_links))

        # Step 2: Add 2 members to PortChannel
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port2)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port2)

        # Step 3: Create VLAN and add PortChannel as untagged member
        vlan_obj.create_vlan(data.dut1, vlan_id)
        vlan_obj.create_vlan(data.dut3, vlan_id)
        vlan_obj.add_vlan_member(data.dut1, vlan_id, portchannel, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id, portchannel, tagging_mode=False)

        # Step 4: Configure IPv4 address on Vlan10 on both devices
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_vlan10_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_vlan10_ip, data.mask, family='ipv4')

        # Step 5: Verify initial state - PortChannel UP and ping works
        st.log("Step: Verifying initial state - PortChannel should be UP")
        portchannel_obj.get_portchannel_list(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut3)

        st.log("Step: Verifying initial ping from both sides")
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Initial ping between SD3 and SD1 failed - expected to pass")
            result = False

        # Step 6: Shutdown one member on SD3 only (admin_down on SD3, op_down on SD1 peer)
        st.log("Step: Shutting down member1 ({}) on SD3 only".format(data.d3d1_port1))
        intf_obj.interface_shutdown(data.dut3, data.d3d1_port1)
        
        # Step 7: Verify PortChannel state and ping
        st.log("Step: Verifying PortChannel state after shutting down one member on SD3")
        portchannel_obj.get_portchannel_list(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut3)

        st.log("Step: Verifying ping fails in both directions due to min-links constraint on SD1")
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count, expected=False):
            st.error("Ping succeeded but expected to fail due to min-links constraint")
            result = False

        # Step 8: Bring member back up on SD3
        st.log("Step: Bringing up member1 ({}) on SD3".format(data.d3d1_port1))
        intf_obj.interface_noshutdown(data.dut3, data.d3d1_port1)
        st.wait(30, "Waiting for PortChannel to stabilize after member startup")

        # Step 9: Verify PortChannel UP again and ping works from both sides
        st.log("Step: Verifying PortChannel state after bringing member back up on SD3")
        portchannel_obj.get_portchannel_list(data.dut1)
        portchannel_obj.get_portchannel_list(data.dut3)

        st.log("Step: Verifying ping works again from both sides after restoring min-links")
        if not verify_ping_both_sides(data.dut3, data.d1_vlan10_ip, data.dut1, data.d3_vlan10_ip,
                                      count=data.ping_count):
            st.error("Ping between SD3 and SD1 failed after restoring min-links")
            result = False

    finally:
        # Ensure SD3 interfaces are up before cleanup
        intf_obj.interface_noshutdown(data.dut3, data.d3d1_port1)
        intf_obj.interface_noshutdown(data.dut3, data.d3d1_port2)

        vlan_ping_module_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")