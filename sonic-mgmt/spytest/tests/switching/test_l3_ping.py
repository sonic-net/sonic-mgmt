import pytest
from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as portchannel_obj
import apis.routing.ip as ip_obj

# Test data
data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def l3_ping_module_hooks(request):
    """
    Module level setup and teardown for L3 ping tests.

    Topology:
        SD3 ---- SD1 ---- SD4
              (2 links)  (1 link)

    Single hop: SD1 <-> SD3
    Transit: SD3 <-> SD1 <-> SD4
    SD1 <-> SD3: Ethernet1_1, Ethernet1_2
    SD1 <-> SD4: Ethernet1_5 on SD1, Ethernet1_2 on SD4
    """
    global vars

    vars = st.ensure_min_topology("D1D3:2", "D1D4:1")

    l3_ping_init_data()

    yield


def l3_ping_init_data():
    """
    Initialize test data variables.
    """
    # VLAN configuration (for SVI tests)
    data.vlan_id = 10
    data.vlan_id_2 = 20
    data.vlan_int = "Vlan{}".format(data.vlan_id)
    data.vlan_int_2 = "Vlan{}".format(data.vlan_id_2)

    # IP addresses for single hop tests (SD1 <-> SD3)
    data.d1_ip = "10.1.1.1"
    data.d3_ip = "10.1.1.2"

    # IP addresses for transit tests (SD3 -> SD1 -> SD4)
    data.d3_ip_transit = "10.1.1.1"
    data.d1_ip_left = "10.1.1.2"   
    data.d1_ip_right = "20.1.1.2"  
    data.d4_ip_transit = "20.1.1.1"

    # Subnet info for static routes
    data.subnet_10 = "10.1.1.0/24"
    data.subnet_20 = "20.1.1.0/24"

    data.mask = "24"

    # Subinterface configuration
    data.subintf_id = 10
    data.subintf_id_2 = 20

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


def l3_ping_test_cleanup():
    """
    Per-testcase cleanup: clear routes, IP, VLAN, and PortChannel configurations.
    Subinterface tests must delete their own subinterfaces before calling this.
    """
    st.log("Cleanup: Clearing test configurations")

    # Clear static routes first (must be done before removing IPs)
    ip_obj.delete_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4', skip_error_check=True)
    ip_obj.delete_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4', skip_error_check=True)

    ip_obj.clear_ip_configuration(st.get_dut_names())
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    clear_portchannel_config(st.get_dut_names())


###############################################################################
# Verification Functions
###############################################################################

def verify_ping(dut, dest_ip, count=5, expected=True):
    """
    Verify ping from DUT to destination IP.
    """
    st.log("Step: Verifying ping from {} to {}".format(dut, dest_ip))
    result = ip_obj.ping(dut, dest_ip, family='ipv4', count=count)

    if expected:
        if result:
            st.log("Ping to {} successful as expected".format(dest_ip))
            return True
        else:
            st.error("Ping to {} failed, but expected to pass".format(dest_ip))
            return False
    else:
        if not result:
            st.log("Ping to {} failed as expected".format(dest_ip))
            return True
        else:
            st.error("Ping to {} succeeded, but expected to fail".format(dest_ip))
            return False


def verify_ping_both_sides(dut_a, dest_ip_b, dut_b, dest_ip_a, count=5, expected=True):
    """
    Verify ping between two DUTs in both directions.
    """
    result = True
    if not verify_ping(dut_a, dest_ip_b, count=count, expected=expected):
        result = False
    if not verify_ping(dut_b, dest_ip_a, count=count, expected=expected):
        result = False
    return result


def get_subinterface_name(interface, vlan_id):
    """
    Construct subinterface name from interface and VLAN ID.
    Uses short interface naming convention.
    Examples:
        Ethernet1_1, 10 -> Eth1_1.10
        PortChannel10, 10 -> Po10.10
    """
    if interface.startswith("Ethernet"):
        short_name = interface.replace("Ethernet", "Eth")
    elif interface.startswith("PortChannel"):
        short_name = interface.replace("PortChannel", "Po")
    
    return "{}.{}".format(short_name, vlan_id)


###############################################################################
# Test Case 1: SVI Ping (VLAN Interface)
###############################################################################

def test_l3_svi_ping():
    """
    Test Case 1: Validate SVI Ping

    Topology: SD3 ---- SD1 (VLAN 10 SVI)

    Steps:
        1. Create VLAN 10 on SD1 and SD3
        2. Add physical port as untagged member on both devices
        3. Configure IP on Vlan10 interface on both devices
        4. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    vlan_id = data.vlan_id
    vlan_int = data.vlan_int

    st.banner("Test Case 1: Validate SVI Ping")

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
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int, data.d1_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int, data.d3_ip, data.mask, family='ipv4')

        # Step 4: Verify configurations
        st.log("Step: Verifying VLAN configuration")
        vlan_obj.show_vlan_brief(data.dut1)
        vlan_obj.show_vlan_brief(data.dut3)

        # Step 5: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_ip, data.dut1, data.d3_ip, count=data.ping_count):
            st.error("SVI ping between SD3 and SD1 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 2: Routed Port Ping (No VLAN)
###############################################################################

def test_l3_routed_port_ping():
    """
    Test Case 2: Validate Routed Port Ping (No VLAN)

    Topology: SD3 ---- SD1 (Direct IP on physical port)

    Steps:
        1. Configure IP directly on physical port on both devices
        2. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True

    st.banner("Test Case 2: Validate Routed Port Ping (No VLAN)")

    try:
        # Step 1: Configure IPv4 address directly on physical ports
        st.log("Step: Configuring IPv4 addresses on physical ports")
        ip_obj.config_ip_addr_interface(data.dut1, data.d1d3_port1, data.d1_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, data.d3d1_port1, data.d3_ip, data.mask, family='ipv4')

        # Step 2: Verify interface status
        st.log("Step: Verifying interface configuration")
        ip_obj.get_interface_ip_address(data.dut1, interface_name=data.d1d3_port1)
        ip_obj.get_interface_ip_address(data.dut3, interface_name=data.d3d1_port1)

        # Step 3: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_ip, data.dut1, data.d3_ip, count=data.ping_count):
            st.error("Routed port ping between SD3 and SD1 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 3: Subinterface on Physical Port
###############################################################################

def test_l3_subinterface_physical_port_ping():
    """
    Test Case 3: Validate Subinterface on Physical Port Ping

    Topology: SD3 ---- SD1 (Subinterface Ethernet1_1.10)

    Steps:
        1. Create subinterface on physical port on both devices
        2. Configure IP on subinterface on both devices
        3. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    subintf_d1 = get_subinterface_name(data.d1d3_port1, data.subintf_id)
    subintf_d3 = get_subinterface_name(data.d3d1_port1, data.subintf_id)

    st.banner("Test Case 3: Validate Subinterface on Physical Port Ping")

    try:
        # Step 1: Create subinterface on physical ports
        st.log("Step: Creating subinterface {} on SD1".format(subintf_d1))
        ip_obj.config_sub_interface(data.dut1, subintf_d1, vlan=data.subintf_id, config='yes')

        st.log("Step: Creating subinterface {} on SD3".format(subintf_d3))
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='yes')

        # Step 2: Configure IPv4 address on subinterfaces
        st.log("Step: Configuring IPv4 addresses on subinterfaces")
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1, data.d1_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, subintf_d3, data.d3_ip, data.mask, family='ipv4')

        # Step 3: Verify interface status
        st.log("Step: Verifying subinterface configuration")
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1)
        ip_obj.get_interface_ip_address(data.dut3, interface_name=subintf_d3)

        # Step 4: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_ip, data.dut1, data.d3_ip, count=data.ping_count):
            st.error("Subinterface ping between SD3 and SD1 failed")
            result = False

    finally:
        st.log("Step: Cleanup - Deleting subinterfaces")
        ip_obj.config_sub_interface(data.dut1, subintf_d1, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='no', skip_error_check=True)
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 4: Subinterface on PortChannel
###############################################################################

def test_l3_subinterface_portchannel_ping():
    """
    Test Case 4: Validate Subinterface on PortChannel Ping

    Topology: SD3 ---- SD1 (Subinterface PortChannel10.10)

    Subinterface is created on PortChannel; subinterface packets are always tagged.

    Steps:
        1. Create PortChannel on both devices
        2. Add member to PortChannel
        3. Create subinterface on PortChannel
        4. Configure IP on subinterface
        5. Verify ping from both sides (SD3->SD1 and SD1->SD3)
    """
    result = True
    portchannel = data.portchannel_name
    subintf_d1 = get_subinterface_name(portchannel, data.subintf_id)
    subintf_d3 = get_subinterface_name(portchannel, data.subintf_id)

    st.banner("Test Case 4: Validate Subinterface on PortChannel Ping")

    try:
        # Step 1: Create PortChannel on SD1 and SD3
        st.log("Step: Creating {} on SD1 and SD3".format(portchannel))
        portchannel_obj.create_portchannel(data.dut1, portchannel)
        portchannel_obj.create_portchannel(data.dut3, portchannel)

        # Step 2: Add member to PortChannel
        st.log("Step: Adding member to PortChannel")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel, data.d3d1_port1)

        # Step 3: Create subinterface on PortChannel
        st.log("Step: Creating subinterface {} on SD1".format(subintf_d1))
        ip_obj.config_sub_interface(data.dut1, subintf_d1, vlan=data.subintf_id, config='yes')

        st.log("Step: Creating subinterface {} on SD3".format(subintf_d3))
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='yes')

        # Step 4: Configure IPv4 address on subinterfaces
        st.log("Step: Configuring IPv4 addresses on subinterfaces")
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1, data.d1_ip, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, subintf_d3, data.d3_ip, data.mask, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying configurations")
        portchannel_obj.get_portchannel_list(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1)

        # Step 6: Verify ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d1_ip, data.dut1, data.d3_ip, count=data.ping_count):
            st.error("Subinterface on PortChannel ping between SD3 and SD1 failed")
            result = False

    finally:
        st.log("Step: Cleanup - Deleting subinterfaces")
        ip_obj.config_sub_interface(data.dut1, subintf_d1, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='no', skip_error_check=True)
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 5: Transit Routed Port
###############################################################################

def test_l3_transit_routed_port_ping():
    """
    Test Case 5: Validate Transit Routed Port Ping

    Steps:
        1. Configure IP on physical ports on all devices
        2. Configure static routes on SD3 and SD4 for transit
        3. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True

    st.banner("Test Case 5: Validate Transit Routed Port Ping")

    try:
        # Step 1: Configure IPv4 address on physical ports
        st.log("Step: Configuring IPv4 addresses on physical ports")
        # SD1: IP on port facing SD3 and port facing SD4
        ip_obj.config_ip_addr_interface(data.dut1, data.d1d3_port1, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, data.d1d4_port1, data.d1_ip_right, data.mask, family='ipv4')
        # SD3: IP on port facing SD1
        ip_obj.config_ip_addr_interface(data.dut3, data.d3d1_port1, data.d3_ip_transit, data.mask, family='ipv4')
        # SD4: IP on port facing SD1
        ip_obj.config_ip_addr_interface(data.dut4, data.d4d1_port1, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 2: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        # SD3: route to 20.1.1.0/24 via 10.1.1.2
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        # SD4: route to 10.1.1.0/24 via 20.1.1.2
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 3: Verify configurations
        st.log("Step: Verifying interface configuration")
        ip_obj.get_interface_ip_address(data.dut1, interface_name=data.d1d3_port1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=data.d1d4_port1)

        # Step 4: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit routed port ping between SD3 and SD4 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 6: Transit Subinterface (Physical Port)
###############################################################################

def test_l3_transit_subinterface_physical_ping():
    """
    Test Case 6: Validate Transit Subinterface (Physical Port) Ping

    Steps:
        1. Create subinterfaces on physical ports on all devices
        2. Configure IP on subinterfaces
        3. Configure static routes on SD3 and SD4 for transit
        4. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    # Subinterface names
    subintf_d1_left = get_subinterface_name(data.d1d3_port1, data.subintf_id)      # Ethernet1_1.10
    subintf_d1_right = get_subinterface_name(data.d1d4_port1, data.subintf_id_2)   # Ethernet1_5.20
    subintf_d3 = get_subinterface_name(data.d3d1_port1, data.subintf_id)           # Ethernet1_1.10
    subintf_d4 = get_subinterface_name(data.d4d1_port1, data.subintf_id_2)         # Ethernet1_2.20

    st.banner("Test Case 6: Validate Transit Subinterface (Physical Port) Ping")

    try:
        # Step 1: Create subinterfaces on physical ports
        st.log("Step: Creating subinterfaces on SD1")
        ip_obj.config_sub_interface(data.dut1, subintf_d1_left, vlan=data.subintf_id, config='yes')
        ip_obj.config_sub_interface(data.dut1, subintf_d1_right, vlan=data.subintf_id_2, config='yes')

        st.log("Step: Creating subinterface on SD3")
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='yes')

        st.log("Step: Creating subinterface on SD4")
        ip_obj.config_sub_interface(data.dut4, subintf_d4, vlan=data.subintf_id_2, config='yes')

        # Step 2: Configure IPv4 address on subinterfaces
        st.log("Step: Configuring IPv4 addresses on subinterfaces")
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1_left, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1_right, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, subintf_d3, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, subintf_d4, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 3: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 4: Verify configurations
        st.log("Step: Verifying subinterface configuration")
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1_left)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1_right)

        # Step 5: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit subinterface ping between SD3 and SD4 failed")
            result = False

    finally:
        st.log("Step: Cleanup - Deleting subinterfaces")
        ip_obj.config_sub_interface(data.dut1, subintf_d1_left, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut1, subintf_d1_right, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut4, subintf_d4, vlan=data.subintf_id, config='no', skip_error_check=True)
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 7: Transit Subinterface on PortChannel
###############################################################################

def test_l3_transit_subinterface_portchannel_ping():
    """
    Test Case 7: Validate Transit Subinterface on PortChannel Ping

    Topology:
        SD3 (PC10.10: 10.1.1.1/24) ---- SD1 (PC10.10: 10.1.1.2/24, PC20.20: 20.1.1.2/24) ---- SD4 (PC20.20: 20.1.1.1/24)

    Subinterface is created on PortChannel; subinterface packets are always tagged.

    Steps:
        1. Create PortChannels on all devices
        2. Add members to PortChannels
        3. Create subinterfaces on PortChannels
        4. Configure IP on subinterfaces
        5. Configure static routes on SD3 and SD4 for transit
        6. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    portchannel_10 = data.portchannel_name
    portchannel_20 = data.portchannel_name_2

    # Subinterface names
    subintf_d1_pc10 = get_subinterface_name(portchannel_10, data.subintf_id)       
    subintf_d1_pc20 = get_subinterface_name(portchannel_20, data.subintf_id_2)     
    subintf_d3 = get_subinterface_name(portchannel_10, data.subintf_id)            
    subintf_d4 = get_subinterface_name(portchannel_20, data.subintf_id_2)          

    st.banner("Test Case 7: Validate Transit Subinterface on PortChannel Ping")

    try:
        # Step 1: Create PortChannels
        st.log("Step: Creating PortChannels on SD1")
        portchannel_obj.create_portchannel(data.dut1, portchannel_10)
        portchannel_obj.create_portchannel(data.dut1, portchannel_20)

        st.log("Step: Creating PortChannel on SD3")
        portchannel_obj.create_portchannel(data.dut3, portchannel_10)

        st.log("Step: Creating PortChannel on SD4")
        portchannel_obj.create_portchannel(data.dut4, portchannel_20)

        # Step 2: Add members to PortChannels
        st.log("Step: Adding members to PortChannels")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_10, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_20, data.d1d4_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel_10, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut4, portchannel_20, data.d4d1_port1)

        # Step 3: Create subinterfaces on PortChannels
        st.log("Step: Creating subinterfaces on PortChannels")
        ip_obj.config_sub_interface(data.dut1, subintf_d1_pc10, vlan=data.subintf_id, config='yes')
        ip_obj.config_sub_interface(data.dut1, subintf_d1_pc20, vlan=data.subintf_id_2, config='yes')
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='yes')
        ip_obj.config_sub_interface(data.dut4, subintf_d4, vlan=data.subintf_id_2, config='yes')

        # Step 4: Configure IPv4 address on subinterfaces
        st.log("Step: Configuring IPv4 addresses on subinterfaces")
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1_pc10, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, subintf_d1_pc20, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, subintf_d3, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, subintf_d4, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 5: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 6: Verify configurations
        st.log("Step: Verifying configurations")
        portchannel_obj.get_portchannel_list(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1_pc10)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=subintf_d1_pc20)

        # Step 7: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit subinterface on PortChannel ping between SD3 and SD4 failed")
            result = False

    finally:
        st.log("Step: Cleanup - Deleting subinterfaces")
        ip_obj.config_sub_interface(data.dut1, subintf_d1_pc10, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut1, subintf_d1_pc20, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut3, subintf_d3, vlan=data.subintf_id, config='no', skip_error_check=True)
        ip_obj.config_sub_interface(data.dut4, subintf_d4, vlan=data.subintf_id, config='no', skip_error_check=True)
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 8: Transit VLAN SVI on Physical Port (Tagged)
###############################################################################

def test_l3_transit_vlan_physical_tagged_ping():
    """
    Test Case 8: Validate Transit VLAN SVI on Physical Port (Tagged) Ping

    Topology:
        SD3 (Vlan10: 10.1.1.1/24) ---- SD1 (Vlan10: 10.1.1.2/24, Vlan20: 20.1.1.2/24) ---- SD4 (Vlan20: 20.1.1.1/24)

    Steps:
        1. Create VLANs on all devices
        2. Add physical ports as tagged members to VLANs
        3. Configure IP on VLAN interfaces (SVIs)
        4. Configure static routes on SD3 and SD4 for transit
        5. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 8: Validate Transit VLAN SVI on Physical Port (Tagged) Ping")

    try:
        # Step 1: Create VLANs
        st.log("Step: Creating VLANs on SD1")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)

        st.log("Step: Creating VLAN on SD3")
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN on SD4")
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 2: Add physical ports as tagged members to VLANs
        st.log("Step: Adding physical ports as tagged members to VLANs")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, data.d1d3_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, data.d1d4_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, data.d3d1_port1, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, data.d4d1_port1, tagging_mode=True)

        # Step 3: Configure IPv4 address on VLAN interfaces (SVIs)
        st.log("Step: Configuring IPv4 addresses on VLAN interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 4: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying VLAN configuration")
        vlan_obj.show_vlan_brief(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_10)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_20)

        # Step 6: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit VLAN SVI on physical port (tagged) ping between SD3 and SD4 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 9: Transit VLAN SVI on Physical Port (Untagged)
###############################################################################

def test_l3_transit_vlan_physical_untagged_ping():
    """
    Test Case 9: Validate Transit VLAN SVI on Physical Port (Untagged) Ping

    Topology:
        SD3 (Vlan10: 10.1.1.1/24) ---- SD1 (Vlan10: 10.1.1.2/24, Vlan20: 20.1.1.2/24) ---- SD4 (Vlan20: 20.1.1.1/24)

    Steps:
        1. Create VLANs on all devices
        2. Add physical ports as untagged members to VLANs
        3. Configure IP on VLAN interfaces (SVIs)
        4. Configure static routes on SD3 and SD4 for transit
        5. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 9: Validate Transit VLAN SVI on Physical Port (Untagged) Ping")

    try:
        # Step 1: Create VLANs
        st.log("Step: Creating VLANs on SD1")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)

        st.log("Step: Creating VLAN on SD3")
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN on SD4")
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 2: Add physical ports as untagged members to VLANs
        st.log("Step: Adding physical ports as untagged members to VLANs")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, data.d1d3_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, data.d1d4_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, data.d3d1_port1, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, data.d4d1_port1, tagging_mode=False)

        # Step 3: Configure IPv4 address on VLAN interfaces (SVIs)
        st.log("Step: Configuring IPv4 addresses on VLAN interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 4: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 5: Verify configurations
        st.log("Step: Verifying VLAN configuration")
        vlan_obj.show_vlan_brief(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_10)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_20)

        # Step 6: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit VLAN SVI on physical port (untagged) ping between SD3 and SD4 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 10: Transit VLAN SVI on PortChannel (Tagged)
###############################################################################

def test_l3_transit_vlan_portchannel_tagged_ping():
    """
    Test Case 10: Validate Transit VLAN SVI on PortChannel (Tagged) Ping

    Topology:
        SD3 (PC10/Vlan10: 10.1.1.1/24) ---- SD1 (PC10/Vlan10: 10.1.1.2/24, PC20/Vlan20: 20.1.1.2/24) ---- SD4 (PC20/Vlan20: 20.1.1.1/24)

    Steps:
        1. Create PortChannels on all devices
        2. Add members to PortChannels
        3. Create VLANs on all devices
        4. Add PortChannels as tagged members to VLANs
        5. Configure IP on VLAN interfaces (SVIs)
        6. Configure static routes on SD3 and SD4 for transit
        7. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    portchannel_10 = data.portchannel_name
    portchannel_20 = data.portchannel_name_2
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 10: Validate Transit VLAN SVI on PortChannel (Tagged) Ping")

    try:
        # Step 1: Create PortChannels
        st.log("Step: Creating PortChannels on SD1")
        portchannel_obj.create_portchannel(data.dut1, portchannel_10)
        portchannel_obj.create_portchannel(data.dut1, portchannel_20)

        st.log("Step: Creating PortChannel on SD3")
        portchannel_obj.create_portchannel(data.dut3, portchannel_10)

        st.log("Step: Creating PortChannel on SD4")
        portchannel_obj.create_portchannel(data.dut4, portchannel_20)

        # Step 2: Add members to PortChannels
        st.log("Step: Adding members to PortChannels")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_10, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_20, data.d1d4_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel_10, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut4, portchannel_20, data.d4d1_port1)

        # Step 3: Create VLANs
        st.log("Step: Creating VLANs on SD1")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)

        st.log("Step: Creating VLAN on SD3")
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN on SD4")
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 4: Add PortChannels as tagged members to VLANs
        st.log("Step: Adding PortChannels as tagged members to VLANs")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, portchannel_10, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, portchannel_20, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, portchannel_10, tagging_mode=True)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, portchannel_20, tagging_mode=True)

        # Step 5: Configure IPv4 address on VLAN interfaces (SVIs)
        st.log("Step: Configuring IPv4 addresses on VLAN interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 6: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 7: Verify configurations
        st.log("Step: Verifying configurations")
        portchannel_obj.get_portchannel_list(data.dut1)
        vlan_obj.show_vlan_brief(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_10)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_20)

        # Step 8: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit VLAN SVI on PortChannel (tagged) ping between SD3 and SD4 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Test Case 11: Transit VLAN SVI on PortChannel (Untagged)
###############################################################################

def test_l3_transit_vlan_portchannel_untagged_ping():
    """
    Test Case 11: Validate Transit VLAN SVI on PortChannel (Untagged) Ping

    Topology:
        SD3 (PC10/Vlan10: 10.1.1.1/24) ---- SD1 (PC10/Vlan10: 10.1.1.2/24, PC20/Vlan20: 20.1.1.2/24) ---- SD4 (PC20/Vlan20: 20.1.1.1/24)

    Steps:
        1. Create PortChannels on all devices
        2. Add members to PortChannels
        3. Create VLANs on all devices
        4. Add PortChannels as untagged members to VLANs
        5. Configure IP on VLAN interfaces (SVIs)
        6. Configure static routes on SD3 and SD4 for transit
        7. Verify ping from both sides (SD3->SD4 and SD4->SD3, transit through SD1)
    """
    result = True
    portchannel_10 = data.portchannel_name
    portchannel_20 = data.portchannel_name_2
    vlan_id_10 = data.vlan_id
    vlan_id_20 = data.vlan_id_2
    vlan_int_10 = data.vlan_int
    vlan_int_20 = data.vlan_int_2

    st.banner("Test Case 11: Validate Transit VLAN SVI on PortChannel (Untagged) Ping")

    try:
        # Step 1: Create PortChannels
        st.log("Step: Creating PortChannels on SD1")
        portchannel_obj.create_portchannel(data.dut1, portchannel_10)
        portchannel_obj.create_portchannel(data.dut1, portchannel_20)

        st.log("Step: Creating PortChannel on SD3")
        portchannel_obj.create_portchannel(data.dut3, portchannel_10)

        st.log("Step: Creating PortChannel on SD4")
        portchannel_obj.create_portchannel(data.dut4, portchannel_20)

        # Step 2: Add members to PortChannels
        st.log("Step: Adding members to PortChannels")
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_10, data.d1d3_port1)
        portchannel_obj.add_portchannel_member(data.dut1, portchannel_20, data.d1d4_port1)
        portchannel_obj.add_portchannel_member(data.dut3, portchannel_10, data.d3d1_port1)
        portchannel_obj.add_portchannel_member(data.dut4, portchannel_20, data.d4d1_port1)

        # Step 3: Create VLANs
        st.log("Step: Creating VLANs on SD1")
        vlan_obj.create_vlan(data.dut1, vlan_id_10)
        vlan_obj.create_vlan(data.dut1, vlan_id_20)

        st.log("Step: Creating VLAN on SD3")
        vlan_obj.create_vlan(data.dut3, vlan_id_10)

        st.log("Step: Creating VLAN on SD4")
        vlan_obj.create_vlan(data.dut4, vlan_id_20)

        # Step 4: Add PortChannels as untagged members to VLANs
        st.log("Step: Adding PortChannels as untagged members to VLANs")
        vlan_obj.add_vlan_member(data.dut1, vlan_id_10, portchannel_10, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut1, vlan_id_20, portchannel_20, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut3, vlan_id_10, portchannel_10, tagging_mode=False)
        vlan_obj.add_vlan_member(data.dut4, vlan_id_20, portchannel_20, tagging_mode=False)

        # Step 5: Configure IPv4 address on VLAN interfaces (SVIs)
        st.log("Step: Configuring IPv4 addresses on VLAN interfaces")
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_10, data.d1_ip_left, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut1, vlan_int_20, data.d1_ip_right, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut3, vlan_int_10, data.d3_ip_transit, data.mask, family='ipv4')
        ip_obj.config_ip_addr_interface(data.dut4, vlan_int_20, data.d4_ip_transit, data.mask, family='ipv4')

        # Step 6: Configure static routes for transit
        st.log("Step: Configuring static routes on SD3 and SD4")
        ip_obj.create_static_route(data.dut3, data.d1_ip_left, data.subnet_20, family='ipv4')
        ip_obj.create_static_route(data.dut4, data.d1_ip_right, data.subnet_10, family='ipv4')

        # Step 7: Verify configurations
        st.log("Step: Verifying configurations")
        portchannel_obj.get_portchannel_list(data.dut1)
        vlan_obj.show_vlan_brief(data.dut1)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_10)
        ip_obj.get_interface_ip_address(data.dut1, interface_name=vlan_int_20)

        # Step 8: Verify transit ping from both sides
        if not verify_ping_both_sides(data.dut3, data.d4_ip_transit, data.dut4, data.d3_ip_transit,
                                      count=data.ping_count):
            st.error("Transit VLAN SVI on PortChannel (untagged) ping between SD3 and SD4 failed")
            result = False

    finally:
        l3_ping_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")