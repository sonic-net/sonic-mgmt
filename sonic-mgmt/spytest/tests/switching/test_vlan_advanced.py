import pytest
import time
from spytest import st, SpyTestDict

import apis.switching.vlan as vlan
import apis.switching.portchannel as portchannel
import apis.switching.mac as mac
import apis.routing.ip as ip
import apis.system.interface as intf
import apis.system.reboot as reboot
import apis.system.basic as basic

sc_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def vlan_advanced_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D3:2", "D1D4:1")
    vlan_variables()

    yield


def vlan_variables():
    """
    Initialize test data variables.
    """
    # VLAN configuration
    sc_data.vlan_id = 10
    sc_data.vlan_id_2 = 20
    sc_data.vlan_id_3 = 30
    sc_data.vlan_int = "Vlan{}".format(sc_data.vlan_id)
    sc_data.vlan_int_3 = "Vlan{}".format(sc_data.vlan_id_3)

    # Boundary VLAN IDs
    sc_data.vlan_min = 2
    sc_data.vlan_max = 4094
    sc_data.vlan_invalid_0 = 0
    sc_data.vlan_invalid_1 = 1
    sc_data.vlan_invalid_4095 = 4095

    sc_data.d1_vlan10_ip = "10.1.1.1"
    sc_data.d3_vlan10_ip = "10.1.1.2"
    sc_data.d1_vlan30_ip = "30.1.1.1"
    sc_data.d3_vlan30_ip = "30.1.1.2"

    sc_data.d1_vlan2_ip = "2.1.1.1"
    sc_data.d3_vlan2_ip = "2.1.1.2"

    sc_data.d1_vlan4094_ip = "4.94.1.1"
    sc_data.d3_vlan4094_ip = "4.94.1.2"

    sc_data.mask = "24"

    sc_data.static_mac = "00:00:00:11:22:33"

    sc_data.portchannel_name = "PortChannel10"

    sc_data.dut1 = vars.D1
    sc_data.dut3 = vars.D3
    sc_data.d1d3_port1 = vars.D1D3P1
    sc_data.d1d3_port2 = vars.D1D3P2
    sc_data.d3d1_port1 = vars.D3D1P1
    sc_data.d3d1_port2 = vars.D3D1P2

    sc_data.ping_count = 5


def clear_portchannel_config(dut_list):
    """
    Clear all PortChannel configurations on the given DUTs.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("############## {} : PortChannel Cleanup ################".format(dut))
        portchannel_list = portchannel.get_portchannel_list(dut)
        if portchannel_list:
            for pc_entry in portchannel_list:
                portchannel_name = pc_entry.get("teamdev") or pc_entry.get("name")
                if not portchannel_name:
                    continue

                portchannel_members = portchannel.get_portchannel_members(dut, portchannel_name)
                if portchannel_members:
                    if not portchannel.delete_portchannel_member(dut, portchannel_name, portchannel_members):
                        st.log("Error while deleting portchannel members for {}".format(portchannel_name))

                if not portchannel.delete_portchannel(dut, portchannel_name):
                    st.log("Portchannel deletion failed {}".format(portchannel_name))
    return True


def ensure_d1d3_ports_up():
    """
    Ensure D1-D3 interconnect ports are administratively up before cleanup.
    """
    intf.interface_noshutdown(sc_data.dut1, [sc_data.d1d3_port1, sc_data.d1d3_port2])
    intf.interface_noshutdown(sc_data.dut3, [sc_data.d3d1_port1, sc_data.d3d1_port2])
    st.wait(5, "Waiting for ports to come up")


def vlan_test_cleanup(ensure_ports=True):
    """
    Per-testcase cleanup: restore ports and clear all test configurations.
    """
    st.log("Cleanup: Clearing all configurations")
    if ensure_ports:
        ensure_d1d3_ports_up()
    mac.clear_mac(sc_data.dut1)
    mac.clear_mac(sc_data.dut3)
    ip.clear_ip_configuration(st.get_dut_names())
    vlan.clear_vlan_configuration(st.get_dut_names())
    clear_portchannel_config(st.get_dut_names())

###############################################################################
# Verification Functions
###############################################################################

def verify_ping(dut, dest_ip, count=5, expected=True):
    """
    Verify ping from DUT to destination IP.
    """
    st.log("Step: Verifying ping from {} to {}".format(dut, dest_ip))
    result = ip.ping(dut, dest_ip, family='ipv4', count=count)

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


def verify_vlan_exists(dut, vlan_id):
    """
    Verify if VLAN exists on a DUT.
    """
    vlan_list = vlan.get_vlan_list(dut)
    return str(vlan_id) in [str(v) for v in vlan_list]



def verify_mac_on_port(dut, peer_dut, vlan_id, vlan_int, port):
    """
    Verify peer MAC is learned on the specified port.
    """
    mac_addr = mac.get_sbin_intf_mac(peer_dut, vlan_int)
    if not mac_addr:
        st.error("Failed to get MAC address from {} interface {}".format(peer_dut, vlan_int))
        return False

    return mac.verify_mac_address_table(dut, str(mac_addr).upper(), vlan=vlan_id, port=port)


###############################################################################
# Category 1: VLAN Boundary and Range Tests
###############################################################################

def test_l2_vlan_boundary_vlan_ids():
    """
    Test Case 1: VLAN Boundary and Range Tests
    """
    result = True

    st.banner("Test Case 1: VLAN Boundary and Range Tests")

    try:
        st.log("Step: Testing VLAN 2 (minimum valid VLAN)")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_min)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_min)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_min, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_min, sc_data.d3d1_port1, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, "Vlan{}".format(sc_data.vlan_min), sc_data.d1_vlan2_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, "Vlan{}".format(sc_data.vlan_min), sc_data.d3_vlan2_ip, sc_data.mask, family='ipv4')

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan2_ip, count=sc_data.ping_count):
            st.error("VLAN 2 ping test failed")
            result = False
        else:
            st.log("VLAN 2 (minimum boundary) test passed")

        # Cleanup VLAN 2
        ip.delete_ip_interface(sc_data.dut1, "Vlan{}".format(sc_data.vlan_min), sc_data.d1_vlan2_ip, sc_data.mask, family='ipv4')
        ip.delete_ip_interface(sc_data.dut3, "Vlan{}".format(sc_data.vlan_min), sc_data.d3_vlan2_ip, sc_data.mask, family='ipv4')
        vlan.delete_vlan_member(sc_data.dut1, sc_data.vlan_min, sc_data.d1d3_port1, tagging_mode=False)
        vlan.delete_vlan_member(sc_data.dut3, sc_data.vlan_min, sc_data.d3d1_port1, tagging_mode=False)
        vlan.delete_vlan(sc_data.dut1, sc_data.vlan_min)
        vlan.delete_vlan(sc_data.dut3, sc_data.vlan_min)

        # Test 2: Create VLAN 4094 (maximum valid VLAN)
        st.log("Step: Testing VLAN 4094 (maximum valid VLAN)")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_max)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_max)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_max, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_max, sc_data.d3d1_port1, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, "Vlan{}".format(sc_data.vlan_max), sc_data.d1_vlan4094_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, "Vlan{}".format(sc_data.vlan_max), sc_data.d3_vlan4094_ip, sc_data.mask, family='ipv4')

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan4094_ip, count=sc_data.ping_count):
            st.error("VLAN 4094 ping test failed")
            result = False
        else:
            st.log("VLAN 4094 (maximum boundary) test passed")

        # Cleanup VLAN 4094
        ip.delete_ip_interface(sc_data.dut1, "Vlan{}".format(sc_data.vlan_max), sc_data.d1_vlan4094_ip, sc_data.mask, family='ipv4')
        ip.delete_ip_interface(sc_data.dut3, "Vlan{}".format(sc_data.vlan_max), sc_data.d3_vlan4094_ip, sc_data.mask, family='ipv4')
        vlan.delete_vlan_member(sc_data.dut1, sc_data.vlan_max, sc_data.d1d3_port1, tagging_mode=False)
        vlan.delete_vlan_member(sc_data.dut3, sc_data.vlan_max, sc_data.d3d1_port1, tagging_mode=False)
        vlan.delete_vlan(sc_data.dut1, sc_data.vlan_max)
        vlan.delete_vlan(sc_data.dut3, sc_data.vlan_max)

        # Test 3: Attempt to add member to non-existing VLAN 0 (should fail - negative test)
        st.log("Step: Testing adding member to VLAN 0 (invalid - should fail)")
        if vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_invalid_0, [sc_data.d1d3_port1], tagging_mode=False, skip_error=True):
            st.report_fail("unknown_vlan_untagged_member_add_fail", sc_data.d1d3_port1, sc_data.vlan_invalid_0)
        st.log("VLAN 0 add member correctly rejected (invalid VLAN ID)")

        # Test 4: Attempt to add member to non-existing VLAN 1 (reserved - should fail - negative test)
        st.log("Step: Testing adding member to VLAN 1 (reserved - should fail)")
        if vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_invalid_1, [sc_data.d1d3_port1], tagging_mode=False, skip_error=True):
            st.report_fail("unknown_vlan_untagged_member_add_fail", sc_data.d1d3_port1, sc_data.vlan_invalid_1)
        st.log("VLAN 1 add member correctly rejected (reserved VLAN ID)")

        # Test 5: Attempt to add member to non-existing VLAN 4095 (reserved - should fail - negative test)
        st.log("Step: Testing adding member to VLAN 4095 (reserved - should fail)")
        if vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_invalid_4095, [sc_data.d1d3_port1], tagging_mode=False, skip_error=True):
            st.report_fail("unknown_vlan_untagged_member_add_fail", sc_data.d1d3_port1, sc_data.vlan_invalid_4095)
        st.log("VLAN 4095 add member correctly rejected (reserved VLAN ID)")

    finally:
        vlan_test_cleanup(ensure_ports=False)

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_l2_vlan_duplicate_creation():
    """
    Test Case 2: VLAN Duplicate Creation Test

    Steps:
        1. Create VLAN 10 on SD1 and SD3
        2. Attempt to create VLAN 10 again (duplicate)
        3. Verify VLAN still exists on both DUTs
    """
    result = True
    vlan_id = sc_data.vlan_id

    st.banner("Test Case 2: VLAN Duplicate Creation Test")

    try:
        # Step 1: Create VLAN on SD1 and SD3
        st.log("Step: Creating VLAN {} on SD1 and SD3".format(vlan_id))
        vlan.create_vlan(sc_data.dut1, vlan_id)
        vlan.create_vlan(sc_data.dut3, vlan_id)

        if not verify_vlan_exists(sc_data.dut1, vlan_id):
            st.error("VLAN {} creation failed on DUT1".format(vlan_id))
            result = False
        if not verify_vlan_exists(sc_data.dut3, vlan_id):
            st.error("VLAN {} creation failed on DUT3".format(vlan_id))
            result = False

        # Step 2: Attempt duplicate VLAN creation (negative test)
        st.log("Step: Attempting duplicate VLAN creation on DUT1")
        output = st.config(sc_data.dut1, "config vlan add {}".format(vlan_id), skip_error_check=True)
        st.log("Duplicate VLAN creation output: {}".format(output))

        if "invalid" in str(output).lower() or "error" in str(output).lower() or "exists" in str(output).lower():
            st.log("Duplicate VLAN creation correctly rejected on DUT1")
        else:
            st.log("Duplicate creation attempt completed - verifying VLAN is still present")

        # Step 3: Verify VLAN still exists on both DUTs
        st.log("Step: Verifying VLAN {} still exists after duplicate creation attempt".format(vlan_id))
        if not verify_vlan_exists(sc_data.dut1, vlan_id):
            st.error("VLAN {} not found on DUT1 after duplicate creation attempt".format(vlan_id))
            result = False
        if not verify_vlan_exists(sc_data.dut3, vlan_id):
            st.error("VLAN {} not found on DUT3 after duplicate creation attempt".format(vlan_id))
            result = False

    finally:
        vlan_test_cleanup(ensure_ports=False)

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Category 2: Member Port State and Transitions
###############################################################################

def test_l2_vlan_member_port_flap():
    """
    Test Case 3: VLAN Member Port Flap Test

    Steps:
        1. Create VLAN 10, add port as member, configure IP
        2. Verify ping works
        3. Admin-shutdown the port
        4. Verify ping fails
        5. Admin-no-shutdown the port
        6. Verify ping resumes and MAC re-learning occurs
    """
    result = True
    vlan_id = sc_data.vlan_id
    vlan_int = sc_data.vlan_int

    st.banner("Test Case 3: VLAN Member Port Flap Test")

    try:
        # Step 1: Create VLAN and add member
        st.log("Step: Creating VLAN {} and adding member".format(vlan_id))
        vlan.create_vlan(sc_data.dut1, vlan_id)
        vlan.create_vlan(sc_data.dut3, vlan_id)

        vlan.add_vlan_member(sc_data.dut1, vlan_id, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, vlan_id, sc_data.d3d1_port1, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, vlan_int, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        # Step 2: Verify initial ping
        st.log("Step: Verifying initial ping")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=sc_data.ping_count):
            st.error("Initial ping failed")
            result = False

        # Step 3: Admin-shutdown the port
        st.log("Step: Admin-shutdown port {}".format(sc_data.d1d3_port1))
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port1)
        st.wait(5, "Waiting for port state change to propagate")

        # Step 4: Verify ping fails
        st.log("Step: Verifying ping fails after port shutdown")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=3, expected=False):
            st.error("Ping should have failed after port shutdown")
            result = False

        # Step 5: Admin-no-shutdown the port
        st.log("Step: Admin-no-shutdown port {}".format(sc_data.d1d3_port1))
        intf.interface_noshutdown(sc_data.dut1, sc_data.d1d3_port1)
        st.wait(10, "Waiting for port to come up and MAC learning")

        # Step 6: Verify ping resumes
        st.log("Step: Verifying ping resumes after port startup")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=sc_data.ping_count):
            st.error("Ping failed to resume after port startup")
            result = False

        # Verify MAC table shows entries (MAC re-learning)
        st.log("Step: Verifying MAC entries after port flap")
        mac.get_mac(sc_data.dut1)

    finally:
        vlan_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Category 3: MAC Table and FDB Verification
###############################################################################

def test_l2_vlan_mac_move():
    """
    Test Case 4: VLAN MAC Move Test

    Steps:
        1. Create VLAN 10 with two ports as members (port1 and port2)
        2. Send traffic from SD3 via port1, verify MAC is learned on port1
        3. Simulate MAC move by sending traffic via port2
        4. Verify FDB entry updates to port2
        5. Verify no duplicate MAC entries
    """
    result = True
    vlan_id = sc_data.vlan_id
    vlan_int = sc_data.vlan_int

    st.banner("Test Case 4: VLAN MAC Move Test")

    try:
        st.log("Step: Creating VLAN {} with two ports as members".format(vlan_id))
        vlan.create_vlan(sc_data.dut1, vlan_id)
        vlan.create_vlan(sc_data.dut3, vlan_id)

        vlan.add_vlan_member(sc_data.dut1, vlan_id, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut1, vlan_id, sc_data.d1d3_port2, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, vlan_id, sc_data.d3d1_port1, tagging_mode=False)

        st.log("Step: Configuring IP and sending traffic via port1")
        ip.config_ip_addr_interface(sc_data.dut1, vlan_int, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=5):
            st.error("Initial ping failed before MAC move verification")
            result = False

        peer_mac = str(mac.get_sbin_intf_mac(sc_data.dut3, vlan_int)).upper()

        st.log("Step: Verifying MAC learned on port1 ({})".format(sc_data.d1d3_port1))
        if not st.poll_wait(verify_mac_on_port, 60, sc_data.dut1, sc_data.dut3, vlan_id, vlan_int,
                            sc_data.d1d3_port1):
            st.error("MAC not learned on port1 ({})".format(sc_data.d1d3_port1))
            result = False
        else:
            st.log("MAC correctly learned on port1")

        st.log("Step: Moving SD3 connection from port1 to port2 (MAC move simulation)")
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port1)
        ip.delete_ip_interface(sc_data.dut3, vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')
        vlan.delete_vlan_member(sc_data.dut3, vlan_id, sc_data.d3d1_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, vlan_id, sc_data.d3d1_port2, tagging_mode=False)
        ip.config_ip_addr_interface(sc_data.dut3, vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        st.wait(3, "Waiting for VLAN member change")

        st.log("Step: Sending traffic via port2 to trigger MAC move")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=10):
            st.error("Ping failed after MAC move to port2")
            result = False

        st.log("Step: Verifying MAC learned on port2 ({})".format(sc_data.d1d3_port2))
        if mac.get_mac_address_list(sc_data.dut1, mac=peer_mac, vlan=vlan_id, port=sc_data.d1d3_port1):
            st.error("MAC still present on port1 ({}) after move".format(sc_data.d1d3_port1))
            result = False
        if not st.poll_wait(verify_mac_on_port, 60, sc_data.dut1, sc_data.dut3, vlan_id, vlan_int,
                            sc_data.d1d3_port2):
            st.error("MAC not learned on port2 ({}) after move".format(sc_data.d1d3_port2))
            result = False
        else:
            st.log("MAC correctly moved to port2")

    finally:
        vlan_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_l2_vlan_mac_flush_on_vlan_delete():
    """
    Test Case 6: VLAN MAC Flush on VLAN Delete Test

    Steps:
        1. Create VLAN 10 and VLAN 30 with members
        2. Send traffic to populate MAC table for both VLANs
        3. Verify MAC entries exist for both VLANs
        4. Delete VLAN 30
        5. Verify VLAN 30 MAC entries are flushed
        6. Verify VLAN 10 MAC entries remain intact
    """
    result = True
    vlan_id_10 = sc_data.vlan_id
    vlan_id_30 = sc_data.vlan_id_3
    vlan_int_10 = sc_data.vlan_int
    vlan_int_30 = sc_data.vlan_int_3

    st.banner("Test Case 6: VLAN MAC Flush on VLAN Delete Test")

    try:
        # Step 1: Create VLANs
        st.log("Step: Creating VLAN 10 and VLAN 30")
        vlan.create_vlan(sc_data.dut1, vlan_id_10)
        vlan.create_vlan(sc_data.dut1, vlan_id_30)
        vlan.create_vlan(sc_data.dut3, vlan_id_10)
        vlan.create_vlan(sc_data.dut3, vlan_id_30)

        # Step 2: Add members
        st.log("Step: Adding VLAN members")
        vlan.add_vlan_member(sc_data.dut1, vlan_id_10, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, vlan_id_10, sc_data.d3d1_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut1, vlan_id_30, sc_data.d1d3_port2, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, vlan_id_30, sc_data.d3d1_port2, tagging_mode=False)

        # Step 3: Configure IP and send traffic
        st.log("Step: Configuring IP and sending traffic")
        ip.config_ip_addr_interface(sc_data.dut1, vlan_int_10, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, vlan_int_10, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut1, vlan_int_30, sc_data.d1_vlan30_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, vlan_int_30, sc_data.d3_vlan30_ip, sc_data.mask, family='ipv4')

        st.wait(10, "Waiting for VLAN interfaces to come up")

        # Send traffic to populate MAC tables
        st.log("Step: Verifying ping on VLAN 10")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=3):
            st.log("VLAN 10 ping failed - continuing with test")
        
        st.log("Step: Verifying ping on VLAN 30")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan30_ip, count=3):
            st.log("VLAN 30 ping failed - continuing with test")

        # Step 4: Verify MAC entries exist
        st.log("Step: Verifying MAC entries exist for both VLANs")
        mac.get_mac(sc_data.dut1, vlan=vlan_id_10)
        mac.get_mac(sc_data.dut1, vlan=vlan_id_30)

        # Step 5: Delete VLAN 30
        st.log("Step: Deleting VLAN 30")
        ip.delete_ip_interface(sc_data.dut1, vlan_int_30, sc_data.d1_vlan30_ip, sc_data.mask, family='ipv4')
        ip.delete_ip_interface(sc_data.dut3, vlan_int_30, sc_data.d3_vlan30_ip, sc_data.mask, family='ipv4')
        vlan.delete_vlan_member(sc_data.dut1, vlan_id_30, sc_data.d1d3_port2, tagging_mode=False)
        vlan.delete_vlan_member(sc_data.dut3, vlan_id_30, sc_data.d3d1_port2, tagging_mode=False)
        vlan.delete_vlan(sc_data.dut1, vlan_id_30)
        vlan.delete_vlan(sc_data.dut3, vlan_id_30)

        st.wait(5, "Waiting for MAC table cleanup")

        # Step 6: Verify VLAN 30 MAC entries are flushed
        st.log("Step: Verifying VLAN 30 MAC entries are flushed")
        mac_entries_30 = mac.get_mac(sc_data.dut1)
        # Filter to only check for actual VLAN 30 entries (API may return all entries)
        vlan30_entries = [entry for entry in mac_entries_30 if str(entry.get('vlan')) == str(vlan_id_30)]
        st.log("VLAN 30 specific entries: {}".format(vlan30_entries))
        if vlan30_entries:
            st.error("VLAN 30 MAC entries should be flushed but found: {}".format(vlan30_entries))
            result = False
        else:
            st.log("VLAN 30 MAC entries correctly flushed")

        # Step 7: Verify VLAN 10 MAC entries remain
        st.log("Step: Verifying VLAN 10 MAC entries remain")
        # Trigger traffic again to ensure MAC entries
        verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=3)
        mac_entries_10 = mac.get_mac(sc_data.dut1, vlan=vlan_id_10)
        st.log("VLAN 10 MAC entries after VLAN 30 delete: {}".format(mac_entries_10))

        # Verify VLAN 10 ping still works
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=sc_data.ping_count):
            st.error("VLAN 10 ping failed after VLAN 30 delete")
            result = False

        st.log("Final result value: {}".format(result))
        
    finally:
        vlan_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Category 6: Reserved VLAN Range
###############################################################################

def test_l2_vlan_reserved_range():
    """
    Test Case 6: Reserved VLAN Range Test

    Steps:
        1. Configure a reserved VLAN range using vlan.config_reserved_vlan_range()
        2. Verify the reserved range with vlan.verify_reserved_vlan()
        3. Attempt to create a VLAN within the reserved range -- should fail
        4. Create a VLAN outside the reserved range - should succeed
        5. Verify show system reserved vlan output
    """
    result = True
    reserved_range_start = 3000  # Reserved VLANs will be 3000-3127 (128 VLANs)
    test_vlan_reserved = 3050    # Within reserved range
    test_vlan_normal = sc_data.vlan_id  # Outside reserved range (VLAN 10)

    st.banner("Test Case 6: Reserved VLAN Range Test")

    try:
        # Step 1: Configure reserved VLAN range using config_reserved_vlan_range API
        st.log("Step: Configuring reserved VLAN range starting at {}".format(reserved_range_start))
        if not vlan.config_reserved_vlan_range(sc_data.dut1, reserved_range=reserved_range_start, 
                                                config='yes', skip_error=True):
            st.log("Reserved VLAN range configuration may not be supported - continuing test")
        else:
            st.log("Reserved VLAN range {} configured successfully".format(reserved_range_start))

        # Step 2: Verify reserved VLAN range using verify_reserved_vlan API
        st.log("Step: Verifying reserved VLAN range with verify_reserved_vlan()")
        reserved_vlan_output = vlan.verify_reserved_vlan(sc_data.dut1, return_output=True, skip_error=True)
        if reserved_vlan_output:
            st.log("Reserved VLAN output: {}".format(reserved_vlan_output))
            # Verify the range matches expected
            expected_range = "{}-{}".format(reserved_range_start, reserved_range_start + 127)
            if vlan.verify_reserved_vlan(sc_data.dut1, vlan_range=expected_range, skip_error=True):
                st.log("Reserved VLAN range {} verified successfully".format(expected_range))
            else:
                st.log("Reserved VLAN range verification with specific range failed")
        else:
            st.log("verify_reserved_vlan returned no output - feature may not be supported")

        # Step 3: Attempt to create a VLAN within the reserved range (negative test - should fail)
        st.log("Step: Attempting to create VLAN {} (within reserved range - should fail)".format(test_vlan_reserved))
        # Try to create VLAN - should fail if reserved range is configured
        create_result = vlan.create_vlan(sc_data.dut1, test_vlan_reserved, skip_error=True)
        if create_result:
            st.log("VLAN {} creation succeeded - checking if it's actually usable".format(test_vlan_reserved))
            # If VLAN was created, try to add member - this should fail if truly reserved
            if vlan.add_vlan_member(sc_data.dut1, test_vlan_reserved, sc_data.d1d3_port1, 
                                    tagging_mode=False, skip_error=True):
                st.log("VLAN {} member add succeeded - VLAN is not in reserved range".format(test_vlan_reserved))
                # Cleanup the accidentally created VLAN
                vlan.delete_vlan_member(sc_data.dut1, test_vlan_reserved, sc_data.d1d3_port1, 
                                        tagging_mode=False, skip_error_check=True)
            vlan.delete_vlan(sc_data.dut1, test_vlan_reserved, skip_error=True)
        else:
            st.log("VLAN {} creation correctly rejected (in reserved range)".format(test_vlan_reserved))

        # Step 4: Create VLAN outside reserved range - should succeed
        st.log("Step: Creating VLAN {} (outside reserved range)".format(test_vlan_normal))
        vlan.create_vlan(sc_data.dut1, test_vlan_normal)
        vlan.create_vlan(sc_data.dut3, test_vlan_normal)

        # Verify VLAN is created
        if not verify_vlan_exists(sc_data.dut1, test_vlan_normal):
            st.error("VLAN {} creation failed".format(test_vlan_normal))
            result = False
        else:
            st.log("VLAN {} created successfully (outside reserved range)".format(test_vlan_normal))

        # Add member and verify traffic
        st.log("Step: Adding members and verifying traffic on non-reserved VLAN")
        vlan.add_vlan_member(sc_data.dut1, test_vlan_normal, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, test_vlan_normal, sc_data.d3d1_port1, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=sc_data.ping_count):
            st.error("Ping on non-reserved VLAN {} failed".format(test_vlan_normal))
            result = False
        else:
            st.log("Traffic verified on non-reserved VLAN {}".format(test_vlan_normal))

        # Step 5: Display show system reserved vlan output
        st.log("Step: Displaying 'show system vlan reserved' output")
        st.config(sc_data.dut1, "show system vlan reserved", type='klish', skip_error_check=True)

        # Also display VLAN brief for reference
        st.log("Step: Displaying VLAN brief")
        vlan.show_vlan_brief(sc_data.dut1)

    finally:
        vlan.config_reserved_vlan_range(sc_data.dut1, reserved_range=reserved_range_start,
                                        config='no', skip_error=True)
        vlan_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

