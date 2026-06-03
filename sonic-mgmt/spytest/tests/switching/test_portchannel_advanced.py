import time
import re

import pytest
from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan
import apis.switching.portchannel as portchannel
import apis.switching.mac as mac
import apis.routing.ip as ip
import apis.system.interface as intf
import apis.system.reboot as reboot

sc_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def portchannel_advanced_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D3:4", "D1D4:1", "D3T1:1")
    portchannel_variables()

    yield

def portchannel_variables():
    """Initialize test data variables."""
    # PortChannel configuration
    sc_data.portchannel_name = "PortChannel10"
    sc_data.portchannel_name_2 = "PortChannel20"

    # Boundary PortChannel IDs
    sc_data.portchannel_min = "PortChannel1"
    sc_data.portchannel_max = "PortChannel9999"

    # VLAN configuration
    sc_data.vlan_id = 100
    sc_data.vlan_id_2 = 200
    sc_data.vlan_10 = 10
    sc_data.vlan_20 = 20
    sc_data.vlan_int_10 = "Vlan{}".format(sc_data.vlan_10)
    sc_data.vlan_int_20 = "Vlan{}".format(sc_data.vlan_20)
    sc_data.vlan_int = "Vlan{}".format(sc_data.vlan_id)
    sc_data.vlan_int_2 = "Vlan{}".format(sc_data.vlan_id_2)

    # IP addresses for VLAN 10 (10.10.10.x/24)
    sc_data.d1_vlan10_ip = "10.10.10.1"
    sc_data.d3_vlan10_ip = "10.10.10.2"

    # IP addresses for VLAN 20 (20.20.20.x/24) - different subnet
    sc_data.d1_vlan20_ip = "20.20.20.1"
    sc_data.d3_vlan20_ip = "20.20.20.2"

    # IP addresses
    sc_data.d1_vlan100_ip = "100.1.1.1"
    sc_data.d3_vlan100_ip = "100.1.1.2"
    sc_data.d1_vlan200_ip = "200.1.1.1"
    sc_data.d3_vlan200_ip = "200.1.1.2"
    sc_data.mask = "24"

    # DUT references
    sc_data.dut1 = vars.D1
    sc_data.dut3 = vars.D3

    # Port references (4 ports between D1 and D3)
    sc_data.d1d3_port1 = vars.D1D3P1
    sc_data.d1d3_port2 = vars.D1D3P2
    sc_data.d1d3_port3 = vars.D1D3P3
    sc_data.d1d3_port4 = vars.D1D3P4
    sc_data.d3d1_port1 = vars.D3D1P1
    sc_data.d3d1_port2 = vars.D3D1P2
    sc_data.d3d1_port3 = vars.D3D1P3
    sc_data.d3d1_port4 = vars.D3D1P4

    # Member lists for PortChannel
    sc_data.members_dut1 = [sc_data.d1d3_port1, sc_data.d1d3_port2]
    sc_data.members_dut3 = [sc_data.d3d1_port1, sc_data.d3d1_port2]
    sc_data.members_dut1_all = [sc_data.d1d3_port1, sc_data.d1d3_port2, sc_data.d1d3_port3, sc_data.d1d3_port4]
    sc_data.members_dut3_all = [sc_data.d3d1_port1, sc_data.d3d1_port2, sc_data.d3d1_port3, sc_data.d3d1_port4]

    # Ping settings
    sc_data.ping_count = 5


def clear_portchannel_config(dut_list):
    """Clear all PortChannel configurations on the given DUTs."""
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
    """Ensure all D1-D3 interconnect ports are administratively up."""
    intf.interface_noshutdown(sc_data.dut1, sc_data.members_dut1_all)
    intf.interface_noshutdown(sc_data.dut3, sc_data.members_dut3_all)
    st.wait(5, "Waiting for ports to come up")

def portchannel_test_cleanup(ensure_ports=True):
    """Per-testcase cleanup: restore ports and clear all test configurations."""
    st.log("Cleanup: Clearing all configurations")
    if ensure_ports:
        ensure_d1d3_ports_up()
    mac.clear_mac(sc_data.dut1)
    mac.clear_mac(sc_data.dut3)
    ip.clear_ip_configuration(st.get_dut_names(), thread=True)
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=True)
    clear_portchannel_config(st.get_dut_names())


###############################################################################
# Verification Functions
###############################################################################

def verify_ping(dut, dest_ip, count=5, expected=True, max_attempts=1):
    """Verify ping from DUT to destination IP. Returns True if result matches expected."""
    for attempt in range(1, max_attempts + 1):
        result = ip.ping(dut, dest_ip, family='ipv4', count=count)
        if result == expected:
            return True
        if attempt < max_attempts:
            st.wait(2, "Waiting before ping retry")
    st.error("Ping to {}: got {}, expected {}".format(dest_ip, result, expected))
    return False


def verify_portchannel_exists(dut, portchannel_name):
    """Return True if PortChannel exists on DUT."""
    pc_list = portchannel.get_portchannel_list(dut)
    if pc_list:
        for pc in pc_list:
            if pc.get('name') == portchannel_name or pc.get('teamdev') == portchannel_name:
                return True
    return False


def verify_mac_on_portchannel(dut, peer_dut, vlan_id, vlan_int, pc_name):
    """Verify peer MAC is learned on the PortChannel interface."""
    peer_mac = mac.get_sbin_intf_mac(peer_dut, vlan_int)
    if not peer_mac:
        st.error("Failed to get MAC address from {} interface {}".format(peer_dut, vlan_int))
        return False
    return verify_mac_entry(dut, peer_mac, vlan_id, port=pc_name)


def verify_mac_flushed(dut, peer_dut, vlan_id, vlan_int, port=None):
    """Verify peer MAC is not present in the FDB."""
    peer_mac = mac.get_sbin_intf_mac(peer_dut, vlan_int)
    if not peer_mac:
        st.error("Failed to get MAC address from {} interface {}".format(peer_dut, vlan_int))
        return False

    kwargs = {'mac': str(peer_mac).upper(), 'vlan': str(vlan_id), 'cli_type': 'click'}
    if port:
        kwargs['port'] = port
    if mac.get_mac_address_list(dut, **kwargs):
        st.error("MAC {} still present in FDB on {} VLAN {}{}".format(
            peer_mac, dut, vlan_id, " port {}".format(port) if port else ""))
        return False

    st.log("MAC {} flushed from FDB on {} VLAN {}".format(peer_mac, dut, vlan_id))
    return True


MAC_AGING_TIME_DEFAULT = 600
MAC_AGING_TIME_NEW = 120

# Platform detection - maps platform string to platform key
PLATFORM_DICT = {
    'fx3': ['x86_64-n9k-c93108tc-fx3-r0'],
    'gamut': ['x86_64-n9164e_ns4_o-r0'],
    'siren': ['x86_64-n9k-c93180yc-fx4-r0'],
    'laguna': ['x86_64-n9k-c93240yc-fx2-r0'],
}


def find_platform_str(dut):
    """Get platform key (fx3, gamut, siren, laguna) from platform summary."""
    result = st.show(dut, "show platform summary | grep Platform: | awk '{print $2}'", skip_tmpl=True)
    if not result:
        return None
    platform_str = result.split('\n')[0].strip()
    for key, platforms in PLATFORM_DICT.items():
        if platform_str in platforms:
            return key
    return None


def get_mac_aging_multiplier(platform_str):
    """Return MAC aging time multiplier based on platform (gamut=3x, fx3=2x, default=1x)."""
    platform_lower = str(platform_str).lower()
    if 'gamut' in platform_lower:
        return 3
    if 'fx3' in platform_lower or 'fx-3' in platform_lower:
        return 2
    return 1


def update_mac_aging(dut, mac_aging_time, verify=False):
    """Set fdb_aging_time via swssconfig runtime SET."""
    cmd = '''
          docker exec swss sh -c 'echo "[{{\\"SWITCH_TABLE:switch\\": {{\\"fdb_aging_time\\" : \\"{}\\"}},\\"OP\\": \\"SET\\"}}]" > ./fdb.json'
          docker exec swss swssconfig ./fdb.json
          '''.format(mac_aging_time)
    st.config(dut, cmd)
    st.wait(1, "Waiting for fdb_aging_time to take effect")

    if verify:
        cmd_output = st.show(dut, "show mac aging-time", skip_tmpl=True)
        if not cmd_output:
            st.error("No output from show mac aging-time on {}".format(dut))
            return False
        if str(mac_aging_time) + " " not in str(cmd_output):
            parsed = st.show(dut, "show mac aging-time")
            actual = parsed[0].get("aging_time") if parsed else "unknown"
            st.error("MAC aging verify failed on {}: expected {}, got {}".format(
                dut, mac_aging_time, actual))
            return False
        st.log("MAC aging time update successful: {} seconds on {}".format(mac_aging_time, dut))
    return True


def restore_mac_aging(dut):
    """Restore default fdb_aging_time (600 seconds)."""
    update_mac_aging(dut, MAC_AGING_TIME_DEFAULT, verify=False)

def get_tg_handle_d3():
    """Return (tg, tg_port_handle) for T1D3P1, or (None, None) if unavailable."""
    try:
        tg, tg_ph = tgapi.get_handle_byname("T1D3P1")
        tg.tg_traffic_control(action="reset", port_handle=tg_ph)
        tg.tg_traffic_control(action="clear_stats", port_handle=tg_ph)
        return tg, tg_ph
    except Exception as err:
        st.log("Traffic generator not available: {}".format(err))
        return None, None


def send_tg_l2_burst(tg, tg_ph, mac_src, mac_dst, vlan_id=None, pkts=200):
    """Send a single L2 burst from TGen. Returns stream_id."""
    kwargs = {
        "port_handle": tg_ph,
        "mode": "create",
        "length_mode": "fixed",
        "frame_size": 90,
        "mac_src": mac_src,
        "mac_dst": mac_dst,
        "transmit_mode": "single_burst",
        "pkts_per_burst": pkts,
    }
    if vlan_id is None:
        kwargs["l2_encap"] = "ethernet_ii"
    else:
        kwargs["l2_encap"] = "ethernet_ii_vlan"
        kwargs["vlan_id"] = vlan_id
        kwargs["vlan"] = "enable"

    stream = tg.tg_traffic_config(**kwargs)
    stream_id = stream["stream_id"]
    tg.tg_traffic_control(action="run", stream_handle=stream_id, enable_arp=0)
    st.wait(2, "Waiting for traffic burst to complete")
    tg.tg_traffic_control(action="stop", stream_handle=stream_id)
    return stream_id


def verify_mac_entry(dut, mac_addr, vlan_id, port=None, mac_type=None):
    """
    Verify MAC entry exists in MAC table with optional port and type verification.

    Returns True if MAC found matching criteria.
    """
    mac_upper = str(mac_addr).upper()
    mac_entries = mac.get_mac_address_list(
        dut, mac=str(mac_upper), vlan=str(vlan_id), cli_type='click')
    st.log("MAC table entries for {} in VLAN {}: {}".format(mac_upper, vlan_id, mac_entries))
    if not mac_entries:
        st.log("MAC {} not found in VLAN {}".format(mac_upper, vlan_id))
        return False

    mac_table = mac.get_mac(dut, cli_type='click')
    if not mac_table:
        mac_table = []

    for entry in mac_table:
        entry_mac = str(entry.get('macaddress', entry.get('mac', ''))).upper()
        entry_vlan = str(entry.get('vlan', '')).replace('Vlan', '')
        if entry_mac != mac_upper or entry_vlan != str(vlan_id):
            continue
        entry_port = entry.get('port', '')
        entry_type = str(entry.get('type', '')).lower()
        st.log("Found MAC entry: mac={}, vlan={}, port={}, type={}".format(
            entry_mac, entry_vlan, entry_port, entry_type))
        if port and entry_port != port:
            st.log("Port mismatch: expected {}, got {}".format(port, entry_port))
            return False
        if mac_type and mac_type.lower() not in entry_type:
            st.log("Type mismatch: expected {}, got {}".format(mac_type, entry_type))
            return False
        return True
    return False


def get_dut_interface_mac(dut, interface):
    """Get the MAC address of a DUT interface, or None if not found."""
    output = st.config(dut, "ip link show {}".format(interface), type='click', skip_error_check=True)
    if output:
        match = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', str(output))
        if match:
            return match.group(1).upper()
    output = st.config(dut, "cat /sys/class/net/{}/address".format(interface), type='click', skip_error_check=True)
    if output:
        match = re.search(r'([0-9a-fA-F:]{17})', str(output))
        if match:
            return match.group(1).upper()
    return None


###############################################################################
# Category 1: PortChannel Boundary and Range Tests
###############################################################################

def test_l2_portchannel_boundary_ids():
    """
    Test Case 1: PortChannel Boundary ID Tests

    Steps:
        1. Create PortChannel1 (minimum valid ID)
        2. Verify PortChannel1 is created successfully
        3. Delete PortChannel1
        4. Create PortChannel999 (maximum valid ID)
        5. Verify PortChannel999 is created successfully
        6. Delete PortChannel999
        7. Attempt to create PortChannelABC (invalid - should fail)
        8. Attempt to create PortChannel1000 (invalid - should fail)
    """
    result = True
    pc_min_created = False
    pc_max_created = False

    st.banner("Test Case 1: PortChannel Boundary ID Tests")

    try:
        # Step 1: Test PortChannel1 (minimum valid ID)
        st.log("Step: Creating PortChannel1 (minimum valid ID)")
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[sc_data.portchannel_min])
        
        if not verify_portchannel_exists(sc_data.dut1, sc_data.portchannel_min):
            st.error("PortChannel1 creation failed")
            result = False
        else:
            st.log("PortChannel1 (minimum boundary) created successfully")
            pc_min_created = True
        
        # Step 2: Delete PortChannel1 before creating PortChannel999
        if pc_min_created:
            st.log("Step: Deleting PortChannel1")
            portchannel.delete_portchannel(sc_data.dut1, portchannel_list=[sc_data.portchannel_min])
            pc_min_created = False
            if verify_portchannel_exists(sc_data.dut1, sc_data.portchannel_min):
                st.error("PortChannel1 deletion failed")
                result = False
            else:
                st.log("PortChannel1 deleted successfully")

        # Step 3: Test PortChannel999 (maximum valid ID)
        st.log("Step: Creating PortChannel999 (maximum valid ID)")
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[sc_data.portchannel_max])
        
        if not verify_portchannel_exists(sc_data.dut1, sc_data.portchannel_max):
            st.error("PortChannel999 creation failed")
            result = False
        else:
            st.log("PortChannel999 (maximum boundary) created successfully")
            pc_max_created = True

        # Step 4: Delete PortChannel999
        if pc_max_created:
            st.log("Step: Deleting PortChannel9999")
            portchannel.delete_portchannel(sc_data.dut1, portchannel_list=[sc_data.portchannel_max])
            pc_max_created = False
            if verify_portchannel_exists(sc_data.dut1, sc_data.portchannel_max):
                st.error("PortChannel9999 deletion failed")
                result = False
            else:
                st.log("PortChannel9999 deleted successfully")

        # Step 5: Attempt to create PortChannelABC (invalid - negative test)
        st.log("Step: Attempting to create PortChannelABC (invalid - should fail)")
        output = st.config(sc_data.dut1, "config portchannel add PortChannelABC", skip_error_check=True)
        st.log("PortChannelABC creation output: {}".format(output))
        # Check if it contains error message indicating rejection
        if "invalid" in str(output).lower() or "error" in str(output).lower():
            st.log("PortChannelABC correctly rejected (invalid ID)")
        else:
            result = False
            st.log("PortChannelABC was created but should have been rejected")

    finally:
        portchannel_test_cleanup(ensure_ports=False)

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_l2_portchannel_duplicate_creation():
    """
    Test Case 2: PortChannel Duplicate Creation Test

    Steps:
        1. Create PortChannel on DUT1
        2. Attempt duplicate PortChannel creation (negative test)
        3. Verify original PortChannel still exists
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 2: PortChannel Duplicate Creation Test")

    try:
        # Step 1: Create PortChannel on DUT1 only (no LACP neighbor required)
        st.log("Step: Creating {} on DUT1".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])

        if not verify_portchannel_exists(sc_data.dut1, pc_name):
            st.error("PortChannel {} creation failed".format(pc_name))
            result = False

        # Step 2: Attempt duplicate PortChannel creation (negative test)
        st.log("Step: Attempting duplicate PortChannel creation")
        output = st.config(sc_data.dut1, "config portchannel add {}".format(pc_name), skip_error_check=True)
        st.log("Duplicate PortChannel creation output: {}".format(output))

        if "invalid" in str(output).lower() or "error" in str(output).lower() or "exists" in str(output).lower():
            st.log("Duplicate PortChannel creation correctly rejected")
        else:
            st.log("Duplicate creation attempt completed - verifying original PortChannel is intact")

        # Step 3: Verify original PortChannel still exists
        if not verify_portchannel_exists(sc_data.dut1, pc_name):
            st.error("Original PortChannel {} missing after duplicate creation attempt".format(pc_name))
            result = False

    finally:
        portchannel_test_cleanup(ensure_ports=False)

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
     
###############################################################################
# Category 2: Member Port State and Transitions (Partially Covered Tests)
###############################################################################

def test_l2_portchannel_member_port_flap():
    """
    Test Case 3: PortChannel Member Port Flap Test

    Steps:
        1. Create PortChannel10 with 2 members
        2. Add to VLAN and configure IP
        3. Verify ping works
        4. Shutdown one member port on both DUTs
        5. Verify PortChannel still UP (one member remaining)
        6. Verify ping still works
        7. Shutdown second member port on both DUTs
        8. Verify PortChannel goes DOWN
        9. Verify ping fails
        10. Bring both ports back up on both DUTs
        11. Verify PortChannel recovers and ping works
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 3: PortChannel Member Port Flap Test")

    try:
        # Step 1: Create PortChannel with 2 members
        st.log("Step: Creating {} with 2 members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.wait(15, "Waiting for LACP negotiation")

        # Verify PortChannel is UP before proceeding
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel not UP after member addition - cannot proceed")
            result = False

        # Step 2: Add to VLAN and configure IP
        st.log("Step: Configuring VLAN and IP")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        st.wait(10, "Waiting for VLAN interface to come up")

        # Step 3: Verify initial ping
        st.log("Step: Verifying initial ping with both members UP")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Initial ping failed")
            result = False
        else:
            st.log("Initial ping successful with both members")

        # Step 4: Shutdown first member port on DUT1 only
        st.log("Step: Shutting down first member port {} on DUT1 only".format(sc_data.d1d3_port1))
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port1)
        st.wait(25, "Waiting for LACP to converge after port shutdown")

        # Step 5: Verify PortChannel still UP with remaining member
        st.log("Step: Verifying PortChannel still UP with one member")
        if not portchannel.verify_portchannel_state(sc_data.dut3, pc_name, state="up"):
            st.error("PortChannel went DOWN with one member still active")
            result = False
        else:
            st.log("PortChannel remains UP with one member on each side")

        # Step 6: Verify ping from both DUTs with single member
        st.log("Step: Verifying ping from DUT3 to DUT1 with one member")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count, max_attempts=5):
            st.error("Ping from DUT3 to DUT1 failed with one member active")
            result = False
        else:
            st.log("Ping from DUT3 to DUT1 successful with single member")

        st.log("Step: Verifying ping from DUT1 to DUT3 with one member")
        if not verify_ping(sc_data.dut1, sc_data.d3_vlan100_ip, count=sc_data.ping_count, max_attempts=5):
            st.error("Ping from DUT1 to DUT3 failed with one member active")
            result = False
        else:
            st.log("Ping from DUT1 to DUT3 successful with single member")

        # Step 7: Shutdown second member port on DUT1 only
        st.log("Step: Shutting down second member port {} on DUT1 only".format(sc_data.d1d3_port2))
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port2)
        st.wait(10, "Waiting for port state change")

        # Step 8: Verify PortChannel goes DOWN
        st.log("Step: Verifying PortChannel goes DOWN with no members")
        if portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up", error_msg=False):
            st.error("PortChannel should be DOWN with no active members")
            result = False
        else:
            st.log("PortChannel correctly DOWN with no active members")

        # Step 9: Verify ping fails from both DUTs
        st.log("Step: Verifying ping from DUT3 to DUT1 fails with no active members")
        if verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=3, expected=False):
            st.log("Ping from DUT3 to DUT1 correctly fails with no active members")
        else:
            st.error("Ping from DUT3 to DUT1 should fail with no active members")
            result = False

        st.log("Step: Verifying ping from DUT1 to DUT3 fails with no active members")
        if verify_ping(sc_data.dut1, sc_data.d3_vlan100_ip, count=3, expected=False):
            st.log("Ping from DUT1 to DUT3 correctly fails with no active members")
        else:
            st.error("Ping from DUT1 to DUT3 should fail with no active members")
            result = False

        # Step 10: Bring both ports back up on DUT1
        st.log("Step: Bringing both member ports back up on DUT1")
        intf.interface_noshutdown(sc_data.dut1, sc_data.d1d3_port1)
        intf.interface_noshutdown(sc_data.dut1, sc_data.d1d3_port2)
        st.wait(20, "Waiting for LACP negotiation after port recovery")

        # Step 11: Verify PortChannel recovers
        st.log("Step: Verifying PortChannel recovers after port flap")
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel failed to recover after member ports came up")
            result = False
        else:
            st.log("PortChannel recovered successfully")

        # Verify ping works again from both DUTs
        st.log("Step: Verifying ping from both DUTs after recovery")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping from DUT3 to DUT1 failed after PortChannel recovery")
            result = False
        elif not verify_ping(sc_data.dut1, sc_data.d3_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping from DUT1 to DUT3 failed after PortChannel recovery")
            result = False
        else:
            st.log("Ping restored after member port flap recovery")

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def test_l2_portchannel_member_move():
    """
    Test Case 4: PortChannel Member Move Test

    Steps:
        1. Create PortChannel10 with port1 and port2 as members on both DUTs
        2. Configure VLAN and IP, verify ping works with 2 members
        3. Remove port2 from PortChannel10 on both DUTs
        4. Create PortChannel20 on both DUTs and add port2 to it
        5. Verify port2 is now member of PortChannel20
        6. Verify PortChannel10 still functional with port1 only
    
    Note: PortChannel requires matching members on both ends for LACP.
          If DUT1 has 3 members but DUT3 has only 1, only 1 link will be active.
    """
    result = True
    pc_name_1 = sc_data.portchannel_name
    pc_name_2 = sc_data.portchannel_name_2

    st.banner("Test Case 4: PortChannel Member Move Test")

    try:
        # Step 1: Create PortChannel10 with 2 members on both DUTs
        st.log("Step 1: Creating {} with 2 members on both DUTs".format(pc_name_1))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name_1])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name_1])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name_1, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name_1, members=sc_data.members_dut3)

        st.wait(10, "Waiting for LACP negotiation")

        # Verify PortChannel is UP with both members
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name_1, state="up"):
            st.error("{} is not UP after member addition".format(pc_name_1))
            result = False

        # Step 2: Configure VLAN and verify ping
        st.log("Step 2: Configuring VLAN and IP, verifying ping")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name_1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name_1, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Initial ping failed with 2 members")
            result = False
        else:
            st.log("Ping working with 2 members on {}".format(pc_name_1))

        # Step 3: Remove port2 from PortChannel10 on both DUTs
        st.log("Step 3: Removing port2 from {} on both DUTs".format(pc_name_1))
        portchannel.delete_portchannel_member(sc_data.dut1, pc_name_1, [sc_data.d1d3_port2])
        portchannel.delete_portchannel_member(sc_data.dut3, pc_name_1, [sc_data.d3d1_port2])
        st.wait(5, "Waiting for member removal")

        # Step 4: Create PortChannel20 on both DUTs and add port2
        st.log("Step 4: Creating {} on both DUTs and adding port2".format(pc_name_2))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name_2])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name_2])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name_2, members=[sc_data.d1d3_port2])
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name_2, members=[sc_data.d3d1_port2])

        st.wait(10, "Waiting for LACP negotiation on new PortChannel")

        # Step 5: Verify port2 is member of PortChannel20
        st.log("Step 5: Verifying port2 is member of {}".format(pc_name_2))
        if not portchannel.verify_portchannel_member(sc_data.dut1, pc_name_2, [sc_data.d1d3_port2], flag='add'):
            st.error("Port2 not found in {}".format(pc_name_2))
            result = False
        else:
            st.log("Port2 successfully moved to {}".format(pc_name_2))

        # Verify PortChannel20 is UP
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name_2, state="up"):
            st.error("{} is not UP".format(pc_name_2))
            result = False
        else:
            st.log("{} is UP with port2".format(pc_name_2))

        # Step 6: Verify PortChannel10 still functional with port1 only
        st.log("Step 6: Verifying {} still functional with port1 only".format(pc_name_1))
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name_1, state="up"):
            st.error("{} went DOWN after member move".format(pc_name_1))
            result = False
        else:
            st.log("{} still UP with single member".format(pc_name_1))

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping failed on {} with single member".format(pc_name_1))
            result = False
        else:
            st.log("Ping still working on {} with single member".format(pc_name_1))

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def test_l2_portchannel_tagged_untagged_ping():
    """
    Test Case 5: PortChannel Tagged vs Untagged Ping Test

    Steps:
        1. Create PortChannel10 with members
        2. Add PortChannel as untagged member to VLAN 100
        3. Configure IP and verify untagged ping works
        4. Change PortChannel to tagged member of VLAN 100
        5. Verify tagged ping works
        6. Add PortChannel as tagged member to VLAN 200 (trunk mode)
        7. Verify ping on both VLANs
        8. Verify VLAN isolation - unicast from VLAN 100 to VLAN 200 is dropped
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 5: PortChannel Tagged vs Untagged Ping Test")

    try:
        # Step 1: Create PortChannel with members
        st.log("Step: Creating {} with members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.wait(10, "Waiting for LACP negotiation")

        # Step 2: Add PortChannel as untagged member to VLAN 100
        st.log("Step: Adding PortChannel as untagged member to VLAN 100")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        # Step 3: Configure IP and verify untagged ping
        st.log("Step: Configuring IP and verifying untagged ping")
        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Untagged ping failed on VLAN 100")
            result = False
        else:
            st.log("Untagged ping working on VLAN 100")

        # Step 4: Change PortChannel from untagged to tagged member 
        st.log("Step: Changing PortChannel from untagged to tagged member")
        vlan.delete_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.delete_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=True)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        # Step 5: Verify tagged ping
        st.log("Step: Verifying tagged ping on VLAN 100")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Tagged ping failed on VLAN 100")
            result = False
        else:
            st.log("Tagged ping working on VLAN 100")

        # Step 6: Add PortChannel as tagged member to VLAN 200 (trunk mode)
        st.log("Step: Adding PortChannel as tagged member to VLAN 200 (trunk mode)")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id_2)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id_2)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id_2, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id_2, pc_name, tagging_mode=True)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int_2, sc_data.d1_vlan200_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int_2, sc_data.d3_vlan200_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        # Step 7: Verify ping on both VLANs
        st.log("Step: Verifying ping on both VLANs (trunk mode)")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("VLAN 100 ping failed in trunk mode")
            result = False
        else:
            st.log("VLAN 100 ping working in trunk mode")

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan200_ip, count=sc_data.ping_count):
            st.error("VLAN 200 ping failed in trunk mode")
            result = False
        else:
            st.log("VLAN 200 ping working in trunk mode")

        # Step 8: Verify VLAN isolation between VLAN 100 and VLAN 200
        st.log("Step: Verifying VLAN isolation - ping from VLAN 100 to VLAN 200 IP should fail")
        ping_result = ip.ping(sc_data.dut3, sc_data.d1_vlan200_ip, family='ipv4', count=3,
                              interface=sc_data.vlan_int)
        if ping_result:
            st.error("Ping from VLAN 100 to VLAN 200 succeeded - VLAN isolation broken")
            result = False
        else:
            st.log("Ping from VLAN 100 to VLAN 200 failed as expected - VLANs are properly isolated")

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

###############################################################################
# Category 3: VLAN Isolation and Traffic Tests
###############################################################################

def test_l2_portchannel_broadcast_isolation():
    """
    Test Case 7: PortChannel Broadcast Domain Isolation Test

    Steps:
        1. Create PortChannel10 as trunk with VLAN 10 and VLAN 20
        2. Configure IP addresses on both VLANs
        3. Clear ARP and MAC tables
        4. Send broadcast on VLAN 10 (via ping to trigger ARP)
        5. Verify VLAN 10 members receive broadcast (ARP resolves, ping works)
        6. Verify VLAN 20 members do NOT receive VLAN 10 broadcast (isolated)
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 7: PortChannel Broadcast Domain Isolation Test")

    try:
        # Step 1: Create PortChannel as trunk with VLAN 10 and VLAN 20
        st.log("Step 1: Creating PortChannel {} as trunk link".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        # Verify PortChannel is UP
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel {} is not UP".format(pc_name))
            result = False

        # Create VLANs and add PortChannel as tagged member (trunk)
        st.log("Step 1b: Creating VLANs 10 and 20, adding PortChannel as trunk member")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_10)
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_20)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_10)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_20)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_10, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_20, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_10, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_20, pc_name, tagging_mode=True)

        # Step 2: Configure IP addresses
        st.log("Step 2: Configuring IP addresses on VLAN interfaces")
        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int_10, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int_10, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int_20, sc_data.d1_vlan20_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int_20, sc_data.d3_vlan20_ip, sc_data.mask, family='ipv4')


        # Step 3: Clear ARP and MAC tables to ensure clean state
        st.log("Step 3: Clearing ARP and MAC tables for clean broadcast test")
        st.config(sc_data.dut1, "sonic-clear arp", skip_error_check=True)
        st.config(sc_data.dut3, "sonic-clear arp", skip_error_check=True)
        mac.clear_mac(sc_data.dut1)
        mac.clear_mac(sc_data.dut3)
        st.wait(3, "Waiting for tables to clear")

        # Step 4: Send broadcast on VLAN 10 via ping (triggers ARP broadcast)
        st.log("Step 4: Sending broadcast on VLAN 10 via ping (triggers ARP broadcast)")
        st.log("Pinging DUT1 VLAN10 IP {} from DUT3 VLAN10 interface".format(sc_data.d1_vlan10_ip))

        # Step 5: Verify VLAN 10 broadcast reaches VLAN 10 members (ARP resolves, ping works)
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan10_ip, count=sc_data.ping_count):
            st.error("FAIL: VLAN 10 broadcast did not reach VLAN 10 member - ARP failed")
            result = False
        else:
            st.log("PASS: VLAN 10 broadcast reached VLAN 10 member - ARP resolved successfully")

        # Verify peer MAC learned on VLAN 10 PortChannel (not just dump the table)
        st.log("Step 5: Verifying peer MAC learned on VLAN 10 PortChannel")
        peer_mac_vlan10 = mac.get_sbin_intf_mac(sc_data.dut3, sc_data.vlan_int_10)
        if not peer_mac_vlan10:
            st.error("Failed to get VLAN 10 MAC from {}".format(sc_data.dut3))
            result = False
        elif not mac.get_mac_address_list(
                sc_data.dut1, mac=str(peer_mac_vlan10).upper(), vlan=str(sc_data.vlan_10),
                port=pc_name, cli_type='click'):
            st.error("FAIL: Peer MAC not learned on VLAN 10 PortChannel")
            result = False
        else:
            st.log("PASS: Peer MAC {} learned on VLAN 10 PortChannel".format(peer_mac_vlan10))

        # Step 6: Verify VLAN 20 did NOT receive VLAN 10 broadcast
        st.log("Step 6: Verifying VLAN 10 peer MAC is not present on VLAN 20")
        if peer_mac_vlan10 and mac.get_mac_address_list(
                sc_data.dut1, mac=str(peer_mac_vlan10).upper(), vlan=str(sc_data.vlan_20),
                cli_type='click'):
            st.error("FAIL: VLAN 10 peer MAC leaked into VLAN 20 FDB")
            result = False
        else:
            st.log("PASS: VLAN 10 peer MAC not present on VLAN 20 (broadcast domain isolated)")

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

###############################################################################
# Category 4: MAC Table and FDB Verification
###############################################################################

def test_l2_portchannel_mac_flush_member_removal():
    """
    Test Case 8: PortChannel MAC Flush on Member Removal Test

    Steps:
        1. Create PortChannel10 with 2 members
        2. Add to VLAN and send ping to populate MAC table
        3. Verify MAC is learned on PortChannel interface
        4. Remove one member from PortChannel
        5. Verify MAC remains on PortChannel (PC still up)
        6. Remove all members
        7. Verify MAC is flushed from FDB and ping fails
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 8: PortChannel MAC Flush on Member Removal Test")

    try:
        # Step 1: Create PortChannel with 2 members
        st.log("Step: Creating {} with 2 members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        # Step 2: Add to VLAN and configure IP
        st.log("Step: Configuring VLAN and IP")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')


        # Step 3: Send ping to populate MAC table and verify learning on PortChannel
        st.log("Step: Sending ping to populate MAC table")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=5):
            st.error("Initial ping failed before MAC verification")
            result = False

        st.log("Step: Verifying MAC is learned on PortChannel interface")
        if not verify_mac_on_portchannel(sc_data.dut1, sc_data.dut3, sc_data.vlan_id,
                                          sc_data.vlan_int, pc_name):
            st.error("MAC not learned on PortChannel {}".format(pc_name))
            result = False
        else:
            st.log("MAC correctly learned on PortChannel {}".format(pc_name))

        # Step 4: Remove one member
        st.log("Step: Removing one member from PortChannel")
        portchannel.delete_portchannel_member(sc_data.dut1, pc_name, [sc_data.d1d3_port2])
        portchannel.delete_portchannel_member(sc_data.dut3, pc_name, [sc_data.d3d1_port2])
        st.wait(5, "Waiting for member removal to take effect")

        # Step 5: Verify ping still works and MAC remains on PortChannel
        st.log("Step: Verifying ping and MAC entry with single member")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping failed after removing one member")
            result = False
        elif not verify_mac_on_portchannel(sc_data.dut1, sc_data.dut3, sc_data.vlan_id,
                                            sc_data.vlan_int, pc_name):
            st.error("MAC flushed unexpectedly after removing one member")
            result = False
        else:
            st.log("Ping and MAC entry remain with single PortChannel member")

        # Step 6: Remove remaining member (PortChannel goes down)
        st.log("Step: Removing last member from PortChannel")
        portchannel.delete_portchannel_member(sc_data.dut1, pc_name, [sc_data.d1d3_port1])
        portchannel.delete_portchannel_member(sc_data.dut3, pc_name, [sc_data.d3d1_port1])
        st.wait(5, "Waiting for PortChannel to go down")

        # Step 7: Verify ping fails and MAC is flushed from FDB
        st.log("Step: Verifying MAC flush and ping failure with no PortChannel members")
        if verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=3, expected=False):
            st.log("Ping correctly fails with no PortChannel members")
        else:
            st.error("Ping should fail with no PortChannel members")
            result = False

        if not verify_mac_flushed(sc_data.dut1, sc_data.dut3, sc_data.vlan_id,
                                  sc_data.vlan_int, port=pc_name):
            st.error("MAC not flushed from FDB after PortChannel member removal")
            result = False

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def test_portchannel_mac_aging():
    """
    Test Case 9: PortChannel MAC Aging Test

    Verify MAC entries learned over a PortChannel age out after the configured
    fdb_aging_time expires when traffic stops.

    Steps:
        1. Create PortChannel with members and configure VLAN
        2. Add TGen port to VLAN on DUT3 for traffic injection
        3. Set fdb_aging_time via update_mac_aging() (swssconfig SET)
        4. Send TGen L2 burst through PortChannel to populate FDB
        5. Verify TGen MAC is learned on DUT1's PortChannel
        6. Stop traffic, wait for MAC aging based on platform
        7. Verify TGen MAC aged out; restore default aging time
    """
    result = True
    pc_name = sc_data.portchannel_name
    dut_list = [sc_data.dut1, sc_data.dut3]
    tg_src_mac = "00:0A:01:00:00:01"  # TGen source MAC for aging test
    tg_dst_mac = "00:0A:02:00:00:02"  # Arbitrary destination MAC
    tg_port = None

    st.banner("Test Case 9: PortChannel MAC Aging Test (TGen-based)")

    # Get TGen handle - required for this test
    tg, tg_ph = get_tg_handle_d3()
    if not tg:
        pytest.skip("Traffic generator is required for MAC aging test")

    tg_port = vars.D3T1P1  # TGen port on DUT3

    # Detect platform for MAC aging policy
    platform_str = find_platform_str(sc_data.dut1)
    st.log("Detected platform: {}".format(platform_str))

    try:
        st.log("Step 1: Creating {} with members and configuring VLAN".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.wait(15, "Waiting for LACP negotiation")

        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        # Add PortChannel to VLAN on both DUTs
        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        # Step 2: Add TGen port to VLAN on DUT3 for traffic injection
        st.log("Step 2: Adding TGen port {} to VLAN {} on DUT3".format(tg_port, sc_data.vlan_id))
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, tg_port, tagging_mode=False)

        st.wait(5, "Waiting for PortChannel and VLAN interfaces to come up")

        st.log("Step 3: Setting fdb_aging_time to {} seconds".format(MAC_AGING_TIME_NEW))
        for dut in dut_list:
            if not update_mac_aging(dut, MAC_AGING_TIME_NEW, verify=True):
                st.error("Failed to set MAC aging time on {}".format(dut))
                result = False

        if not result:
            st.log("Skipping MAC aging verification because aging time configuration failed")
        else:
            mac.clear_mac(sc_data.dut1)
            mac.clear_mac(sc_data.dut3)
            st.wait(3, "Waiting for MAC tables to clear")

            # Step 4: Send TGen L2 burst to populate FDB
            # Traffic path: TGen -> D3 (tg_port) -> PortChannel -> D1
            # D1 will learn tg_src_mac on its PortChannel interface
            st.log("Step 4: Sending TGen L2 burst with src MAC {} to populate FDB".format(tg_src_mac))
            stream_id = send_tg_l2_burst(tg, tg_ph, tg_src_mac, tg_dst_mac, vlan_id=None, pkts=500)
            st.log("TGen burst sent, stream_id: {}".format(stream_id))

            # Step 5: Verify TGen MAC is learned on DUT1's PortChannel
            st.log("Step 5: Verifying TGen MAC {} is learned on {} {}".format(tg_src_mac, sc_data.dut1, pc_name))
            st.wait(2, "Waiting for MAC learning")
            if not verify_mac_entry(sc_data.dut1, tg_src_mac, sc_data.vlan_id, port=pc_name):
                st.error("TGen MAC {} not learned on PortChannel {}".format(tg_src_mac, pc_name))
                result = False
            else:
                st.log("TGen MAC {} correctly learned on PortChannel {}".format(tg_src_mac, pc_name))

            # Step 6: Wait for MAC aging based on platform
            if result:
                macs_aged_out = False
                poll_interval = 30
                multiplier = get_mac_aging_multiplier(platform_str)
                max_wait = MAC_AGING_TIME_NEW * multiplier
                st.log("Step 6: Platform {} ({}x) - waiting up to {} seconds for MAC aging".format(
                    platform_str or 'default', multiplier, max_wait))

                elapsed = 0
                while elapsed < max_wait:
                    time.sleep(poll_interval)
                    elapsed += poll_interval
                    st.log("Polling MAC table after {} seconds (max wait: {} seconds)".format(elapsed, max_wait))
                    if not verify_mac_entry(sc_data.dut1, tg_src_mac, sc_data.vlan_id, port=pc_name):
                        macs_aged_out = True
                        st.log("TGen MAC {} aged out after {} seconds".format(tg_src_mac, elapsed))
                        break

                if not macs_aged_out:
                    st.error("TGen MAC {} did not age out from PortChannel {} within {} seconds".format(
                        tg_src_mac, pc_name, max_wait))
                    result = False
                else:
                    st.log("Step 7: TGen MAC {} successfully aged out from PortChannel {}".format(tg_src_mac, pc_name))

    finally:
        st.log("Restoring default fdb_aging_time ({} seconds)".format(MAC_AGING_TIME_DEFAULT))
        for dut in dut_list:
            restore_mac_aging(dut)
        # Remove TGen port from VLAN before cleanup (if it was added)
        if tg_port:
            try:
                vlan.delete_vlan_member(sc_data.dut3, sc_data.vlan_id, tg_port, tagging_mode=False)
            except Exception:
                pass
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

###############################################################################
# Category 5: Rapid Member Add/Remove Stress
###############################################################################

def test_l2_portchannel_rapid_member_add_remove():
    """
    Test Case 10: PortChannel Rapid Member Add/Remove Stress Test

    Steps:
        1. Create PortChannel10 with 2 members initially
        2. Configure VLAN/IP and verify ping works
        3. Rapidly add and remove port3 20+ times in succession
        4. After all iterations, verify PortChannel is stable and functional
        5. Verify no stale member state in show interfaces portchannel
    """
    result = True
    pc_name = sc_data.portchannel_name
    iterations = 25
    st.banner("Test Case 10: PortChannel Rapid Member Add/Remove Stress Test ({} iterations)".format(iterations))

    try:
        st.log("Step 1: Creating {} with 2 initial members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.log("Step 2: Configuring VLAN/IP and verifying initial ping")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Initial ping failed before stress test")
            result = False

        st.log("Step 3: Starting rapid member add/remove stress test ({} iterations)".format(iterations))
        test_port_dut1 = sc_data.d1d3_port3
        test_port_dut3 = sc_data.d3d1_port3

        for i in range(iterations):
            if (i + 1) % 5 == 0:
                st.log("Iteration {}/{}".format(i + 1, iterations))

            portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=[test_port_dut1])
            portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=[test_port_dut3])
            st.wait(1, "Waiting for member add to register")

            portchannel.delete_portchannel_member(sc_data.dut1, pc_name, [test_port_dut1])
            portchannel.delete_portchannel_member(sc_data.dut3, pc_name, [test_port_dut3])
            st.wait(1, "Waiting for member remove to register")

        st.log("Completed {} rapid add/remove iterations".format(iterations))
        st.wait(10, "Waiting for system to stabilize after stress test")

        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel not UP after rapid add/remove stress test")
            result = False

        st.log("Step 5: Verifying no stale member state in PortChannel")
        pc_details = portchannel.get_portchannel(sc_data.dut1, pc_name)
        st.log("PortChannel details after stress test: {}".format(pc_details))

        if portchannel.verify_portchannel_member(sc_data.dut1, pc_name, [test_port_dut1], flag='add'):
            st.error("Stale member {} found in PortChannel after stress test".format(test_port_dut1))
            result = False
            portchannel.delete_portchannel_member(sc_data.dut1, pc_name, [test_port_dut1])
            portchannel.delete_portchannel_member(sc_data.dut3, pc_name, [test_port_dut3])
        else:
            st.log("No stale member state - {} correctly not in PortChannel".format(test_port_dut1))

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Category 6: Native VLAN with Trunk
###############################################################################

def test_l2_portchannel_native_vlan_with_trunk():
    """
    Test Case 11: PortChannel Native VLAN with Trunk Test

    Steps:
        1. Create PortChannel10 with members
        2. Configure PortChannel as untagged member of VLAN 10 (native VLAN)
        3. Configure PortChannel as tagged member of VLAN 20 (trunk)
        4. Configure IP addresses on both VLANs
        5. Send untagged Ixia traffic -- classified into native VLAN 10 on PortChannel
        6. Send VLAN 20 tagged Ixia traffic -- forwarded within VLAN 20 on PortChannel
        7. Verify MAC learning on PortChannel for native and trunk VLANs
        8. Send BUM (broadcast) traffic on native VLAN and verify MAC on PortChannel
    """
    result = True
    pc_name = sc_data.portchannel_name
    native_vlan = 10
    trunk_vlan = 20
    native_vlan_int = "Vlan{}".format(native_vlan)
    trunk_vlan_int = "Vlan{}".format(trunk_vlan)
    native_d1_ip = "10.10.10.1"
    native_d3_ip = "10.10.10.2"
    trunk_d1_ip = "20.20.20.1"
    trunk_d3_ip = "20.20.20.2"
    tg_src_mac_native = "00:0B:01:00:00:01"
    tg_src_mac_trunk = "00:0B:02:00:00:02"
    tg_dst_mac = "00:0b:00:00:00:ff"
    tg_bcast_mac = "ff:ff:ff:ff:ff:ff"

    tg, tg_ph = get_tg_handle_d3()
    if not tg:
        pytest.skip("Traffic generator (Ixia) is required for native VLAN with trunk test")

    tg_port = vars.D3T1P1

    st.banner("Test Case 13: PortChannel Native VLAN with Trunk Test")

    try:
        # Step 1: Create PortChannel with members
        st.log("Step 1: Creating {} with members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.wait(10, "Waiting for LACP negotiation")

        # Verify PortChannel is UP
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel {} is not UP".format(pc_name))
            result = False

        # Step 2: Create VLANs
        st.log("Step 2: Creating native VLAN {} and trunk VLAN {}".format(native_vlan, trunk_vlan))
        vlan.create_vlan(sc_data.dut1, native_vlan)
        vlan.create_vlan(sc_data.dut1, trunk_vlan)
        vlan.create_vlan(sc_data.dut3, native_vlan)
        vlan.create_vlan(sc_data.dut3, trunk_vlan)

        # Step 3: Configure PortChannel as untagged member of native VLAN and tagged member of trunk VLAN
        st.log("Step 3: Adding PortChannel as untagged member to VLAN {} (native)".format(native_vlan))
        vlan.add_vlan_member(sc_data.dut1, native_vlan, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, native_vlan, pc_name, tagging_mode=False)

        st.log("Step 3b: Adding PortChannel as tagged member to VLAN {} (trunk)".format(trunk_vlan))
        vlan.add_vlan_member(sc_data.dut1, trunk_vlan, pc_name, tagging_mode=True)
        vlan.add_vlan_member(sc_data.dut3, trunk_vlan, pc_name, tagging_mode=True)

        # Step 4: Configure IP addresses on both VLANs
        st.log("Step 4: Configuring IP addresses on native and trunk VLAN interfaces")
        ip.config_ip_addr_interface(sc_data.dut1, native_vlan_int, native_d1_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, native_vlan_int, native_d3_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut1, trunk_vlan_int, trunk_d1_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, trunk_vlan_int, trunk_d3_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interfaces to come up")

        # Add TG access/trunk port on DUT3 (same VLAN membership as PortChannel)
        st.log("Step 4b: Adding TG port {} on DUT3 for Ixia traffic injection".format(tg_port))
        vlan.add_vlan_member(sc_data.dut3, native_vlan, tg_port, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, trunk_vlan, tg_port, tagging_mode=True)

        mac.clear_mac(sc_data.dut1)
        mac.clear_mac(sc_data.dut3)
        st.wait(3, "Waiting for MAC tables to clear")

        # Step 5: Send untagged Ixia traffic classified into native VLAN on PortChannel
        st.log("Step 5: Sending untagged Ixia traffic for native VLAN {}".format(native_vlan))
        send_tg_l2_burst(tg, tg_ph, tg_src_mac_native, tg_dst_mac, vlan_id=None)
        st.wait(2, "Waiting for MAC learning on native VLAN")
        if not mac.verify_mac_address_table(sc_data.dut1, tg_src_mac_native.upper(),
                                            vlan=native_vlan, port=pc_name):
            st.error("Untagged Ixia MAC not learned on {} for native VLAN {}".format(
                pc_name, native_vlan))
            result = False
        else:
            st.log("PASS: Untagged Ixia MAC learned on {} for native VLAN {}".format(
                pc_name, native_vlan))

        # Step 6: Send VLAN 20 tagged Ixia traffic on PortChannel
        st.log("Step 6: Sending VLAN {} tagged Ixia traffic on trunk".format(trunk_vlan))
        send_tg_l2_burst(tg, tg_ph, tg_src_mac_trunk, tg_dst_mac, vlan_id=trunk_vlan)
        st.wait(2, "Waiting for MAC learning on trunk VLAN")
        if not mac.verify_mac_address_table(sc_data.dut1, tg_src_mac_trunk.upper(),
                                            vlan=trunk_vlan, port=pc_name):
            st.error("Tagged Ixia MAC not learned on {} for trunk VLAN {}".format(
                pc_name, trunk_vlan))
            result = False
        else:
            st.log("PASS: Tagged Ixia MAC learned on {} for trunk VLAN {}".format(
                pc_name, trunk_vlan))

        # Step 7: Verify BUM (broadcast) traffic on native VLAN learns MAC on PortChannel
        st.log("Step 7: Sending BUM (broadcast) Ixia traffic on native VLAN")
        mac.clear_mac(sc_data.dut1)
        send_tg_l2_burst(tg, tg_ph, tg_src_mac_native, tg_bcast_mac, vlan_id=None)
        st.wait(2, "Waiting for broadcast MAC learning")
        if not mac.verify_mac_address_table(sc_data.dut1, tg_src_mac_native.upper(),
                                            vlan=native_vlan, port=pc_name):
            st.error("BUM Ixia MAC not learned on {} for native VLAN {}".format(
                pc_name, native_vlan))
            result = False
        else:
            st.log("PASS: BUM Ixia MAC learned on {} for native VLAN {}".format(
                pc_name, native_vlan))

        # Step 8: Final ping check -- both VLANs reachable over PortChannel
        st.log("Step 8: Final ping verification on native and trunk VLANs")
        if not verify_ping(sc_data.dut3, native_d1_ip, count=3):
            st.error("Native VLAN {} ping failed in final check".format(native_vlan))
            result = False

        if not verify_ping(sc_data.dut3, trunk_d1_ip, count=3):
            st.error("Trunk VLAN {} ping failed in final check".format(trunk_vlan))
            result = False

        if result:
            st.log("PASS: Native VLAN {} and trunk VLAN {} verified on PortChannel".format(
                native_vlan, trunk_vlan))

    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

###############################################################################
# Category 7: Warm Reboot with Traffic
###############################################################################

def test_l2_portchannel_warm_reboot_with_traffic():
    """
    Test Case 14: PortChannel Warm Reboot with Continuous Traffic Test

    Steps:
        1. Create PortChannel10 with members
        2. Configure VLAN and IP
        3. Verify traffic before warm reboot
        4. Save configuration
        5. Perform warm reboot on DUT1
        6. Verify PortChannel state is restored after warm reboot
        7. Verify traffic resumes with minimal or zero loss
    """
    result = True
    pc_name = sc_data.portchannel_name

    st.banner("Test Case 14: PortChannel Warm Reboot with Continuous Traffic Test")

    try:
        # Step 1: Create PortChannel with members
        st.log("Step 1: Creating {} with members".format(pc_name))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name])
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name])

        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3)

        st.wait(10, "Waiting for LACP negotiation")

        # Verify PortChannel is UP
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel {} is not UP before warm reboot".format(pc_name))
            result = False

        # Step 2: Configure VLAN and IP
        st.log("Step 2: Configuring VLAN and IP addresses")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interface to come up")

        # Step 3: Verify traffic before warm reboot
        st.log("Step 3: Verifying traffic before warm reboot")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Traffic failed before warm reboot")
            result = False
        else:
            st.log("Traffic working before warm reboot")

        # Step 4: Save configuration before warm reboot
        # Warm reboot preserves running config; no startup save needed and avoids
        # persisting temporary test state into startup-config.
        st.log("Step 4: Skipping startup save (warm reboot uses running config)")

        # Record PortChannel state before reboot
        pc_state_before = portchannel.get_portchannel(sc_data.dut1, pc_name)
        st.log("PortChannel state before warm reboot: {}".format(pc_state_before))

        # Step 5: Perform warm reboot on DUT1
        st.log("Step 5: Performing warm reboot on DUT1")
        reboot.config_warm_restart(sc_data.dut1, oper="enable")
        st.reboot(sc_data.dut1, method="warm")

        st.wait(120, "Waiting for DUT1 to complete warm reboot and stabilize")

        st.log("Step 6: Verifying PortChannel state after warm reboot")
        
        # Wait for PortChannel to come up (may take time after reboot)
        max_wait = 60
        pc_up = False
        for i in range(max_wait // 5):
            if portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up", error_msg=False):
                pc_up = True
                st.log("PortChannel {} is UP after warm reboot (waited {} seconds)".format(pc_name, i * 5))
                break
            st.wait(5, "Waiting for PortChannel to come up...")
        
        if not pc_up:
            st.error("PortChannel {} failed to come UP after warm reboot".format(pc_name))
            result = False
        else:
            st.log("PASS: PortChannel state restored after warm reboot")

        # Step 7: Verify traffic resumes
        st.log("Step 7: Verifying traffic resumes after warm reboot")
        
        # Wait for full convergence
        st.wait(10, "Waiting for full convergence after warm reboot")
        
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Traffic failed to resume after warm reboot")
            result = False
        else:
            st.log("PASS: Traffic resumed after warm reboot")

        # Step 8: Verify PortChannel members are all active
        st.log("Step 8: Verifying PortChannel members are active after warm reboot")
        if not portchannel.verify_portchannel_member(sc_data.dut1, pc_name, sc_data.members_dut1, flag='add'):
            st.error("PortChannel members not restored after warm reboot")
            result = False
        else:
            st.log("PASS: All PortChannel members active after warm reboot")

        # Record PortChannel state after reboot
        pc_state_after = portchannel.get_portchannel(sc_data.dut1, pc_name)
        st.log("PortChannel state after warm reboot: {}".format(pc_state_after))

        if result:
            st.log("PASS: Warm reboot completed successfully with PortChannel restored")

    finally:
        reboot.config_warm_restart(sc_data.dut1, oper="disable")
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

###############################################################################
# Category 8: Min-Links Extended Scenarios
###############################################################################

def test_l2_portchannel_min_links_various_thresholds():
    """
    Test Case 15: PortChannel Min-Links Various Thresholds Test

    Steps:
        1. Create PortChannel10 with min-links=3 and 4 members
        2. Verify PortChannel is UP (4 members >= min-links 3)
        3. Configure VLAN/IP and verify ping works
        4. Shut 1 member (3 remaining >= min-links 3)
        5. Verify PortChannel still UP and ping works
        6. Shut another member (2 remaining < min-links 3)
        7. Verify PortChannel goes DOWN and ping fails
        8. Unshut both members
        9. Verify PortChannel recovers and ping works
    """
    result = True
    pc_name = sc_data.portchannel_name
    min_links = "3"

    st.banner("Test Case 15: PortChannel Min-Links Various Thresholds Test (min-links=3, 4 members)")

    try:
        # Step 1: Create PortChannel with min-links=3 and 4 members
        st.log("Step: Creating {} with min-links={} and 4 members".format(pc_name, min_links))
        portchannel.create_portchannel(sc_data.dut1, portchannel_list=[pc_name], min_link=min_links)
        portchannel.create_portchannel(sc_data.dut3, portchannel_list=[pc_name], min_link=min_links)

        # Add all 4 members
        portchannel.add_portchannel_member(sc_data.dut1, portchannel=pc_name, members=sc_data.members_dut1_all)
        portchannel.add_portchannel_member(sc_data.dut3, portchannel=pc_name, members=sc_data.members_dut3_all)

        st.wait(15, "Waiting for LACP negotiation with 4 members")

        # Step 2: Verify PortChannel is UP 
        st.log("Step: Verifying PortChannel is UP with 4 members (>= min-links 3)")
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel should be UP with 4 members >= min-links 3")
            result = False

        # Step 3: Configure VLAN and verify ping
        st.log("Step: Configuring VLAN and IP")
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, pc_name, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, pc_name, tagging_mode=False)

        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan100_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan100_ip, sc_data.mask, family='ipv4')


        st.log("Step: Verifying initial ping with 4 members")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Initial ping failed with 4 members")
            result = False
        else:
            st.log("Ping working with 4 members")

        # Step 4: Shut 1 member on both DUTs
        st.log("Step: Shutting down 1 member port (port4) on both DUTs")
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port4)
        intf.interface_shutdown(sc_data.dut3, sc_data.d3d1_port4)
        st.wait(10, "Waiting for LACP to converge after port shutdown")

        # Step 5: Verify PortChannel still UP
        st.log("Step: Verifying PortChannel still UP with 3 members")
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel should still be UP with 3 members = min-links 3")
            result = False

        st.log("Step: Verifying ping with 3 members")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping failed with 3 members")
            result = False

        # Step 6: Shut another member on both DUTs (2 remaining < min-links 3)
        st.log("Step: Shutting down another member port (port3) on both DUTs")
        intf.interface_shutdown(sc_data.dut1, sc_data.d1d3_port3)
        intf.interface_shutdown(sc_data.dut3, sc_data.d3d1_port3)
        st.wait(10, "Waiting for LACP to converge after port shutdown")

        # Step 7: Verify PortChannel goes DOWN
        st.log("Step: Verifying PortChannel goes DOWN with 2 members")
        if portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up", error_msg=False):
            st.error("PortChannel should be DOWN with 2 members")
            result = False
        else:
            st.log("PortChannel correctly DOWN (below min-links threshold)")

        st.log("Step: Verifying ping fails with PortChannel DOWN")
        if verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=3, expected=False):
            st.log("Ping correctly fails with PortChannel DOWN")
        else:
            st.error("Ping should fail when PortChannel is DOWN")
            result = False

        # Step 8: Unshut both members on both DUTs
        st.log("Step: Bringing both member ports (port3 and port4) back up on both DUTs")
        intf.interface_noshutdown(sc_data.dut1, sc_data.d1d3_port3)
        intf.interface_noshutdown(sc_data.dut1, sc_data.d1d3_port4)
        intf.interface_noshutdown(sc_data.dut3, sc_data.d3d1_port3)
        intf.interface_noshutdown(sc_data.dut3, sc_data.d3d1_port4)

        # Step 9: Verify PortChannel recovers (4 >= 3)
        st.log("Step: Verifying PortChannel recovers after members come back up")
        if not portchannel.verify_portchannel_state(sc_data.dut1, pc_name, state="up"):
            st.error("PortChannel failed to recover after members came up")
            result = False
       
        st.log("Step: Verifying ping after recovery")
        if not verify_ping(sc_data.dut3, sc_data.d1_vlan100_ip, count=sc_data.ping_count):
            st.error("Ping failed after PortChannel recovery")
            result = False
        
    finally:
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


###############################################################################
# Static MAC Test Cases
###############################################################################

def test_static_mac_no_move_to_dynamic():
    """
    Verify static MAC entry does not get overwritten by dynamic MAC traffic.

    Test Steps:
    1. Configure VLAN 10 on DUT1 and DUT3 with direct interconnect ports
    2. Configure IP addresses on VLAN interfaces
    3. Get DUT3's interface MAC address
    4. Configure static MAC entry on DUT1 for DUT3's MAC pointing to d1d3_port1
    5. Verify static MAC is configured correctly
    6. Generate traffic by pinging from DUT3 to DUT1 (sends packets with DUT3's MAC)
    7. Verify MAC entry on DUT1 remains STATIC (not converted to dynamic)

    Expected Result: Static MAC entry should NOT be overwritten by dynamic traffic
    """
    result = True
    dut3_mac = None

    try:
        st.banner("Test Case 15: Static MAC entry does not get overwritten by dynamic MAC traffic")

        # Step 1: Create VLAN on both DUTs
        st.log("Step 1: Creating VLAN {} on DUT1 and DUT3".format(sc_data.vlan_id))
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        # Step 2: Add ports to VLAN as untagged members
        st.log("Step 2: Adding ports to VLAN as untagged members")
        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, sc_data.d3d1_port1, tagging_mode=False)

        # Step 3: Configure IP addresses on VLAN interfaces
        st.log("Step 3: Configuring IP addresses on VLAN interfaces")
        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interfaces to come up")

        # Step 4: Get DUT3's interface MAC address
        st.log("Step 4: Getting DUT3's interface MAC address")
        dut3_mac = get_dut_interface_mac(sc_data.dut3, sc_data.d3d1_port1)
        if not dut3_mac:
            # Fallback: use VLAN interface MAC
            dut3_mac = get_dut_interface_mac(sc_data.dut3, sc_data.vlan_int)
        if not dut3_mac:
            st.error("Failed to get DUT3's MAC address")
            result = False
            raise Exception("Cannot get DUT3 MAC")
        st.log("DUT3's MAC address: {}".format(dut3_mac))

        # Step 5: Configure static MAC on DUT1 for DUT3's MAC
        st.log("Step 5: Configuring static MAC {} on DUT1 pointing to {}".format(dut3_mac, sc_data.d1d3_port1))
        mac.config_mac(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1)

        # Step 6: Verify static MAC is configured
        st.log("Step 6: Verifying static MAC is configured")
        if not verify_mac_entry(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1, "static"):
            st.error("Static MAC entry not found or not marked as static")
            result = False
            raise Exception("Static MAC verification failed")
        st.log("Static MAC configured and verified successfully")

        # Step 7: Generate traffic by pinging from DUT3 to DUT1
        st.log("Step 7: Pinging from DUT3 to DUT1 to generate traffic with DUT3's MAC")
        for i in range(3):
            ip.ping(sc_data.dut3, sc_data.d1_vlan10_ip, family='ipv4', count=10)
            st.wait(2, "Waiting between ping iterations")

        # Step 8: Verify MAC entry remains STATIC on DUT1
        st.log("Step 8: Verifying MAC entry remains STATIC after dynamic traffic")
        st.wait(5, "Waiting for MAC table to stabilize")

        if not verify_mac_entry(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1, "static"):
            st.error("CRITICAL: Static MAC was converted to dynamic! This is a failure.")
            result = False
        else:
            st.log("SUCCESS: Static MAC entry remains STATIC after dynamic traffic")

    except Exception as e:
        st.error("Exception occurred: {}".format(str(e)))
        result = False

    finally:
        st.log("Cleanup: Removing configurations")
        if dut3_mac:
            mac.delete_mac(sc_data.dut1, dut3_mac, sc_data.vlan_id)
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.static_mac
def test_static_mac_no_aging():
    """
    Verify static MAC entry does not age out even with short aging time.

    Test Steps:
    1. Configure VLAN 10 on DUT1 and DUT3 with direct interconnect ports
    2. Configure IP addresses on VLAN interfaces
    3. Get DUT3's interface MAC address
    4. Configure static MAC entry on DUT1 for DUT3's MAC
    5. Set a short MAC aging time (10 seconds)
    6. Wait longer than aging time (with platform multiplier)
    7. Verify static MAC entry still exists (static MAC should NOT age out)

    Expected Result: Static MAC entry should NOT age out
    """
    result = True
    base_aging_time = 10  # seconds
    dut3_mac = None

    try:
        st.banner("Test Case 15: Static MAC entry does not get overwritten by dynamic MAC traffic")

        # Step 1: Create VLAN on both DUTs
        st.log("Step 1: Creating VLAN {} on DUT1 and DUT3".format(sc_data.vlan_id))
        vlan.create_vlan(sc_data.dut1, sc_data.vlan_id)
        vlan.create_vlan(sc_data.dut3, sc_data.vlan_id)

        # Step 2: Add ports to VLAN as untagged members
        st.log("Step 2: Adding ports to VLAN as untagged members")
        vlan.add_vlan_member(sc_data.dut1, sc_data.vlan_id, sc_data.d1d3_port1, tagging_mode=False)
        vlan.add_vlan_member(sc_data.dut3, sc_data.vlan_id, sc_data.d3d1_port1, tagging_mode=False)

        # Step 3: Configure IP addresses on VLAN interfaces
        st.log("Step 3: Configuring IP addresses on VLAN interfaces")
        ip.config_ip_addr_interface(sc_data.dut1, sc_data.vlan_int, sc_data.d1_vlan10_ip, sc_data.mask, family='ipv4')
        ip.config_ip_addr_interface(sc_data.dut3, sc_data.vlan_int, sc_data.d3_vlan10_ip, sc_data.mask, family='ipv4')

        st.wait(5, "Waiting for VLAN interfaces to come up")

        # Step 4: Get DUT3's interface MAC address
        st.log("Step 4: Getting DUT3's interface MAC address")
        dut3_mac = get_dut_interface_mac(sc_data.dut3, sc_data.d3d1_port1)
        if not dut3_mac:
            dut3_mac = get_dut_interface_mac(sc_data.dut3, sc_data.vlan_int)
        if not dut3_mac:
            st.error("Failed to get DUT3's MAC address")
            result = False
            raise Exception("Cannot get DUT3 MAC")
        st.log("DUT3's MAC address: {}".format(dut3_mac))

        # Step 5: Configure static MAC on DUT1 for DUT3's MAC
        st.log("Step 5: Configuring static MAC {} on DUT1 pointing to {}".format(dut3_mac, sc_data.d1d3_port1))
        mac.config_mac(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1)

        # Step 6: Verify static MAC is configured
        st.log("Step 6: Verifying static MAC is configured")
        if not verify_mac_entry(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1, "static"):
            st.error("Static MAC entry not found or not marked as static")
            result = False
            raise Exception("Static MAC verification failed")
        st.log("Static MAC configured and verified successfully")

        # Step 7: Get platform type and calculate wait time
        st.log("Step 7: Getting platform type for aging multiplier")
        platform_str = find_platform_str(sc_data.dut1)
        aging_multiplier = get_mac_aging_multiplier(platform_str or '')
        st.log("Platform: {}, Aging multiplier: {}".format(platform_str or 'default', aging_multiplier))

        # Step 8: Set short MAC aging time (swssconfig; config mac aging_time unsupported on community builds)
        st.log("Step 8: Setting MAC aging time to {} seconds".format(base_aging_time))
        if not update_mac_aging(sc_data.dut1, base_aging_time, verify=True):
            st.error("Failed to set MAC aging time")
            result = False
            raise Exception("MAC aging time configuration failed")

        # Step 9: Wait longer than aging time
        wait_time = base_aging_time * aging_multiplier + 15  # Add buffer
        st.log("Step 9: Waiting {} seconds (aging_time * multiplier + buffer)".format(wait_time))
        st.wait(wait_time, "Waiting for aging timer to expire")

        # Step 10: Verify static MAC still exists
        st.log("Step 10: Verifying static MAC entry still exists after aging time")
        if not verify_mac_entry(sc_data.dut1, dut3_mac, sc_data.vlan_id, sc_data.d1d3_port1, "static"):
            st.error("CRITICAL: Static MAC aged out! This is a failure.")
            result = False
        else:
            st.log("SUCCESS: Static MAC entry did NOT age out (expected behavior)")

    except Exception as e:
        st.error("Exception occurred: {}".format(str(e)))
        result = False

    finally:
        st.log("Cleanup: Removing configurations")
        restore_mac_aging(sc_data.dut1)
        if dut3_mac:
            mac.delete_mac(sc_data.dut1, dut3_mac, sc_data.vlan_id)
        portchannel_test_cleanup()

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
