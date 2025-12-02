import os
import pytest
from spytest import st, SpyTestDict
import apis.system.reboot as reboot

# Global data dictionary
data_glob = SpyTestDict()

@pytest.fixture(scope='function', autouse=True)
def lldp_func_hooks(request):
    """
    Fixture to manage per-function cleanup for LLDP tests.
    Ensures cleanup runs even if a test fails.
    """
    st.log('LLDP Custom TLV Startup completed')
    data_glob.function_unconfig = False # Flag to control cleanup execution
    try:
        yield # This is where the test function runs
    finally:
        # This block will ALWAYS execute, even if the test fails or an exception occurs
        function_unconfig()
        st.log("Cleanup via function_unconfig completed in finally block.")

def function_unconfig():
    """
    Performs cleanup specifically for LLDP custom TLV configurations.
    This function is called automatically after each test function.
    """
    st.log('LLDP Custom TLV cleanup Started')
    if not data_glob.function_unconfig:
        data_glob.function_unconfig = True
        st.log('LLDP Custom TLV Cleanup started in function_unconfig')

        # Cleanup based on the tlv_definitions that were active during the test
        if hasattr(data_glob, 'tlv_definitions') and data_glob.tlv_definitions:
            for tlv_data in data_glob.tlv_definitions:
                # Remove custom TLV association from interface
                cmd_remove_intf_tlv = "config interface lldp custom-tlv remove {} {}".format(data_glob.dut1_port, tlv_data.tlv_name)
                st.config(data_glob.dut1, cmd_remove_intf_tlv, skip_error_check=True, timeout=10)
                # Remove custom TLV definition
                cmd_remove_tlv = "config lldp custom-tlv remove {}".format(tlv_data.tlv_name)
                st.config(data_glob.dut1, cmd_remove_tlv, skip_error_check=True, timeout=10)
            st.log('LLDP Custom TLV Cleanup completed in function_unconfig')
            # --- Post-cleanup verification: Verify TLVs are absent ---
            st.log("Verifying absence of TLVs on peer after cleanup.")
            st.wait(2) # Give LLDP time to update after removal
            if verify_no_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, data_glob.tlv_definitions):
                st.log("Successfully verified absence of all TLVs on peer after cleanup.")
            else:
                st.report_fail("msg", "Failed to verify absence of one or more TLVs on peer after cleanup.")
            # --- End post-cleanup verification ---

        else:
            st.log('LLDP Custom TLV cleanup skipped: tlv_definitions was empty or not set for this test.')


@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    """
    Module-scoped fixture to set up the testbed and global variables.
    Ensures a minimal topology for the LLDP test.
    """
    global vars

    # Ensure a minimal topology: D1 connected to D3 (e.g., Spine0 to Leaf0)
    st.ensure_min_topology("D1D3:1")
    vars = st.get_testbed_vars()

    # Define DUTs and interfaces for the LLDP test
    data_glob.dut1 = vars.D1 # Device where TLV is configured
    data_glob.dut2 = vars.D3 # Peer device to verify TLV
    data_glob.dut1_port = vars.D1D3P1 # Interface on DUT1 connected to DUT2
    data_glob.dut1_port_2 = vars.D1D3P2 # Interface on DUT1 connected to DUT2
    data_glob.dut2_port = vars.D3D1P1 # Interface on DUT2 connected to DUT1
    data_glob.dut2_port_2 = vars.D3D1P2 # Interface on DUT2 connected to DUT1
    data_glob.single_lldp = False

    data_glob.tlv_definitions = [
        SpyTestDict({
            'tlv_name': "my_custom_tlv_1",
            'oui_value': "00,20,2C",
            'subtype_value': "1",
            'oui_info_value': "12,46,5C,04,9A,4D,01,01,28,B1,87,1C",
        }),
        SpyTestDict({
            'tlv_name': "my_custom_tlv_2",
            'oui_value': "00,0A,0B",
            'subtype_value': "10",
            'oui_info_value': "A1,B2,C3,D4,E5,F6",
        }),
        SpyTestDict({
            'tlv_name': "my_custom_tlv_3",
            'oui_value': "00,0C,0D",
            'subtype_value': "20",
            'oui_info_value': "01,02,03,04,05,06,07,08",
        })
    ]

    for tlv_data in data_glob.tlv_definitions:
        tlv_data.expected_oui_lldpcli = tlv_data.oui_value # OUI format is same for config and lldpcli
        tlv_data.expected_subtype_lldpcli = tlv_data.subtype_value # Subtype format is same
        tlv_data.expected_oui_info_lldpcli =  tlv_data.oui_info_value

    yield 'setup_teardown_basic'
    st.log("LLDP test teardown completed.")


def verify_lldp_custom_tlv_on_peer(dut, peer_port, tlv_data):
    """
    Verifies the presence and correctness of a single custom LLDP TLV on a peer device.

    Args:
        dut (str): The name of the peer device (e.g., data_glob.dut2).
        peer_port (str): The interface on the peer device connected to the sender.
        tlv_data (SpyTestDict): A dictionary containing 'expected_oui_lldpcli',
                                'expected_subtype_lldpcli', 'expected_oui_info_lldpcli',
                                and 'oui_info_value' (raw hex for length calculation).

    Returns:
        bool: True if the custom TLV is found and matches, False otherwise.
    """
    st.log("Executing 'lldpcli show neighbors' on {} port {} to verify TLV: {}".format(dut, peer_port, tlv_data.tlv_name))
    cmd_show_lldp = "lldpcli show neighbors ports {}".format(peer_port)
    output = st.config(dut, cmd_show_lldp)

    if not output:
        st.log("No LLDP neighbor output received from {} on port {}".format(dut, peer_port))
        return False

    found_tlv_match = False
    lines = output.splitlines()
    for line in lines:
        tlv_line = line.strip()
        if tlv_line.startswith("TLV:"):
            tlv_data_part = tlv_line.split("TLV:", 1)[1].strip()

            # Check for OUI
            oui_match_str = "OUI: {}".format(tlv_data.expected_oui_lldpcli)
            if oui_match_str not in tlv_data_part:
                continue # Not the TLV we are looking for, or mismatch

            # Check for SubType
            subtype_match_str = "SubType: {}".format(tlv_data.expected_subtype_lldpcli)
            if subtype_match_str not in tlv_data_part:
                continue

            # Check for OUI-Info
            oui_info_match_str = tlv_data.expected_oui_info_lldpcli
            if oui_info_match_str not in tlv_data_part:
                continue

            # If all parts are found, then the TLV is verified
            st.log("Found and verified custom TLV '{}': {}".format(tlv_data.tlv_name, tlv_line))
            found_tlv_match = True
            break # Found this specific TLV, no need to check further lines

    if not found_tlv_match:
        st.log("Custom TLV '{}' not found or not matching on peer device.".format(tlv_data.tlv_name))
    return found_tlv_match

def verify_no_lldp_custom_tlv_on_peer(dut, peer_port, tlv_definitions_to_check_for_absence):
    """
    Verifies the absence of specified custom LLDP TLVs on a peer device.

    Args:
        dut (str): The name of the peer device (e.g., data_glob.dut2).
        peer_port (str): The interface on the peer device connected to the sender.
        tlv_definitions_to_check_for_absence (list): A list of SpyTestDicts,
            each defining a TLV that should NOT be present.

    Returns:
        bool: True if NONE of the specified TLVs are found, False if any are found.
    """
    st.log("Executing 'lldpcli show neighbors' on {} port {} to verify absence of TLVs.".format(dut, peer_port))
    cmd_show_lldp = "lldpcli show neighbors ports {}".format(peer_port)
    output = st.config(dut, cmd_show_lldp)

    if not output:
        st.log("No LLDP neighbor output received from {} on port {}. (Good, if no TLVs are expected).".format(dut, peer_port))
        return True # If no output, then no TLVs are present, which is good.

    lines = output.splitlines()
    for tlv_data_expected_absent in tlv_definitions_to_check_for_absence:
        # Re-derive expected lldpcli format for this TLV, as tlv_definitions_source
        # does not store these. This ensures consistency with how they would appear.
        expected_oui_lldpcli = tlv_data_expected_absent.oui_value
        expected_subtype_lldpcli = tlv_data_expected_absent.subtype_value
        expected_oui_info_lldpcli = tlv_data_expected_absent.oui_info_value

        for line in lines:
            tlv_line = line.strip()
            if tlv_line.startswith("TLV:"):
                tlv_data_part = tlv_line.split("TLV:", 1)[1].strip()

                # Check if this TLV matches any of the ones we expect to be absent
                if (("OUI: {}".format(expected_oui_lldpcli) in tlv_data_part) and
                    ("SubType: {}".format(expected_subtype_lldpcli) in tlv_data_part) and
                    (expected_oui_info_lldpcli in tlv_data_part)):
                    st.log("ERROR: Found unexpected TLV '{}' on peer after cleanup: {}".format(tlv_data_expected_absent.tlv_name, tlv_line))
                    return False # Found a TLV that should be absent

    st.log("Successfully verified absence of all specified TLVs on peer.")
    return True # All specified TLVs are absent



def configure_and_verify_all_tlvs():
    """
    Helper function to configure all TLVs currently in data_glob.tlv_definitions
    and then verify them.

    Returns:
        bool: True if all TLVs are successfully configured and verified, False otherwise.
    """
    if (data_glob.single_lldp):
        original_tlv_definitions = list(data_glob.tlv_definitions) # Save original for safety, though not strictly needed here
        data_glob.tlv_definitions = [data_glob.tlv_definitions[0]]
        for tlv_data in data_glob.tlv_definitions: # Corrected from data_glob.tlv_definitions
           tlv_data.expected_oui_lldpcli = tlv_data.oui_value
           tlv_data.expected_subtype_lldpcli = tlv_data.subtype_value

    # --- Configuration Phase ---
    for tlv_data in data_glob.tlv_definitions:
        st.log("Configuring LLDP custom TLV '{}' on {}".format(tlv_data.tlv_name, data_glob.dut1))
        cmd_add_tlv = (
            "config lldp custom-tlv add {} "
            "oui {} "
            "subtype {} "
            "oui-info {}".format(tlv_data.tlv_name, tlv_data.oui_value, tlv_data.subtype_value, tlv_data.oui_info_value)
        )
        st.config(data_glob.dut1, cmd_add_tlv)

        st.log("Associating custom TLV '{}' with interface {} on {}".format(tlv_data.tlv_name, data_glob.dut1_port, data_glob.dut1))
        cmd_add_intf_tlv = "config interface lldp custom-tlv add {} {}".format(data_glob.dut1_port, tlv_data.tlv_name)
        st.config(data_glob.dut1, cmd_add_intf_tlv)

    st.wait(5) # Give LLDP time to send out updated packets with all TLVs

    # --- Verification Phase ---
    all_tlvs_verified = True
    for tlv_data in data_glob.tlv_definitions:
        st.log("Attempting to verify TLV: {}".format(tlv_data.tlv_name))
        if not verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, tlv_data):
            all_tlvs_verified = False
            st.log("Verification FAILED for TLV: {}".format(tlv_data.tlv_name))
            # Continue checking other TLVs for better debug info

    return all_tlvs_verified


def test_lldp_3_custom_tlv_verification(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of three custom LLDP TLVs on the peer device.
    This test uses the default three TLV definitions set in setup_teardown_basic.
    """
    st.log("Starting test_lldp_3_custom_tlv_verification")

    # No need to assign data_glob.tlv_definitions here, it's already set by setup_teardown_basic
    # and processed by lldp_func_hooks.

    if configure_and_verify_all_tlvs():
        st.report_pass("test_case_passed")
    else:
        st.report_fail("msg", "One or more custom TLVs were not found or did not match on peer device.")


def test_lldp_1_custom_tlv_verification(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of a single custom LLDP TLV on the peer device.
    This test uses the first TLV definition from the list defined in setup_teardown_basic.
    """
    st.log("Starting test_lldp_1_custom_tlv_verification")
    data_glob.single_lldp = True
    if configure_and_verify_all_tlvs():
        st.report_pass("test_case_passed")
    else:
        st.report_fail("msg", "The single custom TLV was not found or did not match on the peer device.")
    
def test_lldp_custom_tlv_verification_docker_restart(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of three custom LLDP TLVs on the peer device and restart the docker and verify.
    This test uses the default three TLV definitions set in setup_teardown_basic.
    """
    st.log("Starting test_lldp_custom_tlv_verification_docker_restart")

    if not configure_and_verify_all_tlvs():
        st.report_fail("msg", "Initial verification of one or more custom TLVs failed.")

    # --- Restart LLDP Docker ---
    st.log("--- Restarting LLDP docker on {} ---".format(data_glob.dut1))
    st.config(data_glob.dut1, "docker restart lldp", skip_error_check=False, timeout=60)
    st.wait(100) # Give LLDP time to restart and send out new BPDUs

    # --- Re-Verification after Restart ---
    st.log("--- Re-verifying custom TLVs after LLDP docker restart ---")
    for tlv_data in data_glob.tlv_definitions:
        st.log("Attempting to verify TLV: {}".format(tlv_data.tlv_name))
        if not verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, tlv_data):
            st.report_fail("msg", "Verification of one or more custom TLVs failed after LLDP docker restart.")
        else:
            st.report_pass("test_case_passed")

def test_lldp_custom_tlv_verification_with_link_up_down(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of three custom LLDP TLVs on the peer device and down the link and verify.
    Then up the link and verify  that all the TLVs are come up.
    This test uses the default three TLV definitions set in setup_teardown_basic.
    """
    st.log("Starting test_lldp_custom_tlv_verification_with_link_up_down")

    if not configure_and_verify_all_tlvs():
        st.report_fail("msg", "Initial verification of one or more custom TLVs failed.")

    st.log("Shutting down interface {} on {}".format(data_glob.dut1_port, data_glob.dut1))
    cmd_intf_down = "config interface shutdown {}".format(data_glob.dut1_port)
    st.config(data_glob.dut1, cmd_intf_down)
    st.wait(300) # Give some time for link status to propagate and LLDP to stop advertising

    # --- Verification after interface down ---
    st.log("Verifying absence of TLVs on peer after interface shutdown.")
    if verify_no_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, data_glob.tlv_definitions):
         st.log("Successfully verified absence of all TLVs on peer after interface shutdown.")
    else :
          st.report_fail("msg", "Failed to verify absence of one or more TLVs on peer after interface shutdown.")

    st.log("Bringing up interface {} on {}".format(data_glob.dut1_port, data_glob.dut1))
    cmd_intf_up = "config interface startup {}".format(data_glob.dut1_port)
    st.config(data_glob.dut1, cmd_intf_up)
    st.wait(30) # Give LLDP time to re-establish and send TLVs

    # --- Re-Verification after interface up ---
    st.log("Re-verifying custom TLVs after interface startup.")
    for tlv_data in data_glob.tlv_definitions:
        st.log("Attempting to verify TLV: {}".format(tlv_data.tlv_name))
        if not verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, tlv_data):
            st.report_fail("msg", "Verification of one or more custom TLVs failed after interface up")
        else:
            st.report_pass("test_case_passed")


def test_lldp_custom_tlv_verification_system_restart(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of three custom LLDP TLVs on the peer device and restart the system and verify.
    This test uses the default three TLV definitions set in setup_teardown_basic.
    """
    st.log("Starting test_lldp_custom_tlv_verification_system_restart")

    if not configure_and_verify_all_tlvs():
        st.report_fail("msg", "Initial verification of one or more custom TLVs failed.")

    # --- Restart Device ---
    st.log("--- Restarting device on {} ---".format(data_glob.dut1))
    st.log("Save the current config")
    reboot.config_save(data_glob.dut1)

    st.log("Initiate Fast reboot")
    reboot.dut_reboot(data_glob.dut1, method='fast')
    st.wait(300) # Give system time to reboot and LLDP to restart and send out new BPDUs

    # --- Re-Verification after Restart ---
    st.log("--- Re-verifying custom TLVs after system restart ---")
    if configure_and_verify_all_tlvs():
        st.report_pass("test_case_passed")
    else:
        st.report_fail("msg", "Verification of one or more custom TLVs failed after system restart.")


def test_lldp_single_tlv_modify_and_verify_update(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    1. Create one custom LLDP TLV.
    2. Assign this TLV to an interface on DUT1 (data_glob.dut1_port).
    3. Verify the initial TLV on the corresponding peer interface on DUT2 (data_glob.dut2_port).
    4. Modify the OUI-Info of the same custom TLV on DUT1.
    5. Verify that the peer device updates and receives the changed TLV on its interface.

    Note: The request mentioned "assign to couple of interfaces". Due to the constraint "wont change anything in the above testscript",
    and 'setup_teardown_basic' only providing a single interface pair (D1D3:1), this test will operate on that single pair.
    To test with multiple interfaces, 'setup_teardown_basic' would need to be extended to define additional ports
    (e.g., vars.D1D3P2, vars.D3D1P2) and the test logic would need to iterate over these.
    """
    st.log("Starting test_lldp_single_tlv_modify_and_verify_update")
    initial_tlv_data = data_glob.tlv_definitions[0]
    initial_tlv_data.expected_oui_lldpcli = initial_tlv_data.oui_value
    initial_tlv_data.expected_subtype_lldpcli = initial_tlv_data.subtype_value
    initial_tlv_data.expected_oui_info_lldpcli = initial_tlv_data.oui_info_value

    # Temporarily set data_glob.tlv_definitions for cleanup to only include this TLV.
    # This ensures that lldp_func_hooks cleans up only what this specific test creates.
    original_data_glob_tlv_definitions = data_glob.tlv_definitions
    data_glob.tlv_definitions = [initial_tlv_data]

    # --- Step 1 & 2: Create one TLV and assign to interface ---
    st.log("Configuring initial custom TLV '{}' on {}".format(initial_tlv_data.tlv_name, data_glob.dut1))
    cmd_add_tlv = (
        "config lldp custom-tlv add {} "
        "oui {} "
        "subtype {} "
        "oui-info {}".format(initial_tlv_data.tlv_name, initial_tlv_data.oui_value,
                             initial_tlv_data.subtype_value, initial_tlv_data.oui_info_value)
    )
    st.config(data_glob.dut1, cmd_add_tlv)

    st.log("Associating custom TLV '{}' with interface {} on {}".format(initial_tlv_data.tlv_name, data_glob.dut1_port, data_glob.dut1))
    cmd_add_intf_tlv = "config interface lldp custom-tlv add {} {}".format(data_glob.dut1_port, initial_tlv_data.tlv_name)
    st.config(data_glob.dut1, cmd_add_intf_tlv)
    cmd_add_intf_tlv_2 = "config interface lldp custom-tlv add {} {}".format(data_glob.dut1_port_2, initial_tlv_data.tlv_name)
    st.config(data_glob.dut1, cmd_add_intf_tlv_2)

    st.wait(5) # Give LLDP time to send out updated packets

    # --- Step 3: Verify initial TLV on peer interface ---
    st.log("Verifying initial custom TLV on peer interface {}.".format(data_glob.dut2_port))
    if not verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, initial_tlv_data):
        st.report_fail("msg", "Initial custom TLV was not found or did not match on peer interface {}.".format(data_glob.dut2_port))

    # --- Step 4: Modify the OUI-Info of the same custom TLV ---
    modified_oui_info_value = "FF,EE,DD,CC,BB,AA,01,02" # New OUI-Info value
    st.log("Modifying OUI-Info for custom TLV '{}' to '{}' on {}".format(initial_tlv_data.tlv_name, modified_oui_info_value, data_glob.dut1))

    # The 'add' command for an existing TLV name is expected to update its properties.
    cmd_modify_tlv = (   
        "config lldp custom-tlv add {} "
        "oui {} "
        "subtype {} "
        "oui-info {}".format(initial_tlv_data.tlv_name, initial_tlv_data.oui_value,
                             initial_tlv_data.subtype_value, modified_oui_info_value)
    )
    st.config(data_glob.dut1, cmd_modify_tlv)

    # Update the tlv_data object with the new expected value for verification
    initial_tlv_data.oui_info_value = modified_oui_info_value
    initial_tlv_data.expected_oui_info_lldpcli = modified_oui_info_value

    st.wait(10) # Give LLDP time to send out updated packets with the modified TLV

    # --- Step 5: Verify that the peer device updates and receives the changed TLV ---
    st.log("Verifying modified custom TLV on peer interface {}.".format(data_glob.dut2_port))
    if verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port, initial_tlv_data) and verify_lldp_custom_tlv_on_peer(data_glob.dut2, data_glob.dut2_port_2, initial_tlv_data):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("msg", "Modified custom TLV was not found or did not match on peer interface {} after update.".format(data_glob.dut2_port))
     
    cmd_remove_intf_tlv = "config interface lldp custom-tlv remove {} {}".format(data_glob.dut1_port_2, initial_tlv_data.tlv_name)
    st.config(data_glob.dut1, cmd_remove_intf_tlv, skip_error_check=True, timeout=10)

def test_lldp_tlv_with_breakout(setup_teardown_basic, lldp_func_hooks):
    """
    Test Description:
    Verify configuration and reception of three custom LLDP TLVs on the peer device.
    This test uses the default three TLV definitions set in setup_teardown_basic.
    """
    st.log("Starting test_lldp_tlv_with_breakout")

    Breakout_dut1 = "sudo config interface breakout {} 2x100G -yfl".format(data_glob.dut1_port)
    st.config(data_glob.dut1, Breakout_dut1, skip_error_check=True, timeout=10)
    Breakout_dut2 = "sudo config interface breakout {} 2x100G -yfl".format(data_glob.dut2_port)
    st.config(data_glob.dut2, Breakout_dut2, skip_error_check=True, timeout=10)
     
    st.wait(90)   
    new_intfs_dut1 = [vars.D1D3P1 + '_' + str(index) for index in range(1,3)] 
    new_intfs_dut2 = [vars.D3D1P1 + '_' + str(index) for index in range(1,3)]
 
    port_start_dut1 = "sudo config interface startup {}".format(new_intfs_dut1[0])
    port_start_dut2 = "sudo config interface startup {}".format(new_intfs_dut2[0])
    st.config(data_glob.dut1, port_start_dut1, skip_error_check=True, timeout=10)
    st.config(data_glob.dut2, port_start_dut2, skip_error_check=True, timeout=10)
    
    data_glob.dut1_port = new_intfs_dut1[0]
    data_glob.dut2_port = new_intfs_dut2[0]
    data_glob.single_lldp = True
    if configure_and_verify_all_tlvs():
        st.report_pass("test_case_passed")
    else:
        st.report_fail("msg", "One or more custom TLVs were not found or did not match on peer device.")
