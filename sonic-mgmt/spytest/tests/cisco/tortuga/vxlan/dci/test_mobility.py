import pytest
from spytest import st
from dci.sonic_verifiers import verify_dci_remotevtep, verify_dci_remotemac
from dci.ixia import start_stop

def test_intra_dc_mobility(setup):
    nodes = setup["nodes"]
    session_assistant = setup["session_assistant"]
    
    # STEP 1: Verify VTEP tunnels are established (infrastructure prerequisite)
    st.log("=== Verifying remote VTEP tunnels are UP ===")
    verify_dci_remotevtep(nodes, "test_intra_dc_mobility")
    
    # STEP 2: Start all device groups at once (Leaf3, Leaf1, Leaf2)
    st.log("=== Starting all Ixia device groups (Leaf3-Hosts, Leaf1-Hosts, Leaf2-Hosts) ===")
    if not start_stop.start_device_group(session_assistant, "Leaf3-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility start Leaf3-Hosts")
    if not start_stop.start_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility start Leaf1-Hosts")
    
    # STEP 3: Wait for all device groups to come up and protocols to stabilize
    st.wait(30, "waiting for all device groups to come up and MACs to be learned")
    
    # STEP 4: Verify MAC state BEFORE intra-DC mobility (MACs from Leaf1 and Leaf3)
    st.log("=== Verifying MAC learning BEFORE intra-DC mobility ===")
    verify_dci_remotemac(nodes, "test_intra_dc_mobility", mac_data_type="before_mobility_intra_dc")
    
    # STEP 5: Trigger intra-DC mobility - shut down Leaf1-Hosts (disconnect from original leaf)
    st.log("=== Shutting down Leaf1-Hosts to simulate host disconnect from original leaf ===")
    if not start_stop.stop_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility stop Leaf1-Hosts")
    st.wait(10, "waiting for Leaf1-Hosts to shut down")
    
    # STEP 6: Activate Leaf2-Hosts (reconnect on different leaf in same DC - intra-DC mobility)
    st.log("=== Activating Leaf2-Hosts to simulate host reconnect on different leaf (INTRA-DC mobility within DC1) ===")
    if not start_stop.start_device_group(session_assistant, "Leaf2-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility activate Leaf2-Hosts")
    
    # STEP 7: Wait for intra-DC MAC mobility to complete and protocols to settle
    st.wait(60, "waiting for intra-DC MAC mobility (Leaf1→Leaf2 within DC1) to complete and protocols to stabilize")
    
    # STEP 8: Verify MAC learning AFTER intra-DC mobility (MACs should appear on Leaf2 VTEP)
    st.log("=== Verifying MAC learning AFTER intra-DC mobility (Leaf1→Leaf2) ===")
    verify_dci_remotemac(nodes, "test_intra_dc_mobility", mac_data_type="after_mobility_intra_dc")
    
    # STEP 9: Cleanup - Shut down Leaf2-Hosts (mobility port)
    st.log("=== Cleanup: Shutting down Leaf2-Hosts (mobility port) ===")
    if not start_stop.stop_device_group(session_assistant, "Leaf2-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility cleanup - stop Leaf2-Hosts")
    
    # STEP 10: Cleanup - Restart Leaf1-Hosts to reset topology to original state
    st.log("=== Cleanup: Restarting Leaf1-Hosts to reset topology ===")
    if not start_stop.start_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_intra_dc_mobility cleanup - restart Leaf1-Hosts")
    
    # STEP 11: Wait for MACs to relearn after cleanup
    st.wait(30, "waiting for MACs to relearn after topology reset")
    
    # STEP 12: Verify MAC state after cleanup (should match BEFORE mobility state)
    st.log("=== Verifying MAC learning after cleanup (topology reset validation) ===")
    verify_dci_remotemac(nodes, "test_intra_dc_mobility", mac_data_type="before_mobility_intra_dc")
    
    st.log("=== Test completed successfully - topology validated and reset to original state ===")
    st.report_pass("test_case_passed", "test_intra_dc_mobility passed")


def test_inter_dc_mobility(setup):
    nodes = setup["nodes"]
    session_assistant = setup["session_assistant"]
    
    # STEP 1: Verify VTEP tunnels are established (infrastructure prerequisite)
    st.log("=== Verifying remote VTEP tunnels are UP ===")
    verify_dci_remotevtep(nodes, "test_inter_dc_mobility")
    
    # STEP 2: Start all device groups at once (Leaf3, Leaf1, Leaf4)
    st.log("=== Starting all Ixia device groups (Leaf3-Hosts, Leaf1-Hosts) ===")
    if not start_stop.start_device_group(session_assistant, "Leaf3-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility start Leaf3-Hosts")
    if not start_stop.start_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility start Leaf1-Hosts")
    
    # STEP 3: Wait for all device groups to come up and protocols to stabilize
    st.wait(30, "waiting for all device groups to come up and MACs to be learned")
    
    # STEP 4: Verify MAC state BEFORE inter-DC mobility (MACs from Leaf1 and Leaf3)
    st.log("=== Verifying MAC learning BEFORE inter-DC mobility ===")
    verify_dci_remotemac(nodes, "test_inter_dc_mobility", mac_data_type="before_mobility_inter_dc")
    
    # STEP 5: Trigger inter-DC mobility - shut down Leaf1-Hosts (disconnect from DC1)
    st.log("=== Shutting down Leaf1-Hosts to simulate host disconnect from DC1 ===")
    if not start_stop.stop_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility stop Leaf1-Hosts")
    st.wait(10, "waiting for Leaf1-Hosts to shut down")
    
    # STEP 6: Activate Leaf4-Hosts (reconnect in DC3 - inter-DC mobility)
    st.log("=== Activating Leaf4-Hosts to simulate host reconnect in DC3 (INTER-DC mobility) ===")
    if not start_stop.start_device_group(session_assistant, "Leaf4-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility activate Leaf4-Hosts")
    
    # STEP 7: Wait for inter-DC MAC mobility to complete and protocols to settle
    st.wait(60, "waiting for inter-DC MAC mobility (DC1→DC3) to complete and protocols to stabilize")
    
    # STEP 8: Verify MAC learning AFTER inter-DC mobility (MACs should have moved from DC1 to DC3)
    st.log("=== Verifying MAC learning AFTER inter-DC mobility (Leaf1→Leaf4) ===")
    verify_dci_remotemac(nodes, "test_inter_dc_mobility", mac_data_type="after_mobility_inter_dc")
    
    # STEP 9: Cleanup - Shut down Leaf4-Hosts (mobility port)
    st.log("=== Cleanup: Shutting down Leaf4-Hosts (mobility port) ===")
    if not start_stop.stop_device_group(session_assistant, "Leaf4-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility cleanup - stop Leaf4-Hosts")
    
    # STEP 10: Cleanup - Restart Leaf1-Hosts to reset topology to original state
    st.log("=== Cleanup: Restarting Leaf1-Hosts to reset topology ===")
    if not start_stop.start_device_group(session_assistant, "Leaf1-Hosts"):
        st.report_fail("test_case_failed", "test_inter_dc_mobility cleanup - restart Leaf1-Hosts")
    
    # STEP 11: Wait for MACs to relearn after cleanup
    st.wait(30, "waiting for MACs to relearn after topology reset")
    
    # STEP 12: Verify MAC state after cleanup (should match BEFORE mobility state)
    st.log("=== Verifying MAC learning after cleanup (topology reset validation) ===")
    verify_dci_remotemac(nodes, "test_inter_dc_mobility", mac_data_type="before_mobility_inter_dc")
    
    st.log("=== Test completed successfully - topology validated and reset to original state ===")
    st.report_pass("test_case_passed", "test_inter_dc_mobility passed")

