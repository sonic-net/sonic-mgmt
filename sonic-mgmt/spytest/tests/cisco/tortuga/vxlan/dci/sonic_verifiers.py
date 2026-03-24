from spytest import st
from typing import List, Tuple, Union, Dict

# For MAC verification: VTEP can be a single value or a list of allowed VTEPs (either/both)
MacVtepVniEntry = Tuple[str, Union[str, List[str]], str]
from dci.expected_results_sonic import (
    remote_vtep_test_data,
    remote_mac_test_data,
    remote_mac_before_mobility_intra_dc_test_data,
    remote_mac_after_mobility_intra_dc_test_data,
    remote_mac_before_mobility_inter_dc_test_data,
    remote_mac_after_mobility_inter_dc_test_data,
)
from retry import retry


@retry(tries=5, delay=10)
def verify_remotevtep(dut, vtep_data: List[Tuple[str, str]], expected_status: str = "oper_up", **kwargs) -> bool:
    """
    Verify that specified remote VTEPs are present in the VXLAN remote VTEP table with correct tunnel status.

    Args:
        dut (WorkArea): Device under test
        vtep_data (List[Tuple[str, str]]): List of (source_ip, destination_ip) tuples to verify
        expected_status (str): Expected tunnel status ("oper_up" or "oper_down"), defaults to "oper_up"
        **kwargs: Additional arguments to pass to the show command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        bool: True if all source/destination VTEP pairs are found with correct status, False otherwise

    Example:
        verify_remotevtep(dut, [
            ("fd27::233:d0c6:feda", "fd27::233:d0c6:fed5"),
            ("101.101.101.101", "102.102.102.102"),
            ("101.101.101.101", "103.103.103.103")
        ], expected_status="oper_up")
    """
    command = "show vxlan remotevtep"
    parsed_output = st.show(dut, command, **kwargs)
    if not parsed_output:
        st.log(f"No parsed output from command '{command}' on DUT {dut}")
        return False

    st.log(f"Verifying {len(vtep_data)} remote VTEP entries on DUT {dut}")
    st.log(f"Parsed output contains {len(parsed_output)} entries")

    for source_ip, destination_ip in vtep_data:
        vtep_found = False
        st.log(
            f"Searching for Source IP: {source_ip}, Destination IP: {destination_ip}, Expected Status: {expected_status}"
        )

        # Search through parsed entries from TextFSM template
        for entry in parsed_output:
            # TextFSM template uses SRC_VTEP, DST_VTEP, and TUN_STATUS fields
            entry_source = entry.get("src_vtep", "").strip()
            entry_destination = entry.get("dst_vtep", "").strip()
            entry_status = entry.get("tun_status", "").strip()

            # Check if this entry matches our target source and destination IPs
            if entry_source == source_ip and entry_destination == destination_ip:
                # Also check if the tunnel status matches expected status
                if entry_status == expected_status:
                    st.log(
                        f"Found VTEP entry: Source {source_ip} -> Destination {destination_ip}, Status: {entry_status}"
                    )
                    vtep_found = True
                    break
                else:
                    st.log(f"Found VTEP entry but status mismatch: Source {source_ip} -> Destination {destination_ip}")
                    st.log(f"Expected status: {expected_status}, Actual status: {entry_status}")

        if not vtep_found:
            st.log(
                f"VTEP entry not found or status incorrect: Source {source_ip} -> Destination {destination_ip} (status: {expected_status}) on DUT {dut}"
            )
            st.log(f"Available entries (showing all {len(parsed_output)} entries):")
            for i, entry in enumerate(parsed_output):
                src = entry.get("src_vtep", "N/A")
                dst = entry.get("dst_vtep", "N/A")
                status = entry.get("tun_status", "N/A")
                st.log(f"Entry {i}: Source={src}, Destination={dst}, Status={status}")
            return False

    total_entries = len(parsed_output)
    if total_entries != len(vtep_data):
        st.log(f"Total entries {total_entries} does not match expected {len(vtep_data)} on DUT {dut}, parsed output: {parsed_output}")
        return False
    st.log(f"All {len(vtep_data)} remote VTEP entries verified successfully on DUT {dut}")
    return True


@retry(tries=5, delay=10)
def verify_remotemac(dut, mac_vtep_vni_list: List[MacVtepVniEntry], **kwargs) -> bool:
    """
    Verify that MAC addresses are learned with correct VTEP and VNI associations.

    Args:
        dut (WorkArea): Device under test
        mac_vtep_vni_list: List of (MAC, VTEP_or_allowed_VTEPs, VNI) tuples.
                          VTEP can be a single string or a list of allowed VTEPs;
                          a list means accept the MAC+VNI if the device has any of those VTEPs.
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        bool: True if all MAC/VTEP/VNI combinations are found, False otherwise

    Example:
        verify_remotemac(dut, [
            ("00:00:00:00:00:01", "fd27::233:d0c6:fed5", "5010"),
            ("00:00:00:00:00:02", ["fd27::233:d0c6:fed5", "fd27::233:d0c6:fed6"], "5010"),  # either VTEP
            ("00:00:00:00:00:03", "102.102.102.102", "5011")
        ])
    """
    command = "show vxlan remotemac all"
    parsed_output = st.show(dut, command, **kwargs)
    if not parsed_output:
        st.log(f"No parsed output from command '{command}' on DUT {dut}")
        return False

    st.log(f"Verifying {len(mac_vtep_vni_list)} MAC/VTEP/VNI combinations on DUT {dut}")
    st.log(f"Parsed output contains {len(parsed_output)} entries")

    # Debug: Show raw first entry to understand structure
    if parsed_output:
        st.log(f"DEBUG: First entry raw data: {parsed_output[0]}")
        st.log(f"DEBUG: First entry keys: {list(parsed_output[0].keys())}")

    for mac_entry in mac_vtep_vni_list:
        mac = mac_entry[0]
        expected_vtep_or_list = mac_entry[1]
        expected_vni = mac_entry[2]
        allowed_vteps = (
            [expected_vtep_or_list]
            if isinstance(expected_vtep_or_list, str)
            else list(expected_vtep_or_list)
        )

        mac_found = False
        st.log(f"Searching for MAC: {mac}, VTEP: {allowed_vteps}, VNI: {expected_vni}")

        # Search through parsed entries from TextFSM template
        for entry in parsed_output:
            # TextFSM template uses fields: vlan, remote_mac, remote_vtep, vni
            entry_mac = entry.get("remote_mac", "").strip()
            entry_vni = entry.get("vni", "").strip()
            entry_vtep = entry.get("remote_vtep", "").strip()

            # Check if this entry matches our target MAC and VNI
            if entry_mac == mac and entry_vni == expected_vni:
                # Handle multiple VTEPs in entry separated by newlines or spaces
                entry_vtep_list = entry_vtep.replace("\n", " ").split()

                # Check if any allowed VTEP matches the entry
                for vtep in allowed_vteps:
                    if vtep in entry_vtep_list or vtep in entry_vtep:
                        st.log(f"✓ Found MAC {mac} with VTEP {vtep} and VNI {expected_vni}")
                        mac_found = True
                        break
                if mac_found:
                    break

        if not mac_found:
            st.log(f"MAC {mac} with VTEP {allowed_vteps} and VNI {expected_vni} not found on DUT {dut}")
            st.log(f"Available entries (showing all {len(parsed_output)} entries):")
            for i, entry in enumerate(parsed_output):
                st.log(
                    f"  Entry {i}: MAC={entry.get('remote_mac', 'N/A')}, VTEP={entry.get('remote_vtep', 'N/A')}, VNI={entry.get('vni', 'N/A')}"
                )
                st.log(f"  Entry {i} RAW: {entry}")
            return False

    st.log(f"All {len(mac_vtep_vni_list)} MAC/VTEP/VNI combinations verified successfully on DUT {dut}")
    return True


def verify_dci_remotevtep(nodes, test_name):
    """
    Verify remote VTEP configuration on all DCI gateway nodes.

    Args:
        nodes: Dictionary of node objects
        test_name: Name of the test for error reporting
    """
    for nodes_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if not verify_remotevtep(
            nodes[nodes_name], remote_vtep_test_data[nodes_name], skip_tmpl=False, skip_error_check=False
        ):
            st.report_fail("test_case_failed", f"{test_name} verify_remotevtep failed on {nodes_name}")


def verify_dci_remotemac(nodes, test_name, mac_data_type="default"):
    """
    Verify remote MAC learning on all DCI gateway nodes.

    Args:
        nodes: Dictionary of node objects
        test_name: Name of the test for error reporting
        mac_data_type: Type of MAC test data to use. Options:
            - "default": Use remote_mac_test_data (default initial state)
            - "before_mobility_intra_dc": Use data before intra-DC mobility
            - "after_mobility_intra_dc": Use data after intra-DC mobility
            - "before_mobility_inter_dc": Use data before inter-DC mobility
            - "after_mobility_inter_dc": Use data after inter-DC mobility
            - dict: Directly pass a custom dictionary of MAC test data
            
    Example:
        # Use default data
        verify_dci_remotemac(nodes, "test_name")
        
        # Use after intra-DC mobility data
        verify_dci_remotemac(nodes, "test_name", "after_mobility_intra_dc")
        
        # Use custom data
        custom_data = {"dc1gw1": [("00:00:00:00:10:01", "fd27::233:d0c6:fed5", "5010")]}
        verify_dci_remotemac(nodes, "test_name", custom_data)
    """
    # Map string keys to actual data dictionaries
    mac_data_map = {
        "default": remote_mac_test_data,
        "before_mobility_intra_dc": remote_mac_before_mobility_intra_dc_test_data,
        "after_mobility_intra_dc": remote_mac_after_mobility_intra_dc_test_data,
        "before_mobility_inter_dc": remote_mac_before_mobility_inter_dc_test_data,
        "after_mobility_inter_dc": remote_mac_after_mobility_inter_dc_test_data,
    }
    
    # Determine which test data to use
    if isinstance(mac_data_type, dict):
        # User passed custom dictionary directly
        selected_mac_data = mac_data_type
        st.log(f"Using custom MAC test data with {len(mac_data_type)} node entries")
    elif mac_data_type in mac_data_map:
        # User passed a valid string key
        selected_mac_data = mac_data_map[mac_data_type]
        st.log(f"Using MAC test data type: {mac_data_type}")
    else:
        # Invalid key, log warning and use default
        st.warn(f"Invalid mac_data_type '{mac_data_type}', falling back to 'default'")
        selected_mac_data = remote_mac_test_data
    
    # Verify MAC learning on all gateway nodes
    for nodes_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if nodes_name not in selected_mac_data:
            st.warn(f"No MAC test data found for {nodes_name} in selected data type")
            continue
            
        st.log(f"Verifying {len(selected_mac_data[nodes_name])} MAC entries on {nodes_name}")
        if not verify_remotemac(
            nodes[nodes_name], selected_mac_data[nodes_name], skip_tmpl=False, skip_error_check=False
        ):
            st.report_fail("test_case_failed", f"{test_name} verify_remotemac failed on {nodes_name}")
