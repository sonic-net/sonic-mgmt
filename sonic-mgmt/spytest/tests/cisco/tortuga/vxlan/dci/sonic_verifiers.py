from spytest import st
from typing import List, Tuple
from dci.expected_results_sonic import remote_vtep_test_data, remote_mac_test_data


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
        st.log(f"Searching for Source IP: {source_ip}, Destination IP: {destination_ip}, Expected Status: {expected_status}")
        
        # Search through parsed entries from TextFSM template
        for entry in parsed_output:
            # TextFSM template uses SRC_VTEP, DST_VTEP, and TUN_STATUS fields
            entry_source = entry.get('src_vtep', '').strip()
            entry_destination = entry.get('dst_vtep', '').strip()
            entry_status = entry.get('tun_status', '').strip()
            
            # Check if this entry matches our target source and destination IPs
            if entry_source == source_ip and entry_destination == destination_ip:
                # Also check if the tunnel status matches expected status
                if entry_status == expected_status:
                    st.log(f"Found VTEP entry: Source {source_ip} -> Destination {destination_ip}, Status: {entry_status}")
                    vtep_found = True
                    break
                else:
                    st.log(f"Found VTEP entry but status mismatch: Source {source_ip} -> Destination {destination_ip}")
                    st.log(f"Expected status: {expected_status}, Actual status: {entry_status}")
        
        if not vtep_found:
            st.log(f"VTEP entry not found or status incorrect: Source {source_ip} -> Destination {destination_ip} (status: {expected_status}) on DUT {dut}")
            st.log(f"Available entries:")
            for i, entry in enumerate(parsed_output[:5]):  # Show first 5 entries for debugging
                src = entry.get('src_vtep', 'N/A')
                dst = entry.get('dst_vtep', 'N/A')
                status = entry.get('tun_status', 'N/A')
                st.log(f"Entry {i}: Source={src}, Destination={dst}, Status={status}")
            if len(parsed_output) > 5:
                st.log(f"... and {len(parsed_output) - 5} more entries")
            return False
    
    st.log(f"All {len(vtep_data)} remote VTEP entries verified successfully on DUT {dut}")
    return True

    
def verify_remotemac(dut, mac_vtep_vni_list: List[Tuple[str, str, str]], **kwargs) -> bool:
    """
    Verify that MAC addresses are learned with correct VTEP and VNI associations.
    
    Args:
        dut (WorkArea): Device under test
        mac_vtep_vni_list (List[Tuple[str, str, str]]): List of (MAC, VTEP, VNI) tuples to verify
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        bool: True if all MAC/VTEP/VNI combinations are found, False otherwise
        
    Example:
        verify_remotemac(dut, [
            ("00:00:00:00:00:01", "fd27::233:d0c6:fed5", "5010"),
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
    
    for mac, expected_vtep, expected_vni in mac_vtep_vni_list:
        mac_found = False
        st.log(f"Searching for MAC: {mac}, VTEP: {expected_vtep}, VNI: {expected_vni}")
        
        # Search through parsed entries from TextFSM template
        for entry in parsed_output:
            # TextFSM template should parse fields like vlan, mac, remotetunnel, vni, type
            entry_mac = entry.get('mac', '').strip()
            entry_vni = entry.get('vni', '').strip()
            entry_vtep = entry.get('remotetunnel', '').strip()
            
            # Check if this entry matches our target MAC and VNI
            if entry_mac == mac and entry_vni == expected_vni:
                # Check if the VTEP matches - handle multiple VTEPs separated by newlines or spaces
                vtep_list = entry_vtep.replace('\n', ' ').split()
                if expected_vtep in vtep_list or expected_vtep in entry_vtep:
                    st.log(f"✓ Found MAC {mac} with VTEP {expected_vtep} and VNI {expected_vni}")
                    mac_found = True
                    break
        
        if not mac_found:
            st.log(f"MAC {mac} with VTEP {expected_vtep} and VNI {expected_vni} not found on DUT {dut}")
            st.log(f"Available entries:")
            for i, entry in enumerate(parsed_output[:5]):  # Show first 5 entries for debugging
                st.log(f"  Entry {i}: MAC={entry.get('mac', 'N/A')}, VTEP={entry.get('remotetunnel', 'N/A')}, VNI={entry.get('vni', 'N/A')}")
            if len(parsed_output) > 5:
                st.log(f"  ... and {len(parsed_output) - 5} more entries")
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
        if not verify_remotevtep(nodes[nodes_name], remote_vtep_test_data[nodes_name], skip_tmpl=False, skip_error_check=False):
            st.report_fail("test_case_failed", f"{test_name} verify_remotevtep failed on {nodes_name}")


def verify_dci_remotemac(nodes, test_name):
    """
    Verify remote MAC learning on all DCI gateway nodes.
    
    Args:
        nodes: Dictionary of node objects  
        test_name: Name of the test for error reporting
    """
    for nodes_name in ["dc1gw1", "dc1gw2", "dc2gw1", "dc3gw1"]:
        if not verify_remotemac(nodes[nodes_name], remote_mac_test_data[nodes_name], skip_tmpl=False, skip_error_check=False):
            st.report_fail("test_case_failed", f"{test_name} verify_remotemac failed on {nodes_name}")