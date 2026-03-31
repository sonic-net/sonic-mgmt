#!/usr/bin/env python3
"""
Port Error Status Parser and Grouper

This script parses SONiC port error status output and groups ports
based on their error status to identify healthy and problematic interfaces.

Usage:
    python port_error_parser.py <input_file>
    or
    cat port_error_output.txt | python port_error_parser.py
"""


import re
import sys
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from datetime import datetime
from spytest.dicts import SpyTestDict
from collections import defaultdict, Counter
from apis.common.sonic_hooks import SonicHooks
from typing import List, Dict, Tuple, Optional
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def xcvr_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** SENSOR DATA *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def parse_port_error_status(input_text: str) -> List[Dict[str, str]]:
    """
    Parse port error status output into structured data
    
    Args:
        input_text (str): Raw port error status output
        
    Returns:
        List[Dict]: Parsed port error data
    """
    port_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Port' in line and 'Error Status' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find port error status table headers")
        return []
    
    # Parse port error data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line, 1)  # Split into max 2 parts
        
        if len(parts) >= 2:
            port = parts[0]
            error_status = parts[1]
            
            port_data.append({
                'port': port,
                'error_status': error_status.strip(),
                'port_number': extract_port_number(port)
            })
    
    return port_data

def extract_port_number(port_name: str) -> int:
    """
    Extract numeric part from port name for sorting
    
    Args:
        port_name (str): Port name like "Ethernet0", "Ethernet104"
        
    Returns:
        int: Numeric part of port name
    """
    try:
        # Extract number from port name
        match = re.search(r'(\d+)$', port_name)
        if match:
            return int(match.group(1))
        return 0
    except (ValueError, AttributeError):
        return 0

def group_ports_by_status(port_data: List[Dict[str, str]]) -> Dict[str, any]:
    """
    Group ports by their error status and provide analysis
    
    Args:
        port_data (List[Dict]): Parsed port error data
        
    Returns:
        Dict: Grouped port analysis results
    """
    results = {
        'overall_valid': True,
        'total_ports': 0,
        'status_groups': defaultdict(list),
        'status_summary': {},
        'port_ranges': {},
        'health_analysis': {}
    }
    
    # Group ports by error status
    for port in port_data:
        port_name = port['port']
        error_status = port['error_status']
        port_number = port['port_number']
        
        results['total_ports'] += 1
        results['status_groups'][error_status].append({
            'port': port_name,
            'port_number': port_number
        })
    
    # Sort ports within each group by port number
    for status in results['status_groups']:
        results['status_groups'][status].sort(key=lambda x: x['port_number'])
    
    # Create status summary
    status_counter = Counter(port['error_status'] for port in port_data)
    results['status_summary'] = dict(status_counter)
    
    # Analyze port ranges for each status
    for status, ports in results['status_groups'].items():
        port_numbers = [p['port_number'] for p in ports]
        if port_numbers:
            results['port_ranges'][status] = {
                'min_port': min(port_numbers),
                'max_port': max(port_numbers),
                'count': len(port_numbers),
                'percentage': (len(port_numbers) / results['total_ports'] * 100) if results['total_ports'] > 0 else 0
            }
    
    # Health analysis
    ok_ports = len(results['status_groups'].get('OK', []))
    error_ports = results['total_ports'] - ok_ports
    
    results['health_analysis'] = {
        'healthy_ports': ok_ports,
        'error_ports': error_ports,
        'health_percentage': (ok_ports / results['total_ports'] * 100) if results['total_ports'] > 0 else 0,
        'overall_health': 'HEALTHY' if error_ports == 0 else 'ERRORS_DETECTED'
    }
    results['overall_valid'] = True if error_ports == 0 else False
    
    return results

def print_port_error_analysis(results: Dict[str, any], show_details: bool = True):
    """
    Print formatted port error analysis results
    
    Args:
        results (Dict): Analysis results from group_ports_by_status
        show_details (bool): Whether to show detailed port lists
    """
    print("=" * 100)
    print("PORT ERROR STATUS ANALYSIS")
    print("=" * 100)
    
    health = results['health_analysis']
    print(f"Total Ports: {results['total_ports']}")
    print(f"Healthy Ports (OK): {health['healthy_ports']} ({health['health_percentage']:.1f}%)")
    print(f"Ports with Errors: {health['error_ports']}")
    print(f"Overall Health Status: {health['overall_health']}")
    print("-" * 100)
    
    # Status summary
    print("ERROR STATUS SUMMARY:")
    for status, count in results['status_summary'].items():
        percentage = (count / results['total_ports'] * 100) if results['total_ports'] > 0 else 0
        port_range = results['port_ranges'].get(status, {})
        min_port = port_range.get('min_port', 'N/A')
        max_port = port_range.get('max_port', 'N/A')
        
        print(f"  {status}: {count} ports ({percentage:.1f}%) - Range: Ethernet{min_port} to Ethernet{max_port}")
    print()
    
    if show_details:
        # Show detailed port groupings
        for status, ports in results['status_groups'].items():
            print(f"{status} PORTS ({len(ports)} ports):")
            print("-" * 50)
            
            # Group consecutive ports for better display
            port_ranges = group_consecutive_ports(ports)
            for port_range in port_ranges:
                print(f"  {port_range}")
            print()
    
    # Health status messages
    if health['error_ports'] == 0:
        print("✓ All ports are in OK status - no errors detected")
    else:
        print(f"⚠ {health['error_ports']} ports have error conditions")
        
        # Show non-OK statuses
        for status, ports in results['status_groups'].items():
            if status != 'OK' and ports:
                print(f"❌ {status}: {len(ports)} ports")

def group_consecutive_ports(ports: List[Dict[str, any]]) -> List[str]:
    """
    Group consecutive port numbers into ranges for better display
    
    Args:
        ports (List[Dict]): List of port dictionaries with port numbers
        
    Returns:
        List[str]: List of port range strings
    """
    if not ports:
        return []
    
    # Sort by port number
    sorted_ports = sorted(ports, key=lambda x: x['port_number'])
    ranges = []
    current_range_start = sorted_ports[0]['port_number']
    current_range_end = sorted_ports[0]['port_number']
    
    for i in range(1, len(sorted_ports)):
        port_num = sorted_ports[i]['port_number']
        
        # Check if consecutive
        if port_num == current_range_end + 8:  # Ethernet ports usually increment by 8
            current_range_end = port_num
        else:
            # End current range and start new one
            if current_range_start == current_range_end:
                ranges.append(f"Ethernet{current_range_start}")
            else:
                ranges.append(f"Ethernet{current_range_start}-Ethernet{current_range_end}")
            
            current_range_start = port_num
            current_range_end = port_num
    
    # Add the last range
    if current_range_start == current_range_end:
        ranges.append(f"Ethernet{current_range_start}")
    else:
        ranges.append(f"Ethernet{current_range_start}-Ethernet{current_range_end}")
    
    return ranges

def validate_xcvr_status(port_output):
    """
    Spytest integration function for port error status validation
    
    Args:
        output: Xcvr Error Status
        
    Returns:
        Dict: Validation results
    """
    try:
        # Parse and analyze port error status data
        port_data = parse_port_error_status(port_output)
        
        if not port_data:
            st.error("Failed to parse port error status data")
            return {"success": False, "error": "Failed to parse port error status data"}
        
        # Perform analysis
        results = group_ports_by_status(port_data)
        
        # Log results
        st.log(f"Port Error Status Analysis Results:")
        st.log(f"  Total Ports: {results['total_ports']}")
        st.log(f"  Healthy Ports: {results['health_analysis']['healthy_ports']}")
        st.log(f"  Error Ports: {results['health_analysis']['error_ports']}")
        st.log(f"  Overall Health: {results['health_analysis']['overall_health']}")
        
        # Log status summary
        for status, count in results['status_summary'].items():
            percentage = (count / results['total_ports'] * 100) if results['total_ports'] > 0 else 0
            st.log(f"  {status}: {count} ports ({percentage:.1f}%)")
        
        # Log error ports if any
        if results['health_analysis']['error_ports'] > 0:
            st.error(f"Ports with errors detected ({results['health_analysis']['error_ports']}):")
            for status, ports in results['status_groups'].items():
                if status != 'OK' and ports:
                    port_list = [p['port'] for p in ports]
                    st.error(f"  {status}: {', '.join(port_list)}")
        
        if results['health_analysis']['error_ports'] == 0:
            st.log("✓ All ports have OK error status")
        
        return results
        
    except Exception as e:
        if 'st' in locals():
            st.error(f"Port error status validation error: {e}")
        return results


def check_xcvr_state(CfgDataG, type):
    '''
    '''
    match type:
        case "error_status":
            cmd = "show interface transceiver error-status"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get xcvr error-status from device")
                return False
            result = validate_xcvr_status(output)
            if not result['overall_valid']:
                report_fail(f"{CfgDataG.logprefix}: Validation of xcvr error-status failed")

        case _:  # Default case
            st.error(f"Unknown test type: {type}")
            return False

    return True

def test_xcvr_check(CfgDataG, xcvr_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {xcvr_check} check")

    for check_item in xcvr_check:
        if not check_xcvr_state(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
