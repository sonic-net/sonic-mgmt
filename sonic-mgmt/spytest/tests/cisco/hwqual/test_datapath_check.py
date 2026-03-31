#!/usr/bin/env python3
"""
Interface Status Parser and Validator

This script parses SONiC 'show interface status' output and validates
interface operational states, identifying interfaces that are up or down.

Usage:
    python interface_status_parser.py <input_file>
    or
    cat interface_status_output.txt | python interface_status_parser.py
"""

import re
import sys
import time
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from datetime import datetime
from spytest.dicts import SpyTestDict
from apis.common.sonic_hooks import SonicHooks
from typing import List, Dict, Tuple, Optional
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def datapath_check_hooks(request):
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

def parse_interface_status(input_text: str) -> List[Dict[str, str]]:
    """
    Parse interface status output into structured data
    
    Args:
        input_text (str): Raw interface status output from 'show int status'
        
    Returns:
        List[Dict]: Parsed interface data
    """
    interface_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Interface' in line and 'Lanes' in line and 'Oper' in line and 'Admin' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find interface status table headers")
        return []
    
    # Parse interface data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 10:
            interface = parts[0]
            lanes = parts[1]
            speed = parts[2]
            mtu = parts[3]
            fec = parts[4]
            alias = parts[5]
            vlan = parts[6]
            oper = parts[7]
            admin = parts[8]
            interface_type = " ".join(parts[9:-1]) if len(parts) > 10 else parts[9]
            asym_pfc = parts[-1]
            
            interface_data.append({
                'interface': interface,
                'lanes': lanes,
                'speed': speed,
                'mtu': mtu,
                'fec': fec,
                'alias': alias,
                'vlan': vlan,
                'oper': oper.lower(),
                'admin': admin.lower(),
                'type': interface_type,
                'asym_pfc': asym_pfc
            })
    
    return interface_data

def analyze_interface_status(CfgDataG, interface_data: List[Dict[str, str]]) -> Dict[str, any]:
    """
    Analyze interface status and categorize interfaces by operational state
    
    Args:
        interface_data (List[Dict]): Parsed interface data
        
    Returns:
        Dict: Analysis results with interface categorization
    """
    results = {
        'overall_valid': True,
        'total_interfaces': 0,
        'oper_up_interfaces': [],
        'oper_down_interfaces': [],
        'admin_up_interfaces': [],
        'admin_down_interfaces': [],
        'mismatched_interfaces': [],  # Admin up but Oper down
        'speed_analysis': {},
        'type_analysis': {},
        'summary': {}
    }
    
    speed_counts = {}
    type_counts = {}
    
    for interface in interface_data:
        if interface in CfgDataG['exception_intf']:
            continue
        interface_name = interface['interface']
        oper_state = interface['oper']
        admin_state = interface['admin']
        speed = interface['speed']
        interface_type = interface['type']
        alias = interface['alias']
        
        results['total_interfaces'] += 1
        
        # Categorize by operational state
        if oper_state == 'up':
            results['oper_up_interfaces'].append({
                'interface': interface_name,
                'alias': alias,
                'speed': speed,
                'type': interface_type,
                'admin': admin_state
            })
        elif oper_state == 'down':
            results['oper_down_interfaces'].append({
                'interface': interface_name,
                'alias': alias,
                'speed': speed,
                'type': interface_type,
                'admin': admin_state
            })
        
        # Categorize by admin state
        if admin_state == 'up':
            results['admin_up_interfaces'].append({
                'interface': interface_name,
                'alias': alias,
                'oper': oper_state
            })
        elif admin_state == 'down':
            results['admin_down_interfaces'].append({
                'interface': interface_name,
                'alias': alias,
                'oper': oper_state
            })
        
        # Check for mismatched states (Admin up but Oper down)
        if admin_state == 'up' and oper_state == 'down':
            results['mismatched_interfaces'].append({
                'interface': interface_name,
                'alias': alias,
                'speed': speed,
                'type': interface_type,
                'issue': 'Admin UP but Oper DOWN'
            })
        
        # Speed analysis
        if speed not in speed_counts:
            speed_counts[speed] = {'total': 0, 'up': 0, 'down': 0}
        speed_counts[speed]['total'] += 1
        if oper_state == 'up':
            speed_counts[speed]['up'] += 1
        else:
            speed_counts[speed]['down'] += 1
        
        # Type analysis
        if interface_type not in type_counts:
            type_counts[interface_type] = {'total': 0, 'up': 0, 'down': 0}
        type_counts[interface_type]['total'] += 1
        if oper_state == 'up':
            type_counts[interface_type]['up'] += 1
        else:
            type_counts[interface_type]['down'] += 1
    
    results['speed_analysis'] = speed_counts
    results['type_analysis'] = type_counts
    
    # Create summary
    results['summary'] = {
        'total_interfaces': results['total_interfaces'],
        'oper_up_count': len(results['oper_up_interfaces']),
        'oper_down_count': len(results['oper_down_interfaces']),
        'admin_up_count': len(results['admin_up_interfaces']),
        'admin_down_count': len(results['admin_down_interfaces']),
        'mismatched_count': len(results['mismatched_interfaces']),
        'oper_up_percentage': (len(results['oper_up_interfaces']) / results['total_interfaces'] * 100) if results['total_interfaces'] > 0 else 0,
        'health_status': 'HEALTHY' if len(results['mismatched_interfaces']) == 0 else 'ISSUES_DETECTED'
    }
    results['overall_valid'] = True if len(results['mismatched_interfaces']) == 0 else False
    
    return results

def print_interface_analysis(results: Dict[str, any], show_details: bool = True):
    """
    Print formatted interface analysis results
    
    Args:
        results (Dict): Analysis results from analyze_interface_status
        show_details (bool): Whether to show detailed interface lists
    """
    print("=" * 100)
    print("SONIC INTERFACE STATUS ANALYSIS")
    print("=" * 100)
    
    summary = results['summary']
    print(f"Total Interfaces: {summary['total_interfaces']}")
    print(f"Operationally UP: {summary['oper_up_count']} ({summary['oper_up_percentage']:.1f}%)")
    print(f"Operationally DOWN: {summary['oper_down_count']}")
    print(f"Administratively UP: {summary['admin_up_count']}")
    print(f"Administratively DOWN: {summary['admin_down_count']}")
    print(f"Mismatched States: {summary['mismatched_count']}")
    print(f"Overall Health: {summary['health_status']}")
    print("-" * 100)
    
    # Speed analysis
    if results['speed_analysis']:
        print("INTERFACE SPEED ANALYSIS:")
        for speed, counts in results['speed_analysis'].items():
            up_percentage = (counts['up'] / counts['total'] * 100) if counts['total'] > 0 else 0
            print(f"  {speed}: {counts['total']} total, {counts['up']} up, {counts['down']} down ({up_percentage:.1f}% up)")
        print()
    
    # Type analysis
    if results['type_analysis']:
        print("INTERFACE TYPE ANALYSIS:")
        for iface_type, counts in results['type_analysis'].items():
            up_percentage = (counts['up'] / counts['total'] * 100) if counts['total'] > 0 else 0
            print(f"  {iface_type}: {counts['total']} total, {counts['up']} up, {counts['down']} down ({up_percentage:.1f}% up)")
        print()
    
    if show_details:
        # Show operationally UP interfaces
        if results['oper_up_interfaces']:
            print("OPERATIONALLY UP INTERFACES:")
            print(f"{'Interface':<12} {'Alias':<8} {'Speed':<8} {'Admin':<8} {'Type':<25}")
            print("-" * 70)
            for iface in results['oper_up_interfaces']:
                print(f"{iface['interface']:<12} {iface['alias']:<8} {iface['speed']:<8} {iface['admin']:<8} {iface['type']:<25}")
            print()
        
        # Show operationally DOWN interfaces
        if results['oper_down_interfaces']:
            print("OPERATIONALLY DOWN INTERFACES:")
            print(f"{'Interface':<12} {'Alias':<8} {'Speed':<8} {'Admin':<8} {'Type':<25}")
            print("-" * 70)
            for iface in results['oper_down_interfaces']:
                print(f"{iface['interface']:<12} {iface['alias']:<8} {iface['speed']:<8} {iface['admin']:<8} {iface['type']:<25}")
            print()
        
        # Show mismatched interfaces (Admin UP but Oper DOWN)
        if results['mismatched_interfaces']:
            print("⚠ MISMATCHED INTERFACES (Admin UP but Oper DOWN):")
            print(f"{'Interface':<12} {'Alias':<8} {'Speed':<8} {'Type':<25} {'Issue':<20}")
            print("-" * 80)
            for iface in results['mismatched_interfaces']:
                print(f"{iface['interface']:<12} {iface['alias']:<8} {iface['speed']:<8} {iface['type']:<25} {iface['issue']:<20}")
            print()
    
    # Summary messages
    if results['oper_up_interfaces']:
        print(f"✓ {len(results['oper_up_interfaces'])} interfaces are operationally UP")
    
    if results['oper_down_interfaces']:
        print(f"⚠ {len(results['oper_down_interfaces'])} interfaces are operationally DOWN")
    
    if results['mismatched_interfaces']:
        print(f"❌ {len(results['mismatched_interfaces'])} interfaces have mismatched states (Admin UP but Oper DOWN)")
    else:
        print("✓ No mismatched interface states detected")

# Integration function for spytest framework
def validate_interface_status(CfgDataG, output):
    """
    Spytest integration function for interface status validation
    
    Args:
        dut: Device under test
        
    Returns:
        Dict: Validation results
    """
    try:
        # Parse and analyze interface status data
        interface_data = parse_interface_status(output)
        
        if not interface_data:
            st.error("Failed to parse interface status data")
            return {"success": False, "error": "Failed to parse interface status data"}
        
        # Perform analysis
        results = analyze_interface_status(CfgDataG, interface_data)
        
        # Log results
        st.log(f"Interface Status Analysis Results:")
        st.log(f"  Total Interfaces: {results['summary']['total_interfaces']}")
        st.log(f"  Operationally UP: {results['summary']['oper_up_count']}")
        st.log(f"  Operationally DOWN: {results['summary']['oper_down_count']}")
        st.log(f"  Mismatched States: {results['summary']['mismatched_count']}")
        st.log(f"  Health Status: {results['summary']['health_status']}")
        
        # Log interface details
        if results['oper_up_interfaces']:
            st.log(f"UP interfaces: {', '.join([iface['interface'] for iface in results['oper_up_interfaces']])}")
        
        if results['oper_down_interfaces']:
            st.log(f"DOWN interfaces: {', '.join([iface['interface'] for iface in results['oper_down_interfaces']])}")
        
        # Log mismatched interfaces
        if results['mismatched_interfaces']:
            st.error(f"Mismatched interfaces detected ({len(results['mismatched_interfaces'])}):")
            for mismatched in results['mismatched_interfaces']:
                st.error(f"  {mismatched['interface']} ({mismatched['alias']}): {mismatched['issue']}")
        
        # Log speed analysis
        for speed, counts in results['speed_analysis'].items():
            up_percentage = (counts['up'] / counts['total'] * 100) if counts['total'] > 0 else 0
            st.log(f"  {speed} interfaces: {counts['up']}/{counts['total']} up ({up_percentage:.1f}%)")
        
        return results
        
    except Exception as e:
        if 'st' in locals():
            st.error(f"Interface status validation error: {e}")
        return results

def check_datapath_state(CfgDataG, type):
    '''
    '''
    match type:
        case "intf_status":
            cmd = "show interface status"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get intf satus from device")
                return False
            result = validate_interface_status(CfgDataG, output)
            if not result['overall_valid']:
                report_fail(f"{CfgDataG.logprefix}: Validation of intf status failed")

        case "shut_noshut":
            num_of_iter = CfgDataG.shut_noshut
            start_cmd = "/opt/cisco/bin/traffic-cfggen.py up"
            stop_cmd = "/opt/cisco/bin/traffic-cfggen.py down"
            show_cmd = "show interface status"

            for i in range(num_of_iter):
                st.log(f"{CfgDataG.logprefix}: Executing {type} iteration {i}")
                st.config(CfgDataG.dut, stop_cmd)
                time.sleep(30)
                st.config(CfgDataG.dut, start_cmd)
                time.sleep(CfgDataG.noshut_timer)
                output = st.config(CfgDataG.dut, show_cmd)
                if not output:
                    st.error("Failed to get intf satus from device")
                    return False
                result = validate_interface_status(CfgDataG, output)
                if not result['overall_valid']:
                    report_fail(f"{CfgDataG.logprefix}: Validation of intf status failed")

        case _:  # Default case
            st.error(f"Unknown test type: {type}")
            return False

    return True

def test_datapath_check(CfgDataG, datapath_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {datapath_check} check")

    for check_item in datapath_check:
        if not check_datapath_state(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
