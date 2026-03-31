#!/usr/bin/env python3
"""
Voltage Margin Percentage Validation Script

This script validates voltage margin percentage readings to ensure they are within
acceptable tolerance ranges (±10%) of their target percentage values.

Usage:
    python voltage_margin_validator.py <input_file>
    or
    cat voltage_margin_output.txt | python voltage_margin_validator.py
"""
import re
import sys
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from typing import List, Dict, Tuple, Optional
from spytest import st
from spytest.dicts import SpyTestDict
from apis.common.sonic_hooks import SonicHooks
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def vmon_nominal_data_check_hooks(request):
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

def parse_voltage_margin_data(input_text: str) -> List[Dict[str, str]]:
    """
    Parse voltage margin output into structured data
    
    Args:
        input_text (str): Raw voltage margin output
        
    Returns:
        List[Dict]: Parsed voltage margin data
    """
    voltage_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Device Name' in line and 'Actual %' in line and 'Target %' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find voltage margin data table headers")
        return []
    
    # Parse voltage margin data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 6:
            device_name = parts[0]
            margin = parts[1]
            actual_percent = parts[2]
            target_percent = parts[3]
            actual_mv = parts[4]
            nominal_mv = parts[5]
            
            voltage_data.append({
                'device_name': device_name,
                'margin': margin,
                'actual_percent': actual_percent,
                'target_percent': target_percent,
                'actual_mv': actual_mv,
                'nominal_mv': nominal_mv
            })
    
    return voltage_data

def validate_margin_percentage(actual_percent: str, target_percent: str, tolerance: float = 10.0) -> Tuple[bool, float, str]:
    """
    Validate if actual percentage is within tolerance of target percentage
    
    Args:
        actual_percent (str): Actual margin percentage reading
        target_percent (str): Target margin percentage value
        tolerance (float): Tolerance percentage (default: 10.0%)
        
    Returns:
        Tuple[bool, float, str]: (is_valid, deviation_percent, status_message)
    """
    try:
        actual = float(actual_percent)
        target = float(target_percent)
    except (ValueError, TypeError):
        return False, 0.0, "Invalid percentage values (non-numeric)"
    
    if target == 0:
        return False, 0.0, "Target percentage is zero"
    
    # Calculate percentage deviation from target
    deviation_percent = abs((actual - target) / target) * 100
    
    # Check if within tolerance
    is_within_tolerance = deviation_percent <= tolerance
    
    # Create status message with actual deviation
    actual_diff = actual - target
    if is_within_tolerance:
        status = f"PASS (deviation: {actual_diff:+.1f}% from target, {deviation_percent:.1f}% relative)"
    else:
        status = f"FAIL (deviation: {actual_diff:+.1f}% from target, {deviation_percent:.1f}% > {tolerance}%)"
    
    return is_within_tolerance, deviation_percent, status

def validate_all_margin_percentages(voltage_data: List[Dict[str, str]], tolerance: float = 10.0) -> Dict[str, any]:
    """
    Validate all voltage margin percentage readings
    
    Args:
        voltage_data (List[Dict]): Parsed voltage margin data
        tolerance (float): Tolerance percentage
        
    Returns:
        Dict: Validation results summary
    """
    results = {
        'overall_valid': True,
        'total_devices': 0,
        'valid_devices': 0,
        'invalid_devices': 0,
        'skipped_devices': 0,
        'pass_count': 0,
        'fail_count': 0,
        'device_results': [],
        'failed_devices': [],
        'skipped_device_list': [],
        'summary': {}
    }
    
    for device in voltage_data:
        device_name = device['device_name']
        actual_percent = device['actual_percent']
        target_percent = device['target_percent']
        margin = device['margin']
        actual_mv = device['actual_mv']
        nominal_mv = device['nominal_mv']
        
        results['total_devices'] += 1
        
        # Skip devices with N/A values
        if (actual_percent == 'N/A' or target_percent == 'N/A' or 
            actual_percent == '0' or target_percent == '0' or
            margin == 'N/A'):
            
            results['skipped_devices'] += 1
            results['skipped_device_list'].append({
                'device_name': device_name,
                'reason': f"N/A values (Actual: {actual_percent}, Target: {target_percent}, Margin: {margin})"
            })
            
            device_result = {
                'device_name': device_name,
                'actual_percent': actual_percent,
                'target_percent': target_percent,
                'margin': margin,
                'status': 'SKIPPED (N/A or zero values)',
                'deviation': 0.0,
                'valid': None
            }
            results['device_results'].append(device_result)
            continue
        
        # Validate margin percentage
        is_valid, deviation, status = validate_margin_percentage(actual_percent, target_percent, tolerance)
        
        results['valid_devices'] += 1
        
        if is_valid:
            results['pass_count'] += 1
        else:
            results['fail_count'] += 1
            results['failed_devices'].append({
                'device_name': device_name,
                'actual_percent': float(actual_percent),
                'target_percent': float(target_percent),
                'margin': margin,
                'actual_mv': actual_mv,
                'nominal_mv': nominal_mv,
                'deviation': deviation,
                'status': status
            })
        
        device_result = {
            'device_name': device_name,
            'actual_percent': actual_percent,
            'target_percent': target_percent,
            'margin': margin,
            'status': status,
            'deviation': deviation,
            'valid': is_valid
        }
        results['device_results'].append(device_result)
    
    # Create summary
    results['summary'] = {
        'total_devices': results['total_devices'],
        'tested_devices': results['valid_devices'],
        'skipped_devices': results['skipped_devices'],
        'pass_rate': (results['pass_count'] / results['valid_devices'] * 100) if results['valid_devices'] > 0 else 0,
        'overall_status': 'PASS' if results['fail_count'] == 0 else 'FAIL'
    }
    results['overall_valid'] = True if results['fail_count'] == 0 else False
    
    return results

def print_margin_validation_results(results: Dict[str, any], show_all: bool = True, tolerance: float = 10.0):
    """
    Print formatted voltage margin validation results
    
    Args:
        results (Dict): Validation results from validate_all_margin_percentages
        show_all (bool): Whether to show all devices or just failures
        tolerance (float): Tolerance percentage used
    """
    print("=" * 90)
    print("VOLTAGE MARGIN PERCENTAGE VALIDATION RESULTS")
    print("=" * 90)
    print(f"Tolerance: ±{tolerance}% of target percentage")
    print(f"Total Devices: {results['summary']['total_devices']}")
    print(f"Tested Devices: {results['summary']['tested_devices']}")
    print(f"Skipped Devices: {results['summary']['skipped_devices']}")
    print(f"Pass Rate: {results['summary']['pass_rate']:.1f}%")
    print(f"Overall Status: {results['summary']['overall_status']}")
    print("-" * 90)
    
    # Show skipped devices
    if results['skipped_device_list']:
        print("\nSKIPPED DEVICES:")
        print("-" * 60)
        for skipped in results['skipped_device_list']:
            print(f"  {skipped['device_name']}: {skipped['reason']}")
        print()
    
    if show_all:
        print("DEVICE VALIDATION RESULTS:")
        print(f"{'Device Name':<20} {'Margin':<8} {'Actual %':<8} {'Target %':<8} {'Status':<30}")
        print("-" * 90)
        
        for device in results['device_results']:
            device_name = device['device_name'][:19]  # Truncate long names
            margin = device.get('margin', 'N/A')[:7]
            actual_percent = device['actual_percent']
            target_percent = device['target_percent']
            status = device['status'][:29]  # Truncate long status
            
            print(f"{device_name:<20} {margin:<8} {actual_percent:<8} {target_percent:<8} {status:<30}")
    
    if results['failed_devices']:
        print("\n" + "=" * 90)
        print("FAILED DEVICES:")
        print("=" * 90)
        
        for failed in results['failed_devices']:
            print(f"Device: {failed['device_name']}")
            print(f"  Margin: {failed['margin']}")
            print(f"  Actual %: {failed['actual_percent']}%")
            print(f"  Target %: {failed['target_percent']}%")
            print(f"  Actual mV: {failed['actual_mv']}")
            print(f"  Nominal mV: {failed['nominal_mv']}")
            print(f"  Relative Deviation: {failed['deviation']:.1f}%")
            print(f"  Status: {failed['status']}")
            print()
    else:
        if results['valid_devices'] > 0:
            print("\n✓ All tested devices are within tolerance!")

def verify_vmon_max_state(output):
    """
    function to run validate nominal voltage condition 
    """
    try:
        # Parse voltage margin data
        voltage_data = parse_voltage_margin_data(output)
        
        if not voltage_data:
            print("ERROR: No voltage margin data found in input")
            return False
        
        # Validate margin percentages (±10% tolerance)
        tolerance = 10.0
        results = validate_all_margin_percentages(voltage_data, tolerance)
        
        # Print results
        show_all = '--show-all' in sys.argv or '-a' in sys.argv
        print_margin_validation_results(results, show_all, tolerance)
        
        return results
        
    except Exception as e:
        print(f"ERROR: {e}")
        return results

def check_vmon_max_data(CfgDataG, entity):
    '''
    '''
    cmd = "/opt/cisco/bin/voltage_margin.py margin max"
    output = st.config(CfgDataG.dut, cmd)
    st.tg_wait(90)
    cmd = "/opt/cisco/bin/voltage_margin.py ls -m"
    output = st.config(CfgDataG.dut, cmd)
    result = verify_vmon_max_state(output)
    if not result['overall_valid']: 
        report_fail(f"{CfgDataG.logprefix}: Validation of MAX voltaage margining failed")
        return False

    return True

def test_vmon_max_check(CfgDataG, vm_max_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {vm_max_check} check")

    for check_item in vm_max_check:
        if not check_vmon_max_data(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
