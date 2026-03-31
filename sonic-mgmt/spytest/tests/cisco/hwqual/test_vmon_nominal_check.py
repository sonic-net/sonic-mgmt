#!/usr/bin/env python3
"""
Voltage Margin Validation Script

This script validates voltage sensor readings to ensure they are within
acceptable tolerance ranges (±0.5%) of their nominal values.

Usage:
    python voltage_validator.py <input_file>
    or
    cat voltage_output.txt | python voltage_validator.py
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


def parse_voltage_data(input_text: str) -> List[Dict[str, str]]:
    """
    Parse voltage margin output into structured data
    
    Args:
        input_text (str): Raw voltage margin output
        
    Returns:
        List[Dict]: Parsed voltage data
    """
    voltage_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Device Name' in line and 'Actual mV' in line and 'Nominal mV' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find voltage data table headers")
        return []
    
    # Parse voltage data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 5:
            device_name = parts[0]
            margin = parts[1]
            actual_percent = parts[2]
            target_percent = parts[3]
            actual_mv = parts[4]
            nominal_mv = parts[5] if len(parts) > 5 else "N/A"
            
            voltage_data.append({
                'device_name': device_name,
                'margin': margin,
                'actual_percent': actual_percent,
                'target_percent': target_percent,
                'actual_mv': actual_mv,
                'nominal_mv': nominal_mv
            })
    
    return voltage_data

def validate_voltage_tolerance(actual_mv: str, nominal_mv: str, tolerance: float = 0.5) -> Tuple[bool, float, str]:
    """
    Validate if actual voltage is within tolerance of nominal voltage
    
    Args:
        actual_mv (str): Actual voltage reading in mV
        nominal_mv (str): Nominal voltage value in mV
        tolerance (float): Tolerance percentage (default: 0.5%)
        
    Returns:
        Tuple[bool, float, str]: (is_valid, deviation_percent, status_message)
    """
    try:
        actual = float(actual_mv)
        nominal = float(nominal_mv)
    except (ValueError, TypeError):
        return False, 0.0, "Invalid voltage values (non-numeric)"
    
    if nominal == 0:
        return False, 0.0, "Nominal voltage is zero"
    
    # Calculate percentage deviation
    deviation_percent = abs((actual - nominal) / nominal) * 100
    
    # Check if within tolerance
    is_within_tolerance = deviation_percent <= tolerance
    
    # Create status message
    if is_within_tolerance:
        status = f"PASS (deviation: {deviation_percent:.2f}%)"
    else:
        status = f"FAIL (deviation: {deviation_percent:.2f}% > {tolerance}%)"
    
    return is_within_tolerance, deviation_percent, status

def validate_all_voltages(voltage_data: List[Dict[str, str]], tolerance: float = 0.5) -> Dict[str, any]:
    """
    Validate all voltage readings
    
    Args:
        voltage_data (List[Dict]): Parsed voltage data
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
        'summary': {}
    }
    
    for device in voltage_data:
        device_name = device['device_name']
        actual_mv = device['actual_mv']
        nominal_mv = device['nominal_mv']
        
        results['total_devices'] += 1
        
        # Skip devices with N/A values
        if actual_mv == 'N/A' or nominal_mv == 'N/A' or actual_mv == '0' or nominal_mv == '0':
            results['skipped_devices'] += 1
            device_result = {
                'device_name': device_name,
                'actual_mv': actual_mv,
                'nominal_mv': nominal_mv,
                'status': 'SKIPPED (N/A or zero values)',
                'deviation': 0.0,
                'valid': None
            }
            results['device_results'].append(device_result)
            continue
        
        # Validate voltage
        is_valid, deviation, status = validate_voltage_tolerance(actual_mv, nominal_mv, tolerance)
        
        results['valid_devices'] += 1
        
        if is_valid:
            results['pass_count'] += 1
        else:
            results['fail_count'] += 1
            results['failed_devices'].append({
                'device_name': device_name,
                'actual_mv': float(actual_mv),
                'nominal_mv': float(nominal_mv),
                'deviation': deviation,
                'status': status
            })
        
        device_result = {
            'device_name': device_name,
            'actual_mv': actual_mv,
            'nominal_mv': nominal_mv,
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

def print_validation_results(results: Dict[str, any], show_all: bool = True, tolerance: float = 0.5):
    """
    Print formatted validation results
    
    Args:
        results (Dict): Validation results from validate_all_voltages
        show_all (bool): Whether to show all devices or just failures
        tolerance (float): Tolerance percentage used
    """
    print("=" * 80)
    print("VOLTAGE MARGIN VALIDATION RESULTS")
    print("=" * 80)
    print(f"Tolerance: ±{tolerance}%")
    print(f"Total Devices: {results['summary']['total_devices']}")
    print(f"Tested Devices: {results['summary']['tested_devices']}")
    print(f"Skipped Devices: {results['summary']['skipped_devices']}")
    print(f"Pass Rate: {results['summary']['pass_rate']:.1f}%")
    print(f"Overall Status: {results['summary']['overall_status']}")
    print("-" * 80)
    
    if show_all:
        print("DEVICE VALIDATION RESULTS:")
        print(f"{'Device Name':<20} {'Actual mV':<10} {'Nominal mV':<10} {'Deviation':<10} {'Status':<20}")
        print("-" * 80)
        
        for device in results['device_results']:
            device_name = device['device_name'][:19]  # Truncate long names
            actual_mv = device['actual_mv']
            nominal_mv = device['nominal_mv']
            deviation = f"{device['deviation']:.2f}%" if device['deviation'] > 0 else "N/A"
            status = device['status']
            
            print(f"{device_name:<20} {actual_mv:<10} {nominal_mv:<10} {deviation:<10} {status:<20}")
    
    if results['failed_devices']:
        print("\n" + "=" * 80)
        print("FAILED DEVICES:")
        print("=" * 80)
        
        for failed in results['failed_devices']:
            print(f"Device: {failed['device_name']}")
            print(f"  Actual: {failed['actual_mv']} mV")
            print(f"  Nominal: {failed['nominal_mv']} mV")
            print(f"  Deviation: {failed['deviation']:.2f}%")
            print(f"  Status: {failed['status']}")
            print()
    else:
        print("\n✓ All tested devices are within tolerance!")

def verify_vmon_nominal_state(output):
    """
    function to run validate nominal voltage condition 
    """
    try:
        # Parse voltage data
        voltage_data = parse_voltage_data(output)
        
        if not voltage_data:
            print("ERROR: No voltage data found in input")
            return False
        
        # Validate voltages (±0.5% tolerance)
        tolerance = 0.5
        results = validate_all_voltages(voltage_data, tolerance)
        
        # Print results
        show_all = '--show-all' in sys.argv or '-a' in sys.argv
        print_validation_results(results, show_all, tolerance)
        
        return results
        
    except Exception as e:
        print(f"ERROR: {e}")
        return results

def check_vmon_nomial_data(CfgDataG, entity):
    '''
    '''
    cmd = "/opt/cisco/bin/voltage_margin.py margin nominal"
    output = st.config(CfgDataG.dut, cmd)
    st.tg_wait(90)
    cmd = "/opt/cisco/bin/voltage_margin.py ls -m"
    output = st.config(CfgDataG.dut, cmd)
    result = verify_vmon_nominal_state(output)
    if not result['overall_valid']: 
        report_fail(f"{CfgDataG.logprefix}: Validation of temperature sensor failed")
        return False

    return True

def test_vmon_nominal_check(CfgDataG, vm_nom_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {vm_nom_check} check")

    for check_item in vm_nom_check:
        if not check_vmon_nomial_data(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
