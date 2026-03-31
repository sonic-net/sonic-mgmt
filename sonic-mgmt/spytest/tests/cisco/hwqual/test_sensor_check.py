#!/usr/bin/env python3
"""
Temperature/Voltage/Current Sensor Warning Validation Script

This script parses sensor data and validates that no sensors
are in warning state, which could indicate thermal/volt/current issues or hardware problems.
"""

import re
import sys
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from datetime import datetime
from spytest.dicts import SpyTestDict
from apis.common.sonic_hooks import SonicHooks
from typing import List, Dict, Tuple, Optional
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def sensor_data_check_hooks(request):
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


def parse_temperature_sensor_data(input_text: str) -> List[Dict[str, str]]:
    """
    Parse temperature sensor output into structured data
    
    Args:
        input_text (str): Raw temperature sensor output
        
    Returns:
        List[Dict]: Parsed temperature sensor data
    """
    sensor_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Sensor' in line and 'Temperature' in line and 'Warning' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find temperature sensor data table headers")
        return []
    
    # Parse temperature sensor data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 8:
            sensor_name = parts[0]
            temperature = parts[1]
            high_th = parts[2]
            low_th = parts[3]
            crit_high_th = parts[4]
            crit_low_th = parts[5]
            warning = parts[6]
            timestamp = " ".join(parts[7:])  # Join remaining parts for timestamp
            
            sensor_data.append({
                'sensor_name': sensor_name,
                'temperature': temperature,
                'high_th': high_th,
                'low_th': low_th,
                'crit_high_th': crit_high_th,
                'crit_low_th': crit_low_th,
                'warning': warning,
                'timestamp': timestamp
            })
    
    return sensor_data

def validate_temperature_thresholds(sensor: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Validate temperature sensor against thresholds
    
    Args:
        sensor (Dict): Sensor data dictionary
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    issues = []
    is_valid = True
    
    try:
        temp = float(sensor['temperature'])
        high_th = float(sensor['high_th'])
        low_th = float(sensor['low_th'])
        crit_high_th = float(sensor['crit_high_th'])
        crit_low_th = float(sensor['crit_low_th'])
        
        # Check critical thresholds
        if temp >= crit_high_th:
            issues.append(f"CRITICAL: Temperature {temp}°C >= Critical High {crit_high_th}°C")
            is_valid = False
        elif temp <= crit_low_th:
            issues.append(f"CRITICAL: Temperature {temp}°C <= Critical Low {crit_low_th}°C")
            is_valid = False
        # Check warning thresholds
        elif temp >= high_th:
            issues.append(f"WARNING: Temperature {temp}°C >= High Threshold {high_th}°C")
        elif temp <= low_th:
            issues.append(f"WARNING: Temperature {temp}°C <= Low Threshold {low_th}°C")
            
    except (ValueError, TypeError):
        issues.append("Invalid temperature values (non-numeric)")
        is_valid = False
    
    return is_valid, issues

def validate_all_temperature_sensors(sensor_data: List[Dict[str, str]]) -> Dict[str, any]:
    """
    Validate all temperature sensors for warning conditions
    
    Args:
        sensor_data (List[Dict]): Parsed temperature sensor data
        
    Returns:
        Dict: Validation results summary
    """
    results = {
        'overall_valid': True,
        'total_sensors': 0,
        'valid_sensors': 0,
        'skipped_sensors': 0,
        'warning_sensors': 0,
        'critical_sensors': 0,
        'sensor_results': [],
        'warning_sensor_list': [],
        'critical_sensor_list': [],
        'skipped_sensor_list': [],
        'temperature_stats': {
            'min_temp': float('inf'),
            'max_temp': float('-inf'),
            'avg_temp': 0.0,
            'temp_readings': []
        },
        'summary': {}
    }
    
    temp_readings = []
    
    for sensor in sensor_data:
        sensor_name = sensor['sensor_name']
        temperature = sensor['temperature']
        warning = sensor['warning'].lower()
        timestamp = sensor['timestamp']
        
        results['total_sensors'] += 1
        
        # Check for N/A or invalid values and skip them
        if (temperature == 'N/A' or warning == 'N/A' or 
            sensor['high_th'] == 'N/A' or sensor['low_th'] == 'N/A'):
            
            results['skipped_sensors'] += 1
            skip_reason = []
            if temperature == 'N/A':
                skip_reason.append("Temperature is N/A")
            if warning == 'N/A':
                skip_reason.append("Warning is N/A")
            if sensor['high_th'] == 'N/A':
                skip_reason.append("High threshold is N/A")
            if sensor['low_th'] == 'N/A':
                skip_reason.append("Low threshold is N/A")
            
            results['skipped_sensor_list'].append({
                'sensor_name': sensor_name,
                'reason': "; ".join(skip_reason),
                'timestamp': timestamp
            })
            
            sensor_result = {
                'sensor_name': sensor_name,
                'temperature': temperature,
                'warning': warning,
                'timestamp': timestamp,
                'status': 'SKIPPED (N/A values detected)',
                'issues': [],
                'valid': None
            }
            results['sensor_results'].append(sensor_result)
            continue
        
        results['valid_sensors'] += 1
        
        # Track temperature statistics
        try:
            temp_val = float(temperature)
            temp_readings.append(temp_val)
            results['temperature_stats']['min_temp'] = min(results['temperature_stats']['min_temp'], temp_val)
            results['temperature_stats']['max_temp'] = max(results['temperature_stats']['max_temp'], temp_val)
        except ValueError:
            pass
        
        # Check warning status
        is_warning = warning == 'true'
        
        # Validate against thresholds
        is_threshold_valid, threshold_issues = validate_temperature_thresholds(sensor)
        
        # Determine sensor status
        if is_warning:
            results['warning_sensors'] += 1
            if any('CRITICAL' in issue for issue in threshold_issues):
                results['critical_sensors'] += 1
                status = "CRITICAL WARNING"
                results['critical_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'temperature': float(temperature),
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
            else:
                status = "WARNING"
                results['warning_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'temperature': float(temperature),
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
        else:
            status = "OK"
            # Even if warning is False, check if temperature is actually out of range
            if threshold_issues:
                status = f"OK (but {'; '.join(threshold_issues)})"
        
        sensor_result = {
            'sensor_name': sensor_name,
            'temperature': temperature,
            'warning': warning,
            'timestamp': timestamp,
            'status': status,
            'issues': threshold_issues,
            'valid': not is_warning
        }
        results['sensor_results'].append(sensor_result)
    
    # Calculate temperature statistics
    if temp_readings:
        results['temperature_stats']['avg_temp'] = sum(temp_readings) / len(temp_readings)
        results['temperature_stats']['temp_readings'] = temp_readings
    else:
        results['temperature_stats']['min_temp'] = 0.0
        results['temperature_stats']['max_temp'] = 0.0
    
    # Create summary
    results['summary'] = {
        'total_sensors': results['total_sensors'],
        'valid_sensors': results['valid_sensors'],
        'skipped_sensors': results['skipped_sensors'],
        'warning_sensors': results['warning_sensors'],
        'critical_sensors': results['critical_sensors'],
        'warning_rate': (results['warning_sensors'] / results['valid_sensors'] * 100) if results['valid_sensors'] > 0 else 0,
        'overall_status': 'FAIL' if results['warning_sensors'] > 0 else 'PASS'
    }
    results['overall_valid'] = False if results['warning_sensors'] > 0 else True
    
    return results

def print_temperature_validation_results(results: Dict[str, any], show_all: bool = True):
    """
    Print formatted temperature sensor validation results
    
    Args:
        results (Dict): Validation results from validate_all_temperature_sensors
        show_all (bool): Whether to show all sensors or just warnings/failures
    """
    print("=" * 100)
    print("TEMPERATURE SENSOR WARNING VALIDATION RESULTS")
    print("=" * 100)
    print(f"Validation Rule: Check if any sensor has Warning = True")
    print(f"Total Sensors: {results['summary']['total_sensors']}")
    print(f"Valid Sensors: {results['summary']['valid_sensors']}")
    print(f"Skipped Sensors: {results['summary']['skipped_sensors']}")
    print(f"Warning Sensors: {results['summary']['warning_sensors']}")
    print(f"Critical Sensors: {results['summary']['critical_sensors']}")
    
    if results['valid_sensors'] > 0:
        print(f"Warning Rate: {results['summary']['warning_rate']:.1f}%")
    else:
        print("Warning Rate: N/A (no valid sensors)")
    
    print(f"Overall Status: {results['summary']['overall_status']}")
    
    # Temperature statistics
    temp_stats = results['temperature_stats']
    if temp_stats['temp_readings']:
        print(f"Temperature Range: {temp_stats['min_temp']:.1f}°C to {temp_stats['max_temp']:.1f}°C")
        print(f"Average Temperature: {temp_stats['avg_temp']:.1f}°C")
    
    print("-" * 100)
    
    # Show skipped sensors
    if results['skipped_sensor_list']:
        print("SKIPPED SENSORS (N/A values detected):")
        print("-" * 70)
        for skipped in results['skipped_sensor_list']:
            print(f"  {skipped['sensor_name']}: {skipped['reason']}")
        print()
    
    if show_all and results['sensor_results']:
        print("ALL SENSOR VALIDATION RESULTS:")
        print(f"{'Sensor Name':<20} {'Temp (°C)':<10} {'Warning':<8} {'Status':<25} {'Timestamp':<18}")
        print("-" * 100)
        
        for sensor in results['sensor_results']:
            sensor_name = sensor['sensor_name'][:19]
            temperature = sensor['temperature']
            warning = sensor['warning']
            status = sensor['status'][:24]
            timestamp = sensor['timestamp'][:17]
            
            print(f"{sensor_name:<20} {temperature:<10} {warning:<8} {status:<25} {timestamp:<18}")
    
    # Show warning sensors
    if results['warning_sensor_list']:
        print("\n" + "=" * 100)
        print(f"WARNING SENSORS ({len(results['warning_sensor_list'])} sensors):")
        print("=" * 100)
        
        for warning_sensor in results['warning_sensor_list']:
            print(f"Sensor: {warning_sensor['sensor_name']}")
            print(f"  Temperature: {warning_sensor['temperature']}°C")
            print(f"  Warning Status: {warning_sensor['warning']}")
            print(f"  Timestamp: {warning_sensor['timestamp']}")
            if warning_sensor['issues']:
                print(f"  Issues: {'; '.join(warning_sensor['issues'])}")
            print()
    
    # Show critical sensors
    if results['critical_sensor_list']:
        print("\n" + "=" * 100)
        print(f"CRITICAL SENSORS ({len(results['critical_sensor_list'])} sensors):")
        print("=" * 100)
        
        for critical_sensor in results['critical_sensor_list']:
            print(f"Sensor: {critical_sensor['sensor_name']}")
            print(f"  Temperature: {critical_sensor['temperature']}°C")
            print(f"  Warning Status: {critical_sensor['warning']}")
            print(f"  Timestamp: {critical_sensor['timestamp']}")
            if critical_sensor['issues']:
                print(f"  Issues: {'; '.join(critical_sensor['issues'])}")
            print()
    
    if results['warning_sensors'] == 0 and results['valid_sensors'] > 0:
        print("\n✓ All temperature sensors are operating normally (Warning = False)")
    elif results['valid_sensors'] == 0:
        print("\n⚠ WARNING: No valid sensors found for validation")


def verify_temperature_sensor_data(sensor_output):
    """
    Spytest integration function for temperature sensor validation
    
    Args:
        dut: Device under test
        
    Returns:
        Dict: Validation results
    """
    try:
        # Parse and validate temperature sensor data
        sensor_data = parse_temperature_sensor_data(sensor_output)
        
        if not sensor_data:
            st.error("Failed to parse temperature sensor data")
            return False
        
        # Perform validation
        results = validate_all_temperature_sensors(sensor_data)
        
        # Log results
        st.log(f"Temperature Sensor Validation Results:")
        st.log(f"  Total Sensors: {results['summary']['total_sensors']}")
        st.log(f"  Valid Sensors: {results['summary']['valid_sensors']}")
        st.log(f"  Warning Sensors: {results['summary']['warning_sensors']}")
        st.log(f"  Critical Sensors: {results['summary']['critical_sensors']}")
        st.log(f"  Overall Status: {results['summary']['overall_status']}")
        
        # Log temperature statistics
        temp_stats = results['temperature_stats']
        if temp_stats['temp_readings']:
            st.log(f"  Temperature Range: {temp_stats['min_temp']:.1f}°C to {temp_stats['max_temp']:.1f}°C")
            st.log(f"  Average Temperature: {temp_stats['avg_temp']:.1f}°C")
        
        # Log warning sensors
        if results['warning_sensor_list']:
            st.error(f"Warning sensors detected ({len(results['warning_sensor_list'])}):")
            for warning_sensor in results['warning_sensor_list']:
                st.error(f"  {warning_sensor['sensor_name']}: {warning_sensor['temperature']}°C (Warning = {warning_sensor['warning']})")
        
        # Log critical sensors
        if results['critical_sensor_list']:
            st.error(f"Critical sensors detected ({len(results['critical_sensor_list'])}):")
            for critical_sensor in results['critical_sensor_list']:
                st.error(f"  {critical_sensor['sensor_name']}: {critical_sensor['temperature']}°C (CRITICAL)")
        
        if results['warning_sensors'] == 0:
            st.log("✓ All temperature sensors operating normally")
        
        # Print results
        #show_all = '--show-all' in sys.argv or '-a' in sys.argv
        #print_temperature_validation_results(results, show_all)

        return results
        
    except Exception as e:
        if 'st' in locals():
            st.error(f"Temperature sensor validation error: {e}")
        return results 

def parse_voltage_sensor_data(input_text: str) -> List[Dict[str, str]]:
    """
    Parse voltage sensor output into structured data
    
    Args:
        input_text (str): Raw voltage sensor output
        
    Returns:
        List[Dict]: Parsed voltage sensor data
    """
    sensor_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Sensor' in line and 'Voltage' in line and 'Warning' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find voltage sensor data table headers")
        return []
    
    # Parse voltage sensor data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 8:
            sensor_name = parts[0]
            voltage_raw = parts[1]  # e.g., "1199 mV"
            high_th = parts[2]
            low_th = parts[3]
            crit_high_th = parts[4]
            crit_low_th = parts[5]
            warning = parts[6]
            timestamp = " ".join(parts[7:])  # Join remaining parts for timestamp
            
            # Extract voltage value (remove "mV" suffix)
            voltage = voltage_raw.replace(' mV', '').replace('mV', '')
            
            sensor_data.append({
                'sensor_name': sensor_name,
                'voltage': voltage,
                'voltage_raw': voltage_raw,
                'high_th': high_th,
                'low_th': low_th,
                'crit_high_th': crit_high_th,
                'crit_low_th': crit_low_th,
                'warning': warning,
                'timestamp': timestamp
            })
    
    return sensor_data

def validate_voltage_thresholds(sensor: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Validate voltage sensor against thresholds
    
    Args:
        sensor (Dict): Sensor data dictionary
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    issues = []
    is_valid = True
    
    try:
        voltage = float(sensor['voltage'])
        high_th = float(sensor['high_th'])
        low_th = float(sensor['low_th'])
        crit_high_th = float(sensor['crit_high_th'])
        crit_low_th = float(sensor['crit_low_th'])
        
        # Check critical thresholds
        if voltage >= crit_high_th:
            issues.append(f"CRITICAL: Voltage {voltage}mV >= Critical High {crit_high_th}mV")
            is_valid = False
        elif voltage <= crit_low_th:
            issues.append(f"CRITICAL: Voltage {voltage}mV <= Critical Low {crit_low_th}mV")
            is_valid = False
        # Check warning thresholds
        elif voltage >= high_th:
            issues.append(f"WARNING: Voltage {voltage}mV >= High Threshold {high_th}mV")
        elif voltage <= low_th:
            issues.append(f"WARNING: Voltage {voltage}mV <= Low Threshold {low_th}mV")
            
    except (ValueError, TypeError):
        issues.append("Invalid voltage values (non-numeric)")
        is_valid = False
    
    return is_valid, issues

def validate_all_voltage_sensors(sensor_data: List[Dict[str, str]]) -> Dict[str, any]:
    """
    Validate all voltage sensors for warning conditions
    
    Args:
        sensor_data (List[Dict]): Parsed voltage sensor data
        
    Returns:
        Dict: Validation results summary
    """
    results = {
        'overall_valid': True,
        'total_sensors': 0,
        'valid_sensors': 0,
        'skipped_sensors': 0,
        'warning_sensors': 0,
        'critical_sensors': 0,
        'sensor_results': [],
        'warning_sensor_list': [],
        'critical_sensor_list': [],
        'skipped_sensor_list': [],
        'voltage_stats': {
            'min_voltage': float('inf'),
            'max_voltage': float('-inf'),
            'avg_voltage': 0.0,
            'voltage_readings': []
        },
        'power_rail_analysis': {},
        'summary': {}
    }
    
    voltage_readings = []
    power_rails = {}
    
    for sensor in sensor_data:
        sensor_name = sensor['sensor_name']
        voltage = sensor['voltage']
        warning = sensor['warning'].lower()
        timestamp = sensor['timestamp']
        voltage_raw = sensor['voltage_raw']
        
        results['total_sensors'] += 1
        
        # Check for N/A or invalid values and skip them
        if (voltage == 'N/A' or warning == 'N/A' or 
            sensor['high_th'] == 'N/A' or sensor['low_th'] == 'N/A'):
            
            results['skipped_sensors'] += 1
            skip_reason = []
            if voltage == 'N/A':
                skip_reason.append("Voltage is N/A")
            if warning == 'N/A':
                skip_reason.append("Warning is N/A")
            if sensor['high_th'] == 'N/A':
                skip_reason.append("High threshold is N/A")
            if sensor['low_th'] == 'N/A':
                skip_reason.append("Low threshold is N/A")
            
            results['skipped_sensor_list'].append({
                'sensor_name': sensor_name,
                'reason': "; ".join(skip_reason),
                'timestamp': timestamp
            })
            
            sensor_result = {
                'sensor_name': sensor_name,
                'voltage': voltage,
                'voltage_raw': voltage_raw,
                'warning': warning,
                'timestamp': timestamp,
                'status': 'SKIPPED (N/A values detected)',
                'issues': [],
                'valid': None
            }
            results['sensor_results'].append(sensor_result)
            continue
        
        results['valid_sensors'] += 1
        
        # Track voltage statistics
        try:
            voltage_val = float(voltage)
            voltage_readings.append(voltage_val)
            results['voltage_stats']['min_voltage'] = min(results['voltage_stats']['min_voltage'], voltage_val)
            results['voltage_stats']['max_voltage'] = max(results['voltage_stats']['max_voltage'], voltage_val)
            
            # Categorize by power rail type
            rail_type = sensor_name.split('_')[0] if '_' in sensor_name else 'Other'
            if rail_type not in power_rails:
                power_rails[rail_type] = []
            power_rails[rail_type].append({
                'sensor': sensor_name,
                'voltage': voltage_val,
                'warning': warning == 'true'
            })
            
        except ValueError:
            pass
        
        # Check warning status
        is_warning = warning == 'true'
        
        # Validate against thresholds
        is_threshold_valid, threshold_issues = validate_voltage_thresholds(sensor)
        
        # Determine sensor status
        if is_warning:
            results['warning_sensors'] += 1
            if any('CRITICAL' in issue for issue in threshold_issues):
                results['critical_sensors'] += 1
                status = "CRITICAL WARNING"
                results['critical_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'voltage': float(voltage),
                    'voltage_raw': voltage_raw,
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
            else:
                status = "WARNING"
                results['warning_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'voltage': float(voltage),
                    'voltage_raw': voltage_raw,
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
        else:
            status = "OK"
            # Even if warning is False, check if voltage is actually out of range
            if threshold_issues:
                status = f"OK (but {'; '.join(threshold_issues)})"
        
        sensor_result = {
            'sensor_name': sensor_name,
            'voltage': voltage,
            'voltage_raw': voltage_raw,
            'warning': warning,
            'timestamp': timestamp,
            'status': status,
            'issues': threshold_issues,
            'valid': not is_warning
        }
        results['sensor_results'].append(sensor_result)
    
    # Calculate voltage statistics
    if voltage_readings:
        results['voltage_stats']['avg_voltage'] = sum(voltage_readings) / len(voltage_readings)
        results['voltage_stats']['voltage_readings'] = voltage_readings
    else:
        results['voltage_stats']['min_voltage'] = 0.0
        results['voltage_stats']['max_voltage'] = 0.0
    
    # Power rail analysis
    results['power_rail_analysis'] = power_rails
    
    # Create summary
    results['summary'] = {
        'total_sensors': results['total_sensors'],
        'valid_sensors': results['valid_sensors'],
        'skipped_sensors': results['skipped_sensors'],
        'warning_sensors': results['warning_sensors'],
        'critical_sensors': results['critical_sensors'],
        'warning_rate': (results['warning_sensors'] / results['valid_sensors'] * 100) if results['valid_sensors'] > 0 else 0,
        'overall_status': 'FAIL' if results['warning_sensors'] > 0 else 'PASS'
    }
    results['overall_valid'] = False if results['warning_sensors'] > 0 else True
    
    return results

def print_voltage_validation_results(results: Dict[str, any], show_all: bool = True):
    """
    Print formatted voltage sensor validation results
    
    Args:
        results (Dict): Validation results from validate_all_voltage_sensors
        show_all (bool): Whether to show all sensors or just warnings/failures
    """
    print("=" * 110)
    print("VOLTAGE SENSOR WARNING VALIDATION RESULTS")
    print("=" * 110)
    print(f"Validation Rule: Check if any voltage sensor has Warning = True")
    print(f"Total Sensors: {results['summary']['total_sensors']}")
    print(f"Valid Sensors: {results['summary']['valid_sensors']}")
    print(f"Skipped Sensors: {results['summary']['skipped_sensors']}")
    print(f"Warning Sensors: {results['summary']['warning_sensors']}")
    print(f"Critical Sensors: {results['summary']['critical_sensors']}")
    
    if results['valid_sensors'] > 0:
        print(f"Warning Rate: {results['summary']['warning_rate']:.1f}%")
    else:
        print("Warning Rate: N/A (no valid sensors)")
    
    print(f"Overall Status: {results['summary']['overall_status']}")
    
    # Voltage statistics
    voltage_stats = results['voltage_stats']
    if voltage_stats['voltage_readings']:
        print(f"Voltage Range: {voltage_stats['min_voltage']:.0f}mV to {voltage_stats['max_voltage']:.0f}mV")
        print(f"Average Voltage: {voltage_stats['avg_voltage']:.0f}mV")
    
    print("-" * 110)
    
    # Power rail analysis
    if results['power_rail_analysis']:
        print("POWER RAIL ANALYSIS:")
        for rail_type, sensors in results['power_rail_analysis'].items():
            warning_count = sum(1 for s in sensors if s['warning'])
            print(f"  {rail_type}: {len(sensors)} sensors, {warning_count} warnings")
        print()
    
    # Show skipped sensors
    if results['skipped_sensor_list']:
        print("SKIPPED SENSORS (N/A values detected):")
        print("-" * 70)
        for skipped in results['skipped_sensor_list']:
            print(f"  {skipped['sensor_name']}: {skipped['reason']}")
        print()
    
    if show_all and results['sensor_results']:
        print("ALL SENSOR VALIDATION RESULTS:")
        print(f"{'Sensor Name':<18} {'Voltage':<12} {'Warning':<8} {'Status':<25} {'Timestamp':<18}")
        print("-" * 110)
        
        for sensor in results['sensor_results']:
            sensor_name = sensor['sensor_name'][:17]
            voltage = sensor['voltage_raw'] if 'voltage_raw' in sensor else f"{sensor['voltage']}mV"
            warning = sensor['warning']
            status = sensor['status'][:24]
            timestamp = sensor['timestamp'][:17]
            
            print(f"{sensor_name:<18} {voltage:<12} {warning:<8} {status:<25} {timestamp:<18}")
    
    # Show warning sensors
    if results['warning_sensor_list']:
        print("\n" + "=" * 110)
        print(f"WARNING SENSORS ({len(results['warning_sensor_list'])} sensors):")
        print("=" * 110)
        
        for warning_sensor in results['warning_sensor_list']:
            print(f"Sensor: {warning_sensor['sensor_name']}")
            print(f"  Voltage: {warning_sensor['voltage_raw']}")
            print(f"  Warning Status: {warning_sensor['warning']}")
            print(f"  Timestamp: {warning_sensor['timestamp']}")
            if warning_sensor['issues']:
                print(f"  Issues: {'; '.join(warning_sensor['issues'])}")
            print()
    
    # Show critical sensors
    if results['critical_sensor_list']:
        print("\n" + "=" * 110)
        print(f"CRITICAL SENSORS ({len(results['critical_sensor_list'])} sensors):")
        print("=" * 110)
        
        for critical_sensor in results['critical_sensor_list']:
            print(f"Sensor: {critical_sensor['sensor_name']}")
            print(f"  Voltage: {critical_sensor['voltage_raw']}")
            print(f"  Warning Status: {critical_sensor['warning']}")
            print(f"  Timestamp: {critical_sensor['timestamp']}")
            if critical_sensor['issues']:
                print(f"  Issues: {'; '.join(critical_sensor['issues'])}")
            print()
    
    if results['warning_sensors'] == 0 and results['valid_sensors'] > 0:
        print("\n✓ All voltage sensors are operating normally (Warning = False)")
    elif results['valid_sensors'] == 0:
        print("\n⚠ WARNING: No valid sensors found for validation")

def verify_voltage_sensor_data(sensor_output):
    """
    Spytest integration function for voltage sensor validation
    
    Args:
        dut: Device under test
        
    Returns:
        Dict: Validation results
    """
    try:
        # Parse and validate voltage sensor data
        sensor_data = parse_voltage_sensor_data(sensor_output)
        
        if not sensor_data:
            st.error("Failed to parse voltage sensor data")
            return {"success": False, "error": "Failed to parse voltage sensor data"}
        
        # Perform validation
        results = validate_all_voltage_sensors(sensor_data)
        
        # Log results
        st.log(f"Voltage Sensor Validation Results:")
        st.log(f"  Total Sensors: {results['summary']['total_sensors']}")
        st.log(f"  Valid Sensors: {results['summary']['valid_sensors']}")
        st.log(f"  Warning Sensors: {results['summary']['warning_sensors']}")
        st.log(f"  Critical Sensors: {results['summary']['critical_sensors']}")
        st.log(f"  Overall Status: {results['summary']['overall_status']}")
        
        # Log voltage statistics
        voltage_stats = results['voltage_stats']
        if voltage_stats['voltage_readings']:
            st.log(f"  Voltage Range: {voltage_stats['min_voltage']:.0f}mV to {voltage_stats['max_voltage']:.0f}mV")
            st.log(f"  Average Voltage: {voltage_stats['avg_voltage']:.0f}mV")
        
        # Log power rail analysis
        for rail_type, sensors in results['power_rail_analysis'].items():
            warning_count = sum(1 for s in sensors if s['warning'])
            if warning_count > 0:
                st.log(f"  {rail_type} Rail: {warning_count}/{len(sensors)} sensors in warning state")
        
        # Log warning sensors
        if results['warning_sensor_list']:
            st.error(f"Warning sensors detected ({len(results['warning_sensor_list'])}):")
            for warning_sensor in results['warning_sensor_list']:
                st.error(f"  {warning_sensor['sensor_name']}: {warning_sensor['voltage_raw']} (Warning = {warning_sensor['warning']})")
        
        # Log critical sensors
        if results['critical_sensor_list']:
            st.error(f"Critical sensors detected ({len(results['critical_sensor_list'])}):")
            for critical_sensor in results['critical_sensor_list']:
                st.error(f"  {critical_sensor['sensor_name']}: {critical_sensor['voltage_raw']} (CRITICAL)")
        
        if results['warning_sensors'] == 0:
            st.log("✓ All voltage sensors operating normally")
        
        # Print results
        #show_all = '--show-all' in sys.argv or '-a' in sys.argv
        #print_temperature_validation_results(results, show_all)

        return results

    except Exception as e:
        if 'st' in locals():
            st.error(f"Voltage sensor validation error: {e}")
        return results


def parse_current_sensor_data(input_text: str) -> List[Dict[str, str]]:
    """
    Parse current sensor output into structured data
    
    Args:
        input_text (str): Raw current sensor output
        
    Returns:
        List[Dict]: Parsed current sensor data
    """
    sensor_data = []
    lines = input_text.strip().split('\n')
    
    # Skip header lines and find data start
    data_start = -1
    for i, line in enumerate(lines):
        if 'Sensor' in line and 'Current' in line and 'Warning' in line:
            data_start = i + 2  # Skip header and separator line
            break
    
    if data_start == -1:
        print("ERROR: Could not find current sensor data table headers")
        return []
    
    # Parse current sensor data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue
            
        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line)
        
        if len(parts) >= 8:
            sensor_name = parts[0]
            current_raw = parts[1]  # e.g., "8031 mA"
            high_th = parts[2]
            low_th = parts[3]
            crit_high_th = parts[4]
            crit_low_th = parts[5]
            warning = parts[6]
            timestamp = " ".join(parts[7:])  # Join remaining parts for timestamp
            
            # Extract current value (remove "mA" suffix)
            current = current_raw.replace(' mA', '').replace('mA', '')
            
            sensor_data.append({
                'sensor_name': sensor_name,
                'current': current,
                'current_raw': current_raw,
                'high_th': high_th,
                'low_th': low_th,
                'crit_high_th': crit_high_th,
                'crit_low_th': crit_low_th,
                'warning': warning,
                'timestamp': timestamp
            })
    
    return sensor_data

def validate_current_thresholds(sensor: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Validate current sensor against thresholds
    
    Args:
        sensor (Dict): Sensor data dictionary
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    issues = []
    is_valid = True
    
    try:
        current = float(sensor['current'])
        
        # Handle N/A values in thresholds
        high_th = float(sensor['high_th']) if sensor['high_th'] != 'N/A' else None
        low_th = float(sensor['low_th']) if sensor['low_th'] != 'N/A' else None
        crit_high_th = float(sensor['crit_high_th']) if sensor['crit_high_th'] != 'N/A' else None
        crit_low_th = float(sensor['crit_low_th']) if sensor['crit_low_th'] != 'N/A' else None
        
        # Check critical thresholds
        if crit_high_th is not None and current >= crit_high_th:
            issues.append(f"CRITICAL: Current {current}mA >= Critical High {crit_high_th}mA")
            is_valid = False
        elif crit_low_th is not None and current <= crit_low_th:
            issues.append(f"CRITICAL: Current {current}mA <= Critical Low {crit_low_th}mA")
            is_valid = False
        # Check warning thresholds
        elif high_th is not None and current >= high_th:
            issues.append(f"WARNING: Current {current}mA >= High Threshold {high_th}mA")
        elif low_th is not None and current <= low_th:
            issues.append(f"WARNING: Current {current}mA <= Low Threshold {low_th}mA")
            
    except (ValueError, TypeError):
        issues.append("Invalid current values (non-numeric)")
        is_valid = False
    
    return is_valid, issues

def validate_all_current_sensors(sensor_data: List[Dict[str, str]]) -> Dict[str, any]:
    """
    Validate all current sensors for warning conditions
    
    Args:
        sensor_data (List[Dict]): Parsed current sensor data
        
    Returns:
        Dict: Validation results summary
    """
    results = {
        'overall_valid': True,
        'total_sensors': 0,
        'valid_sensors': 0,
        'skipped_sensors': 0,
        'warning_sensors': 0,
        'critical_sensors': 0,
        'sensor_results': [],
        'warning_sensor_list': [],
        'critical_sensor_list': [],
        'skipped_sensor_list': [],
        'current_stats': {
            'min_current': float('inf'),
            'max_current': float('-inf'),
            'avg_current': 0.0,
            'total_current': 0.0,
            'current_readings': []
        },
        'component_analysis': {},
        'summary': {}
    }
    
    current_readings = []
    components = {}
    
    for sensor in sensor_data:
        sensor_name = sensor['sensor_name']
        current = sensor['current']
        warning = sensor['warning'].lower()
        timestamp = sensor['timestamp']
        current_raw = sensor['current_raw']
        
        results['total_sensors'] += 1
        
        # Check for N/A or invalid values and skip them
        if current == 'N/A' or warning == 'N/A':
            
            results['skipped_sensors'] += 1
            skip_reason = []
            if current == 'N/A':
                skip_reason.append("Current is N/A")
            if warning == 'N/A':
                skip_reason.append("Warning is N/A")
            
            results['skipped_sensor_list'].append({
                'sensor_name': sensor_name,
                'reason': "; ".join(skip_reason),
                'timestamp': timestamp
            })
            
            sensor_result = {
                'sensor_name': sensor_name,
                'current': current,
                'current_raw': current_raw,
                'warning': warning,
                'timestamp': timestamp,
                'status': 'SKIPPED (N/A values detected)',
                'issues': [],
                'valid': None
            }
            results['sensor_results'].append(sensor_result)
            continue
        
        results['valid_sensors'] += 1
        
        # Track current statistics
        try:
            current_val = float(current)
            current_readings.append(current_val)
            results['current_stats']['min_current'] = min(results['current_stats']['min_current'], current_val)
            results['current_stats']['max_current'] = max(results['current_stats']['max_current'], current_val)
            results['current_stats']['total_current'] += current_val
            
            # Categorize by component type
            if 'CPU' in sensor_name.upper():
                component_type = 'CPU'
            elif 'DDR' in sensor_name.upper() or 'MEMORY' in sensor_name.upper():
                component_type = 'Memory'
            elif 'FAN' in sensor_name.upper():
                component_type = 'Fan'
            elif 'PSU' in sensor_name.upper() or 'POWER' in sensor_name.upper():
                component_type = 'Power'
            else:
                component_type = 'Other'
                
            if component_type not in components:
                components[component_type] = []
            components[component_type].append({
                'sensor': sensor_name,
                'current': current_val,
                'warning': warning == 'true'
            })
            
        except ValueError:
            pass
        
        # Check warning status
        is_warning = warning == 'true'
        
        # Validate against thresholds
        is_threshold_valid, threshold_issues = validate_current_thresholds(sensor)
        
        # Determine sensor status
        if is_warning:
            results['warning_sensors'] += 1
            if any('CRITICAL' in issue for issue in threshold_issues):
                results['critical_sensors'] += 1
                status = "CRITICAL WARNING"
                results['critical_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'current': float(current),
                    'current_raw': current_raw,
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
            else:
                status = "WARNING"
                results['warning_sensor_list'].append({
                    'sensor_name': sensor_name,
                    'current': float(current),
                    'current_raw': current_raw,
                    'warning': warning,
                    'issues': threshold_issues,
                    'timestamp': timestamp
                })
        else:
            status = "OK"
            # Even if warning is False, check if current is actually out of range
            if threshold_issues:
                status = f"OK (but {'; '.join(threshold_issues)})"
        
        sensor_result = {
            'sensor_name': sensor_name,
            'current': current,
            'current_raw': current_raw,
            'warning': warning,
            'timestamp': timestamp,
            'status': status,
            'issues': threshold_issues,
            'valid': not is_warning
        }
        results['sensor_results'].append(sensor_result)
    
    # Calculate current statistics
    if current_readings:
        results['current_stats']['avg_current'] = sum(current_readings) / len(current_readings)
        results['current_stats']['current_readings'] = current_readings
    else:
        results['current_stats']['min_current'] = 0.0
        results['current_stats']['max_current'] = 0.0
    
    # Component analysis
    results['component_analysis'] = components
    
    # Create summary
    results['summary'] = {
        'total_sensors': results['total_sensors'],
        'valid_sensors': results['valid_sensors'],
        'skipped_sensors': results['skipped_sensors'],
        'warning_sensors': results['warning_sensors'],
        'critical_sensors': results['critical_sensors'],
        'warning_rate': (results['warning_sensors'] / results['valid_sensors'] * 100) if results['valid_sensors'] > 0 else 0,
        'total_current_consumption': results['current_stats']['total_current'],
        'overall_status': 'FAIL' if results['warning_sensors'] > 0 else 'PASS'
    }
    results['overall_valid'] = False if results['warning_sensors'] > 0 else True
    
    return results

def print_current_validation_results(results: Dict[str, any], show_all: bool = True):
    """
    Print formatted current sensor validation results
    
    Args:
        results (Dict): Validation results from validate_all_current_sensors
        show_all (bool): Whether to show all sensors or just warnings/failures
    """
    print("=" * 110)
    print("CURRENT SENSOR WARNING VALIDATION RESULTS")
    print("=" * 110)
    print(f"Validation Rule: Check if any current sensor has Warning = True")
    print(f"Total Sensors: {results['summary']['total_sensors']}")
    print(f"Valid Sensors: {results['summary']['valid_sensors']}")
    print(f"Skipped Sensors: {results['summary']['skipped_sensors']}")
    print(f"Warning Sensors: {results['summary']['warning_sensors']}")
    print(f"Critical Sensors: {results['summary']['critical_sensors']}")
    
    if results['valid_sensors'] > 0:
        print(f"Warning Rate: {results['summary']['warning_rate']:.1f}%")
    else:
        print("Warning Rate: N/A (no valid sensors)")
    
    print(f"Overall Status: {results['summary']['overall_status']}")
    
    # Current statistics
    current_stats = results['current_stats']
    if current_stats['current_readings']:
        print(f"Current Range: {current_stats['min_current']:.0f}mA to {current_stats['max_current']:.0f}mA")
        print(f"Average Current: {current_stats['avg_current']:.0f}mA")
        print(f"Total Power Consumption: {current_stats['total_current']:.0f}mA")
    
    print("-" * 110)
    
    # Component analysis
    if results['component_analysis']:
        print("COMPONENT CURRENT ANALYSIS:")
        for component_type, sensors in results['component_analysis'].items():
            warning_count = sum(1 for s in sensors if s['warning'])
            total_current = sum(s['current'] for s in sensors)
            avg_current = total_current / len(sensors) if sensors else 0
            print(f"  {component_type}: {len(sensors)} sensors, {warning_count} warnings, Total: {total_current:.0f}mA, Avg: {avg_current:.0f}mA")
        print()
    
    # Show skipped sensors
    if results['skipped_sensor_list']:
        print("SKIPPED SENSORS (N/A values detected):")
        print("-" * 70)
        for skipped in results['skipped_sensor_list']:
            print(f"  {skipped['sensor_name']}: {skipped['reason']}")
        print()
    
    if show_all and results['sensor_results']:
        print("ALL SENSOR VALIDATION RESULTS:")
        print(f"{'Sensor Name':<18} {'Current':<12} {'Warning':<8} {'Status':<25} {'Timestamp':<18}")
        print("-" * 110)
        
        for sensor in results['sensor_results']:
            sensor_name = sensor['sensor_name'][:17]
            current = sensor['current_raw'] if 'current_raw' in sensor else f"{sensor['current']}mA"
            warning = sensor['warning']
            status = sensor['status'][:24]
            timestamp = sensor['timestamp'][:17]
            
            print(f"{sensor_name:<18} {current:<12} {warning:<8} {status:<25} {timestamp:<18}")
    
    # Show warning sensors
    if results['warning_sensor_list']:
        print("\n" + "=" * 110)
        print(f"WARNING SENSORS ({len(results['warning_sensor_list'])} sensors):")
        print("=" * 110)
        
        for warning_sensor in results['warning_sensor_list']:
            print(f"Sensor: {warning_sensor['sensor_name']}")
            print(f"  Current: {warning_sensor['current_raw']}")
            print(f"  Warning Status: {warning_sensor['warning']}")
            print(f"  Timestamp: {warning_sensor['timestamp']}")
            if warning_sensor['issues']:
                print(f"  Issues: {'; '.join(warning_sensor['issues'])}")
            print()
    
    # Show critical sensors
    if results['critical_sensor_list']:
        print("\n" + "=" * 110)
        print(f"CRITICAL SENSORS ({len(results['critical_sensor_list'])} sensors):")
        print("=" * 110)
        
        for critical_sensor in results['critical_sensor_list']:
            print(f"Sensor: {critical_sensor['sensor_name']}")
            print(f"  Current: {critical_sensor['current_raw']}")
            print(f"  Warning Status: {critical_sensor['warning']}")
            print(f"  Timestamp: {critical_sensor['timestamp']}")
            if critical_sensor['issues']:
                print(f"  Issues: {'; '.join(critical_sensor['issues'])}")
            print()
    
    if results['warning_sensors'] == 0 and results['valid_sensors'] > 0:
        print("\n✓ All current sensors are operating normally (Warning = False)")
    elif results['valid_sensors'] == 0:
        print("\n⚠ WARNING: No valid sensors found for validation")

def verify_current_sensor_data(sensor_output):
    """
    Spytest integration function for current sensor validation
    
    Args:
        dut: Device under test
        
    Returns:
        Dict: Validation results
    """
    try:
        # Parse and validate current sensor data
        sensor_data = parse_current_sensor_data(sensor_output)
        
        if not sensor_data:
            st.error("Failed to parse current sensor data")
            return {"success": False, "error": "Failed to parse current sensor data"}
        
        # Perform validation
        results = validate_all_current_sensors(sensor_data)
        
        # Log results
        st.log(f"Current Sensor Validation Results:")
        st.log(f"  Total Sensors: {results['summary']['total_sensors']}")
        st.log(f"  Valid Sensors: {results['summary']['valid_sensors']}")
        st.log(f"  Warning Sensors: {results['summary']['warning_sensors']}")
        st.log(f"  Critical Sensors: {results['summary']['critical_sensors']}")
        st.log(f"  Overall Status: {results['summary']['overall_status']}")
        
        # Log current statistics
        current_stats = results['current_stats']
        if current_stats['current_readings']:
            st.log(f"  Current Range: {current_stats['min_current']:.0f}mA to {current_stats['max_current']:.0f}mA")
            st.log(f"  Total Power Consumption: {current_stats['total_current']:.0f}mA")
        
        # Log component analysis
        for component_type, sensors in results['component_analysis'].items():
            warning_count = sum(1 for s in sensors if s['warning'])
            total_current = sum(s['current'] for s in sensors)
            if warning_count > 0:
                st.log(f"  {component_type}: {warning_count}/{len(sensors)} sensors in warning, {total_current:.0f}mA total")
        
        # Log warning sensors
        if results['warning_sensor_list']:
            st.error(f"Warning sensors detected ({len(results['warning_sensor_list'])}):")
            for warning_sensor in results['warning_sensor_list']:
                st.error(f"  {warning_sensor['sensor_name']}: {warning_sensor['current_raw']} (Warning = {warning_sensor['warning']})")
        
        # Log critical sensors
        if results['critical_sensor_list']:
            st.error(f"Critical sensors detected ({len(results['critical_sensor_list'])}):")
            for critical_sensor in results['critical_sensor_list']:
                st.error(f"  {critical_sensor['sensor_name']}: {critical_sensor['current_raw']} (CRITICAL)")
        
        if results['warning_sensors'] == 0:
            st.log("✓ All current sensors operating normally")
        
        return results
        
    except Exception as e:
        if 'st' in locals():
            st.error(f"Current sensor validation error: {e}")
        return results

def check_sensor_data(CfgDataG, entity):
    '''
    '''
    match entity:
        case "temperature":
            cmd = "show platform temperature"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get temperature sensor data from device")
                return False
            result = verify_temperature_sensor_data(output)
            if result.get('total_sensors', 0) == 0 or result.get('skipped_sensors', 0) > 0:
                report_fail(f"{CfgDataG.logprefix}: Validation of temperature sensor failed")

        case "temperature_warning":
            cmd = "show platform temperature"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get temperature sensor data from device")
                return False
            result = verify_temperature_sensor_data(output)

            total = result.get('total_sensors', 0)
            skipped = result.get('skipped_sensors', 0)
            overall_valid = result.get('overall_valid', False)
            if total == 0 or skipped > 0 or not overall_valid:
                report_fail(f"{CfgDataG.logprefix}: Validation of temperature sensor failed")

        case "voltage":
            cmd = "show platform voltage"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get voltage sensor data from device")
                return False
            result = verify_voltage_sensor_data(output)
            if result.get('total_sensors', 0) == 0 or result.get('skipped_sensors', 0) > 0:
                report_fail(f"{CfgDataG.logprefix}: Validation of voltage sensor failed")

        case "voltage_warning":
            cmd = "show platform voltage"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get voltage sensor data from device")
                return False
            result = verify_voltage_sensor_data(output)

            total = result.get('total_sensors', 0)
            skipped = result.get('skipped_sensors', 0)
            overall_valid = result.get('overall_valid', False)
            if total == 0 or skipped > 0 or not overall_valid:
                report_fail(f"{CfgDataG.logprefix}: Validation of voltage sensor failed")
            
        case "current":
            cmd = "show platform current"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get current sensor data from device")
                return False
            result = verify_current_sensor_data(output)
            if result.get('total_sensors', 0) == 0 or result.get('skipped_sensors', 0) > 0:
                report_fail(f"{CfgDataG.logprefix}: Validation of current sensor failed")

        case "current_warning":
            cmd = "show platform current"
            output = st.config(CfgDataG.dut, cmd)
            if not output:
                st.error("Failed to get current sensor data from device")
                return False
            result = verify_current_sensor_data(output)

            total = result.get('total_sensors', 0)
            skipped = result.get('skipped_sensors', 0)
            overall_valid = result.get('overall_valid', False)
            if total == 0 or skipped > 0 or not overall_valid:
                report_fail(f"{CfgDataG.logprefix}: Validation of current sensor failed")
            
        case _:  # Default case
            st.error(f"Unknown test type: {entity}")
            return False

    return True

def test_sensor_check(CfgDataG, sensor_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {sensor_check} check")

    for check_item in sensor_check:
        if not check_sensor_data(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
