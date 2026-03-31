import re
import sys
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from apis.common.sonic_hooks import SonicHooks
from typing import List, Dict, Tuple, Optional
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def fan_data_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** PLATFORM DATA *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

    
def parse_platform_fan_output(fan_output):
    """
    Parse 'show platform fan' output into a structured dictionary
    
    Args:
        fan_output (str): Raw output from 'show platform fan' command
        
    Returns:
        dict: Parsed fan information
    """
    fan_data = {
        'psu_fans': [],
        'fantray_fans': [],
        'total_fans': 0,
        'total_fantrays': 0
    }
    
    try:
        lines = fan_output.strip().split('\n')
        
        # Find header line to understand column positions
        header_line = None
        data_start_idx = 0
        
        for idx, line in enumerate(lines):
            if 'Drawer' in line and 'FAN' in line and 'Status' in line:
                header_line = line
                data_start_idx = idx + 1
                break
        
        if not header_line:
            st.error("Could not find header line in fan output")
            return fan_data
        
        # Find separator line (dashes)
        for idx in range(data_start_idx, len(lines)):
            if '---' in lines[idx]:
                data_start_idx = idx + 1
                break
        
        # Parse fan data
        for line_idx in range(data_start_idx, len(lines)):
            line = lines[line_idx].strip()
            
            if not line:
                continue
            
            # Split line into columns (handle multiple spaces)
            parts = re.split(r'\s{2,}', line)
            
            if len(parts) >= 8:
                fan_info = {
                    'drawer': parts[0].strip(),
                    'led': parts[1].strip(),
                    'fan': parts[2].strip(),
                    'speed': parts[3].strip(),
                    'direction': parts[4].strip(),
                    'presence': parts[5].strip(),
                    'status': parts[6].strip(),
                    'timestamp': parts[7].strip()
                }
                
                # Categorize fans
                if 'PSU' in fan_info['fan']:
                    fan_data['psu_fans'].append(fan_info)
                elif 'fantray' in fan_info['fan']:
                    fan_data['fantray_fans'].append(fan_info)
                
                fan_data['total_fans'] += 1
        
        # Count unique fantrays
        fantrays = set()
        for fan in fan_data['fantray_fans']:
            if fan['drawer'] != 'N/A':
                fantrays.add(fan['drawer'])
        fan_data['total_fantrays'] = len(fantrays)
        
        return fan_data
        
    except Exception as e:
        st.error(f"Error parsing platform fan output: {e}")
        return fan_data

def validate_fantray_direction_consistency(fantray_fans):
    """
    Validate that all fantray fans have the same direction
    
    Args:
        fantray_fans (list): List of fantray fan information
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'directions': {},
        'inconsistent_fans': [],
        'errors': []
    }
    
    if not fantray_fans:
        result['errors'].append("No fantray fans found")
        result['valid'] = False
        return result
    
    # Collect all directions
    directions = []
    for fan in fantray_fans:
        direction = fan['direction']
        if direction != 'N/A':
            directions.append(direction)
            if direction not in result['directions']:
                result['directions'][direction] = []
            result['directions'][direction].append(fan['fan'])
    
    # Check for consistency
    unique_directions = list(set(directions))
    
    if len(unique_directions) == 0:
        result['errors'].append("All fantray fans have 'N/A' direction")
        result['valid'] = False
    elif len(unique_directions) > 1:
        result['errors'].append(f"Inconsistent fan directions found: {unique_directions}")
        result['valid'] = False
        
        # Find inconsistent fans
        primary_direction = max(result['directions'].keys(), 
                              key=lambda x: len(result['directions'][x]))
        
        for fan in fantray_fans:
            if fan['direction'] != primary_direction and fan['direction'] != 'N/A':
                result['inconsistent_fans'].append({
                    'fan': fan['fan'],
                    'direction': fan['direction'],
                    'expected': primary_direction
                })
    
    return result

def validate_fantray_status_ok(fantray_fans):
    """
    Validate that all fantray fans have status 'OK'
    
    Args:
        fantray_fans (list): List of fantray fan information
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'failed_fans': [],
        'status_summary': {},
        'errors': []
    }
    
    if not fantray_fans:
        result['errors'].append("No fantray fans found")
        result['valid'] = False
        return result
    
    # Check status for each fan
    for fan in fantray_fans:
        status = fan['status']
        
        if status not in result['status_summary']:
            result['status_summary'][status] = []
        result['status_summary'][status].append(fan['fan'])
        
        if status != 'OK':
            result['failed_fans'].append({
                'fan': fan['fan'],
                'status': status,
                'drawer': fan['drawer']
            })
            result['valid'] = False
    
    if result['failed_fans']:
        result['errors'].append(f"Found {len(result['failed_fans'])} fantray fans with non-OK status")
    
    return result


def validate_platform_fan_speed(CfgDataG):
    """
    Validate fan speeds against acceptable ranges based on direction

    Args:
        CfgDataG (Dict): ConfigData including Speed ranges

    Returns:
        Dict: Validation results with detailed analysis
    """
    fantray_fans = CfgDataG['fan_data']['fantray_fans']
    speed_ranges = CfgDataG['fan_data']['pwm_range']
    results = {
        'total_fans': len(fantray_fans),
        'passed_fans': [],
        'failed_fans': [],
        'speed_violations': [],
        'status_issues': [],
        'presence_issues': [],
        'overall_status': 'UNKNOWN'
    }

    # Initialize direction counters

    for fan_data in fantray_fans:
        fan_name = fan_data.get('fan', 'unknown')
        drawer = fan_data.get('drawer', 'unknown')
        direction = fan_data.get('direction', '').lower()
        speed_str = fan_data.get('speed', '0%')
        status = fan_data.get('status', 'UNKNOWN')
        presence = fan_data.get('presence', 'UNKNOWN')
        led = fan_data.get('led', 'unknown')
        timestamp = fan_data.get('timestamp', 'unknown')

        # Extract numeric speed value
        try:
            speed_numeric = int(speed_str.replace('%', ''))
        except (ValueError, AttributeError):
            speed_numeric = 0

        # Fan validation record
        fan_record = {
            'fan': fan_name,
            'drawer': drawer,
            'direction': direction,
            'speed': speed_str,
            'speed_numeric': speed_numeric,
            'status': status,
            'presence': presence,
            'led': led,
            'timestamp': timestamp,
            'validation_result': 'UNKNOWN'
        }

        # Check presence first
        if presence.lower() != 'present':
            results['presence_issues'].append({
                'fan': fan_name,
                'issue': f"Fan not present: {presence}",
                'drawer': drawer
            })
            fan_record['validation_result'] = 'PRESENCE_FAIL'
            results['failed_fans'].append(fan_record)
            continue

        # Check status
        if status.upper() != 'OK':
            results['status_issues'].append({
                'fan': fan_name,
                'issue': f"Fan status not OK: {status}",
                'drawer': drawer
            })
            fan_record['validation_result'] = 'STATUS_FAIL'
            results['failed_fans'].append(fan_record)
            continue

        # Determine speed range based on direction
        speed_range = None
        if direction == 'intake':
            speed_range = speed_ranges.get('FAN_DIRECTION_INTAKE')
        elif direction == 'exhaust':
            speed_range = speed_ranges.get('FAN_DIRECTION_EXHAUST')

        if not speed_range:
            results['speed_violations'].append({
                'fan': fan_name,
                'issue': f"Unknown fan direction: {direction}",
                'speed': speed_str,
                'drawer': drawer
            })
            fan_record['validation_result'] = 'DIRECTION_UNKNOWN'
            results['failed_fans'].append(fan_record)
            continue

        # Validate speed is within range
        min_speed, max_speed = speed_range[0], speed_range[1]

        if min_speed <= speed_numeric <= max_speed:
            fan_record['validation_result'] = 'PASS'
            results['passed_fans'].append(fan_record)
        else:
            results['speed_violations'].append({
                'fan': fan_name,
                'issue': f"Speed {speed_str} outside range [{min_speed}%-{max_speed}%] for {direction}",
                'speed': speed_str,
                'expected_range': f"{min_speed}%-{max_speed}%",
                'drawer': drawer,
                'direction': direction
            })
            fan_record['validation_result'] = 'SPEED_FAIL'
            results['failed_fans'].append(fan_record)

    # Determine overall status
    if len(results['failed_fans']) == 0:
        results['overall_status'] = 'PASS'
    else:
        results['overall_status'] = 'FAIL'

    return results

def print_fan_validation_results(results: Dict[str, any], show_details: bool = True):
    """
    Print formatted fan validation results

    Args:
        results (Dict): Validation results from validate_fan_speeds
        show_details (bool): Whether to show detailed fan information
    """
    print("=" * 100)
    print("FAN SPEED VALIDATION RESULTS")
    print("=" * 100)

    print(f"Overall Status: {results['overall_status']}")
    print(f"Total Fans: {results['total_fans']}")
    print(f"Passed Fans: {len(results['passed_fans'])}")
    print(f"Failed Fans: {len(results['failed_fans'])}")

    if results['total_fans'] > 0:
        pass_rate = (len(results['passed_fans']) / results['total_fans'] * 100)
        print(f"Pass Rate: {pass_rate:.1f}%")

    print("-" * 100)

    # Direction summary
    print("FAN DIRECTION SUMMARY:")
    for direction, summary in results['direction_summary'].items():
        print(f"  {direction.upper()}: {summary['total_fans']} fans, "
              f"{summary['passed_fans']} passed, {summary['failed_fans']} failed "
              f"({summary['pass_rate']:.1f}% pass rate, avg speed: {summary['avg_speed']})")
    print()

    # Show detailed results if requested
    if show_details:
        # Passed fans
        if results['passed_fans']:
            print("✅ PASSED FANS:")
            print(f"{'Fan':<15} {'Drawer':<10} {'Direction':<10} {'Speed':<8} {'Status':<8} {'LED':<8}")
            print("-" * 70)
            for fan in results['passed_fans']:
                print(f"{fan['fan']:<15} {fan['drawer']:<10} {fan['direction']:<10} "
                      f"{fan['speed']:<8} {fan['status']:<8} {fan['led']:<8}")
            print()

        # Failed fans
        if results['failed_fans']:
            print("❌ FAILED FANS:")
            print(f"{'Fan':<15} {'Drawer':<10} {'Direction':<10} {'Speed':<8} {'Result':<15}")
            print("-" * 70)
            for fan in results['failed_fans']:
                print(f"{fan['fan']:<15} {fan['drawer']:<10} {fan['direction']:<10} "
                      f"{fan['speed']:<8} {fan['validation_result']:<15}")
            print()

    # Show violations
    if results['speed_violations']:
        print("⚠️ SPEED VIOLATIONS:")
        for violation in results['speed_violations']:
            print(f"  {violation['fan']} ({violation['drawer']}): {violation['issue']}")
        print()

    if results['status_issues']:
        print("❌ STATUS ISSUES:")
        for issue in results['status_issues']:
            print(f"  {issue['fan']} ({issue['drawer']}): {issue['issue']}")
        print()

    if results['presence_issues']:
        print("❌ PRESENCE ISSUES:")
        for issue in results['presence_issues']:
            print(f"  {issue['fan']} ({issue['drawer']}): {issue['issue']}")
        print()

    # Overall result
    if results['overall_status'] == 'PASS':
        print("✅ ALL FANS PASSED VALIDATION")
    elif results['overall_status'] == 'WARNING':
        print("⚠️ SOME FANS FAILED VALIDATION")
    else:
        print("❌ CRITICAL FAN VALIDATION FAILURES")

def validate_platform_fantray_count(platform_id: str, detected_fantrays: int) -> bool:
    """
    Validate detected fantray count matches platform configuration
    Integrates with platform_edvt_cfg.py
    """
    # Import platform configuration
    from platform_edvt_cfg import get_platform_edvt_cfg

    platform_cfg = get_platform_edvt_cfg(platform_id)
    if not platform_cfg:
        print(f"ERROR: Platform {platform_id} not found in EDVT configuration")
        return False

    expected_fantrays = platform_cfg.get('fantrays', 0)

    if detected_fantrays == expected_fantrays:
        print(f"✓ Platform {platform_id}: Expected {expected_fantrays} fantrays, detected {detected_fantrays}")
        return True
    else:
        print(f"❌ Platform {platform_id}: Expected {expected_fantrays} fantrays, but detected {detected_fantrays}")
        return False

def validate_platform_fan_status(CfgDataG, fan_output):
    """
    Validate all platform fan criteria
    
    Args:
        fan_output (str): Raw output from 'show platform fan' command
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': [],
        'fan_summary': {}
    }
    
    # Parse fan output
    fan_data = parse_platform_fan_output(fan_output)
    
    if not fan_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse platform fan output")
        return validation_result
    
    # Store fan summary
    validation_result['fan_summary'] = {
        'total_fans': fan_data['total_fans'],
        'total_fantrays': fan_data['total_fantrays'],
        'psu_fans': len(fan_data['psu_fans']),
        'fantray_fans': len(fan_data['fantray_fans'])
    }
    
    fantray_fans = fan_data['fantray_fans']
    CfgDataG['fan_data']['fantray_fans'] = fantray_fans
    
    # Validate fantray direction consistency
    direction_result = validate_fantray_direction_consistency(fantray_fans)
    validation_result['results']['direction_consistency'] = direction_result
    if not direction_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(direction_result['errors'])
    
    # Validate fantray status OK
    status_result = validate_fantray_status_ok(fantray_fans)
    validation_result['results']['status_ok'] = status_result
    if not status_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(status_result['errors'])
    
    return validation_result

def check_fan_data(CfgDataG, entity):
    '''
    '''
    match entity:
        case "fan_status":
            cmd = "show platform fan"
            output = st.config(CfgDataG.dut, cmd)
            if output:
                st.log(f"{CfgDataG.logprefix}: Executing fan_status check")
                result = validate_platform_fan_status(CfgDataG, output)
            else:
                st.error("Could not retrieve platform fan information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform fan information from device")
                return
            if not result['overall_valid']: 
                report_fail(f"{CfgDataG.logprefix}: Validation of platform fan failed")
            
        case "fan_speed":
            st.log(f"{CfgDataG.logprefix}: Executing fan_speed check")
            result = validate_platform_fan_speed(CfgDataG)
            if result['overall_status'] != 'PASS':
                return False

        case _:  # Default case
            st.error(f"Unknown test type: {entity}")
            return False

    return True

def test_fan_check(CfgDataG, fan_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {fan_check} check")

    for item in fan_check:
        if not check_fan_data(CfgDataG, item):
            report_fail(f"{CfgDataG.logprefix}: Validation of fanmodule {item} failed")
            continue
        else:
            st.log(f"{CfgDataG.logprefix}: {item} data ok")

    return True
