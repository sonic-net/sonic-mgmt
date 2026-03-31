import pytest
import re
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def psu_data_check_hooks(request):
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

    
def parse_platform_psu_output(psu_output):
    """
    Parse 'show platform psustatus' output into a structured dictionary
    
    Args:
        psu_output (str): Raw output from 'show platform psustatus' command
        
    Returns:
        dict: Parsed PSU information
    """
    psu_data = {
        'psu_units': [],
        'total_psus': 0,
        'parsing_errors': []
    }
    
    try:
        lines = psu_output.strip().split('\n')
        
        #Remove last line
        lines = lines[:-1]

        # Find header line to understand column positions
        header_line = None
        data_start_idx = 0
        
        for idx, line in enumerate(lines):
            if 'PSU' in line and 'Model' in line and 'Status' in line:
                header_line = line
                data_start_idx = idx + 1
                break
        
        if not header_line:
            psu_data['parsing_errors'].append("Could not find header line in PSU output")
            return psu_data
        
        # Find separator line (dashes)
        for idx in range(data_start_idx, len(lines)):
            if '---' in lines[idx]:
                data_start_idx = idx + 1
                break
        
        # Parse PSU data
        for line_idx in range(data_start_idx, len(lines)):
            line = lines[line_idx].strip()
            
            if not line:
                continue
            
            # Split line into columns (handle multiple spaces)
            parts = re.split(r'\s{2,}', line)
            
            if len(parts) >= 9:
                psu_info = {
                    'psu': parts[0].strip(),
                    'model': parts[1].strip(),
                    'serial': parts[2].strip(),
                    'hw_rev': parts[3].strip(),
                    'voltage': parts[4].strip(),
                    'current': parts[5].strip(),
                    'power': parts[6].strip(),
                    'status': parts[7].strip(),
                    'led': parts[8].strip()
                }
                
                psu_data['psu_units'].append(psu_info)
                psu_data['total_psus'] += 1
            else:
                psu_data['parsing_errors'].append(f"Invalid PSU line format: {line}")
        
        return psu_data
        
    except Exception as e:
        psu_data['parsing_errors'].append(f"Error parsing platform PSU output: {e}")
        return psu_data

def validate_psu_model_presence(psu_units):
    """
    Validate that every PSU entry has a Model field (not empty or N/A)
    
    Args:
        psu_units (list): List of PSU information
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'missing_model_psus': [],
        'model_summary': {},
        'errors': []
    }
    
    if not psu_units:
        result['errors'].append("No PSU units found")
        result['valid'] = False
        return result
    
    # Check model field for each PSU
    for psu in psu_units:
        model = psu['model'].strip()
        
        # Track all models
        if model not in result['model_summary']:
            result['model_summary'][model] = []
        result['model_summary'][model].append(psu['psu'])
        
        # Check if model is missing or invalid
        if not model or model in ['N/A', 'n/a', '', '-', 'Unknown']:
            result['missing_model_psus'].append({
                'psu': psu['psu'],
                'model': model if model else 'EMPTY'
            })
            result['valid'] = False
    
    if result['missing_model_psus']:
        result['errors'].append(f"Found {len(result['missing_model_psus'])} PSU units with missing or invalid model")
    
    return result

def validate_psu_serial_presence(psu_units):
    """
    Validate that every PSU entry has a Serial field (not empty or N/A)
    
    Args:
        psu_units (list): List of PSU information
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'missing_serial_psus': [],
        'serial_summary': [],
        'errors': []
    }
    
    if not psu_units:
        result['errors'].append("No PSU units found")
        result['valid'] = False
        return result
    
    # Check serial field for each PSU
    for psu in psu_units:
        serial = psu['serial'].strip()
        
        # Track serial info
        result['serial_summary'].append({
            'psu': psu['psu'],
            'serial': serial,
            'length': len(serial)
        })
        
        # Check if serial is missing or invalid
        if not serial or serial in ['N/A', 'n/a', '', '-', 'Unknown']:
            result['missing_serial_psus'].append({
                'psu': psu['psu'],
                'serial': serial if serial else 'EMPTY'
            })
            result['valid'] = False
    
    if result['missing_serial_psus']:
        result['errors'].append(f"Found {len(result['missing_serial_psus'])} PSU units with missing or invalid serial")
    
    return result

def validate_psu_status_ok(psu_units):
    """
    Validate that every PSU entry has Status as 'OK'
    
    Args:
        psu_units (list): List of PSU information
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'non_ok_psus': [],
        'status_summary': {},
        'errors': []
    }
    
    if not psu_units:
        result['errors'].append("No PSU units found")
        result['valid'] = False
        return result
    
    # Check status for each PSU
    for psu in psu_units:
        status = psu['status'].strip()
        
        # Track all statuses
        if status not in result['status_summary']:
            result['status_summary'][status] = []
        result['status_summary'][status].append(psu['psu'])
        
        # Check if status is not OK
        if status != 'OK':
            result['non_ok_psus'].append({
                'psu': psu['psu'],
                'status': status,
                'model': psu['model']
            })
            result['valid'] = False
    
    if result['non_ok_psus']:
        result['errors'].append(f"Found {len(result['non_ok_psus'])} PSU units with non-OK status")
    
    return result

def validate_required_psu_fields(psu_units):
    """
    Comprehensive validation of required PSU fields: Model, Serial, and Status
    
    Args:
        psu_units (list): List of PSU information
        
    Returns:
        dict: Combined validation result
    """
    combined_result = {
        'overall_valid': True,
        'individual_results': {},
        'failed_psus': [],
        'errors': [],
        'field_summary': {}
    }
    
    if not psu_units:
        combined_result['overall_valid'] = False
        combined_result['errors'].append("No PSU units found for validation")
        return combined_result
    
    # Validate Model presence
    model_result = validate_psu_model_presence(psu_units)
    combined_result['individual_results']['model_presence'] = model_result
    if not model_result['valid']:
        combined_result['overall_valid'] = False
        combined_result['errors'].extend(model_result['errors'])
    
    # Validate Serial presence
    serial_result = validate_psu_serial_presence(psu_units)
    combined_result['individual_results']['serial_presence'] = serial_result
    if not serial_result['valid']:
        combined_result['overall_valid'] = False
        combined_result['errors'].extend(serial_result['errors'])
    
    # Validate Status OK
    status_result = validate_psu_status_ok(psu_units)
    combined_result['individual_results']['status_ok'] = status_result
    if not status_result['valid']:
        combined_result['overall_valid'] = False
        combined_result['errors'].extend(status_result['errors'])
    
    # Create comprehensive failed PSU list
    failed_psu_set = set()
    
    # Add PSUs with missing model
    for psu_info in model_result.get('missing_model_psus', []):
        failed_psu_set.add(psu_info['psu'])
    
    # Add PSUs with missing serial
    for psu_info in serial_result.get('missing_serial_psus', []):
        failed_psu_set.add(psu_info['psu'])
    
    # Add PSUs with non-OK status
    for psu_info in status_result.get('non_ok_psus', []):
        failed_psu_set.add(psu_info['psu'])
    
    # Generate detailed failed PSU information
    for psu in psu_units:
        if psu['psu'] in failed_psu_set:
            psu_issues = []
            
            # Check what issues this PSU has
            if not psu['model'].strip() or psu['model'].strip() in ['N/A', 'n/a', '', '-', 'Unknown']:
                psu_issues.append("missing_model")
            
            if not psu['serial'].strip() or psu['serial'].strip() in ['N/A', 'n/a', '', '-', 'Unknown']:
                psu_issues.append("missing_serial")
            
            if psu['status'].strip() != 'OK':
                psu_issues.append(f"status_{psu['status'].strip()}")
            
            combined_result['failed_psus'].append({
                'psu': psu['psu'],
                'model': psu['model'],
                'serial': psu['serial'],
                'status': psu['status'],
                'issues': psu_issues
            })
    
    # Create field summary
    combined_result['field_summary'] = {
        'models': model_result.get('model_summary', {}),
        'statuses': status_result.get('status_summary', {}),
        'total_psus': len(psu_units),
        'valid_psus': len(psu_units) - len(combined_result['failed_psus'])
    }
    
    return combined_result

def validate_platform_psustatus_data(psu_output):
    """
    Validate platform PSU requirements: Model, Serial, and Status OK
    
    Args:
        psu_output (str): Raw output from 'show platform psustatus' command
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'validation_results': {},
        'errors': [],
        'warnings': [],
        'psu_summary': {}
    }
    
    # Parse PSU output
    psu_data = parse_platform_psu_output(psu_output)
    
    # Check for parsing errors
    if psu_data.get('parsing_errors'):
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(psu_data['parsing_errors'])
        return validation_result
    
    if not psu_data['psu_units']:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("No PSU units found in output")
        return validation_result
    
    # Store PSU summary
    validation_result['psu_summary'] = {
        'total_psus': psu_data['total_psus'],
        'psu_list': [psu['psu'] for psu in psu_data['psu_units']]
    }
    
    # Validate required fields
    field_validation = validate_required_psu_fields(psu_data['psu_units'])
    validation_result['validation_results'] = field_validation
    
    if not field_validation['overall_valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(field_validation['errors'])
    
    # Additional checks
    if psu_data['total_psus'] < 2:
        validation_result['warnings'].append("Expected at least 2 PSUs for redundancy")
    
    # Check for model consistency (warning only)
    models = field_validation.get('field_summary', {}).get('models', {})
    if len(models) > 1:
        validation_result['warnings'].append(f"Multiple PSU models detected: {list(models.keys())}")
    
    return validation_result

def check_psu_data(CfgDataG, entity):
    '''
    '''
    match entity:
        case "psu_status":
            cmd = "show platform psustatus"
            output = st.config(CfgDataG.dut, cmd)
            if output:
               result = validate_platform_psustatus_data(output)
            else:
                st.error("Could not retrieve platform psustatus information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform psustatus information from device")
                return
            if not result['overall_valid']:
                report_fail(f"{CfgDataG.logprefix}: Validation of platform psustatus failed")

        case "psu_voltage":
            cmd = "show platform psustatus"
            output = st.config(CfgDataG.dut, cmd)
            if output:
               result = validate_platform_psustatus_data(output)
            else:
                st.error("Could not retrieve platform psustatus information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform psustatus information from device")
                return
            if not result['overall_valid']:
                report_fail(f"{CfgDataG.logprefix}: Validation of platform psustatus failed")

            
        case "fan_speed":
            pass 

        case _:  # Default case
            st.error(f"Unknown test type: {entity}")
            return False

    return True

def test_psu_check(CfgDataG, psu_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {psu_check} check")

    for item in psu_check:
        if not check_psu_data(CfgDataG, item):
            report_fail(f"{CfgDataG.logprefix}: Validation of psu {item} failed")
            continue
        else:
            st.log(f"{CfgDataG.logprefix}: {item} data ok")

    return True
