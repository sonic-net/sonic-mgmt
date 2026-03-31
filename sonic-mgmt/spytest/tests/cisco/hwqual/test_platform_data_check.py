import pytest
import re
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def platform_data_check_hooks(request):
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

def update_result_with_dict(ret_result, test_check, reason):
    d = {}
    d[test_check] = 'Failed'
    d['reason'] = reason
    ret_result.append(d)

def update_result_with_str(ret_result, test_check, reason):
    d = {}
    d[test_check] = 'Failed'
    d['reason'] = reason
    ret_result.append(d)

def parse_platform_info(platform_output):
    """
    Parse platform information output into a dictionary
    
    Args:
        platform_output (str): Raw platform information output
        
    Returns:
        dict: Parsed platform information
    """
    platform_data = {}
    
    try:
        lines = platform_output.strip().split('\n')
        lines = lines[:-1]    
        for line in lines:
            line = line.strip()
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    platform_data[key] = value
        
        return platform_data
        
    except Exception as e:
        st.error(f"Error parsing platform information: {e}")
        return {}

def validate_hwsku(hwsku):
    """
    Validate HwSKU field
    Requirements: Upper case alpha numeric prefixed with Cisco-
    
    Args:
        hwsku (str): HwSKU value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': hwsku,
        'errors': []
    }
    
    if not hwsku:
        result['errors'].append("HwSKU is missing or empty")
        return result
    
    # Check if it starts with "Cisco-"
    if not hwsku.startswith('Cisco-'):
        result['errors'].append(f"HwSKU '{hwsku}' does not start with 'Cisco-'")
    
    # Check if the rest is upper case alphanumeric (after "Cisco-")
    remainder = hwsku[6:]  # Skip "Cisco-"
    if not remainder.replace('-', '').replace('_', '').isalnum():
        result['errors'].append(f"HwSKU '{hwsku}' contains invalid characters (only alphanumeric, '-', '_' allowed)")
    
    # Check if it's in upper case (after "Cisco-")
    if not remainder.isupper():
        result['errors'].append(f"HwSKU '{hwsku}' is not in upper case")
    
    # Additional validation for expected format
    hwsku_pattern = r'^Cisco-[A-Z0-9\-_]+$'
    if not re.match(hwsku_pattern, hwsku):
        result['errors'].append(f"HwSKU '{hwsku}' doesn't match expected pattern")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_asic(asic):
    """
    Validate ASIC field
    Requirements: verify as cisco-8000
    
    Args:
        asic (str): ASIC value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': asic,
        'errors': []
    }
    
    if not asic:
        result['errors'].append("ASIC is missing or empty")
        return result
    
    # Exact match check
    if asic != "cisco-8000":
        result['errors'].append(f"ASIC '{asic}' is not 'cisco-8000'")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_serial_number(serial_number, length):
    """
    Validate Serial Number field
    Requirements: 13 byte alpha numeric
    
    Args:
        serial_number (str): Serial Number value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': serial_number,
        'errors': []
    }
    
    if not serial_number:
        result['errors'].append("Serial Number is missing or empty")
        return result
    
    # Check if alphanumeric
    if not serial_number.isalnum():
        result['errors'].append(f"Serial Number '{serial_number}' is not alphanumeric")
    
    # Check length (13 bytes)
    if len(serial_number) != length:
        result['errors'].append(f"Serial Number '{serial_number}' is {len(serial_number)} bytes, expected {length} bytes")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_model_number(model_number):
    """
    Validate Model Number field
    Requirements: alpha numeric string with -
    
    Args:
        model_number (str): Model Number value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': model_number,
        'errors': []
    }
    
    if not model_number:
        result['errors'].append("Model Number is missing or empty")
        return result
    
    # Check if it contains alpha numeric characters and hyphens
    model_pattern = r'^[A-Za-z0-9\-]+$'
    if not re.match(model_pattern, model_number):
        result['errors'].append(f"Model Number '{model_number}' contains invalid characters (only alphanumeric and '-' allowed)")
    
    # Check if it contains at least one hyphen
    if '-' not in model_number:
        result['errors'].append(f"Model Number '{model_number}' must contain at least one hyphen")
    
    # Check if it doesn't start or end with hyphen
    if model_number.startswith('-') or model_number.endswith('-'):
        result['errors'].append(f"Model Number '{model_number}' cannot start or end with hyphen")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_hardware_revision(hw_revision):
    """
    Validate Hardware Revision field
    Requirements: floating number
    
    Args:
        hw_revision (str): Hardware Revision value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': hw_revision,
        'errors': []
    }
    
    if not hw_revision:
        result['errors'].append("Hardware Revision is missing or empty")
        return result
    
    try:
        # Convert to float to validate it's a valid floating point number
        revision_float = float(hw_revision)
        
        # Check if it's non-negative
        if revision_float < 0:
            result['errors'].append(f"Hardware Revision '{hw_revision}' cannot be negative")
        
        # Check if it's reasonable (between 0 and 100)
        if revision_float > 10:
            result['errors'].append(f"Hardware Revision '{hw_revision}' seems unusually high")
        
    except ValueError:
        result['errors'].append(f"Hardware Revision '{hw_revision}' is not a valid floating point number")
    
    # Check format pattern (should be like 0.12, 1.5, etc.)
    revision_pattern = r'^\d+(\.\d+)?$'
    if not re.match(revision_pattern, hw_revision):
        result['errors'].append(f"Hardware Revision '{hw_revision}' doesn't match expected format")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_platform_summary_data(summary_output):
    """
    Validate all platform information fields
    
    Args:
        platform_output (str): Raw platform information output
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': [],
        'platform_info': {}
    }
    
    # Parse platform information
    platform_data = parse_platform_info(summary_output)
    
    if not platform_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse platform information")
        return validation_result
    
    # Store platform info
    validation_result['platform_info'] = platform_data
    
    # Validate HwSKU
    hwsku_result = validate_hwsku(platform_data.get('HwSKU'))
    validation_result['results']['hwsku'] = hwsku_result
    if not hwsku_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(hwsku_result['errors'])
    
    # Validate ASIC
    asic_result = validate_asic(platform_data.get('ASIC'))
    validation_result['results']['asic'] = asic_result
    if not asic_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(asic_result['errors'])
    
    # Validate Serial Number
    serial_result = validate_serial_number(platform_data.get('Serial Number'),11)
    validation_result['results']['serial_number'] = serial_result
    if not serial_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(serial_result['errors'])
    
    # Validate Model Number
    model_result = validate_model_number(platform_data.get('Model Number'))
    validation_result['results']['model_number'] = model_result
    if not model_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(model_result['errors'])
    
    # Validate Hardware Revision
    hw_rev_result = validate_hardware_revision(platform_data.get('Hardware Revision'))
    validation_result['results']['hardware_revision'] = hw_rev_result
    if not hw_rev_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(hw_rev_result['errors'])
    
    # Additional checks
    if not platform_data.get('Platform'):
        validation_result['warnings'].append("Platform field is missing")
    
    if not platform_data.get('ASIC Count'):
        validation_result['warnings'].append("ASIC Count field is missing")
    else:
        try:
            asic_count = int(platform_data.get('ASIC Count'))
            if asic_count != 1:
                validation_result['warnings'].append(f"ASIC Count is {asic_count}, expected 1")
        except ValueError:
            validation_result['warnings'].append("ASIC Count is not a valid integer")
    
    return validation_result

def parse_tlvinfo_eeprom(eeprom_output):
    """
    Parse TlvInfo EEPROM output into a dictionary
    
    Args:
        eeprom_output (str): Raw TlvInfo EEPROM data output
        
    Returns:
        dict: Parsed TlvInfo data
    """
    tlv_data = {
        'header': {},
        'tlv_fields': {},
        'checksum_valid': False
    }
    
    try:
        lines = eeprom_output.strip().split('\n')
        lines = lines[:-1]    
        # Parse header information
        for line in lines:
            line = line.strip()
            
            if 'Id String:' in line:
                tlv_data['header']['id_string'] = line.split(':', 1)[1].strip()
            elif 'Version:' in line:
                tlv_data['header']['version'] = line.split(':', 1)[1].strip()
            elif 'Total Length:' in line:
                tlv_data['header']['total_length'] = line.split(':', 1)[1].strip()
            elif '(checksum valid)' in line:
                tlv_data['checksum_valid'] = True
            elif '(checksum invalid)' in line:
                tlv_data['checksum_valid'] = False
        
        # Parse TLV fields (after header lines and table header)
        parsing_tlv = False
        for line in lines:
            line = line.strip()
            
            # Skip header lines and table header
            if line.startswith('TLV Name') or line.startswith('---'):
                parsing_tlv = True
                continue
            
            if parsing_tlv and line and not line.startswith('(checksum'):
                # Parse TLV entry: "Product Name         0x21       12  8122-64EHF-O"
                parts = line.split()
                if len(parts) >= 4:
                    # Handle multi-word TLV names
                    if parts[0] in ['Product', 'Part', 'Serial', 'Base', 'Device', 
                                   'Platform', 'MAC', 'Manufacture', 'Vendor']:
                        if parts[0] == 'Product' and parts[1] == 'Name':
                            tlv_name = 'Product Name'
                            code_idx = 2
                        elif parts[0] == 'Part' and parts[1] == 'Number':
                            tlv_name = 'Part Number'
                            code_idx = 2
                        elif parts[0] == 'Serial' and parts[1] == 'Number':
                            tlv_name = 'Serial Number'
                            code_idx = 2
                        elif parts[0] == 'Base' and parts[1] == 'MAC' and parts[2] == 'Address':
                            tlv_name = 'Base MAC Address'
                            code_idx = 3
                        elif parts[0] == 'Device' and parts[1] == 'Version':
                            tlv_name = 'Device Version'
                            code_idx = 2
                        elif parts[0] == 'Platform' and parts[1] == 'Name':
                            tlv_name = 'Platform Name'
                            code_idx = 2
                        elif parts[0] == 'MAC' and parts[1] == 'Addresses':
                            tlv_name = 'MAC Addresses'
                            code_idx = 2
                        elif parts[0] == 'Manufacture' and parts[1] == 'Country':
                            tlv_name = 'Manufacture Country'
                            code_idx = 2
                        elif parts[0] == 'Vendor' and parts[1] == 'Name':
                            tlv_name = 'Vendor Name'
                            code_idx = 2
                        else:
                            tlv_name = parts[0]
                            code_idx = 1
                        
                        if len(parts) > code_idx + 2:
                            code = parts[code_idx]
                            length = parts[code_idx + 1]
                            value = ' '.join(parts[code_idx + 2:])
                            
                            tlv_data['tlv_fields'][tlv_name] = {
                                'code': code,
                                'length': length,
                                'value': value
                            }
                    else:
                        # Single word TLV names
                        tlv_name = parts[0]
                        if len(parts) >= 4:
                            code = parts[1]
                            length = parts[2]
                            value = ' '.join(parts[3:])
                            
                            tlv_data['tlv_fields'][tlv_name] = {
                                'code': code,
                                'length': length,
                                'value': value
                            }
        
        return tlv_data
        
    except Exception as e:
        st.error(f"Error parsing TlvInfo EEPROM data: {e}")
        return {}

def validate_product_name(product_name):
    """
    Validate Product Name field
    Requirements: alpha numeric
    
    Args:
        product_name (str): Product Name value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': product_name,
        'errors': []
    }
    
    if not product_name:
        result['errors'].append("Product Name is missing or empty")
        return result
    
    # Check if alphanumeric (allowing hyphens for product names like 8122-64EHF-O)
    alphanumeric_pattern = r'^[A-Za-z0-9\-]+$'
    if not re.match(alphanumeric_pattern, product_name):
        result['errors'].append(f"Product Name '{product_name}' contains invalid characters (only alphanumeric and '-' allowed)")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_serial_number_tlv(serial_number, expected_length=11):
    """
    Validate Serial Number field
    Requirements: alpha numeric and 11 bytes
    
    Args:
        serial_number (str): Serial Number value
        expected_length (int): Expected length in bytes
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': serial_number,
        'errors': []
    }
    
    if not serial_number:
        result['errors'].append("Serial Number is missing or empty")
        return result
    
    # Check if alphanumeric
    if not serial_number.isalnum():
        result['errors'].append(f"Serial Number '{serial_number}' is not alphanumeric")
    
    # Check length
    if len(serial_number) != expected_length:
        result['errors'].append(f"Serial Number '{serial_number}' is {len(serial_number)} bytes, expected {expected_length} bytes")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_base_mac_address(mac_address):
    """
    Validate Base MAC Address field
    Requirements: valid MAC address format
    
    Args:
        mac_address (str): Base MAC Address value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': mac_address,
        'errors': []
    }
    
    if not mac_address:
        result['errors'].append("Base MAC Address is missing or empty")
        return result
    
    # MAC address pattern (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    mac_patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$',  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$'     # XXXX.XXXX.XXXX
    ]
    
    valid_format = any(re.match(pattern, mac_address) for pattern in mac_patterns)
    
    if not valid_format:
        result['errors'].append(f"Base MAC Address '{mac_address}' is not in valid MAC address format")
    
    # Check for valid MAC address ranges (not broadcast, not multicast)
    try:
        # Remove separators and convert to int to check range
        mac_clean = re.sub(r'[:\-\.]', '', mac_address).upper()
        if len(mac_clean) == 12:
            # Check if it's not broadcast address
            if mac_clean == 'FFFFFFFFFFFF':
                result['errors'].append(f"Base MAC Address '{mac_address}' cannot be broadcast address")
            
            # Check if it's not multicast (first byte odd)
            first_byte = int(mac_clean[0:2], 16)
            if first_byte & 1:
                result['errors'].append(f"Base MAC Address '{mac_address}' cannot be multicast address")
            
    except ValueError:
        result['errors'].append(f"Base MAC Address '{mac_address}' contains invalid hexadecimal characters")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_mac_addresses_count(mac_count, min_count=500):
    """
    Validate MAC Addresses count
    Requirements: size > 500
    
    Args:
        mac_count (str): MAC Addresses count value
        min_count (int): Minimum required count
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': mac_count,
        'errors': []
    }
    
    if not mac_count:
        result['errors'].append("MAC Addresses count is missing or empty")
        return result
    
    try:
        count = int(mac_count)
        
        if count <= min_count:
            result['errors'].append(f"MAC Addresses count '{count}' must be greater than {min_count}")
        
        # Check if it's reasonable (not too high)
        if count > 100000:
            result['errors'].append(f"MAC Addresses count '{count}' seems unusually high")
        
    except ValueError:
        result['errors'].append(f"MAC Addresses count '{mac_count}' is not a valid integer")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_platform_name_presence(platform_name):
    """
    Validate Platform Name field
    Requirements: presence (not empty)
    
    Args:
        platform_name (str): Platform Name value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': platform_name,
        'errors': []
    }
    
    if not platform_name or platform_name.strip() == '':
        result['errors'].append("Platform Name is missing or empty")
        return result
    
    # Additional validation for expected format
    platform_pattern = r'^x86_64-[a-z0-9_]+-r[0-9]+$'
    if not re.match(platform_pattern, platform_name):
        result['errors'].append(f"Platform Name '{platform_name}' doesn't match expected format (e.g., x86_64-8122_64ehf_o-r0)")
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_platform_syseeprom_data(eeprom_output):
    """
    Validate all TlvInfo EEPROM fields
    
    Args:
        eeprom_output (str): Raw TlvInfo EEPROM data output
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': [],
        'tlv_info': {},
        'checksum_valid': False
    }
    
    # Parse TlvInfo data
    tlv_data = parse_tlvinfo_eeprom(eeprom_output)
    
    if not tlv_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse TlvInfo EEPROM data")
        return validation_result
    
    # Store TLV info
    validation_result['tlv_info'] = tlv_data
    validation_result['checksum_valid'] = tlv_data.get('checksum_valid', False)
    
    # Validate checksum
    if not validation_result['checksum_valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("TlvInfo checksum is invalid")
    
    # Get TLV fields
    tlv_fields = tlv_data.get('tlv_fields', {})
    
    # Validate Product Name
    product_name = tlv_fields.get('Product Name', {}).get('value')
    product_result = validate_product_name(product_name)
    validation_result['results']['product_name'] = product_result
    if not product_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(product_result['errors'])
    
    # Validate Serial Number
    serial_number = tlv_fields.get('Serial Number', {}).get('value')
    serial_result = validate_serial_number_tlv(serial_number, 11)
    validation_result['results']['serial_number'] = serial_result
    if not serial_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(serial_result['errors'])
    
    # Validate Base MAC Address
    mac_address = tlv_fields.get('Base MAC Address', {}).get('value')
    mac_result = validate_base_mac_address(mac_address)
    validation_result['results']['base_mac_address'] = mac_result
    if not mac_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(mac_result['errors'])
    
    # Validate MAC Addresses count
    mac_count = tlv_fields.get('MAC Addresses', {}).get('value')
    mac_count_result = validate_mac_addresses_count(mac_count, 500)
    validation_result['results']['mac_addresses_count'] = mac_count_result
    if not mac_count_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(mac_count_result['errors'])
    
    # Validate Platform Name presence
    platform_name = tlv_fields.get('Platform Name', {}).get('value')
    platform_result = validate_platform_name_presence(platform_name)
    validation_result['results']['platform_name'] = platform_result
    if not platform_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(platform_result['errors'])
    
    # Additional validations
    if not tlv_fields.get('Part Number'):
        validation_result['warnings'].append("Part Number field is missing")
    
    if not tlv_fields.get('Manufacturer'):
        validation_result['warnings'].append("Manufacturer field is missing")
    
    if not tlv_fields.get('Vendor Name'):
        validation_result['warnings'].append("Vendor Name field is missing")
    
    # Validate manufacturer/vendor consistency
    manufacturer = tlv_fields.get('Manufacturer', {}).get('value')
    vendor_name = tlv_fields.get('Vendor Name', {}).get('value')
    if manufacturer and vendor_name and manufacturer != vendor_name:
        validation_result['warnings'].append(f"Manufacturer '{manufacturer}' and Vendor Name '{vendor_name}' don't match")
    
    return validation_result



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

def validate_platform_fan_data(fan_output):
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

def parse_firmware_components(firmware_output):
    """
    Parse firmware output and extract all components for each chassis
    
    Args:
        firmware_output (str): Raw firmware status output
        
    Returns:
        dict: Parsed components by chassis
    """
    components_data = {
        'chassis_components': {},
        'parsing_errors': []
    }
    
    try:
        lines = firmware_output.strip().split('\n')
        lines = lines[:-1]
        
        # Find header line
        header_found = False
        data_start_idx = 0
        
        for idx, line in enumerate(lines):
            if 'Component' in line:
                header_found = True
                data_start_idx = idx + 1
                break
        
        if not header_found:
            components_data['parsing_errors'].append("Could not find header line")
            return components_data
        
        # Skip separator line
        for idx in range(data_start_idx, len(lines)):
            if '---' in lines[idx]:
                data_start_idx = idx + 1
                break
        
        current_chassis = None
        
        # Parse component data
        for line_idx in range(data_start_idx, len(lines)):
            line = lines[line_idx].strip()
            
            if not line:
                continue
            
            # Split line into columns
            parts = re.split(r'\s{2,}', line)
            
            if len(parts) >= 4:
                chassis = parts[0].strip() if parts[0].strip() else current_chassis
                module = parts[1].strip()
                component = parts[2].strip()
                version = parts[3].strip()
                description = parts[4].strip() if len(parts) > 4 else ""
                
                # Update current chassis
                if chassis and chassis != '':
                    current_chassis = chassis
                    components_data['chassis_components'][current_chassis] = []
            else:
                component = parts[0].strip()
                version = parts[1].strip()
                description = parts[2].strip() if len(parts) > 4 else ""
                    
            components_data['chassis_components'][current_chassis].append({
                'component': component,
                'version': version,
                'description': description,
                'module': module
            })
        
        return components_data
        
    except Exception as e:
        components_data['parsing_errors'].append(f"Error parsing firmware: {e}")
        return components_data

def get_fpds_components_from_config(platform_id):
    """
    Get expected FPDS components from platform configuration
    
    Args:
        platform_id (str): Platform identifier
        
    Returns:
        dict: Expected FPDS components or None if not found
    """
    try:
        
        # Get platform configuration
        platform_config = platform_edvt_cfg["platforms"].get(platform_id)
        if not platform_config:
            st.error(f"Platform {platform_id} not found in platform_edvt_cfg")
            return None
        
        # Get FPDS configuration
        fpds_config = platform_config.get('fpds')
        if not fpds_config:
            st.log(f"No FPDS configuration found for {platform_id}, using default")
            # Return default expected components based on your sample
            return get_default_fpds_components(platform_id)
        
        return fpds_config
        
    except Exception as e:
        st.error(f"Error getting FPDS config for {platform_id}: {e}")
        return None

def validate_components_against_fpds(parsed_components, platform_id):
    """
    Validate parsed components against FPDS configuration
    
    Args:
        parsed_components (dict): Parsed components from firmware output
        platform_id (str): Platform identifier
        
    Returns:
        dict: Validation results
    """
    validation_result = {
        'overall_valid': True,
        'platform_id': platform_id,
        'found_components': [],
        'missing_required': [],
        'unexpected_components': [],
        'component_details': [],
        'errors': [],
        'warnings': []
    }
    
    try:
        # Get expected FPDS components
        fpds_config = get_fpds_components_from_config(platform_id)
        if not fpds_config:
            validation_result['overall_valid'] = False
            validation_result['errors'].append(f"No FPDS configuration available for {platform_id}")
            return validation_result
        
        required_components = fpds_config
        
        # Extract found components for the specific platform
        chassis_components = parsed_components.get('chassis_components', {})
        platform_components = chassis_components.get(platform_id, [])
        
        if not platform_components:
            validation_result['overall_valid'] = False
            validation_result['errors'].append(f"No components found for platform {platform_id}")
            return validation_result
        
        # Collect found component names
        found_component_names = []
        for comp_info in platform_components:
            component_name = comp_info['component']
            found_component_names.append(component_name)
            
            validation_result['component_details'].append({
                'component': component_name,
                'version': comp_info['version'],
                'description': comp_info['description'],
                'module': comp_info['module']
            })
        
        validation_result['found_components'] = found_component_names
        
        # Check for missing required components
        for required_comp in required_components:
            if required_comp not in found_component_names:
                validation_result['missing_required'].append(required_comp)
                validation_result['overall_valid'] = False
        
        # Generate validation messages
        if validation_result['missing_required']:
            validation_result['errors'].append(
                f"Missing required FPDS components: {', '.join(validation_result['missing_required'])}"
            )
        
        if validation_result['unexpected_components']:
            validation_result['warnings'].append(
                f"Unexpected components (not in FPDS config): {', '.join(validation_result['unexpected_components'])}"
            )
        
        return validation_result
        
    except Exception as e:
        validation_result['overall_valid'] = False
        validation_result['errors'].append(f"Error validating components against FPDS: {e}")
        return validation_result

def verify_firmware_components_against_fpds(firmware_output, platform_id):
    """
    Complete verification of firmware components against FPDS configuration
    
    Args:
        firmware_output (str): Raw firmware status output
        platform_id (str): Platform identifier
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'validation_details': {},
        'summary': {},
        'errors': [],
        'warnings': []
    }
    
    try:
        # Parse firmware components
        parsed_data = parse_firmware_components(firmware_output)
        
        if parsed_data.get('parsing_errors'):
            validation_result['overall_valid'] = False
            validation_result['errors'].extend(parsed_data['parsing_errors'])
            return validation_result
        
        # Validate against FPDS configuration
        fpds_validation = validate_components_against_fpds(parsed_data, platform_id)
        validation_result['validation_details'] = fpds_validation
        
        if not fpds_validation['overall_valid']:
            validation_result['overall_valid'] = False
            validation_result['errors'].extend(fpds_validation['errors'])
        
        validation_result['warnings'].extend(fpds_validation.get('warnings', []))
        
        # Create summary
        validation_result['summary'] = {
            'platform_id': platform_id,
            'total_found_components': len(fpds_validation.get('found_components', [])),
            'missing_required_count': len(fpds_validation.get('missing_required', [])),
            'unexpected_count': len(fpds_validation.get('unexpected_components', [])),
            'found_components': fpds_validation.get('found_components', [])
        }
        
        return validation_result
        
    except Exception as e:
        validation_result['overall_valid'] = False
        validation_result['errors'].append(f"Error in firmware components verification: {e}")
        return validation_result


def detect_platform_id_from_firmware(firmware_output):
    """
    Detect platform ID from firmware output chassis column
    
    Args:
        firmware_output (str): Raw firmware output
        
    Returns:
        str: Platform ID or None if not detected
    """
    try:
        parsed_data = parse_firmware_components(firmware_output)
        chassis_list = list(parsed_data.get('chassis_components', {}).keys())
        
        if chassis_list:
            platform_id = chassis_list[0]
            st.log(f"Detected platform ID: {platform_id}")
            return platform_id
        
        st.error("Could not detect platform ID from firmware output")
        return None
        
    except Exception as e:
        st.error(f"Error detecting platform ID: {e}")
        return None

def validate_platform_firmware_status_data(firmware_output):
    """
    Verify platform components against FPDS configuration
    
    Args:
        dut: Device under test
        platform_id (str, optional): Platform ID. If None, auto-detect from firmware
        
    Returns:
        bool: True if validation passes, False otherwise
    """
    try:
        
        platform_id = detect_platform_id_from_firmware(firmware_output)

        # Verify components against FPDS
        validation_result = verify_firmware_components_against_fpds(firmware_output, platform_id)
        
        # Log summary
        summary = validation_result['summary']
        st.log("FPDS Validation Summary:")
        st.log(f"  Platform ID: {summary['platform_id']}")
        st.log(f"  Total Components Found: {summary['total_found_components']}")
        st.log(f"  Missing Required: {summary['missing_required_count']}")
        st.log(f"  Unexpected Components: {summary['unexpected_count']}")
        
        # Log found components
        st.log(f"  Found Components: {', '.join(summary['found_components'])}")
        
        # Log validation details
        validation_details = validation_result['validation_details']
        
        if validation_details.get('missing_required'):
            st.error(f"Missing Required FPDS Components:")
            for missing in validation_details['missing_required']:
                st.error(f"  - {missing}")
        
        if validation_details.get('unexpected_components'):
            st.log(f"Unexpected Components (not in FPDS config):")
            for unexpected in validation_details['unexpected_components']:
                st.log(f"  - {unexpected}")
        
        # Log component details
        st.log("\nComponent Details:")
        for comp_detail in validation_details.get('component_details', []):
            st.log(f"  {comp_detail['component']}: v{comp_detail['version']} - {comp_detail['description']}")
        
        # Log warnings
        if validation_result['warnings']:
            st.log("\nWarnings:")
            for warning in validation_result['warnings']:
                st.log(f"  - {warning}")
        
        return validation_result
            
    except Exception as e:
        st.error(f"Error during FPDS components validation: {e}")
        return False

def check_platform_data(CfgDataG, data_entity, ret_result):
    '''
    '''
    match data_entity:
        case "summary":
            st.log("{CfgDataG.logprefix}: Executing platform summary validation")
            cmd = "show platform summary"
            output = st.config(CfgDataG.dut, cmd)
            if output:
                result = validate_platform_summary_data(output)
            else:
                reason = 'Failed to retrieve platform summary Info'
                update_result_with_str(ret_result, data_entity, reason)
                st.error("Could not retrieve platform summary information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform summary information from device")
                return
            if not result['overall_valid']: 
                update_result_with_dict(ret_result, data_entity, result)
                report_fail(f"{CfgDataG.logprefix}: Validation of platform summary failed")
            
        case "syseeprom":
            st.log("{CfgDataG.logprefix}: Executing platform syseeprom validation")
            cmd = "show platform syseeprom"
            output = st.config(CfgDataG.dut, cmd)
            if output:
                result = validate_platform_syseeprom_data(output)
            else:
                reason = 'Failed to retrieve syseeprom Info'
                update_result_with_str(ret_result, data_entity, reason)
                st.error("Could not retrieve platform syseeprom information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform syseeprom information from device")
                return
            if not result['overall_valid']: 
                update_result_with_dict(ret_result, data_entity, result)
                report_fail(f"{CfgDataG.logprefix}: Validation of platform syseeprom failed")
            
        case "fan":
            cmd = "show platform fan"
            output = st.show(CfgDataG.dut, cmd)
            if output:
                result = validate_platform_fan_data(output)
            else:
                reason = 'Failed to retrieve Fan Info'
                update_result_with_str(ret_result, data_entity, reason)
                st.error("Could not retrieve platform fan information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform fan information from device")
                return
            if not result['overall_valid']: 
                update_result_with_dict(ret_result, data_entity, result)
                report_fail(f"{CfgDataG.logprefix}: Validation of platform fan failed")
            
        case "psustatus":
            cmd = "show platform psustatus"
            output = st.config(CfgDataG.dut, cmd)
            if output:
               result = validate_platform_psustatus_data(output)
            else:
                reason = 'Failed to retrieve psustatus Info'
                update_result_with_str(ret_result, data_entity, reason)
                st.error("Could not retrieve platform psustatus information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform psustatus information from device")
                return
            if not result['overall_valid']: 
                update_result_with_dict(ret_result, data_entity, result)
                report_fail(f"{CfgDataG.logprefix}: Validation of platform psustatus failed")
            
        case "firmware_status":
            st.log("{CfgDataG.logprefix}: Executing platform firmware status validation")
            cmd = "show platform firmware status"
            output = st.config(CfgDataG.dut, cmd)
            if output:
               result = validate_platform_firmware_status_data(output)
            else:
                reason = 'Failed to retrieve firmware status Info'
                update_result_with_str(ret_result, data_entity, reason)
                st.error("Could not retrieve platform firmware status information from device")
                report_fail(f"{CfgDataG.logprefix}: Could not retrieve platform firware status information from device")
                return
            if not result['overall_valid']: 
                update_result_with_dict(ret_result, data_entity, result)
                report_fail(f"{CfgDataG.logprefix}: Validation of platform firmware status failed")
            
        case _:  # Default case
            st.error(f"Unknown test type: {data_entity}")
            return False

    return True

def test_platform_data_check(CfgDataG, platform_data_check, ret_result):
    st.log(f"{CfgDataG.logprefix}: Executing {platform_data_check} check")

    for item in platform_data_check:
        if not check_platform_data(CfgDataG, item, ret_result):
            report_fail(f"{CfgDataG.logprefix}: Validation of platform_data {item} failed")
            continue
        else:
            st.log(f"{CfgDataG.logprefix}: {item} data ok")

    return True
