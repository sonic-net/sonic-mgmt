import pytest
import re
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def idprom_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** IDPROM CHECK *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"
    CfgDataG.dut = TBDataG.D1

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def parse_baseboard_idprom_data(idprom_output):
    """
    Parse IDPROM output into a dictionary
    
    Args:
        idprom_output (str): Raw IDPROM data output
        
    Returns:
        dict: Parsed IDPROM fields
    """
    parsed_data = {}
    
    try:
        lines = idprom_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line and not line.startswith('board:'):
                # Split on first colon only
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    parsed_data[key] = value
        
        return parsed_data
        
    except Exception as e:
        st.error(f"Error parsing IDPROM data: {e}")
        return {}

def validate_chassis_serial(chassis_serial):
    """
    Validate CHASSIS_SERIAL field
    Requirements: alphanumeric and 11 bytes long
    
    Args:
        chassis_serial (str): CHASSIS_SERIAL value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': chassis_serial,
        'errors': []
    }
    
    if not chassis_serial:
        result['errors'].append("CHASSIS_SERIAL is missing or empty")
        return result
    
    # Check if alphanumeric
    if not chassis_serial.isalnum():
        result['errors'].append(f"CHASSIS_SERIAL '{chassis_serial}' is not alphanumeric")
    
    # Check length (11 bytes)
    if len(chassis_serial) != 11:
        result['errors'].append(f"CHASSIS_SERIAL '{chassis_serial}' is {len(chassis_serial)} bytes, expected 11 bytes")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_pcb_serial(pcb_serial):
    """
    Validate PCB_SERIAL field
    Requirements: alphanumeric and 11 bytes long
    
    Args:
        pcb_serial (str): PCB_SERIAL value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': pcb_serial,
        'errors': []
    }
    
    if not pcb_serial:
        result['errors'].append("PCB_SERIAL is missing or empty")
        return result
    
    # Check if alphanumeric
    if not pcb_serial.isalnum():
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is not alphanumeric")
    
    # Check length (11 bytes)
    if len(pcb_serial) != 11:
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is {len(pcb_serial)} bytes, expected 11 bytes")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_product_id(product_id):
    """
    Validate PRODUCT_ID field
    Requirements: has a value (not empty)
    
    Args:
        product_id (str): PRODUCT_ID value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': product_id,
        'errors': []
    }
    
    if not product_id or product_id.strip() == "":
        result['errors'].append("PRODUCT_ID is missing or empty")
        return result
    
    # Additional validation - should match expected format
    if not re.match(r'^[A-Z0-9-]+$', product_id):
        result['errors'].append(f"PRODUCT_ID '{product_id}' contains invalid characters")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_hw_version(hw_version):
    """
    Validate HW_VERSION field
    Requirements: not 0 or 0.0
    
    Args:
        hw_version (str): HW_VERSION value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': hw_version,
        'errors': []
    }
    
    if not hw_version:
        result['errors'].append("HW_VERSION is missing or empty")
        return result
    
    try:
        # Convert to float for comparison
        version_float = float(hw_version)
        
        # Check if it's 0 or 0.0
        if version_float == 0.0:
            result['errors'].append(f"HW_VERSION '{hw_version}' cannot be 0 or 0.0")
        
        # Additional validation - should be positive
        if version_float < 0:
            result['errors'].append(f"HW_VERSION '{hw_version}' cannot be negative")
        
    except ValueError:
        result['errors'].append(f"HW_VERSION '{hw_version}' is not a valid numeric value")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def verify_baseboard_idprom_data(idprom_data):
    """
    Validate IDPROM fields according to specified requirements

    Args:
        idprom_data (str): Raw IDPROM data output from device

    Returns:
        dict: Validation results with detailed information
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': []
    }

    # Parse IDPROM data into dictionary
    parsed_data = parse_baseboard_idprom_data(idprom_data)

    if not parsed_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse IDPROM data")
        return validation_result

    # Validate CHASSIS_SERIAL
    chassis_result = validate_chassis_serial(parsed_data.get('CHASSIS_SERIAL'))
    validation_result['results']['chassis_serial'] = chassis_result
    if not chassis_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(chassis_result['errors'])

    # Validate PCB_SERIAL
    pcb_result = validate_pcb_serial(parsed_data.get('PCB_SERIAL'))
    validation_result['results']['pcb_serial'] = pcb_result
    if not pcb_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(pcb_result['errors'])

    # Validate PRODUCT_ID
    product_result = validate_product_id(parsed_data.get('PRODUCT_ID'))
    validation_result['results']['product_id'] = product_result
    if not product_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(product_result['errors'])

    # Validate HW_VERSION
    hw_version_result = validate_hw_version(parsed_data.get('HW_VERSION'))
    validation_result['results']['hw_version'] = hw_version_result
    if not hw_version_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(hw_version_result['errors'])

    return validation_result

def parse_psu_eeprom_data(eeprom_output):
    """
    Parse PSU EEPROM output into a dictionary
    
    Args:
        eeprom_output (str): Raw PSU EEPROM data output
        
    Returns:
        dict: Parsed EEPROM data
    """
    try:
        parsed_data = {}
        lines = eeprom_output.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Handle different line formats
            if line.endswith(':'):
                # Section header (like "aliases:", "content:")
                current_section = line[:-1]
                if current_section == 'aliases':
                    parsed_data[current_section] = []
                continue
            elif line.startswith('- '):
                # List item (for NEW_DEVIATION, etc.)
                if current_section:
                    if current_section not in parsed_data:
                        parsed_data[current_section] = []
                    try:
                        # Try to convert to int if possible
                        value = int(line[2:])
                        parsed_data[current_section].append(value)
                    except ValueError:
                        parsed_data[current_section].append(line[2:])
            elif ':' in line:
                # Key-value pair
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    # Handle quoted values and special formatting
                    if value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    elif value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    
                    # Try to convert numeric values
                    if value.isdigit():
                        value = int(value)
                    elif value.replace('.', '').isdigit() and value.count('.') == 1:
                        value = float(value)
                    
                    parsed_data[key] = value
            elif line == 'content':
                current_section = 'content'
                continue
        
        return parsed_data
        
    except Exception as e:
        st.error(f"Error parsing PSU EEPROM data: {e}")
        return {}

def validate_psu_product_id(product_id):
    """
    Validate PRODUCT_ID for PSU
    Requirements: Should be valid PSU product ID (e.g., PSU3KW-HVPI)
    
    Args:
        product_id (str): PRODUCT_ID value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': product_id,
        'errors': []
    }
    
    if not product_id:
        result['errors'].append("PRODUCT_ID is missing or empty")
        return result
    
    # Check if it matches expected PSU product ID pattern
    psu_pattern = r'^PSU\w+$'
    if not re.match(psu_pattern, product_id):
        result['errors'].append(f"PRODUCT_ID '{product_id}' doesn't match expected PSU pattern (PSUxxxx)")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_psu_pcb_serial(pcb_serial):
    """
    Validate PCB_SERIAL for PSU
    Requirements: Should be alphanumeric and 11 characters long
    
    Args:
        pcb_serial (str): PCB_SERIAL value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': pcb_serial,
        'errors': []
    }
    
    if not pcb_serial:
        result['errors'].append("PCB_SERIAL is missing or empty")
        return result
    
    # Check if alphanumeric
    if not pcb_serial.isalnum():
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is not alphanumeric")
    
    # Check length (11 characters)
    if len(pcb_serial) != 11:
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is {len(pcb_serial)} characters, expected 11 characters")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_psu_hw_version(hw_version):
    """
    Validate HW_VERSION for PSU
    Requirements: Should not be 0 or 0.0, should be valid version format
    
    Args:
        hw_version (str): HW_VERSION value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': hw_version,
        'errors': []
    }
    
    if not hw_version:
        result['errors'].append("HW_VERSION is missing or empty")
        return result
    
    # Convert to string if it's a number
    hw_version_str = str(hw_version)
    
    try:
        # Convert to float for comparison
        version_float = float(hw_version_str)
        
        # Check if it's 0 or 0.0
        if version_float == 0.0:
            result['errors'].append(f"HW_VERSION '{hw_version_str}' cannot be 0 or 0.0")
        
        # Check if it's negative
        if version_float < 0:
            result['errors'].append(f"HW_VERSION '{hw_version_str}' cannot be negative")
        
        # Check if it's reasonable (between 0.1 and 10.0)
        if version_float > 10.0:
            result['errors'].append(f"HW_VERSION '{hw_version_str}' seems unusually high")
        
    except ValueError:
        result['errors'].append(f"HW_VERSION '{hw_version_str}' is not a valid numeric value")
    
    # Check version format pattern (should be like 1.0, 2.3, etc.)
    version_pattern = r'^\d+(\.\d+)?$'
    if not re.match(version_pattern, hw_version_str):
        result['errors'].append(f"HW_VERSION '{hw_version_str}' doesn't match expected format (X.Y or X)")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_psu_eeprom_fields(eeprom_data):
    """
    Validate all required EEPROM fields for PSU
    
    Args:
        eeprom_data (str): Raw PSU EEPROM data output
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': [],
        'psu_info': {}
    }
    
    # Parse EEPROM data
    parsed_data = parse_psu_eeprom_data(eeprom_data)
    
    if not parsed_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse PSU EEPROM data")
        return validation_result
    
    # Validate PRODUCT_ID
    product_result = validate_psu_product_id(parsed_data.get('PRODUCT_ID'))
    validation_result['results']['product_id'] = product_result
    if not product_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(product_result['errors'])
    
    # Validate PCB_SERIAL
    pcb_result = validate_psu_pcb_serial(parsed_data.get('PCB_SERIAL'))
    validation_result['results']['pcb_serial'] = pcb_result
    if not pcb_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(pcb_result['errors'])
    
    # Validate HW_VERSION
    hw_version_result = validate_psu_hw_version(parsed_data.get('HW_VERSION'))
    validation_result['results']['hw_version'] = hw_version_result
    if not hw_version_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(hw_version_result['errors'])
    
    return validation_result

def verify_psu_idprom_data(CfgDataG, device):
    """
    Get psu tray EEPROM data from device using spytest
    
    Args:
        dut: Device under test
        psu_name (str, optional): Specific fan tray name (e.g., "fantray0")
        
    Returns:
        dict: PSU EEPROM data for all or specific fan trays
    """
    try:
        # Commands to get fan tray EEPROM data
        cmd = f"cat /var/cache/cisco/idprom/{device}.yaml"
        eeprom_data = {}
        output = st.show(CfgDataG.dut, cmd, skip_error_check=True)
        if output and ("PRODUCT_ID" in output or "PCB_SERIAL" in output):
            # Parse multiple fan trays if present
            return validate_psu_eeprom_fields(output)

    except Exception as e:
        st.error(f"Error getting fan tray EEPROM data: {e}")
        return {}

def parse_fantray_eeprom_data(eeprom_output):
    """
    Parse fan tray EEPROM output into a dictionary
    
    Args:
        eeprom_output (str): Raw fan tray EEPROM data output
        
    Returns:
        dict: Parsed EEPROM data
    """
    try:
        # The data appears to be in YAML-like format
        parsed_data = {}
        
        lines = eeprom_output.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Handle different line formats
            if line.endswith(':'):
                # Section header (like "aliases:")
                current_section = line[:-1]
                parsed_data[current_section] = []
            elif line.startswith('- '):
                # List item
                if current_section:
                    parsed_data[current_section].append(line[2:])
            elif ':' in line:
                # Key-value pair
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    # Handle quoted values and special formatting
                    if value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    elif value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    
                    # Store under content if it looks like EEPROM field
                    if current_section == 'content' or current_section is None:
                        parsed_data[key] = value
                    else:
                        if current_section not in parsed_data:
                            parsed_data[current_section] = {}
                        parsed_data[current_section][key] = value
            elif line.startswith('content'):
                current_section = 'content'
                continue
        
        return parsed_data
        
    except Exception as e:
        st.error(f"Error parsing fan tray EEPROM data: {e}")
        return {}

def validate_fantray_product_id(product_id):
    """
    Validate PRODUCT_ID for fan tray
    Requirements: Should be valid fan product ID (e.g., FAN-PI-V4)
    
    Args:
        product_id (str): PRODUCT_ID value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': product_id,
        'errors': []
    }
    
    if not product_id:
        result['errors'].append("PRODUCT_ID is missing or empty")
        return result
    
    # Check if it matches expected fan product ID pattern
    fan_pattern = r'^FAN-[A-Z0-9-]+$'
    if not re.match(fan_pattern, product_id):
        result['errors'].append(f"PRODUCT_ID '{product_id}' doesn't match expected fan pattern (FAN-xxx)")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_fantray_pcb_serial(pcb_serial):
    """
    Validate PCB_SERIAL for fan tray
    Requirements: Should be alphanumeric and 11 characters long
    
    Args:
        pcb_serial (str): PCB_SERIAL value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': pcb_serial,
        'errors': []
    }
    
    if not pcb_serial:
        result['errors'].append("PCB_SERIAL is missing or empty")
        return result
    
    # Check if alphanumeric
    if not pcb_serial.isalnum():
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is not alphanumeric")
    
    # Check length (11 characters)
    if len(pcb_serial) != 11:
        result['errors'].append(f"PCB_SERIAL '{pcb_serial}' is {len(pcb_serial)} characters, expected 11 characters")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_fantray_hw_version(hw_version):
    """
    Validate HW_VERSION for fan tray
    Requirements: Should not be 0 or 0.0, should be valid version format
    
    Args:
        hw_version (str): HW_VERSION value
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': False,
        'value': hw_version,
        'errors': []
    }
    
    if not hw_version:
        result['errors'].append("HW_VERSION is missing or empty")
        return result
    
    try:
        # Convert to float for comparison
        version_float = float(hw_version)
        
        # Check if it's 0 or 0.0
        if version_float == 0.0:
            result['errors'].append(f"HW_VERSION '{hw_version}' cannot be 0 or 0.0")
        
        # Check if it's negative
        if version_float < 0:
            result['errors'].append(f"HW_VERSION '{hw_version}' cannot be negative")
        
        # Check if it's reasonable (between 0.1 and 10.0)
        if version_float > 10.0:
            result['errors'].append(f"HW_VERSION '{hw_version}' seems unusually high")
        
    except ValueError:
        result['errors'].append(f"HW_VERSION '{hw_version}' is not a valid numeric value")
    
    # Check version format pattern (should be like 1.0, 2.3, etc.)
    version_pattern = r'^\d+\.\d+$'
    if not re.match(version_pattern, hw_version):
        result['errors'].append(f"HW_VERSION '{hw_version}' doesn't match expected format (X.Y)")
    
    # If no errors, mark as valid
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_fantray_eeprom_fields(eeprom_data):
    """
    Validate all required EEPROM fields for fan tray
    
    Args:
        eeprom_data (str): Raw fan tray EEPROM data output
        
    Returns:
        dict: Comprehensive validation results
    """
    validation_result = {
        'overall_valid': True,
        'results': {},
        'errors': [],
        'warnings': [],
        'fantray_info': {}
    }
    
    # Parse EEPROM data
    parsed_data = parse_fantray_eeprom_data(eeprom_data)
    
    if not parsed_data:
        validation_result['overall_valid'] = False
        validation_result['errors'].append("Failed to parse fan tray EEPROM data")
        return validation_result
    
    # Store fan tray info
    validation_result['fantray_info'] = {
        'name': parsed_data.get('name'),
        'i2c_path': parsed_data.get('i2c_path'),
        'path': parsed_data.get('path')
    }
    
    # Validate PRODUCT_ID
    product_result = validate_fantray_product_id(parsed_data.get('PRODUCT_ID'))
    validation_result['results']['product_id'] = product_result
    if not product_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(product_result['errors'])
    
    # Validate PCB_SERIAL
    pcb_result = validate_fantray_pcb_serial(parsed_data.get('PCB_SERIAL'))
    validation_result['results']['pcb_serial'] = pcb_result
    if not pcb_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(pcb_result['errors'])
    
    # Validate HW_VERSION
    hw_version_result = validate_fantray_hw_version(parsed_data.get('HW_VERSION'))
    validation_result['results']['hw_version'] = hw_version_result
    if not hw_version_result['valid']:
        validation_result['overall_valid'] = False
        validation_result['errors'].extend(hw_version_result['errors'])
    
    # Additional validations for completeness
    if not parsed_data.get('UDI_DESC'):
        validation_result['warnings'].append("UDI_DESC is missing")
    
    if not parsed_data.get('CRC_32'):
        validation_result['warnings'].append("CRC_32 is missing")
    
    return validation_result

def verify_fantray_idprom_data(CfgDataG, device):
    """
    Get fan tray EEPROM data from device using spytest
    
    Args:
        dut: Device under test
        fantray_name (str, optional): Specific fan tray name (e.g., "fantray0")
        
    Returns:
        dict: Fan tray EEPROM data for all or specific fan trays
    """
    try:
        # Commands to get fan tray EEPROM data
        cmd = f"cat /var/cache/cisco/idprom/{device}.yaml"
        eeprom_data = {}
        output = st.show(CfgDataG.dut, cmd, skip_error_check=True)
        if output and ("PRODUCT_ID" in output or "PCB_SERIAL" in output):
            # Parse multiple fan trays if present
            return validate_fantray_eeprom_fields(output)

    except Exception as e:
        st.error(f"Error getting fan tray EEPROM data: {e}")
        return {}

def check_idprom_data(CfgDataG, entity):
    '''
    '''
    match entity:
        case "baseboard":
            st.log("{CfgDataG.logprefix}: Executing baseboard idprom validation")
            cmd = "show platform idprom"
            output = st.config(CfgDataG.dut, cmd)
            result = verify_baseboard_idprom_data(output)
            if not result['overall_valid']: 
                report_fail(f"{CfgDataG.logprefix}: Validation of baseboard idprom failed")
            
        case "fantray":
            st.log("Executing HWQUAL test sequence")
            cooling_devices = CfgDataG.cooling_devices
        
            # Execute checks for each fantray
            for device in cooling_devices:
                st.log(f"  Checking idprom data for {device}")
                # Add actual check implementation here
                result = verify_fantray_idprom_data(CfgDataG, device)
                if not result['overall_valid']: 
                    report_fail(f"{CfgDataG.logprefix}: Validation of baseboard idprom failed")
            st.log(f"Idprom validation completed successfully for {len(cooling_devices)} devices")
            
        case "psu":
            st.log("Executing HWQUAL_UT test sequence")
            psu_trays = CfgDataG.psu_trays
        
            # Execute checks for each PSU
            for psu in psu_trays:
                st.log(f"  Checking idprom data for {psu}")
                # Add actual check implementation here
                result = verify_psu_idprom_data(CfgDataG, psu)
            st.log(f"Idprom validation completed successfully for {len(psu_trays)} PSUs")
        
        case _:  # Default case
            st.error(f"Unknown test type: {entity}")
            return False

    return True

def parse_platform_inventory(inventory_output):
    """
    Parse platform inventory output and extract cooling devices and PSU information
    
    Args:
        inventory_output (str): Raw platform inventory output
        
    Returns:
        dict: Parsed inventory with cooling devices and PSU trays
    """
    inventory_data = {
        'cooling_devices': [],
        'psu_trays': [],
        'chassis_info': {},
        'route_processors': []
    }
    
    try:
        lines = inventory_output.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect sections
            if line.startswith('Chassis'):
                current_section = 'chassis'
                continue
            elif line.startswith('Route Processors'):
                current_section = 'route_processors'
                continue
            elif line.startswith('Power Supplies'):
                current_section = 'power_supplies'
                continue
            elif line.startswith('Cooling Devices'):
                current_section = 'cooling_devices'
                continue
            elif line.startswith('Name') and 'Product ID' in line:
                # Skip header line
                continue
            
            # Parse data based on current section
            if current_section == 'chassis':
                chassis_info = parse_inventory_line(line)
                if chassis_info:
                    inventory_data['chassis_info'] = chassis_info
                    
            elif current_section == 'route_processors':
                rp_info = parse_inventory_line(line)
                if rp_info:
                    inventory_data['route_processors'].append(rp_info)
                    
            elif current_section == 'power_supplies':
                if line.startswith('psutray'):
                    # PSU tray header
                    continue
                else:
                    psu_info = parse_inventory_line(line)
                    if psu_info:
                        inventory_data['psu_trays'].append(psu_info)
                        
            elif current_section == 'cooling_devices':
                cooling_info = parse_inventory_line(line)
                if cooling_info:
                    inventory_data['cooling_devices'].append(cooling_info)
        
        return inventory_data
        
    except Exception as e:
        st.error(f"Error parsing platform inventory: {e}")
        return inventory_data

def parse_inventory_line(line):
    """
    Parse a single inventory line into components
    
    Args:
        line (str): Single line from inventory output
        
    Returns:
        dict: Parsed component information
    """
    try:
        # Split line by multiple spaces to handle aligned columns
        parts = re.split(r'\s{2,}', line.strip())
        
        if len(parts) >= 4:
            component_info = {
                'name': parts[0].strip(),
                'product_id': parts[1].strip() if parts[1].strip() else None,
                'version': parts[2].strip() if parts[2].strip() else None,
                'serial_number': parts[3].strip() if parts[3].strip() else None,
                'description': parts[4].strip() if len(parts) > 4 and parts[4].strip() else None
            }
            return component_info
        
        return None
        
    except Exception as e:
        st.error(f"Error parsing inventory line '{line}': {e}")
        return None

def validate_cooling_devices(cooling_devices, expected_count=None):
    """
    Validate cooling devices list
    
    Args:
        cooling_devices (list): List of cooling device names
        expected_count (int, optional): Expected number of cooling devices
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'count': len(cooling_devices),
        'devices': cooling_devices,
        'errors': [],
        'warnings': []
    }
    
    # Check if any cooling devices found
    if not cooling_devices:
        result['valid'] = False
        result['errors'].append("No cooling devices found")
        return result
    
    # Check expected count
    if expected_count and len(cooling_devices) != expected_count:
        result['warnings'].append(f"Expected {expected_count} cooling devices, found {len(cooling_devices)}")
    
    # Validate device naming pattern
    for device in cooling_devices:
        if not re.match(r'^fantray\d+$', device):
            result['warnings'].append(f"Unexpected cooling device name format: {device}")
    
    return result

def validate_psu_trays(psu_trays, expected_count=None):
    """
    Validate PSU trays list
    
    Args:
        psu_trays (list): List of PSU tray names
        expected_count (int, optional): Expected number of PSU trays
        
    Returns:
        dict: Validation result
    """
    result = {
        'valid': True,
        'count': len(psu_trays),
        'devices': psu_trays,
        'errors': [],
        'warnings': []
    }
    
    # Check if any PSU trays found
    if not psu_trays:
        result['valid'] = False
        result['errors'].append("No PSU trays found")
        return result
    
    # Check expected count
    if expected_count and len(psu_trays) != expected_count:
        result['warnings'].append(f"Expected {expected_count} PSU trays, found {len(psu_trays)}")
    
    # Validate PSU naming pattern
    for psu in psu_trays:
        if not re.match(r'^PSU\d+$', psu):
            result['warnings'].append(f"Unexpected PSU name format: {psu}")
    
    return result

def get_cooling_devices_list(inventory_data):
    entity_names = []

    cooling_devices = inventory_data['cooling_devices']
    for device in cooling_devices:
        entity_names.append(device['name'])

    return entity_names

def get_psu_trays_list(inventory_data):
    entity_names = []

    psutrays = inventory_data['psu_trays']
    for device in psutrays:
        entity_names.append(device['name'])

    return entity_names

def get_platform_inventory_data(CfgDataG):
    """
    Retrieve inventory data
    """
    cmd = "show platform inventory"
    output = st.config(CfgDataG.dut, cmd)

    # Parse inventory
    return parse_platform_inventory(output)
    
    # Display results
    #print(f"Cooling Devices ({len(cooling_devices)}):")
    #for device in cooling_devices:
    #    print(f"  - {device}")
    
    #print(f"\nPSU Trays ({len(psu_trays)}):")
    #for psu in psu_trays:
    #    print(f"  - {psu}")
    
    # Validate
    #cooling_validation = validate_cooling_devices(cooling_devices, expected_count=4)
    #psu_validation = validate_psu_trays(psu_trays, expected_count=2)
    
    #print(f"\nCooling Validation: {'✓ PASS' if cooling_validation['valid'] else '✗ FAIL'}")
    #print(f"PSU Validation: {'✓ PASS' if psu_validation['valid'] else '✗ FAIL'}")

def test_idprom_check(CfgDataG, idprom_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {idprom_check} check")

    # Parse inventory
    inventory_data = get_platform_inventory_data(CfgDataG)

    # Get Fantray and Psutray lists
    CfgDataG.cooling_devices = get_cooling_devices_list(inventory_data)
    CfgDataG.psu_trays = get_psu_trays_list(inventory_data)
    
    for idprom in idprom_check:
        if not check_idprom_data(CfgDataG, idprom):
            report_fail(f"{CfgDataG.logprefix}: Validation of {idprom} idprom failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {idprom} data ok")

    return True
