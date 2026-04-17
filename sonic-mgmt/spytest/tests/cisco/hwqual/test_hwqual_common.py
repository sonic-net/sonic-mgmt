import re
import yaml
import pytest
import os.path
import ipaddress
from spytest import st, SpyTestDict

@pytest.fixture(scope="module", autouse=True)
def hwqual_common_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** HWQUAL COMMON *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"

    yield
    pass

def remove_last_line(text):
    """
    Remove the last line from text (typically the command prompt)
    
    Args:
        text (str): Input text
        
    Returns:
        str: Text with last line removed
    """
    try:
        if not text:
            return ""
        
        # Split into lines
        lines = text.split('\n')
        
        # Remove empty lines from the end first
        while lines and not lines[-1].strip():
            lines.pop()
        
        # Remove the last line (command prompt)
        if lines:
            lines.pop()
        
        # Remove any remaining trailing empty lines
        while lines and not lines[-1].strip():
            lines.pop()
        
        # Join back together
        return '\n'.join(lines)
        
    except Exception as e:
        st.error(f"Error removing last line: {e}")
        return text  # Return original if cleaning fails

def read_thermal_zone_yaml_from_device(dut):
    """
    Read thermal_zone.yaml file from device
    
    Args:
        dut: Device under test
        
    Returns:
        str: Raw YAML content or None if failed
    """
    try:
        yaml_file_path = "/opt/cisco/etc/thermal_zone.yaml"
        
        # Check if file exists
        cmd = f"test -f {yaml_file_path} && echo EXISTS || echo NOT_EXISTS"
        result = st.config(dut, cmd, skip_error_check=True)

        if "NOT_EXISTS" in str(result):
            st.error(f"Thermal zone YAML file not found: {yaml_file_path}")
            return None

        # Read the YAML file content
        read_cmd = f"cat {yaml_file_path}"
        yaml_content = st.show(dut, read_cmd, skip_error_check=True)
        
        if not yaml_content:
            st.error(f"Failed to read thermal zone YAML file: {yaml_file_path}")
            return None

        #Last line contains the cmd prompt
        yaml_content = remove_last_line(yaml_content)
        
        st.log(f"Successfully read thermal zone YAML file from {yaml_file_path}")
        return yaml_content
        
    except Exception as e:
        st.error(f"Error reading thermal zone YAML from device: {e}")
        return None

def parse_thermal_zone_yaml(yaml_content):
    """
    Parse thermal zone YAML content
    
    Args:
        yaml_content (str): Raw YAML content
        
    Returns:
        dict: Parsed YAML data or None if failed
    """
    try:
        # Parse YAML content
        yaml_data = yaml.safe_load(yaml_content)
        
        if not yaml_data:
            st.error("Failed to parse YAML content - empty or invalid YAML")
            return None
        
        st.log("Successfully parsed thermal zone YAML content")
        return yaml_data
        
    except yaml.YAMLError as e:
        st.error(f"YAML parsing error: {e}")
        return None
    except Exception as e:
        st.error(f"Error parsing thermal zone YAML: {e}")
        return None

def extract_voltage_sensors(yaml_data):
    """
    Extract voltage_sensors container data from parsed YAML
    
    Args:
        yaml_data (dict): Parsed YAML data
        
    Returns:
        dict: Voltage sensors data with metadata
    """
    voltage_sensors_data = {
        'voltage_sensors': [],
        'sensor_count': 0,
        'sensor_types': {},
        'voltage_ranges': {},
        'extraction_errors': []
    }
    
    try:
        # Navigate to voltage_sensors container
        voltage_sensors = None
        
        # Try different possible paths for voltage_sensors
        possible_paths = [
            ['voltage_sensors']
        ]
        
        for path in possible_paths:
            current_data = yaml_data
            try:
                for key in path:
                    if isinstance(current_data, dict) and key in current_data:
                        current_data = current_data[key]
                    else:
                        current_data = None
                        break
                
                if current_data is not None:
                    voltage_sensors = current_data
                    st.log(f"Found voltage_sensors at path: {' -> '.join(path)}")
                    break
                    
            except Exception:
                continue
        
        if voltage_sensors is None:
            # Search for voltage_sensors recursively
            voltage_sensors = find_voltage_sensors_recursive(yaml_data)
        
        if voltage_sensors is None:
            voltage_sensors_data['extraction_errors'].append("voltage_sensors container not found in YAML data")
            return voltage_sensors_data
        
        # Process voltage sensors data
        if isinstance(voltage_sensors, list):
            voltage_sensors_data['voltage_sensors'] = voltage_sensors
        elif isinstance(voltage_sensors, dict):
            # If it's a dict, convert to list of sensor entries
            sensor_list = []
            for sensor_name, sensor_config in voltage_sensors.items():
                if isinstance(sensor_config, dict):
                    sensor_config['name'] = sensor_name
                    sensor_list.append(sensor_config)
                else:
                    sensor_list.append({'name': sensor_name, 'config': sensor_config})
            voltage_sensors_data['voltage_sensors'] = sensor_list
        else:
            voltage_sensors_data['extraction_errors'].append(f"Unexpected voltage_sensors data type: {type(voltage_sensors)}")
            return voltage_sensors_data
        
        # Create a new list with only sensors that have 'margin_path'
        voltage_sensors_data['voltage_sensors'] = [
           sensor for sensor in voltage_sensors_data['voltage_sensors'] 
           if 'margin_path' in sensor]

        # Calculate metadata
        voltage_sensors_data['sensor_count'] = len(voltage_sensors_data['voltage_sensors'])
        
        st.log(f"Extracted {voltage_sensors_data['sensor_count']} voltage sensors")
        return voltage_sensors_data
        
    except Exception as e:
        voltage_sensors_data['extraction_errors'].append(f"Error extracting voltage sensors: {e}")
        return voltage_sensors_data

def find_voltage_sensors_recursive(data, path=""):
    """
    Recursively search for voltage_sensors in YAML data
    
    Args:
        data: Current data node
        path (str): Current path for debugging
        
    Returns:
        dict/list: voltage_sensors data if found, None otherwise
    """
    try:
        if isinstance(data, dict):
            # Check if current dict contains voltage_sensors
            if 'voltage_sensors' in data:
                st.log(f"Found voltage_sensors at path: {path}")
                return data['voltage_sensors']
            
            # Recursively search in child nodes
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                result = find_voltage_sensors_recursive(value, new_path)
                if result is not None:
                    return result
        
        elif isinstance(data, list):
            # Search in list items
            for idx, item in enumerate(data):
                new_path = f"{path}[{idx}]"
                result = find_voltage_sensors_recursive(item, new_path)
                if result is not None:
                    return result
        
        return None
        
    except Exception:
        return None

def validate_voltage_sensors_data(voltage_sensors_data):
    """
    Validate extracted voltage sensors data
    
    Args:
        voltage_sensors_data (dict): Extracted voltage sensors data
        
    Returns:
        dict: Validation results
    """
    validation_result = {
        'valid': True,
        'sensor_validation': {},
        'errors': [],
        'warnings': []
    }
    
    try:
        # Check if extraction was successful
        if voltage_sensors_data.get('extraction_errors'):
            validation_result['valid'] = False
            validation_result['errors'].extend(voltage_sensors_data['extraction_errors'])
            return validation_result
        
        # Validate sensor count
        sensor_count = voltage_sensors_data.get('sensor_count', 0)
        if sensor_count == 0:
            validation_result['valid'] = False
            validation_result['errors'].append("No voltage sensors found in thermal zone configuration")
            return validation_result
        
        # Validate individual sensors
        sensors = voltage_sensors_data.get('voltage_sensors', [])
        sensor_names = []
        
        for idx, sensor in enumerate(sensors):
            sensor_validation = {
                'index': idx,
                'name': sensor.get('name', f'sensor_{idx}'),
                'valid': True,
                'issues': []
            }
            
            # Check for required fields
            required_fields = ['name', 'min_margin', 'max_margin']
            for field in required_fields:
                if field not in sensor or not sensor[field]:
                    sensor_validation['issues'].append(f"Missing required field: {field}")
                    sensor_validation['valid'] = False
            
            # Check for duplicate sensor names
            sensor_name = sensor.get('name', f'sensor_{idx}')
            if sensor_name in sensor_names:
                sensor_validation['issues'].append(f"Duplicate sensor name: {sensor_name}")
                sensor_validation['valid'] = False
            else:
                sensor_names.append(sensor_name)
            
            # Store sensor validation result
            validation_result['sensor_validation'][f'sensor_{idx}'] = sensor_validation
            
            if not sensor_validation['valid']:
                validation_result['valid'] = False
                validation_result['errors'].extend([
                    f"Sensor {sensor_name}: {issue}" for issue in sensor_validation['issues']
                ])
        
        # Summary validation
        validation_result['summary'] = {
            'total_sensors': sensor_count,
            'valid_sensors': sum(1 for sv in validation_result['sensor_validation'].values() if sv['valid']),
            'sensor_types': voltage_sensors_data.get('sensor_types', {}),
            'voltage_ranges': voltage_sensors_data.get('voltage_ranges', {})
        }
        
        return validation_result
        
    except Exception as e:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Error validating voltage sensors data: {e}")
        return validation_result

def get_thermal_zone_fan_data(CfgDataG):
    cooling_devices = CfgDataG['tz_yaml_data']['defaults']['cooling_devices']
    if not cooling_devices:
        return False

    CfgDataG['fan_data']['pwm_range'] = cooling_devices['pwm_range']
    return True

def retrieve_thermal_zone_config_data(CfgDataG):
    """
    Complete function to read thermal zone YAML
    
    Args:
        CfgDataG: Configuration Info Dict
        
    Returns:
        dict: Complete voltage sensors dictionary with validation
    """
    result_dict = {
        'success': False,
        'errors': [],
        'warnings': []
    }
    
    try:
        st.log("=" * 60)
        st.log("THERMAL ZONE CONFIG SENSORS EXTRACTION")
        st.log("=" * 60)
        
        # Read thermal zone YAML from device
        yaml_content = read_thermal_zone_yaml_from_device(CfgDataG.dut)
        if not yaml_content:
            result_dict['errors'].append("Failed to read thermal zone YAML file")
            return result_dict
        
        # Parse YAML content
        yaml_data = parse_thermal_zone_yaml(yaml_content)
        if yaml_data is None:
            result_dict['errors'].append("YAML parsing failed")
            return result_dict

        if not yaml_data:
            result_dict['errors'].append("Thermal zone YAML is empty")
            return result_dict

        CfgDataG['tz_yaml_data'] = yaml_data
        result_dict['success'] = True
        return result_dict

    except Exception as e:
        result_dict['errors'].append(f"Error extracting thermal_zone configuration: {e}")
        st.error(f"Error in extracting thermal_zone configuration: {e}")
        return result_dict


def create_voltage_sensors_dictionary(CfgDataG):
    """
    Complete function to read thermal zone YAML and create voltage sensors dictionary

    Args:
        dut: Device under test

    Returns:
        dict: Complete voltage sensors dictionary with validation
    """
    result_dict = {
        'success': False,
        'voltage_sensors_data': {},
        'validation_result': {},
        'errors': [],
        'warnings': []
    }

    try:
        st.log("=" * 60)
        st.log("THERMAL ZONE VOLTAGE SENSORS EXTRACTION")
        st.log("=" * 60)

        # Read thermal zone YAML from device
        #yaml_content = read_thermal_zone_yaml_from_device(dut)
        #if not yaml_content:
        #    result_dict['errors'].append("Failed to read thermal zone YAML file")
        #    return result_dict

        # Parse YAML content
        #yaml_data = parse_thermal_zone_yaml(yaml_content)
        #if not yaml_data:
        #    result_dict['errors'].append("Failed to parse thermal zone YAML content")
        #    return result_dict
        
        # Extract voltage sensors data
        voltage_sensors_data = extract_voltage_sensors(CfgDataG['tz_yaml_data'])
        result_dict['voltage_sensors_data'] = voltage_sensors_data

        if voltage_sensors_data.get('extraction_errors'):
            result_dict['errors'].extend(voltage_sensors_data['extraction_errors'])
            return result_dict

        # Validate voltage sensors data
        validation_result = validate_voltage_sensors_data(voltage_sensors_data)
        result_dict['validation_result'] = validation_result

        if not validation_result['valid']:
            result_dict['errors'].extend(validation_result['errors'])
            return result_dict

        result_dict['success'] = True
        result_dict['warnings'].extend(validation_result.get('warnings', []))

        # Log results
        st.log("Voltage Sensors Extraction Results:")
        st.log(f"  Total Sensors: {voltage_sensors_data['sensor_count']}")

        st.log("\nVoltage Sensors List:")
        for idx, sensor in enumerate(voltage_sensors_data['voltage_sensors']):
            sensor_name = sensor.get('name', f'sensor_{idx}')
            sensor_type = sensor.get('type', 'unknown')
            st.log(f"  {idx+1}. {sensor_name} (type: {sensor_type})")

        if result_dict['warnings']:
            st.log("\nWarnings:")
            for warning in result_dict['warnings']:
                st.log(f"  - {warning}")

        st.log("\n✓ Voltage sensors extraction completed successfully")
        return result_dict

    except Exception as e:
        result_dict['errors'].append(f"Error creating voltage sensors dictionary: {e}")
        st.error(f"Error in voltage sensors extraction: {e}")
        return result_dict

def get_voltage_sensors_with_margining(CfgDataG):
    """
    Verify thermal zone voltage sensors configuration
    
    Args:
        dut: Device under test
        
    Returns:
        bool: True if extraction and validation successful, False otherwise
    """
    try:
        st.log("Starting thermal zone voltage sensors verification")
        
        # Create voltage sensors dictionary
        result = create_voltage_sensors_dictionary(CfgDataG)
        
        if result['success']:
            st.log("✓ Thermal zone voltage sensors verification PASSED")
            
            # Log detailed results
            validation_result = result['validation_result']
            summary = validation_result.get('summary', {})
            CfgDataG.vm_sensors = result['voltage_sensors_data']
             
            st.log(f"  Valid Sensors: {summary.get('valid_sensors', 0)}/{summary.get('total_sensors', 0)}")
            
            return True
        else:
            st.error("✗ Thermal zone vm sensors extraction FAILED")
            for error in result['errors']:
                st.error(f"  Error: {error}")
            return False
            
    except Exception as e:
        st.error(f"Error during thermal zone voltage sensors verification: {e}")
        return False

def parse_syseeprom_field(syseeprom_output, field_name):
    """
    Generic function to parse any field from syseeprom output

    Args:
        syseeprom_output (str): Raw syseeprom command output
        field_name (str): Name of the field to extract (e.g., "Product Name", "Serial Number")

    Returns:
        str: Field value or None if not found
    """
    if not syseeprom_output or not field_name:
        return None

    # Split output into lines
    lines = syseeprom_output.strip().split('\n')

    # Look for the specified field
    for line in lines:
        # Remove extra whitespace and split by multiple spaces
        parts = re.split(r'\s{2,}', line.strip())

        # Check if this line contains the field
        if len(parts) >= 3 and parts[0] == field_name:
            # Return the value (last part)
            return parts[-1]

    return None

def get_platform_details(CfgDataG):
    """
    Get comprehensive platform details from syseeprom

    Args:
        mgmt_ip (str): Management IP address

    Returns:
        dict: Platform details
    """
    try:
        syseeprom_out = st.config(CfgDataG.dut, "show platform syseeprom")
        CfgDataG.product_id = parse_syseeprom_field(syseeprom_out, "Product Name")
        CfgDataG.dut_base_mac = parse_syseeprom_field(syseeprom_out, "Base MAC Address")
        details = {
            'product_name': parse_syseeprom_field(syseeprom_out, "Product Name"),
            'part_number': parse_syseeprom_field(syseeprom_out, "Part Number"),
            'serial_number': parse_syseeprom_field(syseeprom_out, "Serial Number"),
            'platform_name': parse_syseeprom_field(syseeprom_out, "Platform Name"),
            'manufacturer': parse_syseeprom_field(syseeprom_out, "Manufacturer"),
        }

        st.log(f"{CfgDataG.logprefix} Platform details: {details}")
        return True

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} Error getting platform details: {e}")
        return False

def verify_file_exists(CfgDataG, dut, file_path):
    """
    Verify file existence using 'ls' command

    Args:
        dut: Device under test
        file_path (str): Full path to the file

    Returns:
        bool: True if file exists, False otherwise
    """
    try:
        st.log(f"Checking file existence using 'ls': {file_path}")

        # Use ls command to check if file exists
        cmd = f"ls -la {file_path}"
        output = st.config(dut, cmd, skip_error_check=True)

        # Check if command was successful
        if "No such file or directory" in output:
            st.log(f"{CfgDataG.logprefix}: File not found: {file_path}")
            return False
        elif "cannot access" in output:
            st.log(f"{CfgDataG.logprefix}: Cannot access file: {file_path}")
            return False
        else:
            st.log(f"{CfgDataG.logprefix}: File exists: {file_path}")
            st.log(f"{CfgDataG.logprefix}: File details: {output.strip()}")
            return True

    except Exception as e:
        st.error(f"{CfgDataG.logprefix}: Error checking file with 'ls': {e}")
        return False

def deploy_hwqual_pkg(CfgDataG):

    # Verify whether pkg already deployed
    dst_filepath=os.path.join(CfgDataG.homedir, "sonic-hwqual_1.0_amd64.deb")
    if verify_file_exists(CfgDataG, CfgDataG.dut, dst_filepath):
        st.log(f"{CfgDataG.logprefix} Hwqual dpkg deployed already")
        return True

    st.log(f"{CfgDataG.logprefix} Download sonic-hwqual_1.0_amd64.deb")
    srcdir = os.path.dirname(os.path.abspath(__file__))
    src_filepath = os.path.join(srcdir, "sonic-hwqual_1.0_amd64.deb")
    cmd = "wget -O " + src_filepath + " https://engci-maven.cisco.com/artifactory/whitebox-group/cisco-wb-hwqual/releases/sonic-hwqual_1.0_amd64.deb"
    os.system(cmd)
    if os.path.exists(src_filepath):
        st.log(f"{CfgDataG.logprefix} Hwqual pkg sonic-hwqual_1.0_amd64.deb download success")
    else:
        return False

    st.log(f"{CfgDataG.logprefix} Copy hwqual dpkg to DUT ##")
    st.upload_file_to_dut(CfgDataG.dut, src_filepath, dst_filepath)

    ## Deploy config on the DUT ##
    st.config(CfgDataG.dut, "sudo dpkg -i --force-overwrite "+ dst_filepath)
    st.tg_wait(CfgDataG.cfg_reload_timer)
    return True

def parse_vrf_output(input_text):
    """
    Parse VRF output into structured data

    Args:
        input_text (str): Raw VRF output from 'show vrf'

    Returns:
        Dict[str, List[str]]: Dictionary mapping VRF names to interface lists
    """
    vrf_data = {}
    lines = input_text.strip().split('\n')

    # Find header line
    header_line = -1
    for i, line in enumerate(lines):
        if 'VRF' in line and 'Interfaces' in line:
            header_line = i
            break

    if header_line == -1:
        print("ERROR: Could not find VRF table headers")
        return {}

    # Skip header and separator line
    data_start = header_line + 2

    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue

        # Split by whitespace, handling multiple spaces
        parts = re.split(r'\s+', line, 1)  # Split into max 2 parts

        if len(parts) >= 2:
            vrf_name = parts[0]
            interfaces_str = parts[1]

            # Parse interfaces (could be comma-separated or space-separated)
            interfaces = [iface.strip() for iface in re.split(r'[,\s]+', interfaces_str) if iface.strip()]

            vrf_data[vrf_name] = interfaces
        elif len(parts) == 1:
            # Handle case where VRF has no interfaces
            vrf_name = parts[0]
            vrf_data[vrf_name] = []

    return vrf_data

def check_vrf_interface_entry(vrf_data, target_vrf, target_interface):
    """
    Check if a specific VRF contains a specific interface

    Args:
        vrf_data (Dict): Parsed VRF data
        target_vrf (str): VRF name to check for
        target_interface (str): Interface name to check for

    Returns:
        bool: True if the VRF contains the interface, False otherwise
    """
    if target_vrf not in vrf_data:
        return False

    interfaces = vrf_data[target_vrf]
    return target_interface in interfaces

def validate_vrf_entry(input_text, vrf_name, interface_name):
    """
    Main validation function to check for VRF entry

    Args:
        input_text (str): Raw VRF output
        vrf_name (str): VRF name to validate (default: "Vrf0")
        interface_name (str): Interface name to validate (default: "Ethernet0")

    Returns:
        bool: True if entry exists, False otherwise
    """
    vrf_data = parse_vrf_output(input_text)

    if not vrf_data:
        print("ERROR: No VRF data found")
        return False

    return check_vrf_interface_entry(vrf_data, vrf_name, interface_name)

# Integration function for spytest framework
def is_vrf_configured(dut, vrf_name, interface_name):
    """
    Spytest integration function for VRF interface validation

    Args:
        dut: Device under test
        vrf_name (str): VRF name to validate
        interface_name (str): Interface name to validate

    Returns:
        bool: True if VRF entry exists, False otherwise
    """
    try:

        # Get VRF data from device
        vrf_output = st.config(dut, "show vrf", skip_error_check=True)

        if not vrf_output:
            st.error("Failed to get VRF data from device")
            return False

        # Validate VRF entry
        entry_exists = validate_vrf_entry(vrf_output, vrf_name, interface_name)

        if entry_exists:
            st.log(f"✓ VRF configuration exist")
        else:
            st.log(f"✗ VRF configuration not found")

        return entry_exists

    except Exception as e:
        if 'st' in locals():
            st.error(f"VRF validation error: {e}")
        return False

def parse_vlan_output(input_text):
    """
    Parse VLAN output into structured data

    Args:
        input_text (str): Raw Vlan output from 'show vlan config'

    Returns:
        Dict[str, List[str]]: Dictionary mapping VLAN names to interface lists
    """
    vlan_data = {}
    lines = input_text.strip().split('\n')

    # Find header line
    header_line = -1
    for i, line in enumerate(lines):
        if 'VID' in line and 'Member' in line:
            header_line = i
            break

    if header_line == -1:
        print("ERROR: Could not find VLAN table headers")
        return {}

    # Skip header and separator line
    data_start = header_line + 2

    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue

        # Split by whitespace, handling multiple spaces
        #parts = re.split(r'\s+', line, 1)  # Split into max 2 parts
        parts = line.split()

        if len(parts) >= 4:
            vlan_name = parts[0]
            interfaces_str = parts[2]

            if vlan_name in vlan_data:
                continue

            # Parse interfaces (could be comma-separated or space-separated)
            interfaces = [iface.strip() for iface in re.split(r'[,\s]+', interfaces_str) if iface.strip()]

            vlan_data[vlan_name] = interfaces
        elif len(parts) == 1:
            # Handle case where VRF has no interfaces
            vlan_name = parts[0]
            vlan_data[vlan_name] = []

    return vlan_data

def check_vlan_interface_entry(vlan_data, target_vlan, target_interface):
    """
    Check if a specific VLAN contains a specific interface

    Args:
        vlan_data (Dict): Parsed VLAN data
        target_vlan (str): VLAN name to check for
        target_interface (str): Interface name to check for

    Returns:
        bool: True if the VLAN contains the interface, False otherwise
    """
    if target_vlan not in vlan_data:
        return False

    interfaces = vlan_data[target_vlan]
    return target_interface in interfaces


def validate_vlan_entry(input_text, vid, interface_name):
    """
    Main validation function to check for VLAN entry

    Args:
        input_text (str): Raw VLAN output
        vid (str): VLAN num to validate (default: "Vlan10")
        interface_name (str): Interface name to validate (default: "Ethernet0")

    Returns:
        bool: True if entry exists, False otherwise
    """
    vlan_data = parse_vlan_output(input_text)

    if not vlan_data:
        print("ERROR: No VLAN data found")
        return False

    return check_vlan_interface_entry(vlan_data, vid, interface_name)

def is_vlan_configured(dut, vid, interface_name):
    """
    Spytest integration function for VLAN interface validation

    Args:
        dut: Device under test
        vid (str): VLAN number to validate
        interface_name (str): Interface name to validate

    Returns:
        bool: True if VLAN entry exists, False otherwise
    """
    try:

        # Get VLAN data from device
        vlan_output = st.config(dut, "show vlan config", skip_error_check=True)

        if not vlan_output:
            st.error("Failed to get VLAN data from device")
            return False

        # Validate VLAN entry
        entry_exists = validate_vlan_entry(vlan_output, vid, interface_name)

        if entry_exists:
            st.log(f"✓ VLAN configuration exist")
        else:
            st.log(f"✗ VLAN configuration not found")

        return entry_exists

    except Exception as e:
        if 'st' in locals():
            st.error(f"VLAN validation error: {e}")
        return False

def check_external_loopback_exist(input_text):
    """
    Parse LLDP output into structured data

    Args:
        input_text (str): Raw lldp table output from 'show lldp table'

    Returns:
        bool: True or False
    """
    e_loopback = False
    lines = input_text.strip().split('\n')

    # Find header line
    header_line = -1
    for i, line in enumerate(lines):
        if 'Capability' in line and 'codes' in line:
            header_line = i
            break

    if header_line == -1:
        print("ERROR: Could not find VLAN table headers")
        return {}

    # Skip header and separator line
    data_start = header_line + 3

    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue

        # Split by whitespace, handling multiple spaces
        #parts = re.split(r'\s+', line, 1)  # Split into max 2 parts
        parts = line.split()

        if len(parts) >= 5:
            localport = parts[0]
            remoteport = parts[4]

            if localport != remoteport:
                e_loopback = True
                break

    return e_loopback

def is_ext_loop_exist(CfgDataG):
    try:

        # Get LLDP table data from device
        lldp_output = st.config(CfgDataG.dut, "show lldp table", skip_error_check=True)

        if not lldp_output:
            st.error("Failed to get LLDP data from device")
            return False

        # Check external loopback connection
        entry_exists = check_external_loopback_exist(lldp_output)

        if entry_exists:
            st.log(f"✓ External loopback exist")
        else:
            st.log(f"✗ External loopback not found")

        return entry_exists

    except Exception as e:
        if 'st' in locals():
            st.error(f"LLDP validation error: {e}")
        return False

def parse_ipaddress(input_text):
    """
    Parse ip interfaces output into structured data

    Args:
        input_text (str): ip interfaces table output from 'show ip interfaces'

    Returns:
        Dict[str, List[str]]: Dictionary mapping interface names to ipaddress
    """
    ipdata = {}
    lines = input_text.strip().split('\n')

    # Find header line
    header_line = -1
    for i, line in enumerate(lines):
        if 'Interface' in line and 'IPv4' in line:
            header_line = i
            break

    if header_line == -1:
        print("ERROR: Could not find IP interfaces table headers")
        return {}

    # Skip header and separator line
    data_start = header_line + 1
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('-'):
            continue

        parts = line.split()
        if len(parts) >= 6:
            parts = line.split()
            intf = parts[0]
            ipdata[intf] = parts[2]

    return ipdata

def get_interface_ipaddress(CfgDataG, ifname):
    try:
        # Get IP table data from device
        ip_output = st.config(CfgDataG.dut, "show ip interfaces", skip_error_check=True)
        if not ip_output:
            st.error("Failed to get ip data from device")
            return False

        # Check external loopback connection
        ipdata = parse_ipaddress(ip_output)
        if ipdata:
            if ifname in ipdata:
                return ipdata[ifname]
        return None
    except Exception as e:
        if 'st' in locals():
            st.error(f"Get IP interfaces error: {e}")
        return False


def get_connected_interface_ipaddress(CfgDataG, ifname):
    try:
        ipinfo = get_interface_ipaddress(CfgDataG, ifname)
        if ipinfo:
            network = ipaddress.IPv4Interface(ipinfo)
            conn_ip = network.ip + 1
            return f"{conn_ip}"
        return None
    except Exception as e:
        if 'st' in locals():
            st.error(f"Connected IP error: {e}")
        return False

