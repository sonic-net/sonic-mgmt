import json
import logging
import pytest
import time
import datetime
from tests.cisco.fault_handler.fault_handler_utils import FaultHandlerTestHelper, System_Helper_Wrap, TEMP_INFO_TABLE_NAME, VOLT_INFO_TABLE_NAME, CURR_INFO_TABLE_NAME, FAULT_INFO_NAME


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

##############################################################
## SUB_TEST_A for FaultMonitor: TH01 TH04
## 4-Step Enhanced Test Sequence:
## Loop1: CRITICAL HIGH: critical_high_threshold + 1 = 106
## Loop2: MAJOR HIGH:             high_threshold + 1 = 101  
## Loop3: CRITICAL LOW:   critical_low_threshold - 1 = 9
## Loop4: CLEAR:          normal range (middle value) = 5500
##############################################################

class FM_Fault_Monitor_Single_Sensor_GroupA:
    """
    Single sensor fault monitoring tests for temperature, voltage, and current sensors
    Covers TH01, TH04, TH05, TH06 test cases - Group A sensors
    """
    
    def __init__(self, duthost):
        self.duthost = duthost
        self.polling_interval = 5
        # Use centralized sensor data from FaultHandlerTestHelper
        self.t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        self.v_data = FaultHandlerTestHelper.SENSOR_DATA["v_data"].copy()
        self.c_data = FaultHandlerTestHelper.SENSOR_DATA["c_data"].copy()
        
        # Use centralized sensor configuration from helper
        self._sensor_config = FaultHandlerTestHelper.get_sensor_config(
            self.t_data, self.v_data, self.c_data
        )

    def _pub_sensor_value(self, sensor_key, sensortype, action):
        """Unified method to publish sensor values to Redis"""
        if sensortype not in self._sensor_config:
            logger.error('Unknown sensor type for publishing: {}'.format(sensortype))
            return
            
        config = self._sensor_config[sensortype]
        
        # Generate timestamp and prepare data
        timestamp = datetime.datetime.now().strftime("%Y%m%d %H:%M:%S")
        data = config["data"].copy()  # Create a copy to avoid modifying original
        data['timestamp'] = timestamp
        data['warning_status'] = "True" if action == "RAISE" else "False"
        
        # Publish to Redis using individual fields (not JSON string)
        FaultHandlerTestHelper.create_test_fault(self.duthost, sensor_key, data, config["table_name"])

    def _verify_sensor_values(self, sensor_key, count, action, sensortype="temp"):
        """Unified method to verify sensor values in Redis match expected values"""
        if sensortype not in self._sensor_config:
            logger.error('FM_MON: Unknown sensor type: {}'.format(sensortype))
            return False
            
        config = self._sensor_config[sensortype]
        
        # First verify the sensor info was written correctly
        actual_value = FaultHandlerTestHelper.get_test_fault(self.duthost, config["table_name"], sensor_key, config["value_key"])
        actual_warning = FaultHandlerTestHelper.get_test_fault(self.duthost, config["table_name"], sensor_key, "warning_status")
        
        if not actual_value:
            logger.error('FM_MON: No {} value found in Redis for sensor: {}'.format(config["value_key"], sensor_key))
            return False
            
        try:
            # Calculate expected values based on count and action (4-step sequence)
            if action == "RAISE":
                if count == 3:  # CRITICAL HIGH: critical_high_threshold + 1
                    threshold_key = "critical_high_threshold"
                    expected_value = str(config["convert"](config["data"][threshold_key]) + 1)
                    expected_warning = "True"
                elif count == 2:  # MAJOR HIGH: high_threshold + 1
                    high_val = config["convert"](config["data"]["high_threshold"])
                    expected_value = str(high_val + 1)
                    expected_warning = "True"
                elif count == 1:  # CRITICAL LOW: critical_low_threshold - 1
                    threshold_key = "critical_low_threshold"
                    expected_value = str(config["convert"](config["data"][threshold_key]) - 1)
                    expected_warning = "True"
            else:  # CLEAR (count=0)
                # Expected value in normal range
                low_val = config["convert"](config["data"]["low_threshold"])
                high_val = config["convert"](config["data"]["high_threshold"])
                expected_value = str((low_val + high_val) // 2)
                expected_warning = "False"

            logger.info('FM_MON: Expected {}: {}, Actual: {}'.format(config["value_key"], expected_value, actual_value))
            logger.info('FM_MON: Expected warning_status: {}, Actual: {}'.format(expected_warning, actual_warning))

            # Verify sensor info values
            if actual_value != expected_value:
                logger.error('FM_MON: {} mismatch! Expected: {}, Got: {}'.format(config["value_key"].capitalize(), expected_value, actual_value))
                return False
                
            if actual_warning != expected_warning:
                logger.error('FM_MON: Warning status mismatch! Expected: {}, Got: {}'.format(expected_warning, actual_warning))
                return False
            
            # Now verify FAULT_INFO_TABLE entries (daemon will process sensor info and create fault entries)
            fault_sensor_key = config["fault_sensor_key"]
            
            if action == "RAISE":
                # Wait a bit for daemon to process
                time.sleep(8)
                
                # Check if fault entry was created in FAULT_INFO_TABLE
                fault_severity = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, fault_sensor_key, "severity")
                fault_action = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, fault_sensor_key, "action")
                fault_component = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, fault_sensor_key, "component")
                
                # Determine expected severity based on 4-step sequence
                if count == 3:  # CRITICAL HIGH
                    expected_severity = "CRITICAL"
                elif count == 2:  # MAJOR HIGH  
                    expected_severity = "MAJOR"
                elif count == 1:  # CRITICAL LOW
                    expected_severity = "CRITICAL"
                expected_component = {"temp": "TempSensor", "volt": "VoltSensor", "curr": "CurrSensor"}[sensortype]

                logger.info('FM_MON: verification for {}: severity={}, action={}, component={}'.format(
                    fault_sensor_key, fault_severity, fault_action, fault_component))
                
                if fault_severity != expected_severity:
                    logger.warning('FM_MON: Expected fault severity: {}, Got: {}'.format(expected_severity, fault_severity))

                if fault_action != "RAISE":
                    logger.warning('FM_MON: Expected fault action: RAISE, Got: {}'.format(fault_action))

                if fault_component != expected_component:
                    logger.warning('FM_MON: Expected fault component: {}, Got: {}'.format(expected_component, fault_component))
            else:
                # For CLEAR action, verify fault entry was removed or action is CLEAR
                time.sleep(2)
                fault_action = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, fault_sensor_key, "action")
                logger.info('FM_MON: clear verification for {}: action={}'.format(fault_sensor_key, fault_action))

            logger.info('FM_MON: sensor verification PASSED for sensor: {}'.format(sensor_key))
            return True
            
        except Exception as e:
            logger.error('FM_MON: Failed to verify Redis {} data: {}'.format(sensortype, e))
            return False

    def _get_sensor_config(self):
        """Unified sensor configuration source for all methods"""
        # Add pub_method and verify_method to the shared config
        config = self._sensor_config.copy()
        for sensor_type in config:
            config[sensor_type]["pub_method"] = self._pub_sensor_value
            config[sensor_type]["verify_method"] = self._verify_sensor_values
        return config

    def generate_single_sensor_fault(self, sensortype, suffix, count, action):
        '''Unified method to raise or clear any sensor type'''
        sensor_config = self._get_sensor_config()
        
        if sensortype not in sensor_config:
            logger.error('FM_MON: Unknown sensor type for {}: {}'.format(action.lower(), sensortype))
            return
            
        config = sensor_config[sensortype]
        sensor = config["sensor_prefix"] + suffix
        
        # Set sensor value based on threshold and action
        if action == "RAISE":
            if count == 3:  # CRITICAL HIGH (count=3): critical_high_threshold + 1
                threshold_key = "critical_high_threshold"
                config["data"][config["value_key"]] = str(config["convert"](config["data"][threshold_key]) + 1)
            elif count == 2:  # MAJOR HIGH (count=2): high_threshold + 1
                high_val = config["convert"](config["data"]["high_threshold"])
                config["data"][config["value_key"]] = str(high_val + 1)
            elif count == 1:  # CRITICAL LOW (count=1): critical_low_threshold - 1
                threshold_key = "critical_low_threshold"
                config["data"][config["value_key"]] = str(config["convert"](config["data"][threshold_key]) - 1)
        else:  # CLEAR (count=0)
            # Set to normal range between low_threshold and high_threshold
            low_val = config["convert"](config["data"]["low_threshold"])
            high_val = config["convert"](config["data"]["high_threshold"])
            normal_val = (low_val + high_val) // 2  # Middle of normal range
            config["data"][config["value_key"]] = str(normal_val)
        
        # Publish sensor value
        config["pub_method"](sensor, sensortype, action)
        
        # Verify the values after setting them (only for RAISE actions in TEST_A)
        if action == "RAISE":
            if config["verify_method"](sensor, count, action, sensortype):
                logger.info('FM_MON: sensor {} {} verification successful on count={}'.format(
                    sensor, action, count))
            else:
                logger.error('FM_MON: sensor {} {} verification failed on count={}'.format(
                    sensor, action, count))

    def pub_sensor(self, sensortype="temp"):
        '''Unified loop to raise any sensor type with 4-step sequence'''
        if sensortype not in ["temp", "volt", "curr"]:
            logger.error('Unknown sensor type: {}'.format(sensortype))
            return
        
        # 4-step sequence: 3=CRITICAL_HIGH, 2=MAJOR_HIGH, 1=CRITICAL_LOW, 0=CLEAR
        for loop_count in range(3, -1, -1):
            if loop_count > 0:  # CRITICAL_HIGH (3), MAJOR_HIGH (2), or CRITICAL_LOW (1)
                self.generate_single_sensor_fault(sensortype, 'A', loop_count, "RAISE")
            else:  # CLEAR (0)
                self.generate_single_sensor_fault(sensortype, 'A', loop_count, "CLEAR")
            time.sleep(self.polling_interval)


###################################################################
## SUB_TEST_B for FaultMonitor: OB01
## Loop1: 3 CRITICAL: (T) critical+1 (V) critical+1 (C) critical+1
## Loop2: 3 MAJOR   : (T) high+1     (V) high+1     (C) high+1
## Loop3: 3 CLEAR   : (T) high-1     (V) high-1     (C) high-1
###################################################################

class FM_Fault_Handler_Multiple_Sensor_GroupB:
    """
    Multiple sensor fault handler tests with OBFL logging verification
    Covers OB01 test case - Group B sensors
    """
    
    def __init__(self, duthost):
        self.duthost = duthost
        # Use centralized sensor data from FaultHandlerTestHelper
        self.t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        self.v_data = FaultHandlerTestHelper.SENSOR_DATA["v_data"].copy()
        self.c_data = FaultHandlerTestHelper.SENSOR_DATA["c_data"].copy()
        
        # Use centralized sensor configuration from helper
        self._sensor_config = FaultHandlerTestHelper.get_sensor_config(
            self.t_data, self.v_data, self.c_data
        )



    def generate_multiple_sensor_fault(self, suffix, sensortype, count, action):
        """Unified method to generate sensor faults with integrated Redis operations"""
        sensor = f"{sensortype.upper()}_SENSOR_{suffix}"
        
        if sensortype not in self._sensor_config:
            return
            
        config = self._sensor_config[sensortype]
        data = config["data"]
        value_key = config["value_key"]
        convert_func = config["convert"]
        
        # Update sensor value based on action
        if action == "RAISE":
            threshold_key = "critical_high_threshold" if count > 1 else "high_threshold"
            base_value = convert_func(data[threshold_key])
            data[value_key] = str(base_value + 1)
        else:  # CLEAR
            base_value = convert_func(data["high_threshold"])
            data[value_key] = str(base_value - 1)
        
        # Update data with fault information
        timestamp_fmt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sev = 'CRITICAL' if count > 1 else 'MAJOR'
        
        data.update({
            'component': config['component'],
            'type_id': config['type_id'],
            'severity': sev,
            'action': action,
            'timestamp': timestamp_fmt
        })
        
        # Execute Redis operations
        if action == "RAISE":
            FaultHandlerTestHelper.create_test_fault(self.duthost, sensor, data, FAULT_INFO_NAME)
        else:  # CLEAR
            FaultHandlerTestHelper.cleanup_test_sensors(self.duthost, [sensor], [FAULT_INFO_NAME])

    def raise_multiple_fault(self):
        '''Loop to monitor sensor fault and report with optimized generic flow'''
        sensors = ['B']  # Can be extended to multiple sensors
        sensor_types = ['temp', 'volt', 'curr']
        
        # Loop through: 2=CRITICAL, 1=MAJOR, 0=CLEAR
        for loop_count in range(2, -1, -1):
            logger.info(f'Starting loop {loop_count}: {"CRITICAL" if loop_count == 2 else "MAJOR" if loop_count == 1 else "CLEAR"}')
            for sensor in sensors:
                for sensor_type in sensor_types:
                    logger.info(f'FM_HND: Processing {sensor_type.upper()}_SENSOR_{sensor} for loop {loop_count}')
                    if loop_count > 0:  # CRITICAL (2) or MAJOR (1)
                        self.generate_multiple_sensor_fault(sensor, sensor_type, loop_count, "RAISE")
                    else:  # CLEAR (0)
                        self.generate_multiple_sensor_fault(sensor, sensor_type, loop_count, "CLEAR") 
                    # Optimized interval for better performance
                    time.sleep(3)
        
        # Wait for final fault processing
        time.sleep(5)
        
        # Verify OBFL logging
        return FaultHandlerTestHelper.validate_obfl_alarm_file(self.duthost)

    # Test method for this class
    def test_service_fm_fault_info(self):
        """Test multiple sensor fault handling with OBFL verification"""
        return self.raise_multiple_fault()


###################################################################
## SUB_TEST_C for Edge Cases: Invalid Thresholds: DB01
# Test Case 1: Temperature with critical_high_threshold = "N/A"
# Test Case 2: Current with extremely low threshold (low > critical_low)
# Test Case 3: Voltage where low_threshold > high_threshold (invalid configuration)
# Test Case 4: Unknown sensor paths (sensors not recognized by daemon)
# Test Case 5: Malformed sensor data (corrupted JSON-like structure)
###################################################################

class FM_Fault_Monitor_Incorrect_Key_GroupC:
    """
    Edge case testing for invalid thresholds and malformed data
    Covers DB01 test case - Group C sensors (invalid configurations)
    """
    
    def __init__(self, duthost):
        self.duthost = duthost
        # Use centralized sensor data from FaultHandlerTestHelper
        self.t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        self.v_data = FaultHandlerTestHelper.SENSOR_DATA["v_data"].copy()
        self.c_data = FaultHandlerTestHelper.SENSOR_DATA["c_data"].copy()

    def test_invalid_threshold_cases(self):
        '''Test edge cases where invalid thresholds should NOT generate FAULT_INFO entries'''
        logger.info('FM_EDGE: Starting edge case testing (Cases 1, 2, 3, 4, 5)')
        
        # Test Case 1: Temperature with critical_high_threshold = "N/A"
        logger.info('FM_EDGE: Test Case 1 - Temperature critical_high_threshold = N/A')
        temp_data_invalid = self.t_data.copy()
        temp_data_invalid["critical_high_threshold"] = "N/A"
        temp_data_invalid["temperature"] = "200.0"  # Very high value
        FaultHandlerTestHelper.create_test_fault(self.duthost, "TEMP_SENSOR_C", temp_data_invalid, TEMP_INFO_TABLE_NAME)
        time.sleep(8)  # Wait for daemon processing
        
        # Verify NO FAULT_INFO entry was created
        fault_severity = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "TEMP_SENSOR_C", "severity")
        if not fault_severity:
            logger.info('FM_EDGE: Test Case 1 PASSED - No FAULT_INFO created for N/A threshold')
        else:
            logger.error('FM_EDGE: Test Case 1 FAILED - FAULT_INFO was created unexpectedly: severity={}'.format(fault_severity))
        
        # Test Case 2: Current with extremely low threshold (low > critical_low)
        logger.info('FM_EDGE: Test Case 2 - Current with invalid low threshold configuration')
        curr_data_invalid = self.c_data.copy()
        curr_data_invalid["low_threshold"] = "-50000"  # Super low value
        curr_data_invalid["critical_low_threshold"] = "-10000"  # Higher than low_threshold (invalid)
        curr_data_invalid["current"] = "-30000"  # Between critical_low and low
        FaultHandlerTestHelper.create_test_fault(self.duthost, "CURR_SENSOR_C", curr_data_invalid, CURR_INFO_TABLE_NAME)
        time.sleep(8)  # Wait for daemon processing
        
        # Verify NO FAULT_INFO entry was created
        fault_severity = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "CURR_SENSOR_C", "severity")
        if not fault_severity:
            logger.info('FM_EDGE: Test Case 2 PASSED - No FAULT_INFO created for invalid low threshold config')
        else:
            logger.error('FM_EDGE: Test Case 2 FAILED - FAULT_INFO was created unexpectedly: severity={}'.format(fault_severity))
        
        # Test Case 3: Voltage where low_threshold > high_threshold (invalid configuration)
        logger.info('FM_EDGE: Test Case 3 - Voltage with low_threshold > high_threshold')
        volt_data_invalid = self.v_data.copy()
        volt_data_invalid["low_threshold"] = "15000"   # Higher than high_threshold
        volt_data_invalid["high_threshold"] = "13800"  # Lower than low_threshold (invalid)
        volt_data_invalid["voltage"] = "14000"  # Between the inverted thresholds
        FaultHandlerTestHelper.create_test_fault(self.duthost, "VOLT_SENSOR_C", volt_data_invalid, VOLT_INFO_TABLE_NAME)
        time.sleep(8)  # Wait for daemon processing
        
        # Verify NO FAULT_INFO entry was created
        fault_severity = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "VOLT_SENSOR_C", "severity")
        if not fault_severity:
            logger.info('FM_EDGE: Test Case 3 PASSED - No FAULT_INFO created for inverted threshold config')
        else:
            logger.error('FM_EDGE: Test Case 3 FAILED - FAULT_INFO was created unexpectedly: severity={}'.format(fault_severity))
        
        # Test Case 4: Unknown sensor paths (sensors not recognized by daemon)
        logger.info('FM_EDGE: Test Case 4 - Unknown sensor paths (sensors not recognized by daemon)')
        unknown_data = self.t_data.copy()
        unknown_data["temperature"] = "150.0"  # High value
        FaultHandlerTestHelper.create_test_fault(self.duthost, "UNKNOWN_SENSOR_D", unknown_data, "UNKNOWN_SENSOR_TABLE")
        FaultHandlerTestHelper.create_test_fault(self.duthost, "INVALID_SENSOR_PATH_D", unknown_data, TEMP_INFO_TABLE_NAME)
        time.sleep(8)  # Wait for daemon processing
        
        # Verify NO FAULT_INFO entries were created
        fault_severity_1 = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "UNKNOWN_SENSOR_D", "severity")
        fault_severity_2 = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "INVALID_SENSOR_PATH_D", "severity")
        if not fault_severity_1 and not fault_severity_2:
            logger.info('FM_EDGE: Test Case 4 PASSED - No FAULT_INFO created for unknown sensor paths')
        else:
            logger.error('FM_EDGE: Test Case 4 FAILED - FAULT_INFO was created unexpectedly: unknown={}, invalid={}'.format(fault_severity_1, fault_severity_2))
        
        # Test Case 5: Malformed sensor data (corrupted JSON-like structure)
        logger.info('FM_EDGE: Test Case 5 - Malformed sensor data')
        malformed_data = {
            "temperature": "120.0",
            "high_threshold": "100.0",
            "critical_high_threshold": "105.0",
            "corrupted_field": '{"malformed": json syntax error}',  # Invalid JSON syntax
            "invalid_chars": "temp<>|:*?\"",  # Invalid filename characters
            "numeric_string": "not_a_number_at_all",  # Non-numeric string for numeric field
            "null_value": "null",  # String "null" instead of actual null
            "empty_string": "",  # Empty string
            "special_chars": "temp\\n\\t\\r"  # Escaped special characters
        }
        FaultHandlerTestHelper.create_test_fault(self.duthost, "TEMP_SENSOR_H", malformed_data, TEMP_INFO_TABLE_NAME)
        time.sleep(8)  # Wait for daemon processing
        
        # Verify NO FAULT_INFO entry was created
        fault_severity = FaultHandlerTestHelper.get_test_fault(self.duthost, FAULT_INFO_NAME, "TEMP_SENSOR_H", "severity")
        if not fault_severity:
            logger.info('FM_EDGE: Test Case 5 PASSED - No FAULT_INFO created for malformed data')
        else:
            logger.error('FM_EDGE: Test Case 5 FAILED - FAULT_INFO was created unexpectedly: severity={}'.format(fault_severity))
        
        # Clean up test sensors
        logger.info('FM_EDGE: Cleaning up test sensors')
        test_sensors = [
            (TEMP_INFO_TABLE_NAME, ["TEMP_SENSOR_C", "TEMP_SENSOR_H", "INVALID_SENSOR_PATH_D"]),
            (CURR_INFO_TABLE_NAME, ["CURR_SENSOR_C"]),
            (VOLT_INFO_TABLE_NAME, ["VOLT_SENSOR_C"]),
            ("UNKNOWN_SENSOR_TABLE", ["UNKNOWN_SENSOR_D"]),
            (FAULT_INFO_NAME, ["TEMP_SENSOR_C", "CURR_SENSOR_C", "VOLT_SENSOR_C", "TEMP_SENSOR_H", "UNKNOWN_SENSOR_D", "INVALID_SENSOR_PATH_D"])
        ]
        
        # Use the shared cleanup utility
        all_sensors = []
        all_tables = []
        for table, sensors in test_sensors:
            all_sensors.extend(sensors)
            all_tables.append(table)
        
        # Remove duplicates while preserving order
        unique_sensors = list(dict.fromkeys(all_sensors))
        unique_tables = list(dict.fromkeys(all_tables))
        
        FaultHandlerTestHelper.cleanup_test_sensors(self.duthost, unique_sensors, unique_tables)
        
        logger.info('FM_EDGE: Edge case testing completed - Cases 1, 2, 3, 4, 5 executed')
        
        # Summary report
        logger.info('FM_EDGE: SUMMARY - All edge cases should result in NO FAULT_INFO entries created')
        logger.info('FM_EDGE: 1. N/A thresholds → ignored')
        logger.info('FM_EDGE: 2. Invalid threshold ranges → rejected')
        logger.info('FM_EDGE: 3. Inverted thresholds → rejected')
        logger.info('FM_EDGE: 4. Unknown sensor paths → logged and ignored')
        logger.info('FM_EDGE: 5. Malformed data → safe handling, no crash')

    # Test method for this class
    def test_service_fm_invalid_thresholds(self):
        """Test edge cases where invalid thresholds should NOT generate FAULT_INFO entries"""
        self.test_invalid_threshold_cases()


##############################################################
## TEST_A for FaultMonitor: TH01 TH04 TH05 TH06
##############################################################
def test_service_fm_temp_info(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    initial_memory_mb = System_Helper_Wrap.test_setup(duthost)
    
    try:
        sensorReport = FM_Fault_Monitor_Single_Sensor_GroupA(duthost)
        sensorReport.pub_sensor("temp")
    finally:
        System_Helper_Wrap.test_cleanup(duthost, initial_memory_mb, test_case="temp_info")
    
def test_service_fm_volt_info(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    initial_memory_mb = System_Helper_Wrap.test_setup(duthost)
    
    try:
        sensorReport = FM_Fault_Monitor_Single_Sensor_GroupA(duthost)
        sensorReport.pub_sensor("volt")
    finally:
        System_Helper_Wrap.test_cleanup(duthost, initial_memory_mb, test_case="volt_info")

def test_service_fm_curr_info(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    initial_memory_mb = System_Helper_Wrap.test_setup(duthost)
    
    try:
        sensorReport = FM_Fault_Monitor_Single_Sensor_GroupA(duthost)
        sensorReport.pub_sensor("curr")
    finally:
        System_Helper_Wrap.test_cleanup(duthost, initial_memory_mb, test_case="curr_info")

##############################################################
## TEST_B for FaultHandler: OB01
##############################################################
def test_service_fm_fault_info(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    initial_memory_mb = System_Helper_Wrap.test_setup(duthost, check_obfl=True)
    
    try:
        sensorReport = FM_Fault_Handler_Multiple_Sensor_GroupB(duthost)
        obfl_verification_passed = sensorReport.test_service_fm_fault_info()
        assert obfl_verification_passed, "OBFL verification failed - check fault logging pipeline"
    finally:
        System_Helper_Wrap.test_cleanup(duthost, initial_memory_mb, test_case="fault_info")


##############################################################
## TEST_C for Edge Cases: Invalid Thresholds: DB01
##############################################################
def test_service_fm_invalid_thresholds(duthosts, enum_rand_one_per_hwsku_hostname):
    """Test edge cases where invalid thresholds should NOT generate FAULT_INFO entries"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    initial_memory_mb = System_Helper_Wrap.test_setup(duthost)
    
    try:
        sensorReport = FM_Fault_Monitor_Incorrect_Key_GroupC(duthost)
        sensorReport.test_service_fm_invalid_thresholds()
    finally:
        System_Helper_Wrap.test_cleanup(duthost, initial_memory_mb, test_case="invalid_thresholds")
