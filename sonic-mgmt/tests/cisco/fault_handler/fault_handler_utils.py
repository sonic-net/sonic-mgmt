"""
Utility module for fault handler test helpers
Contains common utility methods used across fault handler test suites
"""

import logging
import re
import time
import json
import shlex
import datetime

logger = logging.getLogger(__name__)

# Redis database constants
STATE_DB = 6


class FaultHandlerTestHelper:
    """Helper class containing common utility methods for fault handler tests"""
    
    # Centralized sensor data configuration for all test suites
    SENSOR_DATA = {
        "t_data": {
            "critical_high_threshold": "105.0",
            "high_threshold": "100.0",
            "low_threshold": "-5.0",
            "critical_low_threshold": "-10.0",
            "is_replaceable": "False",
            "maximum_temperature": "51.0",
            "minimum_temperature": "37.0",
            "temperature": "50.0",  # Safe value in normal range (-5.0 to 100.0)
            "warning_status": "False"  # No warning by default
        },
        "v_data": {
            "critical_high_threshold": "14400",
            "high_threshold": "13800",
            "low_threshold": "10200",
            "critical_low_threshold": "8000",
            "is_replaceable": "False",
            "maximum_voltage": "N/A",
            "minimum_voltage": "N/A",
            "unit": "mV",
            "voltage": "12000",  # Safe value in normal range (10200 to 13800)
            "warning_status": "False"  # No warning by default
        },
        "c_data": {
            "critical_high_threshold": "9000",
            "high_threshold": "7000",
            "low_threshold": "2000",
            "critical_low_threshold": "1000",
            "is_replaceable": "False",
            "maximum_current": "N/A",
            "minimum_current": "N/A",
            "unit": "mA",
            "current": "4500",  # Safe value in normal range (2000 to 7000)
            "warning_status": "False"  # No warning by default
        }
    }
    
    @staticmethod
    def verify_services_status(dut, services, dut_hostname):
        """Verify that services are active and enabled"""
        for service in services:
            status = dut.shell(f"systemctl is-active {service}", module_ignore_errors=True)
            enabled = dut.shell(f"systemctl is-enabled {service}", module_ignore_errors=True)
            assert status['stdout'].strip() == 'active', f"{service} is not active on DUT {dut_hostname}"
            assert enabled['stdout'].strip() == 'enabled', f"{service} is not enabled on DUT {dut_hostname}"
            logger.info(f"{service}: active and enabled")
    
    @staticmethod
    def check_service_restart_logs(dut, services, time_range, dut_hostname):
        """Check service logs for restart patterns and failures"""
        restart_patterns = [
            r'Failed with result',
            r'Restart.*failed',
            r'status=[0-9]+/FAILURE',
            r'systemd.*restart',
            r'Main process exited'
        ]
        
        for service in services:
            result = dut.shell(f"journalctl -u {service} --since '{time_range}' --no-pager", module_ignore_errors=True)
            log = result['stdout']
            restart_count = 0
            for pattern in restart_patterns:
                matches = re.findall(pattern, log, re.IGNORECASE)
                restart_count += len(matches)
            assert restart_count <= 1, f"{service} shows signs of restart/failure on DUT {dut_hostname}: {restart_count}"
            logger.info(f"{service}: clean startup logs")
    
    @staticmethod
    def create_test_fault(dut, sensor, sensor_data, table_name):
        """
        Create a test fault condition in Redis
        
        Args:
            dut: Device under test
            sensor: Sensor name
            sensor_data: Dictionary of sensor data fields from SENSOR_DATA
                        Example: FaultHandlerTestHelper.SENSOR_DATA["t_data"]
            table_name: Redis table name (e.g., 'TEMPERATURE_INFO', 'VOLTAGE_INFO', 'CURRENT_INFO')
        """
        compound_key = f"{table_name}|{sensor}"
        fields_str = ""
        for field, value in sensor_data.items():
            fields_str += f" {shlex.quote(field)} {shlex.quote(str(value))}"
        timestamp = datetime.datetime.now().strftime("%Y%m%d %H:%M:%S")
        fields_str += f' timestamp "{timestamp}"'
        if fields_str:
            cmd = f'redis-cli -n {STATE_DB} HMSET {shlex.quote(compound_key)}{fields_str}'
            logger.info(f'Setting sensor data in Redis: {compound_key}')
            dut.shell(cmd, module_ignore_errors=True)
    
    @staticmethod
    def verify_fault_exists(dut, sensor, max_attempts=6, wait_seconds=5):
        """Verify that a fault exists in FAULT_INFO_TABLE with retry logic"""
        for attempt in range(max_attempts):
            fault_exists = dut.shell(f"redis-cli -n {STATE_DB} EXISTS 'FAULT_INFO_TABLE|{sensor}'", module_ignore_errors=True)['stdout'].strip()
            if fault_exists == "1":
                return True
            time.sleep(wait_seconds)
            logger.info(f"Waiting for fault {sensor} to be created (attempt {attempt + 1}/{max_attempts})")
        return False
    
    @staticmethod
    def cleanup_test_sensors(dut, sensors, table_names=None):
        """
        Clean up test sensor data from Redis
        
        Args:
            dut: Device under test
            sensors: List of sensor names to clean up
            table_names: List of table names to delete from. Options:
                        - None (default): Cleans all sensor tables + FAULT_INFO_TABLE
                        - ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE']: Cleans only these tables
        """
        if table_names is None:
            # Default: clean all sensor info tables + fault table
            table_names = ['TEMPERATURE_INFO', 'VOLTAGE_INFO', 'CURRENT_INFO', 'FAULT_INFO_TABLE']
        
        for sensor in sensors:
            for table in table_names:
                dut.shell(f"redis-cli -n {STATE_DB} DEL '{table}|{sensor}'", module_ignore_errors=True)
    
    @staticmethod
    def parse_obfl_entries(obfl_content, sensors):
        """Parse OBFL content and return alarm entries for specified sensors"""
        obfl_lines = [line.strip() for line in obfl_content.split('\n') if line.strip()]
        sensor_entries = {}
        
        for sensor in sensors:
            sensor_alarm_entries = []
            for line in obfl_lines:
                # Skip header lines and separator lines
                if 'Time' in line and 'Action' in line and 'Component' in line:
                    continue
                if '=' in line:
                    continue
                if not line:
                    continue
                    
                # Check if our sensor appears in the line
                parts = line.split()
                if len(parts) >= 5:
                    component_and_comment = ' '.join(parts[4:])
                    if sensor in component_and_comment:
                        if any(action in line for action in ['DECLARE', 'CLEAR']):
                            sensor_alarm_entries.append(line)
            
            sensor_entries[sensor] = sensor_alarm_entries
        
        return sensor_entries
    
    @staticmethod
    def validate_obfl_entries(sensor_entries, expected_critical_min=1, expected_major_max=0, expected_clear_max=0):
        """Validate OBFL entries for sensors based on expected counts"""
        for sensor, entries in sensor_entries.items():
            declare_count = sum(1 for entry in entries if 'DECLARE' in entry)
            clear_count = sum(1 for entry in entries if 'CLEAR' in entry)
            critical_count = sum(1 for entry in entries if 'CRITICAL' in entry)
            major_count = sum(1 for entry in entries if 'MAJOR' in entry)
            
            logger.info(f"OBFL analysis for {sensor}: {len(entries)} total entries")
            logger.info(f"  Actions: {declare_count} DECLARE, {clear_count} CLEAR")
            logger.info(f"  Severities: {critical_count} CRITICAL, {major_count} MAJOR")
            
            # Validate based on expectations
            if clear_count > expected_clear_max:
                clear_entries = [entry for entry in entries if 'CLEAR' in entry]
                for entry in clear_entries:
                    logger.error(f"  Unexpected CLEAR: {entry}")
                assert False, f"Unexpected CLEAR OBFL entries for {sensor}: {clear_count} (expected <= {expected_clear_max})"
            
            if critical_count < expected_critical_min:
                assert False, f"Missing CRITICAL OBFL entries for {sensor}: {critical_count} (expected >= {expected_critical_min})"
            
            if major_count > expected_major_max:
                major_entries = [entry for entry in entries if 'MAJOR' in entry]
                for entry in major_entries:
                    logger.error(f"  Unexpected MAJOR: {entry}")
                assert False, f"Unexpected MAJOR OBFL entries for {sensor}: {major_count} (expected <= {expected_major_max})"
            
            logger.info(f"OBFL entries for {sensor} are valid")
    
    @staticmethod
    def restart_fault_handler_service(dut, dut_hostname):
        """Restart fault handler service and verify it's running"""
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(5)
        status = dut.shell("systemctl is-active platform-fault-handler.service", module_ignore_errors=True)
        assert status['stdout'].strip() == 'active', f"Fault handler service failed to restart on DUT {dut_hostname}"
    
    @staticmethod
    def wait_for_redis_connectivity(dut, max_attempts=20, wait_seconds=5):
        """Wait for Redis to be available"""
        for attempt in range(max_attempts):
            result = dut.shell("redis-cli ping", module_ignore_errors=True)
            if result['rc'] == 0 and result['stdout'].strip() == 'PONG':
                logger.info("Redis connectivity confirmed")
                return True
            logger.info(f"Waiting for Redis connectivity (attempt {attempt + 1}/{max_attempts})")
            time.sleep(wait_seconds)
        return False
    
    @staticmethod
    def check_fault_table_rebuild(dut, expected_sensors, max_attempts=15, wait_seconds=4):
        """Check if fault table is properly rebuilt after service restart"""
        for attempt in range(max_attempts):
            rebuilt_count = 0
            for sensor in expected_sensors:
                fault_exists = dut.shell(f"redis-cli -n {STATE_DB} EXISTS 'FAULT_INFO_TABLE|{sensor}'", module_ignore_errors=True)['stdout'].strip()
                if fault_exists == "1":
                    rebuilt_count += 1
            if rebuilt_count == len(expected_sensors):
                logger.info(f"Fault table successfully rebuilt with {rebuilt_count} sensors")
                return True
            logger.info(f"Fault table rebuild in progress: {rebuilt_count}/{len(expected_sensors)} sensors (attempt {attempt + 1}/{max_attempts})")
            time.sleep(wait_seconds)
        return False
    
    @staticmethod
    def monitor_service_logs(dut, service, pattern, max_attempts=10, wait_seconds=3):
        """Monitor service logs for specific patterns"""
        for attempt in range(max_attempts):
            result = dut.shell(f"journalctl -u {service} --since '30 seconds ago' --no-pager", module_ignore_errors=True)
            if result['rc'] == 0 and pattern in result['stdout']:
                logger.info(f"Found expected pattern '{pattern}' in {service} logs")
                return True
            time.sleep(wait_seconds)
        return False
    
    @staticmethod
    def get_platform_policy_path(dut):
        """Get the platform-specific fault policy file path"""
        # Get platform summary to determine the correct path
        platform_result = dut.shell("show platform summary | grep Platform", module_ignore_errors=True)
        if platform_result['rc'] == 0:
            # Extract platform string (e.g., "Platform: x86_64-88_lc0_36fh-r0")
            platform_line = platform_result['stdout'].strip()
            platform_name = platform_line.split(':')[-1].strip()
            policy_path = f"/usr/share/sonic/device/{platform_name}/fault_policy.json"
            logger.info(f"Detected platform-specific policy path: {policy_path}")
            return policy_path
        else:
            # Fallback to generic path
            logger.warning("Could not detect platform, using fallback path")
            return "/usr/share/sonic/device/cisco-8000/fault_policy.json"
    
    @staticmethod
    def create_policy_file(dut, policy_content):
        """Create or update fault policy file"""
        policy_path = FaultHandlerTestHelper.get_platform_policy_path(dut)
        policy_json = json.dumps(policy_content, indent=2)
        dut.shell(f"echo '{policy_json}' > {policy_path}", module_ignore_errors=True)
        logger.info(f"Fault policy file created/updated at {policy_path}")
    
    @staticmethod
    def backup_and_restore_policy(dut, restore=False):
        """Backup or restore original policy file"""
        policy_path = FaultHandlerTestHelper.get_platform_policy_path(dut)
        backup_path = f"{policy_path}.backup"
        if restore:
            dut.shell(f"mv {backup_path} {policy_path}", module_ignore_errors=True)
            logger.info(f"Original policy file restored: {policy_path}")
        else:
            dut.shell(f"cp {policy_path} {backup_path}", module_ignore_errors=True)
            logger.info(f"Policy file backed up: {backup_path}")
    
    @staticmethod
    def check_obfl_alarms(dut, sensor_name=None):
        """Check OBFL alarms and optionally filter by sensor"""
        result = dut.shell("show platform obfl alarms", module_ignore_errors=True)
        if result['rc'] == 0:
            if sensor_name:
                # Filter for specific sensor
                lines = result['stdout'].split('\n')
                sensor_lines = [line for line in lines if sensor_name in line]
                return '\n'.join(sensor_lines)
            return result['stdout']
        return ""

    @staticmethod
    def wait_for_system_recovery(dut, localhost, reboot_type='cold', safe_reboot=True, 
                                  check_intf_up_ports=False, dut_datetime=None):
        """
        Wait for system to recover after reboot
        
        Args:
            dut: Device under test
            localhost: Localhost object
            reboot_type: Type of reboot (cold, warm, fast) - used for timeout/wait defaults
            safe_reboot: If True, wait for all critical services to start
            check_intf_up_ports: If True, check that interfaces are operationally up
            dut_datetime: DUT datetime before reboot (to verify reboot occurred)
        
        Returns:
            bool: True if system recovered successfully, False otherwise
        """
        import time
        import os
        from tests.common.reboot import wait_for_startup, check_dshell_ready, reboot_ctrl_dict
        from tests.common.utilities import wait_until, get_plt_reboot_ctrl
        from tests.common.platform.processes_utils import wait_critical_processes
        from tests.common.platform.interface_utils import check_interface_status_of_up_ports
        from tests.common.helpers.assertions import pytest_assert
        from tests.common.helpers.dut_utils import ignore_t2_syslog_msgs
        
        hostname = dut.hostname
        delay = 10
        timeout = 0
        wait = 0
        
        try:
            # Get platform-specific reboot control settings
            tc_name = os.environ.get('PYTEST_CURRENT_TEST', '').split(' ')[0] if os.environ.get('PYTEST_CURRENT_TEST') else ''
            plt_reboot_ctrl = get_plt_reboot_ctrl(dut, tc_name, reboot_type) if tc_name else None
            reboot_ctrl = reboot_ctrl_dict[reboot_type]
            
            # Set timeout and wait values from reboot control dict
            if timeout == 0:
                timeout = reboot_ctrl['timeout']
            if wait == 0:
                wait = reboot_ctrl['wait']
            if plt_reboot_ctrl:
                # Use 'wait' and 'timeout' overrides from inventory if specified
                wait = plt_reboot_ctrl.get('wait', wait)
                timeout = plt_reboot_ctrl.get('timeout', timeout)
            if dut.get_facts().get("modular_chassis") and safe_reboot:
                wait = max(wait, 600)
                timeout = max(timeout, 420)
        except KeyError:
            raise ValueError('invalid reboot type: "{} for {}"'.format(reboot_type, hostname))
        
        logger.info('Wait for system up on {}: wait[{}], timeout[{}]'.format(hostname, wait, timeout))
        
        # Extend ignore fabric port msgs for T2 chassis with DNX chipset on Linecards
        ignore_t2_syslog_msgs(dut)
        
        # Wait for SSH to become available
        try:
            wait_for_startup(dut, localhost, delay, timeout)
        except Exception as e:
            logger.error(f'Failed to wait for SSH startup on {hostname}: {e}')
            raise
        
        logger.info('waiting for switch {} to initialize'.format(hostname))
        if safe_reboot:
            # The wait time passed in might not be guaranteed to cover the actual
            # time it takes for containers to come back up. Therefore, add 5
            # minutes to the maximum wait time. If it's ready sooner, then the
            # function will return sooner.
            
            # Update critical service list after rebooting in case critical services changed after rebooting
            pytest_assert(wait_until(200, 10, 0, dut.is_critical_processes_running_per_asic_or_host, "database"),
                          "Database did not start.")
            pytest_assert(wait_until(20, 5, 0, dut.is_service_running, "redis", "database"), "Redis DB did not start")
            
            dut.critical_services_tracking_list()
            pytest_assert(wait_until(wait + 400, 20, 0, dut.critical_services_fully_started),
                          "{}: All critical services should be fully started!".format(hostname))
            wait_critical_processes(dut)
            
            if check_intf_up_ports:
                pytest_assert(wait_until(wait + 300, 20, 0, check_interface_status_of_up_ports, dut),
                              "{}: Not all ports that are admin up on are operationally up".format(hostname))
            
            if dut.facts['asic_type'] == "cisco-8000":
                # Wait dshell initialization finish
                pytest_assert(wait_until(wait + 300, 20, 0, check_dshell_ready, dut),
                              "dshell not ready")
        else:
            time.sleep(wait)
        
        # Verify that reboot actually occurred by checking uptime
        if dut_datetime:
            logger.info('Verifying that reboot actually occurred on {}'.format(hostname))
            dut_uptime = dut.get_up_time()
            logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
            
            # Check if device actually rebooted
            if float(dut_uptime.strftime("%s")) < float(dut_datetime.strftime("%s")):
                logger.info('DUT {} timestamp went backwards, waiting for time sync'.format(hostname))
                # Wait for time to sync properly
                max_wait_time = 120
                for attempt in range(max_wait_time // 5):
                    time.sleep(5)
                    dut_uptime = dut.get_up_time()
                    if float(dut_uptime.strftime("%s")) >= float(dut_datetime.strftime("%s")):
                        break
                    logger.debug('Waiting for time sync... (attempt {})'.format(attempt + 1))
            
            dut_uptime = dut.get_up_time()
            if float(dut_uptime.strftime("%s")) <= float(dut_datetime.strftime("%s")):
                error_msg = 'Device {} did not reboot. Uptime {} is not after pre-reboot time {}'.format(
                    hostname, dut_uptime, dut_datetime)
                logger.error(error_msg)
                pytest_assert(False, error_msg)
            logger.info('Reboot verified: uptime {} is after pre-reboot time {}'.format(dut_uptime, dut_datetime))
        
        logger.info('System is up on {}'.format(hostname))
        return True
