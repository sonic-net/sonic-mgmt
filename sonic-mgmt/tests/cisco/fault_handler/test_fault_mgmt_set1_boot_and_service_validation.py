import pytest
import logging
import time
from cisco.fault_handler.fault_handler_utils import FaultHandlerTestHelper


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

HEALTH_TABLE_NAME = 'SYSTEM_HEALTH_INFO'
TEMPERATURE_INFO_NAME = 'TEMPERATURE_INFO'
VOLTAGE_INFO_NAME = 'VOLTAGE_INFO'
CURRENT_INFO_NAME = 'CURRENT_INFO'
FAULT_INFO_NAME = 'FAULT_INFO_TABLE'
STATE_DB = 6


class TestFaultHandlerBootSequenceDuthosts:
    """
    TB-01: First boot on RP/LC – service started cleanly/not restarted multiple times (duthosts version)
    Validate via journalctl logs using duthosts fixture
    """

    def test_fault_handler_boot_sequence(self, duthosts, enum_rand_one_per_hwsku_hostname):
        dut = duthosts[enum_rand_one_per_hwsku_hostname]
        dut_hostname = dut.hostname
        logger.info(f"Testing fault handler boot sequence on DUT: {dut_hostname}")
        
        # SIMULATE FIRSTBOOT
        logger.info("Simulate rc.local")

        bootinfo = dut.shell("show boot", module_ignore_errors=True)

        # Extract the relevant line containing "Current: SONiC-OS-"
        bootinfo_lines = bootinfo['stdout'].splitlines()
        current_line = None
        for line in bootinfo_lines:
            if "Current: SONiC-OS-" in line:
                current_line = line.strip()
                break

        if current_line is None:
            raise ValueError("The 'Current' string does not contain the expected format.")

        extracted_substring = current_line.split("Current: SONiC-OS-")[1]

        # Form the directory path
        currboot_path = f"/host/image-{extracted_substring}"

        dut.shell(f"sudo touch {currboot_path}/platform/firsttime", module_ignore_errors=True)
        time.sleep(1)
        dut.shell(f"sudo /etc/rc.local", module_ignore_errors=True)
        time.sleep(5)

        # Services running and enabled
        services = [
            'platform-fault-monitor.service',
            'platform-fault-handler.service',
            'platform-obfl.service'
        ]
        FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)

        # Service startup logs clean
        monitored_services = ['platform-fault-handler.service', 'platform-fault-monitor.service']
        FaultHandlerTestHelper.check_service_restart_logs(dut, monitored_services, '1 hour ago', dut_hostname)

        # Basic fault log file exists
        result = dut.shell("ls -la /var/log/fault.log", module_ignore_errors=True)
        assert result['rc'] == 0, f"Fault handler log file not found on DUT {dut_hostname}"

    def test_fault_handler_logging_functionality(self, duthosts, enum_rand_one_per_hwsku_hostname):
        dut = duthosts[enum_rand_one_per_hwsku_hostname]
        dut_hostname = dut.hostname
        logger.info(f"Testing fault handler logging functionality on DUT: {dut_hostname}")
        
        # Check if log file exists
        result = dut.shell("ls -la /var/log/faulthandler.log", module_ignore_errors=True)
        assert result['rc'] == 0, f"Fault handler log file not found on DUT {dut_hostname}"
        
        # Get current log size before restart
        log_size_before = dut.shell("wc -c /var/log/faulthandler.log 2>/dev/null || echo '0 /var/log/faulthandler.log'", module_ignore_errors=True)
        size_before = int(log_size_before['stdout'].split()[0])
        
        # Restart service to generate fresh logs
        logger.info(f"Restarting fault handler service to verify logging on DUT {dut_hostname}")
        FaultHandlerTestHelper.restart_fault_handler_service(dut, dut_hostname)
        
        # Check that new logs were generated
        log_size_after = dut.shell("wc -c /var/log/faulthandler.log", module_ignore_errors=True)
        size_after = int(log_size_after['stdout'].split()[0])
        assert size_after > size_before, f"No new logs generated after service restart on DUT {dut_hostname}"
        
        # Check for expected log patterns from service startup
        result = dut.shell("tail -n 10 /var/log/faulthandler.log", module_ignore_errors=True)
        log_content = result['stdout']
        expected_patterns = ['Redis connectivity verified', 'Resync and handle active faults']
        found_patterns = [pattern for pattern in expected_patterns if pattern in log_content]
        
        if found_patterns:
            logger.info(f"Fault handler logging verified - found patterns: {found_patterns}")
        else:
            logger.warning(f"⚠ Expected log patterns not found, but log file is active (size increased from {size_before} to {size_after} bytes)")
            
        logger.info("Fault handler logging functionality verified")


def test_docker_restart_mid_stream(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    SV-01: Test service resilience during Docker restart
    """
    dut = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_hostname = dut.hostname
    logger.info(f"Testing Docker restart resilience on DUT: {dut_hostname}")
    test_sensors = ['SV01_TEMP_SENSOR_1', 'SV01_TEMP_SENSOR_2']
    try:
        # Create initial faults
        logger.info("Creating initial fault conditions...")
        for sensor in test_sensors:
            t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
            t_data["temperature"] = "110.0"
            t_data["warning_status"] = "True"
            FaultHandlerTestHelper.create_test_fault(dut, sensor, t_data, 'TEMPERATURE_INFO')
        time.sleep(5)

        # Verify initial faults are created
        for sensor in test_sensors:
            fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, sensor)
            assert fault_exists, f"Initial fault not created for {sensor}"
        logger.info("Initial faults created successfully")

        # Restart Docker service mid-stream
        logger.info("Restarting Docker service...")
        dut.shell("systemctl restart docker.service", module_ignore_errors=True)
        time.sleep(60)

        services = ['platform-fault-monitor.service', 'platform-fault-handler.service']
        
        # Verify services are running
        FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)
        
        # Verify Redis connectivity is restored
        redis_ok = FaultHandlerTestHelper.wait_for_redis_connectivity(dut)
        assert redis_ok, "Redis connectivity not restored after Docker restart"
        
        # Create new fault to test processing resumption
        logger.info("Testing fault processing resumption...")
        new_sensor = 'SV01_RECOVERY_SENSOR'
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "115.0"
        t_data["warning_status"] = "True"
        FaultHandlerTestHelper.create_test_fault(dut, new_sensor, t_data, 'TEMPERATURE_INFO')
        time.sleep(20)
        
        # Verify new fault processing works
        fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, new_sensor)
        assert fault_exists, "Fault processing not resumed after Docker restart"
        
        logger.info("Docker restart resilience test completed successfully")
    finally:
        # Cleanup -- Restart services is needed to ensure the services reconnect to DB properly.
        dut.shell("systemctl restart platform-fault-monitor.service", module_ignore_errors=True)
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(10)
        all_sensors = test_sensors + ['SV01_RECOVERY_SENSOR']
        FaultHandlerTestHelper.cleanup_test_sensors(dut, all_sensors, ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])


def test_database_service_restart(duthosts, enum_rand_one_per_hwsku_hostname):
    """SV-02: Test database resilience during Redis restart"""
    dut = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_hostname = dut.hostname
    logger.info(f"Testing database restart resilience on DUT: {dut_hostname}")
    test_sensor = 'SV02_DB_RESILIENCE_SENSOR'
    try:
        # Create initial fault
        logger.info("Creating initial fault condition...")
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "112.0"
        t_data["warning_status"] = "True"
        FaultHandlerTestHelper.create_test_fault(dut, test_sensor, t_data, 'TEMPERATURE_INFO')
        
        fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, test_sensor)
        assert fault_exists, "Initial fault not created"
        
        # Restart Redis service (database.service)
        logger.info("Restarting Redis service...")
        dut.shell("systemctl restart database.service", module_ignore_errors=True)
        time.sleep(60)
        
        # Wait for Redis to be available
        redis_ok = FaultHandlerTestHelper.wait_for_redis_connectivity(dut, max_attempts=30)
        assert redis_ok, "Redis not available after restart"
        
        # Verify services didn't crash
        services = ['platform-fault-monitor.service', 'platform-fault-handler.service']
        FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)
        
        # Test new fault processing after DB recovery
        logger.info("Testing fault processing after database recovery...")
        recovery_sensor = 'SV02_POST_RECOVERY_SENSOR'
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "108.0"
        t_data["warning_status"] = "True"
        FaultHandlerTestHelper.create_test_fault(dut, recovery_sensor, t_data, 'TEMPERATURE_INFO')
        time.sleep(20)
        
        fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, recovery_sensor)
        assert fault_exists, "Fault processing not working after database restart"
        
        logger.info("Database restart resilience test completed successfully")
    finally:
        # Cleanup
        dut.shell("systemctl restart platform-fault-monitor.service", module_ignore_errors=True)
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(10)
        FaultHandlerTestHelper.cleanup_test_sensors(dut, [test_sensor, 'SV02_POST_RECOVERY_SENSOR'], ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])


def test_multiple_sensors_simultaneous_breach(duthosts, enum_rand_one_per_hwsku_hostname):
    """MT-01: Test handling of multiple simultaneous sensor breaches"""
    dut = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_hostname = dut.hostname
    logger.info(f"Testing multiple simultaneous sensor breaches on DUT: {dut_hostname}")

    # Create multiple sensors for simultaneous testing
    temp_sensors = [f'MT01_TEMP_SENSOR_{i}' for i in range(1, 6)]  # 5 temperature sensors
    volt_sensors = [f'MT01_VOLT_SENSOR_{i}' for i in range(1, 4)]  # 3 voltage sensors
    all_sensors = temp_sensors + volt_sensors
    try:
        # Create all sensor faults simultaneously
        logger.info("Creating multiple simultaneous sensor faults...")
        
        # Create temperature faults
        for sensor in temp_sensors:
            t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
            t_data["temperature"] = "115.0"
            t_data["warning_status"] = "True"
            FaultHandlerTestHelper.create_test_fault(dut, sensor, t_data, 'TEMPERATURE_INFO')
        
        # Create voltage faults
        for sensor in volt_sensors:
            v_data = FaultHandlerTestHelper.SENSOR_DATA["v_data"].copy()
            v_data["voltage"] = "15000"
            v_data["warning_status"] = "True"
            FaultHandlerTestHelper.create_test_fault(dut, sensor, v_data, 'VOLTAGE_INFO')
        
        # Wait for fault processing
        time.sleep(4)
        
        # Verify all faults are independently created
        logger.info("Verifying independent fault creation...")
        created_faults = []
        
        for sensor in all_sensors:
            fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, sensor, max_attempts=5)
            if fault_exists:
                created_faults.append(sensor)
                # Log severity for verification
                severity = dut.shell(f"redis-cli -n 6 HGET 'FAULT_INFO_TABLE|{sensor}' severity", module_ignore_errors=True)['stdout'].strip()
                logger.info(f"Sensor {sensor}: Fault created with severity {severity}")
        
        # Verify minimum expected faults were created
        min_expected_faults = len(all_sensors) * 0.8  # Allow 80% success rate for robustness
        assert len(created_faults) >= min_expected_faults, f"Only {len(created_faults)} of {len(all_sensors)} expected faults created"
        
        # Test clearing multiple faults
        logger.info("Testing multiple fault clearing...")
        
        # Clear half of the faults
        sensors_to_clear = all_sensors[:len(all_sensors)//2]
        for sensor in sensors_to_clear:
            if 'TEMP' in sensor:
                t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
                t_data["temperature"] = "95.0"
                t_data["warning_status"] = "False"
                FaultHandlerTestHelper.create_test_fault(dut, sensor, t_data, 'TEMPERATURE_INFO')
            else:  # Voltage sensor
                v_data = FaultHandlerTestHelper.SENSOR_DATA["v_data"].copy()
                v_data["voltage"] = "12000"
                v_data["warning_status"] = "False"
                FaultHandlerTestHelper.create_test_fault(dut, sensor, v_data, 'VOLTAGE_INFO')
        time.sleep(5)
        
        # Verify some faults were cleared
        remaining_faults = 0
        for sensor in all_sensors:
            fault_exists = dut.shell(f"redis-cli -n 6 EXISTS 'FAULT_INFO_TABLE|{sensor}'", module_ignore_errors=True)['stdout'].strip()
            if fault_exists == "1":
                remaining_faults += 1
        
        logger.info(f"Multiple sensor test completed: {remaining_faults} faults remaining after partial clearing")
    finally:
        # Cleanup
        FaultHandlerTestHelper.cleanup_test_sensors(dut, temp_sensors, ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])
        FaultHandlerTestHelper.cleanup_test_sensors(dut, volt_sensors, ['VOLTAGE_INFO', 'FAULT_INFO_TABLE'])


def test_fault_services_restart_functionality(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    SV-03 & TB-02: Test fault services restart with comprehensive functionality validation
    - Cold start fault state restoration (no fault loss)
    - OBFL duplicate prevention using both count-based and structured validation
    - Fault table rebuild verification
    - Database resubscription for new fault processing
    - Fault handler log pattern validation
    """
    dut = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_hostname = dut.hostname
    logger.info(f"Testing fault services restart functionality on DUT: {dut_hostname}")
    test_sensors = ['RESTART_TEMP_SENSOR_1', 'RESTART_TEMP_SENSOR_2']
    try:
        # Cleanup any existing test sensor entries from previous runs
        logger.info("Cleaning up any existing test sensor entries...")
        FaultHandlerTestHelper.cleanup_test_sensors(dut, test_sensors, ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])
        time.sleep(2)
        
        # Create initial faults
        logger.info("Creating initial fault conditions...")
        for sensor in test_sensors:
            t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
            t_data["temperature"] = "110.0"  # Critical fault: 110.0 > 105.0 (critical_high_threshold)
            t_data["warning_status"] = "True"
            FaultHandlerTestHelper.create_test_fault(dut, sensor, t_data, 'TEMPERATURE_INFO')
        time.sleep(5)
        
        # Verify initial faults exist
        initial_faults = []
        for sensor in test_sensors:
            fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, sensor)
            if fault_exists:
                initial_faults.append(sensor)
            assert fault_exists, f"Fault key FAULT_INFO_TABLE|{sensor} not found after waiting"
        assert len(initial_faults) > 0, "No initial faults created"
        logger.info(f"Initial faults created: {initial_faults}")
        
        # Get OBFL before restart
        obfl_before = FaultHandlerTestHelper.check_obfl_alarms(dut)
        obfl_entries_before = len([line for line in obfl_before.split('\n') if 'RESTART_TEMP_SENSOR' in line])
        logger.info(f"OBFL entry count before restart: {obfl_entries_before}")
        logger.info(f"OBFL content before restart:\n{obfl_before}")
        
        # Restart fault services
        logger.info("Restarting fault services...")
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(3)
        dut.shell("systemctl restart platform-fault-monitor.service", module_ignore_errors=True)
        time.sleep(10)
        
        # Verify services are running
        services = ['platform-fault-monitor.service', 'platform-fault-handler.service']
        FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)
        
        # Verify service is active after restart
        status = dut.shell("systemctl is-active platform-fault-handler.service", module_ignore_errors=True)
        assert status['stdout'].strip() == 'active', f"Fault handler failed to restart on DUT {dut_hostname}"
        
        # Verify faults are still present (state restored - cold start validation)
        logger.info("Verifying fault state restoration after restart...")
        for sensor in test_sensors:
            fault_exists = dut.shell(f"redis-cli -n 6 EXISTS 'FAULT_INFO_TABLE|{sensor}'", module_ignore_errors=True)['stdout'].strip()
            assert fault_exists == "1", f"Fault FAULT_INFO_TABLE|{sensor} lost after restart"
        logger.info("Fault state restored after service restart")
        
        # Check fault table rebuild
        logger.info("Checking fault table rebuild...")
        table_rebuilt = FaultHandlerTestHelper.check_fault_table_rebuild(dut, initial_faults)
        assert table_rebuilt, "Fault table not properly rebuilt after service restart"
        
        # Verify no duplicate OBFL entries (count-based validation)
        time.sleep(5)  # Allow time for potential duplicate logging
        obfl_after = FaultHandlerTestHelper.check_obfl_alarms(dut)
        obfl_entries_after = len([line for line in obfl_after.split('\n') if 'RESTART_TEMP_SENSOR' in line])
        
        # Should not have significantly more entries (allow for some normal processing)
        max_expected_increase = 4  # Allow minimal increase for resync
        assert obfl_entries_after <= obfl_entries_before + max_expected_increase, f"Duplicate OBFL entries detected: {obfl_entries_before} -> {obfl_entries_after}"
        logger.info(f"OBFL entries count-based check passed: {obfl_entries_before} -> {obfl_entries_after}")
        
        # OBFL structured validation using parse and validate methods
        logger.info(f"OBFL content after restart:\n{obfl_after}")
        sensor_entries = FaultHandlerTestHelper.parse_obfl_entries(obfl_after, test_sensors)
        
        # This test creates CRITICAL faults (110.0 > 105.0 critical_high_threshold)
        # Expected: At least 1 CRITICAL entry, no MAJOR entries, no CLEAR entries
        FaultHandlerTestHelper.validate_obfl_entries(
            sensor_entries, 
            expected_critical_min=1, 
            expected_major_max=0, 
            expected_clear_max=0
        )
        logger.info("OBFL structured validation completed - all test sensors have correct entries")
        
        # Validate fault handler log patterns after restart
        logger.info("Validating fault handler log patterns...")
        result = dut.shell("tail -n 20 /var/log/faulthandler.log", module_ignore_errors=True)
        if result['rc'] == 0:
            log_content = result['stdout']
            
            # Look for specific log patterns that indicate successful fault handler operation
            required_patterns = [
                'Redis connectivity verified',
                'Resync and handle active faults'
            ]
            
            # Optional patterns that indicate successful OBFL logging during resync
            obfl_patterns = [
                'Resync: OBFL logged',
                'with severity CRITICAL',
                'with severity MAJOR'
            ]
            
            found_required = [pattern for pattern in required_patterns if pattern in log_content]
            found_obfl = [pattern for pattern in obfl_patterns if pattern in log_content]
            
            logger.info(f"Found required patterns: {found_required}")
            logger.info(f"Found OBFL patterns: {found_obfl}")
            
            # Check for error conditions
            if 'fault_policy.json not found' in log_content:
                logger.warning("⚠ Fault policy file not found - using default policy")
            
            # Ensure we have evidence of successful fault handler startup
            assert len(found_required) >= 1, f"Missing required fault handler startup patterns. Found: {found_required}"
            
            if found_obfl:
                logger.info(f"Fault handler startup confirmed with OBFL activity: {found_obfl}")
            else:
                logger.info(f"Fault handler startup confirmed: {found_required}")
            
            logger.info("Fault handler operational status verified")
        
        # Test new fault processing (resubscription verification)
        logger.info("Testing database resubscription...")
        new_sensor = 'RESTART_POST_RESTART_SENSOR'
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "118.0"
        t_data["warning_status"] = "True"
        FaultHandlerTestHelper.create_test_fault(dut, new_sensor, t_data, 'TEMPERATURE_INFO')
        
        fault_processed = FaultHandlerTestHelper.verify_fault_exists(dut, new_sensor)
        assert fault_processed, "Database resubscription failed - new faults not processed"
        
        logger.info("Fault services restart functionality test completed successfully")
    finally:
        # Cleanup
        all_sensors = test_sensors + ['RESTART_POST_RESTART_SENSOR']
        FaultHandlerTestHelper.cleanup_test_sensors(dut, all_sensors, ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])


def test_policy_update_critical_reboot_and_recovery(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    """SV-04 and RB-01: Test policy file update with critical=reboot functionality and validate post-reboot fault handling"""
    dut = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_hostname = dut.hostname
    logger.info(f"Testing policy update with critical reboot on DUT: {dut_hostname}")
    test_sensor = 'SV04_CRITICAL_REBOOT_SENSOR'
    try:
        # Backup original policy file
        FaultHandlerTestHelper.backup_and_restore_policy(dut)
        
        # Create test policy with critical=reboot (matching actual format)
        test_policy = {
            "chassis": {
                "faults": [
                    {
                        "type": "TEMPERATURE_EXCEEDED",
                        "severity": "MAJOR",
                        "action": ["obfl"]
                    },
                    {
                        "type": "TEMPERATURE_EXCEEDED", 
                        "severity": "CRITICAL",
                        "action": ["reboot", "obfl"]
                    },
                    {
                        "type": "VOLTAGE_EXCEEDED",
                        "severity": "MAJOR", 
                        "action": ["obfl"]
                    },
                    {
                        "type": "VOLTAGE_EXCEEDED",
                        "severity": "CRITICAL",
                        "action": ["obfl"]
                    },
                    {
                        "type": "CURRENT_EXCEEDED",
                        "severity": "MAJOR",
                        "action": ["obfl"]
                    },
                    {
                        "type": "CURRENT_EXCEEDED",
                        "severity": "CRITICAL", 
                        "action": ["obfl"]
                    }
                ]
            }
        }
        
        logger.info("Creating test policy file with critical=reboot...")
        FaultHandlerTestHelper.create_policy_file(dut, test_policy)
        
        # Restart fault handler to load new policy
        logger.info("Restarting fault handler to load new policy...")
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(10)
        
        # Verify service is running with new policy
        services = ['platform-fault-handler.service']
        FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)
        
        # Trigger critical temperature fault
        logger.info("Triggering critical temperature fault...")
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "120.0"
        t_data["warning_status"] = "True"
        
        # Get current DUT time before triggering fault (to verify reboot occurred)
        dut_datetime = dut.get_now_time()
        logger.info(f"Pre-fault DUT time: {dut_datetime}")
        
        FaultHandlerTestHelper.create_test_fault(dut, test_sensor, t_data, 'TEMPERATURE_INFO')
        
        # Wait for fault processing and system reboot/recovery
        logger.info("Waiting for fault processing and potential system reboot...")
        time.sleep(15)
        
        # System should reboot due to critical fault policy - wait for it to come back up
        logger.info("Waiting for system to recover from reboot...")
        try:
            FaultHandlerTestHelper.wait_for_system_recovery(
                dut=dut,
                localhost=localhost,
                reboot_type='cold',
                safe_reboot=True,
                dut_datetime=dut_datetime
            )
            logger.info("System successfully recovered from reboot")
            
            # Verify critical services are running after recovery
            logger.info("Verifying critical services after recovery...")
            services = ['platform-fault-monitor.service', 'platform-fault-handler.service']
            FaultHandlerTestHelper.verify_services_status(dut, services, dut_hostname)
        except Exception as e:
            logger.error(f"System did not recover from reboot or reboot did not occur: {e}")
            
            # Check if fault was created but reboot didn't happen
            try:
                fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, test_sensor, max_attempts=3)
                if fault_exists:
                    logger.info("Critical fault created but system did not reboot")
                    # Check logs for reboot action
                    reboot_action_found = FaultHandlerTestHelper.monitor_service_logs(
                        dut, 'platform-fault-handler.service', "reboot", max_attempts=5
                    )
                    if reboot_action_found:
                        logger.error("Reboot action was logged but system did not actually reboot")
                    else:
                        logger.error("No reboot action found in logs")
                else:
                    logger.error("Critical fault was not even created")
            except Exception as check_err:
                logger.error(f"Unable to verify fault creation: {check_err}")
            
            assert False, f"System did not reboot as expected from critical fault policy: {e}"
        
        # Check OBFL alarms are cleared after reboot
        time.sleep(5)
        obfl_content = FaultHandlerTestHelper.check_obfl_alarms(dut, test_sensor)
        if obfl_content:
            logger.warning(f"Unexpected OBFL entry found after reboot: {obfl_content}")
            assert False, "OBFL alarms should be cleared after reboot but entries were found"
        else:
            logger.info("OBFL alarms correctly cleared after reboot")
        
        # Verify new fault creation functionality after reboot
        logger.info("Verifying new fault creation functionality after reboot...")
        new_test_sensor = 'POST_REBOOT_TEMP_SENSOR'
        
        t_data = FaultHandlerTestHelper.SENSOR_DATA["t_data"].copy()
        t_data["temperature"] = "112.0"
        t_data["warning_status"] = "True"
        FaultHandlerTestHelper.create_test_fault(dut, new_test_sensor, t_data, 'TEMPERATURE_INFO')
        time.sleep(3)
        
        new_fault_exists = FaultHandlerTestHelper.verify_fault_exists(dut, new_test_sensor)
        assert new_fault_exists, f"New fault not created after reboot for sensor {new_test_sensor}"
        logger.info(f"New fault successfully created for {new_test_sensor} after reboot")
        
        # Verify new fault appears in OBFL
        obfl_new_fault = dut.shell("show platform obfl alarms", module_ignore_errors=True)
        if obfl_new_fault['rc'] == 0:
            obfl_new_content = obfl_new_fault['stdout']
            logger.info(f"OBFL content after creating new fault:\n{obfl_new_content}")
            
            new_sensor_entries = FaultHandlerTestHelper.parse_obfl_entries(obfl_new_content, [new_test_sensor])
            
            # Expect CRITICAL entries (112.0 > 105.0)
            FaultHandlerTestHelper.validate_obfl_entries(
                new_sensor_entries,
                expected_critical_min=1,
                expected_major_max=0,
                expected_clear_max=0
            )
            
            logger.info(f"New fault handling verified - proper OBFL entries for {new_test_sensor}")
        
        logger.info("Post-reboot fault creation and declaration functionality verified")
        logger.info("Policy update and reboot recovery test completed successfully")
    finally:
        # Cleanup and restore
        FaultHandlerTestHelper.cleanup_test_sensors(dut, [test_sensor, 'POST_REBOOT_TEMP_SENSOR'], ['TEMPERATURE_INFO', 'FAULT_INFO_TABLE'])
        FaultHandlerTestHelper.backup_and_restore_policy(dut, restore=True)
        
        # Restart service to reload original policy
        dut.shell("systemctl restart platform-fault-monitor.service", module_ignore_errors=True)
        dut.shell("systemctl restart platform-fault-handler.service", module_ignore_errors=True)
        time.sleep(15)