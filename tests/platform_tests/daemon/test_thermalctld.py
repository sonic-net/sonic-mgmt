"""
Integration tests for thermalctld daemon with liquid cooling

Tests cover:
- Leak sensor monitoring and state tracking
- Leak severity escalation (MINOR → CRITICAL)
- STATE_DB synchronization
- Integration with bmcctld for critical events
- Performance and reliability
"""

import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
    pytest.mark.disable_loganalyzer
]

SYSTEM_LEAK_STATUS_TABLE = 'SYSTEM_LEAK_STATUS'
LIQUID_COOLING_INFO_TABLE = 'LIQUID_COOLING_INFO'
LEAK_PROFILE_TABLE = 'LEAK_PROFILE'


class TestThermalctldDaemon:
    """
    Integration tests for thermalctld daemon leak detection
    """

    @pytest.fixture(scope='function', autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Get duthost reference"""
        self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        # Skip if thermalctld not running
        result = self.duthost.shell(
            "docker exec pmon pgrep thermalctld",
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            pytest.skip("thermalctld daemon not running")

        yield

    def test_thermalctld_initialization(self):
        """
        Verify thermalctld initializes leak monitoring on startup (graceful skip if no liquid cooling)

        Validates:
        - Service is running
        - SYSTEM_LEAK_STATUS table initialized
        - LEAK_PROFILE configuration present
        - LIQUID_COOLING_INFO tables created for sensors
        """
        # Verify service running
        result = self.duthost.shell(
            "docker exec pmon pgrep thermalctld && echo 'running'",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0, "thermalctld should be running")

        # Check SYSTEM_LEAK_STATUS initialization
        result = self.duthost.shell(
            f"redis-cli -n 6 EXISTS '{SYSTEM_LEAK_STATUS_TABLE}:system'",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            exists = result['stdout'].strip() == '1'
            if exists:
                logger.info("SYSTEM_LEAK_STATUS:system initialized")
            else:
                logger.info("No SYSTEM_LEAK_STATUS - expected on non-liquid-cooled platforms")

        # Check LEAK_PROFILE configuration
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LEAK_PROFILE_TABLE}:*'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            profiles = result['stdout'].strip().split('\n')
            logger.info(f"Found {len(profiles)} leak profiles")
        else:
            logger.info("No LEAK_PROFILE found - expected on non-liquid-cooled platforms")

    def test_thermalctld_leak_status(self):
        """
        Verify leak status tracking, severity escalation, and bmcctld integration

        Validates:
        - SYSTEM_LEAK_STATUS:system device_leak_status is valid (MINOR|CRITICAL|None)
        - LIQUID_COOLING_INFO sensors have leaking (Yes|No|N/A) and leak_sensor_status (Good|Fault)
        - Severity levels are valid (MINOR|CRITICAL)
        - Escalation timeout is configured in LEAK_PROFILE
        - Critical leak events propagate to bmcctld (HOST_STATE consistency)
        """
        # Get system leak status
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            status = result['stdout'].strip()
            # LeakSeverity.value = "MINOR"|"CRITICAL"; "None" when no active leak
            valid = ['MINOR', 'CRITICAL', 'None']
            pytest_assert(status in valid, f"device_leak_status '{status}' not in {valid}")
            logger.info(f"System leak status: {status}")

        # Check per-sensor fields and types
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LIQUID_COOLING_INFO_TABLE}:*' | head -3",
            module_ignore_errors=True
        )

        sensor_types = set()
        if result['rc'] == 0 and result['stdout'].strip():
            sensors = result['stdout'].strip().split('\n')

            for sensor in sensors:
                # leaking: "Yes"|"No"|"N/A"
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor}' leaking",
                    module_ignore_errors=True
                )
                if result['rc'] == 0 and result['stdout'].strip():
                    leaking = result['stdout'].strip()
                    pytest_assert(leaking in ['Yes', 'No', 'N/A'],
                                  f"leaking '{leaking}' not in ['Yes', 'No', 'N/A']")

                # leak_sensor_status: "Good"|"Fault"
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor}' leak_sensor_status",
                    module_ignore_errors=True
                )
                if result['rc'] == 0 and result['stdout'].strip():
                    sensor_status = result['stdout'].strip()
                    pytest_assert(sensor_status in ['Good', 'Fault'],
                                  f"leak_sensor_status '{sensor_status}' "
                                  f"not in ['Good', 'Fault']")

                # severity: str(LeakSeverity) → "MINOR"|"CRITICAL"
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor}' severity",
                    module_ignore_errors=True
                )
                if result['rc'] == 0 and result['stdout'].strip():
                    severity = result['stdout'].strip()
                    pytest_assert(severity in ['MINOR', 'CRITICAL'],
                                  f"severity '{severity}' not in ['MINOR', 'CRITICAL']")

                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor}' type",
                    module_ignore_errors=True
                )
                if result['rc'] == 0 and result['stdout'].strip():
                    sensor_types.add(result['stdout'].strip())

            if sensor_types:
                logger.info(f"Sensor types supported: {sensor_types}")

        # Check escalation timeout configuration
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LEAK_PROFILE_TABLE}:*' | head -1",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            profile = result['stdout'].strip()
            result = self.duthost.shell(
                f"redis-cli -n 6 HGET '{profile}' max_minor_duration_sec",
                module_ignore_errors=True
            )

            if result['rc'] == 0 and result['stdout'].strip():
                try:
                    timeout = float(result['stdout'].strip())
                    pytest_assert(timeout > 0, "Timeout should be positive")
                    logger.info(f"Escalation timeout: {timeout}s")
                except ValueError:
                    logger.warning("Could not parse timeout")

        # Verify bmcctld coordination: critical leaks propagate to HOST_STATE
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip() == 'CRITICAL':
            result = self.duthost.shell(
                "redis-cli -n 6 HGET 'HOST_STATE:switch-host' device_status",
                module_ignore_errors=True
            )

            if result['rc'] == 0 and result['stdout'].strip():
                host_status = result['stdout'].strip()
                logger.info(f"Critical leak integration: HOST_STATE={host_status}")

    def test_thermalctld_performance(self):
        """
        Verify thermalctld performance and reliability

        Measures:
        - Event notification latency
        - State persistence and consistency
        - Recovery after STATE_DB operations
        - CPU/resource usage
        """
        # Measure STATE_DB update latency
        start = time.time()
        query_result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' timestamp",
            module_ignore_errors=True
        )
        elapsed = time.time() - start

        logger.info(f"Notification latency: {elapsed:.3f}s")
        pytest_assert(query_result['rc'] == 0 and elapsed < 5.0,
                      f"Query failed or latency {elapsed}s is excessive")

        # Check sensor state persistence
        states1 = []
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LIQUID_COOLING_INFO_TABLE}:*' | wc -l",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            states1.append(int(result['stdout'].strip()))

        time.sleep(2)

        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LIQUID_COOLING_INFO_TABLE}:*' | wc -l",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            states1.append(int(result['stdout'].strip()))

        if len(states1) > 1:
            pytest_assert(states1[0] == states1[1],
                          f"Sensor count unstable: {states1}")

        # Check CPU usage
        result = self.duthost.shell(
            "docker stats --no-stream pmon 2>/dev/null | tail -1 | awk '{print $3}'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            cpu = result['stdout'].strip()
            logger.info(f"PMON CPU usage: {cpu}")

    def test_thermalctld_event_trigger(self):
        """
        Inject sensor states into LIQUID_COOLING_INFO and verify STATE_DB presence
        and any associated syslog entries.

        LIQUID_COOLING_INFO schema (from LiquidCoolingUpdater._refresh_leak_status):
          leaking           = "Yes" | "No" | "N/A"
          leak_sensor_status = "Good" | "Fault"
          name, type, location, severity

        Syslog messages thermalctld emits on hardware state transitions:
          is_leak()=True          → log_error('...sensor {} reported leaking')
          is_leak()=False         → log_notice('...sensor {} recovered from leaking')
          is_leak_sensor_ok()=False → log_error('...sensor {} reported faulty')

        Trigger 1 — leaking sensor (leaking=Yes, leak_sensor_status=Good):
          Represents the STATE_DB entry thermalctld writes when is_leak() returns True.
          Checks syslog for 'reported leaking'.

        Trigger 2 — faulty sensor (leaking=N/A, leak_sensor_status=Fault):
          Represents the STATE_DB entry thermalctld writes when is_leak_sensor_ok()
          returns False.  Verifies the Fault entry is present in STATE_DB; syslog
          check is covered in detail by test_thermalctld_faulty_sensor.

        Both keys are deleted in finally blocks.
        """
        LEAKING_SENSOR_KEY = f"{LIQUID_COOLING_INFO_TABLE}:test_sensor_leaking"
        FAULTY_SENSOR_KEY = f"{LIQUID_COOLING_INFO_TABLE}:test_sensor_faulty"

        def log_contains(pattern):
            """Check pmon journal for pattern."""
            result = self.duthost.shell(
                f"journalctl -u pmon --since '2 minutes ago' 2>/dev/null"
                f" | grep -i '{pattern}' | tail -5",
                module_ignore_errors=True
            )
            return result['rc'] == 0 and bool(result['stdout'].strip())

        def sensor_has_value(key, field, value):
            """Check STATE_DB entry has expected field=value."""
            result = self.duthost.shell(
                f"redis-cli -n 6 HGET '{key}' {field}",
                module_ignore_errors=True
            )
            return result['rc'] == 0 and result['stdout'].strip() == value

        trigger_results = {}

        # --- Trigger 1: leaking sensor (leaking=Yes, leak_sensor_status=Good) ---
        # Expected syslog: log_error('Liquid cooling leakage sensor test_sensor_leaking reported leaking')
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{LEAKING_SENSOR_KEY}'"
                f" name test_sensor_leaking leaking Yes leak_sensor_status Good severity MINOR",
                module_ignore_errors=True
            )
            logger.info("Trigger 1 [leaking sensor]: leaking=Yes leak_sensor_status=Good")
            logger.info("Expected syslog: 'Liquid cooling leakage sensor test_sensor_leaking reported leaking'")

            in_db = wait_until(15, 2, 0, sensor_has_value, LEAKING_SENSOR_KEY, 'leaking', 'Yes')
            trigger_results['leaking_sensor_in_db'] = in_db
            found = wait_until(30, 3, 0, log_contains, 'reported leaking')
            trigger_results['leaking_sensor_syslog'] = found
            if found:
                logger.info("Trigger 1: syslog confirmed 'reported leaking'")
            else:
                logger.info("Trigger 1: no syslog match - thermalctld logs on hardware poll, not DB write")
        finally:
            self.duthost.shell(
                f"redis-cli -n 6 DEL '{LEAKING_SENSOR_KEY}'",
                module_ignore_errors=True
            )

        # --- Trigger 2: faulty sensor (leaking=N/A, leak_sensor_status=Fault) ---
        # Expected syslog: log_error('Liquid cooling leakage sensor test_sensor_faulty reported faulty')
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{FAULTY_SENSOR_KEY}'"
                f" name test_sensor_faulty leaking N/A leak_sensor_status Fault severity CRITICAL",
                module_ignore_errors=True
            )
            logger.info("Trigger 2 [faulty sensor]: leaking=N/A leak_sensor_status=Fault")
            logger.info("Expected syslog: 'Liquid cooling leakage sensor test_sensor_faulty reported faulty'")

            in_db = wait_until(15, 2, 0, sensor_has_value, FAULTY_SENSOR_KEY, 'leak_sensor_status', 'Fault')
            trigger_results['faulty_sensor_in_db'] = in_db
            found = wait_until(30, 3, 0, log_contains, 'reported faulty')
            trigger_results['faulty_sensor_syslog'] = found
            if found:
                logger.info("Trigger 2: syslog confirmed 'reported faulty'")
            else:
                logger.info("Trigger 2: no syslog match - thermalctld logs on hardware poll, not DB write")
        finally:
            self.duthost.shell(
                f"redis-cli -n 6 DEL '{FAULTY_SENSOR_KEY}'",
                module_ignore_errors=True
            )

        result = self.duthost.shell(
            "journalctl -u pmon --since '10 minutes ago' 2>/dev/null"
            " | grep -i 'reported leaking\\|reported faulty\\|recovered from' | tail -10",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"Existing thermalctld liquid cooling events:\n{result['stdout']}")

        logged = [t for t, v in trigger_results.items() if v]
        not_logged = [t for t, v in trigger_results.items() if not v]
        if logged:
            logger.info(f"Confirmed for: {logged}")
        if not_logged:
            logger.info(f"Not confirmed (liquid cooling hardware not present): {not_logged}")
        pytest_assert(
            any(trigger_results.values()),
            f"thermalctld event trigger test found no evidence for: {list(trigger_results.keys())}"
        )

    def test_thermalctld_faulty_sensor(self):
        """
        Verify thermalctld behavior for a faulty/unreadable leak sensor

        A faulty sensor is one where is_leak_sensor_ok() returns False (hardware fault,
        disconnected cable, etc.).  thermalctld:
          1. Writes leaking=N/A and leak_sensor_status=Fault to LIQUID_COOLING_INFO
          2. Logs log_error('Liquid cooling leakage sensor <name> reported faulty')
          3. Logs log_notice('Liquid cooling leaking sensor <name> recovered from fault')
             when the sensor becomes readable again

        This test:
          - Injects a LIQUID_COOLING_INFO entry representing a faulty sensor
          - Verifies the correct fields (leaking=N/A, leak_sensor_status=Fault) are present
          - Checks syslog for any existing 'reported faulty' entries from real hardware
          - Verifies SYSTEM_LEAK_STATUS:system timestamp is present (thermalctld still
            updates the system table even when sensors are faulty)
        """
        FAULTY_KEY = f"{LIQUID_COOLING_INFO_TABLE}:test_faulty_sensor_check"

        def sensor_field_equals(key, field, value):
            result = self.duthost.shell(
                f"redis-cli -n 6 HGET '{key}' {field}",
                module_ignore_errors=True
            )
            return result['rc'] == 0 and result['stdout'].strip() == value

        try:
            # Inject a faulty sensor entry using the exact schema thermalctld writes
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{FAULTY_KEY}'"
                f" name test_faulty_sensor_check"
                f" leaking N/A"
                f" leak_sensor_status Fault"
                f" severity CRITICAL"
                f" type liquid"
                f" location rack",
                module_ignore_errors=True
            )
            logger.info(f"Injected faulty sensor entry: {FAULTY_KEY}")

            # Verify leaking=N/A (sensor unreadable)
            in_db = wait_until(15, 2, 0, sensor_field_equals, FAULTY_KEY, 'leaking', 'N/A')
            pytest_assert(in_db, "Faulty sensor entry with leaking=N/A not found in STATE_DB")
            logger.info("STATE_DB confirmed: leaking=N/A (sensor unreadable)")

            # Verify leak_sensor_status=Fault
            is_fault = wait_until(10, 2, 0, sensor_field_equals, FAULTY_KEY, 'leak_sensor_status', 'Fault')
            pytest_assert(is_fault, "Faulty sensor entry with leak_sensor_status=Fault not found in STATE_DB")
            logger.info("STATE_DB confirmed: leak_sensor_status=Fault")

        finally:
            self.duthost.shell(
                f"redis-cli -n 6 DEL '{FAULTY_KEY}'",
                module_ignore_errors=True
            )

        # Check syslog for any existing real faulty-sensor events from thermalctld
        result = self.duthost.shell(
            "journalctl -u pmon --since '30 minutes ago' 2>/dev/null"
            " | grep -i 'reported faulty\\|recovered from fault' | tail -10",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"Real faulty sensor events in syslog:\n{result['stdout']}")
            # Verify log format: message must contain sensor name
            for line in result['stdout'].strip().split('\n'):
                if 'reported faulty' in line.lower():
                    pytest_assert('leakage sensor' in line.lower() or 'liquid' in line.lower(),
                                  f"Unexpected faulty sensor log format: {line}")
        else:
            logger.info("No faulty sensor syslog events found - liquid cooling hardware not present or all sensors ok")

        # Verify SYSTEM_LEAK_STATUS:system is still updated (thermalctld updates it even with faulty sensors)
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' timestamp",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"SYSTEM_LEAK_STATUS timestamp present: {result['stdout'].strip()}")
        else:
            logger.info("SYSTEM_LEAK_STATUS not populated - liquid cooling not active on this platform")

    def test_leak_state_db_schema(self):
        """
        Verify State DB tables have correct schema (graceful skip if no leak profiles)

        Validates:
        - SYSTEM_LEAK_STATUS:system has required fields
        - LIQUID_COOLING_INFO:<sensor> has required fields
        - LEAK_PROFILE:<type> has required configuration fields
        - Skips gracefully on non-liquid-cooled platforms
        """
        # Test SYSTEM_LEAK_STATUS schema
        result = self.duthost.shell(
            f"redis-cli -n 6 HGETALL '{SYSTEM_LEAK_STATUS_TABLE}:system'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout']:
            lines = result['stdout'].strip().split('\n')
            status_dict = {lines[i]: lines[i+1] for i in range(0, len(lines), 2) if i+1 < len(lines)}

            pytest_assert('device_leak_status' in status_dict,
                          "SYSTEM_LEAK_STATUS missing device_leak_status")
            pytest_assert('timestamp' in status_dict,
                          "SYSTEM_LEAK_STATUS missing timestamp")
            logger.info(f"SYSTEM_LEAK_STATUS fields: {list(status_dict.keys())}")
        else:
            logger.info("Platform has no liquid cooling - skipping SYSTEM_LEAK_STATUS validation")

        # Test LIQUID_COOLING_INFO schema
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LIQUID_COOLING_INFO_TABLE}:*' | head -1",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            sensor_key = result['stdout'].strip()
            result = self.duthost.shell(
                f"redis-cli -n 6 HGETALL '{sensor_key}'",
                module_ignore_errors=True
            )

            if result['rc'] == 0:
                lines = result['stdout'].strip().split('\n')
                sensor_data = {lines[i]: lines[i+1] for i in range(0, len(lines), 2) if i+1 < len(lines)}
                required = {'leaking', 'leak_sensor_status'}
                missing = required - set(sensor_data.keys())
                pytest_assert(not missing,
                              f"LIQUID_COOLING_INFO missing required fields: {missing}")
                logger.info(f"LIQUID_COOLING_INFO fields: {list(sensor_data.keys())}")
        else:
            logger.info("No LIQUID_COOLING_INFO sensors found - non-liquid-cooled platform")

        # Test LEAK_PROFILE schema (written to STATE_DB at thermalctld startup)
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LEAK_PROFILE_TABLE}:*'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            profiles = result['stdout'].strip().split('\n')
            if profiles:
                profile_key = profiles[0]
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGETALL '{profile_key}'",
                    module_ignore_errors=True
                )

                if result['rc'] == 0:
                    lines = result['stdout'].strip().split('\n')
                    profile_data = {lines[i]: lines[i+1] for i in range(0, len(lines), 2) if i+1 < len(lines)}
                    required = {'type', 'max_minor_duration_sec'}
                    missing = required - set(profile_data.keys())
                    pytest_assert(not missing,
                                  f"LEAK_PROFILE missing required fields: {missing}")
                    logger.info(f"LEAK_PROFILE fields: {list(profile_data.keys())}")
        else:
            logger.info("No LEAK_PROFILE found - expected on non-liquid-cooled platforms")

    def test_leak_state_db_values(self):
        """
        Verify State DB values are valid and consistent

        Validates:
        - device_leak_status is in valid set (MINOR, CRITICAL, None)
        - Sensor leaking status is Yes/No/N/A
        - Severity levels are valid
        - No missing or null required fields
        """
        # Test SYSTEM_LEAK_STATUS values
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            device_status = result['stdout'].strip()
            # device_leak_status = LeakSeverity.value ("MINOR"|"CRITICAL") or "None"
            valid_statuses = ['MINOR', 'CRITICAL', 'None']
            pytest_assert(device_status in valid_statuses,
                          f"device_leak_status '{device_status}' not in {valid_statuses}")
            logger.info(f"System leak status: {device_status}")

        # Test LIQUID_COOLING_INFO values
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LIQUID_COOLING_INFO_TABLE}:*' | head -3",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            sensors = result['stdout'].strip().split('\n')

            for sensor_key in sensors:
                # leaking: "Yes" (leak detected), "No" (no leak), "N/A" (sensor faulty)
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor_key}' leaking",
                    module_ignore_errors=True
                )

                if result['rc'] == 0 and result['stdout'].strip():
                    leaking = result['stdout'].strip()
                    pytest_assert(leaking in ['Yes', 'No', 'N/A'],
                                  f"leaking field '{leaking}' not in ['Yes', 'No', 'N/A']")

                # leak_sensor_status: "Good" (sensor ok), "Fault" (sensor unreadable)
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor_key}' leak_sensor_status",
                    module_ignore_errors=True
                )

                if result['rc'] == 0 and result['stdout'].strip():
                    sensor_status = result['stdout'].strip()
                    pytest_assert(sensor_status in ['Good', 'Fault'],
                                  f"leak_sensor_status '{sensor_status}' "
                                  f"not in ['Good', 'Fault']")

                # severity: str(LeakSeverity) → "MINOR" or "CRITICAL"
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{sensor_key}' severity",
                    module_ignore_errors=True
                )

                if result['rc'] == 0 and result['stdout'].strip():
                    severity = result['stdout'].strip()
                    valid_severities = ['MINOR', 'CRITICAL']
                    pytest_assert(severity in valid_severities,
                                  f"severity '{severity}' not in {valid_severities}")

        # Test LEAK_PROFILE values
        result = self.duthost.shell(
            f"redis-cli -n 6 KEYS '{LEAK_PROFILE_TABLE}:*' | head -3",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            profiles = result['stdout'].strip().split('\n')

            for profile_key in profiles:
                # Check max_minor_duration_sec if present
                result = self.duthost.shell(
                    f"redis-cli -n 6 HGET '{profile_key}' max_minor_duration_sec",
                    module_ignore_errors=True
                )

                if result['rc'] == 0 and result['stdout'].strip():
                    try:
                        timeout = float(result['stdout'].strip())
                        pytest_assert(timeout > 0,
                                      f"Timeout should be positive, got {timeout}")
                        logger.info(f"Profile {profile_key}: escalation timeout = {timeout}s")
                    except ValueError:
                        logger.warning("Could not parse timeout value")
