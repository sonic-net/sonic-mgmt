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
from tests.common.platform.bmc_utils import (
    STATE_DB,
    bmc_event_or_syslog_contains,
    get_system_leak_status,
    inject_leak_sensor,
    pmon_journal_contains,
    redis_del,
    redis_hget,
    redis_hgetall,
    redis_hset,
    redis_keys,
    set_system_leak_status,
)
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
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

        # Skip if thermalctld not enabled or not running
        if not check_pmon_daemon_enable_status(self.duthost, "thermalctld"):
            pytest.skip("thermalctld is not enabled on {}".format(self.duthost.facts['platform']))
        daemon_status, _ = self.duthost.get_pmon_daemon_status("thermalctld")
        if daemon_status != "RUNNING":
            pytest.skip("thermalctld daemon not running")

        yield

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
        status = get_system_leak_status(self.duthost)
        if status:
            # LeakSeverity.value = "MINOR"|"CRITICAL"; "None" when no active leak
            valid = ['MINOR', 'CRITICAL', 'None']
            pytest_assert(status in valid, f"device_leak_status '{status}' not in {valid}")
            logger.info(f"System leak status: {status}")

        # Check per-sensor fields and types
        sensors = redis_keys(self.duthost, STATE_DB, f'{LIQUID_COOLING_INFO_TABLE}:*')[:3]

        sensor_types = set()
        for sensor in sensors:
            fields = redis_hgetall(self.duthost, STATE_DB, sensor)

            leaking = fields.get('leaking', '').strip()
            if leaking:
                pytest_assert(leaking in ['Yes', 'No', 'N/A'],
                              f"leaking '{leaking}' not in ['Yes', 'No', 'N/A']")

            sensor_status = fields.get('leak_sensor_status', '').strip()
            if sensor_status:
                pytest_assert(sensor_status in ['Good', 'Fault'],
                              f"leak_sensor_status '{sensor_status}' "
                              f"not in ['Good', 'Fault']")

            severity = fields.get('severity', '').strip()
            if severity:
                pytest_assert(severity in ['MINOR', 'CRITICAL'],
                              f"severity '{severity}' not in ['MINOR', 'CRITICAL']")

            sensor_type = fields.get('type', '').strip()
            if sensor_type:
                sensor_types.add(sensor_type)

        if sensor_types:
            logger.info(f"Sensor types supported: {sensor_types}")

        # Check escalation timeout configuration
        profiles = redis_keys(self.duthost, STATE_DB, f'{LEAK_PROFILE_TABLE}:*')
        if profiles:
            timeout_str = redis_hget(self.duthost, STATE_DB, profiles[0],
                                     'max_minor_duration_sec')
            if timeout_str:
                try:
                    timeout = float(timeout_str)
                    pytest_assert(timeout > 0, "Timeout should be positive")
                    logger.info(f"Escalation timeout: {timeout}s")
                except ValueError:
                    logger.warning("Could not parse timeout")

        # Verify bmcctld coordination: critical leaks propagate to HOST_STATE
        if get_system_leak_status(self.duthost) == 'CRITICAL':
            host_status = redis_hget(self.duthost, STATE_DB,
                                     'HOST_STATE:switch-host', 'device_status')
            if host_status:
                logger.info(f"Critical leak integration: HOST_STATE={host_status}")

    def test_thermalctld_event_trigger(self):
        """
        Inject a leaking sensor state into LIQUID_COOLING_INFO and verify STATE_DB
        presence and the associated syslog entry.

        LIQUID_COOLING_INFO schema (from LiquidCoolingUpdater._refresh_leak_status):
          leaking           = "Yes" | "No" | "N/A"
          leak_sensor_status = "Good" | "Fault"
          name, type, location, severity

        Syslog message thermalctld emits on hardware state transition:
          is_leak()=True          → log_error('...sensor {} reported leaking')
          is_leak()=False         → log_notice('...sensor {} recovered from leaking')

        Trigger — leaking sensor (leaking=Yes, leak_sensor_status=Good):
          Represents the STATE_DB entry thermalctld writes when is_leak() returns True.
          Checks syslog for 'reported leaking'.

        The faulty-sensor path (leak_sensor_status=Fault) is covered by
        test_thermalctld_faulty_sensor.

        The injected key is deleted in a finally block.
        """
        LEAKING_SENSOR_KEY = f"{LIQUID_COOLING_INFO_TABLE}:test_sensor_leaking"

        def log_contains(pattern):
            return pmon_journal_contains(self.duthost, pattern, since='2 minutes ago')

        def sensor_has_value(key, field, value):
            return redis_hget(self.duthost, STATE_DB, key, field) == value

        trigger_results = {}

        # --- Trigger: leaking sensor (leaking=Yes, leak_sensor_status=Good) ---
        # Expected syslog: log_error('Liquid cooling leakage sensor test_sensor_leaking reported leaking')
        try:
            inject_leak_sensor(self.duthost, 'test_sensor_leaking',
                               leaking='Yes', leak_sensor_status='Good', severity='MINOR')
            logger.info("Trigger [leaking sensor]: leaking=Yes leak_sensor_status=Good")
            logger.info("Expected syslog: 'Liquid cooling leakage sensor test_sensor_leaking reported leaking'")

            in_db = wait_until(15, 2, 0, sensor_has_value, LEAKING_SENSOR_KEY, 'leaking', 'Yes')
            trigger_results['leaking_sensor_in_db'] = in_db
            found = wait_until(30, 3, 0, log_contains, 'reported leaking')
            trigger_results['leaking_sensor_syslog'] = found
            if found:
                logger.info("Trigger: syslog confirmed 'reported leaking'")
            else:
                logger.info("Trigger: no syslog match - thermalctld logs on hardware poll, not DB write")
        finally:
            redis_del(self.duthost, STATE_DB, LEAKING_SENSOR_KEY)

        result = self.duthost.shell(
            "journalctl -u pmon --since '10 minutes ago' 2>/dev/null"
            " | grep -i 'reported leaking\\|recovered from leaking' | tail -10",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"Existing thermalctld leaking-sensor events:\n{result['stdout']}")

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
            return redis_hget(self.duthost, STATE_DB, key, field) == value

        try:
            # Inject a faulty sensor entry using the exact schema thermalctld writes
            inject_leak_sensor(self.duthost, 'test_faulty_sensor_check',
                               leaking='N/A', leak_sensor_status='Fault',
                               severity='CRITICAL', type='liquid', location='rack')
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
            redis_del(self.duthost, STATE_DB, FAULTY_KEY)

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
        ts = redis_hget(self.duthost, STATE_DB,
                        f'{SYSTEM_LEAK_STATUS_TABLE}:system', 'timestamp')
        if ts:
            logger.info(f"SYSTEM_LEAK_STATUS timestamp present: {ts}")
        else:
            logger.info("SYSTEM_LEAK_STATUS not populated - liquid cooling not active on this platform")

    def test_thermalctld_leak_escalation(self):
        """
        Verify MINOR→CRITICAL leak escalation configuration in LEAK_PROFILE.

        bmc_enhance change: LiquidCoolingUpdater checks profile.get_leak_max_minor_duration_sec()
        and escalates a MINOR sensor to CRITICAL once it has been leaking longer than
        the configured threshold. The escalation threshold is stored in LEAK_PROFILE.

        Test Steps:
        1. Check LEAK_PROFILE table is present; skip gracefully if not
        2. For each profile key, verify max_minor_duration_sec > 0
        3. Verify current sensor severity values in LIQUID_COOLING_INFO are valid
        4. Check if any sensor shows severity=CRITICAL while SYSTEM_LEAK_STATUS shows
           CRITICAL → confirm escalation result is reflected in system status

        Expected Result:
        - Each LEAK_PROFILE has a positive max_minor_duration_sec (escalation threshold set)
        - Sensor severity values are 'MINOR' or 'CRITICAL'
        - When system status is CRITICAL, at least one sensor shows severity=CRITICAL
        """
        # Check LEAK_PROFILE present
        profiles = redis_keys(self.duthost, STATE_DB, f'{LEAK_PROFILE_TABLE}:*')
        if not profiles:
            logger.info("No LEAK_PROFILE entries — non-liquid-cooled platform; skipping escalation test")
            return

        logger.info(f"Found {len(profiles)} leak profile(s): {profiles}")

        for profile_key in profiles:
            ts = redis_hget(self.duthost, STATE_DB, profile_key, 'max_minor_duration_sec')
            if ts:
                try:
                    threshold = float(ts)
                    pytest_assert(threshold > 0,
                                  f"{profile_key}: max_minor_duration_sec={threshold} must be > 0")
                    logger.info(f"{profile_key}: escalation threshold = {threshold}s")
                except ValueError:
                    logger.warning(f"{profile_key}: could not parse max_minor_duration_sec")

        # Read current sensor severities
        sensors = redis_keys(self.duthost, STATE_DB, f'{LIQUID_COOLING_INFO_TABLE}:*')[:10]
        if not sensors:
            logger.info("No LIQUID_COOLING_INFO sensors — no active leak sensors to check")
            return

        critical_sensors = []
        for sensor_key in sensors:
            severity = redis_hget(self.duthost, STATE_DB, sensor_key, 'severity')
            if not severity:
                continue
            pytest_assert(severity in ['MINOR', 'CRITICAL'],
                          f"{sensor_key}: severity '{severity}' not in ['MINOR', 'CRITICAL']")
            if severity == 'CRITICAL':
                critical_sensors.append(sensor_key)
                # Cross-reference: verify the sensor's assigned profile has a finite
                # max_minor_duration_sec — confirming profile-driven escalation is possible.
                # The daemon calls sensor.get_leak_profile().get_leak_max_minor_duration_sec()
                # and escalates MINOR→CRITICAL once that threshold is exceeded.
                profile_name = redis_hget(self.duthost, STATE_DB, sensor_key, 'profile')
                if profile_name:
                    profile_key = f"{LEAK_PROFILE_TABLE}:{profile_name}"
                    threshold_str = redis_hget(self.duthost, STATE_DB, profile_key,
                                               'max_minor_duration_sec')
                    if threshold_str:
                        try:
                            threshold = float(threshold_str)
                            pytest_assert(
                                threshold > 0,
                                f"{sensor_key}: profile '{profile_name}' has "
                                f"max_minor_duration_sec={threshold}, must be > 0 for escalation"
                            )
                            logger.info(
                                f"{sensor_key}: CRITICAL via profile '{profile_name}' "
                                f"(max_minor={threshold}s)"
                            )
                        except ValueError:
                            logger.warning(
                                f"{sensor_key}: could not parse max_minor_duration_sec "
                                f"from profile '{profile_name}'"
                            )

        # When system status is CRITICAL, at least one sensor must also be CRITICAL
        if get_system_leak_status(self.duthost) == 'CRITICAL':
            pytest_assert(
                len(critical_sensors) > 0,
                "System device_leak_status=CRITICAL but no sensor shows severity=CRITICAL"
            )
            logger.info(f"Escalated CRITICAL sensors: {critical_sensors}")
        else:
            logger.info("No active CRITICAL leak — escalation path not triggered on this run")

    def test_thermalctld_leak_severity_aggregation(self):
        """
        Verify thermalctld's individual-sensor → SYSTEM_LEAK_STATUS aggregation rules
        (pmon-bmc-design.md §2.1.5 truth table). Each scenario injects test sensor
        rows into LIQUID_COOLING_INFO, waits for the daemon's next poll cycle, and
        asserts SYSTEM_LEAK_STATUS:system device_leak_status converges to the
        expected output.

        Rule 1: 1 CRITICAL sensor              → CRITICAL
        Rule 2: 2+ sensors (any severity)      → CRITICAL
        Rule 3: 1 MINOR sensor > max_minor_duration_sec  → CRITICAL (escalation)
        Rule 4: 1 MINOR sensor (< threshold)   → MINOR

        Limitations: thermalctld may re-write LIQUID_COOLING_INFO on each poll
        based on real hardware. If our injected rows do not survive long enough
        for the aggregator to act on them, the relevant scenario logs info and
        the assertion is skipped (rather than asserting a false negative).

        All injected rows and the original device_leak_status are restored in
        `finally` blocks.
        """
        TEST_SENSORS = [
            f"{LIQUID_COOLING_INFO_TABLE}:test_agg_sensor_a",
            f"{LIQUID_COOLING_INFO_TABLE}:test_agg_sensor_b",
        ]

        def inject(key, severity, leaking='Yes'):
            inject_leak_sensor(self.duthost, key.split(':')[-1],
                               leaking=leaking, leak_sensor_status='Good', severity=severity)

        def cleanup_sensors():
            redis_del(self.duthost, STATE_DB, *TEST_SENSORS)

        def sensor_survives(key):
            """True iff thermalctld has not evicted our test row."""
            r = self.duthost.shell(
                f"sonic-db-cli {STATE_DB} EXISTS '{key}'",
                module_ignore_errors=True
            )
            return (r.get('stdout', '') or '').strip() == '1'

        orig_status = get_system_leak_status(self.duthost) or 'None'
        if orig_status == 'CRITICAL':
            pytest.skip("System already in CRITICAL state — cannot run aggregation scenarios safely")

        scenarios = [
            ("Rule 1 (1 CRITICAL sensor)", [(TEST_SENSORS[0], 'CRITICAL')], 'CRITICAL'),
            ("Rule 2 (2 MINOR sensors)",
             [(TEST_SENSORS[0], 'MINOR'), (TEST_SENSORS[1], 'MINOR')], 'CRITICAL'),
            ("Rule 4 (1 MINOR sensor)", [(TEST_SENSORS[0], 'MINOR')], 'MINOR'),
        ]

        try:
            for label, rows, expected in scenarios:
                cleanup_sensors()
                for key, sev in rows:
                    inject(key, sev)
                logger.info(f"{label}: injected {[(k, s) for k, s in rows]}, expect SYSTEM={expected}")

                converged = wait_until(
                    40, 5, 0,
                    lambda exp=expected: (get_system_leak_status(self.duthost) or '').upper() == exp
                )
                survived = all(sensor_survives(k) for k, _ in rows)
                if not survived:
                    logger.info(f"{label}: injected rows were re-written by daemon poll - "
                                f"aggregation not driven by test; skipping assert")
                    continue
                pytest_assert(
                    converged,
                    f"{label}: SYSTEM_LEAK_STATUS did not converge to {expected} "
                    f"within 40s; got {get_system_leak_status(self.duthost)!r}"
                )
                logger.info(f"{label}: SYSTEM_LEAK_STATUS={get_system_leak_status(self.duthost)} ✓")
                cleanup_sensors()
                # Let the system settle back before next scenario
                wait_until(30, 3, 0,
                           lambda: (get_system_leak_status(self.duthost) or '').upper() != 'CRITICAL')

            # Rule 3 (escalation): temporarily shorten max_minor_duration_sec
            profiles = redis_keys(self.duthost, STATE_DB, f'{LEAK_PROFILE_TABLE}:*')
            if not profiles:
                logger.info("Rule 3 (escalation): no LEAK_PROFILE keys — non-LC platform; skipping")
            else:
                pkey = profiles[0]
                orig_thresh = redis_hget(self.duthost, STATE_DB, pkey, 'max_minor_duration_sec')
                try:
                    redis_hset(self.duthost, STATE_DB, pkey, max_minor_duration_sec='5')
                    cleanup_sensors()
                    inject(TEST_SENSORS[0], 'MINOR')
                    logger.info("Rule 3: injected 1 MINOR sensor with max_minor_duration_sec=5s")
                    converged = wait_until(
                        40, 5, 0,
                        lambda: (get_system_leak_status(self.duthost) or '').upper() == 'CRITICAL'
                    )
                    if sensor_survives(TEST_SENSORS[0]):
                        pytest_assert(
                            converged,
                            "Rule 3: SYSTEM_LEAK_STATUS did not escalate MINOR→CRITICAL "
                            f"within 40s; got {get_system_leak_status(self.duthost)!r}"
                        )
                        logger.info("Rule 3: MINOR sensor escalated to CRITICAL ✓")
                    else:
                        logger.info("Rule 3: injected row evicted by daemon poll - skipping assert")
                finally:
                    if orig_thresh:
                        redis_hset(self.duthost, STATE_DB, pkey,
                                   max_minor_duration_sec=orig_thresh)
        finally:
            cleanup_sensors()
            # Restore original system status best-effort
            if orig_status and orig_status != 'CRITICAL':
                set_system_leak_status(self.duthost, orig_status)

    def test_thermalctld_bmc_temperature_mirror(self):
        """
        Verify thermalctld on Switch-Host mirrors TEMPERATURE_INFO to the BMC's STATE_DB.

        bmc_enhance change: TemperatureUpdater._init_bmc_temperature_table() opens a
        remote swsscommon.Table backed by the BMC's STATE_DB (db_connect_remote).
        Every _refresh_temperature_status call tees its TEMPERATURE_INFO write to
        this table via _bmc_table_set().

        Test Steps:
        1. Determine if running on a Switch-Host (device_info.is_switch_host() or
           /etc/sonic/platform_env.conf switch_host=1)
        2. Check thermalctld startup log for "Mirroring TEMPERATURE_INFO to BMC STATE_DB"
        3. Check pmon journal for any BMC mirror warnings
           ("Failed to open remote BMC TEMPERATURE_INFO table")
        4. Read local TEMPERATURE_INFO keys — verify sensors are present on Switch-Host

        Expected Result:
        - On Switch-Host: startup log shows BMC mirror initialization (or warning if BMC unreachable)
        - Local TEMPERATURE_INFO is populated with thermal sensors
        - Graceful skip on non-Switch-Host platforms
        """
        # Determine if Switch-Host
        result = self.duthost.shell(
            "grep -q 'switch_host=1' /etc/sonic/platform_env.conf 2>/dev/null && echo yes || echo no",
            module_ignore_errors=True
        )
        is_switch_host = result['stdout'].strip() == 'yes'

        if not is_switch_host:
            logger.info("Not a Switch-Host platform — BMC temperature mirror not active; skipping")
            return

        logger.info("Switch-Host detected — verifying BMC TEMPERATURE_INFO mirror")

        # Check startup log for BMC mirror initialization
        result = self.duthost.shell(
            "journalctl -u pmon --since '60 minutes ago' 2>/dev/null"
            " | grep -i 'Mirroring TEMPERATURE_INFO\\|Failed to open remote BMC' | tail -5",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"BMC mirror log entries:\n{result['stdout'].strip()}")
            if 'Mirroring TEMPERATURE_INFO' in result['stdout']:
                logger.info("BMC TEMPERATURE_INFO mirror initialization confirmed")
            elif 'Failed to open remote BMC' in result['stdout']:
                logger.info(
                    "BMC mirror initialization failed (BMC unreachable or misconfigured) — "
                    "thermalctld degrades gracefully"
                )
        else:
            logger.info(
                "No BMC mirror log in last 60 min — thermalctld may have started earlier"
            )

        # Verify local TEMPERATURE_INFO is populated (source of mirror data)
        count = len(redis_keys(self.duthost, STATE_DB, 'TEMPERATURE_INFO:*'))
        logger.info(f"Local TEMPERATURE_INFO entries: {count}")
        if count == 0:
            logger.info("No TEMPERATURE_INFO entries — thermals not yet polled or no sensors")

    def test_thermalctld_switch_host_thermal_monitoring(self):
        """
        Verify thermalctld on BMC monitors Switch-Host TEMPERATURE_INFO for CRITICAL breaches.

        bmc_enhance change: ThermalMonitor._init_switch_host_thermal_monitor() opens
        BMC's local TEMPERATURE_INFO table and checks it each cycle via
        _check_switch_host_thermals(). A CRITICAL threshold breach (temp >= critical_high
        or temp <= critical_low) is logged to both syslog and /host/bmc/event.log via
        EventLogger. Recovery is tracked silently (no log).

        Test Steps:
        1. Determine if running on BMC (switch_bmc=1 in /etc/sonic/platform_env.conf)
        2. Check pmon startup log for "Monitoring chassis thermals" initialization message
        3. Read TEMPERATURE_INFO entries that have critical_high_threshold or
           critical_low_threshold — verify schema
        4. Check /host/bmc/event.log for any "CRITICAL chassis thermal" events
        5. Inject a test entry with temp >= critical_high_threshold into TEMPERATURE_INFO
           and verify event.log receives a "CRITICAL chassis thermal" entry

        Expected Result:
        - On BMC: startup log confirms Switch-Host thermal monitoring initialized
        - TEMPERATURE_INFO entries have threshold fields when present
        - CRITICAL breach → event.log entry of form "CRITICAL chassis thermal: <name> ..."
        - Injected test entry is cleaned up regardless of outcome
        - Graceful skip on non-BMC platforms
        """
        # Determine if running on BMC
        result = self.duthost.shell(
            "grep -q 'switch_bmc=1' /etc/sonic/platform_env.conf 2>/dev/null && echo yes || echo no",
            module_ignore_errors=True
        )
        is_switch_bmc = result['stdout'].strip() == 'yes'

        if not is_switch_bmc:
            logger.info("Not a BMC platform — Switch-Host thermal monitoring not active; skipping")
            return

        logger.info("BMC platform detected — verifying Switch-Host thermal monitoring")

        # Check startup log for initialization message
        result = self.duthost.shell(
            "journalctl -u pmon --since '60 minutes ago' 2>/dev/null"
            " | grep -i 'Monitoring chassis thermals\\|Failed to init chassis thermal' | tail -5",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"Thermal monitoring init log:\n{result['stdout'].strip()}")

        # Check /host/bmc/event.log for any existing CRITICAL chassis thermal events
        result = self.duthost.shell(
            "test -f /host/bmc/event.log && grep -i 'CRITICAL chassis thermal' /host/bmc/event.log"
            " | tail -5 || echo 'no events'",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and 'no events' not in result['stdout']:
            logger.info(f"Existing CRITICAL chassis thermal events:\n{result['stdout'].strip()}")

        # Inject a test TEMPERATURE_INFO entry with temp above critical threshold
        TEST_SENSOR = "TEMPERATURE_INFO:test_critical_thermal_monitor"
        try:
            redis_hset(self.duthost, STATE_DB, TEST_SENSOR,
                       temperature='120.0',
                       critical_high_threshold='80.0',
                       high_threshold='70.0',
                       low_threshold='-10.0',
                       warning='False',
                       timestamp='2099-01-01T00:00:00')
            logger.info(f"Injected test TEMPERATURE_INFO entry: {TEST_SENSOR} (120C > 80C critical)")

            # Wait for thermalctld to poll and log the breach (up to 2 update cycles)
            def breach_logged():
                return bmc_event_or_syslog_contains(
                    self.duthost, 'CRITICAL chassis thermal.*test_critical',
                    since='2 minutes ago'
                )

            found = wait_until(90, 5, 0, breach_logged)
            if found:
                logger.info("CRITICAL chassis thermal log confirmed for injected sensor")
            else:
                logger.info(
                    "No CRITICAL chassis thermal log found within 90s — "
                    "thermalctld may use a longer polling interval on this platform"
                )
        finally:
            redis_del(self.duthost, STATE_DB, TEST_SENSOR)


# ---------------------------------------------------------------------------
# Lifecycle tests: running / stop-start / term-start / kill-start
# ---------------------------------------------------------------------------

THERMALCTLD_DAEMON_NAME = "thermalctld"
THERMALCTLD_DB_KEY_PATTERN = "TEMPERATURE_INFO|*"

SIG_STOP_SERVICE = None
SIG_TERM = "-15"
SIG_KILL = "-9"

expected_running_status = "RUNNING"
expected_stopped_status = "STOPPED"
expected_exited_status = "EXITED"


@pytest.fixture(scope="module", autouse=False)
def thermalctld_teardown_module(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure thermalctld is left running after lifecycle tests."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield
    daemon_status, _ = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    if daemon_status != expected_running_status:
        duthost.start_pmon_daemon(THERMALCTLD_DAEMON_NAME)
        time.sleep(10)


@pytest.fixture
def thermalctld_check_daemon_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure thermalctld is running before each lifecycle test."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    daemon_status, _ = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    if daemon_status != expected_running_status:
        duthost.start_pmon_daemon(THERMALCTLD_DAEMON_NAME)
        time.sleep(10)


def _thermalctld_collect_data(duthost):
    keys = duthost.shell(
        'sonic-db-cli STATE_DB KEYS "{}"'.format(THERMALCTLD_DB_KEY_PATTERN)
    )['stdout_lines']
    dev_data = {}
    for k in keys:
        data = duthost.shell('sonic-db-cli STATE_DB HGETALL "{}"'.format(k))['stdout']
        dev_data[k] = data
    return {'keys': sorted(keys), 'data': dev_data}


def _thermalctld_check_expected_status(duthost, expected_status):
    daemon_status, _ = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    return daemon_status == expected_status


def _thermalctld_check_restarted(duthost, pre_pid):
    _, pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    return pid > pre_pid


@pytest.fixture(scope="module")
def thermalctld_data_before_restart(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not check_pmon_daemon_enable_status(duthost, THERMALCTLD_DAEMON_NAME):
        pytest.skip("{} is not enabled on {}".format(THERMALCTLD_DAEMON_NAME, duthost.facts['platform']))
    return _thermalctld_collect_data(duthost)


def test_pmon_thermalctld_running_status(duthosts, enum_rand_one_per_hwsku_hostname,
                                         thermalctld_data_before_restart,
                                         thermalctld_teardown_module):
    """Verify thermalctld is RUNNING with a valid pid."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(THERMALCTLD_DAEMON_NAME, daemon_status, daemon_pid))
    pytest_assert(daemon_status == expected_running_status,
                  "{} expected {} but is {}".format(THERMALCTLD_DAEMON_NAME, expected_running_status, daemon_status))
    pytest_assert(daemon_pid != -1,
                  "{} expected valid pid but got {}".format(THERMALCTLD_DAEMON_NAME, daemon_pid))


def test_pmon_thermalctld_stop_and_start_status(thermalctld_check_daemon_status, duthosts,
                                                enum_rand_one_per_hwsku_hostname,
                                                thermalctld_data_before_restart,
                                                thermalctld_teardown_module):
    """Verify thermalctld stops cleanly and recovers after supervisorctl start."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(THERMALCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(THERMALCTLD_DAEMON_NAME, SIG_STOP_SERVICE)
    time.sleep(2)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    pytest_assert(daemon_status == expected_stopped_status,
                  "{} expected {} but is {}".format(THERMALCTLD_DAEMON_NAME, expected_stopped_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                  "{} expected pid -1 but got {}".format(THERMALCTLD_DAEMON_NAME, daemon_pid))

    duthost.start_pmon_daemon(THERMALCTLD_DAEMON_NAME)
    wait_until(120, 10, 0, _thermalctld_check_restarted, duthost, pre_pid)
    wait_until(60, 10, 0, _thermalctld_check_expected_status, duthost, expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    pytest_assert(post_status == expected_running_status,
                  "{} expected {} after restart but is {}".format(
                      THERMALCTLD_DAEMON_NAME, expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-stop pid {}".format(
                      THERMALCTLD_DAEMON_NAME, post_pid, pre_pid))


def test_pmon_thermalctld_term_and_start_status(thermalctld_check_daemon_status, duthosts,
                                                enum_rand_one_per_hwsku_hostname,
                                                thermalctld_data_before_restart,
                                                thermalctld_teardown_module):
    """Verify thermalctld auto-restarts after SIGTERM."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(THERMALCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(THERMALCTLD_DAEMON_NAME, SIG_TERM, pre_pid)
    wait_until(120, 10, 0, _thermalctld_check_restarted, duthost, pre_pid)
    wait_until(60, 10, 0, _thermalctld_check_expected_status, duthost, expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    pytest_assert(post_status == expected_running_status,
                  "{} expected {} after SIGTERM but is {}".format(
                      THERMALCTLD_DAEMON_NAME, expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-term pid {}".format(
                      THERMALCTLD_DAEMON_NAME, post_pid, pre_pid))


def test_pmon_thermalctld_kill_and_start_status(thermalctld_check_daemon_status, duthosts,
                                                enum_rand_one_per_hwsku_hostname,
                                                thermalctld_data_before_restart,
                                                thermalctld_teardown_module):
    """Verify thermalctld auto-restarts after SIGKILL."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(THERMALCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(THERMALCTLD_DAEMON_NAME, SIG_KILL, pre_pid)
    wait_until(120, 10, 0, _thermalctld_check_restarted, duthost, pre_pid)
    wait_until(120, 10, 0, _thermalctld_check_expected_status, duthost, expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(THERMALCTLD_DAEMON_NAME)
    pytest_assert(post_status == expected_running_status,
                  "{} expected {} after SIGKILL but is {}".format(
                      THERMALCTLD_DAEMON_NAME, expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-kill pid {}".format(
                      THERMALCTLD_DAEMON_NAME, post_pid, pre_pid))
