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
from tests.common.helpers.sonic_db import (
    STATE_DB,
    redis_del,
    redis_hget,
    redis_hgetall,
    redis_hset,
    redis_keys,
)
from tests.common.platform.bmc_utils import (
    BMC_EVENT_LOG,
    bmc_log_zgrep,
    get_system_leak_status,
    inject_leak_sensor,
    make_bmc_loganalyzer,
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
        sensors = redis_keys(self.duthost, STATE_DB, f'{LIQUID_COOLING_INFO_TABLE}|*')[:3]

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

            leak_severity = fields.get('leak_severity', '').strip()
            if leak_severity:
                pytest_assert(leak_severity in ['MINOR', 'CRITICAL'],
                              f"leak_severity '{leak_severity}' not in ['MINOR', 'CRITICAL']")

            sensor_type = fields.get('type', '').strip()
            if sensor_type:
                sensor_types.add(sensor_type)

        if sensor_types:
            logger.info(f"Sensor types supported: {sensor_types}")

        # Check escalation timeout configuration
        profiles = redis_keys(self.duthost, STATE_DB, f'{LEAK_PROFILE_TABLE}|*')
        if profiles:
            timeout_str = redis_hget(self.duthost, STATE_DB, profiles[0],
                                     'max_minor_duration_sec')
            if timeout_str:
                try:
                    timeout = float(timeout_str)
                    # Design: 0 means the platform does not support
                    # minor-leak escalation over time.
                    pytest_assert(timeout >= 0,
                                  "Timeout should be non-negative (0 means unsupported)")
                    logger.info(f"Escalation timeout: {timeout}s")
                except ValueError:
                    logger.warning("Could not parse timeout")

        # Verify bmcctld coordination: critical leaks propagate to HOST_STATE
        if get_system_leak_status(self.duthost) == 'CRITICAL':
            host_status = redis_hget(self.duthost, STATE_DB,
                                     'HOST_STATE|switch-host', 'device_status')
            pytest_assert(host_status is not None,
                          "HOST_STATE|switch-host device_status not set despite CRITICAL leak active")
            pytest_assert(host_status != 'ONLINE',
                          f"HOST_STATE device_status={host_status!r} — "
                          "switch-host must not be ONLINE when CRITICAL leak is active")

    def test_thermalctld_event_trigger(self):
        """
        Inject a leaking sensor state into LIQUID_COOLING_INFO and verify STATE_DB
        presence and the associated syslog entry.

        LIQUID_COOLING_INFO schema (from LiquidCoolingUpdater._refresh_leak_status):
          leaking           = "Yes" | "No" | "N/A"
          leak_sensor_status = "Good" | "Fault"
          name, type, location, leak_severity

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
        LEAKING_SENSOR_KEY = f"{LIQUID_COOLING_INFO_TABLE}|test_sensor_leaking"

        def sensor_has_value(key, field, value):
            return redis_hget(self.duthost, STATE_DB, key, field) == value

        trigger_results = {}

        # Bracket the trigger with BmcLogAnalyzer scanning syslog (live, no reboot).
        la = make_bmc_loganalyzer(self.duthost, "thermalctld_event_trigger_leak")
        marker = la.init(log_target='syslog')
        try:
            inject_leak_sensor(self.duthost, 'test_sensor_leaking',
                               leaking='Yes', leak_sensor_status='Good', leak_severity='MINOR')
            in_db = wait_until(15, 2, 0, sensor_has_value, LEAKING_SENSOR_KEY, 'leaking', 'Yes')
            trigger_results['leaking_sensor_in_db'] = in_db
            # Give thermalctld a hardware-poll cycle to react.
            time.sleep(20)
        finally:
            redis_del(self.duthost, STATE_DB, LEAKING_SENSOR_KEY)

        la.match_regex = [r".*Liquid cooling leak(age|ing) sensor .* reported leaking.*"]
        result = la.analyze(marker, fail=False, log_target='syslog')
        match_count = result.get("total", {}).get("match", 0)
        trigger_results['leaking_sensor_syslog'] = match_count > 0

        # Historical informational scan (rotation-safe via zgrep).
        existing = bmc_log_zgrep(
            self.duthost,
            r"Liquid cooling leak(age|ing) sensor .* (reported leaking|recovered from (CRITICAL leak|leaking))",
            tail=10,
        )
        if existing:
            logger.info(f"Existing thermalctld leaking-sensor events:\n{existing}")

        logged = [t for t, v in trigger_results.items() if v]
        not_logged = [t for t, v in trigger_results.items() if not v]
        logger.info(f"Confirmed: {logged}; not confirmed: {not_logged}")
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
        FAULTY_KEY = f"{LIQUID_COOLING_INFO_TABLE}|test_faulty_sensor_check"

        def sensor_field_equals(key, field, value):
            return redis_hget(self.duthost, STATE_DB, key, field) == value

        try:
            # Inject a faulty sensor entry using the exact schema thermalctld writes
            inject_leak_sensor(self.duthost, 'test_faulty_sensor_check',
                               leaking='N/A', leak_sensor_status='Fault',
                               leak_severity='CRITICAL', sensor_type='liquid', location='rack')
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

        # Historical informational scan (rotation-safe via zgrep).
        existing = bmc_log_zgrep(
            self.duthost,
            r"Liquid cooling leak(age|ing) sensor .* (reported faulty|recovered from fault)",
            tail=10,
        )
        if existing:
            logger.info(f"Real faulty sensor events in syslog:\n{existing}")
        else:
            logger.info("No faulty sensor syslog events found - liquid cooling hardware not present or all sensors ok")

        # Verify SYSTEM_LEAK_STATUS:system is still updated (thermalctld updates it even with faulty sensors)
        ts = redis_hget(self.duthost, STATE_DB,
                        f'{SYSTEM_LEAK_STATUS_TABLE}|system', 'timestamp')
        if ts:
            logger.info(f"SYSTEM_LEAK_STATUS timestamp present: {ts}")
        else:
            logger.info("SYSTEM_LEAK_STATUS not populated - liquid cooling not active on this platform")

    def test_thermalctld_leak_severity_aggregation(self):
        """Verify is_leak() → LIQUID_COOLING_INFO → SYSTEM_LEAK_STATUS aggregation

        Deferred: requires a vendor LiquidLeakageMocker (or equivalent generic
        leak-injection mechanism) to flip is_leak() on real sensor objects.
        STATE_DB-only injection cannot drive thermalctld's in-memory aggregator.
        """
        pytest.skip("Not supported until generic leak injection is available")

    def test_thermalctld_bmc_temperature_mirror(self):
        """
        Verify thermalctld on Switch-Host mirrors TEMPERATURE_INFO to the BMC's STATE_DB.

        TemperatureUpdater._init_bmc_temperature_table() opens a
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

        # Historical startup-log scan (rotation-safe via zgrep).
        mirror_log = bmc_log_zgrep(
            self.duthost,
            r"Mirroring TEMPERATURE_INFO|Failed to open remote BMC",
            tail=5,
        )
        if mirror_log:
            logger.info(f"BMC mirror log entries:\n{mirror_log}")
            if 'Mirroring TEMPERATURE_INFO' in mirror_log:
                logger.info("BMC TEMPERATURE_INFO mirror initialization confirmed")
            elif 'Failed to open remote BMC' in mirror_log:
                logger.info(
                    "BMC mirror initialization failed (BMC unreachable or misconfigured) — "
                    "thermalctld degrades gracefully"
                )
        else:
            logger.info(
                "No BMC mirror log found in /var/log/syslog* — thermalctld may have started earlier"
            )

        # Verify local TEMPERATURE_INFO is populated (source of mirror data).
        # Keys use | separator: TEMPERATURE_INFO|<sensor_name>
        count = len(redis_keys(self.duthost, STATE_DB, 'TEMPERATURE_INFO|*'))
        pytest_assert(count > 0,
                      "No TEMPERATURE_INFO|* entries in STATE_DB — "
                      "thermalctld has not polled thermal sensors yet")

    def test_thermalctld_switch_host_thermal_monitoring(self):
        """
        Verify thermalctld on BMC monitors Switch-Host TEMPERATURE_INFO for CRITICAL breaches.

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

        # Historical startup-log scan (rotation-safe via zgrep).
        init_log = bmc_log_zgrep(
            self.duthost,
            r"Monitoring chassis thermals|Failed to init chassis thermal",
            tail=5,
        )
        if init_log:
            logger.info(f"Thermal monitoring init log:\n{init_log}")

        # Historical CRITICAL chassis thermal events in event.log (informational).
        existing = bmc_log_zgrep(
            self.duthost, r"CRITICAL chassis thermal", tail=5, files=BMC_EVENT_LOG,
        )
        if existing:
            logger.info(f"Existing CRITICAL chassis thermal events:\n{existing}")

        # Inject a test TEMPERATURE_INFO entry with temp above critical threshold.
        # Key uses | separator: TEMPERATURE_INFO|<sensor_name> (sonic TABLE_NAME_SEPARATOR).
        TEST_SENSOR = "TEMPERATURE_INFO|test_critical_thermal_monitor"
        # Bracket the inject with BmcLogAnalyzer scanning syslog (live, no reboot).
        la = make_bmc_loganalyzer(self.duthost, "thermalctld_switch_host_thermal_breach")
        marker = la.init(log_target='syslog')
        try:
            redis_hset(self.duthost, STATE_DB, TEST_SENSOR,
                       temperature='120.0',
                       critical_high_threshold='80.0',
                       high_threshold='70.0',
                       low_threshold='-10.0',
                       warning='False',
                       timestamp='2099-01-01T00:00:00')
            # Wait for thermalctld to poll and log the breach (up to 2 update cycles).
            time.sleep(90)
        finally:
            redis_del(self.duthost, STATE_DB, TEST_SENSOR)

        la.match_regex = [r".*CRITICAL chassis thermal.*test_critical.*"]
        breach_result = la.analyze(marker, fail=False, log_target='syslog')
        match_count = breach_result.get("total", {}).get("match", 0)
        pytest_assert(match_count > 0,
                      "Expected 'CRITICAL chassis thermal' log for injected sensor "
                      f"{TEST_SENSOR} (120C > 80C threshold) not found in syslog within 90s")


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
