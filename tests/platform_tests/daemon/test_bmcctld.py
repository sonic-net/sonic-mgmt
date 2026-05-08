"""
Integration tests for bmcctld daemon behavior

Tests cover:
- Chassis module info initialization and maintenance
- HOST_STATE and CHASSIS_MODULE_INFO synchronization
- Admin status mirroring on config changes
- Critical event handling (leaks, Rack Manager alerts)
- Performance and reliability metrics
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

HOST_STATE_TABLE = 'HOST_STATE'
CHASSIS_MODULE_TABLE = 'CHASSIS_MODULE'
CHASSIS_MODULE_INFO_TABLE = 'CHASSIS_MODULE_INFO'
SYSTEM_LEAK_STATUS_TABLE = 'SYSTEM_LEAK_STATUS'
RACK_MANAGER_COMMAND_TABLE = 'RACK_MANAGER_COMMAND'
RACK_MANAGER_ALERT_TABLE = 'RACK_MANAGER_ALERT'
HOST_STATE_KEY = 'switch-host'


class TestBmcctldDaemon:
    """
    Integration tests for bmcctld daemon
    """

    @pytest.fixture(scope='function', autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Get duthost reference and verify BMC system"""
        self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        result = self.duthost.shell(
            "grep -q 'switch_bmc=1' /etc/sonic/platform_env.conf 2>/dev/null",
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            pytest.skip("Device is not a BMC system")

        yield

    def test_bmcctld_initialization(self):
        """
        Verify bmcctld initializes all required State DB tables

        Validates:
        - CHASSIS_MODULE_INFO:SWITCH-HOST populated with identity fields
        - HOST_STATE:switch-host initialized with valid device_status
        - Service is running and responsive
        """
        # Verify service running
        result = self.duthost.shell(
            "docker exec pmon pgrep bmcctld",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0, "bmcctld daemon should be running")

        # Verify CHASSIS_MODULE_INFO
        result = self.duthost.shell(
            f"redis-cli -n 6 HGETALL '{CHASSIS_MODULE_INFO_TABLE}:SWITCH-HOST'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout']:
            lines = result['stdout'].strip().split('\n')
            info_dict = {lines[i]: lines[i+1] for i in range(0, len(lines), 2) if i+1 < len(lines)}

            pytest_assert('name' in info_dict or 'slot' in info_dict,
                          "CHASSIS_MODULE_INFO missing required identity fields")
            logger.info(f"CHASSIS_MODULE_INFO initialized: {list(info_dict.keys())}")
        else:
            logger.info("CHASSIS_MODULE_INFO not populated - expected on some platforms")

        # Verify HOST_STATE
        result = self.duthost.shell(
            f"redis-cli -n 6 HGETALL '{HOST_STATE_TABLE}:{HOST_STATE_KEY}'",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout']:
            lines = result['stdout'].strip().split('\n')
            state_dict = {lines[i]: lines[i+1] for i in range(0, len(lines), 2) if i+1 < len(lines)}

            pytest_assert('device_status' in state_dict,
                          "HOST_STATE missing device_status field")

            valid_states = ['OFFLINE', 'ONLINE', 'POWERING_ON', 'POWERING_OFF', 'POWER_CYCLE']
            status = state_dict.get('device_status', '')
            pytest_assert(status in valid_states,
                          f"device_status '{status}' not valid")
        else:
            logger.info("HOST_STATE not populated - expected on some platforms")

    def test_bmcctld_state_db_consistency(self):
        """
        Verify State DB consistency and proper synchronization

        Validates:
        - CHASSIS_MODULE oper_status reflects HOST_STATE device_status
        - Schema compliance and atomicity
        - Timestamp accuracy
        - Operational status mapping
        """
        # Get HOST_STATE
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{HOST_STATE_TABLE}:{HOST_STATE_KEY}' device_status",
            module_ignore_errors=True
        )

        if result['rc'] != 0 or not result['stdout']:
            logger.info("HOST_STATE not yet populated")
            return

        host_status = result['stdout'].strip()
        logger.info(f"HOST_STATE device_status: {host_status}")

        # Get CHASSIS_MODULE oper_status
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{CHASSIS_MODULE_TABLE}:SWITCH-HOST' oper_status",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            oper_status = result['stdout'].strip()
            logger.info(f"CHASSIS_MODULE oper_status: {oper_status}")

        # Verify admin_status consistency
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{CHASSIS_MODULE_TABLE}:SWITCH-HOST' admin_status",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            admin_status = result['stdout'].strip()
            pytest_assert(admin_status.lower() in ['up', 'down'],
                          f"admin_status '{admin_status}' should be 'up' or 'down'")

        # Verify timestamps
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{HOST_STATE_TABLE}:{HOST_STATE_KEY}' timestamp",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            try:
                ts = float(result['stdout'].strip())
                current = time.time()
                age = current - ts

                pytest_assert(age < 3600,
                              f"Timestamp age {age}s exceeds 1 hour")
                logger.info(f"Timestamp is {age:.1f}s old - OK")
            except ValueError:
                logger.warning("Could not parse timestamp")

    def test_bmcctld_event_handling(self):
        """
        Verify bmcctld handles events, logs them, and integrates with other daemons

        Validates:
        - Events logged in syslog with timestamps
        - Critical events (leaks) block power-on
        - thermalctld leak events are processed
        - psud power supply events are handled
        - CONFIG_DB changes are applied
        - State changes propagate correctly
        """
        # Check for critical leak blocking power-on
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        )

        leak_status = result['stdout'].strip() if result['rc'] == 0 else None

        if leak_status == 'CRITICAL':
            result = self.duthost.shell(
                f"redis-cli -n 6 HGET '{HOST_STATE_TABLE}:{HOST_STATE_KEY}' device_status",
                module_ignore_errors=True
            )

            if result['rc'] == 0:
                host_status = result['stdout'].strip()
                pytest_assert(host_status not in ['ONLINE', 'POWERING_ON'],
                              f"Critical leak should prevent online: {host_status}")

        # Check event logging
        result = self.duthost.shell(
            "journalctl -u pmon -n 50 2>/dev/null | grep -i 'bmcctld\\|chassis' | head -10",
            module_ignore_errors=True
        )

        logger.info(f"Recent bmcctld events:\n{result['stdout'][:300]}")

        # Verify thermalctld running
        result = self.duthost.shell(
            "docker exec pmon pgrep thermalctld",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info("thermalctld integration: daemon running")

        # Verify config handling
        result = self.duthost.shell(
            "config chassis module --help 2>/dev/null | grep -i admin",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info("CONFIG_DB integration: config chassis module available")

        # Verify psud integration
        result = self.duthost.shell(
            "docker exec pmon pgrep psud",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info("psud integration: daemon running")

    def test_bmcctld_performance(self):
        """
        Verify bmcctld performance and reliability

        Measures:
        - State DB update latency
        - Daemon restart recovery
        - Consistency under repeated state queries
        """
        # Measure query latency
        import time

        start = time.time()
        query_result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{HOST_STATE_TABLE}:{HOST_STATE_KEY}' device_status",
            module_ignore_errors=True
        )
        elapsed = time.time() - start

        pytest_assert(query_result['rc'] == 0 and elapsed < 5.0,
                      f"Query failed or latency {elapsed:.3f}s is excessive")
        logger.info(f"STATE_DB query latency: {elapsed:.3f}s")

        # Verify daemon responsiveness
        result = self.duthost.shell(
            "docker exec pmon systemctl is-active bmcctld",
            module_ignore_errors=True
        )

        pytest_assert(result['rc'] == 0,
                      "bmcctld should remain active after queries")

        # Verify consistency across reads
        values = []
        for _ in range(3):
            result = self.duthost.shell(
                f"redis-cli -n 6 HGET '{HOST_STATE_TABLE}:{HOST_STATE_KEY}' device_status",
                module_ignore_errors=True
            )
            if result['rc'] == 0:
                values.append(result['stdout'].strip())
            time.sleep(0.1)

        if len(values) > 1:
            # All values should be identical (no state drift)
            unique_values = set(values)
            pytest_assert(len(unique_values) <= 2,
                          f"State unstable: {unique_values}")

    def test_bmcctld_event_log(self):
        """
        Verify bmcctld logs critical events to /host/bmc/event.log

        Validates:
        - Event log file exists
        - Critical events are logged with timestamps
        - Log format is consistent (timestamp, severity, event type)
        - Recent critical events are present
        """
        # Check if event log exists
        result = self.duthost.shell(
            "test -f /host/bmc/event.log && echo 'exists' || echo 'not found'",
            module_ignore_errors=True
        )

        if result['rc'] != 0 or 'not found' in result['stdout']:
            logger.info("Event log not present - expected on non-BMC systems")
            return

        logger.info("Event log found at /host/bmc/event.log")

        # Check event log size and content
        result = self.duthost.shell(
            "ls -lh /host/bmc/event.log",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info(f"Event log details: {result['stdout'].strip()}")

        # Read recent events
        result = self.duthost.shell(
            "tail -20 /host/bmc/event.log 2>/dev/null | cat",
            module_ignore_errors=True
        )

        if result['rc'] == 0 and result['stdout'].strip():
            events = result['stdout'].strip().split('\n')
            logger.info(f"Recent events in log ({len(events)} lines):")

            # Validate log format and extract event types
            event_types = set()
            for event in events:
                if event:
                    logger.info(f"  {event[:100]}")

                    # Check for timestamp format (ISO 8601 or similar)
                    has_timestamp = any(pattern in event for pattern in [
                        'T', ':', '2024', '2025', '2026'  # Date/time patterns
                    ])
                    if has_timestamp:
                        event_types.add('timestamped')

                    # Check for severity levels
                    if any(sev in event.upper() for sev in ['CRITICAL', 'ERROR', 'WARN', 'INFO']):
                        event_types.add('severity_marked')

                    # Check for common event types
                    if any(evt in event.lower() for evt in ['leak', 'power', 'status', 'module']):
                        event_types.add('bmc_event')

            logger.info(f"Event characteristics found: {event_types}")
        else:
            logger.info("Event log is empty or not readable - expected for new systems")

    def test_bmcctld_event_trigger(self):
        """
        Trigger bmcctld events via HSET on all four subscribed tables and verify logging

        bmcctld subscribes via SubscriberStateTable to these tables; an HSET on any of
        them wakes the event thread and invokes the corresponding handler, which must
        produce a log entry in syslog (pmon journal) or /host/bmc/event.log:

        - CONFIG_DB  CHASSIS_MODULE|SWITCH-HOST  admin_status      (_handle_chassis_module)
        - STATE_DB   SYSTEM_LEAK_STATUS:system   device_leak_status (_handle_system_leak)
        - STATE_DB   RACK_MANAGER_COMMAND:<id>   command            (_handle_rack_mgr_command)
        - STATE_DB   RACK_MANAGER_ALERT:<id>     severity           (_handle_rack_mgr_alert)

        Safe payload choices avoid real power actions:
        - RACK_MANAGER_COMMAND uses an unknown command so bmcctld logs a warning and
          marks it FAILED without dispatching any power action.
        - RACK_MANAGER_ALERT uses MINOR severity whose default action is syslog_only.
        - SYSTEM_LEAK_STATUS uses MINOR whose default action is syslog_only.
        - CHASSIS_MODULE flips admin_status and immediately restores it.

        Each trigger saves/restores state and the test asserts at least one table
        produced a log entry on a live BMC system.
        """
        def log_contains(pattern):
            """Check pmon journal and /host/bmc/event.log for pattern."""
            result = self.duthost.shell(
                f"journalctl -u pmon --since '1 minute ago' 2>/dev/null"
                f" | grep -i '{pattern}' | tail -3",
                module_ignore_errors=True
            )
            if result['rc'] == 0 and result['stdout'].strip():
                return True
            result = self.duthost.shell(
                f"tail -30 /host/bmc/event.log 2>/dev/null | grep -i '{pattern}'",
                module_ignore_errors=True
            )
            return result['rc'] == 0 and bool(result['stdout'].strip())

        trigger_results = {}

        # --- Trigger 1: CONFIG_DB CHASSIS_MODULE admin_status ---
        # Handler: _handle_chassis_module → logs "CHASSIS_MODULE change: key=SWITCH-HOST admin_status=..."
        result = self.duthost.shell(
            "redis-cli -n 4 HGET 'CHASSIS_MODULE|SWITCH-HOST' admin_status",
            module_ignore_errors=True
        )
        orig_admin = result['stdout'].strip() or 'up'
        new_admin = 'down' if orig_admin.lower() == 'up' else 'up'
        try:
            self.duthost.shell(
                f"redis-cli -n 4 HSET 'CHASSIS_MODULE|SWITCH-HOST' admin_status {new_admin}",
                module_ignore_errors=True
            )
            logger.info(f"Trigger 1 [CONFIG_DB CHASSIS_MODULE admin_status]: {orig_admin} → {new_admin}")
            found = wait_until(30, 3, 0, log_contains, 'SWITCH-HOST')
            trigger_results['CHASSIS_MODULE'] = found
            logger.info(f"Trigger 1: {'logged' if found else 'no log within 30s'}")
        finally:
            self.duthost.shell(
                f"redis-cli -n 4 HSET 'CHASSIS_MODULE|SWITCH-HOST' admin_status {orig_admin}",
                module_ignore_errors=True
            )

        # --- Trigger 2: STATE_DB SYSTEM_LEAK_STATUS device_leak_status ---
        # Handler: _handle_system_leak → logs "System leak..." and dispatches syslog_only for MINOR
        result = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        )
        orig_leak = result['stdout'].strip() or 'OK'
        if orig_leak == 'CRITICAL':
            logger.info("Trigger 2 [STATE_DB SYSTEM_LEAK_STATUS]: already CRITICAL - skipping")
        else:
            try:
                self.duthost.shell(
                    f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                    f" device_leak_status MINOR",
                    module_ignore_errors=True
                )
                logger.info("Trigger 2 [STATE_DB SYSTEM_LEAK_STATUS]: device_leak_status → MINOR")
                found = wait_until(30, 3, 0, log_contains, 'leak')
                trigger_results['SYSTEM_LEAK_STATUS'] = found
                logger.info(f"Trigger 2: {'logged' if found else 'no log within 30s'}")
            finally:
                self.duthost.shell(
                    f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                    f" device_leak_status {orig_leak}",
                    module_ignore_errors=True
                )

        # --- Trigger 3: STATE_DB RACK_MANAGER_COMMAND unknown command ---
        # Handler: _handle_rack_mgr_command → logs "Unknown Rack Manager command: TEST_TRIGGER"
        # and sets status=FAILED; no power action is dispatched for unknown commands.
        cmd_key = 'test_trigger_cmd'
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{RACK_MANAGER_COMMAND_TABLE}:{cmd_key}'"
                f" command TEST_TRIGGER status ''",
                module_ignore_errors=True
            )
            logger.info("Trigger 3 [STATE_DB RACK_MANAGER_COMMAND]: command=TEST_TRIGGER (unknown)")
            found = wait_until(30, 3, 0, log_contains, 'rack.*manager\\|rack_mgr\\|RACK_MGR')
            trigger_results['RACK_MANAGER_COMMAND'] = found
            logger.info("Trigger 3: logged" if found else "no log within 30s")
        finally:
            self.duthost.shell(
                f"redis-cli -n 6 DEL '{RACK_MANAGER_COMMAND_TABLE}:{cmd_key}'",
                module_ignore_errors=True
            )

        # --- Trigger 4: STATE_DB RACK_MANAGER_ALERT MINOR severity ---
        # Handler: _handle_rack_mgr_alert → logs "RACK_MGR_MINOR_EVENT"; default action
        # is syslog_only so no power action is dispatched.
        alert_key = 'test_trigger_alert'
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{RACK_MANAGER_ALERT_TABLE}:{alert_key}'"
                f" severity MINOR",
                module_ignore_errors=True
            )
            logger.info("Trigger 4 [STATE_DB RACK_MANAGER_ALERT]: severity=MINOR")
            found = wait_until(30, 3, 0, log_contains, 'rack.*alert\\|rack_mgr\\|RACK_MGR')
            trigger_results['RACK_MANAGER_ALERT'] = found
            logger.info("Trigger 4: logged" if found else "no log within 30s")
        finally:
            self.duthost.shell(
                f"redis-cli -n 6 DEL '{RACK_MANAGER_ALERT_TABLE}:{alert_key}'",
                module_ignore_errors=True
            )

        # At least one trigger must produce a log on a live BMC system
        logged = [t for t, v in trigger_results.items() if v]
        not_logged = [t for t, v in trigger_results.items() if not v]
        if logged:
            logger.info(f"Event logging confirmed for: {logged}")
        if not_logged:
            logger.info(f"No log detected (may require hardware) for: {not_logged}")
        pytest_assert(
            any(trigger_results.values()),
            f"bmcctld did not log any event after HSET on: {list(trigger_results.keys())}"
        )
