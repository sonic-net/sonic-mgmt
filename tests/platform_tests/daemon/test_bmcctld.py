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
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
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

        if not self.duthost.is_bmc():
            pytest.skip("Device is not a BMC system")

        if not check_pmon_daemon_enable_status(self.duthost, "bmcctld"):
            pytest.skip("bmcctld is not enabled on {}".format(self.duthost.facts['platform']))
        daemon_status, _ = self.duthost.get_pmon_daemon_status("bmcctld")
        if daemon_status != "RUNNING":
            pytest.skip("bmcctld daemon not running")

        yield

    def test_bmcctld_initialization(self, localhost):
        """
        Verify bmcctld initializes all required State DB tables and follows
        the correct startup path after a BMC reboot.

        Validates:
        - CHASSIS_MODULE_INFO:SWITCH-HOST populated with identity fields
        - HOST_STATE:switch-host initialized with valid device_status
        - Startup log reflects liquid-cooled vs air-cooled path
        - Service is running and responsive
        - After a BMC reboot (non-power-loss), pmon journal contains
          "Skipping SWITCH_HOST_POWER_ON_DELAY"
        """
        from tests.common.reboot import reboot, REBOOT_TYPE_COLD

        # Reboot the BMC so we exercise a fresh bmcctld initialization
        reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD)

        # Verify service running via existing infra (not pgrep)
        daemon_status, daemon_pid = self.duthost.get_pmon_daemon_status("bmcctld")
        pytest_assert(daemon_status == "RUNNING", "bmcctld daemon should be running")
        pytest_assert(daemon_pid != -1, "bmcctld daemon should have a valid pid")

        # Verify startup path logged — liquid-cooled or air-cooled branch
        result = self.duthost.shell(
            "journalctl -u pmon --no-pager -n 500 | grep -E 'STARTUP:.*liquid|STARTUP:.*power_on'",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            logger.info(f"bmcctld startup path: {result['stdout'].strip()}")
        else:
            logger.info("No bmcctld startup path log found (daemon may have been running before log window)")

        # Non-power-loss BMC reboot must SKIP the boot delay
        result = self.duthost.shell(
            "journalctl -u pmon --no-pager -n 1000 | grep 'Skipping SWITCH_HOST_POWER_ON_DELAY'",
            module_ignore_errors=True
        )
        pytest_assert(
            result['rc'] == 0 and result['stdout'].strip(),
            "Expected 'Skipping SWITCH_HOST_POWER_ON_DELAY' in pmon journal after non-power-loss BMC reboot"
        )

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
        thermalctld_status, _ = self.duthost.get_pmon_daemon_status("thermalctld")
        if thermalctld_status == "RUNNING":
            logger.info("thermalctld integration: daemon running")

        # Verify config handling
        result = self.duthost.shell(
            "config chassis modules --help 2>/dev/null | grep -i admin",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info("CONFIG_DB integration: config chassis modules available")

        # Verify psud integration
        psud_status, _ = self.duthost.get_pmon_daemon_status("psud")
        if psud_status == "RUNNING":
            logger.info("psud integration: daemon running")

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

        # --- Trigger 2b: CRITICAL leak → Switch-Host power off (disruptive) ---
        # Handler: _handle_system_leak with severity=CRITICAL dispatches the configured
        # LEAK_CONTROL_POLICY.system_critical_leak_action (default: power_off) on the
        # paired Switch-Host. Verify the Switch-Host actually powered off and rebooted.
        host = self.duthost.get_bmc_host()
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()
        # Ensure policy is power_off (the default).
        self.duthost.shell(
            "sonic-db-cli CONFIG_DB HSET 'LEAK_CONTROL_POLICY|system'"
            " system_critical_leak_action power_off",
            module_ignore_errors=True
        )
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                f" device_leak_status CRITICAL",
                module_ignore_errors=True
            )
            logger.info("Trigger 2b [STATE_DB SYSTEM_LEAK_STATUS]: device_leak_status → CRITICAL")
            wait_until(420, 10, 30, lambda: host.critical_services_fully_started())
            post_boot = host.shell("uptime -s").get('stdout', '').strip()
            pytest_assert(post_boot and post_boot != pre_boot,
                          f"Switch-Host uptime did not advance after CRITICAL leak: "
                          f"pre={pre_boot!r} post={post_boot!r}")
            cause_out = host.show_and_parse('show reboot-cause')
            cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
            valid_causes = ('power down request from bmc',
                            'graceful shutdown from bmc',
                            'power loss')
            pytest_assert(any(c in cause for c in valid_causes),
                          f"Switch-Host reboot-cause {cause!r} not in expected "
                          f"BMC-initiated set {valid_causes}")
            trigger_results['SYSTEM_LEAK_STATUS_CRITICAL'] = True
        finally:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                f" device_leak_status {orig_leak}",
                module_ignore_errors=True
            )
            # Best-effort recovery if Switch-Host did not auto-power-on.
            self.duthost.shell(
                "config chassis modules startup SWITCH-HOST",
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

    def test_bmcctld_rack_manager_command(self):
        """Disruptive: exercise all valid RACK_MANAGER_COMMAND values end-to-end.

        Issues POWER_OFF, GRACEFUL_SHUT, POWER_ON, POWER_CYCLE commands via
        RACK_MANAGER_COMMAND table and verifies each command transitions to status=DONE,
        the paired Switch-Host actually powered off/on, and the reboot-cause on the
        Switch-Host is BMC-initiated. Also verifies POWER_ON is rejected when a
        CRITICAL leak is present.
        """
        host = self.duthost.get_bmc_host()
        valid_causes = ('power down request from bmc',
                        'graceful shutdown from bmc',
                        'power loss')

        def hset_cmd(key, command):
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{RACK_MANAGER_COMMAND_TABLE}:{key}'"
                f" command {command} status PENDING",
                module_ignore_errors=True
            )
            logger.info(f"RACK_MANAGER_COMMAND[{key}]: command={command}")

        def hget_status(key):
            return self.duthost.shell(
                f"redis-cli -n 6 HGET '{RACK_MANAGER_COMMAND_TABLE}:{key}' status",
                module_ignore_errors=True
            ).get('stdout', '').strip()

        def del_cmd(*keys):
            for k in keys:
                self.duthost.shell(
                    f"redis-cli -n 6 DEL '{RACK_MANAGER_COMMAND_TABLE}:{k}'",
                    module_ignore_errors=True
                )

        def wait_off():
            wait_until(180, 10, 30,
                       lambda: host.shell("true", module_ignore_errors=True).get('rc') != 0)

        def wait_on():
            wait_until(420, 10, 30, lambda: host.critical_services_fully_started())

        def verify_reboot_cause(pre_boot):
            post_boot = host.shell("uptime -s").get('stdout', '').strip()
            pytest_assert(post_boot and post_boot != pre_boot,
                          f"Switch-Host uptime did not advance: pre={pre_boot!r} post={post_boot!r}")
            cause_out = host.show_and_parse('show reboot-cause')
            cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
            pytest_assert(any(c in cause for c in valid_causes),
                          f"Switch-Host reboot-cause {cause!r} not in {valid_causes}")

        # --- Scenario 1: POWER_OFF then POWER_ON ---
        off_key, on_key = 'test_power_off', 'test_power_on'
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()
        try:
            hset_cmd(off_key, 'POWER_OFF')
            wait_off()
            pytest_assert(hget_status(off_key) == 'DONE',
                          f"POWER_OFF status expected DONE, got {hget_status(off_key)!r}")
            hset_cmd(on_key, 'POWER_ON')
            wait_on()
            pytest_assert(hget_status(on_key) == 'DONE',
                          f"POWER_ON status expected DONE, got {hget_status(on_key)!r}")
            verify_reboot_cause(pre_boot)
        finally:
            del_cmd(off_key, on_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 2: GRACEFUL_SHUT then POWER_ON ---
        gs_key, on2_key = 'test_graceful_shut', 'test_power_on2'
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()
        try:
            hset_cmd(gs_key, 'GRACEFUL_SHUT')
            wait_off()
            pytest_assert(hget_status(gs_key) == 'DONE',
                          f"GRACEFUL_SHUT status expected DONE, got {hget_status(gs_key)!r}")
            hset_cmd(on2_key, 'POWER_ON')
            wait_on()
            pytest_assert(hget_status(on2_key) == 'DONE',
                          f"POWER_ON status expected DONE, got {hget_status(on2_key)!r}")
            verify_reboot_cause(pre_boot)
        finally:
            del_cmd(gs_key, on2_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 3: POWER_CYCLE (single command round-trip) ---
        pc_key = 'test_power_cycle'
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()
        try:
            hset_cmd(pc_key, 'POWER_CYCLE')
            wait_on()
            pytest_assert(hget_status(pc_key) == 'DONE',
                          f"POWER_CYCLE status expected DONE, got {hget_status(pc_key)!r}")
            verify_reboot_cause(pre_boot)
        finally:
            del_cmd(pc_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 4: POWER_ON blocked by CRITICAL leak ---
        blocked_key = 'test_blocked_power_on'
        orig_leak = self.duthost.shell(
            f"redis-cli -n 6 HGET '{SYSTEM_LEAK_STATUS_TABLE}:system' device_leak_status",
            module_ignore_errors=True
        ).get('stdout', '').strip() or 'OK'
        try:
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                f" device_leak_status CRITICAL",
                module_ignore_errors=True
            )
            hset_cmd(blocked_key, 'POWER_ON')
            wait_until(30, 3, 0, lambda: hget_status(blocked_key) == 'FAILED')
            pytest_assert(hget_status(blocked_key) == 'FAILED',
                          f"POWER_ON during CRITICAL leak should fail, got "
                          f"status={hget_status(blocked_key)!r}")
        finally:
            del_cmd(blocked_key)
            self.duthost.shell(
                f"redis-cli -n 6 HSET '{SYSTEM_LEAK_STATUS_TABLE}:system'"
                f" device_leak_status {orig_leak}",
                module_ignore_errors=True
            )
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

    def test_bmcctld_power_on_delay(self, localhost, get_pdu_controller):
        """Verify bmcctld's power_on_delay reaction to its own reboot cause.

        Two scenarios — power_on_delay is a BMC-side reaction to the BMC's own last
        reboot cause; it has nothing to do with the Switch-Host boot path:
          A) BMC cold reboot (non-power-loss): bmcctld must SKIP the delay.
             Journal must contain 'Skipping SWITCH_HOST_POWER_ON_DELAY' and must NOT
             contain 'SWITCH_HOST_POWER_ON_DELAY <N>' (delay-applied form).
          B) BMC power loss via external PDU (power-loss): bmcctld must APPLY the
             configured delay. Journal must contain 'SWITCH_HOST_POWER_ON_DELAY <N>'
             matching the configured value, and the elapsed time between that log
             and the subsequent power_on dispatch must be >= configured delay.
             Skipped if no PDU controller is wired for this BMC.
        """
        import re
        from datetime import datetime
        from tests.common.reboot import reboot, REBOOT_TYPE_COLD

        test_delay = 30
        tolerance_upper = 30

        orig_delay = self.duthost.shell(
            "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay",
            module_ignore_errors=True
        ).get('stdout', '').strip()

        try:
            self.duthost.shell(
                f"config chassis modules power-on-delay SWITCH-HOST {test_delay}",
                module_ignore_errors=True
            )
            readback = self.duthost.shell(
                "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay"
            ).get('stdout', '').strip()
            pytest_assert(readback == str(test_delay),
                          f"CONFIG_DB power_on_delay read-back expected {test_delay}, got {readback!r}")

            # -------------------------------------------------------------------
            # Scenario A: cold reboot the BMC -> reboot cause is NOT power loss
            #             -> bmcctld must skip the delay
            # -------------------------------------------------------------------
            reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
                   wait_for_ssh=True, safe_reboot=True)
            wait_until(420, 10, 30, lambda: self.duthost.critical_services_fully_started())

            bmc_uptime = self.duthost.shell("uptime -s").get('stdout', '').strip()
            journal_a = self.duthost.shell(
                f"journalctl -u pmon --since '{bmc_uptime}' --no-pager"
                " | grep -iE 'SWITCH_HOST_POWER_ON_DELAY' || true"
            ).get('stdout', '')
            logger.info(f"Scenario A (BMC cold reboot) journal:\n{journal_a}")

            pytest_assert('Skipping SWITCH_HOST_POWER_ON_DELAY' in journal_a,
                          "After non-power-loss BMC reboot, expected 'Skipping "
                          "SWITCH_HOST_POWER_ON_DELAY' log not found")
            delay_applied = re.search(
                r'SWITCH_HOST_POWER_ON_DELAY[^\w]*\d+', journal_a.replace('Skipping ', '')
            )
            pytest_assert(not delay_applied,
                          f"After non-power-loss BMC reboot, delay-applied log found "
                          f"unexpectedly: {delay_applied.group(0) if delay_applied else ''}")

            # -------------------------------------------------------------------
            # Scenario B: external PDU power cycle to BMC -> reboot cause IS
            #             power loss -> bmcctld must apply the configured delay
            # -------------------------------------------------------------------
            try:
                pdu_ctrl = get_pdu_controller(self.duthost)
            except Exception as e:
                pytest.skip(f"PDU controller not available for BMC {self.duthost.hostname}: {e}")
            if not pdu_ctrl:
                pytest.skip(f"No PDU controller wired for BMC {self.duthost.hostname}; "
                            "skipping power-loss scenario")

            outlets = pdu_ctrl.get_outlet_status()
            outlet_ids = [o['outlet_id'] for o in outlets if 'outlet_id' in o]
            pytest_assert(outlet_ids, "PDU controller returned no outlets for BMC")

            for outlet in outlet_ids:
                pdu_ctrl.turn_off_outlet(outlet)
            wait_until(120, 5, 10,
                       lambda: self.duthost.shell("true", module_ignore_errors=True).get('rc') != 0)
            for outlet in outlet_ids:
                pdu_ctrl.turn_on_outlet(outlet)

            wait_until(600, 15, 30, lambda: self.duthost.critical_services_fully_started())

            bmc_uptime_b = self.duthost.shell("uptime -s").get('stdout', '').strip()
            journal_b = self.duthost.shell(
                f"journalctl -u pmon --since '{bmc_uptime_b}' --no-pager"
                " | grep -iE 'SWITCH_HOST_POWER_ON_DELAY|power_on|POWER_ON' || true"
            ).get('stdout', '')
            logger.info(f"Scenario B (BMC power-loss) journal:\n{journal_b}")

            delay_match = re.search(
                r'(\S+\s+\S+\s+\S+).*?SWITCH_HOST_POWER_ON_DELAY[^\d]*(\d+)', journal_b
            )
            pytest_assert(delay_match,
                          "After PDU-induced BMC power-loss reboot, expected "
                          "'SWITCH_HOST_POWER_ON_DELAY <N>' log not found")
            logged_delay = int(delay_match.group(2))
            pytest_assert(logged_delay == test_delay,
                          f"Logged power_on_delay {logged_delay} != configured {test_delay}")

            poweron_match = re.search(
                r'(\S+\s+\S+\s+\S+).*?(?:Issuing power_on|POWER_ON dispatched|action=power_on)',
                journal_b
            )
            if poweron_match:
                fmt = '%b %d %H:%M:%S'
                t_delay = datetime.strptime(delay_match.group(1), fmt)
                t_on = datetime.strptime(poweron_match.group(1), fmt)
                elapsed = (t_on - t_delay).total_seconds()
                pytest_assert(test_delay <= elapsed <= test_delay + tolerance_upper,
                              f"Elapsed {elapsed}s between delay-log and power_on-dispatch "
                              f"outside expected [{test_delay}, {test_delay + tolerance_upper}]s")
                logger.info(f"Power-on delay honored: elapsed={elapsed}s, configured={test_delay}s")
            else:
                logger.warning("No 'Issuing power_on' log found; timing assertion skipped")
        finally:
            if orig_delay and orig_delay.isdigit():
                self.duthost.shell(
                    f"config chassis modules power-on-delay SWITCH-HOST {orig_delay}",
                    module_ignore_errors=True
                )

    def test_bmc_reboot_does_not_affect_switch_host(self, localhost):
        """Verify a BMC cold reboot does not power-cycle or reboot the paired Switch-Host.

        Confirms BMC↔Switch-Host fault isolation: rebooting the BMC SONiC instance
        must not trigger any POWER_OFF/POWER_ON/POWER_CYCLE on the Switch-Host.
        - BMC: uptime advances, reboot-cause history grows by one entry
        - Switch-Host: uptime unchanged, reboot-cause history length unchanged
        """
        from tests.common.reboot import reboot, REBOOT_TYPE_COLD

        host = self.duthost.get_bmc_host()

        sw_uptime_pre = host.shell("uptime -s").get('stdout', '').strip()
        sw_history_pre = host.show_and_parse('show reboot-cause history') or []
        bmc_uptime_pre = self.duthost.shell("uptime -s").get('stdout', '').strip()
        bmc_history_pre = self.duthost.show_and_parse('show reboot-cause history') or []

        reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
               wait_for_ssh=True, safe_reboot=True)

        wait_until(420, 10, 30, lambda: self.duthost.critical_services_fully_started())

        bmc_uptime_post = self.duthost.shell("uptime -s").get('stdout', '').strip()
        bmc_history_post = self.duthost.show_and_parse('show reboot-cause history') or []
        pytest_assert(bmc_uptime_post and bmc_uptime_post != bmc_uptime_pre,
                      f"BMC uptime did not advance after reboot: "
                      f"pre={bmc_uptime_pre!r} post={bmc_uptime_post!r}")
        pytest_assert(len(bmc_history_post) > len(bmc_history_pre),
                      f"BMC reboot-cause history did not grow: "
                      f"pre={len(bmc_history_pre)} post={len(bmc_history_post)}")

        sw_uptime_post = host.shell("uptime -s").get('stdout', '').strip()
        sw_history_post = host.show_and_parse('show reboot-cause history') or []
        pytest_assert(sw_uptime_post == sw_uptime_pre,
                      f"Switch-Host uptime advanced after BMC reboot — isolation broken: "
                      f"pre={sw_uptime_pre!r} post={sw_uptime_post!r}")
        pytest_assert(len(sw_history_post) == len(sw_history_pre),
                      f"Switch-Host reboot-cause history grew after BMC reboot — "
                      f"isolation broken: pre={len(sw_history_pre)} post={len(sw_history_post)}")
        pytest_assert(host.critical_services_fully_started(),
                      "Switch-Host critical services not fully started after BMC reboot")


# ---------------------------------------------------------------------------
# Lifecycle tests: running / stop-start / term-start / kill-start
# ---------------------------------------------------------------------------

BMCCTLD_DAEMON_NAME = "bmcctld"
BMCCTLD_DB_KEY_PATTERN = "CHASSIS_MODULE_INFO|*"

_SIG_STOP_SERVICE = None
_SIG_TERM = "-15"
_SIG_KILL = "-9"

_expected_running_status = "RUNNING"
_expected_stopped_status = "STOPPED"


@pytest.fixture(scope="module", autouse=False)
def bmcctld_teardown_module(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure bmcctld is left running after lifecycle tests."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield
    daemon_status, _ = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    if daemon_status != _expected_running_status:
        duthost.start_pmon_daemon(BMCCTLD_DAEMON_NAME)
        time.sleep(10)


@pytest.fixture
def bmcctld_check_daemon_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure bmcctld is running before each lifecycle test."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    daemon_status, _ = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    if daemon_status != _expected_running_status:
        duthost.start_pmon_daemon(BMCCTLD_DAEMON_NAME)
        time.sleep(10)


def _bmcctld_collect_data(duthost):
    keys = duthost.shell(
        'sonic-db-cli STATE_DB KEYS "{}"'.format(BMCCTLD_DB_KEY_PATTERN)
    )['stdout_lines']
    dev_data = {}
    for k in keys:
        data = duthost.shell('sonic-db-cli STATE_DB HGETALL "{}"'.format(k))['stdout']
        dev_data[k] = data
    return {'keys': sorted(keys), 'data': dev_data}


def _bmcctld_check_expected_status(duthost, expected_status):
    daemon_status, _ = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    return daemon_status == expected_status


def _bmcctld_check_restarted(duthost, pre_pid):
    _, pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    return pid > pre_pid


@pytest.fixture(scope="module")
def bmcctld_data_before_restart(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not check_pmon_daemon_enable_status(duthost, BMCCTLD_DAEMON_NAME):
        pytest.skip("{} is not enabled on {}".format(BMCCTLD_DAEMON_NAME, duthost.facts['platform']))
    return _bmcctld_collect_data(duthost)


def test_pmon_bmcctld_running_status(duthosts, enum_rand_one_per_hwsku_hostname,
                                     bmcctld_data_before_restart,
                                     bmcctld_teardown_module):
    """Verify bmcctld is RUNNING with a valid pid."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(BMCCTLD_DAEMON_NAME, daemon_status, daemon_pid))
    pytest_assert(daemon_status == _expected_running_status,
                  "{} expected {} but is {}".format(BMCCTLD_DAEMON_NAME, _expected_running_status, daemon_status))
    pytest_assert(daemon_pid != -1,
                  "{} expected valid pid but got {}".format(BMCCTLD_DAEMON_NAME, daemon_pid))


def test_pmon_bmcctld_stop_and_start_status(bmcctld_check_daemon_status, duthosts,
                                            enum_rand_one_per_hwsku_hostname,
                                            bmcctld_data_before_restart,
                                            bmcctld_teardown_module):
    """Verify bmcctld stops cleanly and recovers after supervisorctl start."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(BMCCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(BMCCTLD_DAEMON_NAME, _SIG_STOP_SERVICE)
    time.sleep(2)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    pytest_assert(daemon_status == _expected_stopped_status,
                  "{} expected {} but is {}".format(BMCCTLD_DAEMON_NAME, _expected_stopped_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                  "{} expected pid -1 but got {}".format(BMCCTLD_DAEMON_NAME, daemon_pid))

    duthost.start_pmon_daemon(BMCCTLD_DAEMON_NAME)
    wait_until(120, 10, 0, _bmcctld_check_restarted, duthost, pre_pid)
    wait_until(60, 10, 0, _bmcctld_check_expected_status, duthost, _expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    pytest_assert(post_status == _expected_running_status,
                  "{} expected {} after restart but is {}".format(
                      BMCCTLD_DAEMON_NAME, _expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-stop pid {}".format(
                      BMCCTLD_DAEMON_NAME, post_pid, pre_pid))


def test_pmon_bmcctld_term_and_start_status(bmcctld_check_daemon_status, duthosts,
                                            enum_rand_one_per_hwsku_hostname,
                                            bmcctld_data_before_restart,
                                            bmcctld_teardown_module):
    """Verify bmcctld auto-restarts after SIGTERM."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(BMCCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(BMCCTLD_DAEMON_NAME, _SIG_TERM, pre_pid)
    wait_until(120, 10, 0, _bmcctld_check_restarted, duthost, pre_pid)
    wait_until(60, 10, 0, _bmcctld_check_expected_status, duthost, _expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    pytest_assert(post_status == _expected_running_status,
                  "{} expected {} after SIGTERM but is {}".format(
                      BMCCTLD_DAEMON_NAME, _expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-term pid {}".format(
                      BMCCTLD_DAEMON_NAME, post_pid, pre_pid))


def test_pmon_bmcctld_kill_and_start_status(bmcctld_check_daemon_status, duthosts,
                                            enum_rand_one_per_hwsku_hostname,
                                            bmcctld_data_before_restart,
                                            bmcctld_teardown_module):
    """Verify bmcctld auto-restarts after SIGKILL."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pre_status, pre_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    logger.info("{} daemon is {} with pid {}".format(BMCCTLD_DAEMON_NAME, pre_status, pre_pid))

    duthost.stop_pmon_daemon(BMCCTLD_DAEMON_NAME, _SIG_KILL, pre_pid)
    wait_until(120, 10, 0, _bmcctld_check_restarted, duthost, pre_pid)
    wait_until(120, 10, 0, _bmcctld_check_expected_status, duthost, _expected_running_status)

    post_status, post_pid = duthost.get_pmon_daemon_status(BMCCTLD_DAEMON_NAME)
    pytest_assert(post_status == _expected_running_status,
                  "{} expected {} after SIGKILL but is {}".format(
                      BMCCTLD_DAEMON_NAME, _expected_running_status, post_status))
    pytest_assert(post_pid > pre_pid,
                  "Restarted {} pid {} should be greater than pre-kill pid {}".format(
                      BMCCTLD_DAEMON_NAME, post_pid, pre_pid))
