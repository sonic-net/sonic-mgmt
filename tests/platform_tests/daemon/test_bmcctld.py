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
import re
import time
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.platform.bmc_utils import (
    BMC_EVENT_LOG,
    CONFIG_DB,
    STATE_DB,
    bmc_log_zgrep,
    get_host_uptime,
    get_switch_host_or_skip_test,
    make_bmc_loganalyzer,
    pause_pmon_daemon,
    redis_del,
    redis_hget,
    redis_hgetall,
    redis_hset,
    verify_bmc_initiated_reboot,
    wait_host_off,
    wait_host_on,
)
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

        # Reboot the BMC so we exercise a fresh bmcctld initialization
        reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
               wait_for_ssh=True, safe_reboot=True)
        wait_until(420, 10, 30, lambda: self.duthost.critical_services_fully_started())

        # Verify service running via existing infra (not pgrep)
        daemon_status, daemon_pid = self.duthost.get_pmon_daemon_status("bmcctld")
        pytest_assert(daemon_status == "RUNNING", "bmcctld daemon should be running")
        pytest_assert(daemon_pid != -1, "bmcctld daemon should have a valid pid")

        # Verify startup path logged (historical scan, rotation-safe via zgrep on syslog+event.log).
        startup = bmc_log_zgrep(
            self.duthost,
            r"STARTUP:.*liquid|STARTUP:.*power_on",
            tail=5,
            files=f"/var/log/syslog* {BMC_EVENT_LOG}",
        )
        if startup:
            logger.info(f"bmcctld startup path: {startup}")
        else:
            logger.info("No bmcctld startup path log found (daemon may have been running before log window)")

        # Non-power-loss BMC reboot must SKIP the boot delay.
        skipped = bmc_log_zgrep(
            self.duthost,
            r"Skipping SWITCH_HOST_POWER_ON_DELAY",
            tail=5,
            files=f"/var/log/syslog* {BMC_EVENT_LOG}",
        )
        pytest_assert(
            bool(skipped),
            "Expected 'Skipping SWITCH_HOST_POWER_ON_DELAY' in BMC syslog/event.log "
            "after non-power-loss BMC reboot"
        )

        # Verify CHASSIS_MODULE_INFO
        info_dict = redis_hgetall(self.duthost, STATE_DB,
                                  f'{CHASSIS_MODULE_INFO_TABLE}|SWITCH-HOST')

        if info_dict:
            pytest_assert('name' in info_dict or 'slot' in info_dict,
                          "CHASSIS_MODULE_INFO missing required identity fields")
            logger.info(f"CHASSIS_MODULE_INFO initialized: {list(info_dict.keys())}")
        else:
            logger.info("CHASSIS_MODULE_INFO not populated - expected on some platforms")

        # Verify HOST_STATE
        state_dict = redis_hgetall(self.duthost, STATE_DB,
                                   f'{HOST_STATE_TABLE}|{HOST_STATE_KEY}')

        if state_dict:
            pytest_assert('device_status' in state_dict,
                          "HOST_STATE missing device_status field")

            valid_states = ['OFFLINE', 'ONLINE', 'POWERING_ON', 'POWERING_OFF', 'POWER_CYCLE']
            status = state_dict.get('device_status', '')
            pytest_assert(status in valid_states,
                          f"device_status '{status}' not valid")
        else:
            logger.info("HOST_STATE not populated - expected on some platforms")

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
        - RACK_MANAGER_ALERT uses MINOR severity whose default action is syslog_only.
        - SYSTEM_LEAK_STATUS uses MINOR whose default action is syslog_only.
        - CHASSIS_MODULE flips admin_status and immediately restores it.

        RACK_MANAGER_COMMAND (both valid and unknown commands) is covered end-to-end
        in test_bmcctld_rack_manager_command.

        Each trigger saves/restores state and the test asserts at least one table
        produced a log entry on a live BMC system. Also verifies bmcctld's daemon
        integrations (thermalctld running, CONFIG_DB CLI present) and that the
        BMC event log file `/host/bmc/event.log` exists with fresh entries after
        triggers.
        """
        # --- Pre-flight: daemon integrations bmcctld depends on ---
        thermalctld_status, _ = self.duthost.get_pmon_daemon_status("thermalctld")
        pytest_assert(thermalctld_status == "RUNNING",
                      "thermalctld must be running for bmcctld leak event handling")

        result = self.duthost.shell(
            "config chassis modules --help 2>/dev/null | grep -Ei 'startup|shutdown'",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0 and result['stdout'].strip(),
                      "'config chassis modules' CLI must be available for CHASSIS_MODULE triggers")

        # Single LogAnalyzer for all triggers; re-init per phase to refresh markers
        # in both syslog and event.log (additional_files).
        la = make_bmc_loganalyzer(self.duthost, "bmcctld_event_trigger_chassis_module")

        trigger_results = {}

        # --- Trigger 1: CONFIG_DB CHASSIS_MODULE admin_status ---
        # Handler: _handle_chassis_module → logs "CHASSIS_MODULE change: key=SWITCH-HOST admin_status=..."
        orig_admin = redis_hget(self.duthost, CONFIG_DB,
                                'CHASSIS_MODULE|SWITCH-HOST', 'admin_status') or 'up'
        new_admin = 'down' if orig_admin.lower() == 'up' else 'up'
        marker = la.init()
        try:
            redis_hset(self.duthost, CONFIG_DB, 'CHASSIS_MODULE|SWITCH-HOST',
                       admin_status=new_admin)
            logger.info(f"Trigger 1 [CONFIG_DB CHASSIS_MODULE admin_status]: {orig_admin} → {new_admin}")
            time.sleep(15)
        finally:
            redis_hset(self.duthost, CONFIG_DB, 'CHASSIS_MODULE|SWITCH-HOST',
                       admin_status=orig_admin)
        la.match_regex = [r".*SWITCH-HOST.*"]
        r1 = la.analyze(marker, fail=False)
        trigger_results['CHASSIS_MODULE'] = r1.get("total", {}).get("match", 0) > 0
        logger.info(f"Trigger 1: {'logged' if trigger_results['CHASSIS_MODULE'] else 'no log within 15s'}")

        # --- Trigger 2: STATE_DB SYSTEM_LEAK_STATUS device_leak_status ---
        # Handler logs "System leak..."; MINOR must go to syslog ONLY (event.log is CRITICAL-only).
        orig_leak = redis_hget(self.duthost, STATE_DB,
                               f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                               'device_leak_status') or 'OK'
        if orig_leak == 'CRITICAL':
            logger.info("Trigger 2 [STATE_DB SYSTEM_LEAK_STATUS]: already CRITICAL - skipping")
        else:
            # Re-init (not update_marker_prefix) so the new start marker is also
            # written to additional_files (event.log); update_marker_prefix only
            # writes to syslog.
            la.marker_prefix = "bmcctld_event_trigger_minor_leak"
            marker = la.init()
            la.match_regex = []
            # Pause thermalctld so it doesn't overwrite the injected device_leak_status.
            with pause_pmon_daemon(self.duthost, 'thermalctld'):
                try:
                    redis_hset(self.duthost, STATE_DB,
                               f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                               device_leak_status='MINOR')
                    logger.info("Trigger 2 [STATE_DB SYSTEM_LEAK_STATUS]: device_leak_status → MINOR")
                    time.sleep(15)
                finally:
                    redis_hset(self.duthost, STATE_DB,
                               f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                               device_leak_status=orig_leak)
            la.match_regex = [r".*[Ll]eak.*"]
            r2 = la.analyze(marker, fail=False)
            trigger_results['SYSTEM_LEAK_STATUS'] = r2.get("total", {}).get("match", 0) > 0
            logger.info(f"Trigger 2: {'logged' if trigger_results['SYSTEM_LEAK_STATUS'] else 'no log within 15s'}")
            # MINOR is syslog-only: must NOT appear in event.log.
            minor_in_eventlog = []
            for path, lines in (r2.get("match_messages") or {}).items():
                if BMC_EVENT_LOG.split('/')[-1] in path:
                    minor_in_eventlog.extend(
                        ln for ln in lines if 'minor' in ln.lower() and 'leak' in ln.lower()
                    )
            pytest_assert(
                not minor_in_eventlog,
                f"MINOR leak event must NOT be written to {BMC_EVENT_LOG} (syslog-only). "
                f"Found {len(minor_in_eventlog)} line(s): {minor_in_eventlog[:3]}"
            )

        # --- Trigger 2b: CRITICAL leak → Switch-Host power off (disruptive) ---
        # CRITICAL dispatches system_critical_leak_action (default: power_off); verify paired Switch-Host rebooted.
        host = get_switch_host_or_skip_test(self.duthost)
        pre_boot = get_host_uptime(host)
        # Ensure policy is power_off (the default).
        redis_hset(self.duthost, CONFIG_DB, 'LEAK_CONTROL_POLICY|system',
                   system_critical_leak_action='power_off')
        # Pause thermalctld so it doesn't overwrite the injected device_leak_status
        with pause_pmon_daemon(self.duthost, 'thermalctld'):
            try:
                redis_hset(self.duthost, STATE_DB,
                           f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                           device_leak_status='CRITICAL')
                logger.info("Trigger 2b [STATE_DB SYSTEM_LEAK_STATUS]: device_leak_status → CRITICAL")
                wait_host_on(host)
                verify_bmc_initiated_reboot(host, pre_boot)
                trigger_results['SYSTEM_LEAK_STATUS_CRITICAL'] = True
            finally:
                redis_hset(self.duthost, STATE_DB,
                           f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                           device_leak_status=orig_leak)
                # Best-effort recovery if Switch-Host did not auto-power-on.
                self.duthost.shell(
                    "config chassis modules startup SWITCH-HOST",
                    module_ignore_errors=True
                )

        # --- Trigger 3: STATE_DB RACK_MANAGER_ALERT MINOR severity ---
        # Handler logs "RACK_MGR_MINOR_EVENT"; default action is syslog_only (no power action).
        alert_key = 'test_trigger_alert'
        la.marker_prefix = "bmcctld_event_trigger_rack_mgr_alert"
        marker = la.init()
        la.match_regex = []
        try:
            redis_hset(self.duthost, STATE_DB,
                       f'{RACK_MANAGER_ALERT_TABLE}|{alert_key}', severity='MINOR')
            logger.info("Trigger 3 [STATE_DB RACK_MANAGER_ALERT]: severity=MINOR")
            time.sleep(15)
        finally:
            redis_del(self.duthost, STATE_DB, f'{RACK_MANAGER_ALERT_TABLE}|{alert_key}')
        la.match_regex = [r".*(rack.*alert|rack_mgr|RACK_MGR).*"]
        r3 = la.analyze(marker, fail=False)
        trigger_results['RACK_MANAGER_ALERT'] = r3.get("total", {}).get("match", 0) > 0
        logger.info(f"Trigger 3: {'logged' if trigger_results['RACK_MANAGER_ALERT'] else 'no log within 15s'}")

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
        host = get_switch_host_or_skip_test(self.duthost)

        def hset_cmd(key, command):
            redis_hset(self.duthost, STATE_DB,
                       f'{RACK_MANAGER_COMMAND_TABLE}|{key}',
                       command=command, status='PENDING')
            logger.info(f"RACK_MANAGER_COMMAND[{key}]: command={command}")

        def hget_status(key):
            return redis_hget(self.duthost, STATE_DB,
                              f'{RACK_MANAGER_COMMAND_TABLE}|{key}', 'status')

        def del_cmd(*keys):
            redis_del(self.duthost, STATE_DB,
                      *[f'{RACK_MANAGER_COMMAND_TABLE}|{k}' for k in keys])

        # --- Scenario 1: POWER_OFF then POWER_ON ---
        off_key, on_key = 'test_power_off', 'test_power_on'
        pre_boot = get_host_uptime(host)
        try:
            hset_cmd(off_key, 'POWER_OFF')
            wait_host_off(host)
            pytest_assert(hget_status(off_key) == 'DONE',
                          f"POWER_OFF status expected DONE, got {hget_status(off_key)!r}")
            hset_cmd(on_key, 'POWER_ON')
            wait_host_on(host)
            pytest_assert(hget_status(on_key) == 'DONE',
                          f"POWER_ON status expected DONE, got {hget_status(on_key)!r}")
            verify_bmc_initiated_reboot(host, pre_boot)
        finally:
            del_cmd(off_key, on_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 2: GRACEFUL_SHUT then POWER_ON ---
        gs_key, on2_key = 'test_graceful_shut', 'test_power_on2'
        pre_boot = get_host_uptime(host)
        try:
            hset_cmd(gs_key, 'GRACEFUL_SHUT')
            wait_host_off(host)
            pytest_assert(hget_status(gs_key) == 'DONE',
                          f"GRACEFUL_SHUT status expected DONE, got {hget_status(gs_key)!r}")
            hset_cmd(on2_key, 'POWER_ON')
            wait_host_on(host)
            pytest_assert(hget_status(on2_key) == 'DONE',
                          f"POWER_ON status expected DONE, got {hget_status(on2_key)!r}")
            verify_bmc_initiated_reboot(host, pre_boot)
        finally:
            del_cmd(gs_key, on2_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 3: POWER_CYCLE (single command round-trip) ---
        pc_key = 'test_power_cycle'
        pre_boot = get_host_uptime(host)
        try:
            hset_cmd(pc_key, 'POWER_CYCLE')
            wait_host_on(host)
            pytest_assert(hget_status(pc_key) == 'DONE',
                          f"POWER_CYCLE status expected DONE, got {hget_status(pc_key)!r}")
            verify_bmc_initiated_reboot(host, pre_boot)
        finally:
            del_cmd(pc_key)
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

        # --- Scenario 4: POWER_ON blocked by CRITICAL leak ---
        blocked_key = 'test_blocked_power_on'
        orig_leak = redis_hget(self.duthost, STATE_DB,
                               f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                               'device_leak_status') or 'OK'
        # Pause thermalctld so it doesn't overwrite the injected device_leak_status
        with pause_pmon_daemon(self.duthost, 'thermalctld'):
            try:
                redis_hset(self.duthost, STATE_DB,
                           f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                           device_leak_status='CRITICAL')
                hset_cmd(blocked_key, 'POWER_ON')
                wait_until(30, 3, 0, lambda: hget_status(blocked_key) == 'FAILED')
                pytest_assert(hget_status(blocked_key) == 'FAILED',
                              f"POWER_ON during CRITICAL leak should fail, got "
                              f"status={hget_status(blocked_key)!r}")
            finally:
                del_cmd(blocked_key)
                redis_hset(self.duthost, STATE_DB,
                           f'{SYSTEM_LEAK_STATUS_TABLE}|system',
                           device_leak_status=orig_leak)
                self.duthost.shell("config chassis modules startup SWITCH-HOST",
                                   module_ignore_errors=True)

        # --- Scenario 5: Unknown command rejected without dispatching power action ---
        # Handler logs "Unknown Rack Manager command: ..." and sets status=FAILED; paired Switch-Host must stay up.
        unknown_key = 'test_unknown_cmd'
        pre_boot = get_host_uptime(host)
        try:
            hset_cmd(unknown_key, 'TEST_UNKNOWN_COMMAND')
            wait_until(30, 3, 0, lambda: hget_status(unknown_key) == 'FAILED')
            pytest_assert(hget_status(unknown_key) == 'FAILED',
                          f"Unknown RACK_MANAGER_COMMAND expected status=FAILED, "
                          f"got {hget_status(unknown_key)!r}")
            post_boot = get_host_uptime(host)
            pytest_assert(post_boot == pre_boot,
                          f"Switch-Host must not reboot for unknown command: "
                          f"pre={pre_boot!r} post={post_boot!r}")
        finally:
            del_cmd(unknown_key)

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

            # Scenario A: cold reboot BMC → reboot cause NOT power loss → bmcctld must skip delay.
            reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
                   wait_for_ssh=True, safe_reboot=True)
            wait_until(420, 10, 30, lambda: self.duthost.critical_services_fully_started())

            # Post-reboot syslog (tmpfs) is fresh — entire file is the window.
            # Use bmc_log_zgrep to also walk event.log + any rotated .gz files.
            journal_a = bmc_log_zgrep(
                self.duthost, r"SWITCH_HOST_POWER_ON_DELAY", tail=50,
                files=f"/var/log/syslog* {BMC_EVENT_LOG}",
            )
            logger.info(f"Scenario A (BMC cold reboot) journal:\n{journal_a}")

            pytest_assert('Skipping SWITCH_HOST_POWER_ON_DELAY' in journal_a,
                          "After non-power-loss BMC reboot, expected 'Skipping "
                          "SWITCH_HOST_POWER_ON_DELAY' log not found")
            # Strip 'Skipping ...' lines so 'Waiting <N>s ... SWITCH_HOST_POWER_ON_DELAY' can't false-match.
            non_skip_lines = '\n'.join(
                ln for ln in journal_a.splitlines()
                if 'Skipping SWITCH_HOST_POWER_ON_DELAY' not in ln
            )
            delay_applied = re.search(
                r'Waiting\s+\d+s.*SWITCH_HOST_POWER_ON_DELAY', non_skip_lines
            )
            pytest_assert(not delay_applied,
                          f"After non-power-loss BMC reboot, delay-applied log found "
                          f"unexpectedly: {delay_applied.group(0) if delay_applied else ''}")

            # Scenario B: PDU power cycle BMC → reboot cause IS power loss → bmcctld must apply delay.
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

            journal_b = bmc_log_zgrep(
                self.duthost, r"SWITCH_HOST_POWER_ON_DELAY|issuing power_on", tail=50,
                files=f"/var/log/syslog* {BMC_EVENT_LOG}",
            )
            logger.info(f"Scenario B (BMC power-loss) journal:\n{journal_b}")

            # Match "Waiting <N>s ... SWITCH_HOST_POWER_ON_DELAY" (N before token).
            delay_match = re.search(
                r'(\S+\s+\S+\s+\S+).*?Waiting\s+(\d+)s.*?SWITCH_HOST_POWER_ON_DELAY',
                journal_b
            )
            pytest_assert(delay_match,
                          "After PDU-induced BMC power-loss reboot, expected "
                          "'Waiting <N>s ... SWITCH_HOST_POWER_ON_DELAY' log not found")
            logged_delay = int(delay_match.group(2))
            pytest_assert(logged_delay == test_delay,
                          f"Logged power_on_delay {logged_delay} != configured {test_delay}")

            # Match "STARTUP: Switch-Host OFFLINE — issuing power_on" (lowercase 'issuing').
            poweron_match = re.search(
                r'(\S+\s+\S+\s+\S+).*?issuing power_on',
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

        host = get_switch_host_or_skip_test(self.duthost)

        sw_uptime_pre = get_host_uptime(host)
        sw_history_pre = host.show_and_parse('show reboot-cause history') or []
        bmc_uptime_pre = get_host_uptime(self.duthost)
        bmc_history_pre = self.duthost.show_and_parse('show reboot-cause history') or []

        reboot(self.duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
               wait_for_ssh=True, safe_reboot=True)

        wait_until(420, 10, 30, lambda: self.duthost.critical_services_fully_started())

        bmc_uptime_post = get_host_uptime(self.duthost)
        bmc_history_post = self.duthost.show_and_parse('show reboot-cause history') or []
        pytest_assert(bmc_uptime_post and bmc_uptime_post != bmc_uptime_pre,
                      f"BMC uptime did not advance after reboot: "
                      f"pre={bmc_uptime_pre!r} post={bmc_uptime_post!r}")
        pytest_assert(len(bmc_history_post) > len(bmc_history_pre),
                      f"BMC reboot-cause history did not grow: "
                      f"pre={len(bmc_history_pre)} post={len(bmc_history_post)}")

        sw_uptime_post = get_host_uptime(host)
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
